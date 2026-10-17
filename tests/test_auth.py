import os
import sqlite3
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.auth import hash_password
import backend.app.main as api
import backend.app.genai_explain as explanations
from backend.app.model_service import ModelsUnavailableError


PASSWORDS = {
    "admin": "Admin testing phrase 2026! secure",
    "analyst": "Analyst testing phrase 2026! secure",
    "analyst2": "Analyst two phrase 2026! secure",
    "analyst_b": "Tenant beta phrase 2026! secure",
    "viewer": "Viewer testing phrase 2026! secure",
}


class AuthenticationAndTenantTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "auth-tests.sqlite3"
        self.db_patch = patch.object(api, "DB_PATH", self.db_path)
        self.db_patch.start()
        api.init_db()
        now = datetime.now(timezone.utc).isoformat()
        with api.db_connect() as db:
            db.executemany("INSERT INTO tenants(tenant_id, display_name, created_at) VALUES (?, ?, ?)", [
                ("alpha", "Tenant Alpha", now), ("beta", "Tenant Beta", now),
            ])
            for name, role, tenant in [
                ("admin", "admin", "alpha"),
                ("analyst", "analyst", "alpha"),
                ("analyst2", "analyst", "alpha"),
                ("analyst_b", "analyst", "beta"),
                ("viewer", "viewer", "alpha"),
            ]:
                db.execute("""
                    INSERT INTO users(user_id, username, password_hash, role, tenant_id, active, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                """, (str(uuid.uuid4()), name, hash_password(PASSWORDS[name]), role, tenant, now, now))
        self.client = TestClient(api.app, base_url="https://testserver")
        self.csrf = {}

    def tearDown(self):
        self.client.close()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def sign_in(self, username="admin", client=None):
        client = client or self.client
        response = client.post("/api/auth/login", json={
            "username": username, "password": PASSWORDS[username],
        }, headers={"Origin": "https://testserver"})
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertNotIn("password", response.text.lower())
        if client is self.client:
            self.csrf[username] = payload["csrf_token"]
        return payload

    def prediction(self, client=None, token=None, event_id="auth-event"):
        return (client or self.client).post("/api/predict", json={
            "event_id": event_id,
            "features": {"Filetop__Total_Reads": 7, "Filetop__Total_Writes": None},
            "evidence": {"file_activity": "present"},
        }, headers={
            "Origin": "https://testserver",
            **({"X-TraceGate-CSRF": token} if token else {}),
        })

    def test_sensitive_routes_reject_anonymous_requests_while_health_is_public(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        self.assertEqual(self.client.get("/api/model-info").status_code, 200)
        self.assertEqual(self.client.get("/api/audit").status_code, 401)
        self.assertEqual(self.prediction().status_code, 401)
        self.assertEqual(self.client.post("/api/genai/explain", json={"event_id": "missing"}).status_code, 401)

    def test_login_uses_secure_http_only_cookie_and_revocable_session(self):
        response = self.client.post("/api/auth/login", json={
            "username": "admin", "password": PASSWORDS["admin"],
        }, headers={"Origin": "https://testserver"})
        self.assertEqual(response.status_code, 200, response.text)
        cookie = response.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("secure", cookie)
        self.assertIn("samesite=strict", cookie)
        self.assertNotIn("password", response.text.lower())
        csrf = response.json()["csrf_token"]
        session = self.client.get("/api/auth/session").json()
        self.assertTrue(session["authenticated"])
        self.assertNotEqual(csrf, session["csrf_token"])
        logout = self.client.post("/api/auth/logout", headers={
            "Origin": "https://testserver", "X-TraceGate-CSRF": session["csrf_token"],
        })
        self.assertEqual(logout.status_code, 200, logout.text)
        self.assertEqual(self.client.get("/api/audit").status_code, 401)

    def test_csrf_origin_and_server_side_role_checks(self):
        self.sign_in("analyst")
        self.assertEqual(self.prediction(token=None).status_code, 403)
        self.assertEqual(self.prediction(token="invalid-csrf-token").status_code, 403)
        self.assertEqual(self.prediction(token=self.csrf["analyst"]).status_code, 200)
        self.sign_in("viewer")
        denied = self.prediction(token=self.csrf["viewer"], event_id="viewer-write")
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.client.get("/api/admin/users").status_code, 403)
        self.assertEqual(self.client.post("/api/admin/tenants", json={
            "tenant_id": "unauthorized-tenant", "display_name": "Unauthorized",
        }, headers={
            "Origin": "https://testserver",
            "X-TraceGate-CSRF": self.csrf["viewer"],
        }).status_code, 403)
        self.assertEqual(self.client.post("/api/auth/login", json={
            "username": "admin", "password": PASSWORDS["admin"],
        }, headers={"Origin": "https://attacker.invalid"}).status_code, 403)

    def test_audit_events_are_attributed_and_tenant_scoped(self):
        self.sign_in("analyst")
        with patch.object(api, "predict_models", side_effect=ModelsUnavailableError("unavailable")):
            response = self.prediction(token=self.csrf["analyst"], event_id="alpha-event")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["score_available"])
        self.assertIsNone(response.json()["model_probabilities"]["ensemble"])
        self.assertEqual(response.json()["decision"], "REVIEW_REQUIRED")
        self.assertEqual(self.client.get("/api/audit").json()["events"][0]["created_by_user_id"],
                         self.user_id("analyst"))
        self.assertIsNone(self.client.get("/api/audit").json()["events"][0]["features"]["Filetop__Total_Writes"])

        client_b = TestClient(api.app, base_url="https://testserver")
        self.sign_in("analyst_b", client_b)
        self.assertEqual(client_b.get("/api/audit").json(), {"count": 0, "events": []})
        client_b.close()

        client_same_tenant = TestClient(api.app, base_url="https://testserver")
        self.sign_in("analyst2", client_same_tenant)
        self.assertEqual([e["event_id"] for e in client_same_tenant.get("/api/audit").json()["events"]], ["alpha-event"])
        client_same_tenant.close()

        with api.db_connect() as db:
            db.execute("""INSERT INTO audit_events(event_id, created_at, model_verdict, decision,
                reasons_json, evidence_json, alerts_json) VALUES ('legacy', ?, 'unknown', 'REVIEW_REQUIRED', '[]', '{}', '[]')""",
                (datetime.now(timezone.utc).isoformat(),))
        self.sign_in("admin")
        ids = {event["event_id"] for event in self.client.get("/api/audit").json()["events"]}
        self.assertEqual(ids, {"alpha-event", "legacy"})

    def test_invitation_enrollment_recovery_and_admin_controls(self):
        admin = self.sign_in("admin")
        create = self.client.post("/api/admin/users", json={
            "username": "new.viewer", "role": "viewer", "tenant_id": "beta",
        }, headers={"Origin": "https://testserver", "X-TraceGate-CSRF": admin["csrf_token"]})
        self.assertEqual(create.status_code, 200, create.text)
        invite = create.json()["enrollment_token"]
        new_password = "A new viewer phrase 2026! secure"
        invited_client = TestClient(api.app, base_url="https://testserver")
        enrolled = invited_client.post("/api/auth/enroll", json={"token": invite, "password": new_password},
                                       headers={"Origin": "https://testserver"})
        self.assertEqual(enrolled.status_code, 200, enrolled.text)
        self.assertEqual(enrolled.json()["user"]["role"], "viewer")
        self.assertEqual(invited_client.get("/api/audit").status_code, 200)
        self.assertEqual(invited_client.post("/api/predict", json={"features": {"x": 1}}, headers={
            "Origin": "https://testserver", "X-TraceGate-CSRF": enrolled.json()["csrf_token"],
        }).status_code, 403)
        replay = TestClient(api.app, base_url="https://testserver")
        self.assertEqual(replay.post("/api/auth/enroll", json={"token": invite, "password": new_password},
                                     headers={"Origin": "https://testserver"}).status_code, 400)
        replay.close()

        reset = self.client.post(f"/api/admin/users/{create.json()['user_id']}/reset-password", headers={
            "Origin": "https://testserver", "X-TraceGate-CSRF": admin["csrf_token"],
        })
        self.assertEqual(reset.status_code, 200, reset.text)
        self.assertEqual(invited_client.get("/api/audit").status_code, 401)
        reset_password = "A reset viewer phrase 2026! secure"
        re_enrolled = invited_client.post("/api/auth/enroll", json={
            "token": reset.json()["reset_token"], "password": reset_password,
        }, headers={"Origin": "https://testserver"})
        self.assertEqual(re_enrolled.status_code, 200, re_enrolled.text)
        self.assertNotIn(reset.json()["reset_token"], re_enrolled.text)

        disable_last_admin = self.client.patch(f"/api/admin/users/{self.user_id('admin')}", json={"active": False}, headers={
            "Origin": "https://testserver", "X-TraceGate-CSRF": admin["csrf_token"],
        })
        self.assertEqual(disable_last_admin.status_code, 409)
        self.assertFalse(any(PASSWORDS["admin"] in row["details_json"] for row in self.security_rows()))
        invited_client.close()

    def test_session_expiry_revokes_api_access(self):
        self.sign_in("analyst")
        analyst_id = self.user_id("analyst")
        with api.db_connect() as db:
            db.execute("UPDATE auth_sessions SET expires_at = ? WHERE user_id = ?",
                       ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(), analyst_id))
        self.assertFalse(self.client.get("/api/auth/session").json()["authenticated"])
        self.assertEqual(self.client.get("/api/audit").status_code, 401)

    def test_collector_token_is_scoped_to_configured_tenant(self):
        client = TestClient(api.app, base_url="https://testserver")
        env = patch.dict(os.environ, {
            "TRACEGATE_COLLECTOR_TOKEN": "local-test-token-that-is-not-a-production-secret",
            "TRACEGATE_COLLECTOR_TENANT_ID": "beta",
        })
        env.start()
        try:
            headers = {"Authorization": "Bearer local-test-token-that-is-not-a-production-secret"}
            with patch.object(api, "predict_models", side_effect=ModelsUnavailableError("unavailable")):
                posted = client.post("/api/predict", json={"event_id": "collector-beta", "features": {"Filetop__Total_Reads": 1}}, headers=headers)
            self.assertEqual(posted.status_code, 200, posted.text)
            audit = client.get("/api/audit", headers=headers).json()
            self.assertEqual([event["event_id"] for event in audit["events"]], ["collector-beta"])
            self.assertIsNone(audit["events"][0]["created_by_user_id"])
            self.assertEqual(audit["events"][0]["tenant_id"], "beta")
        finally:
            env.stop()
            client.close()

    def test_explanation_requires_auth_and_persists_actor_without_changing_decision(self):
        self.assertEqual(self.client.post("/api/genai/explain", json={"event_id": "missing"}).status_code, 401)
        self.sign_in("analyst")
        with patch.object(api, "predict_models", side_effect=ModelsUnavailableError("unavailable")):
            self.assertEqual(self.prediction(token=self.csrf["analyst"], event_id="explainable").status_code, 200)
        explanation_db = Path(self.temp_dir.name) / "explanations.sqlite3"
        with patch.object(explanations, "EXPLANATION_DB", explanation_db):
            response = self.client.post("/api/genai/explain", json={"event_id": "explainable"}, headers={
                "Origin": "https://testserver", "X-TraceGate-CSRF": self.csrf["analyst"],
            })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["formal_decision_changed"])
        self.assertIn("REVIEW_REQUIRED", response.json()["explanation"])
        db = sqlite3.connect(explanation_db)
        try:
            row = db.execute("SELECT actor_user_id, tenant_id FROM explanations").fetchone()
        finally:
            db.close()
        self.assertEqual(row, (self.user_id("analyst"), "alpha"))

    def user_id(self, username):
        with api.db_connect() as db:
            return db.execute("SELECT user_id FROM users WHERE username = ?", (username,)).fetchone()[0]

    def security_rows(self):
        with api.db_connect() as db:
            return db.execute("SELECT details_json FROM security_events").fetchall()


if __name__ == "__main__":
    unittest.main()
