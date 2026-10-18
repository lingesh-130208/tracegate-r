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
    "user": "User testing phrase 2026! secure",
    "user2": "User two phrase 2026! secure",
    "user_b": "Tenant beta user phrase 2026! secure",
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
                ("user", "user", "alpha"),
                ("user2", "user", "alpha"),
                ("user_b", "user", "beta"),
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
        self.sign_in("user")
        self.assertEqual(self.prediction(token=None).status_code, 403)
        self.assertEqual(self.prediction(token="invalid-csrf-token").status_code, 403)
        self.assertEqual(self.prediction(token=self.csrf["user"]).status_code, 200)
        self.assertEqual(self.client.get("/api/admin/users").status_code, 403)
        self.assertEqual(self.client.post("/api/admin/tenants", json={
            "tenant_id": "unauthorized-tenant", "display_name": "Unauthorized",
        }, headers={
            "Origin": "https://testserver",
            "X-TraceGate-CSRF": self.csrf["user"],
        }).status_code, 403)
        self.assertEqual(self.client.post("/api/auth/login", json={
            "username": "admin", "password": PASSWORDS["admin"],
        }, headers={"Origin": "https://attacker.invalid"}).status_code, 403)

    def test_audit_events_are_attributed_and_tenant_scoped(self):
        self.sign_in("user")
        with patch.object(api, "predict_models", side_effect=ModelsUnavailableError("unavailable")):
            response = self.prediction(token=self.csrf["user"], event_id="alpha-event")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["score_available"])
        self.assertIsNone(response.json()["model_probabilities"]["ensemble"])
        self.assertEqual(response.json()["decision"], "REVIEW_REQUIRED")
        self.assertEqual(self.client.get("/api/audit").json()["events"][0]["created_by_user_id"],
                         self.user_id("user"))
        self.assertIsNone(self.client.get("/api/audit").json()["events"][0]["features"]["Filetop__Total_Writes"])

        client_b = TestClient(api.app, base_url="https://testserver")
        self.sign_in("user_b", client_b)
        self.assertEqual(client_b.get("/api/audit").json(), {"count": 0, "events": []})
        client_b.close()

        client_same_tenant = TestClient(api.app, base_url="https://testserver")
        self.sign_in("user2", client_same_tenant)
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
        tenant = self.client.post("/api/admin/tenants", json={
            "tenant_id": "gamma", "display_name": "Tenant Gamma",
        }, headers={"Origin": "https://testserver", "X-TraceGate-CSRF": admin["csrf_token"]})
        self.assertEqual(tenant.status_code, 200, tenant.text)
        self.assertEqual(tenant.json()["tenant_id"], "gamma")
        self.assertIn("gamma", {
            row["tenant_id"] for row in self.client.get("/api/admin/tenants").json()["tenants"]
        })
        create = self.client.post("/api/admin/users", json={
            "username": "new.user", "role": "user", "tenant_id": "beta",
        }, headers={"Origin": "https://testserver", "X-TraceGate-CSRF": admin["csrf_token"]})
        self.assertEqual(create.status_code, 200, create.text)
        invite = create.json()["enrollment_token"]
        new_password = "A new user phrase 2026! secure"
        invited_client = TestClient(api.app, base_url="https://testserver")
        enrolled = invited_client.post("/api/auth/enroll", json={"token": invite, "password": new_password},
                                       headers={"Origin": "https://testserver"})
        self.assertEqual(enrolled.status_code, 200, enrolled.text)
        self.assertEqual(enrolled.json()["user"]["role"], "user")
        self.assertEqual(invited_client.get("/api/audit").status_code, 200)
        with patch.object(api, "predict_models", side_effect=ModelsUnavailableError("unavailable")):
            user_write = invited_client.post("/api/predict", json={
                "event_id": "invited-user-write",
                "features": {"Filetop__Total_Reads": 1},
            }, headers={
                "Origin": "https://testserver", "X-TraceGate-CSRF": enrolled.json()["csrf_token"],
            })
        self.assertEqual(user_write.status_code, 200, user_write.text)
        self.assertEqual(invited_client.get("/api/admin/users").status_code, 403)
        self.assertEqual(invited_client.get("/api/admin/tenants").status_code, 403)
        replay = TestClient(api.app, base_url="https://testserver")
        self.assertEqual(replay.post("/api/auth/enroll", json={"token": invite, "password": new_password},
                                     headers={"Origin": "https://testserver"}).status_code, 400)
        replay.close()

        reset = self.client.post(f"/api/admin/users/{create.json()['user_id']}/reset-password", headers={
            "Origin": "https://testserver", "X-TraceGate-CSRF": admin["csrf_token"],
        })
        self.assertEqual(reset.status_code, 200, reset.text)
        self.assertEqual(invited_client.get("/api/audit").status_code, 401)
        reset_password = "A reset user phrase 2026! secure"
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
        self.sign_in("user")
        user_id = self.user_id("user")
        with api.db_connect() as db:
            db.execute("UPDATE auth_sessions SET expires_at = ? WHERE user_id = ?",
                       ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(), user_id))
        self.assertFalse(self.client.get("/api/auth/session").json()["authenticated"])
        self.assertEqual(self.client.get("/api/audit").status_code, 401)

    def test_disabling_account_invalidates_outstanding_recovery_tokens(self):
        admin = self.sign_in("admin")
        user_id = self.user_id("user")
        old_reset = self.client.post(f"/api/admin/users/{user_id}/reset-password", headers={
            "Origin": "https://testserver", "X-TraceGate-CSRF": admin["csrf_token"],
        })
        self.assertEqual(old_reset.status_code, 200, old_reset.text)
        reset = self.client.post(f"/api/admin/users/{user_id}/reset-password", headers={
            "Origin": "https://testserver", "X-TraceGate-CSRF": admin["csrf_token"],
        })
        self.assertEqual(reset.status_code, 200, reset.text)

        enrollment = TestClient(api.app, base_url="https://testserver")
        response = enrollment.post("/api/auth/enroll", json={
            "token": old_reset.json()["reset_token"],
            "password": "Obsolete reset phrase 2026! secure",
        }, headers={"Origin": "https://testserver"})
        self.assertEqual(response.status_code, 400, response.text)

        disabled = self.client.patch(f"/api/admin/users/{user_id}", json={"active": False}, headers={
            "Origin": "https://testserver", "X-TraceGate-CSRF": admin["csrf_token"],
        })
        self.assertEqual(disabled.status_code, 200, disabled.text)

        try:
            response = enrollment.post("/api/auth/enroll", json={
                "token": reset.json()["reset_token"],
                "password": "Disabled account phrase 2026! secure",
            }, headers={"Origin": "https://testserver"})
            self.assertEqual(response.status_code, 400, response.text)
            with api.db_connect() as db:
                self.assertEqual(db.execute(
                    "SELECT active FROM users WHERE user_id = ?", (user_id,)
                ).fetchone()["active"], 0)
        finally:
            enrollment.close()

    def test_password_change_invalidates_outstanding_recovery_tokens(self):
        admin = self.sign_in("admin")
        user_id = self.user_id("user")
        reset = self.client.post(f"/api/admin/users/{user_id}/reset-password", headers={
            "Origin": "https://testserver", "X-TraceGate-CSRF": admin["csrf_token"],
        })
        self.assertEqual(reset.status_code, 200, reset.text)

        user = TestClient(api.app, base_url="https://testserver")
        try:
            user_session = self.sign_in("user", user)
            changed_password = "Changed user phrase 2026! secure"
            changed = user.post("/api/auth/password", json={
                "current_password": PASSWORDS["user"],
                "new_password": changed_password,
            }, headers={
                "Origin": "https://testserver",
                "X-TraceGate-CSRF": user_session["csrf_token"],
            })
            self.assertEqual(changed.status_code, 200, changed.text)

            enrollment = TestClient(api.app, base_url="https://testserver")
            try:
                response = enrollment.post("/api/auth/enroll", json={
                    "token": reset.json()["reset_token"],
                    "password": "Stale reset phrase 2026! secure",
                }, headers={"Origin": "https://testserver"})
                self.assertEqual(response.status_code, 400, response.text)
            finally:
                enrollment.close()
        finally:
            user.close()

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
        status = self.client.get("/api/genai/status").json()
        self.assertEqual(status["capability"], "Deterministic Evidence Explanation")
        self.assertFalse(status["external_llm"])
        self.assertFalse(status["independently_predicts_maliciousness"])
        self.assertFalse(status["formal_verdict_changes"])
        self.sign_in("user")
        with patch.object(api, "predict_models", side_effect=ModelsUnavailableError("unavailable")):
            self.assertEqual(self.prediction(token=self.csrf["user"], event_id="explainable").status_code, 200)
        formal_decision = next(
            event["decision"] for event in self.client.get("/api/audit").json()["events"]
            if event["event_id"] == "explainable"
        )
        explanation_db = Path(self.temp_dir.name) / "explanations.sqlite3"
        with patch.object(explanations, "EXPLANATION_DB", explanation_db):
            response = self.client.post("/api/genai/explain", json={"event_id": "explainable"}, headers={
                "Origin": "https://testserver", "X-TraceGate-CSRF": self.csrf["user"],
            })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["capability"], "Deterministic Evidence Explanation")
        self.assertFalse(response.json()["external_llm"])
        self.assertFalse(response.json()["formal_decision_changed"])
        self.assertIn("REVIEW_REQUIRED", response.json()["explanation"])
        self.assertEqual(next(
            event["decision"] for event in self.client.get("/api/audit").json()["events"]
            if event["event_id"] == "explainable"
        ), formal_decision)
        admin = self.sign_in("admin")
        admin_explanation = self.client.post("/api/genai/explain", json={"event_id": "explainable"}, headers={
            "Origin": "https://testserver", "X-TraceGate-CSRF": admin["csrf_token"],
        })
        self.assertEqual(admin_explanation.status_code, 200, admin_explanation.text)
        db = sqlite3.connect(explanation_db)
        try:
            row = db.execute("SELECT actor_user_id, tenant_id FROM explanations").fetchone()
        finally:
            db.close()
        self.assertEqual(row, (self.user_id("user"), "alpha"))

    def test_human_role_names_are_exactly_admin_and_user(self):
        admin = self.sign_in("admin")
        self.assertEqual(admin["user"]["role"], "admin")
        user_client = TestClient(api.app, base_url="https://testserver")
        self.sign_in("user", user_client)
        self.assertEqual(user_client.get("/api/auth/session").json()["user"]["role"], "user")
        user_client.close()
        for legacy_or_unknown_role in ("analyst", "viewer", "collector", "owner"):
            result = self.client.post("/api/admin/users", json={
                "username": f"invalid-{legacy_or_unknown_role}",
                "role": legacy_or_unknown_role,
                "tenant_id": "alpha",
            }, headers={
                "Origin": "https://testserver",
                "X-TraceGate-CSRF": admin["csrf_token"],
            })
            self.assertEqual(result.status_code, 422, result.text)
        user_id = self.user_id("user")
        updated = self.client.patch(f"/api/admin/users/{user_id}", json={"role": "viewer"}, headers={
            "Origin": "https://testserver",
            "X-TraceGate-CSRF": admin["csrf_token"],
        })
        self.assertEqual(updated.status_code, 422, updated.text)

    def user_id(self, username):
        with api.db_connect() as db:
            return db.execute("SELECT user_id FROM users WHERE username = ?", (username,)).fetchone()[0]

    def security_rows(self):
        with api.db_connect() as db:
            return db.execute("SELECT details_json FROM security_events").fetchall()


if __name__ == "__main__":
    unittest.main()
