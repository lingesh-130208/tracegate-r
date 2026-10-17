import unittest
import sqlite3
import tempfile
import json
import re
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.app.auth import hash_password
from backend.app.main import app
import backend.app.main as api_module
from backend.app.model_service import ModelsUnavailableError, release_feature_names

client = TestClient(app, base_url="https://testserver")

TEST_ADMIN_USERNAME = "api-test-admin"
TEST_ADMIN_PASSWORD = "API test admin phrase 2026! secure"


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.database_dir = tempfile.TemporaryDirectory()
        cls.database_path_patch = patch.object(
            api_module,
            "DB_PATH",
            Path(cls.database_dir.name) / "api-tests.sqlite3",
        )
        cls.database_path_patch.start()
        api_module.init_db()
        cls.create_test_admin()

    @classmethod
    def tearDownClass(cls):
        client.close()
        cls.database_path_patch.stop()
        cls.database_dir.cleanup()

    @classmethod
    def create_test_admin(cls):
        now = api_module._iso_now()
        with api_module.db_connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO tenants(tenant_id, display_name, created_at) VALUES (?, ?, ?)",
                ("api-test-tenant", "API test tenant", now),
            )
            db.execute(
                """INSERT OR IGNORE INTO users(
                    user_id, username, password_hash, role, tenant_id, active, created_at, updated_at
                ) VALUES (?, ?, ?, 'admin', ?, 1, ?, ?)""",
                (
                    "api-test-admin-id",
                    TEST_ADMIN_USERNAME,
                    hash_password(TEST_ADMIN_PASSWORD),
                    "api-test-tenant",
                    now,
                    now,
                ),
            )

    def setUp(self):
        self.authenticate_test_admin()

    def authenticate_test_admin(self):
        response = client.post(
            "/api/auth/login",
            json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD},
            headers={"Origin": "https://testserver"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.csrf_token = response.json()["csrf_token"]

    def prepare_isolated_database(self):
        api_module.init_db()
        self.create_test_admin()
        self.authenticate_test_admin()

    def api_post(self, path, **kwargs):
        headers = {
            "Origin": "https://testserver",
            "X-TraceGate-CSRF": self.csrf_token,
            **kwargs.pop("headers", {}),
        }
        return client.post(path, headers=headers, **kwargs)

    def test_health_endpoint(self):
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertIn("model_ready", response.json())

    def test_model_info_endpoint(self):
        response = client.get("/api/model-info")
        self.assertEqual(response.status_code, 200)
        self.assertIn("models_available", response.json())
        self.assertIsInstance(response.json()["feature_names"], list)
        self.assertEqual(len(response.json()["feature_names"]), 48)
        self.assertEqual(len(set(response.json()["feature_names"])), 48)
        canonical_names = json.loads((api_module.ROOT / "data" / "model_feature_names.json").read_text(encoding="utf-8"))
        self.assertEqual(response.json()["feature_names"], canonical_names)
        self.assertNotIn("artifact_directory", response.json())

    def test_dashboard_endpoint(self):
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("TraceGate-R", response.text)
        if api_module.FRONTEND_INDEX.is_file():
            asset_paths = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', response.text)
            self.assertTrue(asset_paths, "built dashboard should reference hashed production assets")
            for asset_path in asset_paths:
                with self.subTest(asset=asset_path):
                    asset = client.get(asset_path)
                    self.assertEqual(asset.status_code, 200)
                    self.assertGreater(len(asset.content), 0)
        else:
            self.assertEqual(response.status_code, 503)
            self.assertIn("build required", response.text.lower())

    def test_dashboard_explains_when_production_bundle_is_missing(self):
        missing_bundle = Path(self.database_dir.name) / "not-built" / "index.html"
        with patch.object(api_module, "FRONTEND_INDEX", missing_bundle):
            response = client.get("/")
        self.assertEqual(response.status_code, 503)
        self.assertIn("build required", response.text.lower())

    def test_audit_endpoint(self):
        response = client.get("/api/audit?limit=10")
        self.assertEqual(response.status_code, 200)
        self.assertIn("events", response.json())

    def test_protected_endpoints_reject_anonymous_requests(self):
        with TestClient(app, base_url="https://testserver") as anonymous:
            self.assertEqual(anonymous.get("/api/audit").status_code, 401)
            self.assertEqual(anonymous.post("/api/evaluate", json={
                "model_verdict": "benign",
                "evidence": {"file_activity": "present"},
            }).status_code, 401)
            self.assertEqual(anonymous.post("/api/predict", json={
                "features": {"Filetop__Total_Reads": 1},
            }).status_code, 401)

    def test_complete_evidence_endpoint(self):
        payload = {
            "model_verdict": "benign",
            "evidence": {
                "file_activity": "present",
                "process_execution": "present",
                "system_calls": "present",
                "network_behavior": "present",
            },
        }
        response = self.api_post("/api/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "EVIDENCE_SUFFICIENT")

    def test_missing_evidence_requires_review(self):
        payload = {
            "model_verdict": "benign",
            "evidence": {"file_activity": "present"},
        }
        response = self.api_post("/api/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "REVIEW_REQUIRED")

    def test_invalid_verdict_returns_validation_error(self):
        response = self.api_post(
            "/api/evaluate",
            json={"model_verdict": "maybe"},
        )
        self.assertEqual(response.status_code, 422)

    def test_predict_requires_feature_vector(self):
        response = self.api_post(
            "/api/predict",
            json={"features": {}},
        )
        self.assertEqual(response.status_code, 422)

    def test_predict_rejects_coercible_or_non_finite_feature_values(self):
        cases = (
            ("numeric string", {"features": {"Filetop__Total_Reads": "1.0"}}),
            ("boolean", {"features": {"Filetop__Total_Reads": True}}),
        )
        for label, payload in cases:
            with self.subTest(value=label):
                response = self.api_post(
                    "/api/predict",
                    json=payload,
                )
                self.assertEqual(response.status_code, 422)
        overflow = self.api_post(
            "/api/predict",
            content=b'{"features":{"Filetop__Total_Reads":1e999}}',
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(overflow.status_code, 422)
        large_integer = self.api_post(
            "/api/predict",
            content=(
                b'{"features":{"Filetop__Total_Reads":'
                + b"9" * 309
                + b"}}"
            ),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(large_integer.status_code, 422)


    def test_scored_prediction_and_probability_are_audited(self):
        model_result = {
            "prediction_available": True,
            "prediction_unavailable_reason": None,
            "logistic_probability_malicious": 0.2,
            "random_forest_probability_malicious": 0.4,
            "ensemble_probability_malicious": 0.3,
            "logistic_label": 0,
            "random_forest_label": 0,
            "probability_gap": 0.2,
            "model_disagreement": False,
            "missing_features": release_feature_names()[1:],
            "feature_count": 48,
            "provided_feature_count": 1,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "audit.sqlite3"
            with patch.object(api_module, "DB_PATH", database), patch.object(
                api_module, "predict_models", return_value=model_result
            ):
                self.prepare_isolated_database()
                response = self.api_post("/api/predict", json={
                    "event_id": "scored-prediction-test",
                    "features": {"Filetop__Total_Reads": 3},
                    "evidence": {"file_activity": "present"},
                })
                self.assertEqual(response.status_code, 200, response.text)
                result = response.json()
                self.assertTrue(result["score_available"])
                self.assertEqual(result["model_probabilities"]["ensemble"], 0.3)
                self.assertEqual(result["decision"], "REVIEW_REQUIRED")

                audit = client.get("/api/audit?limit=10").json()
                saved = next(e for e in audit["events"] if e["event_id"] == "scored-prediction-test")
                self.assertAlmostEqual(saved["ensemble_probability"], 0.3)
                self.assertEqual(saved["model_verdict"], "benign")
                self.assertEqual(saved["features"], {"Filetop__Total_Reads": 3.0})
                self.assertEqual(len(saved["missing_features"]), 47)
                self.assertEqual(saved["model_labels"], {
                    "logistic_regression": 0,
                    "random_forest": 0,
                })
                self.assertTrue(saved["score_available"])
                self.assertEqual(len(saved["schema_sha256"]), 64)

    def test_unscorable_partial_runtime_event_is_audited_without_invented_score(self):
        feature_names = release_feature_names()
        model_result = {
            "prediction_available": False,
            "prediction_unavailable_reason": "MODEL_DOES_NOT_SUPPORT_MISSING_FEATURES",
            "logistic_probability_malicious": None,
            "random_forest_probability_malicious": None,
            "ensemble_probability_malicious": None,
            "logistic_label": None,
            "random_forest_label": None,
            "probability_gap": None,
            "model_disagreement": False,
            "missing_features": feature_names[1:],
            "feature_count": 48,
            "provided_feature_count": 1,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "audit.sqlite3"
            with patch.object(api_module, "DB_PATH", database), patch.object(
                api_module, "predict_models", return_value=model_result
            ):
                self.prepare_isolated_database()
                response = self.api_post("/api/predict", json={
                    "event_id": "runtime-partial-test",
                    "features": {
                        "Filetop__Total_Reads": 3,
                        "Filetop__Total_Writes": None,
                    },
                    "evidence": {"file_activity": "present"},
                })
                self.assertEqual(response.status_code, 200, response.text)
                result = response.json()
                self.assertFalse(result["score_available"])
                self.assertIsNone(result["model_probabilities"]["ensemble"])
                self.assertEqual(result["model_verdict"], "unknown")
                self.assertEqual(result["decision"], "REVIEW_REQUIRED")
                self.assertEqual(len(result["missing_features"]), 47)

                audit = client.get("/api/audit?limit=10").json()
                saved = next(e for e in audit["events"] if e["event_id"] == "runtime-partial-test")
                self.assertIsNone(saved["ensemble_probability"])
                self.assertIn("MODEL_DOES_NOT_SUPPORT_MISSING_FEATURES", saved["integrity_alerts"])
                self.assertEqual(saved["features"], {
                    "Filetop__Total_Reads": 3.0,
                    "Filetop__Total_Writes": None,
                })
                self.assertEqual(len(saved["missing_features"]), 47)
                db = sqlite3.connect(database)
                try:
                    row = db.execute(
                        "SELECT ensemble_probability, model_verdict, decision FROM audit_events WHERE event_id=?",
                        ("runtime-partial-test",),
                    ).fetchone()
                finally:
                    db.close()
                self.assertEqual(row, (None, "unknown", "REVIEW_REQUIRED"))

    def test_prediction_without_artifacts_is_audited_unscored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "audit.sqlite3"
            with patch.object(api_module, "DB_PATH", database), patch.object(
                api_module, "predict_models",
                side_effect=ModelsUnavailableError("trained artifacts unavailable"),
            ):
                self.prepare_isolated_database()
                response = self.api_post("/api/predict", json={
                    "event_id": "models-unavailable-test",
                    "features": {"Filetop__Total_Reads": 4},
                })
                self.assertEqual(response.status_code, 200, response.text)
                self.assertFalse(response.json()["score_available"])
                self.assertIsNone(response.json()["model_probabilities"]["ensemble"])
                self.assertEqual(response.json()["model_verdict"], "unknown")
                self.assertEqual(response.json()["decision"], "REVIEW_REQUIRED")
                db = sqlite3.connect(database)
                try:
                    saved = db.execute(
                        "SELECT model_verdict, decision, ensemble_probability, "
                        "prediction_unavailable_reason FROM audit_events WHERE event_id=?",
                        ("models-unavailable-test",),
                    ).fetchone()
                finally:
                    db.close()
                self.assertEqual(saved, (
                    "unknown",
                    "REVIEW_REQUIRED",
                    None,
                    "MODEL_NOT_READY",
                ))

    def test_unknown_feature_name_is_rejected_even_without_models(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "audit.sqlite3"
            with patch.object(api_module, "DB_PATH", database), patch.object(
                api_module,
                "predict_models",
                side_effect=ModelsUnavailableError("trained artifacts unavailable"),
            ):
                self.prepare_isolated_database()
                response = self.api_post("/api/predict", json={
                    "event_id": "unknown-feature-test",
                    "features": {"made_up_feature": 8},
                })
                self.assertEqual(response.status_code, 422)
                db = sqlite3.connect(database)
                try:
                    count = db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
                finally:
                    db.close()
                self.assertEqual(count, 0)

    def test_duplicate_event_id_does_not_replace_audited_record(self):
        model_result = {
            "prediction_available": True,
            "prediction_unavailable_reason": None,
            "logistic_probability_malicious": 0.2,
            "random_forest_probability_malicious": 0.4,
            "ensemble_probability_malicious": 0.3,
            "logistic_label": 0,
            "random_forest_label": 0,
            "probability_gap": 0.2,
            "model_disagreement": False,
            "missing_features": release_feature_names()[1:],
            "feature_count": 48,
            "provided_feature_count": 1,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "audit.sqlite3"
            with patch.object(api_module, "DB_PATH", database), patch.object(
                api_module, "predict_models", return_value=model_result
            ):
                self.prepare_isolated_database()
                payload = {
                    "event_id": "immutable-audit-event",
                    "package_ref": "first-submission",
                    "features": {"Filetop__Total_Reads": 3},
                    "evidence": {"file_activity": "present"},
                }
                first = self.api_post("/api/predict", json=payload)
                self.assertEqual(first.status_code, 200, first.text)

                payload["package_ref"] = "replacement-attempt"
                second = self.api_post("/api/predict", json=payload)
                self.assertEqual(second.status_code, 409, second.text)

                audit = client.get("/api/audit?limit=10").json()
                saved = next(
                    event for event in audit["events"]
                    if event["event_id"] == "immutable-audit-event"
                )
                self.assertEqual(saved["package_ref"], "first-submission")
                self.assertEqual(saved["ensemble_probability"], 0.3)

    def test_additive_audit_migration_preserves_existing_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "legacy.sqlite3"
            db = sqlite3.connect(database)
            try:
                db.execute("""
                    CREATE TABLE audit_events (
                        event_id TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        package_ref TEXT,
                        model_verdict TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        logistic_probability REAL,
                        random_forest_probability REAL,
                        ensemble_probability REAL,
                        probability_gap REAL,
                        coverage_percent REAL,
                        reasons_json TEXT NOT NULL,
                        evidence_json TEXT NOT NULL,
                        alerts_json TEXT NOT NULL
                    )
                """)
                db.execute("""
                    INSERT INTO audit_events VALUES (
                        'legacy-event', '2024-01-01T00:00:00+00:00', NULL,
                        'benign', 'REVIEW_REQUIRED', NULL, NULL, NULL, NULL,
                        25.0, '[]', '{}', '[]'
                    )
                """)
                db.commit()
            finally:
                db.close()

            with patch.object(api_module, "DB_PATH", database):
                api_module.init_db()
                self.create_test_admin()
                self.authenticate_test_admin()
                audit = client.get("/api/audit?limit=10")

            self.assertEqual(audit.status_code, 200, audit.text)
            saved = next(e for e in audit.json()["events"] if e["event_id"] == "legacy-event")
            self.assertEqual(saved["decision"], "REVIEW_REQUIRED")
            self.assertEqual(saved["features"], {})
            self.assertEqual(saved["missing_features"], [])
            self.assertFalse(saved["score_available"])

if __name__ == "__main__":
    unittest.main()
