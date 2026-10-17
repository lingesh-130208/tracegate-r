import unittest
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.app.main import app
import backend.app.main as api_module
from backend.app.model_service import ModelsUnavailableError

client = TestClient(app)


class ApiTests(unittest.TestCase):
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

    def test_dashboard_endpoint(self):
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("TraceGate-R", response.text)

    def test_audit_endpoint(self):
        response = client.get("/api/audit?limit=10")
        self.assertEqual(response.status_code, 200)
        self.assertIn("events", response.json())

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
        response = client.post("/api/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "EVIDENCE_SUFFICIENT")

    def test_missing_evidence_requires_review(self):
        payload = {
            "model_verdict": "benign",
            "evidence": {"file_activity": "present"},
        }
        response = client.post("/api/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "REVIEW_REQUIRED")

    def test_invalid_verdict_returns_validation_error(self):
        response = client.post(
            "/api/evaluate",
            json={"model_verdict": "maybe"},
        )
        self.assertEqual(response.status_code, 422)

    def test_predict_requires_feature_vector(self):
        response = client.post(
            "/api/predict",
            json={"features": {}},
        )
        self.assertEqual(response.status_code, 422)


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
            "missing_features": [],
            "feature_count": 48,
            "provided_feature_count": 48,
        }
        temp_root = Path(__file__).resolve().parents[1] / ".venv"
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            database = Path(temp_dir) / "audit.sqlite3"
            with patch.object(api_module, "DB_PATH", database), patch.object(
                api_module, "predict_models", return_value=model_result
            ):
                api_module.init_db()
                response = client.post("/api/predict", json={
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

    def test_unscorable_partial_runtime_event_is_audited_without_invented_score(self):
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
            "missing_features": ["Install__Total_Dependency_Count"],
            "feature_count": 48,
            "provided_feature_count": 47,
        }
        temp_root = Path(__file__).resolve().parents[1] / ".venv"
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            database = Path(temp_dir) / "audit.sqlite3"
            with patch.object(api_module, "DB_PATH", database), patch.object(
                api_module, "predict_models", return_value=model_result
            ):
                api_module.init_db()
                response = client.post("/api/predict", json={
                    "event_id": "runtime-partial-test",
                    "features": {"Filetop__Total_Reads": 3},
                    "evidence": {"file_activity": "present"},
                })
                self.assertEqual(response.status_code, 200, response.text)
                result = response.json()
                self.assertFalse(result["score_available"])
                self.assertIsNone(result["model_probabilities"]["ensemble"])
                self.assertEqual(result["model_verdict"], "unknown")
                self.assertEqual(result["decision"], "REVIEW_REQUIRED")

                audit = client.get("/api/audit?limit=10").json()
                saved = next(e for e in audit["events"] if e["event_id"] == "runtime-partial-test")
                self.assertIsNone(saved["ensemble_probability"])
                self.assertIn("MODEL_DOES_NOT_SUPPORT_MISSING_FEATURES", saved["integrity_alerts"])
                db = sqlite3.connect(database)
                try:
                    row = db.execute(
                        "SELECT ensemble_probability, model_verdict, decision FROM audit_events WHERE event_id=?",
                        ("runtime-partial-test",),
                    ).fetchone()
                finally:
                    db.close()
                self.assertEqual(row, (None, "unknown", "REVIEW_REQUIRED"))

    def test_prediction_fails_closed_when_trained_artifacts_are_unavailable(self):
        temp_root = Path(__file__).resolve().parents[1] / ".venv"
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            database = Path(temp_dir) / "audit.sqlite3"
            with patch.object(api_module, "DB_PATH", database), patch.object(
                api_module, "predict_models",
                side_effect=ModelsUnavailableError("trained artifacts unavailable"),
            ):
                api_module.init_db()
                response = client.post("/api/predict", json={
                    "event_id": "models-unavailable-test",
                    "features": {"Filetop__Total_Reads": 4},
                })
                self.assertEqual(response.status_code, 503)
                self.assertIn("trained artifacts unavailable", response.json()["detail"])
                db = sqlite3.connect(database)
                try:
                    saved = db.execute(
                        "SELECT COUNT(*) FROM audit_events WHERE event_id=?",
                        ("models-unavailable-test",),
                    ).fetchone()[0]
                finally:
                    db.close()
                self.assertEqual(saved, 0)

if __name__ == "__main__":
    unittest.main()
