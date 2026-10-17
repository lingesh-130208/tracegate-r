import unittest
from fastapi.testclient import TestClient

from backend.app.main import app

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


if __name__ == "__main__":
    unittest.main()
