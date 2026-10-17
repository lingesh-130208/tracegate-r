import unittest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.evidence_gate import REQUIRED_CATEGORIES


client = TestClient(app)


class ApiTests(unittest.TestCase):
    def test_health_endpoint(self):
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_complete_evidence_endpoint(self):
        payload = {
            "model_verdict": "benign",
            "evidence": {
                category: "present"
                for category in REQUIRED_CATEGORIES
            },
        }
        response = client.post("/api/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["decision"], "EVIDENCE_SUFFICIENT"
        )

    def test_missing_evidence_requires_review(self):
        payload = {
            "model_verdict": "benign",
            "evidence": {
                "file_activity": "present",
                "process_execution": "present",
                "network_behavior": "present",
            },
        }
        response = client.post("/api/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["decision"], "REVIEW_REQUIRED")
        self.assertEqual(result["coverage_percent"], 75.0)

    def test_invalid_verdict_returns_validation_error(self):
        response = client.post(
            "/api/evaluate",
            json={"model_verdict": "maybe"},
        )
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
