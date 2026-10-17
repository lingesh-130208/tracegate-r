import unittest

from backend.app.evidence_gate import (
    REQUIRED_CATEGORIES,
    evaluate_evidence,
)


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.complete = {
            category: "present" for category in REQUIRED_CATEGORIES
        }

    def test_complete_evidence_is_sufficient(self):
        result = evaluate_evidence(self.complete, "benign")
        self.assertEqual(result["decision"], "EVIDENCE_SUFFICIENT")
        self.assertEqual(result["coverage_percent"], 100.0)

    def test_missing_evidence_requires_review(self):
        evidence = dict(self.complete)
        evidence["system_calls"] = "missing"
        result = evaluate_evidence(evidence, "benign")
        self.assertEqual(result["decision"], "REVIEW_REQUIRED")
        self.assertEqual(result["coverage_percent"], 75.0)

    def test_unknown_state_is_malformed(self):
        evidence = dict(self.complete)
        evidence["network_behavior"] = "unexpected"
        result = evaluate_evidence(evidence, "benign")
        self.assertEqual(
            result["category_states"]["network_behavior"], "malformed"
        )
        self.assertEqual(result["decision"], "REVIEW_REQUIRED")

    def test_integrity_alert_requires_review(self):
        result = evaluate_evidence(
            self.complete, "benign", ["trace integrity mismatch"]
        )
        self.assertEqual(result["decision"], "REVIEW_REQUIRED")
        self.assertIn("INTEGRITY_ALERT", result["reason_codes"])

    def test_unknown_verdict_requires_review(self):
        result = evaluate_evidence(self.complete, "unknown")
        self.assertEqual(result["decision"], "REVIEW_REQUIRED")

    def test_malicious_verdict_is_preserved(self):
        result = evaluate_evidence(self.complete, "malicious")
        self.assertEqual(result["model_verdict"], "malicious")
        self.assertEqual(result["decision"], "EVIDENCE_SUFFICIENT")


if __name__ == "__main__":
    unittest.main()
