import unittest
from backend.app.genai_explain import sanitize_event_for_llm

class GenAiSanitizationTests(unittest.TestCase):
    def test_keeps_decision_probabilities_and_evidence(self):
        event = {
            "event_id": "evt-1", "decision": "REVIEW_REQUIRED",
            "model_probabilities": {"ensemble": 0.75, "random_forest": 0.8, "bad": "x"},
            "evidence": {"file_activity": "present", "network_behavior": "missing"},
            "integrity_alerts": ["PROCFS_LIMITED_SNAPSHOT"],
        }
        clean = sanitize_event_for_llm(event)
        self.assertEqual(clean["decision"], "REVIEW_REQUIRED")
        self.assertEqual(clean["model_probabilities"]["ensemble"], 0.75)
        self.assertEqual(clean["evidence"]["network_behavior"], "missing")
        self.assertNotIn("bad", clean["model_probabilities"])

    def test_excludes_raw_features_keys_and_secrets(self):
        event = {"event_id": "evt-2", "features": {"secret": 1},
                 "raw_payload": "must-not-leave", "api_key": "secret",
                 "decision": "REVIEW_REQUIRED"}
        clean = sanitize_event_for_llm(event)
        self.assertNotIn("features", clean)
        self.assertNotIn("raw_payload", clean)
        self.assertNotIn("api_key", clean)
        self.assertEqual(clean["decision"], "REVIEW_REQUIRED")

    def test_unknown_fields_are_not_forwarded(self):
        self.assertEqual(sanitize_event_for_llm({"event_id": "evt-3", "password": "x"}),
                         {"event_id": "evt-3"})

if __name__ == "__main__":
    unittest.main()
