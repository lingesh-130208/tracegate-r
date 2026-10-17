import unittest
from backend.app.genai_explain import sanitize_event_for_llm, build_offline_explanation, MODEL_ID

class OfflineExplanationTests(unittest.TestCase):
    def test_keeps_recorded_decision_probability_and_evidence(self):
        event = {"event_id":"evt-1", "decision":"REVIEW_REQUIRED",
                 "model_probabilities":{"ensemble":0.75,"random_forest":0.8,"bad":"x"},
                 "evidence":{"file_activity":"present","network_behavior":"missing"},
                 "integrity_alerts":["PROCFS_LIMITED_SNAPSHOT"], "missing_feature_count":41}
        clean = sanitize_event_for_llm(event)
        self.assertEqual(clean["decision"], "REVIEW_REQUIRED")
        self.assertEqual(clean["model_probabilities"]["ensemble"], 0.75)
        self.assertEqual(clean["evidence"]["network_behavior"], "missing")
        self.assertNotIn("bad", clean["model_probabilities"])
        text = build_offline_explanation(event)
        self.assertIn("REVIEW_REQUIRED", text)
        self.assertIn("41 model feature(s)", text)
        self.assertIn("network_behavior", text)
        self.assertIn("0.750 (75.0%)", text)

    def test_maps_risk_score_from_realistic_audit_schema(self):
        event = {"event_id":"runtime-1", "decision":"REVIEW_REQUIRED", "risk_score":0.752,
                 "evidence":{"system_calls":"missing"}}
        clean = sanitize_event_for_llm(event)
        self.assertAlmostEqual(clean["model_probabilities"]["ensemble"], 0.752)
        explanation = build_offline_explanation(event)
        self.assertIn("0.752 (75.2%)", explanation)
        self.assertNotIn("No recognized numeric model score", explanation)

    def test_maps_nested_probability_from_known_result_wrapper(self):
        event = {"event_id":"runtime-2", "decision":"REVIEW_REQUIRED",
                 "result_json":"{\"prediction\":{\"malicious_probability\":0.752}}"}
        clean = sanitize_event_for_llm(event)
        self.assertAlmostEqual(clean["model_probabilities"]["ensemble"], 0.752)
        self.assertIn("0.752 (75.2%)", build_offline_explanation(event))

    def test_maps_camel_case_score_from_nested_result(self):
        event = {"event_id":"runtime-camel", "decision":"REVIEW_REQUIRED",
                 "modelOutput":{"maliciousProbability":"0.752"}}
        explanation = build_offline_explanation(event)
        self.assertIn("0.752 (75.2%)", explanation)

    def test_maps_numeric_string_score_without_inventing_values(self):
        event = {"event_id":"runtime-3", "decision":"REVIEW_REQUIRED", "malicious_score":"0.752"}
        explanation = build_offline_explanation(event)
        self.assertIn("0.752 (75.2%)", explanation)

    def test_excludes_raw_features_keys_and_secrets(self):
        event = {"event_id":"evt-2", "features":{"secret":1}, "raw_payload":"must-not-leave",
                 "api_key":"secret", "decision":"REVIEW_REQUIRED"}
        clean = sanitize_event_for_llm(event)
        self.assertNotIn("features", clean)
        self.assertNotIn("raw_payload", clean)
        self.assertNotIn("api_key", clean)
        self.assertEqual(clean["decision"], "REVIEW_REQUIRED")

    def test_unknown_fields_are_not_forwarded(self):
        self.assertEqual(sanitize_event_for_llm({"event_id":"evt-3", "password":"x"}), {"event_id":"evt-3"})

    def test_no_probability_is_invented(self):
        text = build_offline_explanation({"event_id":"evt-4", "decision":"REVIEW_REQUIRED", "features":[1,2]})
        self.assertIn("No recognized numeric model score", text)
        self.assertNotIn("0.0%", text)

    def test_local_engine_has_no_external_model_dependency(self):
        self.assertEqual(MODEL_ID, "offline-evidence-rules-v1")
        status = __import__("backend.app.genai_explain", fromlist=["genai_status"]).genai_status()
        self.assertTrue(status["configured"])
        self.assertEqual(status["mode"], "offline_deterministic")
        self.assertFalse(status["formal_verdict_changes"])

if __name__ == "__main__":
    unittest.main()
