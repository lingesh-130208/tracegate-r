import json
import unittest
from pathlib import Path

from scripts.build_feature_provenance import build_manifest


ROOT = Path(__file__).resolve().parents[1]


class FeatureProvenanceTests(unittest.TestCase):
    def test_manifest_is_current_and_matches_the_ordered_release_schema(self):
        schema = json.loads(
            (ROOT / "data" / "model_feature_names.json").read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (ROOT / "data" / "feature_provenance.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest, build_manifest())
        self.assertEqual(manifest["feature_count"], 48)
        self.assertEqual(manifest["feature_order"], schema)
        self.assertEqual([item["name"] for item in manifest["features"]], schema)

    def test_each_feature_records_runtime_source_and_unvalidated_training_parity(self):
        manifest = json.loads(
            (ROOT / "data" / "feature_provenance.json").read_text(encoding="utf-8")
        )
        for feature in manifest["features"]:
            with self.subTest(feature=feature["name"]):
                self.assertIsNotNone(feature["training"]["validation_status"])
                self.assertIsNotNone(feature["runtime"]["availability"])
                self.assertIsNotNone(feature["runtime"]["required_context"])
                self.assertEqual(feature["parity_status"], "NOT_VALIDATED")
                self.assertIn("null means", feature["missing_value_semantics"])

    def test_unknown_runtime_mapping_fails_instead_of_inventing_a_source(self):
        from scripts.build_feature_provenance import _runtime_mapping

        with self.assertRaisesRegex(ValueError, "No runtime mapping"):
            _runtime_mapping("Unknown__Feature")


if __name__ == "__main__":
    unittest.main()
