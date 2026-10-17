import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import build_release_manifest as release


class ReleaseManifestTests(unittest.TestCase):
    def test_manifest_records_source_environment_and_missing_model_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "data").mkdir()
            (root / "data" / "model_feature_names.json").write_text(
                json.dumps([f"feature_{index}" for index in range(48)]), encoding="utf-8"
            )
            (root / "requirements.txt").write_text(
                "fastapi>=0.115\njoblib>=1.3\n", encoding="utf-8"
            )

            def fake_git(_root, *args):
                if args[0] == "rev-parse":
                    return "a" * 40
                if args[0] == "branch":
                    return "tracegate-r-runtime-fixes"
                if args[0] == "diff-index":
                    return ""
                raise AssertionError(args)

            with patch.object(release, "_git", side_effect=fake_git):
                manifest = release.build_manifest(root, root / "missing-artifacts")

        self.assertEqual(manifest["source_revision"], "a" * 40)
        self.assertEqual(manifest["source_branch"], "tracegate-r-runtime-fixes")
        self.assertEqual(manifest["deployment_status"], "NOT_DEPLOYED")
        self.assertEqual(manifest["feature_count"], 48)
        self.assertTrue(manifest["tracked_source_tree_clean"])
        self.assertIsNone(manifest["model_artifacts"]["identifier"])
        self.assertEqual(
            manifest["model_artifacts"]["missing_files"],
            list(release.REQUIRED_ARTIFACTS),
        )
        self.assertEqual(
            {entry["requirement"] for entry in manifest["dependencies"]},
            {"fastapi>=0.115", "joblib>=1.3"},
        )


if __name__ == "__main__":
    unittest.main()
