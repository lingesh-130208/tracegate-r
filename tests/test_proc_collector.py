import sys
import json
import io
import contextlib
import unittest
from unittest.mock import patch
from pathlib import Path

from scripts import tracegate_proc_collector as collector


class ProcCollectorPlatformTests(unittest.TestCase):
    def test_valid_counter_pair_is_complete_with_string_process_start_ticks(self):
        self.assertTrue(collector.io_counters_complete({
            "syscr": 10,
            "syscw": 4,
            "start_ticks": "100",
        }))
        self.assertFalse(collector.io_counters_complete({
            "syscr": 10,
            "syscw": None,
            "start_ticks": "100",
        }))

    def test_api_schema_match_does_not_require_model_readiness(self):
        names = json.loads(
            (Path(__file__).resolve().parents[1] / "data" / "model_feature_names.json")
            .read_text(encoding="utf-8")
        )
        with patch.object(collector, "get_json", return_value={
            "models_available": False,
            "feature_names": names,
        }):
            self.assertEqual(collector.api_feature_schema("http://api", names), names)

    def test_collector_posts_and_verifies_unscored_audit_event(self):
        names = json.loads(
            (Path(__file__).resolve().parents[1] / "data" / "model_feature_names.json")
            .read_text(encoding="utf-8")
        )
        before = {"syscr": 10, "syscw": 2, "start_ticks": "100"}
        after = {"syscr": 12, "syscw": 3, "start_ticks": "100"}
        posted = []

        def fake_get_json(_base, route, payload=None):
            if route == "/api/model-info":
                return {"models_available": False, "feature_names": names}
            if route == "/api/predict":
                posted.append(payload)
                return {
                    "decision": "REVIEW_REQUIRED",
                    "score_available": False,
                    "prediction_unavailable_reason": "MODEL_NOT_READY",
                    "model_probabilities": {"ensemble": None},
                    "missing_feature_count": 46,
                }
            if route == "/api/audit?limit=200":
                return {"events": [{"event_id": posted[0]["event_id"]}]}
            raise AssertionError(f"Unexpected API route: {route}")

        with (
            patch.object(sys, "platform", "linux"),
            patch.object(sys, "argv", [
                "tracegate_proc_collector.py", "--pid", "123", "--duration", "1",
                "--interval", "1",
            ]),
            patch.object(collector, "get_json", side_effect=fake_get_json),
            patch.object(collector, "snapshot", side_effect=[(before, True), (after, True)]),
            patch.object(collector.time, "monotonic", side_effect=[0.0, 0.0, 0.5, 1.1]),
            patch.object(collector.time, "sleep"),
            contextlib.redirect_stdout(io.StringIO()) as stdout,
        ):
            collector.main()

        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0]["features"]["Filetop__Total_Reads"], 2)
        self.assertEqual(posted[0]["features"]["Filetop__Total_Writes"], 1)
        self.assertIsNone(posted[0]["features"]["Filetop__Total_Read_Data_Transfer"])
        self.assertEqual(posted[0]["evidence"]["file_activity"], "present")
        event_output = json.loads(stdout.getvalue().splitlines()[0])
        self.assertFalse(event_output["score_available"])
        self.assertEqual(event_output["prediction_unavailable_reason"], "MODEL_NOT_READY")
        self.assertIn('"audit_ok": true', stdout.getvalue())

    def test_collector_stops_when_the_target_pid_is_reused(self):
        names = json.loads(
            (Path(__file__).resolve().parents[1] / "data" / "model_feature_names.json")
            .read_text(encoding="utf-8")
        )
        before = {"syscr": 10, "syscw": 2, "start_ticks": "100"}
        after = {"syscr": 1, "syscw": 1, "start_ticks": "200"}
        calls = []

        def fake_get_json(_base, route, payload=None):
            calls.append(route)
            return {"models_available": False, "feature_names": names}

        with (
            patch.object(sys, "platform", "linux"),
            patch.object(sys, "argv", [
                "tracegate_proc_collector.py", "--pid", "123", "--duration", "1",
                "--interval", "1",
            ]),
            patch.object(collector, "get_json", side_effect=fake_get_json),
            patch.object(collector, "snapshot", side_effect=[(before, True), (after, True)]),
            patch.object(collector.time, "monotonic", side_effect=[0.0, 0.0, 0.5]),
            patch.object(collector.time, "sleep"),
        ):
            with self.assertRaisesRegex(RuntimeError, "PID identity changed"):
                collector.main()

        self.assertEqual(calls, ["/api/model-info"])

    def test_snapshot_rejects_non_linux_before_accessing_procfs(self):
        with patch.object(sys, "platform", "win32"):
            with self.assertRaisesRegex(OSError, "requires Linux /proc"):
                collector.snapshot(123, ["Filetop__Total_Reads"])

    def test_command_rejects_non_linux_before_calling_the_api(self):
        with patch.object(sys, "platform", "win32"), patch.object(sys, "argv", ["tracegate_proc_collector.py"]):
            with patch.object(collector, "get_json") as get_json:
                with self.assertRaisesRegex(SystemExit, "requires Linux /proc"):
                    collector.main()
                get_json.assert_not_called()

    def test_interval_mapping_preserves_only_supported_count_deltas(self):
        names = json.loads(
            (Path(__file__).resolve().parents[1] / "data" / "model_feature_names.json")
            .read_text(encoding="utf-8")
        )
        features = collector.interval_features(
            {"syscr": 10, "syscw": 4, "start_ticks": "100"},
            {"syscr": 13, "syscw": 9, "start_ticks": "100"},
            names,
        )
        self.assertEqual(features["Filetop__Total_Reads"], 3)
        self.assertEqual(features["Filetop__Total_Writes"], 5)
        self.assertIsNone(features["Filetop__Total_Read_Data_Transfer"])
        self.assertIsNone(features["Filetop__Total_Write_Data_Transfer"])
        self.assertIsNone(features["Opensnoop__Total__File_Descriptor"])
        self.assertIsNone(features["SysCall__File_Operations"])
        self.assertIsNone(features["SysCall__IO_Operations"])

    def test_interval_mapping_keeps_missing_or_reset_counters_unavailable(self):
        names = ["Filetop__Total_Reads", "Filetop__Total_Writes"]
        features = collector.interval_features(
            {"syscr": 10, "syscw": None, "start_ticks": "100"},
            {"syscr": 2, "syscw": 8, "start_ticks": "100"},
            names,
        )
        self.assertIsNone(features["Filetop__Total_Reads"])
        self.assertIsNone(features["Filetop__Total_Writes"])

    def test_pid_reuse_keeps_interval_features_unavailable(self):
        names = ["Filetop__Total_Reads", "Filetop__Total_Writes"]
        features = collector.interval_features(
            {"syscr": 10, "syscw": 4, "start_ticks": "100"},
            {"syscr": 20, "syscw": 9, "start_ticks": "200"},
            names,
        )
        self.assertEqual(features, {name: None for name in names})

    def test_counter_reset_is_reported_as_inconsistent(self):
        before = {"syscr": 10, "syscw": 4}
        after = {"syscr": 5, "syscw": 5}
        self.assertTrue(collector.counters_reset(before, after))


if __name__ == "__main__":
    unittest.main()
