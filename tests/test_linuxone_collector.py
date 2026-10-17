import collections
import importlib.util
import io
import json
import queue
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


COLLECTOR_PATH = Path(__file__).resolve().parents[1] / "scripts" / "tracegate_bpftrace_collector.linuxone.py"
SPEC = importlib.util.spec_from_file_location("tracegate_bpftrace_collector_linuxone", COLLECTOR_PATH)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class FakeTracer:
    pid = 9876

    def __init__(self):
        self.stdout = io.StringIO("")
        self.stderr = io.StringIO("")

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0


class LinuxOneCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(
            (Path(__file__).resolve().parents[1] / "data" / "model_feature_names.json").read_text(encoding="utf-8")
        )

    def test_linuxone_collector_imports_on_windows_for_unit_tests(self):
        with patch.object(collector.sys, "platform", "win32"):
            with self.assertRaisesRegex(OSError, "requires Linux procfs and bpftrace"):
                collector.capture(77, 10, 0.5, "http://127.0.0.1:8001", None)

    def test_release_schema_order_is_exactly_48_unique_features(self):
        self.assertEqual(len(self.schema), 48)
        self.assertEqual(len(set(self.schema)), 48)
        self.assertEqual(list(collector.build_features(
            self.schema, {}, {}, None, 0, set(), collections.Counter(), [], None,
            None, False, "", set(),
        )[0]), self.schema)

    def test_api_schema_match_does_not_require_model_readiness(self):
        with patch.object(collector, "fetch_json", return_value={
            "models_available": False,
            "feature_names": self.schema,
        }):
            self.assertEqual(collector.api_feature_schema("http://api", self.schema), self.schema)

    def test_normal_capture_posts_unscored_event_and_verifies_audit(self):
        original_exists = Path.exists
        clock = [0.0]
        posted = []

        def fake_monotonic():
            clock[0] += 0.1
            return clock[0]

        def exists(path):
            return path == Path("/proc/321") or original_exists(path)

        def fake_fetch_json(_base, route, payload=None, timeout=10):
            if route == "/api/model-info":
                return {"models_available": False, "feature_names": self.schema}
            if route == "/api/predict":
                posted.append(payload)
                return {
                    "decision": "REVIEW_REQUIRED",
                    "score_available": False,
                    "prediction_unavailable_reason": "MODEL_NOT_READY",
                    "model_probabilities": {"ensemble": None},
                }
            if route == "/api/audit?limit=200":
                return {"events": [{"event_id": posted[0]["event_id"]}]}
            raise AssertionError(f"Unexpected API route: {route}")

        with (
            patch.object(collector, "require_linux_runtime"),
            patch.object(collector.Path, "exists", autospec=True, side_effect=exists),
            patch.object(collector, "process_metadata", return_value=(321, "python", "python demo.py", "/home/demo")),
            patch.object(collector, "proc_start_ticks", return_value="987"),
            patch.object(collector, "io_snapshot", return_value={"syscr": 4, "syscw": 2}),
            patch.object(collector, "discover_probes", return_value=(set(collector.KNOWN_SYSCALLS), set(), True, "")),
            patch.object(collector, "fd_snapshot", return_value=(3, set(), True)),
            patch.object(collector, "tcp_snapshot", return_value=set()),
            patch.object(collector.os, "getuid", return_value=321, create=True),
            patch("subprocess.Popen", return_value=FakeTracer()),
            patch.object(collector.os, "killpg", create=True),
            patch.object(collector.time, "monotonic", side_effect=fake_monotonic),
            patch.object(collector.time, "sleep"),
            patch("queue.Queue.get", side_effect=queue.Empty),
            patch.object(collector, "fetch_json", side_effect=fake_fetch_json),
        ):
            result = collector.capture(321, 2, 0.25, "http://127.0.0.1:8001", None)

        self.assertEqual(len(posted), 1)
        self.assertEqual(list(posted[0]["features"]), self.schema)
        self.assertIsNone(posted[0]["features"]["Install__Total_Dependency_Count"])
        self.assertTrue(result["audit_record_verified"])
        self.assertFalse(result["score_available"])
        self.assertIsNone(result["ensemble_probability_provisional"])
        self.assertEqual(result["prediction_unavailable_reason"], "MODEL_NOT_READY")

    def test_procfs_ipv4_addresses_decode_in_little_and_big_endian(self):
        # procfs prints the numeric __be32 value, which follows host endianness.
        little_row = "0: 0100007F:1F90 08080808:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1"
        big_row = "0: 7F000001:1F90 08080808:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1"
        little = collector.parse_proc_tcp_line(little_row, 4, byteorder="little")
        big = collector.parse_proc_tcp_line(big_row, 4, byteorder="big")
        self.assertEqual(little[:4], ("127.0.0.1", 8080, "8.8.8.8", 443))
        self.assertEqual(big[:4], ("127.0.0.1", 8080, "8.8.8.8", 443))

    def test_procfs_ipv6_words_decode_in_s390x_big_endian(self):
        local_hex = "20010db8000000000000000000000001"
        remote_hex = "20010db8000000000000000000000002"
        row = f"0: {local_hex}:1F90 {remote_hex}:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 54321 1"
        parsed = collector.parse_proc_tcp_line(row, 6, byteorder="big")
        self.assertEqual(parsed[:4], ("2001:db8::1", 8080, "2001:db8::2", 443))

    def test_partial_capture_keeps_unobserved_features_null(self):
        features, groups = collector.build_features(
            self.schema,
            {"syscr": 5, "syscw": 1}, {"syscr": 7, "syscw": 2},
            4, 2, {1}, collections.Counter({"read": 2}), [], None, None,
            False, "/home/demo", {"read"}, {1},
        )
        self.assertEqual(list(features), self.schema)
        self.assertEqual(features["Filetop__Total_Reads"], 2)
        self.assertEqual(features["Filetop__Total_Writes"], 1)
        self.assertEqual(features["SysCall__Total_System_Calls"], 2)
        self.assertIsNone(features["SysCall__IO_Operations"])
        self.assertIsNone(features["Install__Total_Dependency_Count"])
        self.assertIsNone(features["TCP__Total_Entries"])
        self.assertNotIn("io", groups)

    def test_malformed_bpf_event_does_not_partially_mutate_capture(self):
        raw_ids, raw_count = set(), [0]
        syscall_counts, paths, errors = collections.Counter(), [], [0]
        with self.assertRaises(ValueError):
            collector.parse_bpf_line(
                "TG|77|RAW|not-an-id\n", 77, raw_ids, raw_count,
                syscall_counts, paths, errors,
            )
        self.assertEqual(raw_ids, set())
        self.assertEqual(raw_count, [0])
        self.assertEqual(syscall_counts, collections.Counter())
        self.assertEqual(paths, [])
        self.assertEqual(errors, [0])

    def test_telemetry_only_capture_writes_real_shape_without_api_or_score(self):
        original_exists = Path.exists
        clock = [0.0]

        def fake_monotonic():
            clock[0] += 0.1
            return clock[0]

        def exists(path):
            return path == Path("/proc/321") or original_exists(path)

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "telemetry.json"
            with (
                patch.object(collector, "require_linux_runtime"),
                patch.object(collector.Path, "exists", autospec=True, side_effect=exists),
                patch.object(collector, "process_metadata", return_value=(321, "python", "python demo.py", "/home/demo")),
                patch.object(collector, "proc_start_ticks", return_value="987"),
                patch.object(collector, "io_snapshot", return_value={"syscr": 4, "syscw": 2}),
                patch.object(collector, "discover_probes", return_value=(set(collector.KNOWN_SYSCALLS), set(), True, "")),
                patch.object(collector, "fd_snapshot", return_value=(3, set(), True)),
                patch.object(collector, "tcp_snapshot", return_value=set()),
                patch.object(collector.os, "getuid", return_value=321, create=True),
                patch("subprocess.Popen", return_value=FakeTracer()),
                patch.object(collector.os, "killpg", create=True) as killpg_mock,
                patch.object(collector.time, "monotonic", side_effect=fake_monotonic),
                patch.object(collector.time, "sleep"),
                patch("queue.Queue.get", side_effect=queue.Empty),
                patch.object(collector, "fetch_json", side_effect=AssertionError("telemetry-only mode called the API")),
            ):
                report = collector.capture(
                    321, 2, 0.25, "http://127.0.0.1:8001", None,
                    telemetry_only=True, output_path=str(report_path),
                )
                killpg_mock.assert_called_once_with(9876, collector.signal.SIGINT)

            self.assertEqual(report["collector_status"], "TELEMETRY_CAPTURED_NOT_SCORED")
            self.assertEqual(report["model_scoring"], "NOT RUN: telemetry-only mode")
            self.assertNotIn("decision", report)
            self.assertNotIn("model_probabilities", report)
            self.assertEqual(list(report["features"]), self.schema)
            self.assertEqual(report["measured_feature_count"] + report["missing_feature_count"], 48)
            self.assertIsNone(report["features"]["Install__Total_Dependency_Count"])
            self.assertEqual(report["missing_feature_count"], sum(v is None for v in report["features"].values()))
            saved = report_path.read_text(encoding="utf-8")
            self.assertTrue(saved.endswith("\n"))
            self.assertEqual(json.loads(saved)["collector_status"], "TELEMETRY_CAPTURED_NOT_SCORED")

    def test_telemetry_report_writer_refuses_to_overwrite_existing_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "report.json"
            destination.write_text("keep this file\n", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                collector.write_telemetry_report({"event_id": "evt-1"}, str(destination))
            self.assertEqual(destination.read_text(encoding="utf-8"), "keep this file\n")

    def test_output_path_is_rejected_for_scored_mode(self):
        with patch.object(collector, "require_linux_runtime"):
            with self.assertRaisesRegex(ValueError, "only supported with --telemetry-only"):
                collector.capture(77, 10, 0.5, "http://127.0.0.1:8001", None, output_path="report.json")


if __name__ == "__main__":
    unittest.main()
