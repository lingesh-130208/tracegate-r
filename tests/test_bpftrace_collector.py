import collections
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.tracegate_bpftrace_collector import (
    DIRECTORY_FEATURES, KNOWN_SYSCALLS, MAX_PATH_EVENTS, PATH_SYSCALLS, SYSCALL_GROUPS,
    build_bpf_program, build_features,
    bucket_paths, classify_path, io_delta, parse_bpf_line, parse_io,
    parse_proc_tcp_line, parse_socket_table, resolve_open_path, tcp_snapshot,
    enqueue_bpf_line, require_complete_event_queue, fd_snapshot,
)

SCHEMA = [
    "Filetop__Total_Reads", "Filetop__Total_Writes",
    "Filetop__Total_Read_Data_Transfer", "Filetop__Total_Write_Data_Transfer",
    "Install__Total_Dependency_Count", "Install__Direct_Dependency_Count",
    "Install__Indirect_Dependency_Count", "Opensnoop__Total_Paths",
    "Opensnoop__Total_Error", "Opensnoop__Total__File_Descriptor",
    "Opensnoop__Python_Related_Keywords", "Opensnoop__Install_Package_Keywords",
    "Opensnoop__Root_DIR_Installation", "Opensnoop__Temporary_DIR_Installation",
    "Opensnoop__Home_DIR_Installation", "Opensnoop__User_Access",
    "Opensnoop__Sys_Access", "Opensnoop__Etc_DIR_Installation",
    "Opensnoop__Other_DIR_Installation", "SysCall__Total_System_Calls",
    "SysCall__Unique_System_Calls", "SysCall__File_Operations",
    "SysCall__Unique_File_Operations", "SysCall__Memory_Operations",
    "SysCall__Unique_Memory_Operations", "SysCall__Network_Operations",
    "SysCall__Unique_Network_Operations", "SysCall__Process_Management_Operations",
    "SysCall__Unique_Process_Management_Operations", "SysCall__IO_Operations",
    "SysCall__Unique_IO_Operations", "SysCall__Time_Operations",
    "SysCall__Unique_Time_Operations", "SysCall__IPC_Operations",
    "SysCall__Unique_IPC_Operations", "SysCall__Filesystem_Operations",
    "SysCall__Unique_Filesystem_Operations", "SysCall__Security_Operations",
    "SysCall__Unique_Security_Operations", "SysCall__Miscellaneous_Operations",
    "SysCall__Unique_Miscellaneous_Operations", "TCP__Total_Entries",
    "TCP__Unique_C-COMM", "TCP__Python_Related_Process",
    "TCP__Local_IP_Address_Access", "TCP__Remote_IP_Address_Access",
    "TCP__Local_Port_Access", "TCP__Remote_Port_Access",
]


class BpftraceCollectorTests(unittest.TestCase):
    def test_collector_module_is_importable_for_cross_platform_unit_tests(self):
        # Windows lacks the POSIX ``pwd`` module. The collector's parsing and
        # program-generation helpers must remain importable for local tests.
        import scripts.tracegate_bpftrace_collector as collector
        self.assertTrue(callable(collector.build_bpf_program))

    def test_model_feature_order_matches_the_release_schema(self):
        schema_path = Path(__file__).resolve().parents[1] / "data" / "model_feature_names.json"
        release_schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(len(SCHEMA), 48)
        self.assertEqual(len(set(SCHEMA)), 48)
        self.assertEqual(release_schema, SCHEMA)

    def test_linux_runtime_capture_fails_clearly_on_windows(self):
        import scripts.tracegate_bpftrace_collector as collector
        with patch.object(collector.sys, "platform", "win32"):
            with self.assertRaisesRegex(OSError, "requires Linux procfs and bpftrace"):
                collector.capture(77, 10, 0.5, "http://127.0.0.1:8001", None)

    def test_proc_io_parse_and_nonnegative_delta(self):
        before = parse_io("syscr: 12\nsyscw: 4\nrchar: 500\nwchar: 80\n")
        after = parse_io("syscr: 19\nsyscw: 9\nrchar: 900\nwchar: 180\n")
        self.assertEqual(io_delta(before, after, "syscr"), 7)
        self.assertEqual(io_delta(before, after, "wchar"), 100)
        self.assertEqual(io_delta(after, before, "syscr"), 0)
        self.assertIsNone(io_delta(before, after, "missing"))

    def test_path_classification(self):
        self.assertEqual(classify_path("/root/.ssh/id_rsa", "/home/linux1"), "root")
        self.assertEqual(classify_path("/tmp/x.whl", "/home/linux1"), "temporary")
        self.assertEqual(classify_path("/home/linux1/a.py", "/home/linux1"), "home")
        self.assertEqual(classify_path("/usr/lib/python3.12/os.py", "/home/linux1"), "user")
        self.assertEqual(classify_path("/usr/bin/bash", "/home/linux1"), "other")
        self.assertEqual(classify_path("/opt/vendor/pkg.py", "/home/linux1"), "other")
        self.assertEqual(classify_path("/sys/fs/cgroup", "/home/linux1"), "sys")
        self.assertEqual(classify_path("/etc/hosts", "/home/linux1"), "etc")
        self.assertEqual(classify_path("/proc/self/status", "/home/linux1"), "other")
        self.assertIsNone(classify_path("relative.txt", "/home/linux1"))

    def test_relative_path_uses_dirfd_or_cwd(self):
        self.assertEqual(resolve_open_path(3, -100, "x.py", "/home/linux1/work"), "/home/linux1/work/x.py")
        self.assertEqual(resolve_open_path(3, -100, "/etc/hosts", "/tmp"), "/etc/hosts")

    def test_bucketed_paths_do_not_return_raw_pathnames(self):
        counts = bucket_paths([(-100, "/tmp/pip-build/demo.whl"), (-100, "/home/linux1/main.py"), (-100, "/etc/hosts")], "/home/linux1")
        self.assertEqual(counts["total_paths"], 3)
        self.assertEqual(counts["temporary"], 1)
        self.assertEqual(counts["home"], 1)
        self.assertEqual(counts["etc"], 1)
        self.assertEqual(counts["python_keywords"], 1)
        self.assertEqual(counts["install_keywords"], 1)
        self.assertNotIn("paths", counts)

    def test_proc_tcp_ipv4_row_and_inode_match(self):
        # /proc/net/tcp renders IPv4 words in native byte order. Build a
        # portable row so this test works on little-endian and s390x hosts.
        local_hex = f"{int.from_bytes(bytes((127, 0, 0, 1)), sys.byteorder):08X}"
        remote_hex = f"{int.from_bytes(bytes((127, 0, 0, 2)), sys.byteorder):08X}"
        row = f"  0: {local_hex}:1F90 {remote_hex}:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1"
        parsed = parse_proc_tcp_line(row, 4)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], "127.0.0.1")
        self.assertEqual(parsed[1], 8080)
        self.assertEqual(parsed[2], "127.0.0.2")
        self.assertEqual(parsed[3], 443)
        self.assertEqual(parsed[5], "12345")
        self.assertEqual(len(parse_socket_table("sl local rem st tx:rx tr:tm retr uid timeout inode\n" + row, 4, {"12345"})), 1)
        self.assertEqual(len(parse_socket_table("sl local rem st tx:rx tr:tm retr uid timeout inode\n" + row, 4, {"nope"})), 0)

    def test_proc_tcp_ipv6_row_on_host_byte_order(self):
        # 2001:db8::1 and 2001:db8::2, ports 8080 and 443, inode 54321.
        local_hex = "20010db8000000000000000000000001"
        remote_hex = "20010db8000000000000000000000002"
        local = "".join(f"{int(local_hex[i:i+8], 16).to_bytes(4, sys.byteorder).hex()}" for i in range(0, 32, 8))
        remote = "".join(f"{int(remote_hex[i:i+8], 16).to_bytes(4, sys.byteorder).hex()}" for i in range(0, 32, 8))
        row = f"  0: {local}:1F90 {remote}:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 54321 1"
        parsed = parse_proc_tcp_line(row, 6)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], "2001:db8::1")
        self.assertEqual(parsed[2], "2001:db8::2")
        self.assertEqual(parsed[5], "54321")

    def test_bpf_program_filters_to_one_pid_and_never_dumps_file_path_to_disk(self):
        program, traced, errors = build_bpf_program(77, {"openat", "connect", "read"}, {"openat"}, True)
        self.assertIn("pid == 77", program)
        self.assertIn("args.filename", program)
        self.assertIn("args.id", program)
        self.assertIn("args.__syscall_nr", program)
        self.assertIn("TG|%d|RAW|%ld", program)
        self.assertNotIn("args->", program)
        self.assertIn("OPENERR", program)
        self.assertEqual(traced, {"openat", "connect", "read"})
        self.assertFalse(errors)

    def test_bpf_program_captures_open_openat_openat2_and_creat_path_arguments(self):
        available = {"open", "openat", "openat2", "creat"}
        program, traced, errors = build_bpf_program(77, available, available, True)
        self.assertEqual(traced, available)
        self.assertTrue(errors)
        self.assertIn('TG|%d|OPEN|%d|%s', program)
        self.assertIn("args.filename", program)
        self.assertIn("args.pathname", program)
        self.assertEqual(PATH_SYSCALLS, available)

    def test_raw_syscall_tracepoint_is_required_for_total_counts(self):
        with self.assertRaisesRegex(RuntimeError, "raw_syscalls:sys_enter tracepoint is unavailable"):
            build_bpf_program(77, {"read", "openat"}, {"openat"}, False)

    def test_bpf_event_parser_counts_raw_and_named_calls(self):
        raw_ids, raw_total = set(), [0]
        calls, paths, errors, mapped_ids = collections.Counter(), [], [0], set()
        parse_bpf_line("TG|77|RAW|42\n", 77, raw_ids, raw_total, calls, paths, errors)
        parse_bpf_line("TG|77|RAW|42\n", 77, raw_ids, raw_total, calls, paths, errors)
        parse_bpf_line("TG|77|CALL|connect|42\n", 77, raw_ids, raw_total, calls, paths, errors, mapped_ids)
        parse_bpf_line("TG|77|OPEN|-100|/tmp/a.whl\n", 77, raw_ids, raw_total, calls, paths, errors)
        parse_bpf_line("TG|77|OPENERR|openat\n", 77, raw_ids, raw_total, calls, paths, errors)
        parse_bpf_line("TG|78|RAW|90\n", 77, raw_ids, raw_total, calls, paths, errors)
        self.assertEqual(raw_total[0], 2)
        self.assertEqual(raw_ids, {42})
        self.assertEqual(calls["connect"], 1)
        self.assertEqual(mapped_ids, {42})
        self.assertEqual(paths, [(-100, "/tmp/a.whl")])
        self.assertEqual(errors[0], 1)

    def test_malformed_bpf_records_fail_without_counting_partial_events(self):
        raw_ids, raw_total = set(), [0]
        calls, paths, errors, mapped_ids = collections.Counter(), [], [0], set()
        malformed = (
            "TG|77|RAW|bad\n",
            "TG|77|RAW|-1\n",
            "TG|+77|RAW|1\n",
            "TG|77|CALL|connect|bad\n",
            "TG|77|CALL|not_a_syscall|2\n",
            "TG|77|OPEN|not-a-fd|relative\n",
            "TG|77|OPEN|+3|relative\n",
            "TG|77|OPENERR|not-a-path-syscall\n",
            "TG|77|UNKNOWN|1\n",
        )
        for line in malformed:
            with self.subTest(line=line), self.assertRaises(ValueError):
                parse_bpf_line(line, 77, raw_ids, raw_total, calls, paths, errors, mapped_ids)
        self.assertEqual(raw_total, [0])
        self.assertEqual(raw_ids, set())
        self.assertEqual(calls, collections.Counter())
        self.assertEqual(paths, [])
        self.assertEqual(errors, [0])

    def test_proc_tcp_unreadable_means_unavailable_not_empty(self):
        with patch("scripts.tracegate_bpftrace_collector.Path.read_text", side_effect=PermissionError("denied")):
            self.assertIsNone(tcp_snapshot(77, {"12345"}))

    def test_inaccessible_descriptor_makes_tcp_fd_snapshot_incomplete(self):
        from pathlib import Path
        with patch("scripts.tracegate_bpftrace_collector.Path.iterdir", return_value=iter([Path("/proc/77/fd/3")])), \
                patch("scripts.tracegate_bpftrace_collector.os.readlink", side_effect=PermissionError("denied")):
            self.assertEqual(fd_snapshot(77), (1, set(), False))

    def test_event_queue_overflow_discards_capture(self):
        import queue
        import threading
        events = queue.Queue(maxsize=1)
        overflowed = threading.Event()
        enqueue_bpf_line(events, overflowed, "TG|77|RAW|1\n")
        enqueue_bpf_line(events, overflowed, "TG|77|RAW|2\n")
        with self.assertRaisesRegex(RuntimeError, "queue overflowed"):
            require_complete_event_queue(overflowed)

    def test_path_event_limit_rejects_partial_capture(self):
        raw_ids, raw_total = set(), [0]
        with self.assertRaisesRegex(RuntimeError, "Path event limit exceeded"):
            parse_bpf_line(
                "TG|77|OPEN|-100|/tmp/a\n", 77, raw_ids, raw_total,
                collections.Counter(), [(-100, "")] * MAX_PATH_EVENTS, [0],
            )

    def test_feature_builder_leaves_semantically_unmatched_fields_missing(self):
        before = {"syscr": 10, "syscw": 3}
        after = {"syscr": 15, "syscw": 9}
        counts = collections.Counter({"read": 5, "write": 6, "openat": 2, "connect": 1})
        complete_probes = set(KNOWN_SYSCALLS)
        features, groups = build_features(
            SCHEMA, before, after, 4, 16, {1, 2, 3}, counts,
            [(-100, "/tmp/setup.py")], 0,
            {("127.0.0.1", 1234, "8.8.8.8", 443, "01")}, True,
            "/home/linux1", complete_probes,
        )
        self.assertEqual(features["SysCall__Total_System_Calls"], 16)
        self.assertEqual(features["SysCall__Unique_System_Calls"], 3)
        self.assertEqual(features["SysCall__Network_Operations"], 1)
        self.assertEqual(features["SysCall__File_Operations"], 2)
        self.assertEqual(features["Filetop__Total_Reads"], 5)
        self.assertEqual(features["Filetop__Total_Writes"], 6)
        self.assertEqual(features["Opensnoop__Temporary_DIR_Installation"], 1)
        self.assertEqual(features["TCP__Remote_IP_Address_Access"], 1)
        self.assertIsNone(features["Filetop__Total_Read_Data_Transfer"])
        self.assertIsNone(features["Install__Total_Dependency_Count"])
        self.assertIsNone(features["SysCall__Unique_Miscellaneous_Operations"])
        self.assertIsNone(features["TCP__Unique_C-COMM"])
        self.assertEqual(set(features), set(SCHEMA))
        self.assertEqual(len(features), 48)

    def test_unique_miscellaneous_uses_measured_unmapped_syscall_ids(self):
        features, _ = build_features(
            SCHEMA, {"syscr": 1, "syscw": 1}, {"syscr": 1, "syscw": 2}, 2,
            4, {10, 11, 12}, collections.Counter({"read": 2, "connect": 1}),
            [], None, set(), False, "/home/linux1", set(KNOWN_SYSCALLS), {10, 11},
        )
        self.assertEqual(features["SysCall__Unique_Miscellaneous_Operations"], 1)

    def test_missing_syscall_group_is_not_reported_as_measured_zero(self):
        features, _ = build_features(SCHEMA, {"syscr": 0, "syscw": 0}, {"syscr": 0, "syscw": 0}, 0,
            0, set(), collections.Counter(), [], None, set(), False, "/home/linux1", {"openat"})
        self.assertIsNone(features["SysCall__Network_Operations"])
        self.assertIsNone(features["SysCall__File_Operations"])
        self.assertIsNone(features["SysCall__Miscellaneous_Operations"])
        self.assertIsNone(features["Opensnoop__Total_Paths"])
        self.assertEqual(features["SysCall__Total_System_Calls"], 0)

    def test_partial_named_syscall_group_keeps_group_features_missing(self):
        features, groups = build_features(
            SCHEMA, {"syscr": 0, "syscw": 0}, {"syscr": 0, "syscw": 0}, 0,
            1, {42}, collections.Counter({"connect": 1}), [], None, set(), False,
            "/home/linux1", {"connect"}, {42},
        )
        self.assertNotIn("network", groups)
        self.assertIsNone(features["SysCall__Network_Operations"])
        self.assertIsNone(features["SysCall__Unique_Network_Operations"])
        self.assertIsNone(features["SysCall__Miscellaneous_Operations"])
        self.assertIsNone(features["SysCall__Unique_Miscellaneous_Operations"])

    def test_complete_but_unobserved_probes_produce_measured_zeros(self):
        features, groups = build_features(
            SCHEMA, {"syscr": 1, "syscw": 2}, {"syscr": 1, "syscw": 2}, 0,
            0, set(), collections.Counter(), [], 0, set(), False,
            "/home/linux1", set(KNOWN_SYSCALLS), set(),
        )
        self.assertEqual(groups, set(SYSCALL_GROUPS))
        self.assertEqual(features["SysCall__File_Operations"], 0)
        self.assertEqual(features["SysCall__Network_Operations"], 0)
        self.assertEqual(features["Opensnoop__Total_Paths"], 0)
        self.assertEqual(features["TCP__Total_Entries"], 0)
        self.assertEqual(features["TCP__Local_IP_Address_Access"], 0)
        self.assertIsNone(features["TCP__Unique_C-COMM"])

    def test_missing_tcp_observation_keeps_all_tcp_features_null(self):
        features, _ = build_features(
            SCHEMA, {"syscr": 0, "syscw": 0}, {"syscr": 0, "syscw": 0}, 0,
            0, set(), collections.Counter(), [], None, None, False,
            "/home/linux1", set(KNOWN_SYSCALLS), set(),
        )
        for name in SCHEMA:
            if name.startswith("TCP__"):
                self.assertIsNone(features[name], name)


if __name__ == "__main__":
    unittest.main()
