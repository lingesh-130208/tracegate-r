from scripts.linuxone_preflight import classify_probe_result


def test_detects_operation_not_permitted():
    r = classify_probe_result(1, "", "ERROR: Operation not permitted")
    assert r["status"] == "BPFTRACE_PERMISSION_DENIED"


def test_detects_passwordless_sudo_requirement():
    assert classify_probe_result(1, "", "sudo: a password is required")["status"] == "BPFTRACE_PERMISSION_DENIED"


def test_detects_missing_binary():
    assert classify_probe_result(127, "", "[Errno 2] No such file or directory")["status"] == "BPFTRACE_MISSING"


def test_detects_unsupported_tracepoint():
    assert classify_probe_result(1, "", "No such tracepoint")["status"] == "BPFTRACE_TRACEPOINT_UNAVAILABLE"


def test_listing_success_is_not_called_capture_success():
    assert classify_probe_result(0, "tracepoint:raw_syscalls:sys_enter", "")["status"] == "BPFTRACE_OK"
