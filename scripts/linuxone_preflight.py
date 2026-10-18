#!/usr/bin/env python3
"""Read-only TraceGate-R LinuxONE preflight. Never contacts legacy port 8000."""
import json, os, platform, shutil, socket, subprocess, urllib.error, urllib.request
from pathlib import Path

TRACEPOINT = "tracepoint:raw_syscalls:sys_enter"
MODELS = ("logistic_regression.joblib", "random_forest.joblib", "feature_names.json")


def classify_probe_result(returncode, stdout="", stderr="", timed_out=False):
    text = (stdout + "\n" + stderr).strip()
    low = text.casefold()
    if timed_out:
        status = "BPFTRACE_TIMEOUT"
    elif "not found" in low or "no such file or directory" in low:
        status = "BPFTRACE_MISSING"
    elif any(x in low for x in ("operation not permitted", "permission denied", "a password is required", "must have root", "not allowed to use sudo")):
        status = "BPFTRACE_PERMISSION_DENIED"
    elif "no such tracepoint" in low or "tracepoint not found" in low or "not traceable" in low:
        status = "BPFTRACE_TRACEPOINT_UNAVAILABLE"
    elif returncode == 0:
        status = "BPFTRACE_OK"
    else:
        status = "BPFTRACE_FAILED"
    return {"status": status, "returncode": returncode, "details": [x.strip()[:300] for x in text.splitlines()[-6:] if x.strip()]}


def run_readonly(command, timeout=8):
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, encoding="utf-8", errors="replace")
        return classify_probe_result(p.returncode, p.stdout, p.stderr)
    except FileNotFoundError as e:
        return classify_probe_result(127, "", str(e))
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return classify_probe_result(None, out, err, True)
    except OSError as e:
        return classify_probe_result(getattr(e, "errno", 1), "", f"{type(e).__name__}: {e}")


def listener(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            open_ = s.connect_ex(("127.0.0.1", port)) == 0
        except OSError as e:
            return {"port": port, "status": "CHECK_FAILED", "detail": str(e)[:200]}
    return {"port": port, "status": "LISTENER_PRESENT" if open_ else "NO_LOOPBACK_LISTENER"}


def api_get(path):
    try:
        req = urllib.request.Request("http://127.0.0.1:8001" + path, method="GET")
        with urllib.request.urlopen(req, timeout=2) as r:
            data = r.read(512 * 1024)
            try:
                body = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                body = None
            return {"http_status": r.status, "json": body}
    except urllib.error.HTTPError as e:
        return {"http_status": e.code, "error": f"HTTP {e.code}"}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"error": f"{type(e).__name__}: {str(e)[:200]}"}


def main():
    report = {
        "diagnostic": "TraceGate-R read-only LinuxONE preflight",
        "hostname": socket.gethostname(), "platform": platform.platform(),
        "architecture": platform.machine(), "python": platform.python_version(),
        "protected_port_8000": "NOT CONTACTED",
        "candidate_port_8001": listener(8001), "candidate_port_8002": listener(8002),
        "commands": {},
    }
    report["commands"]["uname"] = run_readonly(["uname", "-a"])
    report["commands"]["lscpu"] = run_readonly(["lscpu"])
    report["commands"]["bpftrace_version"] = run_readonly(["/usr/bin/bpftrace", "--version"])
    report["commands"]["bpftrace_tracepoint"] = run_readonly(["sudo", "-n", "/usr/bin/bpftrace", "-l", TRACEPOINT], 10)
    lscpu = subprocess.run(["lscpu"], capture_output=True, text=True, timeout=5, check=False) if shutil.which("lscpu") else None
    report["telum_nnpa_flag_visible"] = bool(lscpu and "nnpa" in (lscpu.stdout + lscpu.stderr).casefold())
    report["telum_note"] = "NNPA visibility is a prerequisite signal only; it does not prove accelerator execution."
    artifact_dir = Path(os.environ.get("TRACEGATE_ARTIFACT_DIR", str(Path.home() / "tracegate-live" / "artifacts"))).expanduser()
    report["artifact_directory"] = str(artifact_dir)
    report["model_artifacts"] = {n: {"exists": (artifact_dir/n).is_file(), "size_bytes": (artifact_dir/n).stat().st_size if (artifact_dir/n).is_file() else None} for n in MODELS}
    report["models_complete"] = all(v["exists"] for v in report["model_artifacts"].values())
    if report["candidate_port_8001"]["status"] == "LISTENER_PRESENT":
        report["api_health"] = api_get("/health")
        report["api_model_info"] = api_get("/api/model-info")
    else:
        report["api_health"] = {"status": "NOT_CHECKED_NO_LISTENER"}
        report["api_model_info"] = {"status": "NOT_CHECKED_NO_LISTENER"}
    report["safety_notes"] = [
        "Read-only checks only; no tracing attachment, service restart, deployment, file write, or permission mutation.",
        "Port 8000 is never contacted and remains reserved for the protected legacy service.",
        "Tracepoint listing does not prove that a real telemetry capture will succeed.",
        "NNPA flag visibility does not prove Telum-accelerated inference.",
    ]
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
