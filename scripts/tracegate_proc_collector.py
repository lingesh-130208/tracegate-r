import argparse, json, os, sys, time, urllib.request
from pathlib import Path
from datetime import datetime, timezone

def require_linux_proc():
    if not sys.platform.startswith("linux"):
        raise OSError("The procfs runtime collector requires Linux /proc; Windows supports parsing and unit tests only.")

def get_json(base, route, payload=None):
    data = None if payload is None else json.dumps(payload, allow_nan=False).encode()
    req = urllib.request.Request(base + route, data=data,
        headers={"Content-Type":"application/json"},
        method="GET" if data is None else "POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)

def io_counters_complete(counters):
    return all(
        isinstance(counters.get(key), int) and counters[key] >= 0
        for key in ("syscr", "syscw")
    )

def api_feature_schema(api, local_schema):
    info = get_json(api, "/api/model-info")
    schema = info.get("feature_names") if isinstance(info, dict) else None
    if (
        not isinstance(local_schema, list)
        or len(local_schema) != 48
        or any(not isinstance(name, str) or not name for name in local_schema)
        or len(set(local_schema)) != 48
    ):
        raise RuntimeError("Local release feature schema is invalid")
    if not isinstance(schema, list) or schema != local_schema:
        raise RuntimeError("API feature schema differs from the local 48-feature release schema")
    return schema

def snapshot(pid, names=None):
    require_linux_proc()
    root = Path("/proc") / str(pid)
    if not root.exists():
        raise ProcessLookupError(f"PID {pid} no longer exists")
    if root.stat().st_uid != os.getuid():
        raise PermissionError(f"PID {pid} is not owned by the current user")

    stat_text = (root / "stat").read_text()
    stat_tail = stat_text[stat_text.rfind(")") + 2:].split()
    if len(stat_tail) <= 19:
        raise RuntimeError("Could not read process start time from /proc")

    io = {}
    for line in (root / "io").read_text().splitlines():
        key, _, value = line.partition(":")
        try:
            io[key.strip()] = int(value.strip())
        except ValueError:
            pass

    counters = {key: io.get(key) for key in ("syscr", "syscw")}
    counters["start_ticks"] = stat_tail[19]
    return counters, io_counters_complete(counters)


def interval_features(before, after, names):
    """Map only read/write syscall-count deltas; keep unvalidated fields missing."""
    values = {name: None for name in names}
    if (
        before.get("start_ticks") is None
        or before.get("start_ticks") != after.get("start_ticks")
    ):
        return values
    for feature, counter in (
        ("Filetop__Total_Reads", "syscr"),
        ("Filetop__Total_Writes", "syscw"),
    ):
        if feature not in values:
            continue
        start, end = before.get(counter), after.get(counter)
        if (
            isinstance(start, int) and start >= 0
            and isinstance(end, int) and end >= 0
        ):
            if end >= start:
                values[feature] = end - start
    return values


def counters_reset(before, after):
    return any(
        isinstance(before.get(key), int)
        and isinstance(after.get(key), int)
        and after[key] < before[key]
        for key in ("syscr", "syscw")
    )

def main():
    try:
        require_linux_proc()
    except OSError as exc:
        raise SystemExit(str(exc)) from exc
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--api", default="http://127.0.0.1:8001")
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--interval", type=float, default=2)
    args = ap.parse_args()
    if (
        args.pid <= 1 or not 1 <= args.duration <= 300 or not .5 <= args.interval <= 30
        or args.duration / args.interval > 200
    ):
        raise SystemExit("Invalid PID, duration or interval")

    schema_path = Path(__file__).resolve().parent.parent / "data" / "model_feature_names.json"
    try:
        local_schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Local release feature schema is missing or invalid: {exc}") from exc
    feature_names = api_feature_schema(args.api, local_schema)

    ids = []
    end = time.monotonic() + args.duration
    previous, previous_ok = snapshot(args.pid, feature_names)
    expected_start_ticks = previous.get("start_ticks")
    if expected_start_ticks is None:
        raise RuntimeError("Could not establish process identity at capture start")
    while time.monotonic() < end:
        time.sleep(max(0, min(args.interval, end-time.monotonic())))
        current, io_ok = snapshot(args.pid, feature_names)
        if current.get("start_ticks") != expected_start_ticks:
            raise RuntimeError("PID identity changed during capture; stop and choose the current PID")
        features = interval_features(previous, current, feature_names)
        process_identity_stable = previous.get("start_ticks") == current.get("start_ticks")
        counter_reset = counters_reset(previous, current)
        file_interval_ok = previous_ok and io_ok and process_identity_stable and not counter_reset
        previous, previous_ok = current, io_ok
        event_id = f"runtime-{args.pid}-{time.time_ns()}"
        payload = {
            "event_id": event_id,
            "package_ref": f"procfs-pid-{args.pid}",
            "features": features,
            "evidence": {
                "file_activity": (
                    "present" if file_interval_ok else
                    "inconsistent" if counter_reset or not process_identity_stable else
                    "missing"
                ),
                "process_execution": "present" if process_identity_stable else "inconsistent",
                "system_calls": "missing",
                "network_behavior": "missing",
            },
            "integrity_alerts": [
                "PROCFS_LIMITED_SNAPSHOT",
                "SYSCALL_NETWORK_INSTRUMENTATION_UNAVAILABLE",
            ]
                + ([] if process_identity_stable else ["PROCESS_IDENTITY_CHANGED"])
                + ([] if not counter_reset else ["PROCFS_COUNTER_RESET"]),
        }
        start = time.perf_counter()
        result = get_json(args.api, "/api/predict", payload)
        ids.append(event_id)
        print(json.dumps({
            "event_id": event_id,
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "decision": result["decision"],
            "score_available": result.get("score_available", False),
            "prediction_unavailable_reason": result.get("prediction_unavailable_reason"),
            "malicious_probability": result["model_probabilities"]["ensemble"],
            "missing_feature_count": result["missing_feature_count"],
            "api_latency_ms": round((time.perf_counter()-start)*1000, 2),
        }))

    audit = get_json(args.api, "/api/audit?limit=200")
    saved = {x.get("event_id") for x in audit["events"]}
    found = sum(x in saved for x in ids)
    print(json.dumps({"events_sent":len(ids),"audit_records_verified":found,
                      "audit_ok":found == len(ids)}, indent=2))
    if not ids or found != len(ids):
        raise RuntimeError("Telemetry audit verification failed")

if __name__ == "__main__":
    main()
