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

def snapshot(pid, names):
    require_linux_proc()
    root = Path("/proc") / str(pid)
    if not root.exists():
        raise ProcessLookupError(f"PID {pid} no longer exists")

    io = {}
    for line in (root / "io").read_text().splitlines():
        key, _, value = line.partition(":")
        try:
            io[key.strip()] = int(value.strip())
        except ValueError:
            pass

    fds = list((root / "fd").iterdir())
    values = {n: None for n in names}
    raw = {
        "Filetop__Total_Reads": io.get("syscr"),
        "Filetop__Total_Writes": io.get("syscw"),
        "Filetop__Total_Read_Data_Transfer": io.get("rchar"),
        "Filetop__Total_Write_Data_Transfer": io.get("wchar"),
        "Opensnoop__Total__File_Descriptor": len(fds),
        "SysCall__File_Operations": io.get("syscr", 0) + io.get("syscw", 0),
        "SysCall__IO_Operations": io.get("syscr", 0) + io.get("syscw", 0),
    }
    values.update({k:v for k,v in raw.items() if k in values})

    # Deliberately do not fabricate unsupported model features.
    return values, bool(io)

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
    if args.pid <= 1 or not 1 <= args.duration <= 300 or not .5 <= args.interval <= 30:
        raise SystemExit("Invalid PID, duration or interval")

    info = get_json(args.api, "/api/model-info")
    if not info.get("models_available") or len(info["feature_names"]) != 48:
        raise RuntimeError("Trained models or 48-feature schema unavailable")

    ids = []
    end = time.monotonic() + args.duration
    while time.monotonic() < end:
        features, io_ok = snapshot(args.pid, info["feature_names"])
        event_id = f"runtime-{args.pid}-{time.time_ns()}"
        payload = {
            "event_id": event_id,
            "package_ref": f"procfs-pid-{args.pid}",
            "features": features,
            "evidence": {
                "file_activity": "present" if io_ok else "missing",
                "process_execution": "present",
                "system_calls": "missing",
                "network_behavior": "missing",
            },
            "integrity_alerts": [
                "PROCFS_LIMITED_SNAPSHOT",
                "SYSCALL_NETWORK_INSTRUMENTATION_UNAVAILABLE",
            ],
        }
        start = time.perf_counter()
        result = get_json(args.api, "/api/predict", payload)
        ids.append(event_id)
        print(json.dumps({
            "event_id": event_id,
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "decision": result["decision"],
            "malicious_probability": result["model_probabilities"]["ensemble"],
            "missing_feature_count": result["missing_feature_count"],
            "api_latency_ms": round((time.perf_counter()-start)*1000, 2),
        }))
        time.sleep(max(0, min(args.interval, end-time.monotonic())))

    audit = get_json(args.api, "/api/audit?limit=200")
    saved = {x.get("event_id") for x in audit["events"]}
    found = sum(x in saved for x in ids)
    print(json.dumps({"events_sent":len(ids),"audit_records_verified":found,
                      "audit_ok":found == len(ids)}, indent=2))
    if not ids or found != len(ids):
        raise RuntimeError("Telemetry audit verification failed")

if __name__ == "__main__":
    main()
