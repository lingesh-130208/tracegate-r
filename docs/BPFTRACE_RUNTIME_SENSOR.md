# TraceGate-R LinuxONE/s390x runtime sensor

## Status and evidence

- **Implemented and locally unit-tested:** the separate `scripts/tracegate_bpftrace_collector.linuxone.py` entry point, 48-feature ordering, procfs parsing for little- and big-endian IPv4, partial-feature null handling, malformed-event rejection, and telemetry-only JSON output. The telemetry-only test verifies that the collector makes no API call and emits no score or verdict.
- **Platform-specific behavior not run in this workspace:** actual bpftrace attachment and kernel event capture. The current development workspace is Windows; mocked collector tests do not establish LinuxONE runtime behavior.
- **LinuxONE result reported by the project owner:** Ubuntu 24.04/s390x, controlled 10-second workload, 1,656 syscall events, 10 unique raw IDs, 9 named syscall types, 675 file-open events, 20 measured features, and 28 missing features. The run emitted `TELEMETRY_CAPTURED_NOT_SCORED`. Its raw report is not present in this checkout, so this result is recorded as owner-reported rather than independently reproduced here.
- **Not verified:** QUT-DV25 feature-extraction parity, trained model artifacts on LinuxONE, model scoring, malware verdict quality, and live API/SQLite ingestion from bpftrace.

The canonical feature order is in `data/model_feature_names.json`. Features the runtime cannot measure stay `null`; in particular, this generic process capture cannot derive install dependency counts, the reference Filetop transfer units, or the validated `TCP__Unique_C-COMM` mapping. Partial telemetry is not a substitute for the dataset's feature extractor.

## Safe telemetry-only demo

Use the collector from the active LinuxONE release that contains both the script and `data/model_feature_names.json`. Choose a PID owned by the account running the collector and use a new report path for each run:

```bash
APP=/path/to/active/tracegate-r-release
PID=12345
REPORT="$HOME/tracegate-demo-$(date -u +%Y%m%dT%H%M%SZ).json"

uname -m
sudo -n /usr/bin/bpftrace -l 'tracepoint:raw_syscalls:sys_enter'
ps -p "$PID" -o pid,comm,args
python3 "$APP/scripts/tracegate_bpftrace_collector.linuxone.py" \
  --pid "$PID" --duration 10 --interval 0.5 \
  --telemetry-only --output "$REPORT"
```

Telemetry-only mode reads the local release schema and captures real kernel/procfs observations. It does not call the API, score the vector, create an API audit record, or emit a malware verdict. The report writer refuses to overwrite an existing file. Validate the report before presenting it:

```bash
python3 - "$REPORT" <<'PY'
import json, sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
features = report["features"]
missing = sorted(name for name, value in features.items() if value is None)
assert report["collector_status"] == "TELEMETRY_CAPTURED_NOT_SCORED"
assert len(features) == 48
assert report["measured_feature_count"] == sum(value is not None for value in features.values())
assert report["missing_feature_count"] == len(missing)
assert report["missing_features"] == missing
assert "decision" not in report and "model_probabilities" not in report
print(json.dumps({key: report[key] for key in (
    "collector_status", "syscall_events_observed", "unique_raw_syscall_ids",
    "named_syscall_types_observed", "file_open_events_observed",
    "measured_feature_count", "missing_feature_count", "missing_features",
)}, indent=2))
PY
```

The capture requires `/usr/bin/bpftrace`, syscall tracepoints, and passwordless `sudo -n bpftrace` permission. It refuses foreign-UID targets, PID reuse, malformed/lost events, and incomplete capture queues. It stores counts and nulls, not raw observed paths.

## API, dashboard, and audit conditions

The normal scored path omits `--telemetry-only`. It first requires `/api/model-info` to report available trained artifacts and the same ordered 48-feature schema, then submits through `/api/predict` and verifies the event in `/api/audit`. This checkout has no trained model artifacts in the repository or expected local artifact directory, and no `TRACEGATE_ARTIFACT_DIR` override is set. Therefore local scoring is unavailable; the API correctly fails closed instead of inventing a score. A telemetry-only report does not update the dashboard or SQLite audit trail.

Before using scored mode on a server, verify its `/health` and `/api/model-info` responses and confirm the dashboard's model status. A model score over this partial vector would still be provisional until feature-extraction parity is established; missing evidence and integrity alerts must keep the decision at `REVIEW_REQUIRED`.

The existing collector bounds its event queue and path list, checks target identity throughout capture, and rejects overflow or bpftrace-reported event loss. Captured paths are classified in memory only and are never written to the report or sent to the API.
