# IBM Z Datathon submission draft

**Status:** Draft for review. This wording separates locally tested software behavior from the project-owner-reported LinuxONE capture. No trained-model result or live malware-detection claim is available from this checkout.

## Project summary

TraceGate-R is an evidence-aware runtime telemetry demonstrator for LinuxONE. Its bpftrace collector observes a bounded, PID-scoped window of syscall and procfs activity, maps observations into the project's ordered 48-feature schema, and preserves measurements it cannot establish as missing. A telemetry-only mode produces a local JSON report without model scoring or a malware verdict. The existing API adds a human-review gate, model-disagreement and integrity checks, and SQLite audit persistence when trained artifacts are available. The design makes measurement gaps visible instead of filling them with guessed values.

## What is implemented and tested

- The 48-feature release schema and its ordering are covered by tests.
- Collector parsing, malformed-event rejection, partial-probe behavior, null feature handling, Windows import/runtime guards, and telemetry-only report generation are covered by the local test suite.
- The telemetry-only test uses mocked procfs/bpftrace process interfaces. It verifies that no API call or score is produced; it is not a live kernel test.
- API/evidence/audit behavior is covered with controlled model results. The API fails closed with HTTP 503 when trained artifacts are unavailable.

## LinuxONE result supplied by the project owner

The supplied run record reports Ubuntu 24.04 on s390x and a controlled 10-second workload with 1,656 syscall events, 10 unique raw syscall IDs, 9 named syscall types, 675 file-open events, 20 measured features, and 28 missing features. The status was `TELEMETRY_CAPTURED_NOT_SCORED`. The raw report is not in this repository checkout, so these values should be presented as owner-reported results unless the report is attached to the submission and independently checked.

## Limitations and claims to avoid

- Trained model artifacts are absent from this checkout and local model readiness is false.
- No model score, malware verdict, trained-model benchmark, or live detection-accuracy result has been verified for the LinuxONE capture.
- Feature-extraction parity with QUT-DV25 is not validated. The runtime vector is partial and not a validated substitute for the dataset pipeline.
- Telemetry-only mode writes a local report. It does not populate the API dashboard or SQLite audit database.
- Do not describe the project as a validated malware detector, production EDR, or sandbox.

## Suggested demonstration

Run the documented [LinuxONE telemetry-only workflow](BPFTRACE_RUNTIME_SENSOR.md) on Ubuntu 24.04/s390x, preserve its JSON report, and show the raw observation counts alongside the measured/missing feature totals. Demonstrate that the report contains 48 ordered fields, missing values remain `null`, and no score or verdict appears. If the submission also requires live dashboard predictions and audit records, first restore and verify the trained artifacts on the target API, then run a separate scored integration and retain its API response and SQLite/audit verification. Do not present that second stage as completed until those checks pass.

## Proposed next work (not implemented)

Attach and validate the original LinuxONE JSON report; verify model artifacts and schema on the target host; establish feature-extraction parity against QUT-DV25; and only then run a separately labeled scored integration with audit verification. These steps are proposed follow-up work, not completed capabilities.

## Abstract draft

TraceGate-R explores evidence-aware runtime telemetry for LinuxONE. A bounded bpftrace collector maps observed process activity into a 48-feature security schema and keeps unavailable measurements explicitly missing. The API's evidence gate and SQLite audit trail are designed to prevent incomplete telemetry, model disagreement, or integrity alerts from being presented as a confident result. A telemetry-only workflow has been exercised with local tests, and the project owner reports a 10-second Ubuntu 24.04/s390x capture with 1,656 syscall events and 20 measured of 48 features. That capture was not scored. Trained artifacts, QUT-DV25 feature parity, and live detection accuracy remain unverified, so the project is presented as a transparent telemetry and review prototype rather than a validated malware detector.
