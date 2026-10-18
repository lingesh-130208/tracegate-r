# TraceGate-R engineering verification report

**Date:** 2026-10-18
**Verdict:** **NOT READY**

This report distinguishes local automated tests, a disposable local browser/API
check, and prior isolated LinuxONE candidate validation. It does not treat
synthetic observations as telemetry, unscored responses as model inference, or
software compatibility as Telum execution.

## Workstream verdicts

| Workstream | Status | Evidence and blocker |
|---|---|---|
| LinuxONE deployment | **PARTIALLY VERIFIED** | A prior validation-only bundle passed the candidate's full Linux suite. Candidate runtime smoke was incomplete. The saved SSH host key is trust-on-first-use, not independently verified; no fresh remote access or deployment was performed in this sprint. |
| ML model inference | **BLOCKED** | No authorized `logistic_regression.joblib`, `random_forest.joblib`, or artifact `feature_names.json` was found in the checkout, original archive, available local branches, or documented local artifact locations. The documented QUT-DV25 dataset path is absent. |
| Real telemetry → API → durable audit | **BLOCKED** | A prior bounded collector attempt reported `PermissionError: [Errno 1] Operation not permitted`; the exact denied operation was not established. No genuine collector event has been correlated with a persisted API audit record. |
| IBM Telum acceleration | **NOT DEMONSTRATED** | `s390x` test success does not establish Telum hardware, accessible accelerator runtime, supported model execution, utilization, or performance. No independently verified hardware/runtime evidence or benchmark is available. |

## Changes

- Preserved the earlier feature-contract readiness fix: canonical observations
  can be submitted for an explicitly unscored audit when model artifacts are
  missing; this does not enable Demo Mode writes or alter backend authorization.
- Preserved newline-stable schema provenance hashing and its regression test.
- Fixed the admin tenant-ID HTML validation pattern. Chromium's current
  Unicode-set regex parser rejected the previous pattern and logged a
  `SyntaxError`. The replacement was verified in the rebuilt browser UI, and a
  regression test checks the pattern using the `v` regex mode.
- Corrected stale LinuxONE target and identity statements in the README,
  deployment, and security documentation. Added the collector permission
  limitation to the runtime sensor documentation and documented model,
  collector, and Telum verification gates.

Changed tracked files:

- `README.md`
- `backend/app/model_service.py`
- `backend/app/schema_provenance.py` (new)
- `docs/BPFTRACE_RUNTIME_SENSOR.md`
- `docs/DEPLOYMENT.md`
- `docs/FEATURE_PROVENANCE.md`
- `docs/SECURITY.md`
- `frontend/src/App.test.tsx`
- `frontend/src/App.tsx`
- `frontend/src/lib/api.test.ts`
- `frontend/src/lib/api.ts`
- `scripts/build_feature_provenance.py`
- `tests/test_feature_provenance.py`

The six protected PowerShell files remain untracked and were not opened,
executed, modified, renamed, deleted, staged, or committed. No files were
staged, no commit or push was made, and no official release archive was
created.

## Local verification

| Command or exercise | Result |
|---|---|
| `.\.venv\Scripts\python.exe -m pytest -q tests` | **116 passed, 4 skipped, 67 subtests passed** |
| `.\.venv\Scripts\python.exe scripts\build_feature_provenance.py --check` | **Passed**; manifest current |
| `npm.cmd test` (from `frontend`) | **24 passed** in 3 test files |
| `npm.cmd run typecheck` (from `frontend`) | **Passed** |
| `npm.cmd run build` (from `frontend`) | **Passed**; Vite transformed 1,928 modules |
| `git diff --check` | **Passed**; Git emitted only LF-to-CRLF conversion warnings |

A disposable local API/UI instance ran on loopback port 8013 with a separate
temporary SQLite database and no model artifacts. The live browser checks
used a disposable test administrator and synthetic input:

- All six workspaces rendered in Demo Mode; observed Demo Mode requests to
  `/api/*`: **0**. The prediction-submit button remained disabled, the
  synthetic draft loaded locally, and the feature matrix selection responded.
- Live sign-in succeeded through the real application login route. A
  canonical observation with one supplied feature was accepted with
  `score_available: false`, 47 missing features, and `REVIEW_REQUIRED`.
  The same event appeared in the tenant-authorized audit view.
- Deterministic Evidence Explanation was generated for that event; the
  recorded decision and provenance remained unchanged.
- Tenant creation and invitation creation returned successfully. The
  password-reset action was correctly disabled for the pending, inactive
  invitation; that UI action was not tested on an active target account.
- Admin enable/disable and role-change controls were not separately exercised
  in the browser. The browser automation also timed out trying to scroll to an
  off-screen admin row; this is an incomplete UI check, not evidence that those
  controls fail. This report does not claim click-by-click verification of
  every control.
- Logout returned HTTP 200. After logout, `/health` returned 200 and
  `/api/audit` returned 401.
- The rebuilt tenant-ID pattern accepted a valid ID in Chromium without a
  console error. At viewport widths 390, 768, and 1440 CSS pixels, measured
  document width did not exceed viewport width.

This is synthetic local integration, not real telemetry or model inference.
The initial shared page at port 5174 had no listener. The temporary API and
database were removed after testing; ports 5174, 8012, 8013, and 8000 had no
listener at final cleanup. Port 8000 was not used or modified.

The first version of the new frontend regression assertion failed because its
plain JavaScript regex test did not model the full-value matching applied by
HTML `pattern`; the assertion was anchored to that browser behavior and
rerun. A separate PowerShell probe used `-SkipHttpErrorCheck`, which is not
available in this installed PowerShell version; the anonymous 401 result was
verified later through the browser. These were test-harness issues, not
application failures.

## LinuxONE evidence and limitations

- Authorized candidate: `linux1@148.100.79.31`; Ubuntu 24.04 and `s390x` were
  previously observed.
- Saved host-key fingerprint:
  `SHA256:l7WQnCpIeP23hRpzKzgm2qempmDDyjUhljetN6NNAUQ`. This is
  **trust-on-first-use**, not independent verification. Obtain the candidate
  fingerprint independently from an authorized IBM/provider source before
  any further SSH authentication or deployment.
- Prior validation-only bundle SHA-256:
  `0F2336B40E0D824E66A6289B04841963F4959BC4F6C6CFCC608E6CF311FF3F9A`.
  It was not the original release and contained uncommitted worktree changes.
  Its candidate full test run reported **120 passed, 67 subtests passed**, with
  one Starlette/httpx deprecation warning.
- Candidate runtime smoke was partial. Dashboard/assets, health, model
  metadata, documentation, and anonymous denials responded. The candidate's
  isolated SQLite file was explicitly initialized and checked for restrictive
  permissions. The smoke script then stopped because it reused an existing
  log filename. The candidate API listener was stopped; there was no release
  promotion, legacy-service restart, or legacy-database change.
- No genuine telemetry-to-audit evidence, candidate model artifacts, backup /
  rollback exercise, or candidate Telum benchmark is available.
- No SSH or other remote command was issued during this sprint. A previously
  recorded SSH invocation mistakenly targeted the prohibited old address
  `148.100.77.225`; strict host-key checking rejected it before authentication
  or a remote command. It was not retried.

The original source archive remains unchanged:
`%TEMP%\tracegate-r-source-4f61238.zip`, SHA-256
`3E036EEB6CB8D4400DC1A9D3702983AC42B0324044FD6215671762BF4A8F0F2C`.
The starting HEAD for this verification was
`4f61238bfff87cb17990776d0b06c26fab8e6390` on
`tracegate-r-runtime-fixes`.

## GitHub delivery

The reviewed changes were committed on the existing private branch
`tracegate-r-runtime-fixes` as `073e7975860d6380841713c93bd34d38d318aee2`
(`Fix tenant validation and document release verification`) and pushed normally
to `origin`. The remote branch resolved to the same commit immediately after
the push. The report's final GitHub-status documentation update is recorded in
the follow-up report-only commit; the exact current branch tip is reported in
the final response. No force push or change to repository visibility occurred.
Deployment to the candidate was not performed.

## Remaining requirements

1. Obtain independent host-key verification for `148.100.79.31` from an
   authorized provider source before remote access.
2. Obtain authorized, provenance-documented model artifacts or the licensed
   training dataset and reproducible training pipeline; validate the models
   on the target architecture and exact feature contract.
3. Diagnose the precise Linux kernel operation behind `EPERM`, then run a
   bounded benign capture and correlate a genuine event through authenticated
   API ingestion to durable audit retrieval.
4. Verify the candidate's current services, release state, model readiness,
   backup/rollback, and loopback-only runtime after host identity is
   independently established.
5. Obtain actual Telum hardware/runtime support and execution evidence before
   making acceleration claims.
6. Obtain a written organizer ruling. **IBM Datathon eligibility remains
   unresolved until that ruling is received.**
