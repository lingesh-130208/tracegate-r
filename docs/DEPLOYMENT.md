# LinuxONE deployment and rollback status

## Authorized candidate and identity gate

The authorized candidate is `linux1@148.100.79.31`. Ubuntu 24.04 and `s390x`
were previously observed, and the intended API binding is loopback-only on a
port other than 8000. The saved host-key record reports
`SHA256:l7WQnCpIeP23hRpzKzgm2qempmDDyjUhljetN6NNAUQ`; this is
trust-on-first-use, not independent host identity verification. Obtain the
fingerprint independently from an authorized IBM/provider source and compare
it before authenticating or running any remote command. Until then, do not
reconnect, transfer files, or deploy.

## Current verification state

A validation-only bundle with SHA-256
`0F2336B40E0D824E66A6289B04841963F4959BC4F6C6CFCC608E6CF311FF3F9A` was
previously tested in the isolated candidate directory
`/home/linux1/tracegate-validation-0f2336b40e0d`. The candidate full test suite
reported 120 passed and 67 subtests passed. This bundle contained uncommitted
worktree changes and is not the official release archive.

The candidate runtime smoke was partial: dashboard/assets, health, model
metadata, documentation, and anonymous denials responded; the isolated SQLite
file was later explicitly initialized and its restrictive mode checked. The
smoke script then stopped on a reused log filename. The candidate API listener
was stopped afterward. No candidate release promotion or port-8000 service or
database change was made. A separate bounded collector attempt reported
`PermissionError: [Errno 1] Operation not permitted`; the exact kernel
operation and missing permission were not established. No real
collector-to-API audit event was verified.

No trained models or authorized training dataset were found in the checked-in
source, original archive, available local branches, or documented local
artifact/data paths. Model inference remains unavailable; do not transfer
unverified models or claim scored predictions.

The only deployment procedures currently present in the checkout are six
untracked PowerShell files in the developer's working tree. They are not part
of the repository history; some push to `main`, use mutable release paths, or
contain stale readiness assumptions. Do not execute them as a release process.

## Model, collector, and platform gates

Model artifacts are trusted executable joblib inputs, not source files to
generate as placeholders. Keep `logistic_regression.joblib`,
`random_forest.joblib`, and `feature_names.json` outside the source archive in
an authorized artifact directory configured with `TRACEGATE_ARTIFACT_DIR`.
Record their origin, license/provenance, SHA-256 checksums, Python and
scikit-learn versions, and training-data/split details separately. Before
enabling inference, require the artifact feature list to exactly match
`data/model_feature_names.json` in order and verify estimator dimensions and
the expected benign/malicious class mapping. This checkout has no authorized
training dataset or reproducible training pipeline; do not claim scored model
inference until verified artifacts exist.

The LinuxONE collector requires Linux procfs, the expected syscall tracepoints,
`/usr/bin/bpftrace`, and narrowly authorized noninteractive permission to run
that tracer. It rejects foreign-UID targets and incomplete/lost captures. A
reported `EPERM` does not establish which operation was denied; inspect the
actual host policy and failing operation before considering a specific
capability or permission change. Do not run the application as root or grant
unrestricted privileges as a workaround.

Successful tests on `s390x` establish software compatibility only. They do
not prove IBM Telum hardware exposure, an installed accelerator runtime,
framework/model support, accelerator execution, or a performance benefit.
Record those independently before claiming hardware acceleration.

## Required release procedure

Before a future production switch, an operator with authorized access must:

1. Confirm the target host key, user, architecture, current branch commit, and
   available disk space. Inspect listeners on both 8001 and 8002 and identify
   each process by PID, command, and working directory; never stop an
   unidentified process.
2. Verify the candidate commit and test it locally. Transfer an archive made
   from that exact commit and record its SHA-256 in a release manifest. Keep
   model artifacts and runtime configuration outside the source release.
   After committing a clean tracked tree, generate the local manifest with
   `python scripts/build_release_manifest.py`. It records the actual commit,
   build timestamp, Python/dependency versions, schema hash, and model-artifact
   hash identifier when all required artifacts are present. It never creates
   model files and refuses to overwrite an existing manifest. The frontend
   bundle is generated and Git-ignored: run `npm ci` and `npm run build` in
   `frontend/` for that exact source revision, then include `frontend/dist/`
   alongside the release source. Verify the index and all referenced assets are
   present before candidate checks; an API release without the bundle serves a
   build-required response at `/`.
3. Create a new immutable release directory only after confirming the
   destination path does not already exist. Run candidate checks on an
   isolated port and an isolated temporary database.
4. Identify the live model artifacts and verify their schema, checksums, and
   class/feature compatibility. If artifacts or a trustworthy manifest are
   missing, do not claim model readiness.
5. Record the active release and process identity. Back up both SQLite
   databases using SQLite's online backup mechanism, validate the backups, and
   preserve the current release before switching.
6. Switch using the host's actual process manager or documented start
   convention. Do not invent a symlink or replace the service configuration.
7. Verify the active process path and commit manifest, `/health`,
   `/api/model-info`, `/api/genai/status`, dashboard, audit retrieval, and a
   controlled test event. Confirm the test used a separate database or
   explicitly validated production database handling.
8. Roll back to the recorded prior release if any acceptance check fails, then
   verify the prior process and database history.

The release-directory layout, current listeners, live model readiness,
backup/rollback, and service-manager behavior have not been verified for the
current candidate state. Deployment remains **BLOCKED** until the candidate
host key is independently verified and authorized access is available. Never
use port 8000 or the legacy database for candidate testing.
