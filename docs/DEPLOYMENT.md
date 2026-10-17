# LinuxONE deployment and rollback status

## Target

The only authorized deployment target for this project is `linux1@148.100.77.225`.
The excluded address `148.100.79.31` must not be contacted. The API is intended
to bind to `127.0.0.1:8001` and be accessed through an SSH tunnel.

## Current verification state

The following paths and process details are from the most recent supplied
deployment record. They are **historical report**, not current server
inspection:

- Candidate API source: `/home/linux1/tracegate-stage-f92c618/tracegate-r-runtime-fixes`
- Prior release: `/home/linux1/tracegate-live/tracegate-r-offline-03639843ed`
- Virtual environment: `/home/linux1/tracegate-live/venv`
- Model artifacts: `/home/linux1/tracegate-live/artifacts`
- Audit database: `/home/linux1/.tracegate-r/audit.sqlite3`
- Explanation database: `/home/linux1/.tracegate-r/genai_explanations.sqlite3`
- Prior backup directory: `/home/linux1/tracegate-stage-f92c618/deploy-backup-20261017-142003`

The supplied baseline also reported an API on port 8001 and a staging listener
on port 8002. Neither listener, its process identity, nor these paths could be
rechecked from this checkout. A strict, noninteractive SSH check to the
authorized target using the configured `tracegate_friend` identity returned
`Permission denied (publickey)`. No deployment, process stop, database change,
or release-directory change was made.

The only deployment procedures currently present in the checkout are six
untracked PowerShell files in the developer's working tree. They are not part
of the repository history; some push to `main`, use mutable release paths, or
contain stale readiness assumptions. Do not execute them as a release process.

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

The release-directory layout and rollback have **not** been tested on the
current host. The exact release path, port-8002 owner, current process, live
model readiness, and database backup state remain **BLOCKED** until SSH access
to `148.100.77.225` is authorized.
