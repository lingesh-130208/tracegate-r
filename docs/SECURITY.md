# Security and trust boundary

## Supported demonstration boundary

The current prototype is supported as a **single-operator, loopback-only
demonstration**. Run Uvicorn bound to `127.0.0.1` and reach the dashboard using
an SSH tunnel from an authorized workstation. The API currently has no
backend-backed analyst authentication or per-user authorization. Anyone who
can connect to the API listener can read audit records and submit evaluations;
therefore the API must not be bound to a public interface or exposed through an
unauthenticated reverse proxy.

For the previously reported LinuxONE setup, the trust boundary was the SSH
account `linux1` and its host access. That configuration was not re-inspected
in this checkout because SSH public-key authentication was denied. If the
service is shared by multiple analysts or exposed beyond loopback, implement
and test real server-side authentication, authorization, CSRF protections for
cookie sessions, and rate limiting before deployment. A frontend-only login
does not satisfy that requirement.

## Data handling

- The collectors send aggregate feature values, evidence states, and integrity
  alerts. The bpftrace collectors classify raw file paths in memory and do not
  include the path strings in reports or API payloads.
- The prediction API stores package reference, scores when available, evidence,
  alerts, and the formal decision in SQLite. Do not put secrets, raw command
  lines, or raw file paths in `package_ref` or integrity alerts.
- Deterministic explanations are stored separately in
  `~/.tracegate-r/genai_explanations.sqlite3` and do not change decisions.
- Database encryption, retention automation, user-level access control, and
  deletion/export endpoints are not implemented. Protect the database files
  with host filesystem permissions and verified backups.

## Secrets and model files

Keep SSH private keys, API credentials, and deployment environment files out of
the repository. Configure artifact and database locations through environment
variables. Treat joblib/pickle model artifacts as trusted executable inputs;
load only artifacts from an authorized, verified source.
