# Security and trust boundary

## Authentication and authorization

Human application accounts have exactly two roles:

- **admin** can use normal application features and, through authenticated
  CSRF-protected administrator routes, manage users and tenants.
- **user** can sign in, access audit records for their tenant, submit
  observations, and request event explanations. A user cannot manage users or
  tenants.

Authorization is enforced by the FastAPI routes; hiding an interface control is
not an authorization boundary. Browser sessions use opaque HttpOnly cookies,
server-side expiry/revocation, CSRF validation for writes, password hashing,
login/write rate limits, and safeguards against removing the last active
administrator. Collector bearer-token authentication is a distinct service
identity and is not a third human role. Existing `analyst` and `viewer`
accounts are mapped to `user` by versioned schema migration; unknown role
values are rejected.

Continue to bind Uvicorn to `127.0.0.1` and access the dashboard through an
authorized SSH tunnel unless a separately reviewed deployment provides
verified HTTPS ingress and suitable operational controls. The LinuxONE host
and its current service state were not re-inspected from this checkout because
SSH public-key authentication was denied. Do not treat the current frontend or
this documentation as independent verification of a live deployment.

## Data handling

- The collectors send aggregate feature values, evidence states, and integrity
  alerts. The bpftrace collectors classify raw file paths in memory and do not
  include the path strings in reports or API payloads.
- The prediction API stores package reference, scores when available, evidence,
  alerts, and the formal decision in SQLite. Do not put secrets, raw command
  lines, or raw file paths in `package_ref` or integrity alerts.
- **Deterministic Evidence Explanation** is a local, rules-based summary of
  recorded audit fields. It does not independently predict maliciousness, use
  an external generative LLM, or change the formal decision. Explanations are
  stored separately in `~/.tracegate-r/genai_explanations.sqlite3`.
- On POSIX hosts, newly created SQLite storage directories are restricted to
  the application user (mode `0700`), and database/journal files to that user
  (mode `0600`). Existing database directories and database files are
  validated before opening; unsafe ownership or permissions fail closed and
  are never silently changed. SQLite sidecars are confined by the private
  directory, checked for regular-file ownership, and newly created sidecars
  are restricted after use. Secure existing directories or databases
  administratively before restarting. Windows development skips POSIX mode
  checks and uses the platform's filesystem access controls.
- Database encryption, retention automation, and deletion/export endpoints are
  not implemented. Protect database files with host filesystem permissions
  and verified backups. Tenant isolation for authenticated application reads
  is enforced server-side.

## Secrets and model files

Keep SSH private keys, API credentials, and deployment environment files out of
the repository. Configure artifact and database locations through environment
variables. Treat joblib/pickle model artifacts as trusted executable inputs;
load only artifacts from an authorized, verified source.
