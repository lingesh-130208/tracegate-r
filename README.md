# TraceGate-R

**Evidence-Reliable Runtime Security and Predictive Decision System**  
IBM Z Datathon 2026 · Submission identifier: `SSF2026`

TraceGate-R is a prototype for evidence-aware software-behavior assessment. It combines two trained classifiers with an explicit evidence policy so a numeric model score is not automatically treated as a security verdict. Missing measurements, integrity alerts, or model disagreement can cause the event to be marked `REVIEW_REQUIRED`.

> **Honest status:** the API, model loading, evidence gate, SQLite audit workflow, offline deterministic explanations, and automated tests are implemented. The LinuxONE collector code is present, but complete parity between real runtime telemetry and all 48 training features remains to be validated. Do not describe the prototype as a production malware detector.

## Architecture

1. **Runtime observation:** Linux process telemetry from `/proc` and the LinuxONE bpftrace collector.
2. **Feature handling:** ordered 48-feature schema; unavailable values are represented as missing rather than fabricated.
3. **Prediction:** Logistic Regression and Random Forest each produce a malicious-class probability when supported by the input; the ensemble is the arithmetic mean of those probabilities. Model labels use a `0.5` threshold. Disagreement is reported when labels differ or the probability gap is at least `0.25`.
4. **Evidence gate:** checks evidence states and integrity alerts; incomplete or untrusted events can require human review.
5. **Audit:** persists prediction, evidence, policy decision, and alert information in SQLite.
6. **Explanation:** **Deterministic Evidence Explanation** is a local rules-based summary of recorded audit fields. It does not independently predict maliciousness, connect to an external generative LLM, or change the formal decision.

Human application roles are exactly `admin` and `user`. Both can sign in, access tenant-authorized audit events, submit observations, and request explanations. Only `admin` can manage users and tenants, through authenticated, CSRF-protected API routes. Backend authorization remains authoritative.

## Deployment and verification status

The LinuxONE candidate environment has not been promoted as a release. The
latest candidate runtime smoke did not complete, and independent host identity
verification is required before further remote actions. Do not infer a live
production deployment from unit tests or architecture compatibility; see
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for the release procedure.

Trained model artifacts are not included in this repository. Model-based
inference and end-to-end real telemetry-to-audit verification remain blocked.
Feature parity between the QUT-DV25 training pipeline and runtime telemetry,
and live malware-detection performance, remain unvalidated.

The static Vercel dashboard preview and its access/backend boundaries are
documented in [docs/VERCEL_PREVIEW.md](docs/VERCEL_PREVIEW.md). A preview UI
does not imply that a live API or telemetry source is connected.

## Repository layout

- `backend/app/main.py` — FastAPI routes, evidence decision, audit persistence
- `backend/app/model_service.py` — model and feature-schema loading and scoring
- `backend/app/evidence_gate.py` — evidence policy
- `backend/app/genai_explain.py` — local Deterministic Evidence Explanation engine
- `data/model_feature_names.json` — ordered feature schema
- `data/feature_provenance.json` — per-feature runtime source and parity state
- `frontend/src/` — React + TypeScript command console
- `frontend/dist/` — generated static site and FastAPI dashboard bundle (ignored by Git)
- `scripts/tracegate_bpftrace_collector.py` — general collector implementation
- `scripts/tracegate_bpftrace_collector.linuxone.py` — LinuxONE/s390x collector entry point
- `scripts/tracegate_proc_collector.py` — /proc-based collector
- `scripts/replay_qut.py` — recorded-data replay utility
- `tests/` — unit and API tests
- `docs/FEATURE_PROVENANCE.md` — feature mapping and validation limitations
- `docs/SECURITY.md` — local-only trust boundary and data handling
- `docs/DEPLOYMENT.md` — current verification state and safe release procedure

## Requirements

Python 3.11+ is recommended. Project dependencies are listed in `requirements.txt`. Linux runtime collection additionally needs a supported Linux kernel, suitable permissions, and compatible `bpftrace` probes. Windows can run the platform-independent parsing and unit tests but cannot execute the Linux runtime collector.

## Run the API

Use a virtual environment and install the repository dependencies:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The trained `.joblib` model files are deployment artifacts and are not assumed to be in this repository. Place the following files in a directory accessible to the API: `logistic_regression.joblib`, `random_forest.joblib`, and `feature_names.json`. The project also carries a schema file in `data/model_feature_names.json`, but model readiness requires the expected deployed artifacts.

Model readiness additionally requires the artifact feature list to exactly
match the ordered 48-feature release schema and both estimators to expose
compatible feature dimensions and benign/malicious classes. A checksum manifest
is recommended when packaging model artifacts.

Start the API with explicit artifact and database paths:

```bash
export TRACEGATE_ARTIFACT_DIR=/absolute/path/to/model-artifacts
export TRACEGATE_DB_PATH=/absolute/path/to/audit.sqlite3
cd frontend
npm ci
npm run build
cd ..
uvicorn backend.app.main:app --host 127.0.0.1 --port 8001
```

The frontend build requires Node.js 20.19+ or 22.12+; it was verified with
Node.js 24.22.0. FastAPI serves `frontend/dist/index.html` and its `/assets/`
bundle. If no build exists, `/` returns a build-required page instead of
serving uncompiled TypeScript. `frontend/dist/` is generated and ignored by
Git, so include the build output in a server release bundle after building the
exact candidate source revision.

On Windows PowerShell, from the repository root:

```powershell
Set-Location frontend
npm ci
npm run build
Set-Location ..
.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8001
```

### Windows local development (Vite frontend + FastAPI backend)

When running the React development server, the browser opens Vite on port 5173 while FastAPI listens on port 8000. The Vite config forwards `/health` and `/api/*` to FastAPI. Use two PowerShell terminals from the repository root.

**Optional — enable the live authenticated audit/write flow on a fresh local database.** Demo Mode works without an account. To use Live Mode, create the first local administrator once. This command refuses to run if the database already contains any user records; it is not a production bootstrap route.

```powershell
$env:TRACEGATE_BOOTSTRAP_USERNAME = Read-Host "Local admin username"
$securePassword = Read-Host "Choose a unique password (15+ characters)" -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
try { $env:TRACEGATE_BOOTSTRAP_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
.venv\Scripts\python.exe scripts\bootstrap_local_admin.py
Remove-Item Env:TRACEGATE_BOOTSTRAP_USERNAME
Remove-Item Env:TRACEGATE_BOOTSTRAP_PASSWORD
```

**Terminal 1 — start the backend for local HTTP development:**

```powershell
$env:TRACEGATE_COOKIE_SECURE = "false"
$env:TRACEGATE_ALLOWED_ORIGINS = "http://127.0.0.1:5173"
.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — start the frontend:**

```powershell
Set-Location frontend
npm run dev
```

Open exactly `http://127.0.0.1:5173/`. Keep both terminals running. The environment variables above are only for local development over HTTP; do not disable Secure cookies on an HTTPS deployment. If dependencies have not been installed yet, run `npm ci` from `frontend` first.

On a remote LinuxONE host, bind to loopback and access it through an SSH tunnel rather than exposing the development API publicly. Example from the client machine:

```bash
ssh -L 8001:127.0.0.1:8001 linux1@<linuxone-host>
```

Then open `http://127.0.0.1:8001/` locally.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Dashboard |
| GET | `/health` | Service and model readiness |
| GET | `/api/model-info` | Artifact and feature-schema status |
| POST | `/api/predict` | Predict from a supplied feature vector and apply evidence policy |
| POST | `/api/evaluate` | Evaluate an evidence/decision input |
| GET | `/api/audit?limit=30` | Read persisted audit events |
| GET | `/api/genai/status` | Deterministic Evidence Explanation status |
| POST | `/api/genai/explain` | Locally summarize an existing audit event using deterministic rules |

Interactive API documentation is available at `/docs` when the service is running.

## Run tests

From the repository root:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q tests
python scripts/build_feature_provenance.py --check
```

On Windows, run `.venv\\Scripts\\python.exe -m pytest -q tests`. Test counts
reported for earlier commits are historical and do not validate the current
checkout; record the actual command output and commit for each verification run.

## Open-source components

The repository imports or declares the following direct dependencies; check the pinned/range versions in `requirements.txt` for the working environment:

- **FastAPI** — API framework
- **Uvicorn** — ASGI server
- **NumPy** — numeric arrays
- **scikit-learn** — Logistic Regression / Random Forest model APIs and evaluation utilities
- **joblib** — persisted model loading
- **Pydantic** — request/response data validation (via FastAPI)
- **httpx / httpx2** — HTTP-related project/test dependencies as declared
- **pytest** — automated tests
- **bpftrace** — Linux runtime instrumentation when running the collector

Upstream project references: [FastAPI](https://github.com/fastapi/fastapi), [Uvicorn](https://github.com/encode/uvicorn), [NumPy](https://github.com/numpy/numpy), [scikit-learn](https://github.com/scikit-learn/scikit-learn), [joblib](https://github.com/joblib/joblib), [Pydantic](https://github.com/pydantic/pydantic), [HTTPX](https://github.com/encode/httpx), [pytest](https://github.com/pytest-dev/pytest), and [bpftrace](https://github.com/bpftrace/bpftrace).

## Known limitations / claims boundary

- Runtime collection is PID-scoped and may produce incomplete feature vectors.
- Training-time feature definitions and runtime aggregation parity have not been independently established for every feature.
- Missing values must not be replaced with guessed zeros or fabricated measurements.
- Offline benchmark and recorded-data replay metrics are not equivalent to live malware-detection performance.
- **Deterministic Evidence Explanation** is rules-based and generated locally from recorded event fields; it is not an external generative model and does not alter the formal decision.
- This repository/deployment does not by itself prove pervasive-encryption configuration, Crypto Express/HSM use, container-runtime deployment, or at-rest encryption status. Claim those only with independent host/platform evidence.
- A `REVIEW_REQUIRED` outcome requests human review; it is not a claim that a package is malicious or benign.
- Do not test on real malware or production processes without explicit authorization and a controlled environment.

## Submission and evidence

Submission code: `SSF2026`. Use genuine screenshots/video captured from the actual IBM Z target. Preserve terminal output proving `s390x`, test results, live API health, and real collector observations separately from synthetic smoke-test inputs. The short demo should clearly state what is measured, what remains missing, and why the evidence gate escalates uncertainty.


## Model training and LinuxONE diagnostics

The repository includes a reproducible QUT-DV25 model-training utility and read-only LinuxONE preflight. See [docs/TRAINING_MODELS.md](docs/TRAINING_MODELS.md) for dataset provenance, training commands, grouped holdout evaluation, safe artifact handling, and the limits of model and hardware claims. Model training was not completed for this submission: the automated dataset download returned HTTP 403 in the Windows environment. No trained-model metrics are claimed.
