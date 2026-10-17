"""TraceGate-R API, decision gate, and SQLite audit trail."""
import json
import math
import os
import sqlite3
from contextlib import contextmanager
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator

from backend.app.evidence_gate import evaluate_evidence
from backend.app.model_service import (
    ModelsUnavailableError,
    model_info,
    predict_models,
    release_feature_names,
    release_schema_sha256,
)

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = Path(os.environ.get(
    "TRACEGATE_DB_PATH",
    str(Path.home() / ".tracegate-r" / "audit.sqlite3"),
))

app = FastAPI(
    title="TraceGate-R",
    version="0.2.0",
    description="Evidence reliability and model-disagreement checks for software security.",
)


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(_request, exc):
    """Return bounded validation details without echoing unsafe request values."""
    details = []
    for error in exc.errors():
        location = error.get("loc", ())
        details.append({
            "loc": [part if isinstance(part, (str, int)) else str(part) for part in location],
            "msg": str(error.get("msg", "Invalid request.")),
            "type": str(error.get("type", "validation_error")),
        })
    return JSONResponse(status_code=422, content={"detail": details})


@contextmanager
def db_connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        _ensure_schema(conn)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _ensure_schema(db):
    db.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                package_ref TEXT,
                model_verdict TEXT NOT NULL,
                decision TEXT NOT NULL,
                logistic_probability REAL,
                random_forest_probability REAL,
                ensemble_probability REAL,
                probability_gap REAL,
                coverage_percent REAL,
                reasons_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                alerts_json TEXT NOT NULL
            )
        """)
    # Additive migrations preserve existing audit records and allow the API to
    # retain the exact observation even when trained artifacts are unavailable.
    columns = {
        row["name"] for row in db.execute("PRAGMA table_info(audit_events)")
    }
    migrations = {
        "features_json": "TEXT NOT NULL DEFAULT '{}'",
        "missing_features_json": "TEXT NOT NULL DEFAULT '[]'",
        "model_labels_json": "TEXT NOT NULL DEFAULT '{}'",
        "model_disagreement": "INTEGER NOT NULL DEFAULT 0",
        "score_available": "INTEGER NOT NULL DEFAULT 0",
        "prediction_unavailable_reason": "TEXT",
        "provided_feature_count": "INTEGER NOT NULL DEFAULT 0",
        "expected_feature_count": "INTEGER NOT NULL DEFAULT 0",
        "missing_feature_count": "INTEGER NOT NULL DEFAULT 0",
        "schema_sha256": "TEXT",
    }
    for name, column_type in migrations.items():
        if name not in columns:
            db.execute(f"ALTER TABLE audit_events ADD COLUMN {name} {column_type}")


def init_db():
    """Initialize or safely migrate the configured SQLite audit database."""
    with db_connect():
        pass


class EvaluateRequest(BaseModel):
    model_verdict: str
    evidence: dict[str, str] = Field(default_factory=dict)
    integrity_alerts: list[str] = Field(default_factory=list)


class PredictRequest(BaseModel):
    event_id: str | None = Field(default=None, max_length=100)
    package_ref: str | None = Field(default=None, max_length=200)
    features: dict[str, float | None] = Field(min_length=1)
    evidence: dict[str, str] = Field(default_factory=dict)
    integrity_alerts: list[str] = Field(default_factory=list)

    @field_validator("features", mode="before")
    @classmethod
    def validate_feature_scalars(cls, value):
        if not isinstance(value, dict):
            return value
        for name, number in value.items():
            if number is None:
                continue
            if isinstance(number, bool) or not isinstance(number, (int, float)):
                raise ValueError(f"Feature {name!r} must be a JSON number or null.")
            try:
                is_finite = math.isfinite(number)
            except OverflowError:
                is_finite = False
            if not is_finite:
                raise ValueError(f"Feature {name!r} must be finite or null.")
        return value


def persist_prediction(event_id, package_ref, features, missing_features, result, evidence, alerts):
    probabilities = result["model_probabilities"]
    with db_connect() as db:
        db.execute("""
            INSERT INTO audit_events (
                event_id, created_at, package_ref, model_verdict, decision,
                logistic_probability, random_forest_probability,
                ensemble_probability, probability_gap, coverage_percent,
                reasons_json, evidence_json, alerts_json, features_json,
                missing_features_json, model_labels_json, model_disagreement,
                score_available, prediction_unavailable_reason,
                provided_feature_count, expected_feature_count,
                missing_feature_count, schema_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            result["created_at"],
            package_ref,
            result["model_verdict"],
            result["decision"],
            probabilities["logistic_regression"],
            probabilities["random_forest"],
            probabilities["ensemble"],
            result["probability_gap"],
            result["coverage_percent"],
            json.dumps(result["reason_codes"]),
            json.dumps(evidence),
            json.dumps(alerts),
            json.dumps(features, allow_nan=False, sort_keys=True),
            json.dumps(missing_features),
            json.dumps(result["model_labels"]),
            int(result["model_disagreement"]),
            int(result["score_available"]),
            result["prediction_unavailable_reason"],
            result["provided_feature_count"],
            result["expected_feature_count"],
            result["missing_feature_count"],
            result["schema_sha256"],
        ))


@app.get("/")
def dashboard():
    page = ROOT / "frontend" / "index.html"
    if not page.is_file():
        return {"service": "TraceGate-R", "dashboard": "not installed"}
    return FileResponse(page)


@app.get("/health")
def health():
    info = model_info()
    return {
        "status": "ok",
        "service": "tracegate-r",
        "model_ready": info["models_available"],
        "feature_count": info["feature_count"],
    }


@app.get("/api/model-info")
def get_model_info():
    return model_info()


@app.post("/api/evaluate")
def evaluate(request: EvaluateRequest):
    try:
        return evaluate_evidence(
            evidence=request.evidence,
            model_verdict=request.model_verdict,
            integrity_alerts=request.integrity_alerts,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/predict")
def predict(request: PredictRequest):
    event_id = (request.event_id or str(uuid.uuid4())).strip()
    if not event_id:
        raise HTTPException(status_code=422, detail="event_id cannot be blank")

    package_ref = (request.package_ref or "").strip() or None
    if package_ref and len(package_ref) > 200:
        raise HTTPException(status_code=422, detail="package_ref is too long")

    try:
        feature_names = release_feature_names()
    except ModelsUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    unknown = sorted(set(request.features) - set(feature_names))
    if unknown:
        raise HTTPException(
            status_code=422,
            detail="Unknown feature names: " + ", ".join(unknown[:10]),
        )
    missing_features = [
        name for name in feature_names if request.features.get(name) is None
    ]
    provided_feature_count = len(feature_names) - len(missing_features)

    try:
        model_result = predict_models(request.features)
    except ModelsUnavailableError:
        # Keep the observation and review decision even when this host has no
        # verified trained model artifacts. Never invent probabilities/labels.
        model_result = {
            "prediction_available": False,
            "prediction_unavailable_reason": "MODEL_NOT_READY",
            "logistic_probability_malicious": None,
            "random_forest_probability_malicious": None,
            "ensemble_probability_malicious": None,
            "logistic_label": None,
            "random_forest_label": None,
            "probability_gap": None,
            "model_disagreement": False,
            "missing_features": missing_features,
            "feature_count": len(feature_names),
            "provided_feature_count": provided_feature_count,
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    alerts = list(request.integrity_alerts)
    if model_result["missing_features"]:
        alerts.append(
            f"FEATURE_VECTOR_INCOMPLETE:{len(model_result['missing_features'])}"
        )
    score_available = model_result["prediction_available"]
    if not score_available:
        alerts.append(model_result["prediction_unavailable_reason"])
        verdict = "unknown"
    elif model_result["model_disagreement"]:
        alerts.append("MODEL_DISAGREEMENT")
    probability = model_result["ensemble_probability_malicious"]
    if score_available:
        verdict = "malicious" if probability >= 0.5 else "benign"

    try:
        gate = evaluate_evidence(request.evidence, verdict, alerts)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    created_at = datetime.now(timezone.utc).isoformat()
    result = {
        **gate,
        "event_id": event_id,
        "package_ref": package_ref,
        "created_at": created_at,
        "model_probabilities": {
            "logistic_regression":
                model_result["logistic_probability_malicious"],
            "random_forest":
                model_result["random_forest_probability_malicious"],
            "ensemble": probability,
        },
        "model_labels": {
            "logistic_regression": model_result["logistic_label"],
            "random_forest": model_result["random_forest_label"],
        },
        "model_disagreement": model_result["model_disagreement"],
        "score_available": score_available,
        "prediction_unavailable_reason": model_result["prediction_unavailable_reason"],
        "probability_gap": model_result["probability_gap"],
        "provided_feature_count": model_result["provided_feature_count"],
        "expected_feature_count": model_result["feature_count"],
        "missing_feature_count": len(model_result["missing_features"]),
        "missing_features": model_result["missing_features"],
        "schema_sha256": release_schema_sha256(),
        "policy_note": (
            "EVIDENCE_SUFFICIENT means the supplied evidence passed this gate; "
            "it does not guarantee the package is safe."
        ),
    }
    try:
        persist_prediction(
            event_id,
            package_ref,
            request.features,
            model_result["missing_features"],
            result,
            request.evidence,
            alerts,
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="event_id already exists; audited events are immutable.",
        ) from exc
    return result


@app.get("/api/audit")
def audit(limit: int = Query(default=30, ge=1, le=200)):
    with db_connect() as db:
        rows = db.execute(
            "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

    results = []
    for row in rows:
        item = dict(row)
        item["reason_codes"] = json.loads(item.pop("reasons_json"))
        item["evidence"] = json.loads(item.pop("evidence_json"))
        item["integrity_alerts"] = json.loads(item.pop("alerts_json"))
        item["features"] = json.loads(item.pop("features_json"))
        item["missing_features"] = json.loads(item.pop("missing_features_json"))
        item["model_labels"] = json.loads(item.pop("model_labels_json"))
        item["model_disagreement"] = bool(item["model_disagreement"])
        item["score_available"] = bool(item["score_available"])
        results.append(item)
    return {"count": len(results), "events": results}


# TraceGate-R secure Groq explanation routes (does not alter decisions).
from .genai_explain import router as tracegate_genai_router
app.include_router(tracegate_genai_router)
