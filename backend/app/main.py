"""TraceGate-R API, decision gate, and SQLite audit trail."""
import json
import os
import sqlite3
from contextlib import contextmanager
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.app.evidence_gate import evaluate_evidence
from backend.app.model_service import (
    ModelsUnavailableError,
    model_info,
    predict_models,
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


@contextmanager
def db_connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db_connect() as db:
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


init_db()


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


def persist_prediction(event_id, package_ref, result, evidence, alerts):
    probabilities = result["model_probabilities"]
    with db_connect() as db:
        db.execute("""
            INSERT OR REPLACE INTO audit_events (
                event_id, created_at, package_ref, model_verdict, decision,
                logistic_probability, random_forest_probability,
                ensemble_probability, probability_gap, coverage_percent,
                reasons_json, evidence_json, alerts_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        model_result = predict_models(request.features)
    except ModelsUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
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
        "policy_note": (
            "EVIDENCE_SUFFICIENT means the supplied evidence passed this gate; "
            "it does not guarantee the package is safe."
        ),
    }
    persist_prediction(event_id, package_ref, result, request.evidence, alerts)
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
        results.append(item)
    return {"count": len(results), "events": results}


# TraceGate-R secure Groq explanation routes (does not alter decisions).
from .genai_explain import router as tracegate_genai_router
app.include_router(tracegate_genai_router)
