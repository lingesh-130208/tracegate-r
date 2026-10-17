"""Offline, deterministic explanations for audited TraceGate-R events.

No external API, API key, network provider, or model-generated verdict is used.
Text is derived from allow-listed audit fields and never changes the recorded
formal decision.
"""
import json
import math
import os
import re
import sqlite3
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/genai", tags=["Offline evidence explanations"])
MODEL_ID = "offline-evidence-rules-v1"
API_BASE = os.getenv("TRACEGATE_API_BASE", "http://127.0.0.1:8001").rstrip("/")
EXPLANATION_DB = Path.home() / ".tracegate-r" / "genai_explanations.sqlite3"


class ExplainRequest(BaseModel):
    event_id: str = Field(min_length=1, max_length=200)
    question: str = Field(default="Explain this event and its evidential limitations.", max_length=400)


_ALLOWED_TOP = {
    "event_id", "timestamp", "created_at", "decision", "verdict", "status",
    "model_probabilities", "model_scores", "malicious_probability", "malicious_score",
    "probability_malicious", "malicious_prob", "risk_probability", "risk_score",
    "prediction_score", "predicted_probability", "ensemble_probability", "score",
    "missing_feature_count", "missing_features", "evidence", "integrity_alerts",
    "alerts", "latency_ms", "model_disagreement", "reason", "source", "prediction",
}
_ALLOWED_MODELS = {"ensemble", "random_forest", "logistic_regression", "lr", "rf"}
_MODEL_ALIASES = {
    "ensemble": "ensemble", "ensemble_probability": "ensemble", "avg": "ensemble", "malicious": "ensemble",
    "random_forest": "random_forest", "randomforest": "random_forest", "rf": "random_forest",
    "logistic_regression": "logistic_regression", "logisticregression": "logistic_regression",
    "lr": "logistic_regression",
}
_SCORE_ALIASES = (
    "malicious_probability", "probability_malicious", "malicious_prob",
    "malicious_score", "risk_probability", "ensemble_probability",
    "predicted_malicious_probability", "prediction_score", "predicted_probability",
    "risk_score", "probability", "score",
)
_WRAPPER_KEYS = {
    "prediction", "predictions", "result", "results", "output", "outputs",
    "details", "detail", "payload", "record", "data", "model", "models",
    "scores", "probabilities", "model_scores", "model_probabilities", "response",
    "result_json", "prediction_json", "details_json", "output_json", "record_json",
    "event_json", "model_output", "prediction_result", "inference", "metadata", "metrics",
}
_MISSING_WORDS = {"missing", "absent", "unavailable", "unknown", "not observed", "not_collected"}


def _norm_key(value: Any) -> str:
    text = str(value).strip()
    text = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", text)
    return re.sub(r"_+", "_", text.lower().replace("-", "_").replace(" ", "_"))


def _probability(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = float(value.strip())
        except (ValueError, TypeError):
            return None
    if not isinstance(value, (int, float)):
        return None
    value = float(value)
    if not math.isfinite(value) or value < 0.0 or value > 1.0:
        return None
    return value


def _score_containers(event: dict[str, Any]):
    """Walk only known result-wrapper fields, with strict depth and size bounds."""
    queue: list[tuple[dict[str, Any], int]] = [(event, 0)]
    seen: set[int] = set()
    inspected = 0
    while queue and inspected < 80:
        current, depth = queue.pop(0)
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        inspected += 1
        yield current
        if depth >= 4:
            continue
        for raw_key, child in current.items():
            key = _norm_key(raw_key)
            if key not in _WRAPPER_KEYS:
                continue
            if isinstance(child, dict):
                queue.append((child, depth + 1))
            elif isinstance(child, list):
                for item in child[:20]:
                    if isinstance(item, dict):
                        queue.append((item, depth + 1))
            elif isinstance(child, str) and child[:1] in ("{", "[") and len(child) <= 20000:
                try:
                    decoded = json.loads(child)
                except (ValueError, TypeError):
                    continue
                if isinstance(decoded, dict):
                    queue.append((decoded, depth + 1))
                elif isinstance(decoded, list):
                    for item in decoded[:20]:
                        if isinstance(item, dict):
                            queue.append((item, depth + 1))


def _extract_recorded_scores(event: dict[str, Any]) -> tuple[dict[str, float], str | None]:
    """Normalize known historical audit schemas into canonical probability fields."""
    models: dict[str, float] = {}
    fallback: str | None = None
    for container in _score_containers(event):
        for raw_field, candidate in container.items():
            field = _norm_key(raw_field)
            if field not in ("model_probabilities", "model_scores", "probabilities", "scores", "predictions") or not isinstance(candidate, dict):
                continue
            for alias, value in candidate.items():
                canonical = _MODEL_ALIASES.get(_norm_key(alias))
                number = _probability(value)
                if canonical and number is not None:
                    models.setdefault(canonical, number)
                if _norm_key(alias) in _SCORE_ALIASES and number is not None:
                    fallback = fallback if fallback is not None else f"{number:.12g}"
        for raw_field, raw_value in container.items():
            field = _norm_key(raw_field)
            if field not in _SCORE_ALIASES:
                continue
            number = _probability(raw_value)
            if number is not None:
                # Preserve a named ensemble score; use other explicit scalar scores only as a fallback.
                if field == "ensemble_probability":
                    models.setdefault("ensemble", number)
                elif fallback is None:
                    fallback = f"{number:.12g}"
    if fallback is not None and "ensemble" not in models:
        try:
            models["ensemble"] = float(fallback)
        except ValueError:
            pass
    return models, fallback


def sanitize_event_for_llm(event: dict[str, Any]) -> dict[str, Any]:
    """Legacy-compatible allow-list sanitizer; offline engine does not call an LLM."""
    safe: dict[str, Any] = {}
    for key, value in event.items():
        if key not in _ALLOWED_TOP:
            continue
        if key in {"model_probabilities", "model_scores"}:
            continue  # replaced with canonical, bounded values below
        if key == "evidence" and isinstance(value, dict):
            safe[key] = {str(k)[:80]: str(v)[:100] for k, v in value.items()
                         if isinstance(v, (str, int, float, bool))}
        elif key in ("integrity_alerts", "alerts", "missing_features") and isinstance(value, list):
            safe[key] = [str(item)[:180] for item in value[:40]
                         if isinstance(item, (str, int, float, bool))]
        elif isinstance(value, (str, int, float, bool)) or value is None:
            safe[key] = value if not isinstance(value, str) else value[:300]
    normalized, _ = _extract_recorded_scores(event)
    # Prefer recognized model-specific probabilities while merging any scalar legacy score.
    prior = safe.get("model_probabilities")
    if isinstance(prior, dict):
        for key, value in prior.items():
            model = _MODEL_ALIASES.get(str(key).lower())
            number = _probability(value)
            if model and number is not None:
                normalized.setdefault(model, number)
    if normalized:
        safe["model_probabilities"] = normalized
    return safe


def _find_event(node: Any, wanted: str) -> dict[str, Any] | None:
    if isinstance(node, dict):
        if node.get("event_id") == wanted:
            return node
        for value in node.values():
            found = _find_event(value, wanted)
            if found is not None:
                return found
    elif isinstance(node, list):
        for value in node:
            found = _find_event(value, wanted)
            if found is not None:
                return found
    return None


def _load_audit_event(event_id: str) -> dict[str, Any]:
    req = urllib.request.Request(API_BASE + "/api/audit?limit=200", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Could not read the local audit API.") from exc
    found = _find_event(payload, event_id)
    if found is None:
        raise HTTPException(status_code=404, detail="Event not found in the latest 200 audit records.")
    safe = sanitize_event_for_llm(found)
    if not any(k in safe for k in ("decision", "verdict", "status", "model_probabilities", "malicious_probability", "evidence", "integrity_alerts", "alerts", "missing_feature_count")):
        raise HTTPException(status_code=422, detail="Audit record has no recognized decision or evidence fields.")
    return safe


def _fmt_probability(value: Any) -> str | None:
    number = _probability(value)
    if number is None:
        return None
    return f"{number:.3f} ({number:.1%})"


def build_offline_explanation(raw_event: dict[str, Any]) -> str:
    """Build transparent deterministic text from recorded fields; never infer a verdict."""
    event = sanitize_event_for_llm(raw_event)
    event_id = str(event.get("event_id", "not recorded"))
    decision = event.get("decision") or event.get("verdict") or event.get("status") or "NOT_RECORDED"
    evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
    probs = event.get("model_probabilities") if isinstance(event.get("model_probabilities"), dict) else {}
    missing_count = event.get("missing_feature_count")
    if isinstance(missing_count, bool) or not isinstance(missing_count, int) or missing_count < 0:
        missing_count = len(event.get("missing_features", [])) if isinstance(event.get("missing_features"), list) else 0
    missing_evidence = [str(k) for k, v in evidence.items() if str(v).strip().lower() in _MISSING_WORDS]
    alerts = event.get("integrity_alerts") if isinstance(event.get("integrity_alerts"), list) else event.get("alerts", [])
    if not isinstance(alerts, list):
        alerts = []

    lines = [
        "What the audit record says:",
        f"- Event ID: {event_id}",
        f"- Recorded formal decision: {str(decision)[:100]} (this service does not alter it).",
    ]
    named_probs = [(k, _fmt_probability(v)) for k, v in probs.items() if k in _MODEL_ALIASES.values()]
    named_probs = [(k, v) for k, v in named_probs if v is not None]
    if named_probs:
        lines.extend(f"- Recorded {name.replace('_', ' ')} score: {value}. This score alone is not proof of malicious activity." for name, value in sorted(named_probs))
    else:
        lines.append("- No recognized numeric model score was present in the allowed audit fields.")
    if evidence:
        formatted = ", ".join(f"{str(k)[:60]}={str(v)[:80]}" for k, v in sorted(evidence.items()))
        lines.append("- Recorded evidence states: " + formatted + ".")
    else:
        lines.append("- No structured evidence states were present in the audit record.")
    if alerts:
        lines.append("- Integrity/review alerts: " + "; ".join(str(a)[:160] for a in alerts[:20]) + ".")
    else:
        lines.append("- No integrity-alert list was present in the fields used by this explanation.")

    lines.extend(["", "What is not established:"])
    lines.append("- This is a deterministic summary of recorded fields, not a new malware classification or an independent security verdict.")
    if missing_count:
        lines.append(f"- {missing_count} model feature(s) were recorded as missing. Any probability based on this incomplete vector is provisional, not a validated live-detection result.")
    if missing_evidence:
        lines.append("- Evidence was marked missing/unavailable for: " + ", ".join(sorted(missing_evidence)) + ".")
    if not evidence:
        lines.append("- The audit entry does not provide structured evidence states, so the underlying activity cannot be independently corroborated from this record alone.")

    lines.extend(["", "Safe analyst next steps:"])
    if str(decision).upper() == "REVIEW_REQUIRED" or missing_count or missing_evidence or alerts:
        lines.append("- Keep the event in review and collect the missing evidence before making a stronger conclusion.")
    else:
        lines.append("- Corroborate the recorded decision with the original process context and independent evidence before taking action.")
    lines.append("- Preserve the original event and audit trail; do not treat the numeric model score as proof on its own.")
    lines.append("- This explanation is generated locally from the audit record; no external AI provider or API key was used.")
    return "\n".join(lines)


def _persist_explanation(event_id: str, explanation: str) -> None:
    EXPLANATION_DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(EXPLANATION_DB, timeout=5) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS explanations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            model_id TEXT NOT NULL,
            explanation TEXT NOT NULL
        )""")
        conn.execute("INSERT INTO explanations(event_id, created_at_utc, model_id, explanation) VALUES (?, ?, ?, ?)",
                     (event_id, datetime.now(timezone.utc).isoformat(), MODEL_ID, explanation))


@router.get("/status")
def genai_status():
    return {"service": "tracegate-r-offline-explanations", "configured": True,
            "mode": "offline_deterministic", "model": MODEL_ID,
            "secret_location": "none required", "formal_verdict_changes": False}


@router.post("/explain")
def explain_event(request: ExplainRequest):
    event = _load_audit_event(request.event_id)
    explanation = build_offline_explanation(event)
    try:
        _persist_explanation(request.event_id, explanation)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Local explanation could not be saved to the audit-side SQLite database.") from exc
    return {"event_id": request.event_id, "model": MODEL_ID, "mode": "offline_deterministic",
            "explanation": explanation, "saved": True, "formal_decision_changed": False}
