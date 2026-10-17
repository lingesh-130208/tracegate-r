"""Offline, deterministic explanations for audited TraceGate-R events.

No external API, API key, network provider, or model-generated verdict is used.
The text is derived only from an allow-listed audit event and never changes
its recorded formal decision.
"""
import json
import os
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
    "model_probabilities", "malicious_probability", "ensemble", "missing_feature_count",
    "missing_features", "evidence", "integrity_alerts", "alerts", "latency_ms",
    "model_disagreement", "reason", "source", "risk_score", "prediction",
}
_ALLOWED_MODELS = {"ensemble", "random_forest", "logistic_regression", "lr", "rf"}
_MISSING_WORDS = {"missing", "absent", "unavailable", "unknown", "not observed", "not_collected"}


def sanitize_event_for_llm(event: dict[str, Any]) -> dict[str, Any]:
    """Legacy-compatible allow-list sanitizer; no LLM receives this data."""
    safe: dict[str, Any] = {}
    for key, value in event.items():
        if key not in _ALLOWED_TOP:
            continue
        if key == "model_probabilities" and isinstance(value, dict):
            safe[key] = {str(k): v for k, v in value.items()
                         if k in _ALLOWED_MODELS and isinstance(v, (int, float)) and not isinstance(v, bool)}
        elif key == "evidence" and isinstance(value, dict):
            safe[key] = {str(k)[:80]: str(v)[:100] for k, v in value.items()
                         if isinstance(v, (str, int, float, bool))}
        elif key in ("integrity_alerts", "alerts", "missing_features") and isinstance(value, list):
            safe[key] = [str(item)[:180] for item in value[:40]
                         if isinstance(item, (str, int, float, bool))]
        elif isinstance(value, (str, int, float, bool)) or value is None:
            safe[key] = value if not isinstance(value, str) else value[:300]
        elif key == "prediction" and isinstance(value, dict):
            safe[key] = {str(k)[:60]: v for k, v in value.items()
                         if k in _ALLOWED_MODELS and isinstance(v, (int, float, str, bool))}
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
    if not any(k in safe for k in ("decision", "verdict", "model_probabilities", "malicious_probability",
                                   "evidence", "integrity_alerts", "alerts", "missing_feature_count")):
        raise HTTPException(status_code=422, detail="Audit record has no recognized decision or evidence fields.")
    return safe


def _fmt_probability(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not 0 <= float(value) <= 1:
        return f"{float(value):.3f} (scale not normalized to 0â€“1)"
    return f"{float(value):.3f} ({float(value):.1%})"


def build_offline_explanation(raw_event: dict[str, Any]) -> str:
    """Build a transparent, deterministic narrative; never infer a new verdict."""
    event = sanitize_event_for_llm(raw_event)
    event_id = str(event.get("event_id", "not recorded"))
    decision = event.get("decision") or event.get("verdict") or event.get("status") or "NOT_RECORDED"
    evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
    probs = event.get("model_probabilities") if isinstance(event.get("model_probabilities"), dict) else {}
    if not probs:
        score = event.get("malicious_probability", event.get("ensemble"))
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            probs = {"ensemble": score}

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
    named_probs = [(k, _fmt_probability(v)) for k, v in probs.items() if k in _ALLOWED_MODELS]
    named_probs = [(k, v) for k, v in named_probs if v is not None]
    if named_probs:
        lines.extend(f"- Recorded {name.replace('_', ' ')} model score: {value}. This score alone is not proof of malicious activity." for name, value in sorted(named_probs))
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