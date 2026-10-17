from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from backend.app.evidence_gate import evaluate_evidence

app = FastAPI(
    title="TraceGate-R API",
    version="0.1.0",
    description="Evidence reliability checks for software security decisions",
)


class EvaluateRequest(BaseModel):
    model_verdict: str
    evidence: dict[str, object] = Field(default_factory=dict)
    integrity_alerts: list[str] = Field(default_factory=list)


@app.get("/health")
def health():
    return {"status": "ok", "service": "tracegate-r"}


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
