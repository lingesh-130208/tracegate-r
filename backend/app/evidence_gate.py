"""Evidence sufficiency policy for TraceGate-R."""

from collections.abc import Mapping, Sequence

REQUIRED_CATEGORIES = (
    "file_activity",
    "process_execution",
    "system_calls",
    "network_behavior",
)

VALID_STATES = {"present", "missing", "malformed", "inconsistent"}
VALID_VERDICTS = {"benign", "malicious", "unknown"}


def evaluate_evidence(
    evidence: Mapping[str, object] | None,
    model_verdict: str,
    integrity_alerts: Sequence[str] | None = None,
) -> dict[str, object]:
    """Decide whether evidence is sufficient to trust a model verdict."""

    if not isinstance(model_verdict, str):
        raise ValueError("model_verdict must be a string")

    verdict = model_verdict.strip().lower()
    if verdict not in VALID_VERDICTS:
        raise ValueError("model_verdict must be benign, malicious, or unknown")

    if evidence is None:
        evidence = {}
    elif not isinstance(evidence, Mapping):
        raise TypeError("evidence must be a mapping or None")

    if isinstance(integrity_alerts, (str, bytes)):
        raise TypeError("integrity_alerts must be a sequence of strings")

    alerts = []
    for alert in integrity_alerts or ():
        if not isinstance(alert, str) or not alert.strip():
            raise ValueError("Each integrity alert must be a non-empty string")
        alerts.append(alert.strip())

    states = {}
    for category in REQUIRED_CATEGORIES:
        raw_state = evidence.get(category, "missing")
        if not isinstance(raw_state, str):
            state = "malformed"
        else:
            state = raw_state.strip().lower()
            if state not in VALID_STATES:
                state = "malformed"
        states[category] = state

    incomplete = [
        category
        for category, state in states.items()
        if state != "present"
    ]
    coverage = sum(
        state == "present" for state in states.values()
    ) / len(REQUIRED_CATEGORIES)

    reasons = []
    if incomplete:
        reasons.append("INCOMPLETE_EVIDENCE")
    if alerts:
        reasons.append("INTEGRITY_ALERT")
    if verdict == "unknown":
        reasons.append("UNKNOWN_MODEL_VERDICT")

    decision = "REVIEW_REQUIRED" if reasons else "EVIDENCE_SUFFICIENT"

    return {
        "model_verdict": verdict,
        "decision": decision,
        "coverage_percent": round(coverage * 100, 1),
        "category_states": states,
        "incomplete_categories": incomplete,
        "integrity_alerts": alerts,
        "reason_codes": reasons,
    }
