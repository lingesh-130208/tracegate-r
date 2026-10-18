import { FEATURE_NAMES } from "../schema";
import type { AuditEvent, DemoDataset } from "../types";

const definitions = [
  {
    id: "DEMO-7F31A2",
    at: "2026-10-17T09:42:00.000Z",
    packageRef: "nebula-parser 2.4.1",
    decision: "REVIEW_REQUIRED",
    scoreAvailable: true,
    score: 0.43,
    measured: 20,
    evidence: { file_activity: "present", process_execution: "present", network_behavior: "missing" },
    alerts: ["DEMO_PARTIAL_EVIDENCE"],
    reasons: ["FEATURE_VECTOR_INCOMPLETE"],
  },
  {
    id: "DEMO-7F31A1",
    at: "2026-10-17T09:36:00.000Z",
    packageRef: "trace-io-snapshot 1.8.0",
    decision: "REVIEW_REQUIRED",
    scoreAvailable: true,
    score: 0.71,
    measured: 40,
    evidence: { file_activity: "present", process_execution: "present", system_calls: "present", network_behavior: "missing" },
    alerts: [],
    reasons: ["EVIDENCE_CATEGORY_MISSING"],
  },
  {
    id: "DEMO-7F31A0",
    at: "2026-10-17T09:28:00.000Z",
    packageRef: "hash-cache 0.9.3",
    decision: "EVIDENCE_SUFFICIENT",
    scoreAvailable: true,
    score: 0.18,
    measured: 48,
    evidence: { file_activity: "present", process_execution: "present", system_calls: "present", network_behavior: "present" },
    alerts: [],
    reasons: [],
  },
  {
    id: "DEMO-7F319F",
    at: "2026-10-17T09:14:00.000Z",
    packageRef: "socket-probe 3.1.2",
    decision: "REVIEW_REQUIRED",
    scoreAvailable: true,
    score: 0.53,
    measured: 32,
    evidence: { file_activity: "present", process_execution: "missing", network_behavior: "present" },
    alerts: ["MODEL_DISAGREEMENT"],
    reasons: ["MODEL_DISAGREEMENT", "FEATURE_VECTOR_INCOMPLETE"],
  },
] as const;

function demoEvent(definition: (typeof definitions)[number], seed: number): AuditEvent {
  const alerts: readonly string[] = definition.alerts;
  const features: Record<string, number | null> = {};
  FEATURE_NAMES.forEach((name, index) => {
    features[name] = index < definition.measured
      ? Number((((seed + 3) * (index + 5)) % 137 / 10).toFixed(1))
      : null;
  });
  const missingFeatures = FEATURE_NAMES.slice(definition.measured);
  return {
    event_id: definition.id,
    created_at: definition.at,
    package_ref: definition.packageRef,
    decision: definition.decision,
    model_verdict: definition.scoreAvailable ? (definition.score! >= 0.5 ? "malicious" : "benign") : "unknown",
    score_available: definition.scoreAvailable,
    ensemble_probability: definition.score,
    logistic_probability: definition.scoreAvailable ? Number(Math.max(0, definition.score! - 0.04).toFixed(2)) : null,
    random_forest_probability: definition.scoreAvailable ? Number(Math.min(1, definition.score! + 0.03).toFixed(2)) : null,
    model_probabilities: {
      ensemble: definition.score,
      logistic_regression: definition.scoreAvailable ? Number(Math.max(0, definition.score! - 0.04).toFixed(2)) : null,
      random_forest: definition.scoreAvailable ? Number(Math.min(1, definition.score! + 0.03).toFixed(2)) : null,
    },
    model_disagreement: alerts.includes("MODEL_DISAGREEMENT"),
    prediction_unavailable_reason: definition.scoreAvailable ? null : "MODEL_DOES_NOT_SUPPORT_MISSING_FEATURES",
    features,
    missing_features: [...missingFeatures],
    missing_feature_count: missingFeatures.length,
    provided_feature_count: definition.measured,
    expected_feature_count: FEATURE_NAMES.length,
    coverage_percent: Number((definition.measured / FEATURE_NAMES.length * 100).toFixed(1)),
    evidence: { ...definition.evidence },
    integrity_alerts: [...alerts],
    reason_codes: [...definition.reasons],
  };
}

export function createDemoDataset(): DemoDataset {
  return {
    health: { status: "ok", service: "tracegate-r-demo", model_ready: true, feature_count: FEATURE_NAMES.length },
    latencyMs: 18.6,
    model: {
      models_available: true,
      missing_artifacts: [],
      feature_count: FEATURE_NAMES.length,
      feature_names: [...FEATURE_NAMES],
      schema_valid: true,
      model_readiness_error: null,
      offline_benchmark: {},
    },
    events: definitions.map((definition, index) => demoEvent(definition, index + 17)),
  };
}

export function explainDemoEvent(event: AuditEvent): string {
  const missing = event.missing_features ?? [];
  const alerts = event.integrity_alerts ?? [];
  const probability = event.score_available === true
    && typeof event.ensemble_probability === "number"
    ? `${(event.ensemble_probability * 100).toFixed(1)}% (illustrative)`
    : "Unavailable in this example";
  return [
    "DEMO EXPLANATION — SYNTHETIC RECORD",
    `Event: ${event.event_id}`,
    `Formal example decision: ${event.decision ?? "Not recorded"}. This explanation does not alter it.`,
    `Example ensemble score: ${probability}. A score is not proof of malicious or benign behavior.`,
    `Missing example measurements: ${missing.length}${missing.length ? ` (${missing.slice(0, 6).join(", ")}${missing.length > 6 ? ", …" : ""})` : "."}`,
    `Example integrity alerts: ${alerts.length ? alerts.join("; ") : "none recorded"}.`,
    "This deterministic text describes only the synthetic demo fixture; it is not a live verdict.",
  ].join("\n");
}
