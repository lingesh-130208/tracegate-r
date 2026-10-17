import { EXPECTED_FEATURE_COUNT } from "../schema";
import type { AuditEvent, FeatureState, ObservationPayload } from "../types";

export interface FeatureCoverage {
  measured: number;
  missing: number;
  invalid: number;
  notReported: number;
}

export function scoreText(event: AuditEvent): string {
  if (event.score_available !== true) return "Unavailable";
  const score = event.model_probabilities?.ensemble ?? event.ensemble_probability;
  return typeof score === "number" && Number.isFinite(score) && score >= 0 && score <= 1
    ? `${(score * 100).toFixed(1)}%`
    : "Not reported";
}

export function featureState(name: string, event: AuditEvent | null): FeatureState {
  if (!event) return "not-reported";
  const value = event.features?.[name];
  if (typeof value === "number") return Number.isFinite(value) ? "measured" : "invalid";
  if (value === null || event.missing_features?.includes(name)) return "missing";
  return "not-reported";
}

export function featureCoverage(names: readonly string[], event: AuditEvent | null): FeatureCoverage {
  const counts: FeatureCoverage = { measured: 0, missing: 0, invalid: 0, notReported: 0 };
  for (const name of names) {
    const state = featureState(name, event);
    if (state === "measured") counts.measured += 1;
    else if (state === "missing") counts.missing += 1;
    else if (state === "invalid") counts.invalid += 1;
    else counts.notReported += 1;
  }
  return counts;
}

export function orderAuditEvents(
  events: readonly AuditEvent[],
  search: string,
  decision: string,
  order: "newest" | "oldest",
): AuditEvent[] {
  const query = search.trim().toLocaleLowerCase();
  return [...events]
    .filter((event) => {
      if (!decision) return true;
      if (decision === "Other") {
        return event.decision !== "REVIEW_REQUIRED" && event.decision !== "EVIDENCE_SUFFICIENT";
      }
      return event.decision === decision;
    })
    .filter((event) => !query || `${event.event_id} ${event.package_ref ?? ""}`.toLocaleLowerCase().includes(query))
    .sort((a, b) => {
      const aTime = Date.parse(a.created_at ?? "");
      const bTime = Date.parse(b.created_at ?? "");
      const delta = (Number.isFinite(aTime) ? aTime : 0) - (Number.isFinite(bTime) ? bTime : 0);
      return order === "newest" ? -delta : delta;
    });
}

export function paginate<T>(items: readonly T[], page: number, pageSize: number): T[] {
  return items.slice(Math.max(0, page) * pageSize, (Math.max(0, page) + 1) * pageSize);
}

export function parseObservation(
  packageRef: string,
  featuresText: string,
  evidenceText: string,
  alertsText: string,
  canonicalNames: readonly string[],
): ObservationPayload {
  const features: unknown = JSON.parse(featuresText);
  const evidence: unknown = JSON.parse(evidenceText);
  const alerts: unknown = JSON.parse(alertsText);

  if (!features || typeof features !== "object" || Array.isArray(features)) {
    throw new Error("Features must be a JSON object.");
  }
  const featureEntries = Object.entries(features as Record<string, unknown>);
  if (featureEntries.length === 0) throw new Error("Enter at least one measured or explicitly missing feature.");
  const canonical = new Set(canonicalNames);
  const cleanFeatures: Record<string, number | null> = {};
  for (const [name, value] of featureEntries) {
    if (!canonical.has(name)) throw new Error(`Unknown feature name: ${name}`);
    if (value !== null && (typeof value !== "number" || !Number.isFinite(value))) {
      throw new Error(`Feature ${name} must be a finite number or null.`);
    }
    cleanFeatures[name] = value as number | null;
  }
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    throw new Error("Evidence states must be a JSON object.");
  }
  const cleanEvidence: Record<string, string> = {};
  for (const [name, value] of Object.entries(evidence as Record<string, unknown>)) {
    if (typeof value !== "string") throw new Error(`Evidence state ${name} must be a string.`);
    cleanEvidence[name] = value;
  }
  if (!Array.isArray(alerts) || !alerts.every((item) => typeof item === "string")) {
    throw new Error("Integrity alerts must be a JSON array of strings.");
  }
  return {
    package_ref: packageRef.trim() ? packageRef.trim().slice(0, 200) : null,
    features: cleanFeatures,
    evidence: cleanEvidence,
    integrity_alerts: alerts as string[],
  };
}

export function coverageLabel(event: AuditEvent | null): string {
  if (!event) return "Not reported";
  const expected = event.expected_feature_count;
  const provided = event.provided_feature_count;
  if (typeof expected === "number" && typeof provided === "number") return `${provided} / ${expected}`;
  const missing = event.missing_feature_count ?? event.missing_features?.length;
  if (typeof missing === "number") return `${Math.max(0, EXPECTED_FEATURE_COUNT - missing)} / ${EXPECTED_FEATURE_COUNT}`;
  return "Not reported";
}
