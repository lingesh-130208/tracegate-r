import { describe, expect, it } from "vitest";
import { FEATURE_NAMES, EXPECTED_FEATURE_COUNT, matchesReleaseSchema } from "../schema";
import { featureCoverage, featureState, orderAuditEvents, paginate, parseObservation, scoreText } from "./logic";
import type { AuditEvent } from "../types";

describe("release feature schema", () => {
  it("preserves the exact ordered 48-feature release contract", () => {
    expect(FEATURE_NAMES).toHaveLength(EXPECTED_FEATURE_COUNT);
    expect(new Set(FEATURE_NAMES).size).toBe(EXPECTED_FEATURE_COUNT);
    expect(matchesReleaseSchema([...FEATURE_NAMES])).toBe(true);
    const reordered = [...FEATURE_NAMES];
    [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
    expect(matchesReleaseSchema(reordered)).toBe(false);
  });
});

describe("evidence rendering helpers", () => {
  it("keeps absent scores unavailable instead of showing zero", () => {
    expect(scoreText({ event_id: "partial", score_available: false, ensemble_probability: null })).toBe("Unavailable");
    expect(scoreText({ event_id: "invalid", score_available: true, ensemble_probability: null })).toBe("Not reported");
    expect(scoreText({ event_id: "scored", score_available: true, ensemble_probability: 0.25 })).toBe("25.0%");
  });

  it("distinguishes measured, missing, invalid, and unreported features", () => {
    const event: AuditEvent = {
      event_id: "coverage",
      features: { [FEATURE_NAMES[0]]: 4, [FEATURE_NAMES[1]]: null, [FEATURE_NAMES[2]]: Number.NaN },
      missing_features: [FEATURE_NAMES[1]],
    };
    expect(featureState(FEATURE_NAMES[0], event)).toBe("measured");
    expect(featureState(FEATURE_NAMES[1], event)).toBe("missing");
    expect(featureState(FEATURE_NAMES[2], event)).toBe("invalid");
    expect(featureState(FEATURE_NAMES[3], event)).toBe("not-reported");
    expect(featureCoverage(FEATURE_NAMES, event)).toEqual({ measured: 1, missing: 1, invalid: 1, notReported: 45 });
    expect(featureCoverage(FEATURE_NAMES, null)).toEqual({ measured: 0, missing: 0, invalid: 0, notReported: 48 });
  });
});

describe("audit filtering, ordering, and pagination", () => {
  const events: AuditEvent[] = [
    { event_id: "old-review", package_ref: "alpha", created_at: "2026-10-01T00:00:00Z", decision: "REVIEW_REQUIRED" },
    { event_id: "new-sufficient", package_ref: "beta", created_at: "2026-10-03T00:00:00Z", decision: "EVIDENCE_SUFFICIENT" },
    { event_id: "middle-review", package_ref: "alpha-tools", created_at: "2026-10-02T00:00:00Z", decision: "REVIEW_REQUIRED" },
    { event_id: "unknown-decision", package_ref: "gamma", created_at: "2026-10-04T00:00:00Z", decision: "POLICY_NOT_REPORTED" },
    { event_id: "no-decision", package_ref: "delta", created_at: "2026-10-05T00:00:00Z" },
  ];

  it("filters by reference and decision and sorts by timestamp", () => {
    expect(orderAuditEvents(events, "alpha", "REVIEW_REQUIRED", "newest").map((event) => event.event_id))
      .toEqual(["middle-review", "old-review"]);
    expect(orderAuditEvents(events, "", "", "oldest").map((event) => event.event_id))
      .toEqual(["old-review", "middle-review", "new-sufficient", "unknown-decision", "no-decision"]);
  });

  it("groups unknown and unavailable formal decisions under Other", () => {
    expect(orderAuditEvents(events, "", "Other", "newest").map((event) => event.event_id))
      .toEqual(["no-decision", "unknown-decision"]);
  });

  it("paginates only the already-filtered result", () => {
    const ordered = orderAuditEvents(events, "", "", "newest");
    expect(paginate(ordered, 0, 2).map((event) => event.event_id)).toEqual(["no-decision", "unknown-decision"]);
    expect(paginate(ordered, 1, 2).map((event) => event.event_id)).toEqual(["new-sufficient", "middle-review"]);
  });
});

describe("observation validation", () => {
  it("preserves nulls and accepts only canonical names and finite numeric values", () => {
    const payload = parseObservation("  analyst-ref  ", JSON.stringify({ [FEATURE_NAMES[0]]: 3.5, [FEATURE_NAMES[1]]: null }), "{}", "[]", FEATURE_NAMES);
    expect(payload.package_ref).toBe("analyst-ref");
    expect(payload.features).toEqual({ [FEATURE_NAMES[0]]: 3.5, [FEATURE_NAMES[1]]: null });
  });

  it("rejects unknown names, strings, booleans, non-finite values, and malformed evidence", () => {
    expect(() => parseObservation("", '{"unknown_feature":1}', "{}", "[]", FEATURE_NAMES)).toThrow("Unknown feature name");
    expect(() => parseObservation("", JSON.stringify({ [FEATURE_NAMES[0]]: "2" }), "{}", "[]", FEATURE_NAMES)).toThrow("finite number or null");
    expect(() => parseObservation("", '{"Filetop__Total_Reads":1e999}', "{}", "[]", FEATURE_NAMES)).toThrow("finite number or null");
    expect(() => parseObservation("", JSON.stringify({ [FEATURE_NAMES[0]]: 1 }), '{"file_activity":true}', "[]", FEATURE_NAMES)).toThrow("must be a string");
    expect(() => parseObservation("", JSON.stringify({ [FEATURE_NAMES[0]]: 1 }), "{}", "{}", FEATURE_NAMES)).toThrow("array of strings");
  });
});
