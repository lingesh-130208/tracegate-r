import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, fetchLiveSnapshot, requestJson, submitPrediction } from "./api";
import type { ObservationPayload } from "../types";

const payload: ObservationPayload = {
  package_ref: "fixture",
  features: { Filetop__Total_Reads: null },
  evidence: {},
  integrity_alerts: [],
};

describe("safe same-origin API adapter", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));

  it("rejects Demo Mode writes before touching fetch", async () => {
    await expect(submitPrediction(payload, "demo", true)).rejects.toThrow("Demo Mode never sends");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses writes when live readiness or schema validation is incomplete", async () => {
    await expect(submitPrediction(payload, "live", false)).rejects.toThrow("healthy API");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("restricts requests to same-origin paths", async () => {
    await expect(requestJson("//private-host/api/predict")).rejects.toBeInstanceOf(ApiError);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("measures only the health request, not slower model or audit requests", async () => {
    let clock = 0;
    let performanceReads = 0;
    vi.spyOn(performance, "now").mockImplementation(() => {
      performanceReads += 1;
      return clock;
    });
    let releaseOtherRequests: () => void = () => {};
    const otherRequests = new Promise<void>((resolve) => { releaseOtherRequests = resolve; });
    const asResponse = (body: unknown) => ({
      ok: true,
      status: 200,
      json: async () => body,
    }) as Response;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path === "/health") {
        clock = 12;
        return asResponse({ status: "ok" });
      }
      await otherRequests;
      return asResponse(path.startsWith("/api/model-info")
        ? { models_available: false, feature_names: [], schema_valid: false }
        : { events: [] });
    }));

    const snapshotPromise = fetchLiveSnapshot();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    expect(performanceReads).toBe(2);
    clock = 500;
    releaseOtherRequests();
    const snapshot = await snapshotPromise;
    expect(snapshot.latencyMs).toBe(12);
  });

  it("rejects malformed audit events rather than exposing them to workspace renderers", async () => {
    const asResponse = (body: unknown) => ({
      ok: true,
      status: 200,
      json: async () => body,
    }) as Response;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path === "/health") return asResponse({ status: "ok" });
      if (path === "/api/model-info") return asResponse({ models_available: false });
      return asResponse({ count: 1, events: [null] });
    }));

    const snapshot = await fetchLiveSnapshot();
    expect(snapshot.audit).toBeNull();
    expect(snapshot.auditError).toContain("malformed");
  });
});
