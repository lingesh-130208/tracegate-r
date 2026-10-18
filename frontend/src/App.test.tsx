import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { FEATURE_NAMES } from "./schema";

describe("TraceGate-R isolated demo workflow", () => {
  it("keeps demo content labeled and makes no API requests", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<App initialMode="demo" />);
    expect(screen.getAllByText("DEMO DATA — NOT LIVE TELEMETRY").length).toBeGreaterThan(0);
    expect(screen.getAllByText("DEMO-7F31A2").length).toBeGreaterThan(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("opens a forensic drawer with an unavailable score and closes accessibly", async () => {
    render(<App initialMode="demo" />);
    fireEvent.click(screen.getByRole("button", { name: "Inspect event DEMO-7F31A2" }));
    expect(screen.getByRole("dialog", { name: "Evidence inspection" })).toBeTruthy();
    expect(screen.getByText("Deterministic Evidence Explanation")).toBeTruthy();
    expect(screen.getByText(/does not independently predict maliciousness/)).toBeTruthy();
    expect(screen.getAllByText("Unavailable").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Close event details" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("never enables prediction submission in Demo Mode", () => {
    render(<App initialMode="demo" />);
    fireEvent.click(screen.getByRole("link", { name: "Observation analysis" }));
    const submit = screen.getByRole("button", { name: "Submit to live prediction API" }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    expect(screen.getByText(/NO WRITE OPERATIONS/)).toBeTruthy();
  });

  it("clears synthetic demo input before Live Mode can submit", async () => {
    const signedOut = { authenticated: false, user: null, csrf_token: null, expires_at: null };
    const authenticated = {
      authenticated: true,
      user: { user_id: "user-id", username: "user", role: "user", tenant_id: "tenant-a" },
      csrf_token: "user-csrf",
      expires_at: "2026-10-18T00:00:00Z",
    };
    let currentSession: unknown = signedOut;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      let body: unknown = {};
      if (path === "/api/auth/session") body = currentSession;
      else if (path === "/api/auth/login") {
        currentSession = authenticated;
        body = authenticated;
      } else if (path === "/health") body = { status: "ok", service: "tracegate-r" };
      else if (path === "/api/model-info") body = { schema_valid: true, feature_names: FEATURE_NAMES, models_available: true };
      else if (path === "/api/audit?limit=200") body = { events: [] };
      return { ok: true, status: 200, json: async () => body } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App initialMode="demo" />);
    fireEvent.click(screen.getByRole("link", { name: "Observation analysis" }));
    fireEvent.click(screen.getByRole("button", { name: "Load synthetic draft" }));
    expect((screen.getByLabelText(/Feature values/) as HTMLTextAreaElement).value).toContain("Filetop__Total_Reads");

    fireEvent.click(screen.getByRole("button", { name: "Live" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy());
    expect((screen.getByLabelText(/Feature values/) as HTMLTextAreaElement).value).toBe("{}");

    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "user" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "not-a-real-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in securely" }));
    await waitFor(() => expect(screen.getByRole("button", { name: /Sign out/ })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Submit to live prediction API" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("Enter at least one measured or explicitly missing feature."));
    expect(fetchMock.mock.calls.some(([input]) => String(input) === "/api/predict")).toBe(false);
  });

  it("shows unavailable live state when same-origin API calls fail", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("offline"));
    vi.stubGlobal("fetch", fetchMock);
    render(<App initialMode="live" />);
    await waitFor(() => expect(screen.getAllByText("LIVE API UNAVAILABLE").length).toBeGreaterThan(0));
    expect(screen.queryByText("DEMO DATA — NOT LIVE TELEMETRY")).toBeNull();
  });

  it("enables live submission only after authenticating an authorized session", async () => {
    const signedOut = { authenticated: false, user: null, csrf_token: null, expires_at: null };
    let currentSession: unknown = signedOut;
    const authenticated = {
      authenticated: true,
      user: { user_id: "user-id", username: "user", role: "user", tenant_id: "tenant-a" },
      csrf_token: "session-csrf",
      expires_at: "2026-10-18T00:00:00Z",
    };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      let body: unknown = {};
      if (path === "/api/auth/session") body = currentSession;
      else if (path === "/api/auth/login") {
        currentSession = authenticated;
        body = authenticated;
      } else if (path === "/api/auth/logout") {
        currentSession = signedOut;
        body = signedOut;
      } else if (path === "/health") body = { status: "ok", service: "tracegate-r" };
      else if (path === "/api/model-info") {
        body = { schema_valid: true, feature_names: FEATURE_NAMES, models_available: true };
      } else if (path === "/api/audit?limit=200") body = { events: [] };
      return { ok: true, status: 200, json: async () => body } as Response;
    }));

    render(<App initialMode="live" />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy());
    fireEvent.click(screen.getByRole("link", { name: "Observation analysis" }));
    const submit = screen.getByRole("button", { name: "Submit to live prediction API" }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "user" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "not-a-real-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in securely" }));

    await waitFor(() => expect(screen.getByRole("button", { name: /Sign out/ })).toBeTruthy());
    await waitFor(() => expect(submit.disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: /Sign out/ }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy());
    await waitFor(() => expect(submit.disabled).toBe(true));
  });

  it("allows a signed-in user to submit but keeps account administration unavailable", async () => {
    const responses: Record<string, unknown> = {
      "/api/auth/session": {
        authenticated: true,
        user: { user_id: "user-id", username: "user", role: "user", tenant_id: "tenant-a" },
        csrf_token: "user-csrf",
        expires_at: "2026-10-18T00:00:00Z",
      },
      "/health": { status: "ok", service: "tracegate-r" },
      "/api/model-info": { schema_valid: true, feature_names: FEATURE_NAMES, models_available: true },
    };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => ({
      ok: true,
      status: 200,
      json: async () => responses[String(input)],
    }) as Response));

    render(<App initialMode="live" />);
    fireEvent.click(screen.getByRole("link", { name: "Observation analysis" }));
    const submit = screen.getByRole("button", { name: "Submit to live prediction API" }) as HTMLButtonElement;
    await waitFor(() => expect(screen.getByRole("button", { name: /Sign out/ })).toBeTruthy());
    expect(submit.disabled).toBe(false);
    expect(screen.queryByText("Users and tenant access")).toBeNull();
  });

  it("uses a tenant ID validation pattern supported by current browsers", async () => {
    const authenticated = {
      authenticated: true,
      user: { user_id: "admin-id", username: "admin", role: "admin", tenant_id: "tenant-a" },
      csrf_token: "admin-csrf",
      expires_at: "2026-10-18T00:00:00Z",
    };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      const body = path === "/api/auth/session" ? authenticated
        : path === "/health" ? { status: "ok", service: "tracegate-r" }
          : path === "/api/model-info" ? { schema_valid: true, feature_names: FEATURE_NAMES, models_available: true }
            : path === "/api/audit?limit=200" ? { events: [] }
              : path === "/api/admin/users" ? { users: [] }
                : {};
      return { ok: true, status: 200, json: async () => body } as Response;
    }));

    render(<App initialMode="live" />);
    await waitFor(() => expect(screen.getByRole("button", { name: /Sign out/ })).toBeTruthy());
    fireEvent.click(screen.getByRole("link", { name: "System diagnostics" }));

    const tenantInput = screen.getByLabelText("New tenant ID") as HTMLInputElement;
    const pattern = tenantInput.getAttribute("pattern");
    if (!pattern) throw new Error("Tenant ID input is missing its validation pattern.");
    const tenantPattern = new RegExp(`^(?:${pattern})$`, "v");
    expect(tenantPattern.test("tenant-1")).toBe(true);
    expect(tenantPattern.test("Invalid ID")).toBe(false);
  });

  it("submits a canonical observation for an unscored audit when model artifacts are missing", async () => {
    const prediction = {
      event_id: "SYNTHETIC-UNSCORED-1",
      package_ref: "synthetic fixture; not telemetry",
      created_at: "2026-10-18T00:00:00Z",
      model_verdict: "unknown",
      decision: "REVIEW_REQUIRED",
      model_probabilities: { logistic_regression: null, random_forest: null, ensemble: null },
      model_labels: { logistic_regression: null, random_forest: null },
      score_available: false,
      prediction_unavailable_reason: "MODEL_NOT_READY",
      model_disagreement: false,
      probability_gap: null,
      provided_feature_count: 1,
      expected_feature_count: 48,
      missing_feature_count: 47,
      missing_features: FEATURE_NAMES.slice(1),
      features: { [FEATURE_NAMES[0]]: 7 },
      integrity_alerts: ["SYNTHETIC_LOCAL_INTEGRATION_TEST"],
      reason_codes: ["UNKNOWN_MODEL_VERDICT", "INTEGRITY_ALERT"],
    };
    const responses: Record<string, unknown> = {
      "/api/auth/session": {
        authenticated: true,
        user: { user_id: "test-admin", username: "test-admin", role: "admin", tenant_id: "test-tenant" },
        csrf_token: "test-csrf-token",
        expires_at: "2026-10-18T00:00:00Z",
      },
      "/health": { status: "ok", service: "tracegate-r", model_ready: false, feature_count: 48 },
      "/api/model-info": {
        models_available: false,
        feature_count: 48,
        feature_names: FEATURE_NAMES,
        schema_valid: false,
        schema_error: "ARTIFACT_FEATURE_SCHEMA_MISSING",
        model_readiness_error: "Required model artifacts are missing.",
      },
      "/api/audit?limit=200": { count: 0, events: [] },
      "/api/predict": prediction,
    };
    let submittedCsrf: string | null = null;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/api/predict") {
        submittedCsrf = new Headers(init?.headers).get("X-TraceGate-CSRF");
      }
      return {
        ok: true,
        status: 200,
        json: async () => responses[String(input)],
      } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App initialMode="live" />);
    await waitFor(() => expect(screen.getByRole("button", { name: /Sign out/ })).toBeTruthy());
    fireEvent.click(screen.getByRole("link", { name: "Observation analysis" }));
    const submit = screen.getByRole("button", { name: "Submit to live prediction API" }) as HTMLButtonElement;
    await waitFor(() => expect(submit.disabled).toBe(false));

    fireEvent.change(screen.getByLabelText(/Feature values/), {
      target: { value: JSON.stringify({ [FEATURE_NAMES[0]]: 7 }) },
    });
    fireEvent.click(submit);

    await waitFor(() => expect(screen.getByText("Response received")).toBeTruthy());
    expect(screen.getByText(/accepted without an available model score/)).toBeTruthy();
    expect(submittedCsrf).toBe("test-csrf-token");
  });

  it("renders API-reported model unavailability and partial audit evidence without filling missing features", async () => {
    const event = {
      event_id: "PARTIAL-OBS-1",
      created_at: "2026-10-17T10:00:00Z",
      package_ref: "analyst-sample",
      decision: "REVIEW_REQUIRED",
      model_verdict: "unknown",
      score_available: false,
      ensemble_probability: null,
      model_probabilities: { logistic_regression: null, random_forest: null, ensemble: null },
      features: { [FEATURE_NAMES[0]]: 2.5, [FEATURE_NAMES[1]]: null },
      missing_features: FEATURE_NAMES.slice(1),
      missing_feature_count: 47,
      provided_feature_count: 1,
      expected_feature_count: 48,
      integrity_alerts: ["FEATURE_VECTOR_INCOMPLETE:47"],
    };
    const responses: Record<string, unknown> = {
      "/api/auth/session": {
        authenticated: true,
        user: { user_id: "test-admin", username: "test-admin", role: "admin", tenant_id: "test-tenant" },
        csrf_token: "test-csrf-token",
        expires_at: "2026-10-18T00:00:00Z",
      },
      "/health": { status: "ok", service: "tracegate-r", model_ready: false, feature_count: 48 },
      "/api/model-info": {
        models_available: false,
        feature_count: 48,
        feature_names: FEATURE_NAMES,
        schema_valid: false,
        schema_error: "ARTIFACT_FEATURE_SCHEMA_MISSING",
        model_readiness_error: "Required model artifacts are missing.",
      },
      "/api/audit?limit=200": { count: 1, events: [event] },
    };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => ({
      ok: true,
      status: 200,
      json: async () => responses[String(input)],
    }) as Response));
    render(<App initialMode="live" />);
    await waitFor(() => expect(screen.getByText("LIVE API VERIFIED")).toBeTruthy());
    expect(screen.getByText("Required model artifacts are missing.")).toBeTruthy();
    expect(screen.getByRole("button", { name: `Feature 2: ${FEATURE_NAMES[1]}. Missing.` })).toBeTruthy();
    expect(screen.queryByText("DEMO DATA — NOT LIVE TELEMETRY")).toBeNull();

    fireEvent.click(screen.getByRole("link", { name: "Model & schema" }));
    expect(screen.getByText(/trained-model feature_names\.json is missing/)).toBeTruthy();
    expect(screen.getByText("Artifact schema missing")).toBeTruthy();
    fireEvent.click(screen.getByRole("link", { name: "Audit timeline" }));
    expect(screen.getByText("PARTIAL-OBS-1")).toBeTruthy();
    expect(screen.getByText("Unavailable")).toBeTruthy();
    expect(screen.getByText("47", { selector: "td" })).toBeTruthy();
  });
});
