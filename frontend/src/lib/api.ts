import { matchesReleaseSchema } from "../schema";
import type {
  ApiHealth,
  AdminUser,
  AuthSession,
  AuditEvent,
  AuditResponse,
  LiveSnapshot,
  ModelInfo,
  Mode,
  ObservationPayload,
  PredictionResponse,
  UserRole,
} from "../types";

const REQUEST_TIMEOUT_MS = 5_000;
let csrfToken: string | null = null;

function configuredApiBase(): string | null {
  const configured = import.meta.env.VITE_TRACEGATE_API_BASE?.trim();
  if (!configured) return null;
  try {
    const url = new URL(configured);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
      throw new Error("VITE_TRACEGATE_API_BASE must be a bare HTTPS origin without credentials, path, query, or fragment.");
    }
    const host = url.hostname.toLowerCase();
    const parts = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)?.slice(1).map(Number);
    const privateIpv4 = Boolean(parts && (
      parts[0] === 10 || parts[0] === 127 || parts[0] === 0 ||
      (parts[0] === 169 && parts[1] === 254) ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168)
    ));
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || privateIpv4 || host === "::1" || host.startsWith("fc") || host.startsWith("fd")) {
      throw new Error("A private or loopback API origin cannot be embedded in browser code.");
    }
    return url.origin;
  } catch (error) {
    throw new ApiError(error instanceof Error ? error.message : "Invalid configured API origin.");
  }
}

export class ApiError extends Error {
  constructor(message: string, readonly status: number | null = null) {
    super(message);
    this.name = "ApiError";
  }
}

export async function requestJson<T>(
  path: string,
  init: RequestInit = {},
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<T> {
  if (!path.startsWith("/") || path.startsWith("//")) {
    throw new ApiError("Only same-origin API paths are allowed.");
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    const method = (init.method ?? "GET").toUpperCase();
    if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken && !headers.has("X-TraceGate-CSRF")) {
      headers.set("X-TraceGate-CSRF", csrfToken);
    }
    const apiBase = configuredApiBase();
    const url = apiBase ? `${apiBase}${path}` : path;
    const response = await fetch(url, {
      ...init,
      credentials: "include",
      cache: "no-store",
      signal: controller.signal,
      headers,
    });
    const body: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      const detail = body && typeof body === "object" && "detail" in body
        ? (body as { detail?: unknown }).detail
        : null;
      const message = typeof detail === "string" ? detail : `Request failed (HTTP ${response.status}).`;
      throw new ApiError(message, response.status);
    }
    return body as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted) throw new ApiError("Request timed out. The live API did not respond in time.");
    throw new ApiError("The live API is unavailable at this origin.");
  } finally {
    clearTimeout(timer);
  }
}

async function settled<T>(work: Promise<T>): Promise<{ value: T | null; error: string | null }> {
  try {
    return { value: await work, error: null };
  } catch (error) {
    return { value: null, error: error instanceof Error ? error.message : "Request failed." };
  }
}

async function fetchTimedHealth(): Promise<{ health: ApiHealth; latencyMs: number }> {
  const started = performance.now();
  const health = await requestJson<ApiHealth>("/health");
  return { health, latencyMs: performance.now() - started };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return isRecord(value) && Object.values(value).every((entry) => typeof entry === "string");
}

function isAuditEvent(value: unknown): value is AuditEvent {
  if (!isRecord(value) || typeof value.event_id !== "string" || !value.event_id.trim()) return false;
  const nullableStrings = ["created_by_user_id", "tenant_id", "created_at", "package_ref", "model_verdict", "decision", "prediction_unavailable_reason", "schema_sha256"];
  if (nullableStrings.some((key) => value[key] != null && typeof value[key] !== "string")) return false;
  const nullableNumbers = ["logistic_probability", "random_forest_probability", "ensemble_probability", "probability_gap", "coverage_percent", "provided_feature_count", "expected_feature_count", "missing_feature_count"];
  if (nullableNumbers.some((key) => value[key] != null && (typeof value[key] !== "number" || !Number.isFinite(value[key])))) return false;
  if (["model_disagreement", "score_available"].some((key) => value[key] != null && typeof value[key] !== "boolean")) return false;
  if (["missing_features", "integrity_alerts", "reason_codes"].some((key) => value[key] != null && (!Array.isArray(value[key]) || !value[key].every((entry) => typeof entry === "string")))) return false;
  if (value.features != null && (!isRecord(value.features) || !Object.values(value.features).every((entry) => entry === null || (typeof entry === "number" && Number.isFinite(entry))))) return false;
  if (value.evidence != null && !isStringRecord(value.evidence)) return false;
  if (value.model_probabilities != null && (!isRecord(value.model_probabilities) || !Object.values(value.model_probabilities).every((entry) => entry === null || (typeof entry === "number" && Number.isFinite(entry))))) return false;
  if (value.model_labels != null && (!isRecord(value.model_labels) || !Object.values(value.model_labels).every((entry) => entry === null || typeof entry === "string" || (typeof entry === "number" && Number.isFinite(entry))))) return false;
  return true;
}

function isAuditResponse(value: unknown): value is AuditResponse {
  return isRecord(value)
    && Array.isArray(value.events)
    && value.events.every(isAuditEvent)
    && (value.count == null || (typeof value.count === "number" && Number.isInteger(value.count) && value.count >= 0));
}

export async function fetchAuthSession(): Promise<AuthSession> {
  const session = await requestJson<AuthSession>("/api/auth/session");
  if (!session || typeof session.authenticated !== "boolean" || (session.authenticated && (!session.user || typeof session.csrf_token !== "string"))) {
    throw new ApiError("The authentication endpoint returned an invalid session response.");
  }
  csrfToken = session.authenticated ? session.csrf_token : null;
  return session;
}

export async function signIn(username: string, password: string): Promise<AuthSession> {
  csrfToken = null;
  const session = await requestJson<AuthSession>("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!session.authenticated || !session.user || typeof session.csrf_token !== "string") {
    throw new ApiError("The sign-in response did not establish a valid session.");
  }
  csrfToken = session.csrf_token;
  return session;
}

export async function signOut(): Promise<void> {
  await requestJson<{ authenticated: boolean }>("/api/auth/logout", { method: "POST" });
  csrfToken = null;
}

export function clearClientSession(): void {
  csrfToken = null;
}

export async function createAdminTenant(input: { tenant_id: string; display_name: string }): Promise<{ tenant_id: string; display_name: string }> {
  return requestJson("/api/admin/tenants", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input),
  });
}

export async function fetchAdminUsers(): Promise<AdminUser[]> {
  const result = await requestJson<{ users: AdminUser[] }>("/api/admin/users");
  return result.users;
}

export async function createAdminUser(input: { username: string; role: UserRole; tenant_id: string }): Promise<AdminUser & { enrollment_token: string; token_expires_at: string }> {
  return requestJson("/api/admin/users", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input),
  });
}

export async function updateAdminUser(userId: string, input: { role?: UserRole; tenant_id?: string; active?: boolean }): Promise<AdminUser> {
  return requestJson(`/api/admin/users/${encodeURIComponent(userId)}`, {
    method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input),
  });
}

export async function resetAdminUserPassword(userId: string): Promise<{ user_id: string; reset_token: string; token_expires_at: string }> {
  return requestJson(`/api/admin/users/${encodeURIComponent(userId)}/reset-password`, { method: "POST" });
}

export async function fetchLiveSnapshot(authenticated = true): Promise<Omit<LiveSnapshot, "refreshing">> {
  const auditWork = authenticated
    ? settled(requestJson<AuditResponse>("/api/audit?limit=200"))
    : Promise.resolve({ value: null, error: "Sign in to retrieve tenant-authorized audit records." });
  const [healthResult, modelResult, auditResult] = await Promise.all([
    settled(fetchTimedHealth()),
    settled(requestJson<ModelInfo>("/api/model-info")),
    auditWork,
  ]);
  const validAudit = isAuditResponse(auditResult.value) ? auditResult.value : null;
  const health = healthResult.value?.health ?? null;
  const validHealth = health?.status === "ok" ? health : null;
  return {
    health: validHealth,
    healthError: validHealth ? null : healthResult.error ?? "The health response did not report status=ok.",
    model: modelResult.value,
    modelError: modelResult.error,
    audit: validAudit,
    auditError: validAudit
      ? null
      : auditResult.error ?? "The audit response was malformed and could not be displayed.",
    latencyMs: validHealth && healthResult.value
      ? Number(healthResult.value.latencyMs.toFixed(1))
      : null,
    lastSuccessfulRefresh: validHealth ? new Date().toISOString() : null,
  };
}

export function isLiveSchemaReady(model: ModelInfo | null): boolean {
  return Boolean(model && model.schema_valid === true && matchesReleaseSchema(model.feature_names));
}

export async function submitPrediction(
  payload: ObservationPayload,
  mode: Mode,
  liveSubmissionReady: boolean,
): Promise<PredictionResponse> {
  if (mode !== "live") throw new ApiError("Demo Mode never sends observations to the API.");
  if (!liveSubmissionReady) throw new ApiError("Submission requires a healthy API and the validated 48-feature schema.");
  if (!csrfToken) throw new ApiError("Sign in with an authorized user or administrator account before submitting an observation.");
  return requestJson<PredictionResponse>("/api/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function requestOfflineExplanation(eventId: string, mode: Mode): Promise<string> {
  if (mode !== "live") throw new ApiError("Demo explanations are local and never call the API.");
  if (!csrfToken) throw new ApiError("Sign in with an authorized user or administrator account before requesting an explanation.");
  const response = await requestJson<{ explanation: string; formal_decision_changed: boolean; capability: string; external_llm: boolean }>("/api/genai/explain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event_id: eventId }),
  });
  if (response.formal_decision_changed !== false || response.external_llm !== false
      || response.capability !== "Deterministic Evidence Explanation"
      || typeof response.explanation !== "string") {
    throw new ApiError("The explanation response did not meet the deterministic explanation contract.");
  }
  return response.explanation;
}
