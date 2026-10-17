export type Mode = "live" | "demo";
export type UserRole = "admin" | "user";

export interface AuthUser {
  user_id: string;
  username: string;
  role: UserRole;
  tenant_id: string;
}

export interface AuthSession {
  authenticated: boolean;
  user: AuthUser | null;
  csrf_token: string | null;
  expires_at: string | null;
}

export interface AdminUser extends AuthUser {
  active: boolean;
  created_at?: string;
  updated_at?: string;
}

export type Decision = "REVIEW_REQUIRED" | "EVIDENCE_SUFFICIENT" | string;

export type FeatureState = "measured" | "missing" | "invalid" | "not-reported";

export interface ApiHealth {
  status?: string;
  service?: string;
  model_ready?: boolean;
  feature_count?: number;
}

export interface ModelInfo {
  models_available?: boolean;
  missing_artifacts?: string[];
  feature_count?: number;
  feature_names?: string[];
  schema_valid?: boolean;
  schema_error?: string | null;
  model_readiness_error?: string | null;
  schema_sha256?: string | null;
  offline_benchmark?: Record<string, unknown>;
  ensemble_benchmark?: unknown;
  benchmark_split?: unknown;
}

export interface AuditEvent {
  event_id: string;
  created_by_user_id?: string | null;
  tenant_id?: string | null;
  created_at?: string | null;
  package_ref?: string | null;
  model_verdict?: string | null;
  decision?: Decision | null;
  logistic_probability?: number | null;
  random_forest_probability?: number | null;
  ensemble_probability?: number | null;
  model_probabilities?: {
    logistic_regression?: number | null;
    random_forest?: number | null;
    ensemble?: number | null;
  };
  model_labels?: Record<string, number | string | null>;
  model_disagreement?: boolean;
  score_available?: boolean;
  prediction_unavailable_reason?: string | null;
  probability_gap?: number | null;
  coverage_percent?: number | null;
  provided_feature_count?: number | null;
  expected_feature_count?: number | null;
  missing_feature_count?: number | null;
  missing_features?: string[];
  schema_sha256?: string | null;
  features?: Record<string, number | null | unknown>;
  evidence?: Record<string, string>;
  integrity_alerts?: string[];
  reason_codes?: string[];
  [key: string]: unknown;
}

export interface AuditResponse {
  count?: number;
  events: AuditEvent[];
}

export interface PredictionResponse extends AuditEvent {
  model_probabilities: NonNullable<AuditEvent["model_probabilities"]>;
  score_available: boolean;
  decision: string;
}

export interface LiveSnapshot {
  health: ApiHealth | null;
  healthError: string | null;
  model: ModelInfo | null;
  modelError: string | null;
  audit: AuditResponse | null;
  auditError: string | null;
  latencyMs: number | null;
  lastSuccessfulRefresh: string | null;
  refreshing: boolean;
}

export interface ObservationPayload {
  event_id?: string;
  package_ref: string | null;
  features: Record<string, number | null>;
  evidence: Record<string, string>;
  integrity_alerts: string[];
}

export interface DemoDataset {
  health: ApiHealth;
  latencyMs: number;
  model: ModelInfo;
  events: AuditEvent[];
}
