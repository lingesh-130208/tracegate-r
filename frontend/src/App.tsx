import { type FormEvent, type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, BookOpen, Check, ChevronDown,
  ChevronLeft, ChevronRight, CircleHelp, Clock3, Copy, Cpu, Database, FileSearch,
  Fingerprint, Gauge, Layers3, Menu, Network, RefreshCw, RotateCcw, Search,
  Server, Settings2, ShieldAlert, ShieldCheck, Sparkles, Terminal, Wifi, WifiOff, X,
} from "lucide-react";
import { EvidenceSignalGrid, type SignalNode } from "./components/EvidenceSignalGrid";
import { FeatureMatrix } from "./components/FeatureMatrix";
import { createDemoDataset, explainDemoEvent } from "./lib/demo";
import {
  clearClientSession, createAdminTenant, createAdminUser, fetchAdminUsers, fetchAuthSession,
  fetchLiveSnapshot, isLiveSchemaReady, requestOfflineExplanation, resetAdminUserPassword,
  signIn, signOut, submitPrediction, updateAdminUser,
} from "./lib/api";
import { featureCoverage, orderAuditEvents, paginate, parseObservation, scoreText } from "./lib/logic";
import { EXPECTED_FEATURE_COUNT, FEATURE_NAMES, matchesReleaseSchema } from "./schema";
import type { AdminUser, AuditEvent, AuthSession, LiveSnapshot, Mode, ObservationPayload, UserRole } from "./types";

type Page = "overview" | "audit" | "model" | "runtime" | "analysis" | "diagnostics";
const PAGE_NAMES: Record<Page, string> = {
  overview: "Overview",
  audit: "Audit timeline",
  model: "Model & feature schema",
  runtime: "Runtime telemetry",
  analysis: "Observation analysis",
  diagnostics: "System diagnostics",
};

const NAV_ITEMS = [
  { id: "overview", label: "Overview", icon: Gauge },
  { id: "audit", label: "Audit timeline", icon: Activity },
  { id: "model", label: "Model & schema", icon: Layers3 },
  { id: "runtime", label: "Runtime telemetry", icon: Network },
  { id: "analysis", label: "Observation analysis", icon: FileSearch },
  { id: "diagnostics", label: "System diagnostics", icon: Settings2 },
] as const;

const EMPTY_LIVE: LiveSnapshot = {
  health: null,
  healthError: null,
  model: null,
  modelError: null,
  audit: null,
  auditError: null,
  latencyMs: null,
  lastSuccessfulRefresh: null,
  refreshing: false,
};

function pageFromHash(): Page {
  const name = window.location.hash.replace(/^#\/?/, "").split("/")[0] as Page;
  return name in PAGE_NAMES ? name : "overview";
}

function formatTimestamp(value?: string | null): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, {
    month: "short", day: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).format(date);
}

function authSessionLabel(session: AuthSession | null, error: string | null): string {
  if (error) return `Unavailable: ${error}`;
  if (!session?.authenticated || !session.user) return "Not signed in";
  return `${session.user.username} · ${session.user.role} · tenant ${session.user.tenant_id}`;
}

function safeNumber(value: unknown, digits = 1): string {
  return typeof value === "number" && Number.isFinite(value) ? value.toFixed(digits) : "Not reported";
}

function modelLabelText(value: unknown): string {
  if (value === 1) return "malicious (1)";
  if (value === 0) return "benign (0)";
  return typeof value === "string" ? value : "Not reported";
}

function decisionTone(decision?: string | null): string {
  if (decision === "REVIEW_REQUIRED") return "amber";
  if (decision === "EVIDENCE_SUFFICIENT") return "cyan";
  return "slate";
}

function coverageForEvent(event: AuditEvent | null): string {
  const counts = featureCoverage(FEATURE_NAMES, event);
  if (!event) return "Not reported";
  const provided = event.provided_feature_count;
  const expected = event.expected_feature_count;
  if (typeof provided === "number" && typeof expected === "number") return `${provided} / ${expected}`;
  if (counts.notReported < FEATURE_NAMES.length) return `${counts.measured} / ${FEATURE_NAMES.length}`;
  return "Not reported";
}

function MetricPanel({
  icon: Icon, label, value, detail, tone = "cyan", foot,
}: {
  icon: typeof Gauge;
  label: string;
  value: string;
  detail: string;
  tone?: string;
  foot: string;
}) {
  return (
    <article className={`metric-panel metric-${tone}`}>
      <div className="metric-top"><span className="metric-label">{label}</span><span className="metric-icon"><Icon size={17} strokeWidth={1.8} /></span></div>
      <p className="metric-value">{value}</p>
      <p className="metric-detail">{detail}</p>
      <div className="metric-foot"><span className={`metric-foot-dot ${tone}`} />{foot}</div>
    </article>
  );
}

function StateBadge({ children, tone = "slate" }: { children: ReactNode; tone?: string }) {
  return <span className={`state-badge ${tone}`}><span className="badge-mark" aria-hidden="true" />{children}</span>;
}

function SectionHeading({ eyebrow, title, description, trailing }: {
  eyebrow: string; title: string; description: string; trailing?: ReactNode;
}) {
  return (
    <div className="section-heading">
      <div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="lede">{description}</p></div>
      {trailing && <div className="heading-trailing">{trailing}</div>}
    </div>
  );
}

function EmptyState({ icon: Icon = CircleHelp, title, detail, action }: {
  icon?: typeof CircleHelp; title: string; detail: string; action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon"><Icon size={18} /></span>
      <div><strong>{title}</strong><p>{detail}</p>{action}</div>
    </div>
  );
}

function AuditGrid({ events, onInspect, source, loading = false }: {
  events: AuditEvent[]; onInspect: (event: AuditEvent) => void; source: "live" | "demo"; loading?: boolean;
}) {
  if (loading) return <div className="loading-state" role="status" aria-busy="true"><strong>Loading audit records</strong><span className="loading-line wide" /><span className="loading-line medium" /><span className="loading-line short" /></div>;
  if (!events.length) return <EmptyState icon={Database} title="No audit records returned" detail={source === "live" ? "The live audit API returned an empty result. No example records are substituted." : "The deterministic demo fixture has no events to show."} />;
  return (
    <div className="data-grid-wrap">
      <table className="audit-grid">
        <thead><tr><th>Event / reference</th><th>Recorded at</th><th>Score</th><th>Coverage</th><th>Missing</th><th>Alerts</th><th>Formal decision</th><th><span className="sr-only">Inspect</span></th></tr></thead>
        <tbody>{events.map((event) => {
          const score = event.score_available === true
            ? (event.model_probabilities?.ensemble ?? event.ensemble_probability)
            : null;
          const missing = typeof event.missing_feature_count === "number"
            ? event.missing_feature_count
            : event.missing_features?.length;
          const alerts = event.integrity_alerts?.length;
          return (
            <tr key={event.event_id}>
              <td><span className="event-id">{event.event_id}</span><span className="event-ref">{event.package_ref || "Reference not recorded"}</span></td>
              <td className="mono-cell">{formatTimestamp(event.created_at)}</td>
              <td>{event.score_available === true && typeof score === "number" && Number.isFinite(score)
                ? <div className="score-cell"><span className="score-track" role="progressbar" aria-label="Ensemble score" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(score * 100)}><i style={{ width: `${Math.max(0, Math.min(100, score * 100))}%` }} /></span><b>{scoreText(event)}</b></div>
                : <span className="muted-value">{scoreText(event)}</span>}</td>
              <td>{coverageForEvent(event)}</td>
              <td>{typeof missing === "number" ? missing : "Not reported"}</td>
              <td>{typeof alerts === "number" ? alerts : "Not reported"}</td>
              <td><StateBadge tone={decisionTone(event.decision)}>{event.decision || "Not recorded"}</StateBadge></td>
              <td><button className="icon-button inspect-button" type="button" aria-label={`Inspect ${event.event_id}`} onClick={() => onInspect(event)}><ChevronRight size={16} /></button></td>
            </tr>
          );
        })}</tbody>
      </table>
    </div>
  );
}

function EvidenceTimeline({ events, onInspect, source, loading = false }: {
  events: AuditEvent[]; onInspect: (event: AuditEvent) => void; source: Mode; loading?: boolean;
}) {
  if (loading) return <div className="loading-state compact" role="status" aria-busy="true"><strong>Loading returned activity</strong><span className="loading-line wide" /><span className="loading-line medium" /></div>;
  if (!events.length) return <EmptyState icon={Clock3} title="Timeline is empty" detail={source === "live" ? "No saved observations were returned by the audit API." : "No synthetic observations are present in the demo fixture."} />;
  return <ol className="event-timeline">
    {events.slice(0, 5).map((event) => (
      <li key={event.event_id}>
        <span className={`timeline-marker ${decisionTone(event.decision)}`} aria-hidden="true" />
        <button className="timeline-record" type="button" aria-label={`Inspect event ${event.event_id}`} onClick={() => onInspect(event)}>
          <span className="timeline-head"><strong>{event.package_ref || event.event_id}</strong><StateBadge tone={decisionTone(event.decision)}>{event.decision || "Not recorded"}</StateBadge></span>
          <span className="timeline-meta"><span>{formatTimestamp(event.created_at)}</span><span>{event.event_id}</span><span>{scoreText(event)} score</span></span>
        </button>
      </li>
    ))}
  </ol>;
}

function nodeStatuses(mode: Mode, model: LiveSnapshot["model"], audit: LiveSnapshot["audit"], latest: AuditEvent | null): SignalNode[] {
  const isDemo = mode === "demo";
  const schemaReady = model?.schema_valid === true && matchesReleaseSchema(model.feature_names);
  const artifactSchemaMissing = model?.schema_error === "ARTIFACT_FEATURE_SCHEMA_MISSING";
  const schemaStatus: SignalNode["status"] = schemaReady ? "verified" : model?.schema_valid === false ? "unavailable" : "not-reported";
  const modelsStatus: SignalNode["status"] = model?.models_available === true ? "verified" : model?.models_available === false ? "unavailable" : "not-reported";
  const gateStatus: SignalNode["status"] = latest?.decision === "REVIEW_REQUIRED" ? "partial" : latest?.decision === "EVIDENCE_SUFFICIENT" ? "verified" : "not-reported";
  const auditStatus: SignalNode["status"] = audit ? "verified" : "not-reported";
  return [
    { id: "collector", title: "Runtime collector", subtitle: "NOT REPORTED", status: "not-reported", detail: "The API does not expose collector process, probe, or capture status. The website cannot start bpftrace and does not infer collector health.", icon: <Network size={16} /> },
    { id: "validation", title: "Feature validation", subtitle: isDemo ? "DEMO REFERENCE" : schemaStatus === "verified" ? "SCHEMA VERIFIED" : artifactSchemaMissing ? "ARTIFACT SCHEMA MISSING" : schemaStatus === "unavailable" ? "ARTIFACT SCHEMA INVALID" : "NOT REPORTED", status: schemaStatus, detail: isDemo ? "Synthetic demo schema view; it is not a live model-artifact validation." : schemaReady ? "The API reported a valid model artifact schema in the exact ordered 48-feature release sequence." : artifactSchemaMissing ? "The checked-in 48-feature release schema remains available, but the API reports that the trained-model feature_names.json artifact is missing. Model schema validation and scoring remain unavailable." : model?.schema_valid === false ? `The API reports a model artifact schema error: ${model.schema_error || "SCHEMA_INVALID"}.` : "The model-info API has not verified feature-schema validity." , icon: <Layers3 size={16} /> },
    { id: "models", title: "Model ensemble", subtitle: isDemo ? "DEMO STATE" : modelsStatus === "verified" ? "AVAILABLE" : modelsStatus === "unavailable" ? "NOT READY" : "NOT REPORTED", status: modelsStatus, detail: isDemo ? "Illustrative model state in synthetic demo data; no trained artifacts are packaged in the website." : model?.models_available === true ? "The API reports the model artifacts as available. Per-estimator readiness is not reported separately." : model?.models_available === false ? "The API reports the trained model artifacts are unavailable or incompatible." : "Model readiness is not reported because the model-info API did not respond." , icon: <Cpu size={16} /> },
    { id: "gate", title: "Evidence gate", subtitle: isDemo ? "EXAMPLE DECISION" : latest?.decision ?? "NO RECENT DECISION", status: gateStatus, detail: latest ? `The latest returned record reports ${latest.decision ?? "no decision"}. EVIDENCE_SUFFICIENT means the supplied evidence passed the gate; it does not guarantee safety. REVIEW_REQUIRED requests human review and does not prove maliciousness or external enforcement.` : "No recent audit decision was returned. The gate's readiness is not inferred from the absence of records.", icon: <ShieldCheck size={16} /> },
    { id: "audit", title: "SQLite audit", subtitle: isDemo ? "LOCAL FIXTURE" : audit ? `${audit.events.length} RETURNED` : "NOT REPORTED", status: auditStatus, detail: isDemo ? "Synthetic events exist only in the browser fixture and are never inserted into SQLite." : audit ? `${audit.events.length} records were returned in this response; this is not a lifetime event total.` : "Audit persistence state is not reported because the audit endpoint did not respond.", icon: <Database size={16} /> },
  ];
}

function Overview({
  mode, health, model, audit, events, latest, latency, healthError, modelError, auditError, refreshing, onInspect, onSelectPage, onSelectNode,
}: {
  mode: Mode; health: LiveSnapshot["health"]; model: LiveSnapshot["model"]; audit: LiveSnapshot["audit"];
  events: AuditEvent[]; latest: AuditEvent | null; latency: number | null; healthError: string | null;
  modelError: string | null; auditError: string | null; refreshing: boolean; onInspect: (event: AuditEvent) => void; onSelectPage: (page: Page) => void; onSelectNode: (node: SignalNode) => void;
}) {
  const demo = mode === "demo";
  const healthy = demo || health?.status === "ok";
  const schemaReady = demo || (model?.schema_valid === true && matchesReleaseSchema(model.feature_names));
  const modelReady = demo || model?.models_available === true;
  const eventCount = demo ? events.length : audit?.events.length;
  const nodes = nodeStatuses(mode, model, audit, latest);
  const eventCountText = typeof eventCount === "number" ? String(eventCount) : "Unavailable";
  const latestGate = latest?.decision ?? "No event returned";
  return (
    <>
      <SectionHeading eyebrow="Evidence-first security operations" title="Runtime evidence, in focus." description="A clear view of what the API reports, what the models can score, and where evidence still needs review." trailing={<div className="schema-chip"><span className="chip-orbit" />48 <small>FEATURE CONTRACT</small></div>} />
      {!demo && (!health || healthError) && <div className="alert-strip warning"><WifiOff size={17} /><div><strong>LIVE API UNAVAILABLE</strong><span>{healthError || "No successful health response from this origin. Live records and model state remain unavailable."}</span></div></div>}
      {!demo && modelError && <div className="alert-strip warning"><AlertTriangle size={17} /><div><strong>Model metadata unavailable</strong><span>{modelError}</span></div></div>}
      {!demo && auditError && <div className="alert-strip neutral"><Database size={17} /><div><strong>Audit response unavailable</strong><span>{auditError}</span></div></div>}
      <div className="metric-grid">
        <MetricPanel icon={Wifi} label="API health" value={demo ? "SIMULATED" : healthy ? "HEALTHY" : "UNAVAILABLE"} tone={demo ? "violet" : healthy ? "green" : "amber"} detail={demo ? "Synthetic fixture · not a service check" : healthy ? `Measured ${safeNumber(latency)} ms to /health` : "No successful health response"} foot={demo ? "DEMO DATA" : health?.service ?? "No verified connection"} />
        <MetricPanel icon={Cpu} label="Model ensemble" value={demo ? "ILLUSTRATIVE" : modelReady ? "AVAILABLE" : model?.models_available === false ? "NOT READY" : "UNAVAILABLE"} tone={demo ? "violet" : modelReady ? "green" : "amber"} detail={demo ? "Example state · no model is loaded here" : model ? `${model.feature_count ?? "Not reported"} schema features` : "Artifact readiness not returned"} foot={demo ? "DEMO DATA" : model?.models_available === true ? "Model-info API verified" : model?.model_readiness_error || "Readiness not reported"} />
        <MetricPanel icon={ShieldAlert} label="Evidence reliability gate" value={demo ? "EXAMPLE" : latestGate} tone={demo ? "violet" : latest?.decision === "REVIEW_REQUIRED" ? "amber" : latest?.decision === "EVIDENCE_SUFFICIENT" ? "cyan" : "slate"} detail={latest ? `${latest.missing_feature_count ?? latest.missing_features?.length ?? "Not reported"} missing feature(s) · ${latest.integrity_alerts?.length ?? "Not reported"} alerts` : "No latest decision is inferred"} foot="Passing the gate does not guarantee safety" />
        <MetricPanel icon={Database} label="Audit persistence" value={eventCountText} tone={demo ? "violet" : audit ? "cyan" : "slate"} detail={demo ? "Synthetic records in browser memory only" : audit ? "Records returned in this response" : "No audit response received"} foot={latest ? `Latest ${formatTimestamp(latest.created_at)}` : "Not a lifetime event total"} />
      </div>
      <div className="overview-main-grid">
        <section className="surface signal-panel">
          <div className="surface-heading"><div><p className="eyebrow">Evidence Signal Grid</p><h2>Observation to audit trail</h2><p className="surface-subtitle">Five stages · subsystem status from current response</p></div><span className="quiet-badge"><span className="quiet-dot" />NO LIVE FLOW ANIMATION</span></div>
          <EvidenceSignalGrid nodes={nodes} onSelect={onSelectNode} />
        </section>
        <section className="surface timeline-panel">
          <div className="surface-heading"><div><p className="eyebrow">Recorded activity</p><h2>Security timeline</h2><p className="surface-subtitle">Recent observations in the active data mode</p></div><button className="text-action" type="button" onClick={() => onSelectPage("audit")}>Open history <ArrowUpRight size={14} /></button></div>
          <EvidenceTimeline events={events} onInspect={onInspect} source={mode} loading={mode === "live" && refreshing && !audit} />
        </section>
      </div>
      <div className="overview-lower-grid">
        <section className="surface feature-panel">
          <div className="surface-heading"><div><p className="eyebrow">Ordered feature contract</p><h2>Feature availability matrix</h2><p className="surface-subtitle">48 expected features · values never substituted</p></div><button className="icon-button" type="button" aria-label="Open model and feature schema" onClick={() => onSelectPage("model")}><ArrowUpRight size={16} /></button></div>
          <FeatureMatrix names={FEATURE_NAMES} event={latest} mode={mode} />
        </section>
        <section className="surface context-panel">
          <div className="surface-heading"><div><p className="eyebrow">Evidence context</p><h2>Latest returned record</h2><p className="surface-subtitle">This response is separate from lifetime totals</p></div><Fingerprint size={17} className="surface-icon" /></div>
          {latest ? <>
            <div className="context-event"><span className="event-id">{latest.event_id}</span><StateBadge tone={decisionTone(latest.decision)}>{latest.decision || "Not recorded"}</StateBadge></div>
            <div className="context-rows">
              <div><span>Timestamp</span><b>{formatTimestamp(latest.created_at)}</b></div>
              <div><span>Coverage</span><b>{coverageForEvent(latest)}</b></div>
              <div><span>Model score</span><b>{scoreText(latest)}</b></div>
              <div><span>Integrity alerts</span><b>{latest.integrity_alerts?.length ?? "Not reported"}</b></div>
            </div>
            <p className="policy-note"><ShieldCheck size={14} />Evidence sufficiency is not a safety guarantee. Review-required is a human review escalation, not an enforcement claim.</p>
            <button className="secondary-button full-width" type="button" onClick={() => onInspect(latest)}>Inspect record <ChevronRight size={15} /></button>
          </> : <EmptyState icon={Fingerprint} title="No latest record" detail={demo ? "The demo has no event selected." : "The API has not returned an audit record."} />}
        </section>
      </div>
      <div className="overview-readiness-row">
        <span className={`readiness-bit ${healthy ? "ok" : "off"}`}><i />{demo ? "Demo fixture" : healthy ? "API responded" : "API unavailable"}</span>
        <span className={`readiness-bit ${schemaReady ? "ok" : "off"}`}><i />{demo ? "Illustrative schema" : schemaReady ? "Schema validated" : "Schema not validated"}</span>
        <span className={`readiness-bit ${modelReady ? "ok" : "off"}`}><i />{demo ? "Example model state" : modelReady ? "Models reported available" : "Models unavailable / unknown"}</span>
        <span className={`readiness-bit ${audit ? "ok" : "off"}`}><i />{demo ? "No SQLite writes" : audit ? `${eventCountText} records returned` : "Audit unavailable"}</span>
      </div>
      <section className="surface pipeline-surface">
        <div className="surface-heading"><div><p className="eyebrow">Implemented workflow · known limits</p><h2>How TraceGate-R works</h2><p className="surface-subtitle">Each stage keeps measurement, model output, policy decision, and explanation separate.</p></div><ShieldCheck size={18} className="surface-icon" /></div>
        <ol className="pipeline-steps">
          <li><strong>Collect and extract</strong><span>A runtime collector may measure host/process behavior. Collector capture status is not reported by this API; manual JSON is analyst-provided, not automatically collected telemetry.</span></li>
          <li><strong>Map and validate</strong><span>Values map to the ordered 48-feature schema. Schema validity, missing measurements, and model artifact readiness are checked. The collector does not measure every feature.</span></li>
          <li><strong>Predict with two estimators</strong><span>When supported by the vector, Logistic Regression and Random Forest each produce a malicious-class probability. Missing values are not imputed; failed or unavailable inference stays unscored.</span></li>
          <li><strong>Combine and compare</strong><span>The ensemble is the arithmetic mean of the two probabilities. Labels use the current 0.5 threshold; disagreement is reported for differing labels or a probability gap of at least 0.25.</span></li>
          <li><strong>Apply evidence policy</strong><span>The evidence gate combines the model verdict with evidence completeness and integrity alerts to determine whether review is required. It is distinct from the model probabilities.</span></li>
          <li><strong>Persist and explain</strong><span>The result and recorded evidence/provenance are saved in the audit trail. Deterministic Evidence Explanation is a local rules-based summary of recorded event information; it does not predict maliciousness or change the formal decision.</span></li>
        </ol>
        <p className="methodology-note">Implemented and tested software stages are not proof of runtime extraction parity with QUT-DV25 or production detection accuracy. Offline benchmark results are not live-detection validation.</p>
      </section>
    </>
  );
}

function AuditPage({
  events, source, onInspect, error, loading,
}: { events: AuditEvent[]; source: Mode; onInspect: (event: AuditEvent) => void; error: string | null; loading: boolean }) {
  const [search, setSearch] = useState("");
  const [decision, setDecision] = useState("");
  const [order, setOrder] = useState<"newest" | "oldest">("newest");
  const [page, setPage] = useState(0);
  const pageSize = 8;
  const ordered = useMemo(() => orderAuditEvents(events, search, decision, order), [events, search, decision, order]);
  const pageCount = Math.max(1, Math.ceil(ordered.length / pageSize));
  const visible = paginate(ordered, page, pageSize);
  useEffect(() => setPage((current) => Math.min(current, pageCount - 1)), [pageCount]);
  return <>
    <SectionHeading eyebrow="SQLite audit · read-only view" title="Audit timeline" description="Search and inspect the records returned by the active API or the explicitly labeled demo fixture. Missing scores and incomplete evidence remain visible." trailing={<StateBadge tone={source === "demo" ? "violet" : error ? "amber" : "cyan"}>{source === "demo" ? "SYNTHETIC FIXTURE" : error ? "API ERROR" : `${events.length} RETURNED`}</StateBadge>} />
    {error && source === "live" && <div className="alert-strip warning"><AlertTriangle size={17} /><div><strong>Audit API unavailable</strong><span>{error}</span></div></div>}
    <section className="surface audit-surface">
      <div className="surface-heading audit-heading"><div><p className="eyebrow">Record explorer</p><h2>Observation ledger</h2><p className="surface-subtitle">{source === "demo" ? "Synthetic browser-only records · never persisted" : "Returned records · this is not a lifetime count"}</p></div><span className="count-chip"><b>{ordered.length}</b><small>FILTERED</small></span></div>
      <div className="audit-toolbar">
        <label className="search-field"><Search size={15} /><span className="sr-only">Search by event or package reference</span><input type="search" placeholder="Search event or package…" value={search} onChange={(event) => { setSearch(event.target.value); setPage(0); }} /></label>
        <label className="select-field"><span className="sr-only">Filter formal decision</span><select value={decision} onChange={(event) => { setDecision(event.target.value); setPage(0); }}><option value="">All decisions</option><option value="REVIEW_REQUIRED">Review required</option><option value="EVIDENCE_SUFFICIENT">Evidence sufficient</option><option value="Other">Other / unavailable</option></select><ChevronDown size={14} /></label>
        <label className="select-field"><span className="sr-only">Sort audit timeline</span><select value={order} onChange={(event) => setOrder(event.target.value as "newest" | "oldest")}><option value="newest">Newest first</option><option value="oldest">Oldest first</option></select><ChevronDown size={14} /></label>
      </div>
      <AuditGrid events={visible} source={source} onInspect={onInspect} loading={source === "live" && loading && !error} />
      {ordered.length > 0 && <div className="pagination-row"><span>Page {page + 1} of {pageCount} · {ordered.length} matching records</span><div><button className="secondary-button" type="button" aria-label="Previous page" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}><ChevronLeft size={15} />Previous</button><button className="secondary-button" type="button" aria-label="Next page" disabled={page >= pageCount - 1} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>Next<ChevronRight size={15} /></button></div></div>}
    </section>
  </>;
}

function ModelPage({ mode, model, modelError, latest }: {
  mode: Mode; model: LiveSnapshot["model"]; modelError: string | null; latest: AuditEvent | null;
}) {
  const liveSchemaMatches = model?.feature_names ? matchesReleaseSchema(model.feature_names) : false;
  const apiSchemaValid = mode === "demo" ? null : model?.schema_valid;
  const artifactSchemaMissing = model?.schema_error === "ARTIFACT_FEATURE_SCHEMA_MISSING";
  const rows = FEATURE_NAMES.map((name, index) => ({ name, index, value: latest?.features?.[name] }));
  const metrics = model?.offline_benchmark && typeof model.offline_benchmark === "object" ? Object.entries(model.offline_benchmark) : [];
  return <>
    <SectionHeading eyebrow="Schema contract · model readiness" title="Model & feature schema" description="The ordered 48-feature contract is checked against the backend response. Aggregate readiness is shown only as the API reports it; this page does not load model artifacts." trailing={<span className="count-chip"><b>48</b><small>ORDERED FEATURES</small></span>} />
    {mode === "live" && modelError && <div className="alert-strip warning"><AlertTriangle size={17} /><div><strong>Model metadata unavailable</strong><span>{modelError}</span></div></div>}
    <div className="model-summary-grid">
      <section className="surface model-readiness-card"><div className="surface-heading"><div><p className="eyebrow">Artifact status</p><h2>Ensemble readiness</h2></div><Cpu size={18} className="surface-icon" /></div>
        <div className="readiness-hero"><span className={`readiness-glyph ${mode === "demo" ? "demo" : model?.models_available ? "ready" : "unready"}`}><Layers3 size={23} /></span><div><strong>{mode === "demo" ? "Illustrative demo state" : model?.models_available === true ? "Models available" : model?.models_available === false ? "Models not ready" : "Not reported"}</strong><span>{mode === "demo" ? "Synthetic fixture only; no trained model is included in this website." : model?.model_readiness_error || (model ? "Per-estimator readiness is not reported separately." : "The model-info endpoint did not respond.")}</span></div></div>
        <div className="diagnostic-pairs"><div><span>API model artifacts</span><b>{mode === "demo" ? "Illustrative only" : model?.models_available === true ? "Ready (API)" : model?.models_available === false ? "Not ready (API)" : "Not reported"}</b></div><div><span>48-feature schema</span><b>{mode === "demo" ? "Fixture reference only" : apiSchemaValid === true && liveSchemaMatches ? "Valid and ordered (API)" : artifactSchemaMissing ? "Artifact schema missing" : apiSchemaValid === false ? "Invalid (API)" : "Not reported"}</b></div></div>
      </section>
      <section className="surface schema-identity-card"><div className="surface-heading"><div><p className="eyebrow">Feature identity</p><h2>Release schema reference</h2></div><Fingerprint size={18} className="surface-icon" /></div>
        <div className="schema-number"><strong>48</strong><span>ordered features<br />from repository schema</span></div>
        <div className="schema-validation-note"><span className={`validation-mark ${mode === "demo" ? "demo" : liveSchemaMatches && apiSchemaValid === true ? "pass" : artifactSchemaMissing || (!model && mode === "live") ? "unknown" : apiSchemaValid === false || (model?.feature_names && !liveSchemaMatches) ? "fail" : "unknown"}`}>{mode === "demo" ? <Activity size={14} /> : liveSchemaMatches && apiSchemaValid === true ? <Check size={14} /> : apiSchemaValid === false && !artifactSchemaMissing ? <X size={14} /> : <CircleHelp size={14} />}</span><span>{mode === "demo" ? "Demo reference only; no live model validation." : liveSchemaMatches && apiSchemaValid === true ? "The API reports a valid artifact schema, and its feature list matches the local release order." : artifactSchemaMissing ? "The API feature list matches the local release order, but trained-model feature_names.json is missing; artifact schema validation and scoring remain unavailable." : apiSchemaValid === false ? `The API reports an artifact schema error: ${model?.schema_error || "SCHEMA_INVALID"}.` : model?.feature_names && !liveSchemaMatches ? "The API feature list differs from the local release schema; submission stays disabled." : "Backend schema identity is not yet available."}</span></div>
        {model?.schema_sha256 ? <div className="hash-box"><span>API-reported schema SHA-256</span><code>{model.schema_sha256}</code></div> : <div className="hash-box muted"><span>Schema SHA-256</span><code>{mode === "demo" ? "Not part of demo fixture" : "Not reported by API"}</code></div>}
      </section>
    </div>
    <section className="surface model-output-surface"><div className="surface-heading"><div><p className="eyebrow">{mode === "demo" ? "Synthetic demo fixture" : "Latest returned event"}</p><h2>Estimator outputs</h2><p className="surface-subtitle">{mode === "demo" ? "Synthetic fixture values only—not returned by a live API." : "Per-event values are displayed only when recorded and returned by the API."}</p></div><Cpu size={18} className="surface-icon" /></div>
      {latest ? (() => {
        const probabilities = latest.model_probabilities ?? {
          logistic_regression: latest.logistic_probability,
          random_forest: latest.random_forest_probability,
          ensemble: latest.ensemble_probability,
        };
        const probability = (value: number | null | undefined) => latest.score_available === true
          && typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1
          ? `${(value * 100).toFixed(1)}%`
          : "Unavailable / null";
        return <div className="diagnostic-pairs">
          <div><span>Logistic Regression malicious probability</span><b>{probability(probabilities.logistic_regression)}</b></div>
          <div><span>Logistic Regression label</span><b>{modelLabelText(latest.model_labels?.logistic_regression)}</b></div>
          <div><span>Random Forest malicious probability</span><b>{probability(probabilities.random_forest)}</b></div>
          <div><span>Random Forest label</span><b>{modelLabelText(latest.model_labels?.random_forest)}</b></div>
          <div><span>Arithmetic-mean ensemble</span><b>{probability(probabilities.ensemble)}</b></div>
          <div><span>Probability gap</span><b>{typeof latest.probability_gap === "number" ? `${(latest.probability_gap * 100).toFixed(1)} percentage points` : "Not reported"}</b></div>
          <div><span>Model disagreement</span><b>{typeof latest.model_disagreement === "boolean" ? latest.model_disagreement ? "Yes" : "No" : "Not reported"}</b></div>
          <div><span>Missing measurements</span><b>{latest.missing_feature_count ?? latest.missing_features?.length ?? "Not reported"} · never zero-imputed</b></div>
        </div>;
      })() : <EmptyState icon={Cpu} title="No event outputs returned" detail={mode === "demo" ? "Demo values remain explicitly illustrative." : "Individual estimator outputs and missing measurements are not available without a returned event."} />}
      <p className="methodology-note">Offline benchmark; not live detection validation. Runtime feature-extraction parity with QUT-DV25 has not been validated.</p>
    </section>
    <section className="surface model-schema-surface"><div className="surface-heading"><div><p className="eyebrow">48-node evidence map</p><h2>Feature availability</h2><p className="surface-subtitle">{mode === "demo" ? "Synthetic event values under a persistent demo label." : latest ? `Values from ${latest.event_id}; unavailable values remain missing.` : "No live audit record returned; all feature statuses are not reported."}</p></div></div><FeatureMatrix names={FEATURE_NAMES} event={latest} mode={mode} /></section>
    <section className="surface full-span"><div className="surface-heading"><div><p className="eyebrow">Benchmark boundary</p><h2>Offline benchmark</h2><p className="surface-subtitle">Offline benchmark; not live detection validation.</p></div><StateBadge tone="slate">OFFLINE BENCHMARK</StateBadge></div>
      {mode === "live" && metrics.length > 0 ? <div className="benchmark-grid">{metrics.map(([modelName, raw]) => <BenchmarkCard key={modelName} name={modelName} raw={raw} />)}</div> : <EmptyState icon={BookOpen} title={mode === "demo" ? "Benchmark metrics are not simulated" : "No benchmark metadata returned"} detail={mode === "demo" ? "Demo Mode does not manufacture offline evaluation metrics." : "The model-info endpoint did not provide historical metrics or split methodology."} />}
      {mode === "live" && model?.benchmark_split != null && <p className="methodology-note">Evaluation split reported by API: <code>{JSON.stringify(model.benchmark_split)}</code></p>}
    </section>
    <section className="surface full-span"><div className="surface-heading"><div><p className="eyebrow">Ordered contract</p><h2>Feature names and current values</h2><p className="surface-subtitle">The matrix is a repository schema reference; only event values are shown as measurements.</p></div></div>
      <div className="feature-table-wrap"><table className="feature-table"><thead><tr><th>Index</th><th>Feature name</th><th>Current event value</th><th>Availability</th></tr></thead><tbody>{rows.map(({ name, index, value }) => <tr key={name}><td className="mono-cell">{String(index + 1).padStart(2, "0")}</td><td className="feature-name-cell">{name}</td><td className="mono-cell">{typeof value === "number" && Number.isFinite(value) ? value : value === null ? "null" : "Not reported"}</td><td>{value === null ? <StateBadge tone="amber">Missing</StateBadge> : typeof value === "number" && Number.isFinite(value) ? <StateBadge tone="green">Measured</StateBadge> : <StateBadge tone="slate">Not reported</StateBadge>}</td></tr>)}</tbody></table></div>
    </section>
  </>;
}

function BenchmarkCard({ name, raw }: { name: string; raw: unknown }) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return <div className="benchmark-card"><span>{name}</span><strong>Metadata unavailable</strong><small>The API value is not a metrics object.</small></div>;
  const metrics = Object.entries(raw as Record<string, unknown>).filter(([, value]) => typeof value === "number" && Number.isFinite(value));
  return <div className="benchmark-card"><span>{name.replaceAll("_", " ")}</span>{metrics.length ? metrics.map(([metric, value]) => <div className="benchmark-row" key={metric}><div><span>{metric.replaceAll("_", " ")}</span><b>{typeof value === "number" ? value.toFixed(3) : "Not reported"}</b></div><div className="benchmark-track"><i style={{ width: `${Math.max(0, Math.min(100, (value as number) * 100))}%` }} /></div></div>) : <strong>Numeric metrics not reported</strong>}<small>Offline benchmark; not live detection validation.</small></div>;
}

function RuntimePage({ mode, latest, health, audit, auditError, session }: {
  mode: Mode; latest: AuditEvent | null; health: LiveSnapshot["health"]; audit: LiveSnapshot["audit"]; auditError: string | null;
  session: AuthSession | null;
}) {
  const measured = latest?.provided_feature_count;
  const missing = typeof latest?.missing_feature_count === "number" ? latest.missing_feature_count : latest?.missing_features?.length;
  const persistedLatestReturned = mode === "live" && Boolean(latest && audit?.events.some((event) => event.event_id === latest.event_id));
  return <>
    <SectionHeading eyebrow="IBM LinuxONE · s390x" title="Runtime telemetry" description="This workspace reports only telemetry surfaced by the existing API. The browser cannot start, supervise, or connect directly to bpftrace." trailing={<StateBadge tone="amber">COLLECTOR NOT REPORTED</StateBadge>} />
    <div className="alert-strip warning"><Network size={17} /><div><strong>{mode === "demo" ? "DEMO DATA — NOT LIVE TELEMETRY" : "Collector status is not reported by API"}</strong><span>The backend exposes no collector health, probe, capture-window, or error endpoint. No runtime collection state is inferred.</span></div></div>
    <div className="runtime-grid">
      <section className="surface"><div className="surface-heading"><div><p className="eyebrow">Instrumentation</p><h2>Collector boundary</h2><p className="surface-subtitle">No control surface is implemented in this website.</p></div><Network size={18} className="surface-icon" /></div>
        <div className="diagnostic-pairs runtime-pairs"><div><span>Collector installed</span><b>NOT REPORTED BY API</b></div><div><span>Capture attempted</span><b>NOT REPORTED BY API</b></div><div><span>Capture completed</span><b>NOT REPORTED BY API</b></div><div><span>API submission succeeded</span><b>NOT REPORTED BY API</b></div><div><span>Audit persistence verified</span><b>{mode === "demo" ? "No SQLite writes" : persistedLatestReturned ? "Latest event returned by audit API" : "Not verified in this response"}</b></div><div><span>Runtime platform / architecture</span><b>NOT REPORTED BY API</b></div></div>
      </section>
      <section className="surface"><div className="surface-heading"><div><p className="eyebrow">Latest returned record</p><h2>Feature coverage</h2><p className="surface-subtitle">Coverage is tied to one returned audit event.</p></div><Activity size={18} className="surface-icon" /></div>
        {latest ? <><div className="coverage-big"><div><strong>{typeof measured === "number" ? measured : "—"}</strong><span>Measured</span></div><span className="coverage-divider">/</span><div><strong>{typeof missing === "number" ? missing : "—"}</strong><span>Missing</span></div><span className="coverage-total">of {latest.expected_feature_count ?? EXPECTED_FEATURE_COUNT}</span></div><div className="coverage-bar" role="img" aria-label={`${typeof measured === "number" ? measured : "Not reported"} measured, ${typeof missing === "number" ? missing : "Not reported"} missing`}>{typeof measured === "number" && latest.expected_feature_count ? <i style={{ width: `${Math.min(100, measured / latest.expected_feature_count * 100)}%` }} /> : <span />}</div><p className="surface-subtitle coverage-record">{latest.event_id} · {formatTimestamp(latest.created_at)}</p></> : <EmptyState icon={Activity} title="No event coverage available" detail={mode === "demo" ? "The demo fixture is selected but contains no event." : "The audit API returned no event from which coverage could be derived."} />}
      </section>
    </div>
    <section className="surface full-span"><div className="surface-heading"><div><p className="eyebrow">Secure data boundary</p><h2>Live connection and deployment boundary</h2></div><ShieldCheck size={18} className="surface-icon" /></div>
      <div className="boundary-grid"><div><span className="boundary-icon"><Server size={17} /></span><div><b>API origin</b><p>{mode === "demo" ? "No API requests are made while Demo Mode is active." : health ? `Same-origin health response: ${health.service ?? "service name not reported"}.` : "LIVE API UNAVAILABLE at this origin."}</p></div></div><div><span className="boundary-icon warn"><ShieldAlert size={17} /></span><div><b>Backend authorization</b><p>{mode === "demo" ? "Demo mode does not contact the authentication service." : session?.authenticated ? `Authenticated as ${session.user?.username} · ${session.user?.role} · tenant ${session.user?.tenant_id}. User and admin are the two human roles; administrative routes remain admin-only and server-enforced.` : "Sign in is required before tenant-authorized audit records, predictions, or saved explanations can be accessed."}</p></div></div><div><span className="boundary-icon"><WifiOff size={17} /></span><div><b>Collector and runtime limits</b><p>Installed/capture status is not reported by API. The collector only measures a subset of the 48 features; QUT-DV25 runtime parity is not validated. Database paths and secrets are never exposed to the browser.</p></div></div></div>
      {auditError && mode === "live" && <p className="inline-error">Audit read error: {auditError}</p>}
    </section>
  </>;
}

function DiagnosticsPage({ mode, health, model, audit, healthError, modelError, auditError, latency, lastRefresh, onRefresh, reduceMotion, setReduceMotion, selectedNode, clearSelectedNode, session, authChecked, authError }: {
  mode: Mode; health: LiveSnapshot["health"]; model: LiveSnapshot["model"]; audit: LiveSnapshot["audit"];
  healthError: string | null; modelError: string | null; auditError: string | null; latency: number | null; lastRefresh: string | null;
  onRefresh: () => void; reduceMotion: boolean; setReduceMotion: (value: boolean) => void; selectedNode: SignalNode | null; clearSelectedNode: () => void;
  session: AuthSession | null; authChecked: boolean; authError: string | null;
}) {
  const routes = [
    { name: "GET /health", state: mode === "demo" ? "Simulated" : health?.status === "ok" ? "Responded" : "Unavailable", detail: mode === "demo" ? "Demo fixture" : healthError || (health ? "Live response received" : "No live response") },
    { name: "GET /api/model-info", state: mode === "demo" ? "Simulated" : model ? "Responded" : "Unavailable", detail: mode === "demo" ? "Demo fixture" : modelError || (model ? "Model metadata returned" : "No live response") },
    { name: "GET /api/audit?limit=200", state: mode === "demo" ? "Simulated" : !session?.authenticated ? "Sign-in required" : audit ? "Responded" : "Unavailable", detail: mode === "demo" ? "Browser-only fixture" : auditError || (audit ? `${audit.events.length} tenant-authorized records in this response` : "No live response") },
    { name: "POST /api/predict", state: mode === "demo" ? "Disabled in Demo" : session?.user?.role === "admin" || session?.user?.role === "user" ? health && isLiveSchemaReady(model) ? "Enabled when valid" : "Blocked" : "User or admin sign-in required", detail: mode === "demo" ? "Demo Mode never sends writes" : "The API enforces user/admin role, CSRF token, request limits, and the exact schema" },
    { name: "POST /api/genai/explain", state: mode === "demo" ? "Local explanation" : session?.user?.role === "admin" || session?.user?.role === "user" ? audit ? "Available for saved events" : "Unavailable" : "User or admin sign-in required", detail: mode === "demo" ? "Deterministic synthetic summary; no fetch" : "Deterministic Evidence Explanation: local rules summarize a tenant-authorized event; no external LLM or decision change" },
    { name: "Runtime collector status", state: "NOT REPORTED BY API", detail: "No collector health or probe endpoint is implemented" },
  ];
  return <>
    <SectionHeading eyebrow="Operational truth · trust boundary" title="System diagnostics" description="A per-endpoint view of the active data source, the API trust boundary, and which platform details have not been reported." trailing={<button className="secondary-button" type="button" onClick={onRefresh} disabled={mode === "demo"}><RefreshCw size={14} />Refresh live checks</button>} />
    {selectedNode && <div className={`system-detail state-${selectedNode.status}`} role="status"><span className="signal-detail-icon">{selectedNode.icon}</span><div><span className="eyebrow">Selected pipeline stage · {selectedNode.subtitle}</span><strong>{selectedNode.title}</strong><p>{selectedNode.detail}</p></div><button className="icon-button" type="button" aria-label="Dismiss system detail" onClick={clearSelectedNode}><X size={16} /></button></div>}
    <section className="surface diagnostic-surface"><div className="surface-heading"><div><p className="eyebrow">Endpoint responses</p><h2>Connection matrix</h2><p className="surface-subtitle">Current mode: {mode === "demo" ? "synthetic demo data" : "same-origin live API"}</p></div><span className={`latency-chip ${health && mode === "live" ? "verified" : ""}`}><Clock3 size={14} />{mode === "demo" ? "Illustrative latency · not live" : latency !== null ? `${latency.toFixed(1)} ms measured` : "Latency unavailable"}</span></div>
      <div className="diagnostic-table">{routes.map((route) => <div className="diagnostic-route" key={route.name}><code>{route.name}</code><StateBadge tone={route.state.includes("Unavailable") || route.state === "Blocked" ? "amber" : route.state.includes("Responded") ? "green" : "slate"}>{route.state}</StateBadge><span>{route.detail}</span></div>)}</div>
    </section>
    <div className="diagnostics-lower-grid">
      <section className="surface"><div className="surface-heading"><div><p className="eyebrow">Environment</p><h2>Deployment context</h2></div><Terminal size={18} className="surface-icon" /></div><div className="diagnostic-pairs"><div><span>Current mode</span><b>{mode === "demo" ? "DEMO DATA" : "LIVE API"}</b></div><div><span>Last successful health refresh</span><b>{mode === "demo" ? "Not applicable" : formatTimestamp(lastRefresh)}</b></div><div><span>Service name</span><b>{mode === "demo" ? "tracegate-r-demo" : health?.service ?? "Not reported"}</b></div><div><span>Model readiness</span><b>{mode === "demo" ? "Illustrative" : model?.models_available === true ? "Available (API)" : model?.models_available === false ? "Not ready (API)" : "Not reported"}</b></div><div><span>Authentication / human role</span><b>{mode === "demo" ? "Not queried in Demo" : !authChecked ? "Checking" : session?.user?.role ? `${session.user.role} · ${authSessionLabel(session, authError)}` : authSessionLabel(session, authError)}</b></div><div><span>Administrative boundary</span><b>Admin role required; server-enforced</b></div><div><span>Collector / QUT-DV25 parity</span><b>Capture status not reported; runtime parity not validated</b></div><div><span>Runtime platform / architecture</span><b>Not reported by API</b></div><div><span>Database path / contents / secrets</span><b>Never exposed to browser</b></div></div></section>
      <section className="surface"><div className="surface-heading"><div><p className="eyebrow">Accessibility</p><h2>Motion preference</h2><p className="surface-subtitle">System reduced-motion preference is honored automatically.</p></div><Sparkles size={18} className="surface-icon" /></div><div className="motion-setting"><div><strong>Reduce interface motion</strong><p>Disable ambient movement and transitions for this session.</p></div><button role="switch" aria-checked={reduceMotion} className={`toggle-switch ${reduceMotion ? "selected" : ""}`} type="button" onClick={() => setReduceMotion(!reduceMotion)}><i /><span className="sr-only">Reduce interface motion</span></button></div><div className="diagnostic-divider" /><p className="trust-copy">TraceGate-R is a decision-support prototype. A review-required decision requests human review; it is not an execution block. Collector installation, capture state, and QUT-DV25 feature parity are not reported or validated here. The deterministic explanation is descriptive, not predictive.</p></section>
    </div>
    <AdminUsersPanel mode={mode} session={session} />
  </>;
}

function ObservationPage({ mode, health, model, onRefresh, canSubmit, writeAccessMessage }: {
  mode: Mode; health: LiveSnapshot["health"]; model: LiveSnapshot["model"]; onRefresh: () => Promise<void>;
  canSubmit: boolean; writeAccessMessage: string;
}) {
  const [packageRef, setPackageRef] = useState("");
  const [featuresText, setFeaturesText] = useState("{}");
  const [evidenceText, setEvidenceText] = useState("{}");
  const [alertsText, setAlertsText] = useState("[]");
  const [error, setError] = useState<string | null>(null);
  const [response, setResponse] = useState<ObservationPayload | Record<string, unknown> | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const schemaReady = mode === "live" && canSubmit && health?.status === "ok" && isLiveSchemaReady(model);

  useEffect(() => {
    setPackageRef("");
    setFeaturesText("{}");
    setEvidenceText("{}");
    setAlertsText("[]");
    setError(null);
    setResponse(null);
  }, [mode]);

  const loadDemoDraft = () => {
    setPackageRef("synthetic-reference-only");
    setFeaturesText(JSON.stringify({ [FEATURE_NAMES[0]]: 12, [FEATURE_NAMES[1]]: null, [FEATURE_NAMES[19]]: 3 }, null, 2));
    setEvidenceText(JSON.stringify({ file_activity: "present", network_behavior: "missing" }, null, 2));
    setAlertsText(JSON.stringify(["DEMO_ONLY_SYNTHETIC_INPUT"], null, 2));
    setError(null);
    setResponse(null);
  };

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    setError(null);
    setResponse(null);
    if (mode !== "live") {
      setError("Demo Mode never sends an observation to the API.");
      return;
    }
    if (!canSubmit) {
      setError(writeAccessMessage);
      return;
    }
    if (!schemaReady) {
      setError("Submission is disabled until the live API and exact validated 48-feature schema are available.");
      return;
    }
    try {
      const payload = parseObservation(packageRef, featuresText, evidenceText, alertsText, FEATURE_NAMES);
      setSubmitting(true);
      const result = await submitPrediction(payload, mode, schemaReady);
      setResponse(result);
      await onRefresh();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Observation could not be submitted.");
    } finally {
      setSubmitting(false);
    }
  }

  return <>
    <SectionHeading eyebrow="Evidence-controlled input" title="Observation analysis" description="Submit manually provided observations to the existing prediction API. This is not automatic collection. Null stays missing; the workflow does not launch a collector or manufacture evidence." trailing={<StateBadge tone={schemaReady ? "green" : "amber"}>{schemaReady ? "LIVE SUBMISSION READY" : mode === "demo" ? "WRITE DISABLED" : !canSubmit ? "AUTHORIZED USER OR ADMIN REQUIRED" : "LIVE API / SCHEMA REQUIRED"}</StateBadge>} />
    <div className={`alert-strip ${mode === "demo" ? "violet" : "neutral"}`}><FileSearch size={17} /><div><strong>{mode === "demo" ? "DEMO MODE · NO WRITE OPERATIONS" : "ANALYST-PROVIDED INPUT"}</strong><span>{mode === "demo" ? "Example input stays in this browser and cannot be submitted to FastAPI or stored in SQLite." : "JSON entered here is analyst-provided data, not automatically collected runtime telemetry. Only submit measurements you have actually observed."}</span></div></div>
    <div className="analysis-grid">
      <section className="surface analysis-form-surface"><div className="surface-heading"><div><p className="eyebrow">Input contract</p><h2>Observation payload</h2><p className="surface-subtitle">JSON values must use canonical feature names; use null for unavailable measurements.</p></div><FileSearch size={18} className="surface-icon" /></div>
        <form className="analysis-form" onSubmit={handleSubmit}>
          <label className="form-field"><span>Package or event reference <small>optional · do not include secrets or raw paths</small></span><input maxLength={200} value={packageRef} onChange={(event) => setPackageRef(event.target.value)} placeholder="e.g. analyst-approved reference" autoComplete="off" /></label>
          <label className="form-field"><span>Feature values <small>analyst-provided JSON · numbers or null</small></span><textarea value={featuresText} onChange={(event) => setFeaturesText(event.target.value)} spellCheck={false} placeholder={'Load the live schema first.\n{\n  "Filetop__Total_Reads": 12,\n  "Filetop__Total_Writes": null\n}'} /></label>
          <label className="form-field"><span>Evidence states <small>JSON object of observed states</small></span><textarea className="compact-textarea" value={evidenceText} onChange={(event) => setEvidenceText(event.target.value)} spellCheck={false} /></label>
          <label className="form-field"><span>Integrity alerts <small>JSON array of recorded strings</small></span><textarea className="compact-textarea" value={alertsText} onChange={(event) => setAlertsText(event.target.value)} spellCheck={false} /></label>
          {mode === "demo" && <button className="secondary-button" type="button" onClick={loadDemoDraft}><Sparkles size={14} />Load synthetic draft</button>}
          <button className="primary-button" type="submit" disabled={!schemaReady || submitting}><FileSearch size={15} />{submitting ? "Submitting…" : "Submit to live prediction API"}</button>
          <p className="form-footnote">{schemaReady ? "Your server-authorized user or administrator session is active. Model unavailability still results in an unscored audit record that may require review." : mode === "demo" ? "The submit control remains disabled in Demo Mode. Switching to Live Mode will fetch its own API data and will not reuse this draft." : !canSubmit ? writeAccessMessage : "Submission remains disabled until health and schema validation succeed."}</p>
          {error && <p className="inline-error" role="alert">{error}</p>}
        </form>
      </section>
      <section className="surface analysis-response"><div className="surface-heading"><div><p className="eyebrow">Formal API response</p><h2>Prediction &amp; audit result</h2><p className="surface-subtitle">Probability, decision, and evidence completeness are distinct.</p></div><ShieldCheck size={18} className="surface-icon" /></div>
        {response ? <><div className="response-success"><span><Check size={15} /></span><div><strong>Response received</strong><p>{"score_available" in response && response.score_available === true ? "A model score was returned." : "The event was accepted without an available model score."} A successful API response does not establish safety.</p></div></div><pre className="json-output" aria-live="polite">{JSON.stringify(response, null, 2)}</pre></> : <EmptyState icon={mode === "demo" ? Sparkles : WifiOff} title={mode === "demo" ? "Demo is write-protected" : "No live prediction submitted"} detail={mode === "demo" ? "A synthetic draft can be inspected, but it is never sent to the prediction endpoint." : schemaReady ? "A response appears after you submit an explicitly measured observation." : "Connect to the local FastAPI service and load its validated feature schema to enable submission."} />}
        <div className="response-policy"><AlertTriangle size={15} /><p>If the model cannot score incomplete evidence, missing probabilities stay null and the policy can require analyst review. A review decision is not an external execution block.</p></div>
      </section>
    </div>
  </>;
}

function EventDrawer({ event, mode, onClose, canExplain = false }: { event: AuditEvent; mode: Mode; onClose: () => void; canExplain?: boolean }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const [explanation, setExplanation] = useState("");
  const [explainError, setExplainError] = useState<string | null>(null);
  const [explaining, setExplaining] = useState(false);
  const [copyStatus, setCopyStatus] = useState("");
  const missing = event.missing_features ?? [];
  const probabilities = event.model_probabilities ?? {
    logistic_regression: event.logistic_probability,
    random_forest: event.random_forest_probability,
    ensemble: event.ensemble_probability,
  };

  useEffect(() => {
    closeRef.current?.focus();
    const keyHandler = (keyEvent: KeyboardEvent) => {
      if (keyEvent.key === "Escape") onClose();
      if (keyEvent.key === "Tab" && dialogRef.current) {
        const focusable = Array.from(dialogRef.current.querySelectorAll<HTMLElement>("button:not(:disabled), a[href], input:not(:disabled), textarea:not(:disabled), select:not(:disabled), [tabindex='0']"));
        if (!focusable.length) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (keyEvent.shiftKey && document.activeElement === first) { keyEvent.preventDefault(); last.focus(); }
        else if (!keyEvent.shiftKey && document.activeElement === last) { keyEvent.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener("keydown", keyHandler);
    return () => document.removeEventListener("keydown", keyHandler);
  }, [onClose]);

  async function runExplanation() {
    setExplaining(true);
    setExplainError(null);
    try {
      setExplanation(mode === "demo" ? explainDemoEvent(event) : await requestOfflineExplanation(event.event_id, mode));
    } catch (error) {
      setExplainError(error instanceof Error ? error.message : "Deterministic Evidence Explanation unavailable.");
    } finally {
      setExplaining(false);
    }
  }

  async function copyValue(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopyStatus(`${label} copied to clipboard.`);
    } catch {
      setCopyStatus("Clipboard access is unavailable in this browser.");
    }
  }

  const missingCount = typeof event.missing_feature_count === "number" ? event.missing_feature_count : missing.length;
  return <div className="drawer-backdrop" onMouseDown={(mouseEvent) => { if (mouseEvent.target === mouseEvent.currentTarget) onClose(); }}>
    <aside className="event-drawer" role="dialog" aria-modal="true" aria-labelledby="drawerTitle" ref={dialogRef}>
      <header className="drawer-header"><div><p className="eyebrow">{mode === "demo" ? "Synthetic example record" : "Persisted audit record"}</p><h2 id="drawerTitle">Evidence inspection</h2><p className="mono-subtitle">{event.event_id}</p></div><button ref={closeRef} className="icon-button drawer-close" type="button" aria-label="Close event details" onClick={onClose}><X size={18} /></button></header>
      {mode === "demo" && <div className="drawer-demo-banner">DEMO DATA — NOT LIVE TELEMETRY</div>}
      <div className="drawer-actions"><button className="secondary-button" type="button" onClick={() => void copyValue(event.event_id, "Event ID")}><Copy size={14} />Copy event ID</button><button className="secondary-button" type="button" onClick={() => void copyValue(JSON.stringify(event, null, 2), "Structured event JSON")}><Copy size={14} />Copy JSON</button></div>
      <div className="drawer-content">
        <section className="drawer-section"><div className="drawer-section-title"><div><p className="eyebrow">Event overview</p><h3>{event.package_ref || "Reference not recorded"}</h3></div><StateBadge tone={decisionTone(event.decision)}>{event.decision || "Not recorded"}</StateBadge></div>
          <div className="drawer-data-grid"><div><span>Timestamp</span><b>{formatTimestamp(event.created_at)}</b></div><div><span>Recorded formal policy decision</span><b>{event.decision || "Not recorded"}</b></div><div><span>Score availability</span><b>{event.score_available === true ? "Available" : "Unavailable"}</b></div><div><span>Ensemble score</span><b>{scoreText(event)}</b></div><div><span>Evidence coverage</span><b>{coverageForEvent(event)}</b></div><div><span>Missing features</span><b>{missingCount}</b></div><div><span>Model disagreement</span><b>{typeof event.model_disagreement === "boolean" ? (event.model_disagreement ? "Yes" : "No") : "Not reported"}</b></div></div>
        </section>
        <section className="drawer-section"><div className="drawer-section-title"><div><p className="eyebrow">Model details</p><h3>Reported probabilities</h3></div><Cpu size={17} className="surface-icon" /></div>
          <div className="model-probability-list">{(["logistic_regression", "random_forest", "ensemble"] as const).map((modelName) => { const value = probabilities?.[modelName]; const numeric = typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1; const label = event.model_labels?.[modelName]; return <div key={modelName}><span>{modelName.replaceAll("_", " ")}</span><b>{event.score_available === true && numeric ? `${(value * 100).toFixed(1)}%` : "Unavailable"}{modelName !== "ensemble" ? ` · ${modelLabelText(label)}` : ""}</b></div>; })}</div>
          <p className="drawer-footnote">Model labels and disagreement are shown only when returned. The browser does not reconstruct missing outputs.</p>
        </section>
        <section className="drawer-section"><div className="drawer-section-title"><div><p className="eyebrow">Missing telemetry</p><h3>Unmeasured features</h3></div><StateBadge tone={missingCount ? "amber" : "slate"}>{missingCount} missing</StateBadge></div>
          {(() => {
            const measured = Object.entries(event.features ?? {}).filter(([, value]) => typeof value === "number" && Number.isFinite(value));
            return <details className="raw-record"><summary>{measured.length} measured feature value(s) returned</summary>{measured.length
              ? <ul className="missing-list">{measured.map(([name, value]) => <li key={name}><span className="missing-mark" />{name}: {String(value)}</li>)}</ul>
              : <p className="drawer-footnote">No numeric measured feature values were returned for this record.</p>}</details>;
          })()}
          {missing.length ? <ul className="missing-list">{missing.map((name) => <li key={name}><span className="missing-mark" />{name}</li>)}</ul> : <p className="drawer-footnote">{missingCount === 0 ? "The record reports no missing feature names." : "The record does not include an individual missing-feature list."}</p>}
          {event.integrity_alerts?.length ? <div className="alert-list"><strong>Recorded integrity alerts</strong>{event.integrity_alerts.map((alert, index) => <code key={`${alert}-${index}`}>{alert}</code>)}</div> : <div className="alert-list quiet"><strong>Integrity alerts</strong><span>{Array.isArray(event.integrity_alerts) ? "No alerts recorded in this event." : "Not reported by this record."}</span></div>}
        </section>
        <section className="drawer-section"><div className="drawer-section-title"><div><p className="eyebrow">Audit provenance</p><h3>Recorded ownership and schema</h3></div><Database size={17} className="surface-icon" /></div>
          <div className="diagnostic-pairs"><div><span>Submitting account ID</span><b>{event.created_by_user_id ?? "Not reported / service submission"}</b></div><div><span>Tenant ID</span><b>{event.tenant_id ?? "Not reported"}</b></div><div><span>Feature-schema SHA-256</span><b>{event.schema_sha256 ?? "Not reported"}</b></div><div><span>Collector capture source / status</span><b>Not reported by API</b></div></div>
          <p className="drawer-footnote">The decision and provenance above are values recorded in the audit event. An explanation is saved separately and does not overwrite this event.</p>
        </section>
        <section className="drawer-section explanation-section"><div className="drawer-section-title"><div><p className="eyebrow">Deterministic Evidence Explanation</p><h3>Recorded evidence summary</h3></div><button className="secondary-button" type="button" disabled={explaining || (mode === "live" && !canExplain)} onClick={() => void runExplanation()}><Sparkles size={14} />{explaining ? "Reading record…" : "Generate explanation"}</button></div>
          <p className="drawer-footnote">Generated locally by deterministic rules from recorded event information. It is not an external generative LLM, does not independently predict maliciousness, and cannot change the formal decision shown above.</p>
          {mode === "live" && !canExplain && <p className="drawer-footnote">An authenticated user or administrator role is required to request and persist an explanation.</p>}
          {explainError && <p className="inline-error" role="alert">{explainError}</p>}
          {explanation && <pre className="json-output explanation-output" aria-live="polite">{explanation}</pre>}
        </section>
        <section className="policy-assurance"><div className="drawer-section-title"><div><p className="eyebrow">Policy assurance</p><h3>What this record establishes</h3></div><ShieldCheck size={17} /></div>
          <ul><li><span>Scored by models</span><b>{event.score_available === true ? "Yes, as reported" : "No score available"}</b></li><li><span>Evidence complete</span><b>{missingCount === 0 ? "No missing features reported" : `${missingCount} missing`}</b></li><li><span>Formal decision</span><b>{event.decision || "Not recorded"}</b></li><li><span>External enforcement</span><b>Not reported / not established</b></li></ul>
          <p>Passing the evidence gate does not guarantee safe behavior. REVIEW_REQUIRED asks for analyst review; it is not proof of maliciousness or a claim that an external action was stopped.</p>
        </section>
        <details className="raw-record"><summary>Structured record fields</summary><pre className="json-output">{JSON.stringify(event, null, 2)}</pre></details>
        {copyStatus && <p className="copy-status" role="status" aria-live="polite">{copyStatus}</p>}
      </div>
    </aside>
  </div>;
}

function AdminUsersPanel({ mode, session }: { mode: Mode; session: AuthSession | null }) {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<UserRole>("user");
  const [tenantId, setTenantId] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [oneTimeToken, setOneTimeToken] = useState("");

  const reload = useCallback(async () => {
    if (mode !== "live" || session?.user?.role !== "admin") return;
    try {
      setUsers(await fetchAdminUsers());
      setError(null);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Could not retrieve user accounts.");
    }
  }, [mode, session?.user?.role]);

  useEffect(() => { void reload(); }, [reload]);

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(null); setStatus(""); setOneTimeToken("");
    try {
      const created = await createAdminUser({ username, role, tenant_id: tenantId });
      setOneTimeToken(created.enrollment_token);
      setStatus(`Account invitation created for ${created.username}. Share the one-time token through an approved secure channel; it expires at ${formatTimestamp(created.token_expires_at)}.`);
      setUsername("");
      await reload();
    } catch (createError) {
      setError(createError instanceof Error ? createError.message : "Could not create the account invitation.");
    } finally { setBusy(false); }
  }

  async function createTenant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(null); setStatus("");
    try {
      const tenant = await createAdminTenant({ tenant_id: tenantId, display_name: tenantName });
      setStatus(`Tenant ${tenant.tenant_id} created.`);
      setTenantName("");
    } catch (tenantError) {
      setError(tenantError instanceof Error ? tenantError.message : "Could not create the tenant.");
    } finally { setBusy(false); }
  }

  async function updateUser(user: AdminUser, changes: { role?: UserRole; active?: boolean }) {
    setBusy(true); setError(null); setStatus("");
    try {
      await updateAdminUser(user.user_id, changes);
      setStatus(`Updated ${user.username}. Existing sessions are revoked after role or account-state changes.`);
      await reload();
    } catch (updateError) {
      setError(updateError instanceof Error ? updateError.message : "Could not update the account.");
      await reload();
    } finally { setBusy(false); }
  }

  async function resetPassword(user: AdminUser) {
    setBusy(true); setError(null); setStatus(""); setOneTimeToken("");
    try {
      const result = await resetAdminUserPassword(user.user_id);
      setOneTimeToken(result.reset_token);
      setStatus(`All sessions for ${user.username} were revoked. The recovery token expires at ${formatTimestamp(result.token_expires_at)}.`);
    } catch (resetError) {
      setError(resetError instanceof Error ? resetError.message : "Could not issue a recovery token.");
    } finally { setBusy(false); }
  }

  if (mode !== "live" || session?.user?.role !== "admin") return null;
  return <section className="surface admin-users-panel">
    <div className="surface-heading"><div><p className="eyebrow">Administrator controls</p><h2>Users and tenant access</h2><p className="surface-subtitle">Changes are enforced and recorded by the API. Passwords are set by users with one-time enrollment tokens.</p></div><ShieldCheck size={18} className="surface-icon" /></div>
    <form className="admin-tenant-form" onSubmit={createTenant}>
      <label className="form-field"><span>New tenant ID</span><input required minLength={2} maxLength={64} pattern="[a-z0-9][a-z0-9_-]*" value={tenantId} onChange={(event) => setTenantId(event.target.value)} autoComplete="off" /></label>
      <label className="form-field"><span>Tenant display name</span><input required maxLength={120} value={tenantName} onChange={(event) => setTenantName(event.target.value)} autoComplete="off" /></label>
      <button className="secondary-button" type="submit" disabled={busy || !tenantName}>Create tenant</button>
    </form>
    <form className="admin-user-form" onSubmit={createUser}>
      <label className="form-field"><span>Username</span><input required minLength={3} maxLength={64} value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="off" /></label>
      <label className="form-field"><span>Role</span><select value={role} onChange={(event) => setRole(event.target.value as UserRole)}><option value="user">User</option><option value="admin">Administrator</option></select></label>
      <label className="form-field"><span>Existing tenant ID</span><input required minLength={2} maxLength={64} value={tenantId} onChange={(event) => setTenantId(event.target.value)} autoComplete="off" /></label>
      <button className="primary-button" type="submit" disabled={busy || !username || !tenantId}>Create invitation</button>
    </form>
    {oneTimeToken && <div className="one-time-token"><strong>One-time token · shown only in this session</strong><code>{oneTimeToken}</code><button className="secondary-button" type="button" onClick={() => { void navigator.clipboard.writeText(oneTimeToken).then(() => setStatus("One-time token copied."), () => setError("Clipboard access is unavailable.")); }}>Copy token</button></div>}
    {status && <p className="admin-status" role="status">{status}</p>}
    {error && <p className="inline-error" role="alert">{error}</p>}
    <div className="admin-users-table"><table className="audit-grid"><thead><tr><th>User</th><th>Tenant</th><th>Role</th><th>State</th><th>Actions</th></tr></thead><tbody>{users.map((user) => <tr key={user.user_id}>
      <td>{user.username}</td><td>{user.tenant_id}</td><td><select aria-label={`Role for ${user.username}`} value={user.role} disabled={busy} onChange={(event) => void updateUser(user, { role: event.target.value as UserRole })}><option value="admin">Admin</option><option value="user">User</option></select></td>
      <td>{user.active ? "Active" : "Invitation pending / disabled"}</td><td><div className="admin-row-actions"><button type="button" className="secondary-button" disabled={busy || !user.active} onClick={() => void resetPassword(user)}>Reset password</button><button type="button" className="secondary-button" disabled={busy} onClick={() => void updateUser(user, { active: !user.active })}>{user.active ? "Disable" : "Enable"}</button></div></td>
    </tr>)}</tbody></table></div>
  </section>;
}

function SignInDialog({ onClose, onSubmit, busy, error }: {
  onClose: () => void; onSubmit: (username: string, password: string) => Promise<void>; busy: boolean; error: string | null;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await onSubmit(username, password);
    setPassword("");
  }
  return <div className="drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <section className="auth-dialog" role="dialog" aria-modal="true" aria-labelledby="signInTitle">
      <div className="surface-heading"><div><p className="eyebrow">TraceGate-R access</p><h2 id="signInTitle">Sign in</h2><p className="surface-subtitle">The API verifies your role and tenant before returning audit data.</p></div><button className="icon-button" type="button" aria-label="Close sign in" onClick={onClose}><X size={16} /></button></div>
      <form className="auth-form" onSubmit={submit}>
        <label className="form-field"><span>Username</span><input autoComplete="username" required minLength={3} maxLength={64} value={username} onChange={(event) => setUsername(event.target.value)} /></label>
        <label className="form-field"><span>Password</span><input type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        {error && <p className="inline-error" role="alert">{error}</p>}
        <div className="auth-actions"><button className="secondary-button" type="button" onClick={onClose}>Cancel</button><button className="primary-button" type="submit" disabled={busy || !username || !password}>{busy ? "Checking…" : "Sign in securely"}</button></div>
      </form>
      <p className="drawer-footnote">Accounts are provisioned by an administrator. There is no public sign-up or default password.</p>
    </section>
  </div>;
}

export function App({ initialMode = "live" }: { initialMode?: Mode }) {
  const [page, setPage] = useState<Page>(() => pageFromHash());
  const [mode, setMode] = useState<Mode>(initialMode);
  const [live, setLive] = useState<LiveSnapshot>(EMPTY_LIVE);
  const [demo, setDemo] = useState(() => createDemoDataset());
  const [session, setSession] = useState<AuthSession | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [signInOpen, setSignInOpen] = useState(false);
  const [signInBusy, setSignInBusy] = useState(false);
  const [signInError, setSignInError] = useState<string | null>(null);
  const [signOutBusy, setSignOutBusy] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [selectedNode, setSelectedNode] = useState<SignalNode | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [reduceMotion, setReduceMotion] = useState(false);

  const refresh = useCallback(async () => {
    if (mode !== "live") {
      setDemo(createDemoDataset());
      return;
    }
    setLive((current) => ({ ...current, refreshing: true }));
    setAuthChecked(false);
    setAuthError(null);
    let currentSession: AuthSession | null = null;
    try {
      currentSession = await fetchAuthSession();
      setSession(currentSession.authenticated ? currentSession : null);
    } catch (error) {
      clearClientSession();
      setSession(null);
      setAuthError(error instanceof Error ? error.message : "The authentication service could not be reached.");
    } finally {
      setAuthChecked(true);
    }
    try {
      const snapshot = await fetchLiveSnapshot(currentSession?.authenticated === true);
      setLive({ ...snapshot, refreshing: false });
    } catch (error) {
      const message = error instanceof Error ? error.message : "The live API could not be refreshed.";
      setLive({
        ...EMPTY_LIVE,
        healthError: message,
        modelError: message,
        auditError: currentSession?.authenticated
          ? message
          : "Sign in to retrieve tenant-authorized audit records.",
      });
    }
  }, [mode]);

  async function handleSignIn(username: string, password: string): Promise<void> {
    setSignInBusy(true);
    setSignInError(null);
    try {
      const authenticatedSession = await signIn(username, password);
      setSession(authenticatedSession);
      setAuthChecked(true);
      setAuthError(null);
      setSignInOpen(false);
      await refresh();
    } catch (error) {
      clearClientSession();
      setSession(null);
      setAuthChecked(true);
      setSignInError(error instanceof Error ? error.message : "Sign-in failed. Check the API connection and try again.");
    } finally {
      setSignInBusy(false);
    }
  }

  async function handleSignOut(): Promise<void> {
    setSignOutBusy(true);
    try {
      await signOut();
      setSession(null);
      setAuthChecked(true);
      setAuthError(null);
      setSignInError(null);
      setLive((current) => ({
        ...current,
        audit: null,
        auditError: "Sign in to retrieve tenant-authorized audit records.",
      }));
      await refresh();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Sign-out failed.";
      clearClientSession();
      try {
        const confirmedSession = await fetchAuthSession();
        setSession(confirmedSession.authenticated ? confirmedSession : null);
        setAuthChecked(true);
        setAuthError(confirmedSession.authenticated ? message : "The session expired or was already signed out.");
        if (!confirmedSession.authenticated) {
          setLive((current) => ({
            ...current,
            audit: null,
            auditError: "Sign in to retrieve tenant-authorized audit records.",
          }));
        }
      } catch (checkError) {
        clearClientSession();
        setSession(null);
        setAuthChecked(true);
        setAuthError(`${message} ${checkError instanceof Error ? checkError.message : "Session status could not be verified."}`);
        setLive((current) => ({
          ...current,
          audit: null,
          auditError: "Sign in to retrieve tenant-authorized audit records.",
        }));
      }
    } finally {
      setSignOutBusy(false);
    }
  }

  useEffect(() => {
    const handleHash = () => setPage(pageFromHash());
    window.addEventListener("hashchange", handleHash);
    return () => window.removeEventListener("hashchange", handleHash);
  }, []);

  useEffect(() => {
    if (mode === "live") void refresh();
  }, [mode, refresh]);

  useEffect(() => {
    if (reduceMotion) document.documentElement.dataset.motion = "reduced";
    else delete document.documentElement.dataset.motion;
    return () => { delete document.documentElement.dataset.motion; };
  }, [reduceMotion]);

  const activeHealth = mode === "demo" ? demo.health : live.health;
  const activeModel = mode === "demo" ? demo.model : live.model;
  const activeEvents = useMemo(() => mode === "demo" ? demo.events : live.audit?.events ?? [], [mode, demo, live.audit]);
  const latest = useMemo(() => orderAuditEvents(activeEvents, "", "", "newest")[0] ?? null, [activeEvents]);
  const activeAudit = mode === "demo" ? { count: demo.events.length, events: demo.events } : live.audit;
  const activeLatency = mode === "demo" ? demo.latencyMs : live.latencyMs;
  const healthError = mode === "demo" ? null : live.healthError;
  const modelError = mode === "demo" ? null : live.modelError;
  const auditError = mode === "demo" ? null : live.auditError;
  const canSubmit = mode === "live"
    && authChecked
    && !authError
    && session?.authenticated === true
    && Boolean(session.csrf_token?.trim())
    && (session.user?.role === "admin" || session.user?.role === "user");
  const writeAccessMessage = mode !== "live"
    ? "Demo Mode never sends observations to the API."
    : !authChecked
      ? "Checking the current session before enabling submission."
      : authError
        ? `Authentication status could not be verified: ${authError}`
        : !session?.authenticated
          ? "Sign in with an authorized user or administrator account before submitting an observation."
          : session.user?.role !== "admin" && session.user?.role !== "user"
            ? "Your account role does not authorize observation submissions."
            : "The current session does not have a valid write token.";

  const inspect = useCallback((event: AuditEvent) => setSelectedEvent(event), []);
  const goToPage = useCallback((next: Page) => {
    if (window.location.hash !== `#/${next}`) window.location.hash = `/${next}`;
    setPage(next);
  }, []);

  function selectMode(next: Mode) {
    if (next === mode) return;
    setSelectedEvent(null);
    setSelectedNode(null);
    setMode(next);
  }

  function resetDemo() {
    setDemo(createDemoDataset());
    setSelectedEvent(null);
    setSelectedNode(null);
    goToPage("overview");
  }

  const connectionLabel = mode === "demo" ? "DEMO SIMULATION" : activeHealth ? "LIVE API VERIFIED" : "LIVE API UNAVAILABLE";
  const connectionTone = mode === "demo" ? "demo" : activeHealth ? "connected" : "unavailable";
  const lastRefreshLabel = mode === "demo" ? "Fixture · deterministic" : live.lastSuccessfulRefresh ? `Last verified ${formatTimestamp(live.lastSuccessfulRefresh)}` : "No successful health refresh";

  return <div className={`app-shell ${sidebarCollapsed ? "sidebar-is-collapsed" : ""}`}>
    <div className="ambient-field" aria-hidden="true"><span /><span /><span /></div>
    <aside className="app-sidebar" aria-label="Main workspace navigation">
      <a className="brand-lockup" href="#/overview" aria-label="TraceGate-R overview">
        <span className="brand-mark"><svg viewBox="0 0 40 40" aria-hidden="true"><path d="M7 11h26M20 11v19m-9-10h18M9 30h22" /><circle cx="20" cy="20" r="3.3" /><circle cx="9" cy="11" r="1.7" /><circle cx="31" cy="30" r="1.7" /></svg></span>
        <span className="brand-copy"><strong>TRACEGATE-R</strong><small>EVIDENCE CONSOLE</small></span>
      </a>
      <div className="sidebar-context"><span>WORKSPACE</span><span>IBM Z · s390x</span></div>
      <nav className="workspace-nav" aria-label="Workspaces">
        {NAV_ITEMS.map(({ id, label, icon: Icon }) => <a key={id} href={`#/${id}`} onClick={() => goToPage(id)} className={page === id ? "active" : ""} aria-current={page === id ? "page" : undefined} title={sidebarCollapsed ? label : undefined}>
          <Icon size={17} strokeWidth={1.8} /><span>{label}</span><span className="nav-active-line" />
        </a>)}
      </nav>
      <div className="sidebar-spacer" />
      <div className="sidebar-assurance"><span className="assurance-mark"><ShieldCheck size={16} /></span><div><strong>Evidence before verdict</strong><small>Missing stays missing.</small></div></div>
      <div className="sidebar-foot"><span className="sidebar-led" />SECURITY DECISION SUPPORT<span className="foot-version">0.2</span></div>
      <button className="collapse-button" type="button" onClick={() => setSidebarCollapsed(!sidebarCollapsed)} aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"} aria-expanded={!sidebarCollapsed}><Menu size={16} /><span>{sidebarCollapsed ? "Expand" : "Collapse"}</span></button>
    </aside>
    <div className="main-shell">
      <header className="topbar">
        <div className="breadcrumb"><span className="breadcrumb-root">TRACEGATE-R</span><span className="breadcrumb-slash">/</span><strong>{PAGE_NAMES[page]}</strong><span className={`env-tag ${mode}`}>{mode === "demo" ? "DEMO" : "SAME-ORIGIN"}</span></div>
        <div className="topbar-actions">
          <span className={`connection-state ${connectionTone}`} role="status" aria-live="polite"><i />{connectionLabel}</span>
          <span className="last-refresh"><Clock3 size={13} />{lastRefreshLabel}</span>
          {mode === "live" && (session?.authenticated
            ? <button className="secondary-button" type="button" onClick={() => void handleSignOut()} disabled={signOutBusy}>{signOutBusy ? "Signing out…" : `Sign out · ${session.user?.username ?? "account"}`}</button>
            : <button className="secondary-button" type="button" onClick={() => { setSignInError(null); setSignInOpen(true); }} disabled={!authChecked || signInBusy}>{authChecked ? "Sign in" : "Checking session…"}</button>)}
          <div className="mode-switch" role="group" aria-label="Data mode"><button className={mode === "demo" ? "selected" : ""} type="button" aria-pressed={mode === "demo"} onClick={() => selectMode("demo")}><Sparkles size={13} />Demo</button><button className={mode === "live" ? "selected" : ""} type="button" aria-pressed={mode === "live"} onClick={() => selectMode("live")}><Activity size={13} />Live</button></div>
          <button className="refresh-button" type="button" aria-label={mode === "demo" ? "Reset demo data" : "Refresh live API"} disabled={mode === "live" && live.refreshing} onClick={() => mode === "demo" ? resetDemo() : void refresh()}>{mode === "demo" ? <RotateCcw size={15} /> : <RefreshCw className={live.refreshing ? "spinning" : ""} size={15} />}<span>{mode === "demo" ? "Reset demo" : "Refresh"}</span></button>
        </div>
      </header>
      {mode === "demo" && <div className="demo-ribbon" role="status"><Sparkles size={15} /><strong>DEMO DATA — NOT LIVE TELEMETRY</strong><span>Deterministic synthetic records · browser only · no API writes</span><button type="button" onClick={resetDemo}>Reset fixture <RotateCcw size={13} /></button></div>}
      <main className="workspace-content" id="main-content" tabIndex={-1}>
        {page === "overview" && <Overview mode={mode} health={activeHealth} model={activeModel} audit={activeAudit} events={activeEvents} latest={latest} latency={activeLatency} healthError={healthError} modelError={modelError} auditError={auditError} refreshing={live.refreshing} onInspect={inspect} onSelectPage={goToPage} onSelectNode={(node) => { setSelectedNode(node); goToPage("diagnostics"); }} />}
        {page === "audit" && <AuditPage events={activeEvents} source={mode} onInspect={inspect} error={auditError} loading={live.refreshing} />}
        {page === "model" && <ModelPage mode={mode} model={activeModel} modelError={modelError} latest={latest} />}
        {page === "runtime" && <RuntimePage mode={mode} latest={latest} health={activeHealth} audit={activeAudit} auditError={auditError} session={session} />}
        {page === "analysis" && <ObservationPage mode={mode} health={activeHealth} model={activeModel} onRefresh={refresh} canSubmit={canSubmit} writeAccessMessage={writeAccessMessage} />}
        {page === "diagnostics" && <DiagnosticsPage mode={mode} health={activeHealth} model={activeModel} audit={activeAudit} healthError={healthError} modelError={modelError} auditError={auditError} latency={activeLatency} lastRefresh={live.lastSuccessfulRefresh} onRefresh={() => void refresh()} reduceMotion={reduceMotion} setReduceMotion={setReduceMotion} selectedNode={selectedNode} clearSelectedNode={() => setSelectedNode(null)} session={session} authChecked={authChecked} authError={authError} />}
        <footer className="workspace-footer"><span>TRACEGATE-R <i>·</i> EVIDENCE BEFORE VERDICT</span><span>Decision support only · Not a production malware verdict</span><span>API facts <b>—</b> demo fixtures <b>—</b> clearly separated</span></footer>
      </main>
    </div>
    {selectedEvent && <EventDrawer event={selectedEvent} mode={mode} onClose={() => setSelectedEvent(null)} canExplain={mode === "demo" || Boolean(authChecked && !authError && session?.authenticated && session.csrf_token && (session.user?.role === "admin" || session.user?.role === "user"))} />}
    {signInOpen && <SignInDialog onClose={() => setSignInOpen(false)} onSubmit={handleSignIn} busy={signInBusy} error={signInError} />}
  </div>;
}

export default App;
