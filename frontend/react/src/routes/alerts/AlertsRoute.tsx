import { useSearchParams } from "react-router-dom";
import { alertIncidentId } from "../../domain/alertIncidentLink";
import { AlertIncidentHandoff } from "./AlertIncidentHandoff";
import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, AlertTriangle, BellRing, Braces, Database, FileCode2, GitMerge, LoaderCircle, RadioTower, RotateCcw, Search, Ticket } from "lucide-react";
import { routeJson } from "../../services/routeApi";
import { compactText, formatIstTimestamp, sourceChannelLabel, statusPillClass } from "../../utils/presentation";
import { useRouteRuntimeSlice, type AlertStreamFilters, type AlertStreamRow } from "../../app/routeRuntime";
import { useSession } from "../../app/SessionContext";
import { OperationsWorkflowNav } from "../../components/operations/OperationsWorkflowNav";
import "./AlertsRoute.css";
import { isDemoSignal, isSyntheticSignal } from "../../domain/signalAuthenticity";

const channels = [
  ["all", "ALL", "All arrivals"], ["prometheus", "PR", "Prometheus"],
  ["email", "EM", "Email"],
  ["log", "LG", "Logs / OpenSearch"], ["ticket", "TK", "Tickets / Jira"],
  ["failed", "!", "Failed intake"],
] as const;

function alertRowKey(row: AlertStreamRow): string {
  const identity = (row as AlertStreamRow & { alert_id?: string; fingerprint?: string }).alert_id
    || (row as AlertStreamRow & { fingerprint?: string }).fingerprint;
  return String(identity || row.id || row.file || [row.source_channel, row.name || row.alert_name, row.service, row.received_at || row.created_at].join("::"));
}

function channelIcon(channel: string) {
  return ({ email: "EM", log: "LG", ticket: "TK", telemetry: "OT", prometheus: "PR" } as Record<string, string>)[channel] || "AL";
}

function richText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") {
    const text = value.trim();
    if ((text.startsWith("{") || text.startsWith("[")) && text.length > 2) {
      try { return richText(JSON.parse(text)); } catch { return text; }
    }
    return text;
  }
  if (Array.isArray(value)) return value.map(richText).filter(Boolean).join(" ");
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (record.type === "text") return String(record.text || "").trim();
    return richText(record.content || record.text || record.description || record.summary || "");
  }
  return String(value);
}

function normalizedChannel(row: AlertStreamRow): string {
  const raw = String(row.source_channel || row.origin_system || row.source || "prometheus").toLowerCase();
  if (raw.includes("jira") || raw.includes("ticket")) return "ticket";
  if (raw.includes("mail") || raw.includes("email")) return "email";
  if (raw.includes("log") || raw.includes("opensearch")) return "log";
  if (raw.includes("otel") || raw.includes("telemetry")) return "telemetry";
  return "prometheus";
}

function displayAlert(row: AlertStreamRow) {
  const channel = normalizedChannel(row);
  const metadata = row as AlertStreamRow & Record<string, unknown>;
  const annotations = row.annotations || {};
  const labels = row.labels || {};
  const rawSummary = row.description || annotations.description || metadata.summary || metadata.message || row.error;
  return {
    channel,
    title: compactText(richText(row.name || row.alert_name || metadata.title), 100) || "Unnamed alert",
    summary: compactText(richText(rawSummary), 240) || "Alert received and normalized by the landing pad.",
    // `status` describes landing-pad persistence (usually "processed"). The
    // Alertmanager lifecycle is the operator-facing state and must win.
    status: String(metadata.alert_status || row.status || "processed").replaceAll("_", " ").toUpperCase(),
    service: String(row.service || metadata.component || "-"),
    project: String(row.application || row.project_name || row.project || labels.application || labels.project_name || labels.project || "-"),
    severity: String(row.severity || metadata.priority || "-").toUpperCase(),
    file: compactText(row.file, 44) || "-",
    firstSeen: formatIstTimestamp(row.first_seen || row.starts_at || row.created_at || row.received_at),
    lastSeen: formatIstTimestamp(row.last_seen || row.ends_at || row.updated_at || row.received_at || row.created_at),
    occurrences: Number(row.occurrence_count || row.occurrences?.length || 1),
    owner: String(row.assignee || row.owner || row.jira_assignee || "Unassigned"),
  };
}

const SENSITIVE_SOURCE_KEYS = /authorization|cookie|credential|password|secret|token|api[_-]?key/i;

function redactedSourceValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[maximum depth reached]";
  if (Array.isArray(value)) return value.map((item) => redactedSourceValue(item, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [
      key,
      SENSITIVE_SOURCE_KEYS.test(key) ? "[redacted]" : redactedSourceValue(item, depth + 1),
    ]));
  }
  return value;
}

function sourceEvidence(row: AlertStreamRow) {
  const record = row as AlertStreamRow & Record<string, any>;
  const payload = record.source_payload || record.original_payload || record.raw_payload || record.event_payload || record.payload || record;
  return {
    origin: String(record.origin_system || record.provider || record.source || record.source_channel || "Not recorded"),
    channel: sourceChannelLabel(normalizedChannel(row)),
    location: String(record.object_uri || record.source_uri || record.url || record.path || record.file || "Not recorded"),
    sourceId: String(record.source_event_id || record.event_id || record.alert_id || record.id || "Not recorded"),
    received: formatIstTimestamp(record.received_at || record.created_at || record.modified_at),
    observed: formatIstTimestamp(record.starts_at || record.first_seen || record.timestamp || record.created_at),
    message: richText(record.message || record.description || record.summary || record.annotations?.description || record.error) || "No source message supplied",
    labels: record.labels && typeof record.labels === "object" ? record.labels : {},
    annotations: record.annotations && typeof record.annotations === "object" ? record.annotations : {},
    payload: redactedSourceValue(payload),
  };
}

const flowStages = [
  ["target", "Target", RadioTower], ["scrape", "Scrape /metrics", Activity], ["parse", "Parse metrics", Braces],
  ["store", "Store series", Database], ["rule", "Evaluate rule", FileCode2], ["alert", "Create alert", BellRing],
] as const;

function processedAlertId(row: AlertStreamRow | null): string {
  if (!row) return "";
  const record = row as AlertStreamRow & { alert_id?: string };
  const candidates = [record.alert_id, row.id].map((value) => String(value || "").trim());
  return candidates.find((value) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) || "";
}

function canonicalMatch(source: AlertStreamRow, candidates: any[]): any | null {
  const input = source as AlertStreamRow & Record<string, any>;
  const fingerprint = String(input.fingerprint || input.labels?.fingerprint || input.labels?.alert_fingerprint || "").trim();
  const name = String(source.name || source.alert_name || input.labels?.alertname || "").trim().toLowerCase();
  const service = String(source.service || input.labels?.service || input.labels?.job || "").trim().toLowerCase();
  const sourceTime = Date.parse(String(source.starts_at || source.created_at || source.received_at || ""));
  const uuidRows = candidates.filter((row) => processedAlertId(row));
  if (fingerprint) {
    const exact = uuidRows.find((row) => String(row.fingerprint || row.labels?.fingerprint || row.labels?.alert_fingerprint || "").trim() === fingerprint);
    if (exact) return exact;
  }
  return uuidRows
    .map((row) => {
      const rowName = String(row.name || row.alert_name || row.labels?.alertname || "").trim().toLowerCase();
      const rowService = String(row.service || row.labels?.service || row.labels?.job || "").trim().toLowerCase();
      const rowTime = Date.parse(String(row.starts_at || row.created_at || row.received_at || ""));
      const timeDelta = Number.isFinite(sourceTime) && Number.isFinite(rowTime) ? Math.abs(sourceTime - rowTime) : Number.MAX_SAFE_INTEGER;
      return { row, score: (name && rowName === name ? 4 : 0) + (service && rowService === service ? 2 : 0) + (timeDelta <= 300000 ? 2 : timeDelta <= 3600000 ? 1 : 0) };
    })
    .filter((item) => item.score >= 6)
    .sort((a, b) => b.score - a.score)[0]?.row || null;
}

function workflowFacts(payload: any) {
  const root = payload?.data && typeof payload.data === "object" ? payload.data : payload || {};
  const alert = root.alert || {};
  const incident = root.incident || root.projection || {};
  const context = root.context || {};
  const recommendation = root.recommendation || {};
  const metadata = context.metadata || recommendation.metadata || {};
  const report = metadata.discovery_report || {};
  const evidence = Array.isArray(report.evidence) ? report.evidence
    : Array.isArray(metadata.discovery_evidence) ? metadata.discovery_evidence
      : Object.values(metadata.discovery_evidence || {}).flat().filter((item) => item && typeof item === "object");
  const timeline = Array.isArray(root.timeline) ? root.timeline : [];
  const ticket = incident.ticket_id || incident.jira_key || root.ticket_id || alert.ticket_id;
  const duplicate = alert.deduplication_reason || incident.deduplication_reason || metadata.deduplication_reason;
  return { root, alert, incident, context, recommendation, metadata, report, evidence, timeline, ticket, duplicate };
}

const linkedIncidentId = alertIncidentId;

function workflowWithIncidentProjection(row: AlertStreamRow | null, payload: any) {
  if (!row) return payload;
  const record = row as AlertStreamRow & Record<string, any>;
  const existing = workflowFacts(payload);
  const projection: Record<string, any> = record.incident_projection && typeof record.incident_projection === "object" ? record.incident_projection : {};
  const projectionPayload: Record<string, any> = projection.projection_payload && typeof projection.projection_payload === "object" ? projection.projection_payload : {};
  const eventPayload: Record<string, any> = projectionPayload.event_payload && typeof projectionPayload.event_payload === "object" ? projectionPayload.event_payload : {};
  return {
    data: {
      ...existing.root,
      alert: { ...record, ...existing.alert },
      incident: {
        ...projection,
        ...existing.incident,
        id: existing.incident.id || existing.incident.incident_id || record.incident_id || projection.incident_id || projection.id,
        ticket_id: existing.ticket || record.ticket_id || record.jira_key || projection.ticket_id || projection.jira_key,
      },
      context: Object.keys(existing.context).length ? existing.context : projectionPayload.context || eventPayload.context || {},
      recommendation: Object.keys(existing.recommendation).length ? existing.recommendation : projectionPayload.recommendation || {},
      metadata: { ...projectionPayload, ...existing.metadata },
      timeline: existing.timeline,
    },
  };
}

type AlertPriority = "action" | "watch" | "duplicate" | "noise";

function classifyAlert(row: AlertStreamRow, workflowPayload: any): { kind: AlertPriority; label: string; reason: string; rank: number } {
  if (isDemoSignal(row)) return { kind: "noise", label: "Demo monitoring", reason: "Observed demo-stack signal; excluded from production operations", rank: 4 };
  if (isSyntheticSignal(row)) return { kind: "noise", label: "Test signal", reason: "Synthetic or configured test signal; retained for audit", rank: 4 };
  const record = row as AlertStreamRow & Record<string, any>;
  const facts = workflowFacts(workflowWithIncidentProjection(row, workflowPayload));
  const metadata = record.metadata && typeof record.metadata === "object" ? record.metadata : {};
  const noiseMetadata = metadata.noise && typeof metadata.noise === "object" ? metadata.noise : {};
  const disposition = String(record.incident_disposition || facts.alert.incident_disposition || facts.incident.incident_disposition || "").toLowerCase();
  const severity = String(row.severity || record.priority || record.labels?.severity || "warning").toLowerCase();
  const duplicate = Boolean(facts.duplicate) || disposition === "duplicate" || Number(record.deduplicated_count || 1) > 1;
  const noise = noiseMetadata.classified === true || ["noise", "ignored", "suppressed", "non_actionable", "non-actionable"].includes(disposition);
  if (noise) return { kind: "noise", label: "Ignored noise", reason: String(noiseMetadata.reason || record.suppression_reason || "Classified as non-actionable"), rank: 4 };
  if (duplicate) return { kind: "duplicate", label: "Duplicate", reason: String(facts.duplicate || record.deduplication_reason || "Linked to the canonical alert within the duplicate window"), rank: 3 };
  if (["critical", "high", "p0", "p1"].includes(severity)) return { kind: "action", label: "Action required", reason: facts.ticket ? `Incident tracked in ${facts.ticket}` : "High-impact unique alert requires investigation", rank: 1 };
  return { kind: "watch", label: "Watch", reason: severity === "warning" ? "Warning signal; monitor before escalation" : "Informational signal with no immediate action", rank: 2 };
}

function metricTrace(row: AlertStreamRow | null) {
  if (!row) return null;
  const metadata = row as AlertStreamRow & Record<string, any>;
  const labels = { ...(metadata.labels || {}), ...(metadata.metric_labels || {}) } as Record<string, any>;
  const annotations = { ...(metadata.annotations || {}) } as Record<string, any>;
  const alertName = String(row.name || row.alert_name || labels.alertname || "Prometheus alert");
  const target = String(labels.instance || metadata.target || metadata.endpoint || row.service || "Target not recorded");
  const metric = String(metadata.metric || labels.metric || (labels.job === "blackbox" ? "probe_success" : labels.__name__ || "Metric not recorded"));
  const value = metadata.metric_value ?? metadata.value ?? (alertName.toLowerCase().includes("unavailable") ? 0 : "See Prometheus");
  const expression = String(metadata.rule_expression || metadata.expr || annotations.expression || (metric === "probe_success" ? `${metric} == 0` : "Rule expression not included in alert payload"));
  return {
    alertName, target, metric, value, expression,
    status: String(metadata.alert_status || row.status || "firing").toLowerCase(),
    severity: String(row.severity || labels.severity || "not recorded"),
    job: String(labels.job || "not recorded"),
    started: formatIstTimestamp(row.starts_at || row.first_seen || row.created_at || row.received_at),
    description: richText(row.description || annotations.description || metadata.summary),
    labels,
  };
}

function observedAlertStages(row: AlertStreamRow, workflowPayload: any) {
  const display = displayAlert(row);
  const trace = metricTrace(row)!;
  const facts = workflowFacts(workflowWithIncidentProjection(row, workflowPayload));
  const contextSource = String(facts.metadata.context_source || facts.context.context_source || "").toLowerCase();
  const stages = [
    { id: "application", label: "Application", Icon: Database, detail: display.project },
    { id: "signal", label: "Signal", Icon: Activity, detail: trace.target },
    { id: "source", label: "Alert landing", Icon: RadioTower, detail: display.channel === "prometheus" ? trace.job : sourceChannelLabel(display.channel) },
  ];
  if (display.channel === "prometheus") stages.push({ id: "alert", label: "Prometheus", Icon: BellRing, detail: trace.alertName });
  else stages.push({ id: "alert", label: "Alert received", Icon: BellRing, detail: trace.alertName });
  if (facts.alert.id || facts.root.alert_id || facts.timeline.some((item: any) => /normaliz/i.test(String(item?.stage || item?.event_type || "")))) stages.push({ id: "normalize", label: "Normalize", Icon: Braces, detail: facts.alert.service || display.service });
  if (facts.duplicate || facts.alert.incident_disposition || facts.incident.incident_disposition) stages.push({ id: "deduplicate", label: "Deduplicate", Icon: GitMerge, detail: facts.duplicate ? "Duplicate linked" : "Unique signal" });
  if (facts.incident.id || facts.incident.incident_id) stages.push({ id: "incident", label: "Incident", Icon: Activity, detail: facts.incident.id || facts.incident.incident_id });
  if (facts.ticket) stages.push({ id: "jira", label: "Jira", Icon: Ticket, detail: String(facts.ticket) });
  if ((facts.context && Object.keys(facts.context).length) || (facts.recommendation && Object.keys(facts.recommendation).length)) stages.push({ id: "evidence-understanding", label: contextSource.includes("cache") ? "Evidence & understanding reused" : "Evidence & understanding", Icon: Database, detail: `${facts.evidence.length} evidence item(s)${facts.recommendation && Object.keys(facts.recommendation).length ? " · RCA available" : " · RCA pending"}` });
  if (facts.root.approval && Object.keys(facts.root.approval).length) stages.push({ id: "approval", label: "Approval", Icon: Ticket, detail: String(facts.root.approval.status || "Decision recorded") });
  if (facts.root.remediation_action && Object.keys(facts.root.remediation_action).length) stages.push({ id: "resolve", label: "Resolve", Icon: Activity, detail: String(facts.root.remediation_action.status || "Executed") });
  if (facts.root.closure_report && Object.keys(facts.root.closure_report).length) stages.push({ id: "validate", label: "Validate", Icon: FileCode2, detail: facts.root.closure_report.health_restored ? "Recovery verified" : "Validation recorded" });
  return stages;
}

function AlertFlowSummary({ row, workflow, selected, onInspect }: { row: AlertStreamRow; workflow: any; selected: boolean; onInspect: () => void }) {
  const display = displayAlert(row);
  const trace = metricTrace(row);
  if (!trace) return null;
  const sourceLabel = sourceChannelLabel(display.channel);
  const stages = observedAlertStages(row, workflow);
  const priority = classifyAlert(row, workflow);
  return <article className={`panel live-alert-flow-card priority-${priority.kind} ${selected ? "is-selected" : ""}`}>
    <header>
      <div><span className={`source-badge source-${display.channel}`}>{sourceLabel}</span><strong>{display.title}</strong><small>{display.service} · {display.lastSeen}</small></div>
      <span className={`alert-priority-badge is-${priority.kind}`} title={priority.reason}>{priority.label}</span>
    </header>
    <div className="live-alert-flow-path" aria-label={`${display.title} processing flow`}>
      {stages.map(({ id, label, Icon, detail }, index) => <div className={id === "alert" ? "is-alert" : ""} key={id} aria-label={`${label}: ${detail}`}>
        <span className="metric-trace-sequence">{String(index + 1).padStart(2, "0")}</span><i><Icon size={17} /></i><strong>{label}</strong><small title={detail}>{detail}</small>
      </div>)}
    </div>
    <AlertIncidentHandoff row={row} />
    <button type="button" className="button-secondary" onClick={onInspect} aria-controls="live-alert-flow-inspector" aria-expanded={selected}>{selected ? "View details" : "Inspect flow"}</button>
  </article>;
}

export default function AlertsRoute() {
  const alerts = useRouteRuntimeSlice("alerts");
  const [searchParams, setSearchParams] = useSearchParams();
  const sourceAlertId = searchParams.get("alert_id") || "";
  const session = useSession();
  const authenticatedRequest = session.accessToken
    ? { headers: { Authorization: `Bearer ${session.accessToken}` } }
    : {};
  const [dedupWindow, setDedupWindow] = useState(60);
  const [liveView, setLiveView] = useState<"inbox" | "split" | "timeline">(() => {
    const saved = window.localStorage.getItem("kaiops.live-alert-view");
    if (saved === "split") return "split";
    if (saved === "timeline" || saved === "flow") return "timeline";
    return "inbox";
  });
  useEffect(() => window.localStorage.setItem("kaiops.live-alert-view", liveView), [liveView]);
  const [dedupSaving, setDedupSaving] = useState(false);
  const [dedupMessage, setDedupMessage] = useState("");
  const [traceAlert, setTraceAlert] = useState<AlertStreamRow | null>(null);
  const [traceStage, setTraceStage] = useState("alert");
  const flowInspectorRef = useRef<HTMLElement | null>(null);
  const [traceWorkflow, setTraceWorkflow] = useState<{ loading: boolean; data: any; error: string; alertId: string; state: "idle" | "loading" | "ready" | "pending" | "error" }>({ loading: false, data: null, error: "", alertId: "", state: "idle" });
  const [priorityFilter, setPriorityFilter] = useState<"all" | AlertPriority>("all");
  const [expandedSourceKey, setExpandedSourceKey] = useState("");
  const prioritizedRows = useMemo(() => alerts.rows
    .map((row, index) => ({ row, index, priority: classifyAlert(row, null) }))
    .filter(({ row }) => !sourceAlertId || String(row.alert_id || row.id || "") === sourceAlertId)
    .filter(({ priority }) => priorityFilter === "all" || priority.kind === priorityFilter)
    .sort((left, right) => left.priority.rank - right.priority.rank || left.index - right.index), [alerts.rows, priorityFilter, sourceAlertId]);
  const priorityCounts = useMemo(() => alerts.rows.reduce((counts, row) => {
    counts[classifyAlert(row, null).kind] += 1;
    return counts;
  }, { action: 0, watch: 0, duplicate: 0, noise: 0 }), [alerts.rows]);
  const activeTraceAlert = traceAlert && alerts.rows.some((row) => alertRowKey(row) === alertRowKey(traceAlert)) ? traceAlert : alerts.rows.find((row) => !sourceAlertId || String(row.alert_id || row.id || "") === sourceAlertId) || null;
  const trace = metricTrace(activeTraceAlert);
  const traceSource = (activeTraceAlert || {}) as AlertStreamRow & Record<string, any>;
  const traceFileName = String(traceSource.file || traceSource.filename || "").trim();
  const traceObjectId = String(traceSource.object_id || "").trim();
  const traceFileUrl = traceObjectId ? `/api-gateway/landing-pad/objects/${encodeURIComponent(traceObjectId)}/download` : "";
  const traceExtract = {
    alert_name: traceSource.name || traceSource.alert_name || traceSource.labels?.alertname || null,
    service: traceSource.service || traceSource.labels?.service || null,
    application: traceSource.application || traceSource.project_name || traceSource.labels?.application || null,
    severity: traceSource.severity || traceSource.labels?.severity || null,
    status: traceSource.alert_status || traceSource.status || null,
    source: traceSource.source || traceSource.source_channel || null,
    starts_at: traceSource.starts_at || traceSource.first_seen || traceSource.received_at || null,
    labels: traceSource.labels || {},
    annotations: traceSource.annotations || {},
  };
  const traceWorkflowData = workflowWithIncidentProjection(activeTraceAlert, traceWorkflow.data);
  const facts = workflowFacts(traceWorkflowData);
  useEffect(() => {
    let active = true;
    const load = async () => {
      let alertId = processedAlertId(activeTraceAlert) || sourceAlertId;
      setTraceWorkflow({ loading: true, data: null, error: "", alertId, state: "loading" });
      try {
        if (!alertId && activeTraceAlert) {
          const response = await routeJson("/api-gateway/alerts/all?limit=150&compact=true", { ...authenticatedRequest, timeoutMs: 12000, maxAttempts: 1 }) as any;
          const rows = response?.data?.rows || response?.rows || response?.data || [];
          const match = canonicalMatch(activeTraceAlert, Array.isArray(rows) ? rows : []);
          alertId = processedAlertId(match);
        }
        if (!alertId) throw new Error("Canonical alert is still being persisted; processed context is not available yet.");
        const data = await routeJson(`/api-gateway/alerts/${encodeURIComponent(alertId)}/processed-result`, { ...authenticatedRequest, timeoutMs: 12000, maxAttempts: 1 });
        if (active) setTraceWorkflow({ loading: false, data, error: "", alertId, state: "ready" });
      } catch (error) {
        const message = error instanceof Error ? error.message : "Processed result unavailable";
        const notProcessed = message.includes("HTTP 404") || message.includes("No processed result found");
        if (active) setTraceWorkflow({ loading: false, data: null, error: notProcessed ? "" : message, alertId, state: notProcessed ? "pending" : "error" });
      }
    };
    load();
    return () => { active = false; };
  }, [activeTraceAlert && alertRowKey(activeTraceAlert), sourceAlertId, session.accessToken]);
  useEffect(() => {
    let active = true;
    routeJson("/alert-intelligence/deduplication/config", { timeoutMs: 8000 })
      .then((value: unknown) => { const payload = value as { window_minutes?: number }; if (active) setDedupWindow(Number(payload.window_minutes || 60)); })
      .catch(() => { if (active) setDedupMessage("Using the configured 60-minute default"); });
    return () => { active = false; };
  }, []);
  const saveDedupWindow = async () => {
    setDedupSaving(true);
    setDedupMessage("");
    try {
      const payload = await routeJson("/alert-intelligence/deduplication/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ window_minutes: dedupWindow }),
        timeoutMs: 8000,
      }) as { window_minutes?: number };
      setDedupWindow(Number(payload.window_minutes || dedupWindow));
      setDedupMessage("Applied to new alerts");
    } catch (error) {
      setDedupMessage(error instanceof Error ? error.message : "Could not update duplicate window");
    } finally {
      setDedupSaving(false);
    }
  };
  const updateFilter = (name: keyof AlertStreamFilters, value: string) => {
    alerts.setView("");
    alerts.updateFilter(name, value);
  };
  const clearAlertFilters = () => {
    alerts.setView("");
    alerts.setSection("active");
    alerts.setChannel("all");
    alerts.setQuery("");
    setPriorityFilter("all");
    alerts.updateFilter("timeRange", "all");
    alerts.updateFilter("severity", "all");
    alerts.updateFilter("environment", "all");
  };
  const hasActiveFilters = Boolean(
    alerts.view || alerts.section !== "active" || alerts.channel !== "all" || alerts.query
    || priorityFilter !== "all" || alerts.filters.timeRange !== "all"
    || alerts.filters.severity !== "all" || alerts.filters.environment !== "all"
  );
  const inspectFlow = (row: AlertStreamRow) => {
    setTraceAlert(row);
    setTraceStage("target");
    window.requestAnimationFrame(() => {
      flowInspectorRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      flowInspectorRef.current?.focus({ preventScroll: true });
    });
  };

  return <section className="grid single-col ingestion-stream-page operations-page">
    <OperationsWorkflowNav active="alerts" />
    <article className="operations-feed-hero">
      <div><span className="discovery-eyebrow">Live operations</span><h2>Operations Feed</h2><p>Monitor, prioritize, and inspect normalized signals for {alerts.project} across every connected source.</p></div>
      <div className="ingestion-live-state" role="status" aria-live="polite"><span className={`ingestion-live-dot ${alerts.loading ? "is-loading" : ""} ${alerts.paused ? "is-paused" : ""}`} aria-hidden="true" /><div><strong>{alerts.paused ? "Updates paused" : alerts.liveState === "connected" ? "Live connection healthy" : alerts.loading ? "Synchronizing" : "Polling fallback active"}</strong><small>{alerts.rows.length} of {alerts.totalRows} arrivals shown</small><small>{alerts.updatedAt ? `Updated ${formatIstTimestamp(alerts.updatedAt)}` : "Waiting for first sync"}</small></div><button type="button" className="button-secondary" onClick={alerts.refresh} disabled={alerts.loading}>{alerts.loading ? <><LoaderCircle className="button-spinner" size={15} aria-hidden="true" />Refreshing…</> : "Refresh"}</button><button type="button" className="button-secondary" aria-pressed={alerts.paused} onClick={alerts.togglePaused}>{alerts.paused ? "Resume" : "Pause"}</button></div>
    </article>

    <article className="panel ingestion-control-panel">
      <div className="ingestion-section-tabs" role="tablist" aria-label="Alert lifecycle sections">{["active", "resolved", "failed", "historical"].map((section) => <button type="button" role="tab" aria-selected={alerts.section === section} className={`detail-tab ${alerts.section === section ? "active" : ""}`} key={section} onClick={() => { alerts.setSection(section); alerts.setView(""); }}>{section === "failed" ? "Failed Intake" : section.charAt(0).toUpperCase() + section.slice(1)}</button>)}</div>
      <div className="ingestion-filter-grid">
        <label>Saved view<select value={alerts.view} onChange={(event) => event.target.value ? alerts.applyView(event.target.value) : alerts.setView("")}><option value="">Custom / all active</option>{alerts.savedViews.map((view) => <option key={view.id} value={view.id}>{view.label}</option>)}</select></label>
        <label>Time range<select value={alerts.filters.timeRange} onChange={(event) => updateFilter("timeRange", event.target.value)}><option value="1h">Last hour</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="all">All loaded</option></select></label>
        <label>Severity<select value={alerts.filters.severity} onChange={(event) => updateFilter("severity", event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="warning">Warning</option><option value="info">Info</option></select></label>
        <label>Project<input value={alerts.project} readOnly aria-label="Selected project" /></label>
        <label>Environment<select value={alerts.filters.environment} onChange={(event) => updateFilter("environment", event.target.value)}><option value="all">All environments</option>{alerts.filterOptions.environments.map((environment) => <option key={environment} value={environment}>{environment}</option>)}</select></label>
        <label className="ingestion-density-toggle"><input type="checkbox" checked={alerts.density === "compact"} onChange={(event) => alerts.setDensity(event.target.checked ? "compact" : "comfortable")} />Compact rows</label>
        <label>Duplicate window<select value={dedupWindow} disabled={dedupSaving} onChange={(event) => { setDedupWindow(Number(event.target.value)); setDedupMessage(""); }}><option value={15}>15 minutes</option><option value={30}>30 minutes</option><option value={60}>1 hour</option><option value={120}>2 hours</option><option value={240}>4 hours</option><option value={1440}>24 hours</option></select></label>
        <button type="button" className="button-secondary" disabled={dedupSaving} onClick={saveDedupWindow}>{dedupSaving ? "Saving..." : "Apply window"}</button>
        {dedupMessage ? <small className="dedup-config-status" role="status">{dedupMessage}</small> : null}
      </div>
    </article>

    <div className="ingestion-channel-grid" aria-label="Alert source counts">{channels.map(([channel, icon, label]) => <button type="button" key={channel} className={`ingestion-channel-card channel-${channel} ${alerts.channel === channel ? "is-active" : ""}`} onClick={() => alerts.setChannel(channel)} aria-pressed={alerts.channel === channel}><span>{icon}</span><div><strong>{alerts.counts[channel] || 0}</strong><small>{label}</small></div></button>)}</div>

    <div className="live-alert-view-switch" role="radiogroup" aria-label="Alerts and streams view">
      <span>View</span>
      <button type="button" role="radio" className={liveView === "inbox" ? "is-active" : ""} aria-checked={liveView === "inbox"} onClick={() => setLiveView("inbox")}><RadioTower size={16} /><span><strong>Unified Signal Inbox</strong><small>Prioritized operational queue</small></span></button>
      <button type="button" role="radio" className={liveView === "split" ? "is-active" : ""} aria-checked={liveView === "split"} onClick={() => setLiveView("split")}><Activity size={16} /><span><strong>Alert + Stream</strong><small>Queue and evidence side by side</small></span></button>
      <button type="button" role="radio" className={liveView === "timeline" ? "is-active" : ""} aria-checked={liveView === "timeline"} onClick={() => setLiveView("timeline")}><GitMerge size={16} /><span><strong>Correlation Timeline</strong><small>Signal through incident lifecycle</small></span></button>
    </div>

    <div className="alert-priority-filter" role="group" aria-label="Alert operational priority">
      {([['all', 'All', alerts.rows.length], ['action', 'Action required', priorityCounts.action], ['watch', 'Watch', priorityCounts.watch], ['duplicate', 'Duplicates', priorityCounts.duplicate], ['noise', 'Ignored noise', priorityCounts.noise]] as const).map(([id, label, count]) => <button type="button" key={id} className={priorityFilter === id ? "is-active" : ""} aria-pressed={priorityFilter === id} onClick={() => setPriorityFilter(id)}><strong>{count}</strong><span>{label}</span></button>)}
    </div>

    {sourceAlertId ? <div className="alert-source-focus" role="status"><span>Source alert: <code>{sourceAlertId}</code></span><button className="button-secondary" onClick={() => setSearchParams({})}>Show all live alerts</button><button className="button-secondary" onClick={() => alerts.open({ id: sourceAlertId, alert_id: sourceAlertId })}>Open persisted source record</button><small>The live window may exclude older or resolved alerts. The persisted record remains available.</small></div> : null}
    {sourceAlertId && !prioritizedRows.length ? <section className="panel alert-source-focus" aria-label="Persisted source alert"><strong>{facts.alert.name || facts.alert.alert_name || "Source alert record"}</strong><p>{traceWorkflow.loading ? "Loading the recorded incident relationship?" : traceWorkflow.state === "ready" ? "This source is outside the current live window. Its persisted processing record is shown below." : "The processing record is not available. Open the persisted source record or refresh to retry."}</p>{traceWorkflow.state === "ready" ? <AlertIncidentHandoff row={{ ...facts.alert, alert_id: sourceAlertId, incident_id: facts.incident.incident_id || facts.incident.id }} /> : null}</section> : null}
    <div className="alert-results-summary" role="status" aria-live="polite">
      <div><strong>{prioritizedRows.length}</strong><span>alert{prioritizedRows.length === 1 ? "" : "s"} in this view</span><small>Sorted by operational priority, then newest arrival.</small></div>
      {hasActiveFilters ? <button type="button" className="button-secondary" onClick={clearAlertFilters}><RotateCcw size={15} aria-hidden="true" />Clear all filters</button> : null}
    </div>

    {liveView === "timeline" ? <div className="live-alert-flow-list">
      {prioritizedRows.map(({ row }) => <AlertFlowSummary key={alertRowKey(row)} row={row} workflow={activeTraceAlert && alertRowKey(activeTraceAlert) === alertRowKey(row) ? traceWorkflow.data : null} selected={Boolean(activeTraceAlert && alertRowKey(activeTraceAlert) === alertRowKey(row))} onInspect={() => inspectFlow(row)} />)}
      {alerts.loading && !alerts.rows.length ? <div className="ingestion-stream-loading" role="status"><LoaderCircle size={22} aria-hidden="true" /><strong>Loading live alerts</strong><p>Connecting to the durable alert stream…</p></div> : null}
      {!alerts.rows.length && !alerts.loading ? <div className="ingestion-stream-empty"><Search size={24} aria-hidden="true" /><strong>No alerts match this view</strong><p>Clear the active filters or verify that the selected project connector is delivering events.</p>{hasActiveFilters ? <button type="button" className="button-secondary" onClick={clearAlertFilters}>Clear all filters</button> : null}</div> : null}
    </div> : null}

    {liveView === "timeline" && trace ? <article id="live-alert-flow-inspector" ref={flowInspectorRef} tabIndex={-1} className="panel metric-alert-trace live-alert-flow-inspector">
      <div className="panel-head"><div><span className="discovery-eyebrow">Prometheus execution</span><h3>Metric-to-Alert Trace</h3><p>{trace.alertName} · {trace.target}</p></div><span className={`pill ${statusPillClass(trace.status)}`}>{trace.status.toUpperCase()}</span></div>
      <div className="metric-trace-flow" aria-label="Prometheus metric to alert flow">{flowStages.map(([id, label, Icon], index) => <button key={id} type="button" className={`${traceStage === id ? "is-selected" : ""} ${id === "alert" ? "is-alert" : ""}`} onClick={() => setTraceStage(id)} aria-pressed={traceStage === id}><span className="metric-trace-sequence">{String(index + 1).padStart(2, "0")}</span><i><Icon size={19} /></i><strong>{label}</strong><small>{id === "target" ? trace.job : id === "scrape" ? "/metrics polled" : id === "parse" ? `${trace.metric} = ${trace.value}` : id === "store" ? "Time series" : id === "rule" ? "Condition matched" : trace.alertName}</small></button>)}</div>
      <div className="metric-trace-details">
        <strong>{flowStages.find(([id]) => id === traceStage)?.[1]}</strong>
        {traceStage === "target" ? <dl><div><dt>Endpoint</dt><dd>{trace.target}</dd></div><div><dt>Prometheus job</dt><dd>{trace.job}</dd></div></dl> : null}
        {traceStage === "scrape" ? <><dl><div><dt>Request</dt><dd>Prometheus periodically requests the target metrics endpoint.</dd></div><div><dt>Result</dt><dd>Metric payload parsed successfully; otherwise target health becomes down.</dd></div><div><dt>Landing file</dt><dd>{traceFileName || "Filename not recorded"}</dd></div><div><dt>File URL</dt><dd>{traceFileUrl ? <a href={traceFileUrl} target="_blank" rel="noreferrer">Open original alert file</a> : traceSource.object_uri ? <code>{String(traceSource.object_uri)}</code> : "Live-buffer file; durable download URL is not available yet."}</dd></div></dl><pre className="metric-parsed-extract">{JSON.stringify(traceExtract, null, 2)}</pre></> : null}
        {traceStage === "parse" ? <><dl><div><dt>Metric</dt><dd><code>{trace.metric}</code></dd></div><div><dt>Observed value</dt><dd>{String(trace.value)}</dd></div><div><dt>Parsed from</dt><dd>{traceFileName || "Canonical alert payload"}</dd></div><div><dt>Fields extracted</dt><dd>alert name, service, application, severity, status, source, timestamps, labels, and annotations</dd></div></dl><pre className="metric-parsed-extract">{JSON.stringify(traceExtract, null, 2)}</pre></> : null}
        {traceStage === "store" ? <dl><div><dt>Series identity</dt><dd><code>{trace.metric}{`{job="${trace.job}"}`}</code></dd></div><div><dt>Labels retained</dt><dd>{Object.keys(trace.labels).join(", ") || "Not recorded"}</dd></div></dl> : null}
        {traceStage === "rule" ? <dl><div><dt>Expression</dt><dd><code>{trace.expression}</code></dd></div><div><dt>Decision</dt><dd>The observed series satisfied the configured alert condition.</dd></div></dl> : null}
        {traceStage === "alert" ? <dl><div><dt>Alert</dt><dd>{trace.alertName}</dd></div><div><dt>Alert ID</dt><dd>{String(traceSource.alert_id || traceSource.id || "Not recorded")}</dd></div><div><dt>Trace ID</dt><dd>{String(traceSource.trace_id || "Not recorded")}</dd></div><div><dt>Severity / state</dt><dd>{trace.severity} / {trace.status}</dd></div><div><dt>First observed</dt><dd>{trace.started}</dd></div><div><dt>Description</dt><dd>{trace.description || "No description received"}</dd></div></dl> : null}
      </div>
      <div className="metric-handoff">
        <div className="metric-handoff-title"><div><span className="discovery-eyebrow">Downstream handoff</span><strong>{traceWorkflow.state === "ready" ? "Alert entered incident processing" : traceWorkflow.state === "pending" ? "Alert only · incident decision pending" : "Checking incident processing"}</strong></div>{traceWorkflow.loading ? <small>Loading status...</small> : traceWorkflow.error ? <small>Processing status could not be loaded. Retry with Refresh.</small> : traceWorkflow.state === "pending" ? <small>No incident projection has been created for this alert.</small> : null}</div>
        {traceWorkflowData ? <div className="metric-handoff-row">
          <div><i><GitMerge size={17} /></i><span><small>Disposition</small><strong>{facts.incident.incident_disposition || facts.alert.incident_disposition || (facts.duplicate ? "Duplicate" : "Incident")}</strong></span></div>
          <div><i><BellRing size={17} /></i><span><small>Incident</small><strong>{facts.incident.id || facts.incident.incident_id || "Not created"}</strong></span></div>
          <div><i><Ticket size={17} /></i><span><small>Jira</small><strong>{facts.ticket || "Not created"}</strong></span></div>
          <div><i><FileCode2 size={17} /></i><span><small>Context</small><strong>{facts.evidence.length ? `${facts.evidence.length} evidence item(s)` : "Not collected"}</strong></span></div>
          {activeTraceAlert ? <AlertIncidentHandoff row={activeTraceAlert} /> : null}
        </div> : traceWorkflow.state === "pending" ? <div className="metric-handoff-pending"><i><BellRing size={17} /></i><div><strong>No incident created yet</strong><small>The alert is visible in Live Stream while normalization, deduplication, or the incident decision catches up.</small></div></div> : traceWorkflow.state === "error" ? <p className="subtitle">The downstream status is temporarily unavailable. The verified Prometheus trace remains visible above.</p> : null}
      </div>
    </article> : null}

    {liveView === "split" ? <section className="alert-split-workspace">
      <article className="panel alert-split-queue"><header><div><span className="discovery-eyebrow">Action queue</span><h3>Alerts</h3></div><strong>{prioritizedRows.length}</strong></header><div>{prioritizedRows.map(({ row, priority }) => { const item=displayAlert(row); const selected=Boolean(activeTraceAlert&&alertRowKey(activeTraceAlert)===alertRowKey(row)); return <button type="button" className={`${selected?"is-selected":""} priority-${priority.kind}`} key={alertRowKey(row)} onClick={()=>setTraceAlert(row)}><i/><span><strong>{item.title}</strong><small>{item.service} · {item.severity} · {item.lastSeen}</small></span><em>{priority.label}</em></button> })}</div></article>
      <article className="panel alert-split-evidence">{activeTraceAlert ? (()=>{const item=displayAlert(activeTraceAlert);const source=sourceEvidence(activeTraceAlert);const priority=classifyAlert(activeTraceAlert,traceWorkflow.data);return <><header><div><span className={`source-badge source-${item.channel}`}>{sourceChannelLabel(item.channel)}</span><h3>{item.title}</h3><p>{item.summary}</p></div><span className={`alert-priority-badge is-${priority.kind}`}>{priority.label}</span></header><dl><div><dt>Service</dt><dd>{item.service}</dd></div><div><dt>Severity</dt><dd>{item.severity}</dd></div><div><dt>Owner</dt><dd>{item.owner}</dd></div><div><dt>Occurrences</dt><dd>{item.occurrences}</dd></div><div><dt>Source</dt><dd>{source.origin}</dd></div><div><dt>Received</dt><dd>{source.received}</dd></div></dl><section><h4>Source message</h4><p>{source.message}</p><details><summary>Labels and annotations</summary><pre>{JSON.stringify({labels:source.labels,annotations:source.annotations},null,2)}</pre></details></section><AlertIncidentHandoff row={activeTraceAlert}/><footer><button className="button-secondary" onClick={()=>setLiveView("timeline")}>Open correlation timeline</button><button className="button-secondary" onClick={()=>alerts.open(activeTraceAlert)}>Review source alert</button></footer></>} )() : <div className="alert-split-empty"><Activity/><strong>Select an alert</strong><p>Choose a signal from the queue to inspect its evidence.</p></div>}</article>
    </section> : null}

    {liveView === "inbox" ? <article className="panel ingestion-stream-panel">
      <div className="ingestion-stream-toolbar"><div><span className="discovery-eyebrow">Prioritized event feed</span><h3>{alerts.channel === "all" ? "All source activity" : alerts.channel === "failed" ? "Failed ingestion activity" : `${sourceChannelLabel(alerts.channel)} activity`}</h3></div><label><span>Search feed</span><div className="alert-search-field"><Search size={16} aria-hidden="true" /><input value={alerts.query} onChange={(event) => alerts.setQuery(event.target.value)} placeholder="Alert, service, project, or source" /></div></label></div>
      {alerts.error ? <div className="ingestion-refresh-warning" role="alert"><AlertTriangle size={18} aria-hidden="true" /><div><strong>Live refresh failed</strong><span>Existing results are preserved. {alerts.error}</span></div><button type="button" className="button-secondary" onClick={alerts.refresh}>Retry</button></div> : null}
      <div className="ingestion-stream-list" aria-live="off">{prioritizedRows.map(({ row, priority }) => {
        const display = displayAlert(row);
        const channel = display.channel;
        const failed = String(row.status || "").toLowerCase() === "failed" || Boolean(row.error);
        const rowKey = alertRowKey(row);
        const source = sourceEvidence(row);
        const sourceExpanded = expandedSourceKey === rowKey;
        const linkedIncident = linkedIncidentId(row);
        return <article className={`ingestion-event channel-${channel} priority-${priority.kind} ${failed ? "is-failed" : ""}`} key={rowKey}><div className="ingestion-event-marker"><span>{channelIcon(channel)}</span><i aria-hidden="true" /></div><div className="ingestion-event-main"><header><div><span className={`alert-priority-badge is-${priority.kind}`} title={priority.reason}>{priority.label}</span><strong>{display.title}</strong><span className={`source-badge source-${channel}`}>{sourceChannelLabel(channel)}</span></div><time>{display.lastSeen}</time></header><p>{display.summary}</p><div className="alert-priority-reason">{priority.reason}</div><footer><span><b>Service</b>{display.service}</span><span><b>Severity</b>{display.severity}</span><span><b>Occurrences</b>{display.occurrences}</span><span><b>Owner</b>{display.owner}</span>{linkedIncident ? <span><b>Incident</b>{linkedIncident}</span> : null}</footer><AlertIncidentHandoff row={row} /><div className="ingestion-event-actions"><button type="button" className="button-secondary" aria-expanded={sourceExpanded} aria-controls={`source-${rowKey}`} onClick={() => setExpandedSourceKey(sourceExpanded ? "" : rowKey)}><Braces size={15} />{sourceExpanded ? "Hide source details" : "Show source details"}</button><button type="button" className="button-secondary" onClick={() => alerts.open(row)}>{"Review source alert"}</button></div>{sourceExpanded ? <section id={`source-${rowKey}`} className="alert-source-evidence"><header><div><small>Original source evidence</small><strong>{source.origin}</strong></div><span className={`source-badge source-${channel}`}>{source.channel}</span></header><dl><div><dt>Source event ID</dt><dd><code>{source.sourceId}</code></dd></div><div><dt>Source location</dt><dd>{source.location}</dd></div><div><dt>Observed at</dt><dd>{source.observed}</dd></div><div><dt>Received at</dt><dd>{source.received}</dd></div><div className="source-message"><dt>Source message</dt><dd>{source.message}</dd></div></dl><div className="alert-source-structured"><details open><summary>Labels ({Object.keys(source.labels).length})</summary><pre>{JSON.stringify(source.labels, null, 2)}</pre></details><details open><summary>Annotations ({Object.keys(source.annotations).length})</summary><pre>{JSON.stringify(source.annotations, null, 2)}</pre></details><details><summary>Raw source payload (sensitive values redacted)</summary><pre>{JSON.stringify(source.payload, null, 2)}</pre></details></div></section> : null}{row.error ? <small className="ingestion-event-error">{compactText(richText(row.error), 240)}</small> : null}</div></article>;
      })}{alerts.loading && !alerts.rows.length ? <div className="ingestion-stream-loading" role="status"><LoaderCircle size={22} aria-hidden="true" /><strong>Loading live alerts</strong><p>Connecting to the durable alert stream…</p></div> : null}{!alerts.rows.length && !alerts.loading ? <div className="ingestion-stream-empty"><Search size={24} aria-hidden="true" /><strong>No alerts match this view</strong><p>Clear the active filters or verify that the selected project connector is delivering events.</p>{hasActiveFilters ? <button type="button" className="button-secondary" onClick={clearAlertFilters}>Clear all filters</button> : null}</div> : null}</div>
    </article> : null}
  </section>;
}
