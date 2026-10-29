import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, Bell, BrainCircuit, Check, CircleSlash2, ClipboardCheck, Copy, ExternalLink, FileCheck2, Filter, Gauge, GitMerge, List, RefreshCw, ScanSearch, Server, ShieldCheck, TicketCheck, Workflow, Wrench } from "lucide-react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import { useRouteRuntimeSlice, type AlertStreamRow, type IncidentFilters, type IncidentRow } from "../../app/routeRuntime";
import { OperationsWorkflowNav } from "../../components/operations/OperationsWorkflowNav";
import { effectiveIncidentStatus } from "../../domain/incidentStatus";
import { hasPendingDecision } from "../../domain/pendingDecision";
import { formatIstTimestamp } from "../../utils/presentation";
import { useOpenIncident } from "../../domain/useOpenIncident";
import { durableIncidentPath } from "../../domain/incidentNavigation";
import "./IncidentsRoute.css";
import { IncidentStatusExplanation } from "./IncidentStatusExplanation";
import { useInboxFeed } from "./useInboxFeed";

const PAGE_SIZE = 10;
type InboxView = "needs_me" | "kai_handling" | "critical" | "watching" | "resolved" | "all";
type RecordType = "all" | "incidents" | "alerts";

function apiErrorMessage(payload: any, fallback: string) {
  const detail = payload?.detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (detail && typeof detail === "object") {
    const message = detail.message || detail.error?.message || detail.code;
    if (typeof message === "string" && message.trim()) return message;
  }
  const message = payload?.message || payload?.error?.message;
  return typeof message === "string" && message.trim() ? message : fallback;
}

export function belongsToInboxView(row: IncidentRow, view: InboxView) {
  const status = String(row.status || "").toLowerCase();
  const lifecycleState = String((row as IncidentRow & { lifecycle_state?: unknown }).lifecycle_state || "").toLowerCase();
  const severity = String(row.severity || "").trim().toLowerCase();
  if (["warning", "warn"].includes(severity)) return false;
  const terminal = ["closed", "resolved", "recovered", "cancelled"].some((value) => status.includes(value) || lifecycleState.includes(value));
  const needsHuman = hasPendingDecision(row as Record<string, unknown>) || status.includes("approval") || lifecycleState.includes("approval") || ["failed", "blocked", "waiting_for_human", "manual_intervention_required", "validation_failed", "rollback_failed", "escalated"].some((value) => status.includes(value) || lifecycleState.includes(value));
  if (view === "needs_me") return !terminal && needsHuman;
  if (view === "kai_handling") return !terminal && !needsHuman;
  if (view === "critical") return !terminal && ["critical", "sev1", "p1"].includes(severity);
  if (view === "watching") return !terminal && ["medium", "warning", "low", "info"].includes(severity);
  if (view === "resolved") return terminal;
  return true;
}

function alertDisposition(row: AlertStreamRow) {
  const metadata = (row as AlertStreamRow & { metadata?: Record<string, unknown> }).metadata || {};
  const noiseMetadata = metadata.noise && typeof metadata.noise === "object" ? metadata.noise as Record<string, unknown> : {};
  const disposition = String(row.incident_disposition || "").toLowerCase();
  const noise = ["noise", "suppressed", "ignored", "non_actionable"].includes(disposition) || noiseMetadata.classified === true;
  const duplicate = !noise && (disposition === "duplicate" || Number(row.deduplicated_count || 1) > 1);
  return { noise, duplicate, noiseReason: String(noiseMetadata.reason || row.suppression_reason || "Non-actionable monitoring noise") };
}

function alertLinkedIncidentId(row: AlertStreamRow) {
  const candidate = String((row as AlertStreamRow & { incident_id?: string | number }).incident_id || "").trim();
  const alertId = String((row as AlertStreamRow & { alert_id?: string | number }).alert_id || row.id || "").trim();
  // Some source adapters reuse the alert identifier in incident_id before an
  // incident exists. Only a distinct identifier is an evidence-backed link.
  return candidate && candidate !== alertId ? candidate : "";
}

function alertBelongsToInboxView(row: AlertStreamRow, view: InboxView) {
  const severity = String(row.severity || row.priority || "").trim().toLowerCase();
  if (["warning", "warn"].includes(severity)) return false;
  const disposition = alertDisposition(row);
  if (view === "needs_me") return !disposition.noise && !disposition.duplicate && ["critical", "high", "p1", "p2", "sev1", "sev2"].includes(severity);
  if (view === "kai_handling") return !disposition.noise && !disposition.duplicate;
  if (view === "critical") return !disposition.noise && ["critical", "p1", "sev1"].includes(severity);
  if (view === "watching") return disposition.noise || disposition.duplicate || ["medium", "warning", "low", "info"].includes(severity);
  if (view === "resolved") return false;
  return true;
}

const stageOrder = [
  { id: "application", cockpit: "overview", label: "Application", detail: "Original source" },
  { id: "signal", cockpit: "overview", label: "Signal", detail: "Failure observed" },
  { id: "prometheus", cockpit: "overview", label: "Prometheus", detail: "Rule fired" },
  { id: "ingest", cockpit: "overview", label: "Alert landing", detail: "KaiMS received" },
  { id: "normalize", cockpit: "overview", label: "Normalize", detail: "Canonical alert" },
  { id: "deduplicate", cockpit: "overview", label: "Deduplicate", detail: "Occurrence decision" },
  { id: "jira", cockpit: "overview", label: "Jira", detail: "Ticket created" },
  { id: "decision", cockpit: "overview", label: "Decision", detail: "Incident or noise" },
  { id: "context", cockpit: "evidence", label: "Context", detail: "Evidence collected" },
  { id: "understand", cockpit: "evidence", label: "Evidence & Understanding", detail: "Evidence, RCA, and impact" },
  { id: "approval", cockpit: "execution", label: "Approval", detail: "Decision gate" },
  { id: "resolve", cockpit: "execution", label: "Resolve", detail: "Plan and remediate" },
  { id: "validate", cockpit: "audit", label: "Validate", detail: "Verify and close" },
];

type StageState = "complete" | "current" | "reused" | "stopped" | "failed";
type LifecycleStage = (typeof stageOrder)[number] & { state: StageState; caption: string };
type Presentation = "summary" | "flow" | "details";
type GroupedIncidentRow = IncidentRow & {
  duplicateIncidents: IncidentRow[];
  jira_assignment_group?: string;
  approval_expires_at?: string;
  jira_last_sync_at?: string;
  next_action_owner?: string;
  closure_authority?: string;
};
type IncidentGroupPage = {
  rows: IncidentRow[];
  next_cursor: string | null;
  previous_cursor: string | null;
  total_count: number;
  filtered_count: number;
  active_count: number;
  needs_attention_count: number;
  unlinked_signal_count: number;
  generated_at: string;
};
type UnifiedRecord = { record_type: "incident"; score: number; row: IncidentRow } | { record_type: "alert"; score: number; row: AlertStreamRow };
type UnifiedPage = { rows: UnifiedRecord[]; next_cursor: string | null; previous_cursor: string | null; total_count: number; filtered_count: number; record_counts: { incidents: number; alerts: number }; view_counts: Record<string, number> };

const EMPTY_GROUP_PAGE: IncidentGroupPage = {
  rows: [], next_cursor: null, previous_cursor: null, total_count: 0,
  filtered_count: 0, active_count: 0, needs_attention_count: 0,
  unlinked_signal_count: 0, generated_at: "",
};
const EMPTY_UNIFIED_PAGE: UnifiedPage = { rows: [], next_cursor: null, previous_cursor: null, total_count: 0, filtered_count: 0, record_counts: { incidents: 0, alerts: 0 }, view_counts: {} };

const stageIcons = {
  application: Server,
  signal: Gauge,
  prometheus: Activity,
  ingest: Bell,
  normalize: Filter,
  deduplicate: GitMerge,
  jira: TicketCheck,
  decision: ScanSearch,
  context: ScanSearch,
  understand: BrainCircuit,
  approval: ClipboardCheck,
  resolve: Wrench,
  validate: ShieldCheck,
} as const;

function normalizedStatus(row: IncidentRow) {
  const projection = row.projection_payload && typeof row.projection_payload === "object" ? row.projection_payload : {};
  const event = projectionEvent(row);
  const approval = projection.approval && typeof projection.approval === "object"
    ? projection.approval as Record<string, unknown>
    : {};
  return effectiveIncidentStatus(
    row.status || projection.status || "open",
    row.approval_status
      || projection.approval_status
      || approval.status
      || approval.decision
      || event.approval_status
      || event.decision,
  );
}

export function analysisBlocker(row: IncidentRow): string {
  if (!["open", "investigating", "collecting", "waiting_for_human", "collection_blocked", "rca_ready", "context_ready"].includes(normalizedStatus(row))) return "";
  const analysis = row.analysis_summary;
  if (!analysis?.completed_at) return "";
  const reasons = (analysis.blockers || []).filter(Boolean);
  if (reasons.length) return reasons.join("; ");
  if (analysis.rca_status !== "grounded") {
    const gaps = (analysis.missing_evidence || []).join(", ");
    return gaps ? `Analysis completed; additional evidence required: ${gaps}` : "Analysis completed without a confirmed cause; additional evidence or operator review is required.";
  }
  return "";
}

export function lifecycleFor(row: IncidentRow): LifecycleStage[] {
  const status = normalizedStatus(row);
  const event = projectionEvent(row);
  const labels = projectionLabels(row);
  const mode = String(row.execution_mode || event.execution_mode || "human-approval").toLowerCase();
  const decision = String(row.approval_status || event.approval_status || "").toLowerCase();
  const jiraReady = Boolean(row.ticket_id || row.jira_key);
  const contextState = contextPresentation(row);
  const route = resolutionPath(row);
  const contextReady = !["Context pending", "Historical context unavailable"].includes(contextState.label);
  const projection = row.projection_payload && typeof row.projection_payload === "object" ? row.projection_payload : {};
  const lifecycleCandidate = row.resolution_lifecycle || projection.resolution_lifecycle || event.resolution_lifecycle;
  const lifecycle = lifecycleCandidate && typeof lifecycleCandidate === "object" ? lifecycleCandidate as Record<string, any> : {};
  const lifecycleValidation = lifecycle.validation && typeof lifecycle.validation === "object" ? lifecycle.validation as Record<string, any> : {};
  const observedRecovery = lifecycleValidation.closure_kind === "observed_recovery" || event.closure_kind === "observed_recovery";
  const manualClosure = lifecycleValidation.administrative_disposition === true || String(row.status_reason || "").toLowerCase().includes("administratively closed");
  const latestEvent = String(row.latest_event_type || projection.event_type || "").toLowerCase();
  const noise = incidentNoise(row).noise;
  const deduplication = event.deduplication && typeof event.deduplication === "object" ? event.deduplication as Record<string, unknown> : {};
  const duplicate = String(row.incident_disposition || deduplication.disposition || "").toLowerCase() === "duplicate";
  // "rca_ready" is real forward progress - a grounded, conclusive RCA with no
  // ready-to-execute plan yet (see resolution-agent's
  // _resolution_projection_status and the backend's _STATUS_PRECEDENCE,
  // where it ranks strictly above "investigating"). Omitting it here meant
  // the "Evidence & Understanding" stage stayed captioned "Generating RCA"
  // forever for a genuinely completed RCA, even once the backend's own
  // status correctly advanced.
  const blocker = analysisBlocker(row);
  const understood = ["rca_ready", "awaiting_approval", "approved", "remediating", "validating", "resolved", "closed", "failed"].includes(status);
  const approvalStarted = mode.includes("human") && (["awaiting_approval", "approved", "remediating", "validating", "resolved", "closed"].includes(status) || Boolean(decision));
  const approvalComplete = ["approved", "modified", "rejected"].includes(decision) || ["approved", "remediating", "validating", "resolved", "closed"].includes(status);
  const validated = ["resolved", "closed"].includes(status);
  const hasContextEvidence = Boolean(
    projection.context_metadata || projection.context || event.context_metadata || event.context
    || event.context_source || projection.context_source || latestEvent.includes("context"),
  );
  const complete = (id: string, caption: string): LifecycleStage => ({ ...stageOrder.find((stage) => stage.id === id)!, state: "complete", caption });
  const application = value(labels.application, labels.project_name, event.application, row.service);
  const target = value(labels.instance, event.instance, event.target);
  const alertName = value(labels.alertname, event.alert_name, event.name);
  const source = value(row.source, row.origin_system, labels.origin_system, labels.source);
  const prometheusObserved = /prometheus|blackbox|alertmanager/i.test([source, labels.job, labels.transport, event.ingestion_channel].join(" "));
  const stage = (id: string) => stageOrder.find((item) => item.id === id)!;
  const stages: LifecycleStage[] = [
    ...(application !== "Not recorded" ? [complete("application", application)] : []),
    ...(target !== "Not recorded" ? [complete("signal", target)] : []),
    ...(prometheusObserved ? [complete("prometheus", alertName !== "Not recorded" ? alertName : "Alert rule fired")] : []),
    ...(row.alert_id ? [complete("ingest", value(event.received_at, row.created_at, "Alert received"))] : []),
    ...(/normaliz/.test(latestEvent) || Boolean(event.normalized_alert || projection.normalized_alert) ? [complete("normalize", value(row.service, "Canonical alert"))] : []),
    ...(duplicate || Number(row.deduplicated_count || 1) > 1 || Boolean(event.deduplication || projection.deduplication) ? [complete("deduplicate", duplicate ? "Duplicate linked" : Number(row.deduplicated_count || 1) > 1 ? `${row.deduplicated_count} occurrences merged` : "Unique signal")] : []),
    ...(jiraReady ? [complete("jira", String(row.ticket_id || row.jira_key))] : []),
  ];
  if (noise) {
    stages.push({ ...stage("decision"), state: "stopped", caption: "Noise / no action" });
    return stages;
  }
  if (duplicate) {
    stages.push({ ...stage("decision"), state: "stopped", caption: "Linked to canonical incident" });
    return stages;
  }
  stages.push(complete("decision", "Incident created"));
  if (hasContextEvidence) {
    stages.push({
      ...stage("context"),
      state: contextReady ? (contextState.source.includes("cache") || contextState.source === "ticket_payload" ? "reused" : "complete") : "current",
      caption: contextReady ? contextState.label : "Collecting evidence",
    });
  }
  if (row.recommendation_id || event.recommendation_id || latestEvent.includes("recommendation") || understood) {
    stages.push({ ...stage("understand"), state: observedRecovery || blocker ? "stopped" : route.analysisReused ? "reused" : understood ? "complete" : "current", caption: observedRecovery ? "Cause remains inconclusive" : status === "waiting_for_human" ? "Waiting for human evidence" : blocker ? "Analysis completed; more evidence needed" : route.analysisReused ? "Qualified RCA reused" : understood ? "RCA generated" : "Generating RCA" });
  }
  if (observedRecovery) {
    stages.push({ ...stage("approval"), state: "complete", caption: "Operator authorized recovery assessment" });
  } else if (approvalStarted && !route.skipped.has("approval")) {
    stages.push({ ...stage("approval"), state: approvalComplete ? "complete" : "current", caption: approvalComplete ? "Decision recorded" : "Awaiting decision" });
  }
  const hasRemediation = Boolean(projection.remediation_action || projection.remediation_status || event.remediation_action || latestEvent.includes("remediation"));
  const hasValidation = Boolean(projection.closure_report || projection.validation || event.closure_report || latestEvent.includes("closure") || latestEvent.includes("validation"));
  if (status === "approved") {
    stages.push({ ...stage("resolve"), state: "current", caption: "Awaiting confirmation and execution" });
  } else if (status === "remediating") {
    stages.push({ ...stage("resolve"), state: "current", caption: "Executing remediation" });
  } else if (status === "validating") {
    stages.push({ ...stage("resolve"), state: "complete", caption: "Remediation completed" });
    stages.push({ ...stage("validate"), state: "current", caption: "Verifying recovery" });
  } else if (status === "failed") {
    if (hasValidation) {
      stages.push({ ...stage("resolve"), state: "complete", caption: "Remediation completed" });
      stages.push({ ...stage("validate"), state: "failed", caption: "Recovery validation failed" });
    } else {
      stages.push({ ...stage("resolve"), state: "failed", caption: "Remediation failed or was blocked" });
    }
  } else if (validated) {
    if (observedRecovery) {
      stages.push({ ...stage("resolve"), state: "stopped", caption: "Repair performed outside KaiMS executor" });
      stages.push({ ...stage("validate"), state: "complete", caption: "Recovery independently verified and closed" });
    } else if (manualClosure) {
      stages.push({ ...stage("resolve"), state: "stopped", caption: "Corrective execution not performed" });
      stages.push({ ...stage("validate"), state: "complete", caption: "Administrative closure recorded" });
    } else if (route.id === "diagnostic") {
      stages.push({ ...stage("resolve"), state: "reused", caption: "No corrective action required" });
      stages.push({ ...stage("validate"), state: "complete", caption: "Observation recorded and closed" });
    } else {
      stages.push({ ...stage("resolve"), state: "complete", caption: "Remediation completed" });
      stages.push({ ...stage("validate"), state: "complete", caption: "Verified and closed" });
    }
  } else {
    if (hasRemediation) stages.push({ ...stage("resolve"), state: "complete", caption: "Remediation recorded" });
    if (hasValidation) stages.push({ ...stage("validate"), state: "current", caption: "Verifying recovery" });
  }
  return stages;
}

export function currentLifecycleStage(row: IncidentRow, stages = lifecycleFor(row)) {
  if (["closed", "resolved"].includes(normalizedStatus(row))) return stages[stages.length - 1];
  return stages.find(stage => ["current", "failed", "stopped"].includes(stage.state)) || stages[stages.length - 1];
}

function resolutionPath(row: IncidentRow) {
  const projection = row.projection_payload && typeof row.projection_payload === "object" ? row.projection_payload : {};
  const event = projectionEvent(row);
  const sourcePayload = event.source_payload && typeof event.source_payload === "object" ? event.source_payload as Record<string, any> : {};
  const recommendation = [event.recommendation, projection.recommendation, sourcePayload.recommendation]
    .find((candidate) => candidate && typeof candidate === "object") as Record<string, any> | undefined;
  const metadata = recommendation?.metadata && typeof recommendation.metadata === "object" ? recommendation.metadata : {};
  const persistedCandidate = row.orchestration_path || projection.orchestration_path || metadata.orchestration_path;
  const persisted = persistedCandidate && typeof persistedCandidate === "object" ? persistedCandidate as Record<string, any> : {};
  const lifecycleCandidate = row.resolution_lifecycle || projection.resolution_lifecycle || event.resolution_lifecycle;
  const lifecycle = lifecycleCandidate && typeof lifecycleCandidate === "object" ? lifecycleCandidate as Record<string, any> : {};
  const controlCandidate = lifecycle.control || metadata.resolution_control;
  const control = controlCandidate && typeof controlCandidate === "object" ? controlCandidate as Record<string, any> : {};
  const context = [projection.context_metadata, projection.context, event.context_metadata, event.context, sourcePayload.context]
    .find((candidate) => candidate && typeof candidate === "object") as Record<string, any> | undefined;
  const contextMetadata = context?.metadata && typeof context.metadata === "object" ? context.metadata : context || {};
  const analysisReused = persisted.analysis_reused === true || metadata.analysis_reused === true;
  const contextReused = persisted.context_reused === true || contextMetadata.context_reused === true;
  const disposition = String(persisted.disposition || control.disposition || "").toLowerCase();
  const diagnosticMode = String(row.execution_mode || event.execution_mode || "").toLowerCase().includes("diagnostic");
  const id = String(persisted.id || (diagnosticMode || disposition === "watch_only" || disposition === "investigate" ? "diagnostic" : analysisReused ? "verified_fast_path" : row.requires_approval === false ? "autonomous" : "guided"));
  const fallbackLabel = id === "diagnostic" ? "Diagnostic path" : analysisReused ? "Verified reuse fast path" : contextReused ? "Context reuse path" : "Fresh analysis path";
  return {
    id,
    label: String(persisted.label || fallbackLabel),
    analysisReused,
    contextReused,
    skipped: new Set(Array.isArray(persisted.skipped_stages) ? persisted.skipped_stages.map(String) : []),
  };
}

function projectionEvent(row: IncidentRow) {
  const projection = row.projection_payload && typeof row.projection_payload === "object" ? row.projection_payload : {};
  const event = projection.event_payload && typeof projection.event_payload === "object" ? projection.event_payload as Record<string, unknown> : {};
  return event;
}

function projectionLabels(row: IncidentRow) {
  const projection = row.projection_payload && typeof row.projection_payload === "object" ? row.projection_payload : {};
  const event = projectionEvent(row);
  const candidates = [row.source_alert?.labels, event.labels, projection.labels, event.alert_labels, projection.alert_labels];
  return (candidates.find((candidate) => candidate && typeof candidate === "object") || {}) as Record<string, unknown>;
}

function incidentNoise(row: IncidentRow) {
  const event = projectionEvent(row);
  const candidate = event.incident_candidate && typeof event.incident_candidate === "object"
    ? event.incident_candidate as Record<string, unknown>
    : {};
  const noise = candidate.noise === true || candidate.false_positive === true || candidate.actionable === false;
  return {
    noise,
    reason: String(candidate.actionability_reason || candidate.description || "Classified as non-actionable monitoring noise."),
  };
}

export function isActionableInboxIncident(row: IncidentRow) {
  return !["warning", "warn"].includes(String(row.severity || "").trim().toLowerCase()) && !incidentNoise(row).noise;
}

function contextPresentation(row: IncidentRow) {
  const projection = row.projection_payload && typeof row.projection_payload === "object" ? row.projection_payload : {};
  const event = projectionEvent(row);
  const nested = [projection.context_metadata, projection.context, event.context_metadata, event.context]
    .find((candidate) => candidate && typeof candidate === "object") as Record<string, unknown> | undefined;
  const source = String(nested?.context_source || event.context_source || projection.context_source || "").toLowerCase();
  const strategy = String(nested?.context_strategy || event.context_strategy || projection.context_strategy || "auto").toLowerCase();
  const realtime = nested?.realtime_collection_performed ?? event.realtime_collection_performed ?? projection.realtime_collection_performed;
  const status = normalizedStatus(row);
  const downstreamComplete = ["awaiting_approval", "approved", "remediating", "validating", "resolved", "closed", "failed"].includes(status)
    || Boolean(row.recommendation_id || event.recommendation_id || projection.recommendation_id);
  if (source === "ticket_payload") return { label: "Available in ticket", source, strategy, realtime: false };
  if (["cache", "periodic_cache"].includes(source)) return { label: source === "periodic_cache" ? "Historical snapshot reused" : "Cached context reused", source, strategy, realtime: false };
  if (source === "historical_cache_miss") return { label: "Historical context unavailable", source, strategy, realtime: false };
  if (source === "realtime_collection" || realtime === true) return { label: "Realtime context collected", source: source || "realtime_collection", strategy, realtime: true };
  if (downstreamComplete) return { label: "Context available", source: "provenance_not_recorded", strategy, realtime: null };
  return { label: "Context pending", source: source || "not_recorded", strategy, realtime: false };
}

function value(...candidates: unknown[]) {
  const match = candidates.find((candidate) => candidate !== undefined && candidate !== null && String(candidate).trim());
  return match === undefined ? "Not recorded" : String(match);
}

function incidentTitle(row: IncidentRow) {
  return String(row.title || row.summary || `${row.service || "Service"} incident`).trim();
}

function incidentStatusLabel(row: IncidentRow) {
  const status = normalizedStatus(row);
  if (analysisBlocker(row)) return "Action required";
  return status === "failed" ? "Action required" : status.replaceAll("_", " ");
}

export function authoritativeLifecycleNote(row: IncidentRow): { label: string; reason: string } {
  const status = normalizedStatus(row);
  const blocker = analysisBlocker(row);
  if (status === "waiting_for_human") {
    return {
      label: "Waiting for human",
      reason: "A human evidence request is open in the Evidence tab awaiting responder input before RCA can be confirmed.",
    };
  }
  if (status === "investigating") {
    return {
      label: "Investigating",
      reason: blocker
        ? "Automated analysis completed without a confirmed root cause (<65% confidence or <2 corroborating sources) and no pending human prompt is open."
        : "Automated root-cause analysis is in progress.",
    };
  }
  if (status === "collecting") {
    return {
      label: "Collecting",
      reason: "Automated evidence collection jobs are queued or running.",
    };
  }
  if (status === "collection_blocked") {
    return {
      label: "Collection blocked",
      reason: "Automated evidence collection is blocked by a missing or failing technical source connector.",
    };
  }
  if (status === "context_ready") {
    return {
      label: "Context ready",
      reason: "Context snapshot committed; awaiting root-cause analysis and recommendation generation.",
    };
  }
  if (status === "detected" || status === "open") {
    return {
      label: "Detected",
      reason: "Initial alert intake recorded; awaiting context snapshot and evidence requirement generation.",
    };
  }
  return {
    label: status.replaceAll("_", " "),
    reason: String(row.status_reason || blocker || `Lifecycle status: ${status.replaceAll("_", " ")}`),
  };
}

export default function IncidentsRoute() {
  const openIncident = useOpenIncident();
  const incidents = useRouteRuntimeSlice("incidents");
  const alerts = useRouteRuntimeSlice("alerts");
  const session = useRouteRuntimeSlice("session");
  const [searchParams, setSearchParams] = useSearchParams();
  const cursor = String(searchParams.get("cursor") || "");
  const restoredFilter = (name: keyof IncidentFilters) => String(searchParams.get(name) ?? incidents.filters[name] ?? "");
  const groupPage: IncidentGroupPage = { ...EMPTY_GROUP_PAGE, ...incidents.page, rows: incidents.rows };
  const focusedIncidentId = String(searchParams.get("incident_id") || "").trim();
  const recordType = (focusedIncidentId || searchParams.get("record_type") === "incidents" ? "incidents" : "all") as RecordType;
  const [presentation, setPresentation] = useState<Presentation>(() => {
    const saved = window.localStorage.getItem("kaiops.incident-presentation");
    if (focusedIncidentId) return "details";
    return saved === "flow" ? "flow" : "summary";
  });
  const page = Math.max(1, Math.floor(Number(searchParams.get("page")) || 1));
  const inboxView = focusedIncidentId ? "all" : (["needs_me", "kai_handling", "critical", "watching", "resolved", "all"].includes(searchParams.get("inbox_view") || "") ? searchParams.get("inbox_view") : "all") as InboxView;
  const inboxAlertRows = alerts.inboxRows || alerts.rows;
  // The unified feed owns its cursor; never send it to the legacy incident feed.
  const inboxParams = new URLSearchParams({ limit: String(PAGE_SIZE), inbox_view: inboxView, record_type: recordType });
  const selectedProject = String(incidents.application || "").trim();
  const previousProject = useRef(selectedProject);
  const resetInboxFilters = () => {
    for (const name of ["risk_tier", "execution_mode", "transport_provider", "status", "service"] as const) {
      incidents.updateFilter(name, name === "service" ? "" : "all");
    }
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      for (const name of ["cursor", "page", "incident_id", "risk_tier", "execution_mode", "transport_provider", "status", "service"]) next.delete(name);
      next.set("inbox_view", "all");
      next.set("record_type", "all");
      return next;
    }, { replace: true });
  };
  useEffect(() => {
    if (previousProject.current === selectedProject) return;
    previousProject.current = selectedProject;
    // Cursors and service filters belong to the previous application's queue.
    resetInboxFilters();
  }, [selectedProject]);

  const isAllApplications = !selectedProject || ["all", "all applications", "all-applications", "unscoped"].includes(selectedProject.trim().toLowerCase());
  if (!isAllApplications) inboxParams.set("project_id", selectedProject);
  if (cursor) inboxParams.set("cursor", cursor);
  for (const [key, filterValue] of Object.entries({
    risk_tier: restoredFilter("risk_tier"), execution_mode: restoredFilter("execution_mode"),
    transport_provider: restoredFilter("transport_provider"), status: restoredFilter("status"),
    service: restoredFilter("service"),
  })) if (filterValue && filterValue !== "all") inboxParams.set(key, filterValue);
  const { data: unifiedPage, loading: unifiedLoading, error: unifiedError, refresh: refreshInbox } = useInboxFeed<UnifiedPage>(
    `/api-gateway/incidents/inbox/feed?${inboxParams.toString()}`, session.accessToken || "", EMPTY_UNIFIED_PAGE, apiErrorMessage,
  );
  const groupedIncidents = useMemo<GroupedIncidentRow[]>(() => {
    const alertsById = new Map(inboxAlertRows.map((alert) => [String(alert.id || (alert as typeof alert & { alert_id?: string }).alert_id || ""), alert]));
    const feedRows = unifiedPage.rows
      .filter((item) => item.record_type === "incident")
      .map((item) => item.row as IncidentRow);
    const sourceRows = feedRows;
    const canonicalRows = sourceRows.map((row) => ({
      ...row,
      source_alert: row.source_alert || alertsById.get(String(row.alert_id || "")),
      duplicateIncidents: [],
    }));
    if (!focusedIncidentId) return canonicalRows;
    const focused = canonicalRows.find((row) => String(row.incident_id || row.id || "") === focusedIncidentId)
      || incidents.rows.find((row) => String(row.incident_id || row.id || "") === focusedIncidentId);
    return focused ? [{ ...focused, duplicateIncidents: [] }] : canonicalRows;
  }, [focusedIncidentId, groupPage.rows, incidents.rows, inboxAlertRows, unifiedPage.rows]);
  const filteredIncidents = useMemo(
    () => groupedIncidents,
    [groupedIncidents, inboxView],
  );
  useEffect(() => window.localStorage.setItem("kaiops.incident-presentation", presentation), [presentation]);
  const incidentAlertIds = useMemo(() => new Set(incidents.rows.map((row) => String(row.alert_id || "")).filter(Boolean)), [incidents.rows]);
  const unlinkedAlerts = useMemo(() => inboxAlertRows.filter((alert) => {
    const alertId = String((alert as typeof alert & { alert_id?: string | number }).alert_id || alert.id || "");
    return !alertLinkedIncidentId(alert) && (!alertId || !incidentAlertIds.has(alertId));
  }), [inboxAlertRows, incidentAlertIds]);
  const filteredAlerts = useMemo(() => {
    const candidates = unlinkedAlerts;
    const serviceQuery = incidents.filters.service.trim().toLowerCase();
    return candidates.filter((alert) => {
      if (!alertBelongsToInboxView(alert, inboxView)) return false;
      if (!serviceQuery) return true;
      return [alert.service, alert.application, alert.project_name, alert.name, alert.alert_name]
        .some((value) => String(value || "").toLowerCase().includes(serviceQuery));
    });
  }, [inboxAlertRows, incidents.filters.service, inboxView, recordType, unlinkedAlerts]);
  const unifiedRecords = useMemo(() => unifiedPage.rows.map((item) => item.record_type === "incident"
    ? { kind: "incident" as const, score: item.score, row: item.row as IncidentRow }
    : { kind: "alert" as const, score: item.score, row: item.row as AlertStreamRow }), [unifiedPage.rows]);
  const totalRecords = recordType === "all" ? unifiedPage.filtered_count : recordType === "alerts" ? filteredAlerts.length : unifiedPage.filtered_count;
  const pages = Math.max(1, Math.ceil(totalRecords / PAGE_SIZE));
  useEffect(() => {
    if (!focusedIncidentId) return;
    setPresentation("details");
  }, [focusedIncidentId, groupedIncidents]);
  const rows = useMemo(() => {
    if (focusedIncidentId) return groupedIncidents.filter((row) => String(row.incident_id || row.id || "") === focusedIncidentId);
    return filteredIncidents;
  }, [focusedIncidentId, groupedIncidents, filteredIncidents]);
  const visibleAlerts = useMemo(() => filteredAlerts.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), [filteredAlerts, page]);
  const visibleUnifiedRecords = unifiedRecords;
  const changePresentation = (next: Presentation) => {
    if (next === "summary" && focusedIncidentId) setSearchParams({}, { replace: true });
    setPresentation(next);
  };
  const updateIncidentFilter = (name: keyof IncidentFilters, value: string) => {
    incidents.updateFilter(name, value);
    setSearchParams((current) => { const next = new URLSearchParams(current); next.delete("cursor"); next.delete("page"); if (value && value !== "all") next.set(name, value); else next.delete(name); return next; }, { replace: true });
  };
  const select = (label: string, name: keyof IncidentFilters, options: string[]) => <label>{label}<select value={restoredFilter(name)} onChange={(event) => updateIncidentFilter(name, event.target.value)}>{options.map((option) => <option value={option} key={option}>{option}</option>)}</select></label>;
  const totalIncidents = Number(unifiedPage.record_counts.incidents || unifiedPage.view_counts.all || 0);
  const resolvedIncidents = Number(unifiedPage.view_counts.resolved || 0);
  const active = Math.max(0, totalIncidents - resolvedIncidents);
  const needsAttention = Number(unifiedPage.view_counts.needs_me || 0);
  const viewCount = (view: InboxView) => {
    const incidentCount = Number(unifiedPage.view_counts[view] ?? (view === "all" ? totalIncidents : 0));
    return recordType === "incidents" ? incidentCount : recordType === "alerts" ? inboxAlertRows.filter((row) => alertBelongsToInboxView(row, view)).length : Number(unifiedPage.view_counts[view] || 0);
  };
  const showUnified = recordType === "all";
  const showAlerts = recordType === "alerts";
  const showIncidents = recordType === "incidents";

  if (focusedIncidentId) return <Navigate to={durableIncidentPath({ incident_id: focusedIncidentId })!} replace />;
  return <section className="grid single-col operations-center">
    <OperationsWorkflowNav active="incidents" />
    <header className="incident-list-heading unified-inbox-heading">
      <div><span className="inbox-eyebrow"><Activity size={14} /> Incident command queue</span><h2>Unified Inbox</h2><p>Live signals awaiting correlation and their canonical incidents, including verified resolutions.</p></div>
      <Link className="button-secondary" to="/closed-incidents">Closed incident history</Link>
      <div className="operations-kpis" aria-label="Incident totals"><span className={needsAttention ? "is-urgent" : ""}><small>Needs attention</small><strong>{needsAttention}</strong></span><span><small>Active incidents</small><strong>{active}</strong></span><span><small>Total incidents</small><strong>{totalIncidents}</strong></span></div>
    </header>
    <nav className="incident-inbox-views" aria-label="Incident inbox views">{([
      ["needs_me", "Needs me"], ["kai_handling", "Kai handling"], ["critical", "Critical"], ["watching", "Watching"], ["resolved", "Resolved recently"], ["all", "All"],
    ] as const).map(([id, label]) => <button type="button" key={id} className={inboxView === id ? "active" : ""} aria-pressed={inboxView === id} onClick={() => { setSearchParams((current) => { const next = new URLSearchParams(current); next.delete("cursor"); next.delete("page"); next.set("inbox_view", id); return next; }); }}>{label}<span>{viewCount(id)}</span></button>)}</nav>
    <div className={`compact-filter-bar inbox-filter-bar ${showUnified ? "is-unified" : showAlerts ? "is-signals" : ""}`}>
      <label>Records<select aria-label="Inbox records" value={recordType} onChange={(event) => {
        const nextType = event.target.value as RecordType;
            setSearchParams((current) => { const next = new URLSearchParams(current); next.delete("cursor"); next.delete("page"); next.delete("incident_id"); next.set("record_type", nextType); return next; });
      }}><option value="all">Live alerts and incidents</option><option value="incidents">Incidents only</option></select></label>
      {showIncidents ? <>{select("Risk", "risk_tier", ["all", "high", "medium", "low"])}{select("Status", "status", ["all", "open", "investigating", "waiting_for_human", "awaiting_approval", "remediating", "validating", "closed", "failed"])}</> : null}
      <label className="filter-grow">Service<input value={restoredFilter("service")} placeholder="Search service, application, or signal" onChange={(event) => updateIncidentFilter("service", event.target.value)} /></label>
      {showAlerts ? <div className="alert-view-note"><ScanSearch size={15} /> Raw intake with deduplication and noise outcomes</div> : null}
      <button className="button-secondary" type="button" onClick={resetInboxFilters}>Show all incidents and alerts</button>
      <button className="icon-button" type="button" onClick={refreshInbox} title="Refresh queue" aria-label="Refresh queue"><RefreshCw size={17} /></button>
    </div>
    {unifiedError ? <p className="error" role="alert">{unifiedError}{unifiedPage.rows.length ? " Showing the last successfully loaded page." : ""}</p> : null}
    {!showUnified ? <div className="incident-presentation" role="radiogroup" aria-label={`${showAlerts ? "Signal" : "Incident"} workspace view`}>
      <span>View</span>
      <button type="button" role="radio" aria-checked={presentation === "summary"} className={presentation === "summary" ? "active" : ""} onClick={() => changePresentation("summary")}><List size={15} /><span><strong>{focusedIncidentId ? "Back to inbox" : "Triage queue"}</strong><small>Compact prioritized list</small></span></button>
      <button type="button" role="radio" aria-checked={presentation === "flow"} className={presentation === "flow" ? "active" : ""} onClick={() => changePresentation("flow")}><Workflow size={15} /><span><strong>Correlation Timeline</strong><small>{showAlerts ? "Signal processing path" : "Executed lifecycle"}</small></span></button>
    </div> : null}

    <div className={`incident-summary-list view-${presentation}`} aria-busy={unifiedLoading}>
      {unifiedLoading && !unifiedPage.rows.length ? <p className="empty-state" role="status">Loading incidents and alerts...</p> : null}
      {showUnified ? <div className="unified-inbox-stack" role="region" aria-label="Prioritized operational activity">{visibleUnifiedRecords.map((record, index) => {
        if (record.kind === "incident") {
          const row = record.row;
          const incidentId = String(row.incident_id || row.id || index);
          const lifecycle = lifecycleFor(row);
          const currentStage = currentLifecycleStage(row, lifecycle);
          const event = projectionEvent(row);
          const needsHuman = belongsToInboxView(row, "needs_me");
          const severity = String(row.severity || row.risk_tier || "not-set").toLowerCase();
          return <article className={`unified-inbox-card is-incident severity-${severity}`} key={`incident-${incidentId}`}>
            <span className="unified-card-rail" aria-hidden="true" />
            <div className={`unified-card-icon ${needsHuman ? "is-urgent" : ""}`}>{needsHuman ? <FileCheck2 size={20} /> : <BrainCircuit size={20} />}</div>
            <div className="unified-card-body">
              <div className="unified-card-kicker"><span>Incident</span><code>{incidentId}</code>{Number(row.total_occurrence_count || 0) > 1 ? <em>{row.total_occurrence_count} occurrences</em> : null}</div>
              <button type="button" className="unified-card-title" onClick={() => openIncident(row, "overview")}>{incidentTitle(row)}</button>
              <div className="unified-card-context"><span><Server size={13} /> {row.service || "Unknown service"}</span><span>{row.environment || "Environment not set"}</span><span>{formatIstTimestamp(row.updated_at || row.created_at)}</span></div>
              {value(row.operation, row.source_alert?.labels?.operation, projectionLabels(row).operation) !== "Not recorded" ? <p className="unified-card-operation"><strong>Affected operation</strong> <code>{value(row.operation, row.source_alert?.labels?.operation, projectionLabels(row).operation)}</code></p> : null}
              <p className="unified-card-summary">{analysisBlocker(row) || value(event.customer_impact, event.business_impact, event.impact, row.summary, "No current processing detail has been published.")}</p>
              <div className="unified-card-context"><span>Source: {value(row.source, row.origin_system, row.source_alert?.source)}</span><span>Alert: {row.alert_id || "Not linked"}</span>{row.source_alert?.labels?.event_authenticity ? <span>{String(row.source_alert.labels.event_authenticity).replaceAll("_", " ")}</span> : null}</div>
              <div className="unified-card-progress"><span className="unified-progress-node"><Workflow size={14} /></span><div><small>Current stage · {authoritativeLifecycleNote(row).label}</small><strong>{currentStage?.label || "Awaiting intake"}</strong><span>{currentStage?.caption || "No executed stage recorded"} — {authoritativeLifecycleNote(row).reason}</span></div></div>
            </div>
            <aside className="unified-card-aside">
              <span className={`pill ${normalizedStatus(row) === "failed" ? "status-warning" : `status-${normalizedStatus(row)}`}`}>{incidentStatusLabel(row)}</span>
              <small className="unified-lifecycle-state" title={authoritativeLifecycleNote(row).reason}>Lifecycle: {authoritativeLifecycleNote(row).label}</small>
              <span className={`unified-attention-label ${needsHuman ? "is-urgent" : ""}`}>{normalizedStatus(row) === "waiting_for_human" ? <><FileCheck2 size={13} /> Human evidence needed</> : analysisBlocker(row) ? <><ScanSearch size={13} /> Evidence incomplete</> : needsHuman ? <><FileCheck2 size={13} /> Human decision</> : <><BrainCircuit size={13} /> Kai handling</>}</span>
              <button type="button" className="button-primary" onClick={() => openIncident(row, "overview")}>Open incident</button>
            </aside>
          </article>;
        }
        const alert = record.row;
        const alertId = String(alert.id || alert.file || index);
        const disposition = alertDisposition(alert);
        const linkedIncident = alertLinkedIncidentId(alert);
        const severity = String(alert.severity || alert.priority || "not-set").toLowerCase();
        return <article className={`unified-inbox-card is-signal severity-${severity} ${disposition.noise ? "is-muted" : ""}`} key={`signal-${alertId}`}>
          <span className="unified-card-rail" aria-hidden="true" />
          <div className={`unified-card-icon ${disposition.noise ? "is-muted" : disposition.duplicate ? "is-duplicate" : "is-signal"}`}>{disposition.noise ? <CircleSlash2 size={20} /> : disposition.duplicate ? <Copy size={20} /> : <Bell size={20} />}</div>
          <div className="unified-card-body">
            <div className="unified-card-kicker"><span>Signal</span><code>{alertId}</code></div>
            <button type="button" className="unified-card-title" onClick={() => alerts.open(alert, "overview")}>{alert.name || alert.alert_name || "Unnamed signal"}</button>
            <div className="unified-card-context"><span><Activity size={13} /> {alert.service || "Unknown service"}</span><span>{alert.origin_system || alert.source || alert.source_channel || "Unknown source"}</span><span>{formatIstTimestamp(alert.received_at || alert.created_at || alert.first_seen)}</span></div>
            <p className="unified-card-summary">{value(alert.description, alert.annotations?.description, alert.summary, alert.message, disposition.noise ? disposition.noiseReason : "A new operational signal is awaiting correlation.")}</p>
            <div className="unified-card-progress"><span className="unified-progress-node"><GitMerge size={14} /></span><div><small>Correlation outcome</small><strong>{disposition.noise ? "No incident required" : disposition.duplicate ? "Duplicate signal" : linkedIncident ? "Incident linked" : "Awaiting correlation"}</strong><span>{disposition.noise ? disposition.noiseReason : disposition.duplicate ? "Matched to an existing operational record" : linkedIncident ? linkedIncident : "Kai is evaluating impact and related activity"}</span></div></div>
          </div>
          <aside className="unified-card-aside">
            <span className="pill status-open">{String(alert.severity || alert.priority || "Severity not set")}</span>
            <span className={`alert-classification ${disposition.noise ? "is-noise" : disposition.duplicate ? "is-duplicate" : "is-unique"}`}>{disposition.noise ? "Noise" : disposition.duplicate ? "Duplicate" : "Unique signal"}</span>
            <button type="button" className="button-secondary" onClick={() => alerts.open(alert, "overview")}>Review signal</button>
          </aside>
        </article>;
      })}</div> : null}
      {showAlerts && presentation === "summary" ? <div className="incident-table-wrap"><table className="incident-summary-table alert-summary-table"><thead><tr><th>Alert</th><th>Source</th><th>Severity</th><th>Classification</th><th>Linked record</th><th>Received</th><th><span className="sr-only">Action</span></th></tr></thead><tbody>{visibleAlerts.map((alert, index) => {
        const metadata = (alert as typeof alert & { metadata?: Record<string, unknown> }).metadata || {};
        const noiseMetadata = metadata.noise && typeof metadata.noise === "object" ? metadata.noise as Record<string, unknown> : {};
        const disposition = String(alert.incident_disposition || "").toLowerCase();
        const noise = ["noise", "suppressed", "ignored", "non_actionable"].includes(disposition) || noiseMetadata.classified === true;
        const duplicate = !noise && (disposition === "duplicate" || Number(alert.deduplicated_count || 1) > 1);
        const linkedIncident = alertLinkedIncidentId(alert);
        return <tr key={String(alert.id || alert.file || index)}><td><button type="button" className="incident-table-title" onClick={() => alerts.open(alert, "overview")}>{alert.name || alert.alert_name || "Unnamed alert"}</button><code>{String(alert.id || alert.file || "No alert ID")}</code></td><td><strong>{alert.service || "Unknown service"}</strong><small>{alert.origin_system || alert.source || alert.source_channel || "Unknown source"}</small></td><td>{alert.severity || "Not set"}</td><td><span className={`alert-classification ${noise ? "is-noise" : duplicate ? "is-duplicate" : "is-unique"}`}>{noise ? "Noise" : duplicate ? "Duplicate" : "Unique"}</span></td><td>{linkedIncident || alert.ticket_id || alert.jira_key || (noise ? "No incident" : "Processing")}</td><td>{formatIstTimestamp(alert.received_at || alert.created_at || alert.first_seen)}</td><td><button type="button" className="button-secondary" onClick={() => alerts.open(alert, "overview")}>View details</button></td></tr>;
      })}</tbody></table></div> : null}
      {showAlerts && presentation !== "summary" ? visibleAlerts.map((alert, index) => {
        const metadata = (alert as typeof alert & { metadata?: Record<string, unknown> }).metadata || {};
        const noiseMetadata = metadata.noise && typeof metadata.noise === "object" ? metadata.noise as Record<string, unknown> : {};
        const disposition = String(alert.incident_disposition || "").toLowerCase();
        const noise = ["noise", "suppressed", "ignored", "non_actionable"].includes(disposition) || noiseMetadata.classified === true;
        const duplicate = !noise && (disposition === "duplicate" || Number(alert.deduplicated_count || 1) > 1);
        const noiseReason = String(noiseMetadata.reason || alert.suppression_reason || "Non-actionable monitoring noise");
        const linkedIncident = alertLinkedIncidentId(alert);
        const alertId = String(alert.id || alert.file || index);
        return <article className={`unified-alert-row ${presentation === "details" ? "is-detail" : ""}`} key={alertId}>
          <span className={`unified-record-icon ${noise ? "is-noise" : duplicate ? "is-duplicate" : ""}`}>{noise ? <CircleSlash2 size={16} /> : duplicate ? <Copy size={16} /> : <Bell size={16} />}</span>
          <div><small>Alert</small><strong>{alert.name || alert.alert_name || "Unnamed alert"}</strong><p>{alert.service || "Unknown service"} · {alert.origin_system || alert.source || alert.source_channel || "Unknown source"}</p></div>
          <span className="unified-alert-outcome">{duplicate ? "Duplicate · linked to incident" : "New incident signal"}</span>
          <ol className="alert-processing-story"><li>Ingested</li><li>Normalized</li><li>{duplicate ? "Duplicate matched" : "Unique after dedup"}</li><li>{noise ? "Noise / stopped" : linkedIncident ? "Incident created" : "Decision pending"}</li></ol>
          <span className={`unified-alert-result ${noise ? "is-noise" : ""}`} title={noise ? noiseReason : undefined}>{noise ? "Noise / no action" : duplicate ? "Linked to existing incident" : linkedIncident ? "Incident created" : "Processing"}</span>
          <button type="button" className="button-secondary" onClick={() => alerts.open(alert, "overview")}>{noise ? "View alert" : "Open summary"}</button>
          {presentation === "details" ? <section className="alert-detail-panel"><header><small>Alert details</small><strong>{noise ? "Processing stopped as noise" : duplicate ? "Merged with an existing incident" : linkedIncident ? "Incident created" : "Processing in progress"}</strong></header><dl><div><dt>Alert ID</dt><dd>{alertId}</dd></div><div><dt>Source channel</dt><dd>{value(alert.source_channel, alert.ingestion_channel, alert.origin_system, alert.source)}</dd></div><div><dt>Description</dt><dd>{value(alert.description, alert.annotations?.description, alert.summary, alert.message)}</dd></div><div><dt>First seen</dt><dd>{value(alert.first_seen, alert.received_at, alert.created_at)}</dd></div><div><dt>Occurrences</dt><dd>{value(alert.deduplicated_count, alert.occurrence_count, 1)}</dd></div><div><dt>Decision reason</dt><dd>{noise ? noiseReason : value(alert.deduplication_reason, alert.correlation_reason, duplicate ? "Fingerprint matched within deduplication window" : "Unique actionable signal")}</dd></div><div><dt>Linked incident</dt><dd>{linkedIncident || "Not created"}</dd></div><div><dt>Jira</dt><dd>{alert.ticket_id || alert.jira_key || "Pending"}</dd></div></dl></section> : null}
        </article>;
      }) : null}
      {showIncidents && presentation === "summary" ? <div className="incident-table-wrap"><table className="incident-summary-table"><thead><tr><th>Incident</th><th>Service</th><th>Status</th><th>Jira</th><th>Current stage</th><th>Updated</th><th><span className="sr-only">Action</span></th></tr></thead><tbody>{rows.map((row, index) => {
        const incidentId = String(row.incident_id || row.id || "-");
        const jiraKey = String(row.ticket_id || row.jira_key || (["closed", "resolved"].includes(normalizedStatus(row)) ? "Not linked" : "Pending"));
        const lifecycle = lifecycleFor(row);
        const currentStage = currentLifecycleStage(row, lifecycle);
        return <tr key={incidentId || index}><td data-label="Incident"><button type="button" className="incident-table-title" onClick={() => openIncident(row, "overview")}>{incidentTitle(row)}</button><code>{incidentId}</code>{row.duplicateIncidents.length ? <small>{row.duplicateIncidents.length} duplicate {row.duplicateIncidents.length === 1 ? "incident" : "incidents"} grouped</small> : null}</td><td data-label="Service"><strong>{row.service || "Unknown service"}</strong><small>{row.environment || "Environment not set"}</small></td><td data-label="Status"><span className={`pill ${normalizedStatus(row) === "failed" ? "status-warning" : `status-${normalizedStatus(row)}`}`}>{incidentStatusLabel(row)}</span><IncidentStatusExplanation blocker={analysisBlocker(row)} reason={row.status_reason || authoritativeLifecycleNote(row).reason} /></td><td data-label="Jira">{row.jira_url ? <a href={row.jira_url} target="_blank" rel="noreferrer">{jiraKey}<ExternalLink size={12} /></a> : jiraKey}</td><td data-label="Current stage"><strong>{currentStage?.label || "Not started"}</strong><small>{currentStage?.caption || "No executed stage"}</small></td><td data-label="Updated">{formatIstTimestamp(row.updated_at || row.created_at)}</td><td data-label="Action"><button type="button" className="button-secondary" onClick={() => openIncident(row, currentStage?.cockpit || "overview")}>View details</button></td></tr>;
      })}</tbody></table></div> : null}
      {showIncidents && presentation !== "summary" ? rows.map((row, index) => {
        const incidentId = String(row.incident_id || row.id || "-");
        const jiraKey = String(row.ticket_id || row.jira_key || (["closed", "resolved"].includes(normalizedStatus(row)) ? "Not linked" : "Pending"));
        const lifecycle = lifecycleFor(row);
        const disposition = incidentNoise(row);
        return <article className="incident-summary-row" key={incidentId || index}>
          <div className="incident-summary-identity">
            <div className="incident-summary-title"><button type="button" onClick={() => openIncident(row, "overview")}>{incidentTitle(row)}</button><span className={`pill ${normalizedStatus(row) === "failed" ? "status-warning" : `status-${normalizedStatus(row)}`}`}>{incidentStatusLabel(row)}</span></div>
            <div className="incident-summary-meta"><span>{row.service || "Unknown service"}</span><span>{row.environment || "Environment not set"}</span><code>{incidentId}</code>{row.jira_url ? <a href={row.jira_url} target="_blank" rel="noreferrer">{jiraKey}<ExternalLink size={12} /></a> : <strong>{jiraKey}</strong>}</div>
          </div>
          {presentation === "flow" ? <div className="incident-flow-wrap">
            <div className="incident-flow-caption"><span>Source-to-resolution trace</span><strong>{resolutionPath(row).label} · {lifecycle.length} evidenced stages</strong></div>
            <div className="incident-lifecycle" style={{ gridTemplateColumns: `repeat(${lifecycle.length}, minmax(112px, 1fr))` }} aria-label={`Lifecycle for ${incidentTitle(row)}`}>
            {lifecycle.map((stage, stageIndex) => {
              const selectable = !["pending", "stopped"].includes(stage.state);
              const StageIcon = stageIcons[stage.id as keyof typeof stageIcons] || FileCheck2;
              const domain = ["application", "signal", "prometheus"].includes(stage.id) ? "source-domain" : "kaiops-domain";
              return <button key={stage.id} type="button" className={`is-${stage.state} ${domain}`} disabled={!selectable} title={stage.state === "stopped" ? disposition.reason : stage.caption} onClick={() => { if (selectable) openIncident(row, stage.cockpit); }} aria-label={`${stage.label}: ${stage.caption}`}>
                <span className="incident-stage-node"><StageIcon size={17} strokeWidth={2} />{["complete", "reused"].includes(stage.state) ? <i><Check size={9} strokeWidth={3} /></i> : null}</span><span className="incident-stage-copy"><strong>{stage.label}</strong><small>{stage.caption}</small></span><b className="incident-stage-sequence">{String(stageIndex + 1).padStart(2, "0")}</b>
              </button>;
            })}
            </div>
          </div> : null}
        </article>;
      }) : null}
      {showUnified && !visibleUnifiedRecords.length && !unifiedLoading && !unifiedError ? <p className="empty-state unified-empty-state"><ScanSearch size={22} />No unified inbox records match this view.<small>Choose Show all incidents and alerts to clear saved filters for this application.</small></p> : null}
      {showAlerts && !visibleAlerts.length && !alerts.loading ? <p className="empty-state">No signals match this view.</p> : null}
      {showIncidents && !rows.length && !unifiedLoading && !unifiedError ? <p className="empty-state">No incidents match this view.</p> : null}
    </div>
    {!focusedIncidentId ? <footer className="table-pagination"><span>Showing {unifiedPage.rows.length ? ((page - 1) * PAGE_SIZE) + 1 : 0}-{unifiedPage.rows.length ? ((page - 1) * PAGE_SIZE) + unifiedPage.rows.length : 0} of {totalRecords}</span><div><button className="button-secondary" disabled={unifiedLoading || !unifiedPage.previous_cursor} onClick={() => {
      if (!unifiedPage.previous_cursor) return;
      setSearchParams((current) => { const next = new URLSearchParams(current); next.set("cursor", unifiedPage.previous_cursor!); next.set("page", String(Math.max(1, page - 1))); return next; });
    }}>Previous</button><span>{page} / {pages}</span><button className="button-secondary" disabled={unifiedLoading || !unifiedPage.next_cursor} onClick={() => {
      if (!unifiedPage.next_cursor) return;
      setSearchParams((current) => { const next = new URLSearchParams(current); next.set("cursor", unifiedPage.next_cursor!); next.set("page", String(page + 1)); return next; });
    }}>Next</button></div></footer> : null}
  </section>;
}
