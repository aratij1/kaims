import { parseUtcTimestamp } from "../../utils/presentation";
import { useNavigate } from "react-router-dom";
import { hasPendingDecision } from "../../domain/pendingDecision";
import { Activity, ArrowRight, Bot, CheckCircle2, CircleAlert, Clock3, FileCheck2, RefreshCw, ShieldCheck, Siren } from "lucide-react";

import { useRouteRuntime, type IncidentRow } from "../../app/routeRuntime";
import { durableIncidentId } from "../../domain/incidentNavigation";
import "./DashboardRoute.css";
import { useOpenIncident } from "../../domain/useOpenIncident";
import { isNonProductionSignal } from "../../domain/signalAuthenticity";

const terminal = (row: IncidentRow) => ["closed", "resolved", "recovered", "cancelled"].some((value) => String(row.status || "").toLowerCase().includes(value));
const incidentId = (row: IncidentRow) => durableIncidentId(row);
export function dashboardIncidentRows(rows: IncidentRow[]) {
  const unique = new Map<string, IncidentRow>();
  rows.forEach((row, index) => {
    const key = incidentId(row) || `unidentified-${index}`;
    if (!unique.has(key)) unique.set(key, row);
  });
  return [...unique.values()];
}

export function dashboardSubject(row: IncidentRow) {
  const labels = row.source_alert?.labels || row.context?.alert?.labels || row.context_snapshot?.alert?.labels || {};
  return [row.environment, row.operation || labels.operation || labels.http_route || labels.route].filter(Boolean).join(" · ");
}

export function dashboardAnalysisState(row: IncidentRow) {
  const state = String(row.status || "").toLowerCase();
  if (["collecting", "requirements_identified"].includes(state)) return "Collecting evidence";
  if (["queued", "accepted", "published"].includes(state)) return "Queued";
  const analysis = row.analysis_summary;
  if (analysis?.rca_status === "insufficient_evidence") return "More evidence needed";
  if (analysis?.rca_status === "failed" || analysis?.outcome === "failed") return "Analysis failed";
  if (analysis?.completed_at) return "Analysis recorded";

  if (["collection_blocked", "blocked"].includes(state)) return "Collection blocked";
  return "Investigation in progress";
}
const title = (row: IncidentRow) => String(row.title || row.summary || `${row.service || "Service"} incident`);
const status = (row: IncidentRow) => String(row.status || "investigating").replaceAll("_", " ");
const isCritical = (row: IncidentRow) => ["critical", "sev1", "p1"].includes(String(row.severity || "").toLowerCase());
const isFailed = (row: IncidentRow) => ["failed", "validation_failed", "rollback_failed", "manual_intervention_required"].some((value) => String(row.status || "").toLowerCase().includes(value));
export const needsDashboardApproval = hasPendingDecision;

export function dashboardKaiHandling(row: IncidentRow) {
  return !terminal(row) && ["queued", "accepted", "published", "collecting", "requirements_identified", "investigating", "analyzing", "executing", "verifying", "validating", "remediating", "resolving"].includes(String(row.status || "").toLowerCase());
}

export function dashboardAttentionRows(pending: IncidentRow[], failed: IncidentRow[], critical: IncidentRow[]) {
  const rows = new Map<string, { row: IncidentRow; action: string }>();
  const add = (row: IncidentRow, action: string) => {
    const id = incidentId(row);
    if (id && !rows.has(id)) rows.set(id, { row, action });
  };
  pending.forEach((row) => add(row, "Review decision"));
  failed.forEach((row) => add(row, "Inspect failure"));
  critical.forEach((row) => add(row, "Review critical incident"));
  return [...rows.values()];
}

export function dashboardLanes(rows: IncidentRow[]) {
  const active = dashboardIncidentRows(rows.filter((row) => !terminal(row) && !isNonProductionSignal(row)));
  const attention = dashboardAttentionRows(active.filter(needsDashboardApproval), active.filter(isFailed), []);
  const ids = new Set(attention.map(({ row }) => incidentId(row)));
  return { active, attention, investigations: active.filter((row) => !ids.has(incidentId(row))) };
}

export function timeAgo(value: unknown) {
  const date = parseUtcTimestamp(value);
  if (!date) return "Time unavailable";
  const minutes = Math.max(0, Math.round((Date.now() - date.getTime()) / 60_000));
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`;
}

export function incidentStartedAt(row: Record<string, any>) {
  return row.first_seen_at || row.started_at || row.created_at || row.source_alert?.created_at || row.context?.alert?.created_at;
}

function WorkItem({ row, onOpen, action }: { row: IncidentRow; onOpen: () => void; action: string }) {
  const available = Boolean(incidentId(row));
  return <button type="button" className="oh-work-item" onClick={onOpen} disabled={!available} title={available ? undefined : "Incident identifier unavailable"}>
    <span className={`oh-severity is-${String(row.severity || "unknown").toLowerCase()}`}>{row.severity || "Unrated"}</span>
    <span><strong>{title(row)}</strong>{dashboardSubject(row) ? <small className="oh-operation">{dashboardSubject(row)}</small> : null}<small>{incidentId(row)} · {row.service || "Service unavailable"} · First seen: {timeAgo(incidentStartedAt(row))}</small><small>{dashboardAnalysisState(row)}</small></span>
    <span className="oh-work-action">{available ? action : "Cannot open"}<ArrowRight aria-hidden="true" /></span>
  </button>;
}

export default function DashboardRoute() {
  const openIncident = useOpenIncident();
  const { dashboard, incidents, alerts, executive } = useRouteRuntime();
  const navigate = useNavigate();
  const lanes = dashboardLanes(incidents.rows);
  const active = lanes.active;
  const critical = active.filter(isCritical);
  const pending = active.filter(needsDashboardApproval);
  const testCount = incidents.rows.filter(isNonProductionSignal).length;
  const attentionRows = lanes.attention;
  const kaiHandling = lanes.investigations;
  const activeCount = active.length;
  const attentionCount = attentionRows.length;
  const kaiHandlingCount = kaiHandling.length;
  const recentlyResolved = executive.recentlyClosed.filter((row) => !isNonProductionSignal(row)).sort((left, right) => (parseUtcTimestamp(right.closed_at || right.updated_at)?.getTime() || 0) - (parseUtcTimestamp(left.closed_at || left.updated_at)?.getTime() || 0)).slice(0, 4);
  const snapshotAt = incidents.page.snapshot_at || incidents.page.generated_at;
  const snapshotDate = parseUtcTimestamp(snapshotAt);
  const snapshotLabel = snapshotDate
    ? `Updated ${snapshotDate.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`
    : "Update time unavailable";
  const pulse = [
    { label: "Recent monitoring deliveries", value: alerts.loading ? "Unavailable" : alerts?.rows?.filter((row) => !isNonProductionSignal(row)).length ?? "Unavailable", icon: Activity, open: () => navigate("/alerts") },
    { label: "Open incidents loaded", value: incidents.loading ? "Unavailable" : activeCount, icon: Activity, open: () => dashboard.openSection("summary") },
    { label: "Critical incidents loaded", value: incidents.loading ? "Unavailable" : critical.length, icon: Siren, open: () => dashboard.openSection("summary") },
    { label: "Pending decisions", value: incidents.loading ? "Unavailable" : pending.length, icon: FileCheck2, open: () => dashboard.openSection("approval") },
  ];

  return <section className="operations-home">
    {testCount ? <p className="oh-truth">{testCount} demo or test incident(s) excluded from operational counts. Their history remains in the incident inbox.</p> : null}
    {incidents.error ? <div className="oh-truth" role="alert"><CircleAlert aria-hidden="true" /><span><strong>Live refresh failed. Showing the last successful results.</strong> {snapshotLabel}. <button type="button" onClick={() => dashboard.refreshProjects()}>Retry refresh</button></span></div> : null}
    <header className={`oh-status ${attentionCount ? "needs-attention" : "is-clear"}`}>
      <div className="oh-status-icon">{attentionCount ? <CircleAlert aria-hidden="true" /> : <ShieldCheck aria-hidden="true" />}</div>
      <div><span>Operational overview · current project</span><h2>{incidents.loading ? "Updating operational state" : attentionCount ? `${attentionCount} item${attentionCount === 1 ? "" : "s"} need attention` : "No active attention items"}</h2><p>{attentionCount ? "Pending decisions and failed actions require review. Other open investigations are listed separately." : `Open incident records can outlive the firing signal in the loaded ${dashboard.selectedProject || "project"} scope.`}</p></div>
      <div className="oh-scope"><span>Project: <strong>{dashboard.selectedProject}</strong></span><small aria-live="polite">{incidents.loading ? "Updating live data..." : snapshotLabel}</small><button type="button" disabled={incidents.loading} onClick={() => dashboard.refreshProjects()}><RefreshCw aria-hidden="true" /> {incidents.loading ? "Updating..." : "Refresh"}</button></div>
    </header>

    <section className="oh-pulse" aria-label="Operations pulse"><header><span>Operations pulse</span><small>Every metric opens its operational source</small></header><div>{pulse.map((metric) => { const Icon = metric.icon; return <button type="button" key={metric.label} onClick={metric.open}><Icon aria-hidden="true" /><span>{metric.label}</span><strong>{metric.value}</strong></button>; })}</div></section>

    <div className="oh-attention-grid">
      <section className="oh-lane needs-you"><header><div><FileCheck2 aria-hidden="true" /><span><small>Needs you</small><strong>Pending decisions and failed actions</strong></span></div><em>{attentionCount}</em></header><div>{attentionRows.slice(0, 7).map(({ row, action }) => <WorkItem key={`attention-${incidentId(row)}`} row={row} action={action} onOpen={() => openIncident(row)} />)}{!attentionCount ? <div className="oh-empty"><CheckCircle2 aria-hidden="true" /><span><strong>Nothing needs your decision</strong><small>No pending approvals or failed actions were returned in the loaded scope.</small></span></div> : null}</div>{attentionCount ? <button type="button" className="oh-lane-link" onClick={() => dashboard.openSection("approval")}>Open attention queue <ArrowRight aria-hidden="true" /></button> : null}</section>
      <section className="oh-lane kai-handling"><header><div><Bot aria-hidden="true" /><span><small>Open investigations</small><strong>Recorded incidents awaiting resolution</strong></span></div><em>{kaiHandlingCount}</em></header><div>{kaiHandling.slice(0, 6).map((row) => <WorkItem key={`kai-${incidentId(row)}`} row={row} action={status(row)} onOpen={() => openIncident(row)} />)}{!kaiHandlingCount ? <div className="oh-empty"><Bot aria-hidden="true" /><span><strong>No other open incidents in this project view</strong><small>Open incident records and currently executing jobs are different counts.</small></span></div> : null}</div>{activeCount ? <button type="button" className="oh-lane-link" onClick={() => dashboard.openSection("summary")}>Open incident inbox <ArrowRight aria-hidden="true" /></button> : null}</section>
    </div>

    <section className="oh-resolved"><header><div><CheckCircle2 aria-hidden="true" /><span><small>Recent closures</small><h3>Recorded closures from incident history</h3></span></div><button type="button" onClick={() => dashboard.openSection("closed")}>View history <ArrowRight aria-hidden="true" /></button></header>{recentlyResolved.length ? <div>{recentlyResolved.map((row) => <button type="button" key={`resolved-${incidentId(row)}`} onClick={() => openIncident(row)}><span className="oh-resolved-check"><Clock3 aria-hidden="true" /></span><span><strong>{title(row)}</strong><small>{incidentId(row)} · {row.service || "Service unavailable"}</small></span><span><strong>{String(!row.execution_mode || row.execution_mode === "unknown" ? "Closure recorded" : row.execution_mode).replaceAll("_", " ")}</strong><small>{timeAgo(row.closed_at || row.updated_at)}</small></span><ArrowRight aria-hidden="true" /></button>)}</div> : <div className="oh-empty"><CheckCircle2 aria-hidden="true" /><span><strong>No recent closures returned</strong><small>Closed records do not by themselves establish verified recovery.</small></span></div>}</section>

    <details className="oh-capacity"><summary><Clock3 size={16} aria-hidden="true" />Processing & collection capacity<span>Queue counts and retry status</span></summary>
    <section className="oh-truth" aria-label="Alert processing capacity" role="status">
      <Clock3 aria-hidden="true" /><span><strong>Platform queues: Alert analysis: maximum {dashboard.processing?.alert_processing?.limit || 50} concurrent jobs.</strong>{" "}
      {dashboard.processing?.alert_processing?.status === "available" ? `${dashboard.processing.alert_processing.active} processing` : dashboard.processing?.alert_processing?.status === "unavailable" ? "Processing paused: capacity service unavailable" : "Processing count unavailable"}
      {typeof dashboard.processing?.analysis_backlog_ready === "number" && dashboard.processing?.alert_processing?.status === "available" ? ` | ${dashboard.processing.analysis_backlog_ready + (dashboard.processing.alert_processing.waiting || 0)} queued deliveries` : " | Backlog count unavailable"}.
      {" "}{dashboard.processing?.evidence_collection?.status === "available"
        ? `Evidence jobs: ${dashboard.processing.evidence_collection.scheduled || 0} queued, ${dashboard.processing.evidence_collection.retry || 0} awaiting retry, ${dashboard.processing.evidence_collection.collecting || 0} collecting.`
        : "Evidence job counts unavailable."}
      {" "}Queued work waits for capacity and resumes automatically. One alert may produce several jobs. Recent deliveries and open incidents cover different time windows. Incident lanes do not count running workers.</span>
    </section>
    </details>

    <footer className="oh-truth"><ShieldCheck aria-hidden="true" /><span><strong>Observed data only.</strong> Counts and states come from the current API responses; unavailable KPIs are shown as unavailable.</span></footer>
  </section>;
}
