import { useEffect } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, RefreshCw, ShieldCheck, TicketCheck } from "lucide-react";

import { useRouteRuntime } from "../../app/routeRuntime";

import { formatIstTimestamp as formatTime } from "../../utils/presentation";

export default function ClosedIncidentsRoute() {
  const { closed } = useRouteRuntime();

  useEffect(() => {
    closed.refresh();
  }, []);

  const jiraSynced = closed.rows.filter((row) => Boolean(row.ticket_id)).length;
  const automated = closed.rows.filter((row) => String(row.execution_mode || "").toLowerCase().includes("auto")).length;

  return (
    <section className="grid single-col operational-route resolution-history-workspace">
      <section className="route-insight-strip" aria-label="Resolution history summary">
        <article><CheckCircle2 aria-hidden="true" /><span><small>Closed records</small><strong>{closed.rows.length}</strong></span></article>
        <article><TicketCheck aria-hidden="true" /><span><small>Linked Jira tickets</small><strong>{jiraSynced}</strong></span></article>
        <article><ShieldCheck aria-hidden="true" /><span><small>Automated recovery</small><strong>{automated}</strong></span></article>
      </section>

      <article className="panel route-data-panel">
        <div className="panel-head">
          <div><span className="discovery-eyebrow">Verified outcomes</span><h2>Closed incident records</h2><p>Closure records across all projects in your tenant. Each incident appears separately; these records are not grouped like the inbox.</p></div>
          <button className="button-secondary" type="button" onClick={closed.refresh}><RefreshCw size={15} aria-hidden="true" /> Refresh history</button>
        </div>
        <div className="route-filter-bar" aria-label="Resolution history filters">
          <label>Risk tier<select value={closed.risk} onChange={(event) => closed.setRisk(event.target.value)}><option value="all">All risk tiers</option>{closed.riskOptions.map((option) => <option key={`risk-${option}`} value={option}>{option}</option>)}</select></label>
          <label>Execution mode<select value={closed.mode} onChange={(event) => closed.setMode(event.target.value)}><option value="all">All execution modes</option>{closed.modeOptions.map((option) => <option key={`mode-${option}`} value={option}>{option}</option>)}</select></label>
          <p role="status">Showing <strong>{closed.rows.length}</strong> matching closure{closed.rows.length === 1 ? "" : "s"}</p>
        </div>
        {closed.error ? <p className="error" role="alert">{closed.error}</p> : null}
        <div className="table-wrap">
          <table>
            <caption className="sr-only">Closed incidents matching the current filters</caption>
            <thead><tr><th>Incident</th><th>Service</th><th>Severity</th><th>Jira ticket</th><th>Jira status</th><th>Closure status</th><th>Closed at</th></tr></thead>
            <tbody>
              {closed.rows.map((row, index) => <tr key={row.incident_id || index}><td><Link to={`/incidents/${encodeURIComponent(row.incident_id || "")}`}><code>{row.incident_id || "-"}</code></Link></td><td><strong>{row.service || "-"}</strong></td><td><span className={`pill severity-${String(row.severity || "unknown").toLowerCase()}`}>{row.severity || "-"}</span></td><td>{row.ticket_id ? <a className="resolution-ticket-link" href={row.jira_link || `https://kaiops-test.atlassian.net/browse/${row.ticket_id}`} target="_blank" rel="noopener noreferrer">{row.ticket_id}<span className="sr-only"> (opens in a new tab)</span></a> : "-"}</td><td>{row.ticket_id ? <span className={`pill ${row.jira_status === "Done" ? "status-success" : "status-warning"}`}>{row.jira_status || "Not reported"}</span> : "-"}</td><td><span className={`pill status-${String(row.status || "closed").toLowerCase()}`}>{row.status || "closed"}</span></td><td>{formatTime(row.closed_at || row.updated_at)}</td></tr>)}
              {!closed.rows.length && !closed.loading ? <tr><td colSpan={7}><div className="table-empty-state"><CheckCircle2 aria-hidden="true" /><strong>No closures match these filters</strong><span>Change a filter or refresh after the next verified recovery.</span></div></td></tr> : null}
            </tbody>
          </table>
        </div>
        {closed.hasMore ? <button className="button-secondary" type="button" disabled={closed.loading} onClick={closed.loadMore}>{closed.loading ? "Loading closures..." : "Load older closures"}</button> : null}
      </article>
    </section>
  );
}
