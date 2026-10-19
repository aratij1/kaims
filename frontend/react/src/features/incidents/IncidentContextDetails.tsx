import { useState } from "react";

const asRecord = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
export const hasContextData = (value: unknown): boolean => {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") return value.trim().length > 0;
  if (Array.isArray(value)) return value.some(hasContextData);
  if (typeof value === "object") return Object.values(value).some(hasContextData);
  return true; // Zero measurements and false observations are real data.
};

const sourceAliases: Record<string, string[]> = {
  recent_changes: ["changes"], dependency_services: ["dependency", "topology"],
  related_incidents: ["related_incidents"], runbook: ["runbooks", "runbook"],
  deployment: ["deployment"], logs: ["logs", "log"], telemetry: ["telemetry"],
};

export function emptySourceStatus(key: string, context: Record<string, unknown>): string {
  const metadata = asRecord(context.metadata);
  const category = key.replace(/_evidence$/, "");
  const aliases = [category, ...(sourceAliases[category] || [])];
  const sources = asRecord(metadata.context_sources);
  const recorded = aliases.map(name => asRecord(sources[name])).find(value => Object.keys(value).length > 0);
  const report = asRecord(metadata.discovery_report);
  const stages = Array.isArray(report.retrieval_stages) ? report.retrieval_stages : [];
  const stage = stages.map(asRecord).find(value => aliases.some(name => value.stage === `${name}_search`));
  const details = recorded || stage || {};
  const status = String(details.collection_status || details.status || "").toLowerCase();
  if (["error", "failed", "timeout", "timed_out"].includes(status) || details.error) return "Collection failed; review the recorded error";
  if (["not_configured", "configuration_required", "unavailable"].includes(status)) return "Source unavailable or configuration required";
  if (["running", "queued", "pending", "collecting"].includes(status)) return "Collection pending or in progress";
  if (status === "skipped") return "Skipped by collection policy";
  if (details.attempted === false) return "Not attempted";
  if (status === "no_matches" || (["completed", "collected"].includes(status) && Number(details.result_count) === 0)) return "Search completed with no matching records";
  return "No collection outcome recorded";
}

const identityFields = new Set(["id", "incident_id", "tenant_id", "created_at", "trace_id"]);
export function contextSources(context: Record<string, unknown>, source: Record<string, unknown>, snapshot: Record<string, unknown>) {
  const metadata = asRecord(context.metadata);
  const buckets = { ...asRecord(metadata.context_evidence), ...asRecord(context.context_evidence) };
  // Old snapshots are immutable. Retain alert copies for audit, but never
  // present them as independent application logs.
  const ingestionArtifacts: unknown[] = [];
  const candidates: [string, unknown][] = Object.entries(buckets).map(([key, value]) => {
    if (["logs", "log"].includes(key) && Array.isArray(value)) {
      value = value.filter(row => {
        const record = asRecord(row);
        const artifact = ["uri", "path", "source_uri", "source_reference", "citation"].some(field => {
          let reference = String(record[field] || "");
          try { reference = decodeURIComponent(reference); } catch { /* Retain malformed references as recorded. */ }
          return /(?:^|[\\/])(?:landing|ingested_alerts)(?:[\\/]|$)/i.test(reference);
        });
        if (artifact) ingestionArtifacts.push(row);
        return !artifact;
      });
    }
    return [`${key}_evidence`, value];
  });
  if (ingestionArtifacts.length) candidates.push(["alert_ingestion_artifacts", ingestionArtifacts]);
  candidates.push(...Object.entries(context).filter(([key]) => !identityFields.has(key) && !["metadata", "context_evidence"].includes(key)));
  if (!hasContextData(context.alert) && hasContextData(source)) {
    const index = candidates.findIndex(([key]) => key === "alert");
    if (index >= 0) candidates.splice(index, 1);
    candidates.push(["alert", source]);
  }
  for (const key of ["discovery_report", "context_sources", "context_missing_sections"]) {
    if (hasContextData(metadata[key])) candidates.push([key, metadata[key]]);
  }
  const remainingMetadata = Object.fromEntries(Object.entries(metadata).filter(([key]) => key !== "context_evidence"));
  if (hasContextData(remainingMetadata)) candidates.push(["metadata", remainingMetadata]);
  const identity = Object.fromEntries(Object.entries(context).filter(([key]) => identityFields.has(key)));
  if (hasContextData(identity)) candidates.push(["record_details", identity]);
  if (hasContextData(snapshot)) candidates.push(["snapshot_record", snapshot]);
  const available = candidates.filter(([, value]) => hasContextData(value));
  const availableKeys = new Set(available.map(([key]) => key));
  const unavailable = candidates.filter(([key, value]) => !hasContextData(value)
    && !(sourceAliases[key] || []).some(alias => availableKeys.has(`${alias}_evidence`)))
    .map(([key]) => key);
  return { available, unavailable };

}

const label = (key: string) => key.replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase());

// Mount only the selected source and a bounded page of records. Large trace and
// log collections must not turn opening an incident into thousands of DOM rows.
function ContextValue({ value, depth = 0 }: { value: unknown; depth?: number }) {
  const [page, setPage] = useState(0);
  if (value === null || value === undefined || value === "") return <p>Not recorded</p>;
  if (Array.isArray(value)) {
    const current = Math.min(page, Math.max(0, Math.ceil(value.length / 10) - 1));
    return <div>
      {!value.length ? <p>No records collected for this source.</p> : <ol start={current * 10 + 1}>{value.slice(current * 10, current * 10 + 10).map((item, index) => <li key={`${current}-${index}`}><ContextValue value={item} depth={depth + 1} /></li>)}</ol>}
      {value.length > 10 && <nav aria-label="Context record pages" className="ic-evidence-pagination"><button disabled={!current} onClick={() => setPage(current - 1)}>Previous records</button><span>{current * 10 + 1}–{Math.min(current * 10 + 10, value.length)} of {value.length}</span><button disabled={(current + 1) * 10 >= value.length} onClick={() => setPage(current + 1)}>Next records</button></nav>}
    </div>;
  }
  if (typeof value === "object") {
    if (depth > 5) return <pre>{JSON.stringify(value, null, 2)}</pre>;
    const entries = Object.entries(value);
    if (!entries.length) return <p>No fields recorded.</p>;
    return <dl>{entries.map(([key, item]) => <div key={key}><dt>{label(key)}</dt><dd>{typeof item === "object" && item !== null ? <details><summary>View {label(key).toLowerCase()}{Array.isArray(item) ? ` (${item.length})` : ""}</summary><ContextValue value={item} depth={depth + 1} /></details> : <ContextValue value={item} depth={depth + 1} />}</dd></div>)}</dl>;
  }
  return <p>{String(value)}</p>;
}

export function IncidentContextDetails({ context, source, snapshot }: { context: Record<string, unknown>; source: Record<string, unknown>; snapshot: Record<string, unknown> }) {
  const [selected, setSelected] = useState("");
  const { available: entries, unavailable } = contextSources(context, source, snapshot);
  const active = entries.find(([key]) => key === selected)
    || entries.find(([key]) => ["logs_evidence", "traces_evidence", "metrics_evidence", "observability", "logs", "telemetry"].includes(key))
    || entries.find(([key]) => key === "alert") || entries[0];
  return <section id="incident-detailed-context" className="ic-section ic-detailed-context" aria-label="Detailed context">
    <header><div><span>Collected investigation data</span><h3>Detailed context</h3></div><span>{entries.length} available sections</span></header>
    <p>Inspect the recorded source data below. RCA and impact assessments are shown in the investigation sections; collected data alone does not confirm a cause.</p>
    {entries.some(([key]) => key === "alert_ingestion_artifacts") && <p>Alert ingestion artifacts are retained for audit and are not application logs or independent RCA evidence.</p>}
    {unavailable.length > 0 && <details className="ic-context-unavailable"><summary>Collection status for {unavailable.length} sections without records</summary><dl>{unavailable.map(key => <div key={key}><dt>{label(key)}</dt><dd>{emptySourceStatus(key, context)}</dd></div>)}</dl></details>}
    {active ? <><label>Context section<select value={active[0]} onChange={event => setSelected(event.target.value)}>{entries.map(([key, value]) => <option key={key} value={key}>{label(key)}{Array.isArray(value) ? ` (${value.length} records)` : ""}</option>)}</select></label><div className="ic-context-content"><h4>{label(active[0])}</h4><ContextValue key={active[0]} value={active[1]} /></div></> : <p>No detailed context has been returned for this incident. Review the collection status and missing evidence below.</p>}
  </section>;
}
