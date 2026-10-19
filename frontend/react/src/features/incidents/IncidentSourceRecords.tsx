import { useEffect, useState } from "react";
import { IncidentCommandWorkspaceSchema } from "../../schemas/apiContracts";
import { requestValidated } from "../../services/apiClient";
import { IncidentContextDetails } from "./IncidentContextDetails";

const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};

// Keep multi-megabyte source reports and their DOM off the opening path.
export function IncidentSourceRecords({ incidentId, accessToken, revision }: { incidentId: string; accessToken?: string; revision?: string }) {
  const [open, setOpen] = useState(false);
  const [row, setRow] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => { setRow(null); setError(""); }, [revision]);
  useEffect(() => {
    if (!open || row) return;
    const controller = new AbortController();
    void requestValidated(
      `/api-gateway/incidents/${encodeURIComponent(incidentId)}/command`,
      IncidentCommandWorkspaceSchema,
      { signal: controller.signal, timeoutMs: 45_000,
        headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {} },
    ).then(workspace => {
      if (controller.signal.aborted) return;
      if (workspace.incident_id.toLowerCase() !== incidentId.toLowerCase()) {
        throw new Error("Source records do not match the requested incident.");
      }
      setRow(record(workspace.incident));
    }).catch(reason => {
      if (!controller.signal.aborted) setError(String(reason.message || reason));
    });
    return () => controller.abort();
  }, [open, row, incidentId, accessToken, attempt, revision]);

  return <details className="ic-disclosure ic-raw-context" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>Collected source records<span>Browse logs, metrics, traces and source data</span></summary>
    {open && (row ? <IncidentContextDetails context={record(row.context)} source={record(row.source_alert)} snapshot={record(row.context_snapshot)} />
      : error ? <div role="alert">{error} <button onClick={() => { setError(""); setAttempt(value => value + 1); }}>Retry source records</button></div>
        : <p role="status">Loading collected source records…</p>)}
  </details>;
}
