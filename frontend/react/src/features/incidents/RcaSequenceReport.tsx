import { formatIstTimestamp } from "../../utils/presentation";
import {currentRecoveryVerified} from "./CurrentRecovery";
type Data = Record<string, unknown>;
const record = (value: unknown): Data => value && typeof value === "object" && !Array.isArray(value) ? value as Data : {};
const string = (value: unknown) => typeof value === "string" ? value : "";

export function eventSummary(value: unknown): string {
  const raw = string(value);
  try {
    const parsed = record(JSON.parse(raw));
    const service = string(parsed.runtime_service) || string(parsed.service);
    if (service && typeof parsed.state === "string") return `${service}: ${parsed.state}`;
    const metric = record(parsed.metric);
    if (typeof metric.__name__ === "string" && Array.isArray(parsed.value)) {
      return `${metric.__name__}: ${String(parsed.value[1] ?? "Not recorded")}`;
    }
  } catch { /* Plain-text source observations are already readable. */ }
  return raw;
}

export function RcaSequenceReport({ rca, resolution, execution, validation, confirmed, observation = {} }: {
  rca: Data; resolution: Data; execution: Data; validation: Data; confirmed: boolean; observation?: Data;
}) {
  const timeline = record(rca.timeline);
  const events = Array.isArray(timeline.events) ? timeline.events.map(record) : [];
  const chain = Array.isArray(rca.causal_chain) ? rca.causal_chain.filter((item) => typeof item === "string") : [];
  const verified = validation.health_restored === true && validation.alerts_cleared === true
    && Boolean(validation.report_id && validation.validation_checksum);
  const blockers = Array.isArray(resolution.blocking_reasons) ? resolution.blocking_reasons.filter((item) => typeof item === "string") : [];
  return <div className="ic-context-findings">
    <h4>Sequence of events</h4>
    <p>{confirmed && timeline.causal_sequence_recorded === true ? "Evidence-backed causal sequence." : confirmed ? "The cause is supported. Complete event ordering is not confirmed; the timeline records source observations." : "Recorded observations and hypotheses; the causal sequence has not been established."}</p>
    {events.length ? <ol>{events.map((event, index) => <li key={index}>
      <strong>{event.occurred_at ? formatIstTimestamp(event.occurred_at) : "Event time not recorded"}</strong>
      <p>{eventSummary(event.event)}</p>
      {eventSummary(event.event) !== string(event.event) ? <details><summary>Source payload</summary><pre>{string(event.event)}</pre></details> : null}
      <small>{string(event.causal_role)} · Sources: {Array.isArray(event.evidence_ids) ? event.evidence_ids.filter((id) => typeof id === "string").join(", ") : "Unavailable"}</small>
    </li>)}</ol> : <p>No attributable event sequence is recorded. Collect source observations for the incident window.</p>}
    <p>Times reflect source observations. Collection time does not establish when the failure occurred.</p>
    <h4>How the failure developed</h4>
    {chain.length ? <><p>{confirmed ? "Recorded causal explanation" : "Unconfirmed causal explanation"}</p><ol>{chain.map((step, index) => <li key={index}>{step}</li>)}</ol></> : <p>The trigger, failure mechanism and propagation have not been established.</p>}
    <h4>Proposed remedy</h4>
    <p>{string(resolution.proposed_remedy) || "No evidence-backed remedy has been recorded."}</p>
    <p>{resolution.status === "ready" ? "A governed resolution plan is available; execution and recovery are recorded separately." : "Execution is gated until the required evidence and plan checks pass."}</p>
    {blockers.length ? <p>Pending checks: {blockers.join(", ")}</p> : null}
    <h4>Resolution outcome</h4>
    <p>{verified ? "Recovery verified by the recorded validation report." : currentRecoveryVerified(observation) ? "Current health independently verified. Causal diagnosis and incident closure remain separate." : validation.closure_kind ? "Closure was recorded without verified recovery proof." : "Recovery has not been verified."}</p>
    <p>Recorded execution: {string(execution.status) || "Not recorded"}</p>
    {verified ? <p>Validation report: {string(validation.report_id)}</p> : null}
  </div>;
}
