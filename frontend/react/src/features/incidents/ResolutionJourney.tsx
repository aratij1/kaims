import { Check, ChevronRight, Clock3, X } from "lucide-react";
import "./ResolutionJourney.css";

export function collectionDisplayStatus(status: string, phase: string) {
  if (status.toLowerCase() !== "collecting") return status.toLowerCase();
  if (phase === "queued") return "queued_for_evidence";
  if (phase === "retry_wait") return "waiting_to_retry_evidence";
  return "collecting";
}

export function journeyIndexForStatus(status: string, hasRootCause = false) {
  const value = status.toLowerCase();
  if (["closed", "resolved", "recovered", "cancelled"].includes(value)) return 6;
  if (/validat|verif/.test(value)) return 5;
  if (/execut|remediat|rollback/.test(value) || value === "approved") return 4;
  if (/approval|resolution/.test(value)) return 3;
  if (["rca_ready", "root_cause_confirmed", "conclusive"].includes(value)) return 2;
  if (/context|requirement|investigat|understand|analy|human|collect|evidence/.test(value)) return 1;
  return hasRootCause ? 2 : 0;
}

type Requirement = Record<string, unknown>;
type Props = {
  status: string; phase: string; grounded: boolean; resolutionReady: boolean;
  executionStatus: string; recoveryVerified: boolean; observedRecovery: boolean;
  rcaStatus?: string; rcaVersion?: number; resolutionStatus?: string; validationStatus?: string;
  message?: string; requirements?: Requirement[]; updatedAt?: string;
};
const rec = (value: unknown): Requirement => value && typeof value === "object" ? value as Requirement : {};
const label = (value: unknown) => typeof value === "string" ? value.replaceAll("_", " ") : "";

export default function ResolutionJourney(props: Props) {
  const status = props.status.toLowerCase();
  const terminal = ["closed", "resolved", "recovered", "cancelled"].includes(status);
  const waiting = /human|approval|queued|retry/.test(collectionDisplayStatus(status, props.phase));
  const failed = /failed|blocked|manual_intervention/.test(status);
  let current = journeyIndexForStatus(status, props.grounded);
  if (status === "failed" || status === "manual_intervention_required") {
    current = /failed/.test(props.executionStatus) ? 4 : 1;
  }
  const stages = props.observedRecovery
    ? ["Detected", "Recovery observed", "Independently verified", "Closed"]
    : terminal && !props.recoveryVerified
      ? ["Detected", status === "cancelled" ? "Cancelled" : "Closure recorded"]
      : ["Detected", "Understanding", "Root cause", "Resolution", "Executing", "Verifying", "Recovered"];
  if (terminal) current = stages.length - 1;
  const completed = props.observedRecovery ? stages.map(() => true)
    : terminal && !props.recoveryVerified ? [true, false]
      : [true, props.grounded, props.grounded, props.resolutionReady,
        props.executionStatus === "succeeded", props.recoveryVerified, props.recoveryVerified];
  const human = /human/.test(status);
  const rcaStatus = (props.rcaStatus || "").toLowerCase();
  const rcaRecorded = Number(props.rcaVersion) > 0 && rcaStatus !== "not_started";
  const humanRequests = terminal ? [] : (props.requirements || []).filter(requirement =>
    !["collected", "answered", "satisfied", "cancelled"].includes(String(requirement.status).toLowerCase())
    && Object.keys(rec(requirement.active_human_request)).length > 0);
  const title = status === "cancelled" ? "Incident cancelled"
    : terminal ? props.recoveryVerified ? "Recovery verified" : "Closed — recovery not verified"
      : human ? "Human evidence needed"
        : status === "collection_blocked" ? "Evidence collection blocked"
          : status === "collecting" && props.phase === "queued" ? "Evidence collection queued"
            : status === "collecting" && props.phase === "retry_wait" ? "Evidence collection awaiting retry"
              : label(status);
  return <section className="ic-journey" aria-label="Kai resolution journey">
    <header><div><span>Resolution journey</span><h3>From signal to verified recovery</h3></div><small>Recorded activity and confirmed outcomes</small></header>
    <div className={`rj-status ${failed ? "is-blocked" : waiting ? "is-waiting" : ""}`} role="status">
      <strong>{title}</strong>
      <p>{terminal ? props.recoveryVerified ? "Recovery checks have passed." : "The record is no longer active. Verified recovery has not been recorded."
        : human && (!props.message || props.message.includes("waiting for assigned human evidence"))
          ? "The investigation needs human-supplied evidence. Review the request and recorded owner below."
          : props.message || "The next action has not been recorded."}</p>
      {human && props.phase === "collecting" ? <p>Automated evidence collection is also running.</p> : null}
      {humanRequests.length ? <><h4>Outstanding human evidence requests</h4><ul>{humanRequests.slice(0, 3).map((requirement, index) => {
        const request = rec(requirement.active_human_request);
        return <li key={String(requirement.requirement_id || index)}>
          <span>{String(requirement.question || request.requested_evidence || requirement.description || requirement.reason || requirement.category || "Requested evidence")}</span>
          <small>Owner: {request.status === "assignment_blocked" ? "Assignment blocked" : String(request.expected_responder || request.assignee_id || requirement.assigned_to || "Not assigned")}</small>
        </li>;
      })}</ul></> : human ? <p>Open Detailed context to review the outstanding evidence request and assignment.</p> : null}
      {humanRequests.length > 3 ? <small>{humanRequests.length - 3} more requests in Detailed context.</small> : null}
      {human || status === "collection_blocked" ? <a href="#incident-detailed-context">Review evidence requests</a> : null}
      {props.updatedAt ? <small>Record updated: {props.updatedAt}</small> : null}
    </div>
    <ol>{stages.map((stage, index) => {
      const complete = Boolean(completed[index]) && (index < current || terminal && props.recoveryVerified);
      const active = index === current && !complete;
      const assessed = stage === "Root cause" && rcaRecorded && !props.grounded;
      const planBlocked = stage === "Resolution" && props.resolutionStatus === "blocked";
      const state = complete ? "is-complete" : assessed || planBlocked ? "is-assessed" : active ? terminal ? "is-recorded" : failed ? "is-failed" : waiting ? "is-waiting" : "is-current" : "is-pending";
      let stateLabel = complete ? "Confirmed" : active ? terminal ? "Recorded" : failed ? "Blocked" : waiting ? "Waiting" : "Current" : index < current ? "Not confirmed" : "Not started";
      if (assessed) stateLabel = ["running", "in_progress", "investigating"].includes(rcaStatus) ? "Analysis in progress" : /failed|error/.test(rcaStatus) ? "Analysis failed" : "Assessed; needs evidence";
      if (planBlocked && !complete) stateLabel = "Blocked by prerequisites";
      if (stage === "Executing" && props.executionStatus === "not_started") stateLabel = "Not executed";
      if (stage === "Executing" && props.executionStatus && props.executionStatus !== "not_started" && !complete) stateLabel = `Execution ${label(props.executionStatus)}`;
      if (stage === "Verifying" && props.validationStatus && props.validationStatus !== "not_started" && !props.recoveryVerified) stateLabel = /failed|error/.test(props.validationStatus) ? "Verification failed" : /running|progress/.test(props.validationStatus) ? "Verification running" : "Report recorded; unverified";
      if (stage === "Recovered" && !props.recoveryVerified) stateLabel = "Not verified";
      if (active && stage === "Understanding" && waiting) stateLabel = human ? "Human evidence needed" : props.phase === "queued" ? "Evidence queued" : props.phase === "retry_wait" ? "Retry scheduled" : "Waiting for evidence";
      return <li key={stage} className={state} aria-current={active ? "step" : undefined}>
        <i aria-hidden="true">{complete ? <Check /> : active && failed ? <X /> : active && waiting ? <Clock3 /> : index + 1}</i>
        <span>{stage}<small>{stateLabel}</small></span>{index < stages.length - 1 ? <ChevronRight aria-hidden="true" /> : null}
      </li>;
    })}</ol>
    {!terminal && rcaRecorded && !props.grounded ? <p className="rj-assessment-note">RCA v{props.rcaVersion}: {/[\s_]?progress|running|investigating/.test(rcaStatus) ? "analysis is in progress" : "an assessment is recorded, but the cause is not confirmed"}. Further evidence is required before the cause can be confirmed.</p> : null}
  </section>;
}
