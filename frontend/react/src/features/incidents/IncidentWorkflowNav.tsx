import { useEffect, useState } from "react";
import { CheckCircle2, RefreshCw } from "lucide-react";
import "./IncidentWorkflowNav.css";

type Stage = "orient" | "evidence" | "resolve" | "validate";
type Props = {
  incidentId: string; status: string; evidenceCount: number; grounded: boolean;
  approvalPending: boolean; executionStatus: string; recoveryVerified: boolean;
  impactEstablished?: boolean; resolutionReady?: boolean; openRequirements?: number;
  blockers?: string[]; target?: string; risk?: string;
  onRefresh: () => Promise<void>;
};

export default function IncidentWorkflowNav(props: Props) {
  const terminal = ["closed", "resolved", "recovered", "cancelled"].includes(props.status);
  const executionRecorded = Boolean(props.executionStatus && props.executionStatus !== "not_started");
  const suggested: Stage = terminal || /validat|verif/.test(props.status) ? "validate"
    : /execut|approv|remediat/.test(props.status) ? "resolve" : "evidence";
  const [active, setActive] = useState<Stage>(suggested);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState("");
  useEffect(() => setActive(suggested), [props.incidentId, suggested]);
  const steps: Array<{ id: Stage; label: string; description: string; state: string; complete: boolean; target: string }> = [
    { id: "orient", label: "Orient", description: "Identity and lifecycle", state: "Recorded", complete: true, target: ".ic-command-header" },
    { id: "evidence", label: "Evidence & Understanding", description: `${props.evidenceCount} records; review cause and impact`, state: props.grounded ? "Cause supported" : "Review evidence", complete: props.grounded, target: "#incident-detailed-context" },
    { id: "resolve", label: "Resolve", description: terminal ? "Review recorded disposition" : props.approvalPending ? "Waiting for approval" : props.executionStatus !== "not_started" && props.executionStatus ? props.executionStatus.replaceAll("_", " ") : "Review governed resolution",
      state: terminal ? "Recorded outcome" : props.executionStatus === "succeeded" ? "Executed" : props.approvalPending ? "Decision needed" : props.resolutionReady ? "Plan ready" : "Prerequisites needed",
      complete: props.executionStatus === "succeeded", target: terminal ? ".ic-validation, .ic-observed-recovery" : ".ic-resolution" },
    { id: "validate", label: "Validate", description: props.recoveryVerified ? "Recovery verified" : terminal ? "Closed · review recovery evidence" : "Audit and recovery", state: props.recoveryVerified ? "Verified" : "Not verified", complete: props.recoveryVerified, target: ".ic-validation, .ic-observed-recovery" },
  ];
  const openSection = (selector: string) => {
    document.querySelector<HTMLDetailsElement>(".ic-investigation-history")?.setAttribute("open", "");
    const target = document.querySelector<HTMLElement>(selector)
      || (selector === "#incident-detailed-context" ? document.querySelector<HTMLElement>(".ic-raw-context") : null);
    if (target instanceof HTMLDetailsElement) target.open = true;
    let ancestor = target?.parentElement;
    while (ancestor) { if (ancestor instanceof HTMLDetailsElement) ancestor.open = true; ancestor = ancestor.parentElement; }
    target?.scrollIntoView?.({ behavior: "smooth", block: "start" });
    if (target) { target.setAttribute("tabindex", "-1"); target.focus({ preventScroll: true }); }
  };
  return <div className="incident-workflow">
    <nav className="incident-workflow-nav" aria-label="Incident workflow">
      {steps.map((step, index) => <button key={step.id} type="button" aria-current={active === step.id ? "step" : undefined}
        className={active === step.id ? "is-active" : ""} onClick={() => {
          setActive(step.id);
          if (step.id !== "evidence" && step.id !== "resolve") openSection(step.target);
        }}><span className={step.complete ? "is-complete" : ""}>{step.complete ? <CheckCircle2 aria-hidden="true" /> : String(index + 1).padStart(2, "0")}</span>
        <strong>{step.label}</strong><small>{step.description}</small><em className={step.complete ? "task-confirmed" : "task-pending"}>{step.state}</em></button>)}
    </nav>
    {active === "evidence" ? <section className="workflow-task-summary" aria-label="Evidence review summary">
      <div><span className="workflow-task-eyebrow">Evidence & understanding</span><h3>Build a supported explanation</h3>
        <p>Check the collected context, test the cause, and assess the impact before choosing a remedy.</p></div>
      <dl><div><dt>Collected records</dt><dd>{props.evidenceCount}</dd></div><div><dt>Root cause</dt><dd>{props.grounded ? "Supported by evidence" : "Not established"}</dd></div><div><dt>Customer impact</dt><dd>{props.impactEstablished ? "Established" : "Not established"}</dd></div>
        {props.openRequirements !== undefined && !terminal ? <div><dt>Open evidence questions</dt><dd>{props.openRequirements}</dd></div> : null}</dl>
      <div className="workflow-task-actions"><button type="button" onClick={() => openSection("#incident-detailed-context")}>Review collected context</button><button type="button" onClick={() => openSection("#incident-rca")}>Read root cause analysis</button><button type="button" onClick={() => openSection("#incident-impact")}>Assess impact</button></div>
    </section> : active === "resolve" ? <section className="workflow-task-summary" aria-label="Resolution review summary">
      <div><span className="workflow-task-eyebrow">Resolution review</span><h3>{terminal ? "Review the recorded outcome" : executionRecorded ? "Review recorded execution" : props.resolutionReady ? "Review the proposed remedy" : "Complete resolution prerequisites"}</h3>
        <p>{terminal ? "Review the recorded action and its recovery evidence." : executionRecorded ? "Inspect the recorded execution and validation results before planning a follow-up change." : props.resolutionReady ? "Check the target, risk, approval and rollback before any change is executed." : "A resolution plan becomes actionable after its evidence and safety requirements are satisfied."}</p></div>
      <dl><div><dt>Root cause</dt><dd>{props.grounded ? "Supported by evidence" : "Required"}</dd></div><div><dt>Execution plan</dt><dd>{props.resolutionReady ? "Ready for review" : terminal || executionRecorded ? "Review record" : "Not ready"}</dd></div><div><dt>Target</dt><dd>{props.target || "Not bound"}</dd></div><div><dt>Risk</dt><dd>{props.risk || "Not recorded"}</dd></div></dl>
      {!terminal && !executionRecorded && Boolean(props.blockers?.length) ? <details><summary>View {props.blockers!.length} recorded prerequisites</summary><ul>{props.blockers!.map(reason => <li key={reason}>{reason.replaceAll("_", " ")}</li>)}</ul></details> : null}
      <div className="workflow-task-actions"><button type="button" onClick={() => openSection(terminal || executionRecorded ? ".ic-validation, .ic-observed-recovery" : ".ic-resolution")}>{terminal ? "Review recovery evidence" : executionRecorded ? "Review execution and validation" : props.approvalPending ? "Review plan and approval" : "Review resolution details"}</button><button type="button" onClick={() => { setActive("evidence"); }}>Review evidence</button></div>
      <p className="workflow-task-note">Opening a review does not approve or execute a change.</p>
    </section> : null}
    <div className="incident-workflow-refresh"><button type="button" className="button-secondary" disabled={refreshing} onClick={async () => {
      setRefreshing(true); setRefreshError("");
      try { await props.onRefresh(); } catch { setRefreshError("Could not reload incident details. Try again."); }
      finally { setRefreshing(false); }
    }}><RefreshCw size={16} aria-hidden="true" />{refreshing ? "Refreshing…" : "Reload Alert Details"}</button></div>
    {refreshError ? <p className="error" role="alert">{refreshError}</p> : null}
  </div>;
}
