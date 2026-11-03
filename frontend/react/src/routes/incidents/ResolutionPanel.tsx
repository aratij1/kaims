import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, ChevronRight, SearchCheck, TriangleAlert } from "lucide-react";
import { canonicalIncidentAnalysis } from "../../domain/incidentAnalysis";
import { canonicalApprovalEligibility } from "../../domain/approvalEligibility";
import { formatQualityPercent } from "../../utils/presentation";
import { routeJson as fetchJson } from "../../services/routeApi";
import { useSession } from "../../app/SessionContext";
import DecisionReadinessPanel, { type ReadinessCheck } from "./DecisionReadinessPanel";

interface ExecutionPlan { requiresApproval?: boolean; riskTier?: string; executionMode?: string; action?: string; target?: string; expectedOutcome?: string; commands?: string[]; catalogPlan?: any; readinessDecision?: any; }
interface Props { workflow: any; alertRow: any; confidenceScore: number; executionPlan: ExecutionPlan; onNavigateTab: (tab: string) => void; embedded?: boolean; readinessChecks?: ReadinessCheck[]; }

function commands(value: any): string[] {
  if (Array.isArray(value)) return value.flatMap(commands);
  if (typeof value === "string" && value.trim()) return [value.trim()];
  if (value && typeof value === "object") return commands(value.command ?? value.script ?? value.value);
  return [];
}
function firstCommands(...candidates: any[]): string[] {
  for (const candidate of candidates) {
    const resolved = commands(candidate);
    if (resolved.length) return resolved;
  }
  return [];
}
function text(...values: any[]): string { return values.find((value) => typeof value === "string" && value.trim())?.trim() || ""; }

export default function ResolutionPanel({ workflow, alertRow, executionPlan, onNavigateTab, embedded = false, readinessChecks = [] }: Props) {
  const analysis = useMemo(() => canonicalIncidentAnalysis(workflow, alertRow), [workflow, alertRow]);
  const metadata = workflow?.recommendation?.metadata || {};
  const plan = executionPlan.catalogPlan || metadata.execution_plan || {};
  const typedAction = Array.isArray(plan.actions) ? plan.actions[0] : null;
  const { accessToken } = useSession();
  const incidentId = String(workflow?.incident_investigation?.incident_id || workflow?.incident?.id || "").trim();
  // approval-service computes a real, HMAC-signed approval-readiness receipt
  // (`_signed_approval_readiness`), but only inside its own `GET
  // /incident/{id}` handler - never persisted onto the recommendation or
  // execution plan, so `executionPlan.readinessDecision`/
  // `plan.approval_readiness`/`metadata.approval_readiness` were always
  // empty and this checklist item showed "missing" for every incident
  // regardless of true readiness. Fetch the live receipt directly; fall
  // back to those static fields (kept for the historical/typed-plan shapes
  // some callers already populate) while the fetch is in flight or fails.
  const [liveReceipt, setLiveReceipt] = useState<any>(null);
  useEffect(() => {
    if (!incidentId || !accessToken) {
      setLiveReceipt(null);
      return undefined;
    }
    const controller = new AbortController();
    fetchJson(`/api-gateway/approval/incident/${encodeURIComponent(incidentId)}`, {
      headers: { Authorization: `Bearer ${accessToken}` }, signal: controller.signal,
      maxAttempts: 1, staleTimeMs: 0,
    }).then((response: any) => {
      const payload = response?.data || response || {};
      setLiveReceipt(payload?.approval_readiness || null);
    }).catch((error: any) => {
      if (error?.name !== "AbortError") setLiveReceipt(null);
    });
    return () => controller.abort();
  }, [accessToken, incidentId]);
  const receipt = liveReceipt || executionPlan.readinessDecision || plan.approval_readiness || metadata.approval_readiness || {};
  const eligibility = canonicalApprovalEligibility({ workflow, plan, receipt });
  const target = text(executionPlan.target, plan.remediation_target, typedAction?.target_resource_id) || "Not identified";
  const environment = text(alertRow?.environment, workflow?.incident?.environment) || "Not identified";
  const rawAction = text(executionPlan.action, workflow?.recommendation?.recommended_action, analysis.action);
  const action = (rawAction.startsWith("Verify the external endpoint") ? text(plan.summary, plan.title, rawAction) : rawAction) || "No action proposed";
  const reason = text(typedAction?.reason, typedAction?.rationale, plan.rationale, metadata.rationale, analysis.rootCause) || "The evidence does not yet establish why a system change is required.";
  const outcome = text(executionPlan.expectedOutcome, typedAction?.expected_outcome, plan.expected_outcome) || "Independent health checks confirm recovery for the target.";
  const run = firstCommands(typedAction?.commands, typedAction?.command, plan.commands);
  const validation = firstCommands(typedAction?.validation_commands, plan.validation_commands, plan.validation_queries);
  const rollback = firstCommands(typedAction?.rollback_commands, plan.rollback_commands, plan.rollback_plan, metadata.rollback_plan, plan.recovery_strategy?.summary);
  const suggestions = run.length ? [] : commands(metadata.model_proposed_execution_plan?.commands);
  const hasScript = run.length > 0;
  const evidenceOnly = /collect|evidence|trace|runbook|investigat|diagnos/i.test(action) && !hasScript;
  const status = hasScript ? (eligibility.eligible ? "Ready for guarded approval" : "Execution safeguards incomplete") : (evidenceOnly ? "Evidence collection required" : "No governed execution script");
  const purpose = evidenceOnly ? `${reason} This diagnostic step is needed to close the evidence gaps before KaiMS can safely propose a system change.` : `${reason} The script is intended to produce this outcome: ${outcome}`;
  const checks: ReadinessCheck[] = [...readinessChecks, { id: "governed-script", label: "Governed execution script", detail: hasScript ? `${run.length} bound command${run.length === 1 ? "" : "s"} available.` : "No executable command is bound to this plan.", passed: hasScript, action: evidenceOnly ? "collect the requested evidence and rerun resolution" : "select a governed catalog plan with bound commands" }];

  return <section className="panel incident-workspace-section incident-resolution-section resolution-decision-brief" role="tabpanel" aria-labelledby="resolution-recommendation-title">
    {/* This is a continuation of the RCA, not a fresh start - an operator who
        clicked here from evidence review should not have to click back just to
        remember why. Carrying the conclusion forward is what makes evidence,
        RCA, and resolution read as one flow instead of three isolated tabs. */}
    <button type="button" className="resolution-rca-recap" onClick={() => onNavigateTab("rca")}>
      <SearchCheck size={16} aria-hidden="true" />
      <span>
        <strong>{analysis.rootCause}</strong>
        <small>{formatQualityPercent(analysis.confidence)} RCA confidence · {analysis.service} · view full evidence</small>
      </span>
      <ChevronRight size={15} aria-hidden="true" />
    </button>
    <header className="resolution-brief-header"><div><span className="discovery-eyebrow">Resolution</span><h3 id="resolution-recommendation-title">{hasScript ? "Review execution plan" : "Resolution needs more evidence"}</h3><p>{hasScript ? "Confirm exactly what will run, why it is needed, and how recovery will be verified." : "No system-changing command will be presented until it is evidence-backed and bound to a governed plan."}</p></div><span className={`decision-readiness ${eligibility.eligible && hasScript ? "is-ready" : "is-blocked"}`}>{eligibility.eligible && hasScript ? <CheckCircle2 size={17} /> : <TriangleAlert size={17} />}{status}</span></header>
    <div className="resolution-operator-brief">
      <section className="resolution-purpose" aria-labelledby="resolution-purpose-title"><span className="resolution-brief-label">Why this is needed</span><h4 id="resolution-purpose-title">{action}</h4><p>{purpose}</p></section>
      <dl className="resolution-plan-facts"><div><dt>Target</dt><dd>{target}</dd></div><div><dt>Environment</dt><dd>{environment}</dd></div><div><dt>Executor</dt><dd>{executionPlan.executionMode || "Not configured"}</dd></div><div><dt>Risk / approval</dt><dd>{executionPlan.riskTier || "Not classified"} · {executionPlan.requiresApproval ? "Human approval" : "Policy controlled"}</dd></div></dl>
      <section className="resolution-script" aria-labelledby="execution-script-title"><div><span className="resolution-brief-label">Execution script</span><small>{hasScript ? "Exact governed commands" : "Unavailable"}</small></div><h4 id="execution-script-title">{hasScript ? "What will run" : "No executable remediation script is available"}</h4>{hasScript ? <pre><code>{run.join("\n")}</code></pre> : <p>{evidenceOnly ? "Complete the evidence request, then refresh the analysis to generate an evidence-backed resolution." : "Bind an approved catalog action before requesting execution."}</p>}{suggestions.length ? <details><summary>Review-only model suggestion</summary><pre><code>{suggestions.join("\n")}</code></pre><p>This suggestion is not governed and cannot be executed from KaiMS.</p></details> : null}</section>
      <div className="resolution-verification-grid"><section><span className="resolution-brief-label">Expected result</span><p>{outcome}</p></section><section><span className="resolution-brief-label">Validation</span>{validation.length ? <pre><code>{validation.join("\n")}</code></pre> : <p>No validation command is bound.</p>}</section><section><span className="resolution-brief-label">Rollback</span>{rollback.length ? <pre><code>{rollback.join("\n")}</code></pre> : <p>No rollback command is bound.</p>}</section></div>
    </div>
    <DecisionReadinessPanel title="What is blocking execution" checks={[...checks, {
      id: "backend-readiness-receipt", label: "Signed backend readiness",
      detail: eligibility.eligible ? `Verified decision ${receipt.decision_id}.` : `${eligibility.reasons.length} blocking reason${eligibility.reasons.length === 1 ? "" : "s"}.`,
      detailList: eligibility.eligible ? undefined : eligibility.reasons,
      passed: eligibility.eligible, action: "request a fresh backend approval-readiness evaluation",
    }]} eligibleLabel="Eligible for guarded approval" onReviewEvidence={() => onNavigateTab("evidence")} />
    {!embedded ? <footer className="incident-section-actions resolution-brief-actions"><button type="button" className="button-secondary" onClick={() => onNavigateTab("rca")}>Review supporting evidence</button><button type="button" className="button-primary" disabled={!hasScript} onClick={() => onNavigateTab("execution")}>Inspect safeguards and decide <ChevronRight size={16} /></button></footer> : null}
  </section>;
}
