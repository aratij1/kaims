import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CircleAlert, CircleCheck, RefreshCw, UserRound } from "lucide-react";
import { routeJson } from "../../services/routeApi";
import { formatUtcTimestamp } from "../../utils/presentation";

export type EvidenceGap = { category: string; reason?: string };
type Job = { connector_id: string; status: string; attempt?: number; attempt_count?: number; last_error_code?: string | null; last_error?: string | null };
type HumanRequest = { request_id: string; expected_responder?: string | null; due_at?: string | null; status: string; assignment_failure_reason?: string | null };
type Requirement = { requirement_id: string; rca_version?: number | null; category: string; question: string; reason?: string | null; acceptable_format?: string | null; suggested_source_reference?: string | null; status: string; created_at?: string | null; updated_at?: string | null; evidence_ids?: string[]; latest_job?: Job | null; active_human_request?: HumanRequest | null };
export type OperationsState = {
  schema_version: "kaiops.operations-state.v1"; lifecycle_state: string; updated_at?: string | null;
  context?: { snapshot_id?: string | null; version?: number; evidence_ids?: string[] };
  investigation?: { rca_version?: number; snapshot_id?: string | null };
  investigation_workspace?: {
    binding?: { snapshot_id?: string | null; snapshot_version?: number; rca_version?: number };
    rca?: { status?: string; grounded?: boolean; grounding_notes?: string; resolved_evidence_ids?: string[]; traceable_citation_count?: number; unresolved_evidence_ids?: string[] };
    evidence?: Array<{ evidence_id?: string; accepted_for_rca?: boolean; citation?: string }>;
    evidence_summary?: { latest_context_records?: number; bound_snapshot_records?: number; rca_bound_records?: number; traceable_citations?: number; unresolved_bindings?: number };
  };
  requirements?: Requirement[]; requirement_history?: Requirement[];
};

const TERMINAL_STATES = new Set(["CLOSED"]);

function requirementStatus(item: Requirement) {
  if (["collected", "answered", "satisfied"].includes(item.status.toLowerCase())) return item.status;
  if (item.status === "blocked" && !["pending", "assignment_blocked"].includes(item.active_human_request?.status || "")) return "collection needs attention";
  if (item.active_human_request?.status === "pending" || item.status === "human_requested") return "waiting for human evidence";
  if (item.latest_job?.status === "dead_letter") return "collection failed";
  return (item.latest_job?.status || item.status || "unknown").replaceAll("_", " ");
}


function friendlyFailure(error: unknown) {
  const message = String((error as Error)?.message || error || "");
  if (/HTTP 404/.test(message)) return "Incident operations are unavailable for this release. Confirm the UI, gateway, and context service use the same version.";
  if (/HTTP 401|HTTP 403/.test(message)) return "Your session is not authorized to view this incident's evidence lifecycle.";
  if (/HTTP 502|HTTP 503|HTTP 504|network|fetch/i.test(message)) return "Incident operations are temporarily unavailable. KaiMS will retry automatically.";
  return "Incident operations could not be loaded. Retry or contact the platform owner if the problem continues.";
}

function lifecycleLabel(state: string, evidenceCount = 0) {
  if (state === "DETECTED" && evidenceCount > 0) return "Evidence recorded";
  const labels: Record<string, string> = { DETECTED: "No evidence yet", REQUIREMENTS_IDENTIFIED: "Evidence required", COLLECTING: "Collecting", WAITING_FOR_HUMAN: "Waiting for human", COLLECTION_BLOCKED: "Blocked", INVESTIGATION_FAILED: "Failed", CONTEXT_READY: "Context ready", INVESTIGATING: "Investigating", RCA_READY: "RCA ready", CLOSED: "Closed" };
  return labels[state] || state.replaceAll("_", " ").toLowerCase();
}

function actionableFailure(item: Requirement) {
  if (item.latest_job?.last_error === "TRACE_NOT_FOUND_OR_EXPIRED") return "No matching trace was retrieved. The collector cannot distinguish an absent trace from an expired one. Confirm that a trace source exists for this service, or provide another verified diagnostic source.";
  if (item.latest_job?.last_error === "NO_MATCHING_APPROVED_EVIDENCE") return item.category === "runbook"
    ? "No approved runbook matched this incident. Review and approve a governed runbook, or provide a verified source."
    : "No approved evidence matched this requirement. Provide a verified source or review the governed knowledge corpus.";
  if (item.active_human_request?.status === "assignment_blocked") return "No authorized responder could be resolved. Assign an incident or service owner.";
  if (item.active_human_request?.assignment_failure_reason) return "Human evidence assignment needs attention.";
  if (item.latest_job?.last_error_code) return `Collection failed (${item.latest_job.last_error_code}). Review connector configuration and retry.`;
  if (item.latest_job?.last_error) return "The connector could not collect this evidence. Review connector health and retry.";
  return "";
}

export type ContextEnrichmentPanelProps = { incidentId: string; alertId?: string; accessToken: string; declaredGaps: EvidenceGap[]; proposedRcaDraft?: string; reviewRequestToken?: number; onIncidentRefresh: () => Promise<void>; operationsState?: OperationsState };

export default function ContextEnrichmentPanel({ incidentId, alertId, accessToken, declaredGaps, proposedRcaDraft = "", reviewRequestToken = 0, onIncidentRefresh, operationsState }: ContextEnrichmentPanelProps) {
  const [state, setState] = useState<OperationsState | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [references, setReferences] = useState<Record<string, string>>({});
  const [observedSymptoms, setObservedSymptoms] = useState<Record<string, string>>({});
  const [businessImpacts, setBusinessImpacts] = useState<Record<string, string>>({});
  const [remediationSteps, setRemediationSteps] = useState<Record<string, string>>({});
  const [expandedRequirements, setExpandedRequirements] = useState<Set<string>>(new Set());
  const [activeRequirementId, setActiveRequirementId] = useState("");
  const [announcement, setAnnouncement] = useState("");
  const [workFilter, setWorkFilter] = useState<"all" | "attention" | "running" | "complete">("all");
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyLimit, setHistoryLimit] = useState(20);
  const inFlight = useRef(false);
  const previousState = useRef("");
  const previousProjection = useRef("");
  const failureCount = useRef(0);
  const incidentRefresh = useRef(onIncidentRefresh);
  const panelRef = useRef<HTMLElement | null>(null);
  const refreshButtonRef = useRef<HTMLButtonElement | null>(null);
  const handledReviewRequest = useRef(0);
  const reviewFocusPending = useRef(false);
  const focusedReviewInput = useRef<HTMLTextAreaElement | null>(null);
  const headers = useMemo(() => ({ Authorization: `Bearer ${accessToken}` }), [accessToken]);

  useEffect(() => { incidentRefresh.current = onIncidentRefresh; }, [onIncidentRefresh]);

  const load = useCallback(async (manual = false) => {
    if (!incidentId || !accessToken || inFlight.current) return;
    // Embedded mode shares the parent's verified command generation. A local
    // operations-only refresh would put this panel ahead of the other tabs.
    if (operationsState) {
      if (manual) await incidentRefresh.current();
      return;
    }
    inFlight.current = true;
    if (manual) setLoading(true);
    try {
      const result = await routeJson<OperationsState>(`/api-gateway/incidents/${encodeURIComponent(incidentId)}/operations-state`, { headers, maxAttempts: 1, staleTimeMs: 0 });
      setState(result); setError(""); failureCount.current = 0;
      const projectionIdentity = JSON.stringify({
        lifecycle: result.lifecycle_state,
        snapshot: result.context?.snapshot_id || "",
        contextVersion: result.context?.version || 0,
        rcaVersion: result.investigation?.rca_version || 0,
        investigationSnapshot: result.investigation?.snapshot_id || "",
      });
      if (previousProjection.current && previousProjection.current !== projectionIdentity) {
        setAnnouncement(`Evidence lifecycle changed to ${lifecycleLabel(result.lifecycle_state, result.context?.evidence_ids?.length || 0)}.`);
        void incidentRefresh.current();
      }
      previousState.current = result.lifecycle_state;
      previousProjection.current = projectionIdentity;
    } catch (reason) { failureCount.current += 1; setError(friendlyFailure(reason)); }
    finally { inFlight.current = false; setLoading(false); }
  }, [accessToken, headers, incidentId, operationsState]);

  useEffect(() => {
    if (operationsState) {
      setState(operationsState);
      return;
    }
    let cancelled = false; let timer: number | undefined;
    previousState.current = ""; previousProjection.current = ""; failureCount.current = 0;
    const poll = async () => {
      if (cancelled) return;
      if (!document.hidden) await load(false);
      if (cancelled || TERMINAL_STATES.has(previousState.current)) return;
      timer = window.setTimeout(() => void poll(), Math.min(3000 * (2 ** failureCount.current), 30_000));
    };
    void poll();
    const resume = () => { if (!document.hidden && !inFlight.current) void load(false); };
    document.addEventListener("visibilitychange", resume);
    return () => { cancelled = true; if (timer) window.clearTimeout(timer); document.removeEventListener("visibilitychange", resume); };
  }, [incidentId, load, operationsState]);

  const buildPreparedDraft = useCallback((item: Requirement) => {
    const gap = declaredGaps.find((candidate) => candidate.category.toLowerCase() === item.category.toLowerCase());
    return [
      `Evidence requirement: ${item.question}`,
      item.reason || gap?.reason ? `Why it is needed: ${item.reason || gap?.reason}` : "",
      proposedRcaDraft ? `AI hypothesis to verify or correct: ${proposedRcaDraft}` : "",
      "",
      `Verified ${item.category.replaceAll("_", " ")} observation: `,
    ].filter(Boolean).join("\n");
  }, [declaredGaps, proposedRcaDraft]);

  const submit = async (requirementId: string) => {
    const response = String(answers[requirementId] || "").trim();
    const sourceReference = String(references[requirementId] || "").trim();
    const observedSymptomsText = String(observedSymptoms[requirementId] || "").trim();
    const businessImpactText = String(businessImpacts[requirementId] || "").trim();
    const remediationStepsText = String(remediationSteps[requirementId] || "").trim();
    if ((!response && !observedSymptomsText) || !sourceReference) return;
    setLoading(true); setError("");
    try {
      const payload: Record<string, unknown> = {
        response: response || observedSymptomsText,
        source_reference: sourceReference,
      };
      if (observedSymptomsText) {
        payload.observed_symptoms = observedSymptomsText;
        payload.root_cause = observedSymptomsText;
      }
      if (businessImpactText) {
        payload.business_impact = businessImpactText;
      }
      if (remediationStepsText) {
        payload.remediation_steps = remediationStepsText;
        payload.create_runbook_draft = true;
      }
      await routeJson(`/api-gateway/incidents/${encodeURIComponent(incidentId)}/context-gaps/${encodeURIComponent(requirementId)}/responses`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      });
      setAnswers((current) => ({ ...current, [requirementId]: "" }));
      setReferences((current) => ({ ...current, [requirementId]: "" }));
      setObservedSymptoms((current) => ({ ...current, [requirementId]: "" }));
      setBusinessImpacts((current) => ({ ...current, [requirementId]: "" }));
      setRemediationSteps((current) => ({ ...current, [requirementId]: "" }));
      setAnnouncement("Human evidence was accepted. KaiMS will publish a new governed context snapshot and analysis.");
      await load(true);
      await incidentRefresh.current();
    } catch (reason) { setError(friendlyFailure(reason)); setLoading(false); }
  };

  const rcaVersion = state?.investigation?.rca_version || 0;
  const current = useMemo(() => (state?.requirements || []).filter(item => item.status !== "cancelled"
    && (!rcaVersion || item.rca_version == null || item.rca_version === rcaVersion)), [state?.requirements, rcaVersion]);
  const history = [...new Map([...(state?.requirement_history || []), ...(state?.requirements || []).filter(item =>
    rcaVersion && item.rca_version != null && item.rca_version !== rcaVersion,
  )].map(item => [item.requirement_id, item])).values()];
  const workGroup = (item: Requirement) => ["collected", "answered", "satisfied", "cancelled"].includes(item.status.toLowerCase()) ? "complete"
    : ["human_requested", "assignment_blocked", "blocked"].includes(item.status) || item.latest_job?.status === "dead_letter" || item.active_human_request?.status === "pending" ? "attention" : "running";
  const visibleWork = current.filter((item) => workFilter === "all" || workGroup(item) === workFilter);
  const selectedWork = visibleWork.find((item) => item.requirement_id === activeRequirementId) || visibleWork[0];
  const humanRequirements = current.filter((item) => !["collected", "answered", "satisfied", "cancelled"].includes(item.status.toLowerCase())
    && (item.status === "human_requested" || ["pending", "assignment_blocked"].includes(item.active_human_request?.status || "")));
  const openHumanEvidence = (item: Requirement) => {
    reviewFocusPending.current = true;
    setActiveRequirementId(item.requirement_id);
    setExpandedRequirements((values) => new Set([...values, item.requirement_id]));
    window.requestAnimationFrame(() => {
      const input = Array.from(panelRef.current?.querySelectorAll<HTMLTextAreaElement>("[data-requirement-response]") || []).find((node) => node.dataset.requirementResponse === item.requirement_id);
      input?.scrollIntoView?.({ behavior: "smooth", block: "center" });
      input?.focus();
    });
  };
  const evidenceIds = state?.context?.evidence_ids || [];
  const evidenceSummary = state?.investigation_workspace?.evidence_summary;
  const latestContextCount = evidenceSummary?.latest_context_records ?? evidenceIds.length;
  const boundSnapshotCount = evidenceSummary?.bound_snapshot_records ?? state?.investigation_workspace?.evidence?.length ?? 0;
  const rcaBoundCount = evidenceSummary?.rca_bound_records ?? state?.investigation_workspace?.rca?.resolved_evidence_ids?.length ?? 0;
  const citationCount = evidenceSummary?.traceable_citations ?? state?.investigation_workspace?.rca?.traceable_citation_count ?? 0;
  const unresolvedBindings = evidenceSummary?.unresolved_bindings ?? state?.investigation_workspace?.rca?.unresolved_evidence_ids?.length ?? 0;

  useEffect(() => {
    if (!reviewRequestToken || reviewRequestToken === handledReviewRequest.current) return;
    if (!current.length) {
      handledReviewRequest.current = reviewRequestToken;
      panelRef.current?.scrollIntoView?.({ behavior: "smooth", block: "start" });
      refreshButtonRef.current?.focus();
      setAnnouncement("No active evidence input was published for this RCA. Refresh evidence or rerun analysis to project the missing requirement.");
      return;
    }
    const item = current.find((requirement) => ["pending", "assignment_blocked"].includes(String(requirement.active_human_request?.status || "")))
      || current.find((requirement) => !["collected", "answered", "satisfied"].includes(requirement.status.toLowerCase()));
    if (!item) {
      handledReviewRequest.current = reviewRequestToken;
      panelRef.current?.scrollIntoView?.({ behavior: "smooth", block: "start" });
      refreshButtonRef.current?.focus();
      setAnnouncement("All published evidence requirements are already complete. Rerun analysis to reconcile the remaining readiness checks.");
      return;
    }
    handledReviewRequest.current = reviewRequestToken;
    setWorkFilter("all");
    reviewFocusPending.current = true;
    setActiveRequirementId(item.requirement_id);
    setExpandedRequirements((values) => new Set([...values, item.requirement_id]));
    const gap = declaredGaps.find((candidate) => candidate.category.toLowerCase() === item.category.toLowerCase());
    const draft = [
      `Evidence requirement: ${item.question}`,
      item.reason || gap?.reason ? `Why it is needed: ${item.reason || gap?.reason}` : "",
      proposedRcaDraft ? `AI hypothesis to verify or correct: ${proposedRcaDraft}` : "",
      "",
      `Verified ${item.category.replaceAll("_", " ")} observation: `,
    ].filter(Boolean).join("\n");
    setAnswers((values) => values[item.requirement_id]?.trim() ? values : { ...values, [item.requirement_id]: draft });
    if (item.suggested_source_reference) {
      setReferences((values) => values[item.requirement_id]?.trim() ? values : { ...values, [item.requirement_id]: String(item.suggested_source_reference) });
    }
    panelRef.current?.scrollIntoView?.({ behavior: "smooth", block: "start" });
    setAnnouncement(`Review form opened for ${item.category.replaceAll("_", " ")} evidence.`);
  }, [current, declaredGaps, proposedRcaDraft, reviewRequestToken]);

  useEffect(() => {
    if (!current.length) return;
    setActiveRequirementId((value) => current.some((item) => item.requirement_id === value) ? value : current[0].requirement_id);
    setAnswers((values) => {
      const next = { ...values };
      current.forEach((item) => {
        if (!next[item.requirement_id]?.trim()) {
          next[item.requirement_id] = [
            `Evidence requirement: ${item.question}`,
            item.reason ? `Why it is needed: ${item.reason}` : "",
            proposedRcaDraft ? `AI hypothesis to verify or correct: ${proposedRcaDraft}` : "",
            "",
            `Verified ${item.category.replaceAll("_", " ")} observation: `,
          ].filter(Boolean).join("\n");
        }
      });
      return next;
    });
    setReferences((values) => {
      const next = { ...values };
      current.forEach((item) => {
        if (item.suggested_source_reference && !next[item.requirement_id]?.trim()) {
          next[item.requirement_id] = String(item.suggested_source_reference);
        }
      });
      return next;
    });
  }, [current, incidentId, proposedRcaDraft]);

  const card = (item: Requirement, historical = false) => {
    const request = item.active_human_request; const job = item.latest_job;
    const complete = ["collected", "answered", "satisfied"].includes(item.status.toLowerCase());
    const status = requirementStatus(item); const failure = actionableFailure(item);
    const recordedAt = item.updated_at || item.created_at;
    return <article key={item.requirement_id} className={historical ? "is-historical" : undefined}>
      <div className="context-enrichment-item-heading">
        {complete ? <CircleCheck size={17} /> : request ? <UserRound size={17} /> : <RefreshCw size={17} />}
        <div><strong>{item.category.replaceAll("_", " ")}</strong><p>{item.question}</p><small className="context-enrichment-version">{item.rca_version == null ? "RCA version unavailable" : `RCA v${item.rca_version}`}{recordedAt ? ` · updated ${formatUtcTimestamp(recordedAt)}` : ""}</small></div>
        <span>{status.replaceAll("_", " ")}</span>
      </div>

      {!historical ? <div className="evidence-next-action"><strong>{complete ? "Evidence recorded" : request?.status === "pending" ? "Your next action" : workGroup(item) === "attention" ? "Collection needs attention" : "Automatic collection"}</strong><p>{complete ? "Review the recorded evidence references below. Collection alone does not confirm the cause." : request?.status === "pending" ? "Open the response form below and provide an attributable observation." : workGroup(item) === "attention" ? "Review the collector details and repair or configure the required source. You can also add verified evidence." : job?.status === "collecting" ? "The collector is running. Status refreshes automatically." : job?.status === "retry" ? "A retry is scheduled. Status refreshes automatically." : !job ? "No collection job is recorded. Review the source requirements in collector details." : "This request is waiting for collection capacity. Status refreshes automatically."}</p></div> : null}
      <details className="context-request-diagnostics"><summary>Question context and collector details</summary><div className="context-enrichment-study-brief">
        <strong>What KaiMS needs to establish</strong>
        <dl>
          <div><dt>Why this matters</dt><dd>{item.reason || "Required to test and strengthen the current RCA hypothesis."}</dd></div>
          <div><dt>Preferred source</dt><dd>{item.suggested_source_reference || `${item.category.replaceAll("_", " ")} dashboard, ticket, catalog, or another attributable source`}</dd></div>
        </dl>
      </div>
      {job ? <small>Latest attempt {job.attempt_count || job.attempt || 1} · connector {job.connector_id} · {job.status.replaceAll("_", " ")}</small> : null}
      </details>
      {item.evidence_ids?.length ? <details className="context-enrichment-evidence">
        <summary>Collected evidence ({item.evidence_ids.length})</summary>
        <p>Collection confirms records were retrieved. It does not establish the cause or satisfy execution approval.</p>
        <ul className="context-enrichment-evidence-list" aria-label="Collected evidence references">
          {item.evidence_ids.map((id, index) => <li key={`${index}:${id}`}>{id}</li>)}
        </ul>
      </details> : null}
      {failure ? <p className="context-enrichment-action" role="status">{failure}</p> : null}
      {!historical && item.status === "blocked" && !["pending", "assignment_blocked"].includes(request?.status || "") ? <p className="context-enrichment-action" role="status">A configured technical source or collector repair is needed. Human input is optional; this requirement remains unresolved.</p> : null}
      {!historical && !complete && !job ? <p className="context-enrichment-action" role="status">No automated collection job is recorded for this requirement. A verified observation or a configured evidence source is needed.</p> : null}

      {!historical && !complete ? <details className="context-enrichment-response-shell" open={expandedRequirements.has(item.requirement_id)} onToggle={(event) => {
        const open = event.currentTarget.open;
        setExpandedRequirements((values) => { const next = new Set(values); if (open) next.add(item.requirement_id); else next.delete(item.requirement_id); return next; });
      }}>
        <summary><span>{request?.status === "assignment_blocked" ? "Provide evidence yourself" : request?.status === "pending" ? "Review and provide evidence" : "Add optional evidence"}</span><small>{expandedRequirements.has(item.requirement_id) ? "Hide form" : "Open form"}</small></summary>
        <div className="context-enrichment-response">
        <div className="context-enrichment-guidance">
          <strong>Who provides this &amp; what is missing</strong>
          <p><strong>Intended responder roles:</strong> Internal operational responders (<em>Assigned Responder, On-Call SRE, L1/L2/L3 Engineer, Service Owner, or Administrator</em>) — not end users. Requires authenticated operator permissions (<code>ADMIN</code>, <code>OPERATOR</code>, or <code>HITL_APPROVER</code>).</p>
          <p><strong>Missing information for this requirement:</strong> {item.question} ({item.reason || "Needed to corroborate the root cause with attributable evidence."})</p>
          <p><strong>RCA sufficiency rule:</strong> Confirming an RCA and unlocking an executable remediation plan requires <strong>&ge; 65% confidence</strong> and <strong>&ge; 2 independent corroborating evidence sources</strong> (currently {citationCount} traceable citation{citationCount === 1 ? "" : "s"} bound). Submitting a single uncorroborated source records context but will not falsely confirm the RCA.</p>
        </div>
        <small>{request?.status === "assignment_blocked" ? "Human evidence assignment is blocked. An authorized operator can provide a verified observation here." : request?.status === "pending" ? `Assigned to ${request.expected_responder || "an authorized responder (L1/L2/L3 Engineer, On-Call SRE, or Service Owner)"}${request.due_at ? ` · due ${formatUtcTimestamp(request.due_at)}` : ""}` : "A verified operator response may be submitted here. Collection progress is shown only when a job is recorded."}</small>
        <div className="action-row">
          <small>Complete the required fields below using verified facts and an attributable source reference.</small>
          <button type="button" className="button-secondary" onClick={() => setAnswers((value) => ({ ...value, [item.requirement_id]: buildPreparedDraft(item) }))}>Reset to prepared draft</button>
        </div>
        <label>
          <span>Verified observation <strong>(Required)</strong></span>
          <small>Plain-language factual observation verified from source code, logs, metrics, or traces. Example: <code>In app.py line 42, healthz divides by zero when count=0; HTTP 500 observed at 14:02 UTC.</code></small>
          <textarea rows={6} ref={(node) => {
            if (!node && focusedReviewInput.current?.dataset.requirementResponse === item.requirement_id
              && document.activeElement === focusedReviewInput.current) reviewFocusPending.current = true;
            if (node && reviewFocusPending.current && !historical && item.requirement_id === activeRequirementId) {
              node.focus(); focusedReviewInput.current = node; reviewFocusPending.current = false;
            }
          }} data-requirement-response={item.requirement_id} aria-label={`Response for ${item.category}`} value={answers[item.requirement_id] || ""} onChange={(event) => setAnswers((value) => ({ ...value, [item.requirement_id]: event.target.value }))} placeholder="State the verified factual observation. Remove any AI claim you could not confirm." />
        </label>
        <label>
          <span>Supporting source <strong>(Required)</strong></span>
          <small>Attributable URI, ticket key, commit/file path, or dashboard link. Example: <code>git://service-repo/app.py#L42</code>, <code>jira://OPS-204</code>, or click &ldquo;Use internal evidence URI&rdquo;.</small>
          <div className="action-row">
            <input aria-label={`Source reference for ${item.category}`} value={references[item.requirement_id] || ""} onChange={(event) => setReferences((value) => ({ ...value, [item.requirement_id]: event.target.value }))} placeholder={item.suggested_source_reference || `e.g. git://repo/file#L42 or kaiops://human-evidence/${incidentId}/${item.requirement_id}`} />
            <button type="button" className="button-secondary" onClick={() => setReferences((value) => ({ ...value, [item.requirement_id]: String(item.suggested_source_reference || `kaiops://human-evidence/${incidentId}/${item.requirement_id}`) }))}>Use internal evidence URI</button>
          </div>
        </label>
        <label>
          <span>Observed symptoms / root cause <em>(Optional — enriches RCA &amp; knowledge draft)</em></span>
          <small>Summarize the technical symptom and verified root cause. Example: <code>Unhandled ZeroDivisionError in /healthz endpoint when request counter is 0.</code></small>
          <textarea rows={3} aria-label={`Observed symptoms or root cause for ${item.category}`} value={observedSymptoms[item.requirement_id] || ""} onChange={(event) => setObservedSymptoms((value) => ({ ...value, [item.requirement_id]: event.target.value }))} placeholder="Example: Unhandled ZeroDivisionError in /healthz when counter is zero..." />
        </label>
        <label>
          <span>Business impact <em>(Optional — records operational/SLA impact)</em></span>
          <small>Describe customer, SLA, or service impact during the incident window. Example: <code>Synthetic probe failing every 15s in dev; no customer data loss.</code></small>
          <textarea rows={2} aria-label={`Business impact for ${item.category}`} value={businessImpacts[item.requirement_id] || ""} onChange={(event) => setBusinessImpacts((value) => ({ ...value, [item.requirement_id]: event.target.value }))} placeholder="Example: Synthetic health check failing in dev; no production customer transactions dropped..." />
        </label>
        <label>
          <span>Recommended remediation steps <em>(Optional — creates Draft Runbook &amp; Knowledge Document)</em></span>
          <small>Step-by-step fix and validation commands saved as a governed draft runbook in Knowledge Development. Example: <code>1. Guard denominator in app.py. 2. Restart container. 3. Verify GET /healthz returns HTTP 200.</code></small>
          <textarea rows={3} aria-label={`Recommended remediation steps for ${item.category}`} value={remediationSteps[item.requirement_id] || ""} onChange={(event) => setRemediationSteps((value) => ({ ...value, [item.requirement_id]: event.target.value }))} placeholder="Example: 1. Patch denominator check in app.py. 2. Redeploy service. 3. Verify /healthz returns 200 OK..." />
        </label>
        <button type="button" className="button-primary" disabled={loading || (!String(answers[item.requirement_id] || "").trim() && !String(observedSymptoms[item.requirement_id] || "").trim()) || !String(references[item.requirement_id] || "").trim()} onClick={() => void submit(item.requirement_id)}>Submit reviewed evidence and rerun RCA</button>
        </div>
      </details> : null}
    </article>;
  };

  return <section ref={panelRef} className="context-enrichment-panel" aria-labelledby="context-enrichment-title">
    <div className="sr-only" aria-live="polite">{announcement}</div>
    <header><div><span className="discovery-eyebrow">Missing evidence</span><h3 id="context-enrichment-title">Evidence collection and human input</h3><p>Review automated collection or provide a verified observation with a supporting source.</p></div><button ref={refreshButtonRef} type="button" className="button-secondary" onClick={() => void load(true)} disabled={loading}><RefreshCw size={15} className={loading ? "is-spinning" : ""} /> Reload status</button></header>
    {announcement ? <p className="context-enrichment-action" role="status">{announcement}</p> : null}
    {state ? <div className="evidence-work-summary" aria-label="Evidence work summary">
      {([['all', 'All requests'], ['attention', 'Needs attention'], ['running', 'Queued / collecting'], ['complete', 'Recorded']] as const).map(([filter, label]) => <button type="button" key={filter} aria-pressed={workFilter === filter} onClick={() => setWorkFilter(filter)}><strong>{filter === "all" ? current.length : current.filter(item => workGroup(item) === filter).length}</strong><span>{label}</span></button>)}
    </div> : !error ? <p role="status">Loading evidence work?</p> : null}
    {humanRequirements.length ? <div className="evidence-human-shortcuts" aria-label="Human evidence requests"><strong>Human input requested</strong>{humanRequirements.map(item => <button key={item.requirement_id} className="button-secondary" onClick={() => { setWorkFilter("all"); openHumanEvidence(item); }}>Provide human evidence<span className="sr-only"> for {item.category.replaceAll("_", " ")}</span><small aria-hidden="true"> / {item.category.replaceAll("_", " ")}</small></button>)}</div> : null}
    {state?.context?.snapshot_id && state?.investigation?.snapshot_id && state.context.snapshot_id !== state.investigation.snapshot_id ? <p className="context-enrichment-action" role="status">Newer context is available. The displayed RCA still uses an earlier evidence snapshot; collection alone does not update its conclusion.</p> : null}

    {error ? <p className="context-enrichment-error" role="alert"><CircleAlert size={17} />{error}</p> : null}
    {!alertId && declaredGaps.length ? <p className="context-enrichment-error" role="status"><CircleAlert size={17} />Canonical alert binding is missing. Backend orchestration will regenerate analysis after a governed snapshot is committed.</p> : null}
    {!error && state && !current.length ? <p className="context-enrichment-empty">{declaredGaps.length ? "Evidence requirements have not been projected yet. KaiMS will continue monitoring this incident." : state.investigation_workspace?.rca?.grounded !== true ? "No active collection requests are published. This does not establish evidence sufficiency; review the RCA limitations and publish targeted evidence requirements." : "No unresolved evidence gaps are declared."}</p> : null}
    {current.length ? <section className="context-enrichment-current" aria-labelledby="current-evidence-title"><div className="context-enrichment-group-heading"><div><span>Evidence requests</span><h4 id="current-evidence-title">{current.filter(item => workGroup(item) !== "complete").length} open · {current.filter(item => workGroup(item) === "complete").length} recorded</h4><small>{rcaVersion ? `Analysis revision ${rcaVersion}. ` : ""}{state?.investigation_workspace?.rca?.grounded === true ? "Cause established." : "Cause not established; these requests support the investigation."}</small></div><small>{current.length} requirement{current.length === 1 ? "" : "s"}</small></div>
      <div className="evidence-workspace"><div className="context-enrichment-tabs" role="group" aria-label="Evidence collection tasks">{visibleWork.map((item) => <button key={item.requirement_id} type="button" aria-pressed={item.requirement_id === selectedWork?.requirement_id} onClick={() => {
        setActiveRequirementId(item.requirement_id);
      }}><strong>{item.category.replaceAll("_", " ")}</strong><span>{requirementStatus(item)}</span></button>)}</div>
      <div className="context-enrichment-list">{selectedWork ? card(selectedWork) : <p className="context-enrichment-empty">No requests in this category. Choose another filter.</p>}</div></div>
    </section> : null}
    {state ? <details className="context-accounting-details"><summary>Evidence accounting and snapshot versions</summary><section className="context-evidence-ledger" aria-labelledby="evidence-ledger-title">
      <div className="context-evidence-ledger-heading"><div><span>Evidence accounting</span><h4 id="evidence-ledger-title">Current RCA evidence funnel</h4></div><strong>{lifecycleLabel(state.lifecycle_state, latestContextCount)}</strong></div>
      <ol>
        <li><span>Latest context</span><strong>{latestContextCount}</strong><small>records in snapshot v{state.context?.version || 0}</small></li>
        <li><span>RCA snapshot</span><strong>{boundSnapshotCount}</strong><small>records frozen for this analysis</small></li>
        <li><span>RCA-referenced</span><strong>{rcaBoundCount}</strong><small>records explicitly cited by RCA v{rcaVersion || 0}</small></li>
        <li><span>Traceable</span><strong>{citationCount}</strong><small>RCA citations with a verifiable source</small></li>
      </ol>
      {unresolvedBindings ? <p className="context-evidence-integrity" role="alert"><CircleAlert size={16} />{unresolvedBindings} RCA evidence binding{unresolvedBindings === 1 ? " does" : "s do"} not resolve inside the bound snapshot. Grounding remains blocked.</p> : null}
      <footer><span>Latest: {state.context?.snapshot_id || "not published"}</span><span>RCA-bound: {state.investigation_workspace?.binding?.snapshot_id || state.investigation?.snapshot_id || "not bound"}</span><span>Updated {state.updated_at ? formatUtcTimestamp(state.updated_at) : "unavailable"}</span></footer>
    </section></details> : null}
    {history.length ? <details className="context-enrichment-history" onToggle={event => setHistoryOpen(event.currentTarget.open)}><summary>Previous RCA versions <span>{history.length} archived requirement{history.length === 1 ? "" : "s"}</span></summary><p>Retained for audit history. Responses can only be submitted against active backend-projected work.</p><div className="context-enrichment-list">{historyOpen ? history.slice(0, historyLimit).map((item) => card(item, true)) : null}{historyOpen && history.length > historyLimit ? <button className="button-secondary" onClick={() => setHistoryLimit(value => value + 20)}>Show 20 more archived requests</button> : null}</div></details> : null}
  </section>;
}
