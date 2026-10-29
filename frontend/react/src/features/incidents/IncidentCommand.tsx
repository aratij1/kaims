import RecoveryEvidence from "./RecoveryEvidence";
import ResolutionJourney, { collectionDisplayStatus } from "./ResolutionJourney";
export { collectionDisplayStatus, journeyIndexForStatus } from "./ResolutionJourney";
import { IncidentSourceRecords } from "./IncidentSourceRecords";
import IncidentWorkspaceNav, { incidentView, type IncidentView } from "./IncidentWorkspaceNav";
import { RecordedInvestigationFindings, InvestigationAlternatives } from "./RecordedInvestigationFindings";
import { RcaSequenceReport } from "./RcaSequenceReport";
import {CurrentRecovery} from "./CurrentRecovery";
import { administrativeDuplicateReference, causalPresentation, investigationFindings, isRcaGrounded } from "./incidentTruth";
import HumanEscalation from "./HumanEscalation";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  ArrowLeft,
  Bot,
  CheckCircle2,
  Clock3,
  ExternalLink,
  FileCheck2,
  Gauge,
  GitBranch,
  PauseCircle,
  RotateCcw,
  SearchCheck,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";

import { useRouteRuntimeSlice, type ApprovalRow, type IncidentRow } from "../../app/routeRuntime";
import { EmptyState, ErrorState, LoadingState, StatusBadge, TechnicalDetails } from "../../components/design-system";
import { IncidentCommandWorkspaceSchema } from "../../schemas/apiContracts";
import { ApiRequestError, requestValidated } from "../../services/apiClient";
import ContextEnrichmentPanel, { type EvidenceGap, type OperationsState as EvidenceOperationsState } from "./ContextEnrichmentPanel";

const RELEASE_SHA = String(import.meta.env.VITE_KAIMS_RELEASE_SHA || "dev");
import "./IncidentCommand.css";
import "./IncidentWorkspace.css";
import { InvestigationRecords } from "./InvestigationRecords";
import { InvestigationRetry } from "./InvestigationRetry";
import { formatIstTimestamp, parseUtcTimestamp } from "../../utils/presentation";

type UnknownRecord = Record<string, unknown>;

const TERMINAL = ["closed", "resolved", "recovered", "cancelled"];
const FAILED = ["failed", "rollback_failed", "validation_failed", "manual_intervention_required"];
function record(value: unknown): UnknownRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as UnknownRecord : {};
}

function firstRecord(...values: unknown[]): UnknownRecord {
  return values.map(record).find((candidate) => Object.keys(candidate).length > 0) || {};
}

function text(...values: unknown[]): string {
  const value = values.find((candidate) => typeof candidate === "string" || typeof candidate === "number");
  return value === undefined || value === null ? "" : String(value).trim();
}

function incidentId(row: IncidentRow) {
  return text(row.incident_id, row.id);
}

function normalizedStatus(row: IncidentRow) {
  return text(row.status, record(row.projection_payload).status, "investigating").toLowerCase();
}

function titleFor(row: IncidentRow) {
  const projection = record(row.projection_payload);
  const eventPayload = record(projection.event_payload);
  const context = firstRecord(row.context, projection.context, eventPayload.context);
  const source = firstRecord(row.source_alert, projection.source_alert, record(context.alert), eventPayload.alert);
  const labels = record(source.labels);
  const annotations = record(source.annotations);
  return text(row.title, row.summary, projection.title, projection.summary, source.title, source.name, labels.alertname, annotations.summary, `${row.service || "Service"} incident`);
}

function dateLabel(value: unknown) { return formatIstTimestamp(value); }

function ageLabel(value: unknown) {
  const date = parseUtcTimestamp(value);
  if (!date) return "Freshness unavailable";
  const minutes = Math.max(0, Math.round((Date.now() - date.getTime()) / 60_000));
  if (minutes < 1) return "less than a minute ago";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`;
}

function arrayOfText(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((item) => text(item)).filter(Boolean);
  const candidate = text(value);
  return candidate ? [candidate] : [];
}

function valueOrUnavailable(value: unknown) {
  if (Array.isArray(value)) {
    const items = value.map((item) => text(item)).filter(Boolean);
    return items.length ? items.join("; ") : "Not recorded";
  }
  return text(value) || "Not recorded";
}

function StateBadge({ status }: { status: string }) {
  const tone = status === "cancelled" ? "inactive" : TERMINAL.includes(status) ? "success" : FAILED.some((value) => status.includes(value)) || status.includes("blocked") ? "critical" : /approval|human|queued|retry/.test(status) ? "warning" : "info";
  return <StatusBadge tone={tone}>{status.replaceAll("_", " ")}</StatusBadge>;
}

function Metric({ label, value, detail }: { label: string; value: ReactNode; detail?: string }) {
  return <div className="ic-metric"><span>{label}</span><strong>{value}</strong>{detail ? <small>{detail}</small> : null}</div>;
}

export default function IncidentCommand() {
  const [workspaceParams, setWorkspaceParams] = useSearchParams();
  const activeView = incidentView(workspaceParams.get("section"));
  const changeView = (view: IncidentView) => setWorkspaceParams(previous => {
    const next = new URLSearchParams(previous);
    if (view === "overview") next.delete("section"); else next.set("section", view);
    return next;
  });
  const [workspaceRefreshing, setWorkspaceRefreshing] = useState(false);
  const [workspaceRefreshError, setWorkspaceRefreshError] = useState("");
  const routeParams = useParams();
  const routeIncidentId = routeParams.incidentId ?? routeParams["*"] ?? "";
  const [evidenceOpenedForIncident, setEvidenceOpenedForIncident] = useState("");
  useEffect(() => {
    if (activeView === "evidence") setEvidenceOpenedForIncident(routeIncidentId.toLowerCase());
  }, [activeView, routeIncidentId]);
  const navigate = useNavigate();
  const incidents = useRouteRuntimeSlice("incidents");
  const approvals = useRouteRuntimeSlice("approvals");
  const session = useRouteRuntimeSlice("session");
  const [backendReleaseSha, setBackendReleaseSha] = useState("");
  const [approvalExpanded, setApprovalExpanded] = useState(false);
  const [directRequestVersion, setDirectRequestVersion] = useState(0);
  const [directIncident, setDirectIncident] = useState<{
    loading: boolean;
    loaded: boolean;
    accessToken?: string;
    row: IncidentRow | null;
    error: string;
  }>({ loading: false, loaded: false, row: null, error: "" });
  const [operationsState, setOperationsState] = useState<UnknownRecord>({});
  const [evidenceReadModel, setEvidenceReadModel] = useState<UnknownRecord>({});
  const [amendmentOpen, setAmendmentOpen] = useState(false);
  const [amendmentStatement, setAmendmentStatement] = useState("");
  const [amendmentReason, setAmendmentReason] = useState("");
  const [amendmentSource, setAmendmentSource] = useState("");
  const [amendmentStatus, setAmendmentStatus] = useState("");
  const [amendmentSubmitting, setAmendmentSubmitting] = useState(false);
  const [manualCloseComment, setManualCloseComment] = useState("");
  const [manualCloseState, setManualCloseState] = useState({ loading: false, message: "", error: "" });

  useEffect(() => {
    const controller = new AbortController();
    const loadRelease = async () => {
      try {
        const response = await fetch("/api-gateway/build-info", {
          headers: session.accessToken ? { Authorization: `Bearer ${session.accessToken}`, Accept: "application/json" } : { Accept: "application/json" },
          signal: controller.signal,
        });
        if (!response.ok) return;
        const payload = record(await response.json() as unknown);
        setBackendReleaseSha(text(payload.release_sha));
      } catch (reason) {
        if ((reason as Error)?.name !== "AbortError") setBackendReleaseSha("");
      }
    };
    void loadRelease();
    return () => controller.abort();
  }, [session.accessToken]);

  const requestedIncidentId = useMemo(() => decodeURIComponent(routeIncidentId).trim(), [routeIncidentId]);
  useEffect(() => {
    if (!requestedIncidentId) {
      setDirectIncident({ loading: false, loaded: true, row: null, error: "" });
      setOperationsState({});
      setEvidenceReadModel({});
      return undefined;
    }
    const controller = new AbortController();
    let inFlight = false;
    const loadRequestedIncident = async () => {
      if (inFlight || controller.signal.aborted) return;
      inFlight = true;
      setDirectIncident((current) => ({ ...current, loading: true, loaded: false }));
      try {
        const workspace = await requestValidated(
          `/api-gateway/incidents/${encodeURIComponent(requestedIncidentId)}/command?include_source_records=false`,
          IncidentCommandWorkspaceSchema,
          {
          // Full context may require snapshot and evidence joins under queue load.
          timeoutMs: 45_000,
          headers: session.accessToken ? { Authorization: `Bearer ${session.accessToken}`, Accept: "application/json" } : { Accept: "application/json" },
          signal: controller.signal,
          },
        );
        if (controller.signal.aborted) return;
        const data = record(workspace.incident);
        const match = incidentId(data as IncidentRow).toLowerCase() === requestedIncidentId.toLowerCase()
          ? data as IncidentRow
          : null;
        if (!match) throw new Error("Incident workspace identity does not match the requested incident.");
        setOperationsState(record(workspace.operations));
        setEvidenceReadModel(record(workspace.evidence));
        setDirectIncident({ loading: false, loaded: true, accessToken: session.accessToken, row: match, error: "" });
      } catch (error) {
        if (controller.signal.aborted) return;
        setDirectIncident((current) => ({
          ...current, loading: false, loaded: true,
          row: !(error instanceof ApiRequestError && [401, 403, 404].includes(error.status)) && current.accessToken === session.accessToken && current.row && incidentId(current.row).toLowerCase() === requestedIncidentId.toLowerCase() ? current.row : null,
          error: String((error as Error).message || error),
        }));
      } finally { inFlight = false; }
    };
    void loadRequestedIncident();
    const timer = window.setInterval(() => {
      if (!document.hidden) void loadRequestedIncident();
    }, 30000);
    const onFocus = () => void loadRequestedIncident();
    window.addEventListener("focus", onFocus);
    return () => { controller.abort(); window.clearInterval(timer); window.removeEventListener("focus", onFocus); };
  }, [directRequestVersion, requestedIncidentId, session.accessToken]);

  const directRow = directIncident.accessToken === session.accessToken && directIncident.row && incidentId(directIncident.row).toLowerCase() === requestedIncidentId.toLowerCase()
    ? directIncident.row
    : null;
  // A compact inbox row is not an authoritative context workspace.
  const row = directRow || undefined;
  const approval = useMemo(() => {
    if (!row) return undefined;
    const canonical = record(operationsState.approval);
    const canonicalStatus = text(canonical.status).toLowerCase();
    const feedRow = approvals.rows.find((candidate) => incidentId(candidate).toLowerCase() === incidentId(row).toLowerCase());
    if (!canonicalStatus || canonicalStatus === "not_requested") return feedRow;
    return {
      ...feedRow,
      ...canonical,
      id: text(canonical.approval_id, feedRow?.id),
      incident_id: text(canonical.incident_id, incidentId(row)),
      recommendation_id: text(canonical.recommendation_id, feedRow?.recommendation_id),
      approval_status: canonicalStatus,
      status: canonicalStatus,
    } as ApprovalRow;
  }, [approvals.rows, operationsState.approval, row]);

  if (!row && (directIncident.loading || !directIncident.loaded)) {
    const preview = incidents.rows.find(candidate => incidentId(candidate).toLowerCase() === requestedIncidentId.toLowerCase());
    return <section className="ic-loading-workspace" aria-label="Opening incident">
      <button type="button" className="button-secondary" onClick={() => navigate("/incidents")}><ArrowLeft size={16} /> Incident inbox</button>
      <small>{requestedIncidentId}</small><h2>{preview ? titleFor(preview) : "Opening incident"}</h2>
      <LoadingState label="Loading current investigation and evidence" />
      <p>Older investigations may take longer to load. Actions become available after the current workspace is verified.</p>
    </section>;
  }
  if (!row && directIncident.error) return <ErrorState title="Incident data is temporarily unavailable" description={directIncident.error} retry={() => setDirectRequestVersion((version) => version + 1)} />;
  if (!row) return <EmptyState title="Incident not found" description={`No role-authorized incident record matches ${requestedIncidentId}.`} action={<button type="button" className="button-primary" onClick={() => navigate("/incidents")}>Return to incident inbox</button>} />;

  const projection = record(row.projection_payload);
  const eventPayload = record(projection.event_payload);
  const context = firstRecord(row.context, projection.context, eventPayload.context);
  const contextAlert = record(context.alert);
  const source = firstRecord(row.source_alert, projection.source_alert, contextAlert, eventPayload.alert);
  const sourceLabels = record(source.labels);
  const sourceMetadata = record(source.metadata);
  const deduplication = record(sourceMetadata.deduplication);
  const contextMetadata = record(context.metadata);
  const contextSnapshot = firstRecord(row.context_snapshot, projection.context_snapshot);
  const recommendation = firstRecord(row.recommendation, projection.recommendation, projection.remediation_recommendation, projection.resolution_plan, eventPayload.recommendation, source.recommendation);
  const recommendationMetadata = record(recommendation.metadata);
  const investigationWorkspace = record(operationsState.investigation_workspace);
  const canonicalRca = record(investigationWorkspace.rca);
  const canonicalImpact = record(investigationWorkspace.impact);
  const canonicalBinding = record(investigationWorkspace.binding);
  const canonicalResolution = record(investigationWorkspace.resolution);
  const typedClaims = Array.isArray(canonicalRca.claims) ? canonicalRca.claims.map(record) : [];
  const causalClaim = typedClaims.find((claim) => text(claim.kind).toUpperCase() === "CAUSAL") || {};
  const attachedEvidence = Array.isArray(investigationWorkspace.evidence) ? investigationWorkspace.evidence.map(record) : [];
  const attachedRequirements = Array.isArray(investigationWorkspace.requirements) ? investigationWorkspace.requirements.map(record) : [];
  const canonicalIncidentId = incidentId(row);
  const canonicalAlertId = text(
    recommendationMetadata.alert_id,
    record(record(row).incident_investigation).alert_id,
    row.alert_id,
    source.id,
    contextAlert.id,
  );
  const executionPlan = firstRecord(
    recommendation.execution_plan,
    recommendationMetadata.execution_plan,
    projection.execution_plan,
  );
  const candidatePlan = firstRecord(
    recommendationMetadata.candidate_execution_plan,
    recommendation.candidate_execution_plan,
    projection.candidate_execution_plan,
  );
  const runbookGuidance = firstRecord(
    recommendationMetadata.runbook_guidance,
    recommendation.runbook_guidance,
    projection.runbook_guidance,
  );
  const safety = record(executionPlan.safety_envelope || recommendation.safety_envelope || projection.safety_envelope);
  const canonicalExecution = record(operationsState.execution);
  const canonicalValidation = record(operationsState.validation);
  const executionStatus = text(canonicalExecution.status).toLowerCase();
  const validation = firstRecord(
    canonicalValidation.details,
    projection.validation,
    projection.validation_result,
    projection.recovery_validation,
  );
  const analysis = firstRecord(canonicalRca, projection.analysis, projection.rca, eventPayload.analysis, eventPayload.rca, recommendation.analysis, recommendation.rca, recommendationMetadata.rca_analysis, source.analysis);
  const hasClaimEvidence = arrayOfText(causalClaim.supporting_evidence_ids).some(id => arrayOfText(canonicalRca.resolved_evidence_ids).includes(id))
    || arrayOfText(causalClaim.supporting_evidence_ids).length > 0
    || arrayOfText(canonicalRca.resolved_evidence_ids).length > 0
    || arrayOfText(canonicalRca.supporting_signals).length > 0
    || arrayOfText(analysis.evidence_used).length > 0
    || arrayOfText(analysis.supporting_signals).length > 0
    || Boolean(canonicalRca.hypothesis && canonicalRca.status && !["not_started", "unavailable"].includes(text(canonicalRca.status)));
  const presentedCause = causalPresentation(
    text(causalClaim.statement, canonicalRca.hypothesis),
    causalClaim.confidence ?? canonicalRca.confidence ?? analysis.confidence ?? recommendation.confidence,
    hasClaimEvidence,
  );
  const rootCause = presentedCause.hasCausalStatement ? presentedCause.statement : "";
  const confidence = presentedCause.confidence;
  const confidenceLabel = "Recorded claim confidence";
  const findings = investigationFindings(canonicalRca);
  const supportingReasons = findings.supportingSignals.slice(0, 6);
  const canonicalEvidenceCounts = record(evidenceReadModel.counts);
  const rcaBoundEvidenceCount = Math.max(0, Number(canonicalEvidenceCounts.rca_bound_records) || 0);
  const validatedCitationCount = Math.max(0, Number(canonicalEvidenceCounts.traceable_citations) || 0);
  const hasRecordedAnalysis = Boolean(Number(canonicalBinding.rca_version) > 0 || validatedCitationCount
    || findings.supportingSignals.length || findings.observations.length || findings.limitations
    || (text(canonicalRca.status) && !["not_started", "unavailable"].includes(text(canonicalRca.status))));
  const duplicateReference = administrativeDuplicateReference(canonicalValidation, routeIncidentId);
  const contradictions = [...arrayOfText(causalClaim.contradicting_evidence_ids), ...findings.contradictions];
  const declaredGaps: EvidenceGap[] = (Array.isArray(analysis.missing_evidence) ? analysis.missing_evidence : [])
    .map((gap) => typeof gap === "string"
      ? { category: gap }
      : { category: text(record(gap).category, record(gap).type), reason: text(record(gap).reason, record(gap).description) })
    .filter((gap) => gap.category);
  const nextEvidenceQuestion = (Array.isArray(analysis.missing_evidence) ? analysis.missing_evidence : [])
    .map(gap => text(record(gap).question)).find(Boolean);
  const status = text(operationsState.lifecycle_state, normalizedStatus(row)).toLowerCase();
  const displayStatus = collectionDisplayStatus(status, text(record(operationsState.collection).phase));
  const inFailure = FAILED.some((value) => status.includes(value));
  const isTerminal = TERMINAL.includes(status);
  const rcaConfirmed = Boolean(rootCause) && isRcaGrounded(canonicalRca);
  const technicalRecovery = isTerminal && status !== "cancelled" && canonicalValidation.health_restored === true
    && canonicalValidation.alerts_cleared === true && Boolean(canonicalValidation.report_id && canonicalValidation.validation_checksum);
  const observedRecovery = technicalRecovery && canonicalValidation.closure_kind === "observed_recovery";
  const recoveryResult = record(record(record(validation.metadata).assessment).result);
  const recoveryChecks = Array.isArray(recoveryResult.checks) ? recoveryResult.checks.map(record) : [];
  const recoverySamples = recoveryChecks.flatMap(check => Array.isArray(check.samples) ? check.samples.map(record) : []);
  const observedTimes = recoverySamples.map(sample => parseUtcTimestamp(sample.observed_at)?.getTime()).filter((value): value is number => value !== undefined);
  const observationStart = observedTimes.length ? Math.min(...observedTimes) : null;
  const observationEnd = observedTimes.length ? Math.max(...observedTimes) : null;
  const resolutionReady = text(canonicalResolution.status).toLowerCase() === "ready";
  const evidenceCollectionExhausted = evidenceReadModel.evidence_collection_exhausted === true;
  const action = text(
    canonicalResolution.catalog_operation_id,
    canonicalResolution.proposed_remedy,
    candidatePlan.catalog_operation_id,
    candidatePlan.title,
    arrayOfText(runbookGuidance.remediation_steps).join("; "),
    recommendation.title,
    recommendation.action,
    recommendation.recommended_action,
    eventPayload.recommended_action,
    projection.recommended_action,
    canonicalValidation.action_taken
  );
  const approvalCandidatePending = Boolean(approval) && ![
    "approved", "rejected", "completed", "expired", "not_requested",
  ].includes(text(approval?.approval_status, approval?.status).toLowerCase());
  const sourceTimestamp = text(source.received_at, source.created_at, row.created_at);
  const updatedTimestamp = text(row.latest_event_at, row.updated_at, row.created_at);
  const impact = text(canonicalImpact.statement, recommendation.impact, eventPayload.impact);
  const impactEstablished = ["observed", "grounded", "established"].includes(text(canonicalImpact.status).toLowerCase());
  const partialEvidenceBlocksApproval = evidenceCollectionExhausted && (!rcaConfirmed || !impactEstablished);
  const sourceName = text(row.origin_system, row.source, source.origin_system, source.source, sourceLabels.origin_system, sourceLabels.transport);
  const signalCount = text(row.deduplicated_count, source.deduplicated_count, source.occurrence_count, contextAlert.deduplicated_count, contextAlert.occurrence_count);
  const correlationDetail = text(row.deduplication_reason, deduplication.reason, deduplication.disposition, deduplication.match_type) || "Correlation detail unavailable";
  const contextEvidenceCount = Math.max(0, Number(canonicalEvidenceCounts.latest_context_records) || 0);
  const contextCollectedAt = text(contextSnapshot.collected_at, contextMetadata.context_collected_at);
  const evidenceScores = Array.isArray(evidenceReadModel.scores) ? evidenceReadModel.scores : [];
  const contextQualityScore = evidenceScores.length
    ? evidenceScores.map(record).find((score) => score.key === "context_quality")
    : undefined;
  const contextQuality = Number.isFinite(Number(contextQualityScore?.percent)) ? Number(contextQualityScore?.percent) : null;
  const executionReady = !directIncident.error && executionPlan.execution_ready === true;
  const resolutionAvailable = resolutionReady && Boolean(action) && executionReady && rcaConfirmed && !partialEvidenceBlocksApproval;
  const resolutionBlocks = arrayOfText(canonicalResolution.blocking_reasons);
  const governedOperation = text(canonicalResolution.catalog_operation_id, candidatePlan.catalog_operation_id, runbookGuidance.runbook_slug);
  const governedCapability = text(canonicalResolution.capability_id, candidatePlan.capability_id);
  const governedConnector = text(canonicalResolution.connector_id, candidatePlan.connector_id);
  const governedTarget = text(
    canonicalResolution.target_resource_id,
    candidatePlan.target_resource_id,
    recommendation.target_service,
    recommendation.target,
    row.service,
    sourceLabels.service
  );

  const governedPolicy = record(canonicalResolution.policy_decision);
  const executionUnavailableReason = text(
    executionPlan.readiness_reason,
    executionPlan.blocking_reason,
    arrayOfText(executionPlan.readiness_blocks)[0],
    confidence === 0
      ? "Collect the required evidence before requesting an executable plan."
      : "The backend has not published an execution-ready governed plan.",
  );
  const approvalPending = executionReady && approvalCandidatePending;
  const administrativeClosure = isTerminal && text(canonicalValidation.closure_kind).toLowerCase() === "manual";
  const validationAvailable = Boolean(text(canonicalValidation.status) && text(canonicalValidation.status).toLowerCase() !== "not_started")
    || Object.keys(validation).length > 0;
  const preStateObservations = Array.isArray(canonicalValidation.pre_state_observations)
    ? canonicalValidation.pre_state_observations.map(record) : [];
  const postStateObservations = Array.isArray(canonicalValidation.post_state_observations)
    ? canonicalValidation.post_state_observations.map(record) : [];
  const validationWindow = record(canonicalValidation.observation_window);
  const outcomeDecision = record(canonicalValidation.outcome_decision);
  const rollbackDecision = record(outcomeDecision.rollback);
  const knowledgeDraft = record(canonicalValidation.knowledge_draft);
  const timeline = [
    { at: row.created_at, title: "Incident record created", detail: text(row.source, row.origin_system, source.source) ? `Signal received from ${text(row.source, row.origin_system, source.source)}.` : "Source is not present in the incident record." },
    observedRecovery ? { at: canonicalValidation.updated_at, title: "Recovery independently verified and incident closed", detail: "The recorded assessment verified the monitored endpoint. KaiMS performed no corrective execution." } : null,
    row.latest_event_type ? { at: row.latest_event_at || row.updated_at, title: text(row.latest_event_type).replaceAll("_", " "), detail: `Latest recorded lifecycle event for ${incidentId(row)}.` } : null,
    row.updated_at && row.updated_at !== row.created_at ? { at: row.updated_at, title: "Incident record updated", detail: `Current stored status: ${status.replaceAll("_", " ")}. This timestamp does not establish when that status changed.` } : null,
  ].filter(Boolean) as Array<{ at: unknown; title: string; detail: string }>;

  const refreshIncident = async () => {
    await incidents.refresh();
    setDirectRequestVersion((version) => version + 1);
  };
  const submitClaimAmendment = async () => {
    const claimId = text(causalClaim.claim_id);
    if (!claimId || !session.accessToken) return;
    setAmendmentSubmitting(true); setAmendmentStatus("");
    try {
      const response = await fetch(`/api-gateway/incidents/${encodeURIComponent(canonicalIncidentId)}/claims/${encodeURIComponent(claimId)}/amend`, {
        method: "POST",
        headers: { Authorization: `Bearer ${session.accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ statement: amendmentStatement.trim(), reason: amendmentReason.trim(), source_reference: amendmentSource.trim() }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
      setAmendmentStatus("Amendment recorded. The current RCA and approvals are stale while Kai runs fresh analysis.");
      setAmendmentOpen(false);
      await refreshIncident();
    } catch (reason) {
      setAmendmentStatus((reason as Error).message || "The amendment could not be recorded.");
    } finally { setAmendmentSubmitting(false); }
  };
  const closeAdministratively = async () => {
    if (manualCloseComment.trim().length < 10 || !session.accessToken) return;
    setManualCloseState({ loading: true, message: "", error: "" });
    try {
      const response = await fetch(`/api-gateway/incidents/${encodeURIComponent(canonicalIncidentId)}/manual-close`, {
        method: "POST",
        headers: { Authorization: `Bearer ${session.accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ comment: manualCloseComment.trim() }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(text(record(payload.detail).message, payload.detail, payload.message) || `Manual closure failed (${response.status}).`);
      setManualCloseComment("");
      setManualCloseState({ loading: false, message: "Administrative closure recorded. This does not verify technical recovery.", error: "" });
      await refreshIncident();
    } catch (reason) {
      setManualCloseState({ loading: false, message: "", error: String((reason as Error).message || reason) });
    }
  };
  return <article className="incident-command">
    <header className="ic-command-header">
      <button type="button" className="ic-back" onClick={() => navigate("/incidents")}><ArrowLeft aria-hidden="true" /> Incident inbox</button>
      {canonicalAlertId ? <div className="ic-source-relationship"><span>Source alert</span><Link to={`/alerts?alert_id=${encodeURIComponent(canonicalAlertId)}`}>{canonicalAlertId}</Link><ArrowRight size={12} aria-hidden="true" /><strong>This incident</strong></div> : <p className="ic-source-relationship">Source alert relationship not recorded</p>}
      <div className="ic-title-row">
        <div><span className="ic-id">{incidentId(row)}</span><h2>{titleFor(row)}</h2><p>{impactEstablished ? impact : "Customer or business impact is not established by accepted evidence."}</p></div>
        <div className="ic-header-state"><StateBadge status={displayStatus} /><span><Bot aria-hidden="true" /> Kai {isTerminal ? technicalRecovery ? "verified recovery" : "record closed" : status.includes("human") ? "is waiting for human evidence" : inFailure ? "needs intervention" : status.includes("approval") ? "needs your decision" : "has an open investigation"}</span></div>
      </div>
      <dl className="ic-critical-context">
        <div><dt>Severity</dt><dd>{valueOrUnavailable(row.severity)}</dd></div>
        <div><dt>Service</dt><dd>{valueOrUnavailable(row.service)}</dd></div>
        <div><dt>Environment</dt><dd className={["prod", "production"].includes(text(row.environment, projection.environment, source.environment).toLowerCase()) ? "is-production" : ""}>{valueOrUnavailable(text(row.environment, projection.environment, source.environment))}</dd></div>
        <div><dt>Owner</dt><dd>{valueOrUnavailable(text(projection.owner, projection.assignee, row.jira_assignee))}</dd></div>
      </dl>
      <details className="ic-record-meta"><summary>Record details <span>Application, start time & ticket</span></summary><dl className="ic-critical-context ic-secondary-context">
        <div><dt>Application</dt><dd>{valueOrUnavailable(text(projection.application, source.application, sourceLabels.application, incidents.application !== "all" ? incidents.application : ""))}</dd></div>
        <div><dt>Started</dt><dd>{dateLabel(row.created_at)}</dd></div>
        <div><dt>Jira ticket</dt><dd>{text(row.jira_key, row.ticket_id, projection.jira_key, projection.ticket_id) ? (text(row.jira_url, projection.jira_url) ? <a href={text(row.jira_url, projection.jira_url)} target="_blank" rel="noreferrer">{text(row.jira_key, row.ticket_id, projection.jira_key, projection.ticket_id)} <ExternalLink size={12} /></a> : text(row.jira_key, row.ticket_id, projection.jira_key, projection.ticket_id)) : "Not linked"}</dd></div>
      </dl></details>
    </header>

    {directIncident.error ? <div role="alert" className="ic-action-error">Context refresh failed. Showing the last successfully loaded incident workspace. <button type="button" onClick={() => setDirectRequestVersion((version) => version + 1)}>Retry context</button></div> : null}

    <IncidentWorkspaceNav active={activeView} onChange={changeView} refreshing={workspaceRefreshing}
      onRefresh={() => { void (async () => {
        setWorkspaceRefreshing(true); setWorkspaceRefreshError("");
        try { await refreshIncident(); } catch { setWorkspaceRefreshError("Could not refresh this incident. Try again."); }
        finally { setWorkspaceRefreshing(false); }
      })(); }} />
    {workspaceRefreshError ? <p role="alert" className="ic-action-error">{workspaceRefreshError}</p> : null}
    {duplicateReference ? <aside className="ic-context-findings" aria-label="Duplicate incident reference">
      <h3>Duplicate incident closed</h3>
      <p>This record retains its earlier analysis. Open the incident referenced in the closure note to inspect its investigation and recovery evidence.</p>
      <Link to={`/incidents/${duplicateReference}?section=recovery`}>Open referenced incident</Link>
    </aside> : null}
    <section className="ic-overview-panel" id="incident-panel-overview" role="tabpanel"
      aria-labelledby="incident-tab-overview" tabIndex={0} hidden={activeView !== "overview"}>
      <div className="ic-overview-heading"><span>Incident brief</span><h3>{technicalRecovery ? "Recovery verified" : isTerminal ? "Incident closed" : "Understand the issue. Choose the next step."}</h3>
        <p>{action ? (isTerminal ? `Resolution remedy: ${action}. Earlier investigation tasks are historical.` : `Recommended action: ${action}.`) : text(record(operationsState.next_action).message) || (technicalRecovery ? "Review the recorded action and independent recovery evidence." : "Review the evidence and analysis before selecting a resolution.")}</p></div>
      <div className="ic-overview-facts">
        <Metric label="Evidence" value={`${contextEvidenceCount} records`} detail={`${rcaBoundEvidenceCount} referenced by this RCA; ${Math.max(0, Number(canonicalEvidenceCounts.bound_snapshot_records) || 0)} in its frozen snapshot. Total shows latest collected context.`} />
        <Metric label="Root cause" value={rcaConfirmed ? "Supported" : rootCause || text(source.annotations?.summary, row.summary) ? "Working hypothesis" : hasRecordedAnalysis ? "Inconclusive" : "Not assessed"} detail={rootCause ? (rcaConfirmed ? rootCause : `Unconfirmed: ${rootCause}`) : text(source.annotations?.summary, row.summary) ? `Hypothesis: ${text(source.annotations?.summary, row.summary)}` : findings.limitations || "A causal explanation is not yet available"} />
        <Metric label="Impact" value={impactEstablished ? "Assessed" : impact ? "Unconfirmed assessment" : "Not established"} detail={impact ? (impactEstablished ? impact : `Unconfirmed: ${impact}`) : "Customer impact needs supporting evidence"} />
        <Metric label="Recovery" value={technicalRecovery ? "Verified" : "Not verified"} detail={executionStatus ? `Execution: ${executionStatus.replaceAll("_", " ")}` : "Execution has not started"} />
      </div>

      <div className="ic-overview-actions"><button className="button-primary" type="button" onClick={() => changeView(technicalRecovery || isTerminal ? "recovery" : !rcaConfirmed ? "evidence" : "resolution")}>{technicalRecovery || isTerminal ? "Review recovery record" : !rcaConfirmed ? "Review evidence & gaps" : "Review resolution"}</button><button className="button-secondary" type="button" onClick={() => changeView("analysis")}>Read cause & impact</button><button className="button-secondary" type="button" onClick={() => changeView("activity")}>View activity</button></div>
    </section>
    <details className="ic-disclosure ic-lifecycle-details" hidden={activeView !== "overview"}><summary>Lifecycle and progress<span>Recorded stages and evidence status</span></summary>
    <ResolutionJourney status={status} phase={text(record(operationsState.collection).phase)}
      grounded={rcaConfirmed} resolutionReady={resolutionReady} executionStatus={executionStatus}
      rcaStatus={text(canonicalRca.status)} rcaVersion={Number(canonicalBinding.rca_version) || 0}
      resolutionStatus={text(canonicalResolution.status)} validationStatus={text(canonicalValidation.status)}
      recoveryVerified={technicalRecovery} observedRecovery={observedRecovery}
      message={text(record(operationsState.next_action).message)}
      requirements={Array.isArray(operationsState.requirements) ? operationsState.requirements.map(record) : attachedRequirements}
      updatedAt={updatedTimestamp ? dateLabel(updatedTimestamp) : undefined} />
    </details>

    {inFailure ? <section className="ic-failure" role="alert"><AlertTriangle aria-hidden="true" /><div><span>Resolution did not reach verified recovery</span><strong>{text(validation.message, projection.failure_reason, projection.error) || "The backend marked this incident as failed without a human-readable reason."}</strong><p>{status.includes("rollback") ? "Rollback state is recorded in the incident lifecycle." : "Review the technical record before choosing another action."}</p></div></section> : null}

    <div className="ic-command-grid">
      <main className="ic-primary">
        <section id="incident-panel-evidence" role="tabpanel" aria-labelledby="incident-tab-evidence" tabIndex={0} hidden={activeView !== "evidence"}>
        <div className="ic-panel-heading"><span>Investigation workspace</span><h3>Evidence & collection</h3><p>Inspect source records, track collection, and provide a verified observation where it is needed.</p></div>
        {!isTerminal && (activeView === "evidence" || evidenceOpenedForIncident === canonicalIncidentId.toLowerCase()) ? <ContextEnrichmentPanel key={`collection-${canonicalIncidentId}`}
          incidentId={canonicalIncidentId}
          alertId={canonicalAlertId || undefined}
          accessToken={session.accessToken || ""}
          operationsState={typeof operationsState.lifecycle_state === "string" ? operationsState as EvidenceOperationsState : undefined}
          declaredGaps={declaredGaps}
          proposedRcaDraft={rootCause}
          onIncidentRefresh={refreshIncident}
        /> : null}
        <IncidentSourceRecords key={`${canonicalIncidentId}-${session.accessToken}`} revision={`${text(evidenceReadModel.latest_snapshot_id)}-${text(canonicalBinding.recommendation_id)}`} incidentId={canonicalIncidentId} accessToken={session.accessToken} />
        </section>
        <div className="ic-investigation-history">
        <section id="incident-panel-analysis" role="tabpanel" aria-labelledby="incident-tab-analysis" tabIndex={0} hidden={activeView !== "analysis"}>
        <div className="ic-panel-heading"><span>Analysis</span><h3>Cause & impact</h3><p>Separate confirmed findings from working hypotheses and unknown customer impact.</p></div>
        <section id="incident-impact" className="ic-section ic-impact">
          <header><div><span>Observed state</span><h3>{impactEstablished ? "Verified impact" : "Impact has not been established"}</h3></div><StatusBadge tone={impactEstablished ? "success" : "warning"}>{impactEstablished ? "Evidence-backed" : "Unknown"}</StatusBadge></header>
          <p className="ic-decision-summary">{impactEstablished ? impact : "The alert proves that a signal fired. It does not, by itself, prove customer or business impact."}</p>
          {!impactEstablished && impact ? <article className="ic-context-findings"><h4>Recorded impact assessment</h4><p>{impact}</p><p>Assessment status: {text(canonicalImpact.status, "unconfirmed").replaceAll("_", " ")}. This assessment has not established customer or business impact.</p></article> : null}
          <div className="ic-impact-grid"><Metric label="Impact" value={impactEstablished ? impact : "Not established"} /><Metric label="Monitored service" value={valueOrUnavailable(row.service)} /><Metric label="Signal source" value={valueOrUnavailable(sourceName)} /><Metric label="Correlated signals" value={valueOrUnavailable(signalCount)} detail={correlationDetail} /></div>
        </section>

        <section id="incident-rca" className="ic-section ic-rca">
          <header><div><span>{rcaConfirmed ? "Confirmed root cause" : "Working hypothesis"}{canonicalBinding.rca_version ? ` · RCA v${canonicalBinding.rca_version}` : ""}</span><h3>{rootCause || text(source.annotations?.summary, source.summary, row.summary) || (hasRecordedAnalysis ? "Cause not established" : "No causal analysis recorded")}</h3></div><StatusBadge tone={rcaConfirmed ? "success" : rootCause || hasRecordedAnalysis ? "warning" : "inactive"}>{rcaConfirmed ? "Grounded" : rootCause ? text(canonicalRca.status, "Unconfirmed").replaceAll("_", " ") : hasRecordedAnalysis ? "Inconclusive" : "Unavailable"}</StatusBadge></header>
          {hasRecordedAnalysis && !rootCause ? <p>Evidence and findings are recorded. This RCA has not established a causal explanation; no causal claim confidence has been assigned.</p> : null}
          {rootCause || text(source.annotations?.summary, source.summary, row.summary) || presentedCause.rawObservation || findings.observations.length || supportingReasons.length || findings.alternatives.length || findings.limitations ? <>
            <div className="ic-decision-evidence"><span><strong>{validatedCitationCount}</strong> traceable citation{validatedCitationCount === 1 ? "" : "s"}</span><span><strong>{rcaBoundEvidenceCount}</strong> RCA-bound evidence record{rcaBoundEvidenceCount === 1 ? "" : "s"}</span><span><strong>{confidence === null ? "—" : `${confidence}%`}</strong> {confidenceLabel.toLowerCase()}</span></div>
            <RecordedInvestigationFindings findings={findings} />
            {!isTerminal && !rcaConfirmed ? <InvestigationRetry key={`${canonicalIncidentId}-${text(row.recommendation_id, recommendation.id)}`} alertId={text(row.alert_id, projection.alert_id, source.id)} accessToken={session.accessToken} disabled={Boolean(directIncident.error)} /> : null}
            <div className="ic-reasoning"><article><h4>Recorded supporting rationale</h4>{supportingReasons.length ? <ul>{supportingReasons.map((reason) => <li key={reason}><CheckCircle2 aria-hidden="true" />{reason}</li>)}</ul> : <p>Supporting reasons were not included in the backend analysis.</p>}</article><article><h4>Contradictions and alternatives recorded</h4>{contradictions.length ? <ul>{contradictions.map((reason) => <li key={reason}><X aria-hidden="true" />{reason}</li>)}</ul> : <p>No contradictions were recorded.</p>}</article></div>
            <InvestigationAlternatives findings={findings} />
            {presentedCause.rawObservation ? <article className="ic-context-findings"><h4>{presentedCause.unsupported ? "Untested diagnostic candidate" : "Recorded observation (not a causal explanation)"}</h4><p>{presentedCause.unsupported ? "This recorded candidate has no supporting evidence bound to the current RCA. It is a proposed diagnostic direction, not an established explanation." : "The stored RCA text repeats source data without explaining the cause."}</p><p>{presentedCause.rawObservation}</p></article> : null}
            <details className="ic-analysis-sequence"><summary>Event sequence, remedy & outcome</summary>
          <RcaSequenceReport rca={canonicalRca} resolution={canonicalResolution} execution={canonicalExecution} validation={canonicalValidation} confirmed={rcaConfirmed} observation={record(operationsState.recovery_observation)} />
            </details>
            <TechnicalDetails summary="Why is this gated?"><p>{rcaConfirmed ? "The backend marked this analysis as grounded and supplied traceable citations." : "Causality has not been confirmed. Reference traceability and a confidence score do not confirm causality or authorize remediation."}</p><p>{validatedCitationCount} traceable citation(s), {supportingReasons.length} supporting reason(s), and {contradictions.length} contradicting evidence item(s) are bound to this view.</p>{text(causalClaim.falsification_test) ? <p><strong>Test next:</strong> {text(causalClaim.falsification_test)}</p> : null}</TechnicalDetails>
            {!isTerminal && text(causalClaim.claim_id) ? <div className="ic-amendment">
              <button type="button" className="button-secondary" onClick={() => { setAmendmentOpen((open) => !open); setAmendmentStatement(rootCause); }}>Correct this AI claim</button>
              {amendmentOpen ? <div className="ic-amendment-form">
                <p>This records an operator amendment. It does not become evidence until fresh analysis verifies the cited source.</p>
                <label>Corrected claim<textarea value={amendmentStatement} onChange={(event) => setAmendmentStatement(event.target.value)} /></label>
                <label>Why it needs correction<textarea value={amendmentReason} onChange={(event) => setAmendmentReason(event.target.value)} /></label>
                <label>Source reference<input value={amendmentSource} onChange={(event) => setAmendmentSource(event.target.value)} placeholder="https://ticket, dashboard, trace, or runbook" /></label>
                <button type="button" className="button-primary" disabled={Boolean(directIncident.error) || amendmentSubmitting || amendmentStatement.trim().length < 10 || amendmentReason.trim().length < 10 || !amendmentSource.includes("://")} onClick={() => void submitClaimAmendment()}>{amendmentSubmitting ? "Recording…" : "Record amendment and rerun RCA"}</button>
              </div> : null}
              {amendmentStatus ? <p role="status">{amendmentStatus}</p> : null}
            </div> : null}
          </> : <EmptyState title="Investigation is still forming a hypothesis" description="Kai will show a falsifiable root-cause story when the backend publishes one." />}
        </section>

        </section>
        <section id="incident-panel-resolution" role="tabpanel" aria-labelledby="incident-tab-resolution" tabIndex={0} hidden={activeView !== "resolution"}>
        <div className="ic-panel-heading"><span>Governed action</span><h3>Resolution workspace</h3><p>Review the remedy, target and safety conditions before making a decision.</p></div>
        {isTerminal ? <section className="ic-section"><h3>Recorded execution</h3><p>{action || (administrativeClosure && text(record(record(canonicalValidation.details).metadata).operator_comment)) || "Administrative closure recorded."}</p><div className="ic-resolution-facts"><Metric label="Execution" value={executionStatus && executionStatus !== "not_started" ? executionStatus.replaceAll("_", " ") : administrativeClosure ? "Manual sign-off" : "Not recorded"} /><Metric label="Target" value={governedTarget || "Not recorded"} /><Metric label="Recovery" value={technicalRecovery ? "Verified independently" : administrativeClosure ? "Operator verified" : "Not verified"} /></div><button type="button" className="button-secondary" onClick={() => changeView("recovery")}>Review recovery evidence</button></section> : null}

        {!isTerminal ? <section className="ic-section ic-resolution">
          <header><div><span>{resolutionAvailable ? "Governed resolution" : action ? "Candidate resolution plan (Gated on RCA confirmation / approval)" : "Resolution gate"}</span><h3>{action || "No executable resolution is available"}</h3></div><StatusBadge tone={resolutionAvailable ? "success" : action ? "info" : "warning"}>{resolutionAvailable ? "Ready for review" : action ? "Candidate plan (Gated)" : "Blocked"}</StatusBadge></header>
          {action ? <>
            <p className="ic-resolution-why">{text(recommendation.why, recommendation.rationale, recommendation.reason, projection.recommendation_reason, runbookGuidance.root_cause_guidance) || "The candidate resolution plan was prepared from diagnostic context and matching runbook guidance. Execution remains gated until root cause and governance requirements are satisfied."}</p>
            {Array.isArray(runbookGuidance.remediation_steps) && runbookGuidance.remediation_steps.length ? <article className="ic-context-findings"><h4>Matched runbook guidance ({text(runbookGuidance.runbook_slug, "runbook")}{runbookGuidance.runbook_version ? ` v${runbookGuidance.runbook_version}` : ""})</h4><ul>{arrayOfText(runbookGuidance.remediation_steps).map((step) => <li key={step}>{step}</li>)}</ul></article> : null}
            <div className="ic-resolution-facts">
              <Metric label="Risk" value={valueOrUnavailable(text(recommendation.risk_tier, row.risk_tier))} />
              <Metric label="Blast radius" value={valueOrUnavailable(text(recommendation.blast_radius, executionPlan.blast_radius, safety.allowed_scope))} />
              <Metric label="Target" value={valueOrUnavailable(governedTarget || text(recommendation.target_service, row.service))} />
              <Metric label="Catalog operation" value={valueOrUnavailable(governedOperation || action)} />
              <Metric label="Capability" value={valueOrUnavailable(governedCapability || "service.remediation")} />
              <Metric label="Connector" value={valueOrUnavailable(governedConnector || "docker-compose")} />
              <Metric label="Expected duration" value={valueOrUnavailable(text(recommendation.expected_duration, executionPlan.expected_duration, "3-5 minutes"))} />
              <Metric label="Execution" value={executionStatus && executionStatus !== "not_started" ? executionStatus.replaceAll("_", " ") : "Not started"} />
              <Metric label="Rollback" value={canonicalResolution.rollback_bound === true ? "Bound to plan" : "Available"} />
            </div>
            <section className="ic-safety-envelope"><header><ShieldCheck aria-hidden="true" /><div><span>Execution safety envelope</span><strong>Scope, approval & rollback</strong></div></header><dl>{[
              ["Allowed scope", safety.allowed_scope || executionPlan.scope || `Service: ${row.service}`],
              ["Traffic exposure", safety.traffic_exposure || executionPlan.traffic_exposure || "Internal service traffic only"],
              ["Automatic stop", safety.automatic_stop || safety.stop_conditions || "Stop if error rate increases or container crashes"],
              ["Rollback", safety.rollback || executionPlan.rollback || "Revert to previous container image/tag"],
              ["Approval", safety.approval || row.approval_status || (approvalPending ? "Required" : "Required before execution")],
            ].map(([label, value]) => <div key={String(label)}><dt>{String(label)}</dt><dd>{valueOrUnavailable(Array.isArray(value) ? value.join("; ") : value)}</dd></div>)}</dl></section>
            {approvalPending && approval ? <section className="ic-inline-approval"><header><FileCheck2 aria-hidden="true" /><div><span>Kai needs your decision</span><strong>{action || "Review this production action"}</strong></div></header><p>{text(row.environment).toLowerCase().includes("prod") ? "This action may change Production. Review its scope and stop conditions before approving." : "Policy requires a human decision before Kai can continue."}</p>{approvalExpanded ? <div className="ic-approval-preview"><article><span>What will change</span><p>{action || "Action detail unavailable"}</p></article><article><span>What Kai will watch</span><p>{valueOrUnavailable(safety.stop_conditions || validation.watch_conditions)}</p></article><article><span>When Kai will rollback</span><p>{valueOrUnavailable(safety.rollback_conditions || executionPlan.rollback_conditions)}</p></article></div> : null}<div className="ic-decision-actions"><button type="button" className="button-secondary" onClick={() => setApprovalExpanded((open) => !open)}>{approvalExpanded ? "Hide preview" : "Review safety preview"}</button><button type="button" className="button-secondary" onClick={() => approvals.toggleReject(incidentId(approval))}>Reject</button><button type="button" className="button-primary" disabled={Boolean(directIncident.error) || !approvals.ready || approvals.actionLoading} onClick={() => approvals.approve(approval as ApprovalRow)}>{approvals.actionLoading ? "Submitting decision..." : "Approve plan"}</button></div>{approvals.actionError ? <p className="ic-action-error">{approvals.actionError}</p> : null}</section> : <div className="ic-resolution-actions">{resolutionAvailable ? <button type="button" className="button-secondary" disabled={!executionReady} title={!executionReady ? executionUnavailableReason : undefined} onClick={() => incidents.openTechnical(row, "resolution")}>{executionReady ? "Open technical execution workspace" : "Execution unavailable — collect evidence"}</button> : <p className="ic-action-note">{!rcaConfirmed ? "Remediation plan is prepared. Confirm the root cause or obtain authorization before execution." : "Awaiting governed execution plan compilation."}</p>}{row.jira_url ? <a className="button-secondary" href={row.jira_url} target="_blank" rel="noreferrer">Open ticket <ExternalLink aria-hidden="true" /></a> : null}</div>}
          </> : <div className="ic-resolution-blocked"><ShieldCheck aria-hidden="true" /><div><strong>{rcaConfirmed ? "A governed resolution plan is required" : "Confirm the cause before choosing a remedy"}</strong>
            <p>{rcaConfirmed ? "The cause is supported. Select and review a catalog operation to publish an executable plan." : text(canonicalRca.grounding_notes, "The current RCA has not established which failure mechanism a remedy should address.")}</p>
            <p>{validatedCitationCount} traceable citation(s) are recorded. Citations alone do not establish a cause or authorize an action.</p>
            {resolutionBlocks.length ? <details><summary>Recorded investigation and plan gaps ({resolutionBlocks.length})</summary><ul>{[...new Set(resolutionBlocks)].map(reason => <li key={reason}>{reason === "GOVERNED_EXECUTION_PLAN_NOT_PUBLISHED" ? "A governed execution plan has not been published." : reason}</li>)}</ul></details> : null}
            <button type="button" className="button-secondary" onClick={() => changeView(rcaConfirmed ? "analysis" : "evidence")}>{rcaConfirmed ? "Review analysis and resolution options" : "Review evidence gaps"}</button>
            <details><summary>Plan and execution requirements</summary><dl><div><dt>Grounded RCA</dt><dd>{rcaConfirmed ? "Passed" : "Required"}</dd></div><div><dt>Validated citations</dt><dd>{validatedCitationCount}</dd></div><div><dt>Catalog operation</dt><dd>{governedOperation || "Not selected"}</dd></div><div><dt>Registered capability</dt><dd>{governedCapability || "Not bound"}</dd></div><div><dt>Target / connector</dt><dd>{governedTarget && governedConnector ? `${governedTarget} via ${governedConnector}` : "Not bound"}</dd></div><div><dt>Safety bindings</dt><dd>{canonicalResolution.credential_bound === true && canonicalResolution.rollback_bound === true ? "Credential and rollback bound" : "Incomplete"}</dd></div><div><dt>Policy</dt><dd>{text(governedPolicy.decision, governedPolicy.status) || "Not evaluated"}</dd></div><div><dt>Execution-ready plan</dt><dd>{executionReady ? "Published" : "Required"}</dd></div></dl></details></div></div>}
        </section> : null}

        </section>
        <details className="ic-disclosure" hidden={activeView !== "evidence"}><summary>Evidence references and bindings<span>Supporting records and provenance</span></summary>
          <InvestigationRecords key={`evidence-${canonicalIncidentId}`} evidence={attachedEvidence} requirements={isTerminal ? [] : attachedRequirements} />
        </details>



        {!isTerminal && activeView === "evidence" && evidenceCollectionExhausted && !rcaConfirmed ? <section className="ic-section ic-failure" role="status"><AlertTriangle aria-hidden="true" /><div><span>Evidence collection exhausted</span><strong>RCA remains incomplete, so approval and remediation are blocked.</strong><p>Acknowledge the incident or escalate it for investigation; no partial-evidence remediation plan can be approved.</p></div></section> : null}

        <section className="ic-section ic-causal" hidden={activeView !== "analysis"}>
          <header><div><span>Causal chain</span><h3>{rcaConfirmed && impactEstablished ? "Evidence-supported path to impact" : "Causal path is incomplete"}</h3></div><GitBranch aria-hidden="true" /></header>
          <div className="ic-causal-path">
            <div><div className="ic-causal-node"><span>Observed signal</span><strong>{titleFor(row)}</strong></div><ArrowDown aria-hidden="true" /></div>
            <div><div className="ic-causal-node"><span>Monitored service</span><strong>{valueOrUnavailable(row.service)}</strong></div><ArrowDown aria-hidden="true" /></div>
            <div><div className="ic-causal-node"><span>{rcaConfirmed ? "Confirmed cause" : "Unconfirmed hypothesis"}</span><strong>{rootCause || "Not available"}</strong></div><ArrowDown aria-hidden="true" /></div>
            <div><div className="ic-causal-node"><span>{impactEstablished ? "Verified impact" : "Impact"}</span><strong>{impactEstablished ? impact : "Not established"}</strong></div></div>
          </div>
          {!rcaConfirmed || !impactEstablished ? <p className="ic-gate-note"><ShieldCheck aria-hidden="true" /> KaiMS will not claim an end-to-end causal path until both causality and impact are supported by accepted evidence.</p> : null}
          {!rcaConfirmed || !impactEstablished ? <div className="ic-context-findings" aria-label="Causal path gaps">
            <h4>Why this path is incomplete</h4>
            {!rcaConfirmed ? <p><strong>Cause: </strong>{text(canonicalRca.grounding_notes, arrayOfText(causalClaim.limitations)[0], "This RCA has no accepted evidence establishing an explanatory mechanism.")}</p> : null}
            {!impactEstablished ? <p><strong>Impact: </strong>{text(arrayOfText(record(canonicalImpact.claim).limitations)[0], "This analysis has no corroborated incident-window impact observations. Technical symptoms and customer or business impact need separate evidence.")}</p> : null}
            {nextEvidenceQuestion ? <p><strong>Next evidence question: </strong>{nextEvidenceQuestion}</p> : null}
            <button type="button" className="button-secondary" onClick={() => changeView("evidence")}>Review evidence gaps</button>
          </div> : null}
        </section>

        </div>
        <section id="incident-panel-recovery" role="tabpanel" aria-labelledby="incident-tab-recovery" tabIndex={0} hidden={activeView !== "recovery"}>
        <div className="ic-panel-heading"><span>Outcome verification</span><h3>Recovery evidence</h3><p>Execution and closure are separate from independently verified service recovery.</p></div>
        {observedRecovery ? <section className="ic-section ic-observed-recovery" aria-label="Verified recovery record">
          <header><div><span>Recorded outcome</span><h3>Recovery independently verified</h3></div><StatusBadge tone="success">Closed</StatusBadge></header>
          <p>The monitored service passed its independent recovery checks. KaiMS did not execute a corrective action. The earlier causal hypothesis remains unconfirmed.</p>
          <div className="ic-resolution-facts"><Metric label="Closed at" value={dateLabel(canonicalValidation.updated_at)} /><Metric label="Verification" value={`${recoveryChecks.length} checks passed`} /><Metric label="Recorded samples" value={String(recoverySamples.length)} /><Metric label="Observed stability" value={observationStart !== null && observationEnd !== null ? `${(observationEnd - observationStart) / 1000} seconds` : "Not recorded"} /></div>
          <p><strong>Observation window:</strong> {observationStart !== null ? dateLabel(new Date(observationStart).toISOString()) : "Not recorded"} to {observationEnd !== null ? dateLabel(new Date(observationEnd).toISOString()) : "Not recorded"}</p>
          <details><summary>Recorded recovery note</summary><p>{text(record(validation.metadata).operator_comment) || "No operator note was recorded."}</p></details>
          <div className="ic-recovery-checks">{recoveryChecks.map((check) => {
            const samples = Array.isArray(check.samples) ? check.samples.map(record) : [];
            const latest = samples[samples.length - 1] || {};
            return <article key={text(check.validator_id)}><strong>{text(check.kind).replaceAll("_", " ")}</strong><span>{text(check.status)} / {samples.length} samples</span><small>Latest: {text(latest.measured_value)} / Threshold: {text(latest.expected_value)}</small><small>Target: {text(latest.target_resource_id)}<br />Observer: {text(latest.connector_id)}</small><details><summary>View {samples.length} recorded samples</summary><table><thead><tr><th>Observed at</th><th>Value</th><th>Result</th></tr></thead><tbody>{samples.map((sample, index) => <tr key={index}><td>{dateLabel(sample.observed_at)}</td><td>{text(sample.measured_value)}</td><td>{sample.passed === true ? "Passed" : "Failed"}</td></tr>)}</tbody></table></details></article>;
          })}</div>
          <details><summary>Verification provenance</summary><p>Report: {text(canonicalValidation.report_id)}</p><p>Checksum: {text(canonicalValidation.validation_checksum)}</p><p>Window: {dateLabel(record(record(validation.metadata).assessment).requested_at)} to {dateLabel(recoveryResult.observed_at)}</p></details>
        </section> : null}
        {!isTerminal ? <CurrentRecovery key={canonicalIncidentId} incidentId={canonicalIncidentId} accessToken={session.accessToken} observation={record(operationsState.recovery_observation)} onObserved={(value) => setOperationsState((current) => ({...current, recovery_observation: value}))} /> : null}
        {administrativeClosure ? <section className="ic-section ic-validation">
          <header><div><span>Closure record</span><h3>Administrative closure recorded</h3></div><Clock3 aria-hidden="true" /></header>
          <p>{text(validation.action_taken) || "An operator closed this incident administratively."}</p>
          <p>Technical recovery was not verified by this closure. A separate recovery assessment is required to establish service health.</p>
          <div className="ic-resolution-facts"><Metric label="Closure report" value={valueOrUnavailable(text(canonicalValidation.report_id))} /><Metric label="Recorded at" value={dateLabel(canonicalValidation.updated_at)} /></div>
        </section> : !observedRecovery ? <section className="ic-section ic-validation">
          <header><div><span>Recovery validation</span><h3>{validationAvailable ? text(canonicalValidation.status, validation.status, validation.result, "Validation evidence") : isTerminal ? "Recovery proof unavailable" : "Validation has not started"}</h3></div>{validationAvailable ? <SearchCheck aria-hidden="true" /> : <Clock3 aria-hidden="true" />}</header>
          {validationAvailable ? <>
            <div className="ic-resolution-facts">
              <Metric label="Outcome" value={valueOrUnavailable(text(outcomeDecision.outcome, canonicalValidation.status))} />
              <Metric label="Observation window" value={validationWindow.required_seconds ? `${validationWindow.elapsed_seconds || 0}s / ${validationWindow.required_seconds}s` : "Not recorded"} />
              <Metric label="Pre-state samples" value={String(preStateObservations.length)} />
              <Metric label="Post-state samples" value={String(postStateObservations.length)} />
              <Metric label="Rollback decision" value={valueOrUnavailable(text(rollbackDecision.disposition))} />
              <Metric label="Knowledge draft" value={text(knowledgeDraft.status) || "Not created"} />
            </div>
            <RecoveryEvidence observations={postStateObservations} />
            {knowledgeDraft.status ? <p className="ic-gate-note"><ShieldCheck aria-hidden="true" /> Recovery knowledge is a {text(knowledgeDraft.status)} draft and cannot enter production retrieval until a governance owner reviews and approves it.</p> : null}
          </> : <EmptyState title={isTerminal ? "Closure recorded without verified recovery evidence" : "No recovery validation recorded"} description={isTerminal ? "The record is closed, but this workspace has no verified recovery report for it." : "No recovery assessment or validation observations have been published. An execution is not evidence of recovery by itself."} />}
        </section> : null}

        </section>
        {!isTerminal ? <details className="ic-disclosure" hidden={activeView !== "activity"}><summary>Administrative closure<span>Close a record without claiming recovery</span></summary><section className="ic-section ic-manual-close"><header><div><span>Administrative action</span><h3>Close without claiming recovery</h3></div><StatusBadge tone="warning">Not technical recovery</StatusBadge></header><p>Use this only to record an administrative disposition. The closure record will explicitly state that technical recovery was not verified.</p><textarea rows={3} value={manualCloseComment} onChange={(event) => setManualCloseComment(event.target.value)} placeholder="Explain the evidence, decision, and follow-up action." /><button type="button" className="button-danger" disabled={Boolean(directIncident.error) || manualCloseState.loading || manualCloseComment.trim().length < 10} onClick={() => void closeAdministratively()}>{manualCloseState.loading ? "Recording closure…" : "Record administrative closure"}</button>{manualCloseState.message ? <p className="status-message" role="status">{manualCloseState.message}</p> : null}{manualCloseState.error ? <p className="error" role="alert">{manualCloseState.error}</p> : null}</section></details> : null}
      </main>

      <section className="ic-disclosure ic-supporting-record" id="incident-panel-activity" role="tabpanel" aria-labelledby="incident-tab-activity" tabIndex={0} hidden={activeView !== "activity"}><div className="ic-panel-heading"><span>Incident history</span><h3>Activity & sources</h3><p>Review recorded events, source provenance and operator controls.</p></div><aside className="ic-intelligence">
        <section className="ic-kai-panel"><header><span><Bot aria-hidden="true" />Kai intelligence</span><i>{inFailure ? "Attention" : isTerminal ? technicalRecovery ? "Recovered" : "Closed" : "Live context"}</i></header><div className="ic-kai-state"><Sparkles aria-hidden="true" /><span><small>Current state</small><strong>{isTerminal ? technicalRecovery ? "Recovery recorded" : "Closure recorded" : displayStatus.replaceAll("_", " ")}</strong></span></div></section>
        <section className="ic-narrative"><header><span>{"Recorded history"}</span><h3>{isTerminal ? "Incident and closure timeline" : "What Kai knows so far"}</h3></header>{timeline.length ? <ol>{timeline.map((event, index) => <li key={`${event.title}-${index}`}><time>{dateLabel(event.at)}</time><i /><div><strong>{event.title}</strong><p>{event.detail}</p></div></li>)}</ol> : <p>No timestamped lifecycle events are available.</p>}<small>Summary from the incident record and latest event; this is not a complete execution log.</small></section>
        <section className="ic-evidence"><header><span>Evidence provenance</span><h3>Sources supporting this view</h3></header><article><div><strong>{sourceName || "Incident service"}</strong><em>{!isTerminal && sourceTimestamp && Date.now() - (parseUtcTimestamp(sourceTimestamp)?.getTime() || 0) < 300_000 ? "LIVE" : "RECORDED"}</em></div><p>Collected {ageLabel(sourceTimestamp)}</p><small>Source alert ID: {text(row.alert_id, source.id, "Unavailable")}</small></article>{Object.keys(context).length || Object.keys(contextSnapshot).length || contextEvidenceCount > 0 ? <article><div><strong>Kai context record</strong><em>RECORDED</em></div><p>{contextEvidenceCount ? `${contextEvidenceCount} evidence records` : "Context evidence retained"}{contextQuality !== null ? ` · ${contextQuality}% quality` : ""}</p><small>{contextCollectedAt ? `Collected ${ageLabel(contextCollectedAt)}` : contextMetadata.recovered ? "Recovered from durable alert and recommendation records" : `Snapshot: ${text(contextSnapshot.snapshot_id, contextMetadata.context_fingerprint, "persisted")}`}</small></article> : null}{rootCause ? <article><div><strong>Kai analysis</strong><em className="is-inferred">INFERRED</em></div><p>{isTerminal ? "Historical causal analysis" : `Updated ${ageLabel(updatedTimestamp)}`}</p><small>Inference is visually separated from telemetry.</small></article> : null}</section>
        {!isTerminal ? <HumanEscalation key={canonicalIncidentId} incidentId={canonicalIncidentId} service={text(row.service)} severity={text(row.severity, "medium")} accessToken={session.accessToken} onEscalated={refreshIncident} /> : null}
        {!isTerminal ? <section className="ic-control"><header><PauseCircle aria-hidden="true" /><div><span>Human control</span><h3>Stay in command</h3></div></header><p>{executionReady ? "Holding, taking control, or rolling back requires an authoritative execution capability." : executionUnavailableReason}</p><button type="button" disabled={!executionReady} title={!executionReady ? executionUnavailableReason : undefined} onClick={() => incidents.openTechnical(row, "resolution")}><Gauge aria-hidden="true" /> {executionReady ? "Take control in governed workspace" : "No execution to control"}</button><button type="button" disabled title="Available only when the backend reports an active, controllable execution"><RotateCcw aria-hidden="true" /> Rollback unavailable</button></section> : null}
      </aside></section>
    </div>

    <footer className="ic-truth-note"><ShieldCheck aria-hidden="true" /><span>Evidence, execution and recovery are recorded separately. Updated {dateLabel(updatedTimestamp)}.</span><details><summary>Workspace information</summary><small>UI {RELEASE_SHA.slice(0, 12)} / Gateway {backendReleaseSha ? backendReleaseSha.slice(0, 12) : "unavailable"}</small></details></footer>
  </article>;
}
