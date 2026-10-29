from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import and_, case, delete, exists, func, literal, or_, select, text, union_all, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased, load_only
from common.queue_lifecycle import MAX_COLLECTION_ATTEMPTS
from common.rca_timeline import build_rca_timeline, causal_steps
from common.recovery_status import observation_id, project_observation

from common.database import (
    ActionRecord,
    AgentWorkItemRecord,
    AlertRecord,
    AlertRuleRecord,
    AnalysisRequestRecord,
    ApplicationEnvironmentRecord,
    ApplicationLabelRecord,
    ApplicationRecord,
    ApprovalRecord,
    ApprovalAssignmentRecord,
    AuditLogRecord,
    ContextEnrichmentJobRecord,
    ContextEvidenceRequirementRecord,
    CanonicalEvidenceRecord,
    ContextKnowledgeRecord,
    ContextReconciliationLeaseRecord,
    ContextReconciliationRunRecord,
    ContextSnapshotRecord,
    DraftPullRequestOutboxRecord,
    EvaluationRecord,
    EvidenceRagDraftRecord,
    EvidenceRejectionRecord,
    ExecutionPlanRecord,
    GovernedRagDocumentRecord,
    GovernedResolutionPlanRecord,
    GrafanaDashboardRecord,
    HumanEvidenceRequestRecord,
    IncidentCorrelationOwnershipRecord,
    IncidentEventRecord,
    IncidentInvestigationBindingRecord,
    IncidentLifecycleTransitionRecord,
    IncidentOccurrenceRecord,
    IncidentProjectionRecord,
    IncidentRecord,
    IncidentRcaVersionReservationRecord,
    JiraIncidentBindingRecord,
    JiraSyncCursorRecord,
    JiraTicketLinkRecord,
    JiraWebhookEventRecord,
    KnowledgeBaseRecord,
    KnowledgeRagDraftRecord,
    LearningAuditRecord,
    MonitoringAlertMappingRecord,
    MonitoringConnectionAuditRecord,
    MonitoringConnectionHealthRecord,
    MonitoringCredentialRecord,
    MonitoringIntegrationRecord,
    MonitoringNormalizedAlertRecord,
    MonitoringProfileRecord,
    MonitoringReceivedAlertRecord,
    MonitoringWebhookEndpointRecord,
    ObjectStorageRecord,
    OnboardingControlPlaneRecord,
    OnboardingHistoryRecord,
    OnboardingStateRecord,
    PendingWorkflowRecord,
    PrometheusConfigRecord,
    RcaReportRecord,
    RecordingRuleRecord,
    ResolutionOutboxRecord,
    ResolutionPlanSupersessionRecord,
    RunbookApprovalRecord,
    RunbookOutcomeRecord,
    RunbookRecord,
    RunbookVersionRecord,
    ValidationHistoryRecord,
    ValidationObservationRecord,
)
from common.incident_investigation import IncidentInvestigationContract, is_traceable_evidence_citation
from common.incident_lifecycle import FAILURE_INCIDENT_STATES, IncidentLifecycleState, validate_incident_transition
from common.incident_status import reduce_incident_status
from common.orchestration.execution_plan_contract import (
    ExecutionPlanV2,
    canonical_plan_fingerprint,
    verify_plan_fingerprint,
)
from common.orchestration.resolution_selection_contract import ResolutionSelectionV1
from common.resolution_lifecycle import select_current_lifecycle
from common.tenant_identity import require_tenant_id


class ObjectStorageRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def upsert(self, values: dict[str, Any]) -> ObjectStorageRecord:
        object_key = str(values["object_key"])
        row = (
            await self.session.execute(select(ObjectStorageRecord).where(ObjectStorageRecord.object_key == object_key))
        ).scalar_one_or_none()
        if row is None:
            row = ObjectStorageRecord(**values)
            self.session.add(row)
        else:
            for key, value in values.items():
                if key not in {"id", "object_key", "created_at"} and hasattr(row, key):
                    setattr(row, key, value)
        await self.session.flush()
        return row

    async def list(
        self,
        *,
        limit: int = 100,
        status: str | None = None,
        application: str | None = None,
        environment: str | None = None,
        incident_id: UUID | None = None,
        alert_id: UUID | None = None,
    ) -> list[ObjectStorageRecord]:
        stmt = select(ObjectStorageRecord)
        if status:
            stmt = stmt.where(ObjectStorageRecord.processing_status == status)
        if application:
            stmt = stmt.where(ObjectStorageRecord.application == application)
        if environment:
            stmt = stmt.where(ObjectStorageRecord.environment == environment)
        if incident_id:
            stmt = stmt.where(ObjectStorageRecord.incident_id == incident_id)
        if alert_id:
            stmt = stmt.where(ObjectStorageRecord.alert_id == alert_id)
        result = await self.session.execute(stmt.order_by(ObjectStorageRecord.created_at.desc()).limit(max(1, min(int(limit), 500))))
        return list(result.scalars().all())

    async def get(self, object_id: UUID) -> ObjectStorageRecord | None:
        return (await self.session.execute(select(ObjectStorageRecord).where(ObjectStorageRecord.id == object_id))).scalar_one_or_none()

    async def retention_candidates(self, *, before: datetime, limit: int = 500) -> list[ObjectStorageRecord]:
        stmt = (
            select(ObjectStorageRecord)
            .where(
                ObjectStorageRecord.processing_status == "stored",
                ObjectStorageRecord.ingested_at.is_not(None),
                ObjectStorageRecord.ingested_at < before,
            )
            .order_by(ObjectStorageRecord.ingested_at.asc())
            .limit(max(1, min(int(limit), 5000)))
        )
        return list((await self.session.execute(stmt)).scalars().all())

    async def mark_deleted(self, row: ObjectStorageRecord, *, deleted_at: datetime) -> None:
        row.processing_status = "deleted"
        row.metadata_payload = {**(row.metadata_payload or {}), "deleted_at": deleted_at.isoformat()}
        await self.session.flush()
from common.models import (
    Alert,
    ApplicationRegistration,
    Approval,
    ApprovalDecision,
    GrafanaDashboardResult,
    Incident,
    MetricsValidationResult,
    MonitoringAuditEvent,
    MonitoringValidationResult,
    PrometheusUpdateResult,
    Recommendation,
    RemediationAction,
    ResolutionReport,
    RulesGeneratedResult,
    utc_now,
)

_PLACEHOLDER_TOKENS = {"", "-", "n/a", "na", "none", "null", "unknown"}
_PENDING_DECISIONS = {"PENDING", "QUEUED", "AWAITING_APPROVAL", "AWAITING USER APPROVAL", "STANDBY"}
_STATUS_PRECEDENCE = {
    "unknown": 0,
    "open": 1,
    "investigating": 2,
    "waiting_for_human": 2,
    # A grounded, conclusive RCA with no ready-to-execute plan yet (see
    # resolution-agent's _resolution_projection_status) -- real forward
    # progress past "investigating", not yet in the approval/execution flow.
    "rca_ready": 3,
    "awaiting_approval": 4,
    # Was missing entirely (rank 0, same as "unknown") despite
    # _resolution_projection_status emitting it -- an approved-but-not-yet-
    # remediating event could regress the projection back below
    # "awaiting_approval" on the monotonic-timestamp-tie guard.
    "approved": 5,
    "remediating": 6,
    "validating": 7,
    "failed": 8,
    "closed": 9,
}
_CLOSED_INCIDENT_STATUSES = frozenset({"closed", "resolved", "cancelled", "canceled"})

_EVENT_TABLE_HINTS: dict[str, list[str]] = {
    "incident.alert.enriched": ["alerts", "incidents", "agent_work_items"],
    "incident.workflow.selected": ["incident_events", "incident_projections", "agent_work_items"],
    "incident.context.collected": ["incident_events", "incident_projections", "agent_work_items"],
    "incident.recommendation.generated": ["incident_events", "audit_logs", "incident_projections", "agent_work_items"],
    "incident.approval.requested": ["incident_events", "approvals", "incident_projections", "agent_work_items"],
    "incident.approval.recorded": ["incident_events", "approvals", "incident_projections", "agent_work_items"],
    "incident.remediation.executed": ["incident_events", "actions", "incident_projections", "agent_work_items"],
    "incident.closure.completed": ["incident_events", "rca_reports", "incident_projections", "agent_work_items"],
}


_DISCOVERY_DEFAULT_CODE_ROOT = "/app/fault-lab"
_DISCOVERY_DEFAULT_LOG_ROOT = "/app/fault-lab/runtime"



def _is_meaningful_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in _PLACEHOLDER_TOKENS
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) > 0
    return True


def _event_quality_score(event: dict[str, Any]) -> int:
    score = 0
    decision = str(event.get("decision") or "").strip()
    decision_token = decision.upper()
    if _is_meaningful_value(decision):
        score += 2
    if decision_token and decision_token not in _PENDING_DECISIONS:
        score += 8
    if _is_meaningful_value(event.get("output")):
        score += 3
    if _is_meaningful_value(event.get("action")):
        score += 2
    if isinstance(event.get("input"), dict) and event.get("input"):
        score += 1
    if isinstance(event.get("metrics"), dict) and event.get("metrics"):
        score += 1
    return score


def _merge_events(group: list[dict[str, Any]]) -> dict[str, Any]:
    if len(group) == 1:
        return dict(group[0])

    merged = dict(max(group, key=_event_quality_score))

    for item in group:
        for field in ("action", "decision", "output", "communicates_to"):
            if not _is_meaningful_value(merged.get(field)) and _is_meaningful_value(item.get(field)):
                merged[field] = item.get(field)

        for object_field in ("input", "metrics"):
            existing = merged.get(object_field)
            incoming = item.get(object_field)
            if isinstance(existing, dict) and isinstance(incoming, dict):
                for key, value in incoming.items():
                    if key not in existing and _is_meaningful_value(value):
                        existing[key] = value
            elif (not isinstance(existing, dict) or not existing) and isinstance(incoming, dict) and incoming:
                merged[object_field] = dict(incoming)

    llm_calls: list[Any] = []
    llm_errors: list[Any] = []
    for item in group:
        if isinstance(item.get("llm_calls"), list):
            llm_calls.extend(item.get("llm_calls") or [])
        if isinstance(item.get("llm_errors"), list):
            llm_errors.extend(item.get("llm_errors") or [])
    if llm_calls:
        merged["llm_calls"] = llm_calls
    if llm_errors:
        merged["llm_errors"] = llm_errors

    return merged


def _normalize_match_token(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "").strip().lower())


def _collect_alert_application_tokens(alert_payload: dict[str, Any]) -> list[str]:
    labels = alert_payload.get("labels", {}) if isinstance(alert_payload.get("labels"), dict) else {}
    candidates = [
        alert_payload.get("application"),
        alert_payload.get("project"),
        alert_payload.get("project_name"),
        alert_payload.get("service"),
        labels.get("application"),
        labels.get("project"),
        labels.get("project_name"),
        labels.get("namespace"),
        labels.get("job"),
    ]
    rows = [str(value or "").strip() for value in candidates if str(value or "").strip()]
    deduped: list[str] = []
    seen: set[str] = set()
    for value in rows:
        token = _normalize_match_token(value)
        if not token or token in seen:
            continue
        seen.add(token)
        deduped.append(value)
    return deduped


def _short_snippet(value: Any, limit: int = 520) -> str:
    compact = re.sub(r"\s+", " ", str(value or "").strip())
    if len(compact) <= limit:
        return compact
    return f"{compact[:limit]}..."


def _make_discovery_evidence_row(source: str, uri: str, snippet: str, matched_terms: list[str]) -> dict[str, Any]:
    payload = f"{source}|{uri}|{snippet}"
    digest = hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return {
        "evidence_id": f"{source.upper()}-{digest}",
        "source": source,
        "uri": uri,
        "path": uri.split("://", 1)[-1].split("#", 1)[0],
        "line": 1,
        "snippet": _short_snippet(snippet),
        "matched_terms": matched_terms,
        "sha256": hashlib.sha256(snippet.encode("utf-8", errors="ignore")).hexdigest(),
    }


def _build_discovery_contract(
    *,
    alert_payload: dict[str, Any],
    recommendation: dict[str, Any],
    recommendation_metadata: dict[str, Any],
    matched_application_payload: dict[str, Any],
    onboarding_rows: list[OnboardingStateRecord],
    existing_rag_documents: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    labels = alert_payload.get("labels", {}) if isinstance(alert_payload.get("labels"), dict) else {}
    service = str(alert_payload.get("service") or labels.get("service") or "unknown-service").strip()
    alert_name = str(alert_payload.get("name") or labels.get("alertname") or "incident-alert").strip()
    environment = str(alert_payload.get("environment") or labels.get("environment") or "prod").strip()
    application_tokens = _collect_alert_application_tokens(alert_payload)
    query_terms = [service, alert_name, environment, *application_tokens]
    query_terms = [item for item in query_terms if item]

    discovery_payload = (
        matched_application_payload.get("discovery")
        if isinstance(matched_application_payload.get("discovery"), dict)
        else {}
    )
    discovery_labels = (
        discovery_payload.get("labels") if isinstance(discovery_payload.get("labels"), dict) else {}
    )
    discovered_resources = (
        discovery_payload.get("discovered_resources")
        if isinstance(discovery_payload.get("discovered_resources"), list)
        else []
    )

    discovered_services = [
        str(item.get("name") or "").strip()
        for item in discovered_resources
        if isinstance(item, dict) and str(item.get("kind") or "").strip().lower() == "discoveredservice"
    ]
    discovered_services = [item for item in discovered_services if item]
    discovered_languages = [
        item.strip()
        for item in str(discovery_labels.get("discovered_languages") or "").split(",")
        if item.strip()
    ]
    codebase_root = str(discovery_labels.get("codebase_root") or _DISCOVERY_DEFAULT_CODE_ROOT).strip()
    files_scanned = str(discovery_labels.get("codebase_files_scanned") or "").strip() or "0"
    log_error_count = str(discovery_labels.get("log_error_count") or "0").strip() or "0"
    alert_names = [
        item.strip()
        for item in str(discovery_labels.get("discovered_alert_names") or "").split(",")
        if item.strip()
    ]

    onboarding_inputs: list[str] = []
    onboarding_roots: list[str] = []
    for row in onboarding_rows:
        if row.endpoint_url:
            onboarding_roots.append(str(row.endpoint_url))
        project_payload = row.project_payload if isinstance(row.project_payload, dict) else {}
        connectivity_payload = row.connectivity_payload if isinstance(row.connectivity_payload, dict) else {}
        source_docs = project_payload.get("source_documents") if isinstance(project_payload.get("source_documents"), list) else []
        if source_docs:
            for item in source_docs[:20]:
                if not isinstance(item, dict):
                    continue
                kind = str(item.get("kind") or "other").strip().lower() or "other"
                name = str(item.get("name") or "uploaded-document").strip() or "uploaded-document"
                excerpt = str(item.get("excerpt") or item.get("content") or item.get("text") or "").strip()
                onboarding_inputs.append(f"{kind}: {name} {excerpt}")
        requirements = connectivity_payload.get("result", {}).get("project", {}).get("monitoring_requirements")
        if isinstance(requirements, list) and requirements:
            onboarding_inputs.extend(str(item).strip() for item in requirements[:20] if str(item).strip())
        summary = connectivity_payload.get("summary")
        if isinstance(summary, dict):
            onboarding_inputs.append(json_dumps_safe(summary))

    rag_docs = [item for item in existing_rag_documents if isinstance(item, dict)]
    for doc in rag_docs[:20]:
        doc_title = str(doc.get("title") or doc.get("path") or "document").strip()
        doc_kind = str(doc.get("kind") or doc.get("document_kind") or "other").strip().lower()
        doc_summary = str(doc.get("summary") or doc.get("recommended_action") or "").strip()
        onboarding_inputs.append(f"{doc_kind}: {doc_title} {doc_summary}")

    code_matches: list[dict[str, Any]] = []
    if discovered_services or discovered_languages or int(files_scanned or "0") > 0:
        code_matches.append(
            {
                "service_candidates": discovered_services,
                "languages": discovered_languages,
                "files_scanned": int(files_scanned or "0"),
                "root": codebase_root,
            }
        )

    log_matches: list[dict[str, Any]] = []
    if alert_names or int(log_error_count or "0") > 0:
        log_matches.append(
            {
                "alert_names": alert_names,
                "error_count": int(log_error_count or "0"),
                "root": _DISCOVERY_DEFAULT_LOG_ROOT,
            }
        )

    ticket_matches: list[dict[str, Any]] = []
    for item in onboarding_inputs[:20]:
        ticket_matches.append({"text": _short_snippet(item, 360)})

    evidence: list[dict[str, Any]] = []
    if code_matches:
        evidence.append(
            _make_discovery_evidence_row(
                "code",
                f"code://{codebase_root}",
                f"services={','.join(discovered_services) or service}; languages={','.join(discovered_languages)}; files_scanned={files_scanned}",
                query_terms[:8],
            )
        )
    if log_matches:
        evidence.append(
            _make_discovery_evidence_row(
                "log",
                f"log://{_DISCOVERY_DEFAULT_LOG_ROOT}/application.log",
                f"error_count={log_error_count}; alert_names={','.join(alert_names) or alert_name}",
                query_terms[:8],
            )
        )
    for index, item in enumerate(onboarding_inputs[:8], start=1):
        evidence.append(
            _make_discovery_evidence_row(
                "ticket",
                f"ticket://onboarding/input#{index}",
                item,
                query_terms[:8],
            )
        )

    root_cause = str(recommendation.get("root_cause") or alert_payload.get("description") or "").strip()
    if not root_cause:
        root_cause = f"{service} is degraded according to alert {alert_name}."
    supporting = [row.get("evidence_id") for row in evidence[:4] if isinstance(row, dict) and row.get("evidence_id")]
    report = {
        "summary": f"Discovery correlated {len(evidence)} evidence item(s) across tickets, logs, codebase, and onboarding inputs for {service}.",
        "model": "kaiops-discovery-synth-v1",
        "insufficient_evidence": not bool(evidence),
        "hypotheses": [
            {
                "cause": root_cause,
                "confidence": 0.74 if evidence else 0.42,
                "supporting_evidence": supporting,
            }
        ],
    }

    retrieval_stages = [
        {"stage": "query_planned", "status": "completed", "result_count": len(query_terms)},
        {"stage": "ticket_search", "status": "completed", "result_count": len([row for row in evidence if row.get("source") == "ticket"])},
        {"stage": "log_search", "status": "completed", "result_count": len([row for row in evidence if row.get("source") == "log"])},
        {"stage": "code_search", "status": "completed", "result_count": len([row for row in evidence if row.get("source") == "code"])},
        {"stage": "onboarding_context_merge", "status": "completed", "result_count": len(onboarding_inputs)},
        {"stage": "discovery_completed", "status": "completed", "result_count": len(evidence)},
    ]

    discovery_report = {
        "protocol": "mcp-jsonrpc-2.0",
        "server": "kaiops-discovery-mcp",
        "retrieval_stages": retrieval_stages,
        "evidence": evidence,
        "report": report,
    }
    discovery_evidence = {
        "query_terms": query_terms,
        "code_roots": [codebase_root],
        "log_roots": [_DISCOVERY_DEFAULT_LOG_ROOT],
        "ticket_roots": onboarding_roots,
        "code_matches": code_matches,
        "log_matches": log_matches,
        "ticket_matches": ticket_matches,
    }
    return discovery_report, discovery_evidence


def json_dumps_safe(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return str(value)


def _deduplicate_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[int, str], list[dict[str, Any]]] = {}
    first_index: dict[tuple[int, str], int] = {}

    for index, event in enumerate(events):
        sequence = int(event.get("sequence", 0) or 0)
        agent = str(event.get("agent") or "").strip()
        key = (sequence, agent)
        grouped.setdefault(key, []).append(event)
        first_index.setdefault(key, index)

    ordered_keys = sorted(grouped.keys(), key=lambda key: (key[0], first_index.get(key, 0)))
    return [_merge_events(grouped[key]) for key in ordered_keys]


def _status_rank(status: str | None) -> int:
    token = str(status or "").strip().lower()
    return _STATUS_PRECEDENCE.get(token, 0)


def _utc_dt(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _extract_recommendation_uuid(payload: dict[str, Any] | None) -> UUID | None:
    if not isinstance(payload, dict):
        return None
    recommendation = payload.get("recommendation") if isinstance(payload.get("recommendation"), dict) else {}
    approval = payload.get("approval") if isinstance(payload.get("approval"), dict) else {}
    source_payload = payload.get("source_payload") if isinstance(payload.get("source_payload"), dict) else {}
    source_recommendation = source_payload.get("recommendation") if isinstance(source_payload.get("recommendation"), dict) else {}
    source_approval = source_payload.get("approval") if isinstance(source_payload.get("approval"), dict) else {}

    candidates = [
        payload.get("recommendation_id"),
        payload.get("recommended_action_id"),
        recommendation.get("id"),
        approval.get("recommendation_id"),
        source_payload.get("recommendation_id"),
        source_recommendation.get("id"),
        source_approval.get("recommendation_id"),
    ]
    for candidate in candidates:
        token = str(candidate or "").strip()
        if not token:
            continue
        try:
            return UUID(token)
        except ValueError:
            continue
    return None


def _extract_flow_id(payload: dict[str, Any] | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    decision = payload.get("decision") if isinstance(payload.get("decision"), dict) else {}
    event_contract = payload.get("event_contract") if isinstance(payload.get("event_contract"), dict) else {}
    source_payload = payload.get("source_payload") if isinstance(payload.get("source_payload"), dict) else {}
    source_decision = source_payload.get("decision") if isinstance(source_payload.get("decision"), dict) else {}
    source_contract = source_payload.get("event_contract") if isinstance(source_payload.get("event_contract"), dict) else {}

    candidates = [
        payload.get("flow_id"),
        decision.get("flow_id"),
        event_contract.get("flow_id"),
        source_payload.get("flow_id"),
        source_decision.get("flow_id"),
        source_contract.get("flow_id"),
    ]
    for candidate in candidates:
        token = str(candidate or "").strip()
        if token:
            return token
    return None


def _extract_document_available(payload: dict[str, Any] | None) -> bool | None:
    if not isinstance(payload, dict):
        return None
    if "document_available" not in payload:
        return None
    value = payload.get("document_available")
    return bool(value) if value is not None else None


def _extract_source_channel(payload: dict[str, Any] | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    source_event_contract = (
        payload.get("source_event_contract") if isinstance(payload.get("source_event_contract"), dict) else {}
    )
    source_payload = payload.get("source_payload") if isinstance(payload.get("source_payload"), dict) else {}
    source_payload_contract = (
        source_payload.get("event_contract") if isinstance(source_payload.get("event_contract"), dict) else {}
    )
    candidates = [
        source_event_contract.get("transport", {}).get("channel")
        if isinstance(source_event_contract.get("transport"), dict)
        else None,
        source_payload.get("transport", {}).get("channel")
        if isinstance(source_payload.get("transport"), dict)
        else None,
        source_payload_contract.get("transport", {}).get("channel")
        if isinstance(source_payload_contract.get("transport"), dict)
        else None,
    ]
    for candidate in candidates:
        token = str(candidate or "").strip()
        if token:
            return token
    return None


def _extract_query_hint(payload: dict[str, Any] | None) -> str | None:
    if not isinstance(payload, dict):
        return None

    candidate_keys = (
        "sql",
        "query",
        "statement",
        "db_query",
        "query_text",
        "lookup_query",
    )

    queue: list[Any] = [payload]
    seen: set[int] = set()
    while queue:
        item = queue.pop(0)
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, dict):
            for key in candidate_keys:
                value = item.get(key)
                token = str(value or "").strip()
                if token:
                    return token
            for value in item.values():
                if isinstance(value, (dict, list, tuple)):
                    queue.append(value)
        elif isinstance(item, (list, tuple)):
            queue.extend(item)
    return None


def _infer_table_hints(event_type: str, payload: dict[str, Any] | None) -> list[str]:
    hints = list(_EVENT_TABLE_HINTS.get(str(event_type or "").strip().lower(), []))
    if not isinstance(payload, dict):
        return hints

    query_hint = _extract_query_hint(payload)
    if query_hint:
        upper_query = query_hint.upper()
        for table in ("INCIDENT_EVENTS", "INCIDENT_PROJECTIONS", "AGENT_WORK_ITEMS", "AUDIT_LOGS", "APPROVALS", "ACTIONS", "RCA_REPORTS"):
            if table in upper_query and table.lower() not in hints:
                hints.append(table.lower())
    return hints


class IncidentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def transition_incident_lifecycle(self, **kwargs) -> dict[str, Any]:
        return await ContextEnrichmentRepository(self.session).transition_incident_lifecycle(**kwargs)

    @staticmethod
    def _require(name: str, value: Any) -> Any:
        if value is None:
            raise ValueError(f"{name} is required")
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"{name} is required")
        return value

    async def _require_write_scope(self, model, identity, *, tenant_id: str, incident_id=None):
        """A globally keyed row must never be reassigned by an upsert."""
        existing = await self.session.get(model, identity, with_for_update=True)
        if existing is not None:
            if existing.tenant_id != tenant_id:
                raise ValueError(f"{model.__tablename__} tenant binding mismatch")
            if incident_id is not None and existing.incident_id != incident_id:
                raise ValueError(f"{model.__tablename__} incident binding mismatch")
        return existing

    async def save_alert(self, alert: Alert) -> None:
        await self._require_write_scope(AlertRecord, alert.id, tenant_id=alert.tenant_id or "default")
        await self.session.merge(
            AlertRecord(
                id=self._require("alert.id", alert.id),
                tenant_id=alert.tenant_id or "default",
                source=self._require("alert.source", alert.source),
                name=self._require("alert.name", alert.name),
                service=self._require("alert.service", alert.service),
                environment=self._require("alert.environment", alert.environment),
                severity=self._require("alert.severity", alert.severity.value),
                fingerprint=alert.fingerprint,
                correlation_id=alert.correlation_id,
                payload=alert.model_dump(mode="json"),
            )
        )

    async def get_open_jira_ticket_link(self, fingerprint: str) -> dict[str, Any] | None:
        """Centralized dedup lookup: is there already an open Jira ticket
        for this alert fingerprint? Ingestion paths (Prometheus/log/email)
        call this before deciding whether to create a new Jira issue or
        comment on the existing one."""
        result = await self.session.execute(
            select(JiraTicketLinkRecord).where(
                JiraTicketLinkRecord.fingerprint == self._require("fingerprint", fingerprint),
                JiraTicketLinkRecord.status == "open",
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return {
            "fingerprint": row.fingerprint,
            "jira_issue_key": row.jira_issue_key,
            "status": row.status,
            "source": row.source,
            "occurrence_count": row.occurrence_count,
            "first_seen_at": row.first_seen_at,
            "last_seen_at": row.last_seen_at,
        }

    async def save_jira_ticket_link(self, *, fingerprint: str, jira_issue_key: str, source: str) -> None:
        """Records a newly-created Jira issue against its alert fingerprint."""
        now = utc_now()
        await self.session.merge(
            JiraTicketLinkRecord(
                id=uuid4(),
                fingerprint=self._require("fingerprint", fingerprint),
                jira_issue_key=self._require("jira_issue_key", jira_issue_key),
                status="open",
                source=self._require("source", source),
                occurrence_count=1,
                first_seen_at=now,
                last_seen_at=now,
            )
        )

    async def bump_jira_ticket_occurrence(self, fingerprint: str) -> None:
        """Records a repeat occurrence against an already-open Jira ticket
        (a comment was added rather than a new issue created)."""
        result = await self.session.execute(
            select(JiraTicketLinkRecord).where(JiraTicketLinkRecord.fingerprint == self._require("fingerprint", fingerprint))
        )
        row = result.scalar_one_or_none()
        if row is None:
            return
        row.occurrence_count += 1
        row.last_seen_at = utc_now()

    async def close_jira_ticket_link(self, jira_issue_key: str) -> None:
        """Marks the link closed once the Jira ticket itself is resolved/closed,
        so the next occurrence of the same fingerprint opens a fresh ticket
        instead of commenting on a closed one."""
        result = await self.session.execute(
            select(JiraTicketLinkRecord).where(JiraTicketLinkRecord.jira_issue_key == self._require("jira_issue_key", jira_issue_key))
        )
        row = result.scalar_one_or_none()
        if row is None:
            return
        row.status = "closed"

    async def list_alerts(
        self,
        limit: int = 500,
        include_incident_context: bool = True,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 200))
        alert_ids_query = select(AlertRecord.id)
        if tenant_id is not None:
            alert_ids_query = alert_ids_query.where(AlertRecord.tenant_id == self._require("tenant_id", tenant_id))
        alert_ids_result = await self.session.execute(alert_ids_query.order_by(AlertRecord.created_at.desc()).limit(safe_limit))
        alert_ids = [row[0] for row in alert_ids_result.all()]
        if not alert_ids:
            return []

        result = await self.session.execute(
            select(AlertRecord)
            .options(load_only(AlertRecord.id, AlertRecord.payload, AlertRecord.created_at, AlertRecord.updated_at))
            .where(AlertRecord.id.in_(alert_ids))
        )
        rows_by_id = {row.id: row for row in result.scalars().all()}
        rows = [rows_by_id[alert_id] for alert_id in alert_ids if alert_id in rows_by_id]
        if not rows:
            return []

        if not include_incident_context:
            return [dict(row.payload) if isinstance(row.payload, dict) else {} for row in rows]

        alert_id_set = {str(row.id) for row in rows}
        alert_to_incident: dict[str, str] = {}

        # Incident payload carries linked alert IDs. Build a reverse map to incident IDs,
        # preferring most recent incidents by updated timestamp.
        incident_ids_query = select(IncidentRecord.id).order_by(IncidentRecord.created_at.desc())
        if tenant_id is not None:
            incident_ids_query = incident_ids_query.where(IncidentRecord.tenant_id == self._require("tenant_id", tenant_id))
        incident_ids_result = await self.session.execute(
            incident_ids_query.limit(min(500, max(150, safe_limit * 3)))
        )
        incident_ids = [row[0] for row in incident_ids_result.all()]
        incident_result = await self.session.execute(
            select(IncidentRecord)
            .options(load_only(IncidentRecord.id, IncidentRecord.payload))
            .where(IncidentRecord.id.in_(incident_ids))
            .limit(min(500, max(150, safe_limit * 3)))
        )
        for incident in incident_result.scalars().all():
            payload = incident.payload if isinstance(incident.payload, dict) else {}
            linked_alert_ids = payload.get("alert_ids", []) if isinstance(payload.get("alert_ids"), list) else []
            for item in linked_alert_ids:
                alert_id = str(item)
                if alert_id in alert_id_set and alert_id not in alert_to_incident:
                    alert_to_incident[alert_id] = str(incident.id)

        projection_status_by_incident: dict[str, str] = {}
        projection_document_available_by_incident: dict[str, bool | None] = {}
        projection_incident_ids = {
            self._parse_uuid(incident_id)
            for incident_id in alert_to_incident.values()
            if self._parse_uuid(incident_id) is not None
        }
        if projection_incident_ids:
            projection_result = await self.session.execute(
                select(IncidentProjectionRecord)
                .options(load_only(
                    IncidentProjectionRecord.incident_id,
                    IncidentProjectionRecord.status,
                    IncidentProjectionRecord.document_available
                ))
                .where(IncidentProjectionRecord.incident_id.in_(projection_incident_ids))
            )
            for projection in projection_result.scalars().all():
                incident_key = str(projection.incident_id)
                projection_status_by_incident[incident_key] = str(projection.status or "").strip()
                projection_document_available_by_incident[incident_key] = projection.document_available

        enriched_rows: list[dict[str, Any]] = []
        for row in rows:
            payload = dict(row.payload) if isinstance(row.payload, dict) else {}
            alert_id = str(row.id)
            incident_id = str(payload.get("incident_id") or "").strip() or alert_to_incident.get(alert_id)
            if incident_id:
                payload["incident_id"] = incident_id
                projection_status = projection_status_by_incident.get(incident_id)
                if projection_status:
                    payload["status"] = projection_status
                    payload["state"] = projection_status
                if incident_id in projection_document_available_by_incident:
                    payload["document_available"] = projection_document_available_by_incident[incident_id]
            enriched_rows.append(payload)

        return enriched_rows

    async def list_alerts_source_balanced(self, limit: int = 500, tenant_id: str | None = None) -> list[dict[str, Any]]:
        """Return recent alerts while reserving the latest row per durable source.

        A global LIMIT alone lets bursty sources crowd low-volume sources out of
        the intake UI. This performs one indexed latest-row lookup per distinct
        source and fills the rest from the normal recent window.

        `tenant_id`: when provided, scopes every query to that tenant only
        (backed by idx_alerts_tenant). None returns across all tenants, which
        callers should only do for internal/trusted contexts, not for a
        caller-facing list endpoint.
        """
        safe_limit = max(1, min(int(limit), 200))
        sources_query = select(AlertRecord.source).distinct()
        if tenant_id is not None:
            sources_query = sources_query.where(AlertRecord.tenant_id == tenant_id)
        sources_result = await self.session.execute(sources_query)
        sources = [str(row[0] or "").strip() for row in sources_result.all() if str(row[0] or "").strip()]

        reserved: list[AlertRecord] = []
        for source in sources:
            query = (
                select(AlertRecord)
                .options(load_only(AlertRecord.id, AlertRecord.payload, AlertRecord.created_at))
                .where(AlertRecord.source == source)
            )
            if tenant_id is not None:
                query = query.where(AlertRecord.tenant_id == tenant_id)
            result = await self.session.execute(query.order_by(AlertRecord.created_at.desc()).limit(1))
            record = result.scalar_one_or_none()
            if record is not None:
                reserved.append(record)

        recent_query = select(AlertRecord).options(
            load_only(AlertRecord.id, AlertRecord.payload, AlertRecord.created_at)
        )
        if tenant_id is not None:
            recent_query = recent_query.where(AlertRecord.tenant_id == tenant_id)
        recent_result = await self.session.execute(
            recent_query.order_by(AlertRecord.created_at.desc()).limit(safe_limit)
        )
        recent = list(recent_result.scalars().all())
        selected: list[AlertRecord] = []
        seen: set[UUID] = set()
        for record in [*reserved, *recent]:
            if record.id in seen:
                continue
            seen.add(record.id)
            selected.append(record)
        selected = sorted(selected, key=lambda row: row.created_at, reverse=True)

        # Preserve source reservations even when source count approaches limit.
        reserved_ids = {row.id for row in reserved}
        output = [row for row in selected if row.id in reserved_ids]
        output.extend(row for row in selected if row.id not in reserved_ids)
        output = sorted(output[:safe_limit], key=lambda row: row.created_at, reverse=True)
        alert_ids = {str(row.id) for row in output}
        incident_by_alert: dict[str, dict[str, Any]] = {}
        incident_query = (
            select(IncidentRecord)
            .options(load_only(IncidentRecord.id, IncidentRecord.ticket_id, IncidentRecord.payload))
            .order_by(IncidentRecord.created_at.desc())
            .limit(min(500, max(150, safe_limit * 3)))
        )
        if tenant_id is not None:
            incident_query = incident_query.where(IncidentRecord.tenant_id == tenant_id)
        incident_result = await self.session.execute(incident_query)
        for incident in incident_result.scalars().all():
            incident_payload = incident.payload if isinstance(incident.payload, dict) else {}
            linked_alert_ids = incident_payload.get("alert_ids", [])
            if not isinstance(linked_alert_ids, list):
                continue
            for linked_alert_id in linked_alert_ids:
                alert_id = str(linked_alert_id)
                if alert_id in alert_ids and alert_id not in incident_by_alert:
                    incident_by_alert[alert_id] = {
                        "incident_id": str(incident.id),
                        "ticket_id": str(incident.ticket_id or "").strip() or None,
                    }

        rows: list[dict[str, Any]] = []
        for record in output:
            payload = dict(record.payload) if isinstance(record.payload, dict) else {}
            payload.update({key: value for key, value in incident_by_alert.get(str(record.id), {}).items() if value})
            metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            deduplication = metadata.get("deduplication") if isinstance(metadata.get("deduplication"), dict) else {}
            payload["incident_disposition"] = str(
                deduplication.get("disposition")
                or ("duplicate" if int(payload.get("deduplicated_count") or 1) > 1 else "new_incident")
            )
            rows.append(payload)
        return rows

    async def update_projection_document_flag(self, alert_id: str, available: bool) -> bool:
        """Set incident_projections.document_available for the incident linked to alert_id.

        Used after a user uploads a document for an alert so the landing page
        reflects availability immediately, without waiting for context re-collection.
        """
        parsed_alert_id = self._parse_uuid(alert_id)
        if parsed_alert_id is None:
            return False
        result = await self.session.execute(
            select(IncidentProjectionRecord)
            .where(IncidentProjectionRecord.alert_id == parsed_alert_id)
            .order_by(IncidentProjectionRecord.latest_event_at.desc())
        )
        projection = result.scalars().first()
        if projection is None:
            return False
        projection.document_available = available
        await self.session.merge(projection)
        return True

    async def get_processed_result_by_alert_id(
        self,
        alert_id: str,
        *,
        tenant_id: str,
    ) -> dict[str, Any] | None:
        normalized_alert_id = str(alert_id or "").strip()
        if not normalized_alert_id:
            return None
        normalized_tenant_id = self._require("tenant_id", tenant_id)

        try:
            alert_uuid = UUID(normalized_alert_id)
        except ValueError:
            return None

        alert_result = await self.session.execute(
            select(AlertRecord).where(
                AlertRecord.id == alert_uuid,
                AlertRecord.tenant_id == normalized_tenant_id,
            )
        )
        alert_record = alert_result.scalar_one_or_none()
        if alert_record is None:
            return None

        alert_payload = alert_record.payload if isinstance(alert_record.payload, dict) else {}
        alert_labels = alert_payload.get("labels") if isinstance(alert_payload.get("labels"), dict) else {}
        explicit_incident_id = str(
            alert_payload.get("incident_id")
            or alert_labels.get("kaiops_incident_id")
            or ""
        ).strip()

        incident_record = None
        explicit_incident_uuid = self._parse_uuid(explicit_incident_id)
        if explicit_incident_uuid is not None:
            explicit_result = await self.session.execute(
                select(IncidentRecord).where(
                    IncidentRecord.id == explicit_incident_uuid,
                    IncidentRecord.tenant_id == normalized_tenant_id,
                )
            )
            incident_record = explicit_result.scalar_one_or_none()

        if incident_record is None:
            # The projection is the authoritative alert-to-incident relation.
            # Repeated alerts for the same service/Jira may have many incident
            # records, so a service/severity fallback can hydrate an alert with
            # a newer, still-investigating incident and hide its persisted RCA.
            projection_result = await self.session.execute(
                select(IncidentProjectionRecord)
                .where(
                    IncidentProjectionRecord.alert_id == alert_uuid,
                    IncidentProjectionRecord.tenant_id == normalized_tenant_id,
                )
                .order_by(
                    IncidentProjectionRecord.latest_event_at.desc(),
                    IncidentProjectionRecord.updated_at.desc(),
                )
                .limit(1)
            )
            projection_record = projection_result.scalar_one_or_none()
            projection_incident_uuid = self._parse_uuid(
                getattr(projection_record, "incident_id", None)
            )
            if projection_incident_uuid is not None:
                projection_incident_result = await self.session.execute(
                    select(IncidentRecord).where(
                        IncidentRecord.id == projection_incident_uuid,
                        IncidentRecord.tenant_id == normalized_tenant_id,
                    )
                )
                incident_record = projection_incident_result.scalar_one_or_none()

        if incident_record is None:
            occurrence_result = await self.session.execute(
                select(IncidentOccurrenceRecord)
                .where(
                    IncidentOccurrenceRecord.occurrence_id == alert_uuid,
                    IncidentOccurrenceRecord.tenant_id == normalized_tenant_id,
                )
                .order_by(IncidentOccurrenceRecord.observed_at.desc())
                .limit(1)
            )
            occurrence_record = occurrence_result.scalar_one_or_none()
            if occurrence_record is not None:
                occurrence_incident_result = await self.session.execute(
                    select(IncidentRecord).where(
                        IncidentRecord.id == occurrence_record.canonical_incident_id,
                        IncidentRecord.tenant_id == normalized_tenant_id,
                    )
                )
                incident_record = occurrence_incident_result.scalar_one_or_none()

        if incident_record is None:
            incident_rows = await self.session.execute(
                select(IncidentRecord)
                .where(IncidentRecord.tenant_id == normalized_tenant_id)
                .order_by(IncidentRecord.updated_at.desc(), IncidentRecord.created_at.desc())
                .limit(300)
            )
            for record in incident_rows.scalars().all():
                payload = record.payload if isinstance(record.payload, dict) else {}
                linked_alert_ids = payload.get("alert_ids", []) if isinstance(payload.get("alert_ids"), list) else []
                linked_as_strings = {str(item) for item in linked_alert_ids}
                if normalized_alert_id in linked_as_strings:
                    incident_record = record
                    break

        if incident_record is None:
            alert_tokens = {_normalize_match_token(item) for item in _collect_alert_application_tokens(alert_payload)}

            app_result = await self.session.execute(
                select(ApplicationRecord)
                .where(ApplicationRecord.tenant_id == normalized_tenant_id)
                .order_by(ApplicationRecord.updated_at.desc())
                .limit(500)
            )
            matched_application_payload: dict[str, Any] = {}
            for app_row in app_result.scalars().all():
                app_name = str(getattr(app_row, "name", "") or "").strip()
                app_namespace = str(getattr(app_row, "namespace", "") or "").strip()
                app_tokens = {_normalize_match_token(app_name), _normalize_match_token(app_namespace)}
                if not (alert_tokens & {token for token in app_tokens if token}):
                    continue
                matched_application_payload = app_row.payload if isinstance(app_row.payload, dict) else {}
                break

            onboarding_result = await self.session.execute(
                select(OnboardingStateRecord)
                .where(OnboardingStateRecord.tenant_id == normalized_tenant_id)
                .order_by(OnboardingStateRecord.updated_at.desc())
                .limit(500)
            )
            matched_onboarding_rows: list[OnboardingStateRecord] = []
            for onboarding_row in onboarding_result.scalars().all():
                project_token = _normalize_match_token(getattr(onboarding_row, "project_name", ""))
                if project_token and project_token in alert_tokens:
                    matched_onboarding_rows.append(onboarding_row)

            discovery_report, discovery_evidence = _build_discovery_contract(
                alert_payload=alert_payload,
                recommendation={},
                recommendation_metadata={},
                matched_application_payload=matched_application_payload,
                onboarding_rows=matched_onboarding_rows,
                existing_rag_documents=[],
            )

            service_name = str(alert_payload.get("service") or "selected service").strip() or "selected service"
            hypotheses = discovery_report.get("hypotheses") if isinstance(discovery_report.get("hypotheses"), list) else []
            first_hypothesis = hypotheses[0] if hypotheses and isinstance(hypotheses[0], dict) else {}
            evidence_ids = [
                str(item.get("evidence_id"))
                for item in discovery_evidence
                if isinstance(item, dict) and str(item.get("evidence_id") or "").strip()
            ]
            fallback_root_cause = str(first_hypothesis.get("cause") or "").strip() or (
                f"RCA pending: evidence for {service_name} has been collected but no validated causal conclusion exists yet."
            )
            fallback_impact = (
                f"No direct customer or service impact is established by the collected evidence for {service_name}; "
                "validate availability, latency, error rate, and dependency health before assigning impact."
            )
            recommendation = {
                "id": str(uuid4()),
                "incident_id": None,
                "root_cause": fallback_root_cause,
                "impact": fallback_impact,
                "recommended_action": "Review discovery evidence, verify logs and linked tickets, then run the approved remediation runbook.",
                "confidence": min(float(first_hypothesis.get("confidence") or 0.0), 0.49),
                "metadata": {
                    "fallback": True,
                    "fallback_reason": "No linked incident projection exists for this alert yet.",
                    "discovery_report": discovery_report,
                    "discovery_evidence": discovery_evidence,
                    "rca_analysis": {
                        "root_cause": fallback_root_cause,
                        "evidence_used": evidence_ids,
                        "confidence_score": min(float(first_hypothesis.get("confidence") or 0.0), 0.49),
                        "missing_evidence": ["A linked incident projection and Resolution Agent result are not available yet."],
                    },
                    "impact_analysis": {
                        "impact_summary": fallback_impact,
                        "evidence_used": [],
                        "confidence_score": 0.0,
                        "missing_evidence": ["No direct service or customer-impact measurement was cited."],
                    },
                    "model_usage": [],
                },
            }
            context_payload = {
                "deployment": "unknown",
                "related_incidents": [],
                "dependency_services": [],
                "document_available": False,
                "metadata": {
                    "discovery_report": discovery_report,
                    "discovery_evidence": discovery_evidence,
                },
            }
            return {
                "mode": "alert-only-fallback",
                "scenario": {
                    "id": "alert-only",
                    "title": str(alert_payload.get("name") or "Alert"),
                    "recommended_action": recommendation["recommended_action"],
                },
                "alert": alert_payload,
                "incident": {
                    "id": None,
                    "status": str(alert_payload.get("status") or alert_payload.get("state") or "investigating"),
                    "service": alert_payload.get("service"),
                    "severity": alert_payload.get("severity"),
                    "created_at": alert_payload.get("created_at"),
                },
                "decision": {
                    "workflow": "guided-remediation",
                    "requires_approval": True,
                    "risk_tier": "high",
                    "execution_mode": "supervised",
                    "policy_version": "policy-v1",
                    "policy_reason": "Incident projection unavailable; requiring supervised path.",
                    "message_bus_provider": "rabbitmq",
                    "stream_count": 0,
                    "stream_threshold": 0,
                    "planner_used": False,
                    "planner_model": None,
                    "planner_reason": "fallback path",
                },
                "context": context_payload,
                "recommendation": recommendation,
                "investigation_integrity": {
                    "status": "missing_recommendation",
                    "verified": False,
                    "blocking_reasons": ["alert is not linked to a persisted incident recommendation"],
                    "recommendation_id": None,
                    "context_snapshot_id": None,
                },
                "approval": {},
                "remediation_action": {},
                "closure_report": {},
                "metrics": {
                    "severity": str(alert_payload.get("severity") or "unknown").upper(),
                    "remediation_status": "unknown",
                    "health_restored": False,
                    "alerts_cleared": False,
                    "recommendation_confidence": float(recommendation.get("confidence", 0.0) or 0.0),
                    "agent_handoffs": 0,
                },
                "finops": {
                    "totals": {
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "total_tokens": 0,
                        "total_cost_usd": 0.0,
                        "calls": 0,
                        "failed_calls": 0,
                    },
                    "by_provider": [],
                    "calls": [],
                    "errors": [],
                    "currency": "USD",
                },
                "events": [],
                "event_trace": [],
                "trace_summary": {
                    "services_called": [],
                    "channels": [],
                    "tables_touched": [],
                    "event_count": 0,
                },
                "next_step": "Discovery context loaded from onboarding inputs, ticket/log/code evidence, and alert metadata while incident projection is pending.",
            }

        incident_payload = dict(incident_record.payload) if isinstance(incident_record.payload, dict) else {}
        incident_id_str = str(incident_record.id)
        incident_payload["id"] = incident_id_str
        incident_payload["status"] = incident_record.status
        incident_payload["severity"] = incident_record.severity
        incident_payload["service"] = incident_record.service
        incident_payload["environment"] = incident_record.environment
        incident_payload["title"] = incident_record.title
        ticket_id = incident_record.ticket_id or incident_payload.get("ticket_id") or ""
        incident_payload["ticket_id"] = ticket_id or None

        import os
        jira_base = str(os.environ.get("JIRA_URL") or os.environ.get("JIRA_API_BASE_URL") or "").rstrip("/")
        jira_link = f"{jira_base}/browse/{ticket_id}" if (ticket_id and jira_base) else None
        incident_payload["jira_link"] = jira_link
        # jira_key/jira_url alias the same value under the naming convention
        # alert-intelligence and the incident list UI already use.
        incident_payload["jira_key"] = ticket_id or None
        incident_payload["jira_url"] = jira_link

        status_lower = str(incident_record.status or "").strip().lower()
        if status_lower in {"closed", "resolved", "done"}:
            jira_status = "Done"
        elif status_lower in {"pending", "awaiting_approval"}:
            jira_status = "Awaiting Approval"
        else:
            jira_status = "In Progress"
        incident_payload["jira_status"] = jira_status


        # RCA is canonical at incident scope. A duplicate occurrence has its
        # own alert id but intentionally does not create another investigation
        # binding. Resolve the newest incident binding first so every linked
        # occurrence renders the same RCA, impact, and context snapshot.
        current_binding = (
            await self.session.execute(
                select(IncidentInvestigationBindingRecord)
                .where(
                    IncidentInvestigationBindingRecord.tenant_id == normalized_tenant_id,
                    IncidentInvestigationBindingRecord.incident_id == incident_record.id,
                )
                .order_by(
                    IncidentInvestigationBindingRecord.rca_version.desc(),
                    IncidentInvestigationBindingRecord.created_at.desc(),
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        canonical_alert_uuid = current_binding.alert_id if current_binding is not None else alert_uuid
        bound_projection = (
            await self.session.execute(
                select(IncidentProjectionRecord)
                .where(
                    IncidentProjectionRecord.incident_id == incident_record.id,
                    IncidentProjectionRecord.alert_id == canonical_alert_uuid,
                    IncidentProjectionRecord.tenant_id == normalized_tenant_id,
                )
                .order_by(
                    IncidentProjectionRecord.latest_event_at.desc(),
                    IncidentProjectionRecord.updated_at.desc(),
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        current_recommendation_id = (
            current_binding.recommendation_id
            if current_binding is not None
            else bound_projection.recommendation_id if bound_projection is not None else None
        )
        bound_investigation = await self.get_bound_incident_investigation(
            tenant_id=normalized_tenant_id,
            incident_id=incident_record.id,
            alert_id=canonical_alert_uuid,
            recommendation_id=current_recommendation_id,
        )
        recommendation = dict(bound_investigation.get("recommendation") or {})
        investigation_integrity = dict(
            bound_investigation.get("investigation_integrity") or {}
        )
        current_plan_id = current_binding.resolution_plan_id if current_binding is not None else None
        current_plan_fingerprint = current_binding.plan_fingerprint if current_binding is not None else None

        approval = {}
        approval_stmt = select(ApprovalRecord).where(
                ApprovalRecord.incident_id == UUID(incident_id_str),
                ApprovalRecord.tenant_id == normalized_tenant_id,
            )
        if current_recommendation_id is not None:
            approval_stmt = approval_stmt.where(
                ApprovalRecord.recommendation_id == current_recommendation_id
            )
        if current_plan_id is not None and current_plan_fingerprint:
            approval_stmt = approval_stmt.where(
                ApprovalRecord.plan_id == current_plan_id,
                ApprovalRecord.plan_fingerprint == current_plan_fingerprint,
            )
        else:
            # An approval cannot be current before an immutable governed plan exists.
            approval_stmt = approval_stmt.where(ApprovalRecord.id.is_(None))
        approval_result = await self.session.execute(
            approval_stmt
            .order_by(ApprovalRecord.updated_at.desc(), ApprovalRecord.created_at.desc())
            .limit(1)
        )
        approval_record = approval_result.scalar_one_or_none()
        if approval_record is not None and isinstance(approval_record.payload, dict):
            approval = approval_record.payload

        remediation_action = {}
        action_stmt = select(ActionRecord).where(ActionRecord.id.is_(None))
        if approval_record is not None and current_plan_id is not None and current_plan_fingerprint:
            action_stmt = select(ActionRecord).where(
                ActionRecord.incident_id == UUID(incident_id_str),
                ActionRecord.tenant_id == normalized_tenant_id,
                ActionRecord.recommendation_id == current_recommendation_id,
                ActionRecord.resolution_plan_id == current_plan_id,
                ActionRecord.plan_fingerprint == current_plan_fingerprint,
                ActionRecord.approval_id == approval_record.id,
            )
        action_result = await self.session.execute(
            action_stmt.order_by(ActionRecord.updated_at.desc(), ActionRecord.created_at.desc()).limit(1)
        )
        action_record = action_result.scalar_one_or_none()
        if action_record is not None and isinstance(action_record.payload, dict):
            remediation_action = action_record.payload

        closure_report = {}
        report_stmt = select(RcaReportRecord).where(RcaReportRecord.id.is_(None))
        if action_record is not None and approval_record is not None:
            report_stmt = select(RcaReportRecord).where(
                RcaReportRecord.incident_id == UUID(incident_id_str),
                RcaReportRecord.tenant_id == normalized_tenant_id,
                RcaReportRecord.recommendation_id == current_recommendation_id,
                RcaReportRecord.resolution_plan_id == current_plan_id,
                RcaReportRecord.plan_fingerprint == current_plan_fingerprint,
                RcaReportRecord.approval_id == approval_record.id,
                RcaReportRecord.remediation_action_id == action_record.id,
            )
        report_result = await self.session.execute(
            report_stmt.order_by(RcaReportRecord.updated_at.desc(), RcaReportRecord.created_at.desc()).limit(1)
        )
        report_record = report_result.scalar_one_or_none()
        if incident_record.status in {"closed", "resolved"}:
            administrative_report = await self.committed_non_execution_closure_report(
                tenant_id=normalized_tenant_id, incident_id=incident_record.id,
            )
            if administrative_report is not None:
                report_record = administrative_report
        if report_record is not None and isinstance(report_record.payload, dict):
            closure_report = report_record.payload

        legacy_actions_result = await self.session.execute(
            select(ActionRecord).where(
                ActionRecord.incident_id == UUID(incident_id_str),
                ActionRecord.tenant_id == normalized_tenant_id,
                or_(
                    ActionRecord.recommendation_id.is_(None),
                    ActionRecord.resolution_plan_id.is_(None),
                    ActionRecord.plan_fingerprint.is_(None),
                    ActionRecord.approval_id.is_(None),
                ),
            ).order_by(ActionRecord.updated_at.desc()).limit(50)
        )
        legacy_reports_result = await self.session.execute(
            select(RcaReportRecord).where(
                RcaReportRecord.incident_id == UUID(incident_id_str),
                RcaReportRecord.tenant_id == normalized_tenant_id,
                or_(
                    RcaReportRecord.recommendation_id.is_(None),
                    RcaReportRecord.resolution_plan_id.is_(None),
                    RcaReportRecord.plan_fingerprint.is_(None),
                    RcaReportRecord.approval_id.is_(None),
                    RcaReportRecord.remediation_action_id.is_(None),
                ),
            ).order_by(RcaReportRecord.updated_at.desc()).limit(50)
        )
        legacy_lifecycle_records = [
            {
                "record_type": "remediation_action",
                "record_id": str(row.id),
                "status": "legacy_unbound",
                "recorded_status": row.status,
                "created_at": row.created_at,
            }
            for row in legacy_actions_result.scalars().all()
        ] + [
            {
                "record_type": "closure_report",
                "record_id": str(row.id),
                "status": "legacy_unbound",
                "recorded_status": row.closure_status,
                "created_at": row.created_at,
            }
            for row in legacy_reports_result.scalars().all()
        ]

        closure_metadata = (
            closure_report.get("metadata")
            if isinstance(closure_report.get("metadata"), dict)
            else {}
        )
        processed_status = reduce_incident_status(
            projection_status=(bound_projection.status if bound_projection is not None else None),
            projection_updated_at=(bound_projection.updated_at if bound_projection is not None else None),
            canonical_status=incident_record.status,
            canonical_updated_at=incident_record.updated_at,
            approval_status=(approval_record.decision if approval_record is not None else None),
            approval_updated_at=(approval_record.updated_at if approval_record is not None else None),
            action_status=(action_record.status if action_record is not None else None),
            action_updated_at=(action_record.updated_at if action_record is not None else None),
            closure_kind=closure_metadata.get("closure_kind"),
            lifecycle_state=(bound_projection.lifecycle_state if bound_projection is not None else None),
        )
        incident_payload["status"] = processed_status["status"]
        incident_payload["status_source"] = processed_status["source"]
        incident_payload["status_reason"] = processed_status["reason"]

        work_rows_result = await self.session.execute(
            select(AgentWorkItemRecord)
            .where(AgentWorkItemRecord.incident_id == UUID(incident_id_str))
            .order_by(AgentWorkItemRecord.sequence.asc(), AgentWorkItemRecord.updated_at.asc())
        )
        work_rows = work_rows_result.scalars().all()
        events = [
            {
                "sequence": row.sequence,
                "agent": row.agent_name,
                "status": row.status,
                "timestamp": row.updated_at,
                "action": (row.details or {}).get("action") or row.work_item,
                "input": (row.details or {}).get("input", {}),
                "decision": (row.details or {}).get("decision"),
                "metrics": (row.details or {}).get("metrics", {}),
                "output": (row.details or {}).get("output") or row.status,
                "communicates_to": (row.details or {}).get("communicates_to", ""),
                "llm_calls": (row.details or {}).get("llm_calls", []),
                "llm_errors": (row.details or {}).get("llm_errors", []),
            }
            for row in work_rows
        ]
        events = _deduplicate_events(events)

        incident_event_result = await self.session.execute(
            select(IncidentEventRecord)
            .where(
                IncidentEventRecord.incident_id == UUID(incident_id_str),
                IncidentEventRecord.tenant_id == normalized_tenant_id,
            )
            .order_by(IncidentEventRecord.created_at.asc())
        )
        incident_event_rows = incident_event_result.scalars().all()
        event_trace: list[dict[str, Any]] = []
        for row in incident_event_rows:
            payload = row.payload if isinstance(row.payload, dict) else {}
            source_channel = _extract_source_channel(payload)
            query_hint = _extract_query_hint(payload)
            input_value = payload.get("input") if isinstance(payload.get("input"), (dict, list, str, int, float, bool)) else None
            if input_value is None and isinstance(payload.get("request"), (dict, list, str, int, float, bool)):
                input_value = payload.get("request")
            if input_value is None and isinstance(payload.get("input_payload"), (dict, list, str, int, float, bool)):
                input_value = payload.get("input_payload")
            if input_value is None and isinstance(payload.get("context"), (dict, list, str, int, float, bool)):
                input_value = payload.get("context")

            output_value = payload.get("output") if isinstance(payload.get("output"), (dict, list, str, int, float, bool)) else None
            if output_value is None and isinstance(payload.get("result"), (dict, list, str, int, float, bool)):
                output_value = payload.get("result")
            if output_value is None and payload:
                # Fall back to the full payload so timeline output renders real event data.
                output_value = payload

            error_value = payload.get("error") if isinstance(payload.get("error"), (dict, list, str, int, float, bool)) else None
            if error_value is None and isinstance(payload.get("exception"), (dict, list, str, int, float, bool)):
                error_value = payload.get("exception")

            event_trace.append(
                {
                    "timestamp": row.created_at,
                    "service": row.service,
                    "event_type": row.event_type,
                    "event_stage": row.event_stage,
                    "status": row.status,
                    "source_channel": source_channel,
                    "transport_channel": row.transport_channel,
                    "transport_provider": row.transport_provider,
                    "risk_tier": row.risk_tier,
                    "execution_mode": row.execution_mode,
                    "policy_reason": row.policy_reason,
                    "trace_id": row.trace_id,
                    "table_hints": _infer_table_hints(row.event_type, payload),
                    "query_hint": query_hint,
                    "payload": payload,
                    "input_value": input_value,
                    "output_value": output_value,
                    "error": error_value,
                }
            )

        if not events and event_trace:
            events = [
                {
                    "sequence": index + 1,
                    "agent": str(item.get("service") or "-") or "-",
                    "status": str(item.get("status") or item.get("event_stage") or "-") or "-",
                    "timestamp": item.get("timestamp"),
                    "action": str(item.get("event_type") or "incident.event"),
                    "input": {
                        "source_channel": item.get("source_channel"),
                        "transport_channel": item.get("transport_channel"),
                        "transport_provider": item.get("transport_provider"),
                    },
                    "decision": str(item.get("policy_reason") or item.get("status") or item.get("event_stage") or "").strip() or None,
                    "metrics": {
                        "risk_tier": item.get("risk_tier"),
                        "execution_mode": item.get("execution_mode"),
                    },
                    "output": str(item.get("event_type") or "incident.event"),
                    "communicates_to": str(item.get("transport_channel") or "").strip(),
                    "llm_calls": [],
                    "llm_errors": [],
                }
                for index, item in enumerate(event_trace)
            ]

        recommendation_metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}
        orchestration_decision = (
            recommendation_metadata.get("orchestration_decision", {})
            if isinstance(recommendation_metadata.get("orchestration_decision"), dict)
            else {}
        )

        # The recommendation's immutable snapshot binding is authoritative.  A
        # newer independently collected snapshot belongs to a later analysis
        # attempt and must never be substituted here.
        durable_context_snapshot = dict(
            bound_investigation.get("context_snapshot") or {}
        )
        context_payload: dict[str, Any] = (
            dict(durable_context_snapshot.get("context") or {})
            if isinstance(durable_context_snapshot, dict)
            and isinstance(durable_context_snapshot.get("context"), dict)
            else {}
        )
        context_event_payload = next(
            (
                item.get("payload")
                for item in reversed(event_trace)
                if isinstance(item, dict)
                and "context" in str(item.get("event_type") or "").lower()
                and isinstance(item.get("payload"), dict)
            ),
            {},
        )
        if isinstance(context_event_payload, dict):
            nested_context = context_event_payload.get("context")
            if isinstance(nested_context, dict):
                for key, value in nested_context.items():
                    context_payload.setdefault(key, value)
            else:
                for key in ("deployment", "related_incidents", "dependency_services", "document_available"):
                    if context_event_payload.get(key) is not None:
                        context_payload.setdefault(key, context_event_payload.get(key))

        context_metadata = context_payload.get("metadata") if isinstance(context_payload.get("metadata"), dict) else {}
        if recommendation_metadata.get("rag_documents") is not None:
            context_metadata.setdefault("rag_documents", recommendation_metadata.get("rag_documents"))
        if isinstance(recommendation_metadata.get("rag_matches"), list):
            context_metadata.setdefault("rag_matches", recommendation_metadata.get("rag_matches"))
        if recommendation_metadata.get("rag_top_similarity") is not None:
            context_metadata.setdefault("rag_top_similarity", recommendation_metadata.get("rag_top_similarity"))
        if recommendation_metadata.get("rag_service_tagged_match") is not None:
            context_metadata.setdefault("rag_service_tagged_match", recommendation_metadata.get("rag_service_tagged_match"))
        if isinstance(recommendation_metadata.get("discovery_report"), dict):
            context_metadata.setdefault("discovery_report", recommendation_metadata.get("discovery_report"))
        if isinstance(recommendation_metadata.get("discovery_evidence"), dict):
            context_metadata.setdefault("discovery_evidence", recommendation_metadata.get("discovery_evidence"))
        if context_event_payload.get("document_available") is not None:
            context_metadata.setdefault("document_available", context_event_payload.get("document_available"))
        if isinstance(context_event_payload.get("discovery_report"), dict):
            context_metadata.setdefault("discovery_report", context_event_payload.get("discovery_report"))
        if isinstance(context_event_payload.get("discovery_evidence"), dict):
            context_metadata.setdefault("discovery_evidence", context_event_payload.get("discovery_evidence"))
        if isinstance(context_event_payload.get("context_sources"), dict):
            context_metadata.setdefault("context_sources", context_event_payload.get("context_sources"))
        if isinstance(context_event_payload.get("context_evidence"), dict):
            context_metadata.setdefault("context_evidence", context_event_payload.get("context_evidence"))
        if durable_context_snapshot:
            snapshot_provenance = {
                key: durable_context_snapshot.get(key)
                for key in (
                    "snapshot_id",
                    "source_incident_id",
                    "context_fingerprint",
                    "contract_version",
                    "quality_score",
                    "reusable",
                    "source_manifest",
                    "collected_at",
                    "expires_at",
                )
            }
            context_metadata.setdefault("snapshot", snapshot_provenance)
            context_payload.setdefault("snapshot", snapshot_provenance)

        has_discovery_report = isinstance(context_metadata.get("discovery_report"), dict) and bool(context_metadata.get("discovery_report"))
        has_discovery_evidence = isinstance(context_metadata.get("discovery_evidence"), dict) and bool(context_metadata.get("discovery_evidence"))
        # Never manufacture completed Context/Discovery data from alert text. If
        # Context did not emit a persisted event, return an empty stage so the UI
        # accurately reports that downstream processing has not occurred.
        if context_event_payload and not (has_discovery_report and has_discovery_evidence):
            alert_tokens = {_normalize_match_token(item) for item in _collect_alert_application_tokens(alert_payload)}

            app_result = await self.session.execute(
                select(ApplicationRecord)
                .where(ApplicationRecord.tenant_id == normalized_tenant_id)
                .order_by(ApplicationRecord.updated_at.desc())
                .limit(500)
            )
            matched_application_payload: dict[str, Any] = {}
            for app_row in app_result.scalars().all():
                app_name = str(getattr(app_row, "name", "") or "").strip()
                app_namespace = str(getattr(app_row, "namespace", "") or "").strip()
                app_tokens = {_normalize_match_token(app_name), _normalize_match_token(app_namespace)}
                if not (alert_tokens & {token for token in app_tokens if token}):
                    continue
                matched_application_payload = app_row.payload if isinstance(app_row.payload, dict) else {}
                break

            onboarding_result = await self.session.execute(
                select(OnboardingStateRecord)
                .where(OnboardingStateRecord.tenant_id == normalized_tenant_id)
                .order_by(OnboardingStateRecord.updated_at.desc())
                .limit(500)
            )
            matched_onboarding_rows: list[OnboardingStateRecord] = []
            for onboarding_row in onboarding_result.scalars().all():
                project_token = _normalize_match_token(getattr(onboarding_row, "project_name", ""))
                if project_token and project_token in alert_tokens:
                    matched_onboarding_rows.append(onboarding_row)

            rag_documents = context_metadata.get("rag_documents") if isinstance(context_metadata.get("rag_documents"), list) else []
            discovery_report, discovery_evidence = _build_discovery_contract(
                alert_payload=alert_payload,
                recommendation=recommendation,
                recommendation_metadata=recommendation_metadata,
                matched_application_payload=matched_application_payload,
                onboarding_rows=matched_onboarding_rows,
                existing_rag_documents=rag_documents,
            )
            context_metadata.setdefault("discovery_report", discovery_report)
            context_metadata.setdefault("discovery_evidence", discovery_evidence)
            recommendation_metadata.setdefault("discovery_report", discovery_report)
            recommendation_metadata.setdefault("discovery_evidence", discovery_evidence)

        if context_metadata:
            context_payload["metadata"] = context_metadata
        if recommendation_metadata:
            recommendation["metadata"] = recommendation_metadata
        if recommendation_metadata.get("runbook_found") is not None and not context_payload.get("runbook"):
            context_payload["runbook"] = "available" if bool(recommendation_metadata.get("runbook_found")) else ""

        model_usage = recommendation_metadata.get("model_usage", []) if isinstance(recommendation_metadata.get("model_usage"), list) else []
        finops_totals = {
            "input_tokens": sum(int(item.get("input_tokens", 0) or 0) for item in model_usage if isinstance(item, dict)),
            "output_tokens": sum(int(item.get("output_tokens", 0) or 0) for item in model_usage if isinstance(item, dict)),
            "total_tokens": sum(int(item.get("total_tokens", 0) or 0) for item in model_usage if isinstance(item, dict)),
            "total_cost_usd": round(sum(float(item.get("total_cost_usd", 0.0) or 0.0) for item in model_usage if isinstance(item, dict)), 8),
            "calls": len([item for item in model_usage if isinstance(item, dict)]),
            "failed_calls": 0,
        }
        by_provider: dict[str, dict[str, Any]] = {}
        for item in model_usage:
            if not isinstance(item, dict):
                continue
            provider = str(item.get("provider") or "unknown")
            row = by_provider.setdefault(
                provider,
                {"provider": provider, "calls": 0, "total_tokens": 0, "total_cost_usd": 0.0},
            )
            row["calls"] += 1
            row["total_tokens"] += int(item.get("total_tokens", 0) or 0)
            row["total_cost_usd"] = round(float(row["total_cost_usd"]) + float(item.get("total_cost_usd", 0.0) or 0.0), 8)

        metrics = {
            "severity": str(incident_payload.get("severity") or alert_payload.get("severity") or "unknown").upper(),
            "remediation_status": str(remediation_action.get("status") or "unknown"),
            "health_restored": bool(closure_report.get("health_restored", False)),
            "alerts_cleared": bool(closure_report.get("alerts_cleared", False)),
            "recommendation_confidence": float(recommendation.get("confidence", 0.0) or 0.0),
            "agent_handoffs": len(events),
        }

        observed_transport_provider = next(
            (
                str(item.get("transport_provider") or "").strip()
                for item in reversed(event_trace)
                if str(item.get("transport_provider") or "").strip().lower() not in {"", "unknown"}
            ),
            "",
        )
        observed_workflow = next(
            (
                str(item.get("payload", {}).get("decision", {}).get("workflow") or "").strip()
                for item in reversed(event_trace)
                if isinstance(item.get("payload"), dict)
                and isinstance(item.get("payload", {}).get("decision"), dict)
                and str(item.get("payload", {}).get("decision", {}).get("workflow") or "").strip()
            ),
            "",
        )
        decision_workflow = str(orchestration_decision.get("workflow") or observed_workflow or "guided-remediation")
        decision_message_bus_provider = str(
            orchestration_decision.get("message_bus_provider")
            or observed_transport_provider
            or "rabbitmq"
        )

        scenario = {
            "id": "db-processed",
            "title": str(incident_payload.get("title") or alert_payload.get("name") or "Incident"),
            "recommended_action": str(recommendation.get("recommended_action") or ""),
        }

        lifecycle_candidates = (
            closure_report.get("metadata", {}).get("resolution_lifecycle") if isinstance(closure_report.get("metadata"), dict) else None,
            remediation_action.get("parameters", {}).get("resolution_lifecycle") if isinstance(remediation_action.get("parameters"), dict) else None,
            remediation_action.get("metadata", {}).get("resolution_lifecycle") if isinstance(remediation_action.get("metadata"), dict) else None,
            recommendation.get("metadata", {}).get("resolution_lifecycle") if isinstance(recommendation.get("metadata"), dict) else None,
            incident_payload.get("metadata", {}).get("resolution_lifecycle") if isinstance(incident_payload.get("metadata"), dict) else None,
        )
        resolution_lifecycle = select_current_lifecycle(
            *({"resolution_lifecycle": item} for item in lifecycle_candidates if isinstance(item, dict))
        )
        incident_investigation: dict[str, Any] | None = None
        if investigation_integrity.get("verified") is True:
            try:
                incident_investigation = self.build_incident_investigation_contract(
                    tenant_id=normalized_tenant_id,
                    project_id=str(
                        incident_payload.get("project_id")
                        or alert_payload.get("project_id")
                        or alert_labels.get("project_id")
                        or "default"
                    ),
                    incident_id=incident_record.id,
                    alert_id=alert_uuid,
                    recommendation=recommendation,
                    context_snapshot=durable_context_snapshot,
                    approval=approval,
                    remediation_action=remediation_action,
                    validation_status=str(closure_report.get("status") or "pending"),
                )
            except ValueError as exc:
                investigation_integrity = {
                    **investigation_integrity,
                    "status": "contract_invalid",
                    "verified": False,
                    "blocking_reasons": [
                        "bound investigation does not satisfy the canonical runtime contract",
                        str(exc)[:1000],
                    ],
                }

        return {
            "mode": "db-processed",
            "scenario": scenario,
            "alert": alert_payload,
            "incident": incident_payload,
            "decision": {
                "workflow": decision_workflow,
                "requires_approval": bool(orchestration_decision.get("requires_approval", False)),
                "risk_tier": str(orchestration_decision.get("risk_tier") or "unknown"),
                "execution_mode": str(orchestration_decision.get("execution_mode") or "unknown"),
                "policy_version": str(orchestration_decision.get("policy_version") or "policy-v1"),
                "policy_reason": str(orchestration_decision.get("policy_reason") or ""),
                "message_bus_provider": decision_message_bus_provider,
                "stream_count": int(orchestration_decision.get("stream_count", 0) or 0),
                "stream_threshold": int(orchestration_decision.get("stream_threshold", 0) or 0),
                "planner_used": False,
                "planner_model": None,
                "planner_reason": "db-processed historical result",
            },
            "context": context_payload,
            "recommendation": recommendation,
            "incident_investigation": incident_investigation,
            "investigation_integrity": investigation_integrity,
            "approval": approval,
            "remediation_action": remediation_action,
            "closure_report": closure_report,
            "legacy_lifecycle_records": legacy_lifecycle_records,
            "resolution_lifecycle": resolution_lifecycle,
            "metrics": metrics,
            "finops": {
                "totals": finops_totals,
                "by_provider": list(by_provider.values()),
                "calls": model_usage,
                "errors": [],
                "currency": "USD",
            },
            "events": events,
            "event_trace": event_trace,
            "trace_summary": {
                "services_called": sorted({str(item.get("service") or "").strip() for item in event_trace if str(item.get("service") or "").strip()}),
                "channels": sorted(
                    {
                        str(channel).strip()
                        for item in event_trace
                        for channel in (item.get("source_channel"), item.get("transport_channel"))
                        if str(channel or "").strip()
                    }
                ),
                "tables_touched": sorted(
                    {
                        str(table).strip()
                        for item in event_trace
                        for table in (item.get("table_hints") or [])
                        if str(table or "").strip()
                    }
                ),
                "event_count": len(event_trace),
            },
            "next_step": "Loaded processed incident summary from database.",
        }

    async def get_incident_stage_completeness(
        self,
        incident_id: str,
        *,
        tenant_id: str,
    ) -> dict[str, Any] | None:
        incident_uuid = self._parse_uuid(incident_id)
        if incident_uuid is None:
            return None
        normalized_tenant_id = self._require("tenant_id", tenant_id)

        incident_result = await self.session.execute(
            select(IncidentRecord).where(
                IncidentRecord.id == incident_uuid,
                IncidentRecord.tenant_id == normalized_tenant_id,
            )
        )
        incident_record = incident_result.scalar_one_or_none()
        if incident_record is None:
            return None

        events_result = await self.session.execute(
            select(
                IncidentEventRecord.event_type,
                IncidentEventRecord.status,
                IncidentEventRecord.created_at,
            )
            .where(
                IncidentEventRecord.incident_id == incident_uuid,
                IncidentEventRecord.tenant_id == normalized_tenant_id,
            )
            .order_by(IncidentEventRecord.created_at.asc())
        )
        event_rows = events_result.all()
        event_types = {
            str(row.event_type or "").strip().lower()
            for row in event_rows
            if str(row.event_type or "").strip()
        }
        event_statuses = {
            str(row.status or "").strip().lower()
            for row in event_rows
            if str(row.status or "").strip()
        }

        work_result = await self.session.execute(
            select(AgentWorkItemRecord).where(AgentWorkItemRecord.incident_id == incident_uuid)
        )
        work_rows = work_result.scalars().all()

        approval_result = await self.session.execute(
            select(ApprovalRecord)
            .where(
                ApprovalRecord.incident_id == incident_uuid,
                ApprovalRecord.tenant_id == normalized_tenant_id,
            )
            .order_by(ApprovalRecord.updated_at.desc(), ApprovalRecord.created_at.desc())
        )
        approval_rows = approval_result.scalars().all()

        action_result = await self.session.execute(
            select(ActionRecord)
            .where(
                ActionRecord.incident_id == incident_uuid,
                ActionRecord.tenant_id == normalized_tenant_id,
            )
            .order_by(ActionRecord.updated_at.desc(), ActionRecord.created_at.desc())
        )
        action_rows = action_result.scalars().all()

        report_result = await self.session.execute(
            select(RcaReportRecord).where(
                RcaReportRecord.incident_id == incident_uuid,
                RcaReportRecord.tenant_id == normalized_tenant_id,
            )
        )
        report_rows = report_result.scalars().all()
        report_closure_kinds = {
            str(
                (
                    (report.payload or {}).get("metadata")
                    if isinstance((report.payload or {}).get("metadata"), dict)
                    else {}
                ).get("closure_kind")
                or ""
            ).strip().lower()
            for report in report_rows
        }
        closure_kind = (
            "manual"
            if "manual" in report_closure_kinds
            else "diagnostic"
            if "diagnostic" in report_closure_kinds
            else ""
        )
        projection_result = await self.session.execute(
            select(IncidentProjectionRecord).where(
                IncidentProjectionRecord.incident_id == incident_uuid,
                IncidentProjectionRecord.tenant_id == normalized_tenant_id,
            )
        )
        projection_record = projection_result.scalar_one_or_none()
        current_recommendation_id = (
            projection_record.recommendation_id if projection_record is not None else None
        )
        current_approval_rows = [
            approval for approval in approval_rows
            if current_recommendation_id is None
            or approval.recommendation_id == current_recommendation_id
        ]
        latest_approval = approval_rows[0] if approval_rows else None
        latest_action = action_rows[0] if action_rows else None
        lifecycle_status = reduce_incident_status(
            projection_status=projection_record.status if projection_record is not None else None,
            projection_updated_at=projection_record.updated_at if projection_record is not None else None,
            canonical_status=incident_record.status,
            canonical_updated_at=incident_record.updated_at,
            approval_status=latest_approval.decision if latest_approval is not None else None,
            approval_updated_at=latest_approval.updated_at if latest_approval is not None else None,
            action_status=latest_action.status if latest_action is not None else None,
            action_updated_at=latest_action.updated_at if latest_action is not None else None,
            closure_kind=closure_kind,
            lifecycle_state=projection_record.lifecycle_state if projection_record is not None else None,
        )
        incident_status = lifecycle_status["status"]

        stage_matrix = [
            {
                "stage": "alert_enriched",
                "label": "Alert Intelligence Agent",
                "event_types": ["incident.alert.enriched"],
                "next_action": "Enrich and persist the normalized alert.",
            },
            {
                "stage": "workflow_selected",
                "label": "Orchestrator Agent",
                "event_types": ["incident.workflow.selected"],
                "next_action": "Select and persist the incident workflow.",
            },
            {
                "stage": "context_collected",
                "label": "Context Intelligence Agent",
                "event_types": ["incident.context.collected"],
                "next_action": "Collect logs, metrics, traces, tickets, and dependency context.",
            },
            {
                "stage": "recommendation_generated",
                "label": "Resolution Intelligence Agent",
                "event_types": ["incident.recommendation.generated"],
                "next_action": "Generate and persist an evidence-grounded recommendation.",
            },
            {
                "stage": "approval_recorded",
                "label": "Human Approval Layer",
                "event_types": ["incident.approval.recorded", "incident.approval.requested"],
                "next_action": "Record an authorized operator decision.",
            },
            {
                "stage": "remediation_executed",
                "label": "Remediation Automation Engine",
                "event_types": ["incident.remediation.executed"],
                "next_action": "Execute or explicitly skip the approved remediation plan.",
            },
            {
                "stage": "closure_completed",
                "label": "Closure & Validation",
                "event_types": ["incident.closure.completed", "incident.closed"],
                "next_action": "Validate recovery and close or escalate the incident.",
            },
        ]
        diagnostic_completion = any(
            str(action.action_type or "").strip().lower() == "diagnostic_completion"
            and str(action.status or "").strip().lower() == "skipped"
            and bool(((action.payload or {}).get("parameters") or {}).get("diagnostic_closure"))
            for action in action_rows
        )
        manual_closure = closure_kind == "manual"
        if diagnostic_completion:
            # Approval is not part of a non-mutating diagnostic branch. Count
            # the lifecycle that actually ran instead of reporting a permanent
            # missing approval after the incident was correctly auto-closed.
            stage_matrix = [row for row in stage_matrix if row["stage"] != "approval_recorded"]
        elif manual_closure:
            # Administrative closure is a separate governed terminal branch.
            # Approval and remediation were never required or executed, so do
            # not report those inapplicable phases as missing work.
            stage_matrix = [
                row
                for row in stage_matrix
                if row["stage"] not in {"approval_recorded", "remediation_executed"}
            ]

        stages = []
        for row in stage_matrix:
            matched = [event_type for event_type in row["event_types"] if event_type in event_types]
            persisted = bool(matched)
            evidence_sources = [f"event:{event_type}" for event_type in matched]
            state = "complete" if persisted else "waiting"

            if row["stage"] == "approval_recorded":
                # Approval is immutable authorization for one recommendation
                # version. Historical approval events must not make a newly
                # regenerated plan appear approved.
                persisted = bool(current_approval_rows)
                matched = matched if persisted else []
                evidence_sources = (
                    ["relational:approvals/current-recommendation"] if persisted else []
                )
                state = "complete" if persisted else "waiting"

            # Use persisted relational evidence to avoid under-reporting when some
            # services emit equivalent terminal states under different event names.
            if row["stage"] == "alert_enriched" and not persisted:
                persisted = len(work_rows) > 0 or len(event_rows) > 0
                if persisted:
                    evidence_sources.append("relational:incident_events")
            elif row["stage"] == "context_collected" and not persisted:
                context_work = [work for work in work_rows if
                    str(work.agent_name or "").strip().lower() in {"context intelligence agent", "context-agent"}
                ]
                persisted = any(
                    str(work.status or "").strip().lower() in {"completed", "complete", "succeeded", "success"}
                    for work in context_work
                )
                if persisted:
                    evidence_sources.append("relational:agent_work_items/context-completed")
                elif context_work:
                    state = "in_progress"
                    evidence_sources.append("relational:agent_work_items/context-started")
            elif row["stage"] == "approval_recorded" and not persisted:
                persisted = False
            elif row["stage"] == "remediation_executed" and not persisted:
                policy_blocked_actions = [
                    action
                    for action in action_rows
                    if str(action.action_type or "").strip().lower() == "policy-blocked"
                    or bool(((action.payload or {}).get("metadata") or {}).get("policy_blocked"))
                ]
                terminal_actions = [
                    action
                    for action in action_rows
                    if action not in policy_blocked_actions
                    and str(action.status or "").strip().lower() in {"succeeded", "failed", "skipped"}
                ]
                persisted = bool(terminal_actions)
                if persisted:
                    evidence_sources.extend(f"relational:actions/{str(action.status or '').strip().lower()}" for action in terminal_actions)
                elif policy_blocked_actions:
                    state = "blocked"
                    evidence_sources.append("relational:actions/policy-blocked")
                    row = {
                        **row,
                        "next_action": "Review the policy reason, select a matching runbook, and record operator approval before execution.",
                    }
                elif action_rows or "remediating" in event_statuses:
                    state = "in_progress"
                    evidence_sources.append("relational:actions/in-progress")
            elif row["stage"] == "closure_completed" and not persisted:
                persisted = incident_status in {"closed", "resolved"}
                if persisted:
                    evidence_sources.append(f"relational:incidents/status={incident_status}")

            if persisted:
                state = "complete"

            stages.append(
                {
                    "stage": row["stage"],
                    "label": row["label"],
                    "persisted": persisted,
                    "matched_event_types": matched,
                    "evidence_sources": sorted(set(evidence_sources)),
                    "state": state,
                    "next_action": "Completed." if persisted else row["next_action"],
                }
            )

        completed = len([row for row in stages if row["persisted"]])
        total = len(stages)
        missing = [row["stage"] for row in stages if not row["persisted"]]
        latest_event_at = event_rows[-1].created_at if event_rows else None

        return {
            "incident_id": str(incident_record.id),
            "status": incident_status,
            "status_source": lifecycle_status["source"],
            "status_reason": lifecycle_status["reason"],
            "service": str(incident_record.service or "unknown"),
            "counts": {
                "incident_events": len(event_rows),
                "agent_work_items": len(work_rows),
                "approvals": len(approval_rows),
                "actions": len(action_rows),
                "rca_reports": len(report_rows),
            },
            "event_types": sorted(event_types),
            "stages": stages,
            "stage_completion": {
                "completed": completed,
                "total": total,
                "percentage": round((completed / total) * 100, 2) if total else 0.0,
                "missing": missing,
            },
            "latest_event_at": latest_event_at,
        }

    async def acquire_canonical_incident(
        self,
        *,
        incident: Incident,
        occurrence_id: UUID,
        correlation_key: str,
        project_id: str,
        idempotency_key: str,
        causation_id: str | None = None,
        correlation_window_minutes: int = 60,
        observed_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Atomically acquire bounded correlation ownership and attach an occurrence."""
        tenant_id = self._require("tenant_id", incident.tenant_id)
        project_id = self._require("project_id", project_id)
        environment = self._require("environment", incident.environment)
        service = self._require("service", incident.service)
        correlation_key = self._require("correlation_key", correlation_key)
        idempotency_key = self._require("idempotency_key", idempotency_key)
        now = observed_at or datetime.now(UTC)
        window = timedelta(minutes=max(1, min(int(correlation_window_minutes), 1440)))

        existing_occurrence = (
            await self.session.execute(
                select(IncidentOccurrenceRecord).where(
                    IncidentOccurrenceRecord.tenant_id == tenant_id,
                    IncidentOccurrenceRecord.idempotency_key == idempotency_key,
                )
            )
        ).scalar_one_or_none()
        if existing_occurrence is not None:
            return {
                "canonical_incident_id": existing_occurrence.canonical_incident_id,
                "correlation_family_id": existing_occurrence.correlation_family_id,
                "correlation_generation": existing_occurrence.correlation_generation,
                "created": False,
                "retried": True,
            }

        scope = (
            IncidentCorrelationOwnershipRecord.tenant_id == tenant_id,
            IncidentCorrelationOwnershipRecord.project_id == project_id,
            IncidentCorrelationOwnershipRecord.environment == environment,
            IncidentCorrelationOwnershipRecord.service == service,
            IncidentCorrelationOwnershipRecord.correlation_key == correlation_key,
        )
        ownership = (
            await self.session.execute(
                select(IncidentCorrelationOwnershipRecord)
                .where(*scope)
                .order_by(IncidentCorrelationOwnershipRecord.correlation_generation.desc())
                .limit(1)
                .with_for_update()
            )
        ).scalar_one_or_none()
        terminal = {"closed", "resolved", "cancelled", "canceled"}
        ownership_expiry = ownership.correlation_window_expires_at if ownership is not None else None
        if ownership_expiry is not None and ownership_expiry.tzinfo is None:
            ownership_expiry = ownership_expiry.replace(tzinfo=UTC)
        ownership_last_seen = ownership.last_seen_at if ownership is not None else None
        if ownership_last_seen is not None and ownership_last_seen.tzinfo is None:
            ownership_last_seen = ownership_last_seen.replace(tzinfo=UTC)
        historical_event = ownership_last_seen is not None and now <= ownership_last_seen
        create_generation = (
            ownership is None
            or (
                not historical_event
                and str(ownership.lifecycle_state or "").lower() in terminal
            )
        )
        created = False
        if create_generation:
            generation = 1 if ownership is None else int(ownership.correlation_generation) + 1
            family_id = ownership.correlation_family_id if ownership is not None else uuid5(
                NAMESPACE_URL, f"kaims-correlation:{tenant_id}:{project_id}:{environment}:{service}:{correlation_key}"
            )
            candidate_values = dict(
                id=uuid4(),
                tenant_id=tenant_id,
                project_id=project_id,
                environment=environment,
                service=service,
                correlation_key=correlation_key,
                correlation_family_id=family_id,
                correlation_generation=generation,
                canonical_incident_id=incident.id,
                first_seen_at=now,
                last_seen_at=now,
                correlation_window_expires_at=now + window,
                lifecycle_state=incident.status.value,
                version=1,
                created_at=now,
                updated_at=now,
            )
            dialect_name = self.session.get_bind().dialect.name
            if dialect_name == "mysql":
                statement = mysql_insert(IncidentCorrelationOwnershipRecord).values(**candidate_values)
                statement = statement.on_duplicate_key_update(
                    id=IncidentCorrelationOwnershipRecord.id
                )
                await self.session.execute(statement)
            elif dialect_name == "sqlite":
                statement = sqlite_insert(IncidentCorrelationOwnershipRecord).values(**candidate_values)
                statement = statement.on_conflict_do_nothing(
                    index_elements=[
                        "tenant_id", "project_id", "environment", "service",
                        "correlation_key", "correlation_generation",
                    ]
                )
                await self.session.execute(statement)
            else:
                async with self.session.begin_nested():
                    self.session.add(IncidentCorrelationOwnershipRecord(**candidate_values))
                    await self.session.flush()
            ownership = (
                await self.session.execute(
                    select(IncidentCorrelationOwnershipRecord)
                    .where(*scope)
                    .order_by(IncidentCorrelationOwnershipRecord.correlation_generation.desc())
                    .limit(1)
                    .with_for_update()
                )
            ).scalar_one()
            created = ownership.canonical_incident_id == incident.id
        else:
            last_seen = ownership.last_seen_at
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=UTC)
            ownership.last_seen_at = max(last_seen, now)
            ownership.version = int(ownership.version or 1) + 1

        occurrence = IncidentOccurrenceRecord(
            tenant_id=tenant_id,
            project_id=project_id,
            environment=environment,
            service=service,
            correlation_family_id=ownership.correlation_family_id,
            correlation_generation=ownership.correlation_generation,
            canonical_incident_id=ownership.canonical_incident_id,
            occurrence_id=occurrence_id,
            idempotency_key=idempotency_key,
            causation_id=causation_id,
            observed_at=now,
            payload={"incoming_incident_id": str(incident.id), "correlation_key": correlation_key},
        )
        try:
            async with self.session.begin_nested():
                self.session.add(occurrence)
                await self.session.flush()
        except IntegrityError:
            existing_occurrence = (
                await self.session.execute(
                    select(IncidentOccurrenceRecord).where(
                        IncidentOccurrenceRecord.tenant_id == tenant_id,
                        IncidentOccurrenceRecord.idempotency_key == idempotency_key,
                    )
                )
            ).scalar_one()
            ownership = (
                await self.session.execute(
                    select(IncidentCorrelationOwnershipRecord).where(
                        IncidentCorrelationOwnershipRecord.correlation_family_id
                        == existing_occurrence.correlation_family_id,
                        IncidentCorrelationOwnershipRecord.correlation_generation
                        == existing_occurrence.correlation_generation,
                    )
                )
            ).scalar_one()
            created = False
        return {
            "canonical_incident_id": ownership.canonical_incident_id,
            "correlation_family_id": ownership.correlation_family_id,
            "correlation_generation": ownership.correlation_generation,
            "created": created,
            "retried": False,
        }

    async def save_incident(self, incident: Incident) -> None:
        incident_id = self._require("incident.id", incident.id)
        incoming_status = self._require("incident.status", incident.status.value)
        existing = await self._require_write_scope(
            IncidentRecord, incident_id, tenant_id=incident.tenant_id or "default",
        )
        if (
            existing is not None
            and str(existing.status or "").strip().lower() in _CLOSED_INCIDENT_STATUSES
            and str(incoming_status).strip().lower() not in _CLOSED_INCIDENT_STATUSES
        ):
            # Delayed alert/Jira messages can arrive after closure and still
            # carry the pre-closure Incident object. They may enrich identity,
            # but they must never reopen a terminal incident implicitly.
            stored_payload = dict(existing.payload or {})
            incoming_payload = incident.model_dump(mode="json")
            if not existing.ticket_id and incident.ticket_id:
                existing.ticket_id = incident.ticket_id
                stored_payload["ticket_id"] = incident.ticket_id
            stored_alert_ids = [str(item) for item in stored_payload.get("alert_ids", []) if str(item).strip()]
            incoming_alert_ids = [str(item) for item in incoming_payload.get("alert_ids", []) if str(item).strip()]
            if incoming_alert_ids:
                stored_payload["alert_ids"] = list(dict.fromkeys([*stored_alert_ids, *incoming_alert_ids]))
            stored_payload["status"] = existing.status
            stored_payload["state"] = existing.status
            existing.payload = stored_payload
            await self.session.merge(existing)
            return
        await self.session.merge(
            IncidentRecord(
                id=incident_id,
                tenant_id=incident.tenant_id or "default",
                service=self._require("incident.service", incident.service),
                environment=self._require("incident.environment", incident.environment),
                severity=self._require("incident.severity", incident.severity.value),
                status=incoming_status,
                title=self._require("incident.title", incident.title),
                ticket_id=incident.ticket_id,
                payload=incident.model_dump(mode="json"),
            )
        )
        ownership_rows = (
            await self.session.execute(
                select(IncidentCorrelationOwnershipRecord).where(
                    IncidentCorrelationOwnershipRecord.canonical_incident_id == incident_id,
                    IncidentCorrelationOwnershipRecord.tenant_id == (incident.tenant_id or "default"),
                )
            )
        ).scalars().all()
        for ownership in ownership_rows:
            ownership.lifecycle_state = incoming_status
            ownership.version = int(ownership.version or 1) + 1
        if str(incoming_status).strip().lower() in {"closed", "resolved", "cancelled", "validating"}:
            projection = await self.session.get(IncidentProjectionRecord, incident_id)
            if projection is not None and projection.tenant_id == (incident.tenant_id or "default"):
                projection.status = str(incoming_status).strip().lower()
                projection.lifecycle_state = str(incoming_status).strip().upper()
                projection.lifecycle_version = int(projection.lifecycle_version or 1) + 1
                projection.updated_at = utc_now()
                projection_payload = dict(projection.projection_payload or {})
                projection_payload["status"] = projection.status
                projection_payload["state"] = projection.status
                projection.projection_payload = projection_payload
                await self.session.merge(projection)

    async def committed_non_execution_closure_report(self, *, tenant_id: str, incident_id: UUID):
        """Read the report named by the committed closure, without inventing execution."""
        event = await self.session.scalar(select(IncidentEventRecord).where(
            IncidentEventRecord.tenant_id == tenant_id,
            IncidentEventRecord.incident_id == incident_id,
            IncidentEventRecord.event_type == "incident.closure.completed",
        ).order_by(IncidentEventRecord.created_at.desc(), IncidentEventRecord.id.desc()).limit(1))
        payload = event.payload if event and isinstance(event.payload, dict) else {}
        kind = payload.get("closure_kind")
        if kind not in {"manual", "diagnostic"} or not payload.get("report_id"):
            return None
        try:
            report_id = UUID(str(payload["report_id"]))
        except (ValueError, TypeError):
            return None
        return await self.session.scalar(select(RcaReportRecord).where(
            RcaReportRecord.id == report_id, RcaReportRecord.tenant_id == tenant_id,
            RcaReportRecord.incident_id == incident_id, RcaReportRecord.closure_kind == kind,
            RcaReportRecord.closure_status.in_(["closed", "validation_failed"]),
        ))

    async def get_incident(self, incident_id: str, *, tenant_id: str | None = None) -> dict[str, Any] | None:
        incident_uuid = self._parse_uuid(incident_id)
        if incident_uuid is None:
            return None
        query = select(IncidentRecord).where(IncidentRecord.id == incident_uuid)
        if tenant_id is not None:
            query = query.where(IncidentRecord.tenant_id == self._require("tenant_id", tenant_id))
        result = await self.session.execute(query)
        record = result.scalar_one_or_none()
        if record is None:
            return None
        payload = dict(record.payload or {})
        jira_binding = (await self.session.execute(select(JiraIncidentBindingRecord).where(
            JiraIncidentBindingRecord.tenant_id == record.tenant_id,
            JiraIncidentBindingRecord.incident_id == incident_uuid,
            JiraIncidentBindingRecord.status != "superseded",
        ).order_by(JiraIncidentBindingRecord.binding_version.desc()).limit(1))).scalar_one_or_none()
        if jira_binding is not None:
            jira_state = {
                "key": jira_binding.jira_issue_key, "status": jira_binding.jira_status,
                "binding_status": jira_binding.status, "assignee": jira_binding.assignee_id,
                "assignee_group": jira_binding.assignee_group,
                "approval_due_at": jira_binding.approval_expires_at,
                "last_synchronized_at": jira_binding.last_synced_at,
                "next_action_owner": "person" if jira_binding.status in {"pending", "unauthorized"} else "kaims",
                "closure_authority": jira_binding.ownership,
                "closure_policy": dict(jira_binding.closure_policy or {}),
                "binding_version": jira_binding.binding_version,
            }
            payload.update({
                "ticket_id": jira_binding.jira_issue_key, "jira_key": jira_binding.jira_issue_key,
                "jira_status": jira_binding.jira_status, "jira_assignee": jira_binding.assignee_id,
                "jira_assignment_group": jira_binding.assignee_group,
                "jira_last_sync_at": jira_binding.last_synced_at,
                "approval_expires_at": jira_binding.approval_expires_at,
                "next_action_owner": jira_state["next_action_owner"],
                "closure_authority": jira_binding.ownership, "jira": jira_state,
            })
        return payload

    async def find_open_jira_by_correlation_key(
        self,
        correlation_key: str,
        *,
        tenant_id: str,
        project_id: str,
        environment: str,
        service: str,
    ) -> str | None:
        """Resolve a previously qualified Jira incident for a correlated signal."""
        required_scope = (tenant_id, project_id, environment, service, correlation_key)
        if any(not str(value or "").strip() for value in required_scope):
            return None
        incident = await self.find_open_incident_by_correlation_key(
            correlation_key,
            tenant_id=tenant_id,
            project_id=project_id,
            environment=environment,
            service=service,
        )
        if not incident:
            return None
        metadata = incident.get("metadata") if isinstance(incident.get("metadata"), dict) else {}
        candidate = metadata.get("incident_candidate") if isinstance(metadata.get("incident_candidate"), dict) else {}
        return str(incident.get("ticket_id") or candidate.get("jira_key") or "").strip() or None

    async def find_open_incident_by_correlation_key(
        self,
        correlation_key: str,
        *,
        tenant_id: str = "default",
        project_id: str | None = None,
        environment: str | None = None,
        service: str | None = None,
    ) -> dict[str, Any] | None:
        """Resolve indexed canonical ownership without inspecting JSON payloads."""
        normalized = str(correlation_key or "").strip()
        if not normalized:
            return None
        ownership_query = select(IncidentCorrelationOwnershipRecord).where(
            IncidentCorrelationOwnershipRecord.tenant_id == tenant_id,
            IncidentCorrelationOwnershipRecord.correlation_key == normalized,
            IncidentCorrelationOwnershipRecord.lifecycle_state.not_in(
                ("closed", "resolved", "cancelled", "canceled")
            ),
        )
        if project_id:
            ownership_query = ownership_query.where(IncidentCorrelationOwnershipRecord.project_id == project_id)
        if environment:
            ownership_query = ownership_query.where(IncidentCorrelationOwnershipRecord.environment == environment)
        if service:
            ownership_query = ownership_query.where(IncidentCorrelationOwnershipRecord.service == service)
        ownership = (
            await self.session.execute(
                ownership_query.order_by(
                    IncidentCorrelationOwnershipRecord.last_seen_at.desc(),
                    IncidentCorrelationOwnershipRecord.correlation_generation.desc(),
                ).limit(1)
            )
        ).scalar_one_or_none()
        if ownership is None:
            return None
        record = await self.session.get(IncidentRecord, ownership.canonical_incident_id)
        return record.payload if record is not None else None

    async def list_unresolved_incident_family(
        self,
        *,
        incident_id: str,
        service: str,
        environment: str,
        category: str,
        tenant_id: str = "default",
        limit: int = 100,
        window_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Find unresolved members of the same operational symptom family."""
        from common.incident_identity import same_environment_family

        current_id = self._parse_uuid(incident_id)
        current_record = await self.session.get(IncidentRecord, current_id) if current_id is not None else None
        if current_record is None:
            return []
        family_cutoff = current_record.created_at - timedelta(minutes=max(1, min(int(window_minutes), 1440)))
        query = (
            select(IncidentRecord)
            .where(IncidentRecord.tenant_id == tenant_id)
            .where(IncidentRecord.service == self._require("service", service))
            .where(IncidentRecord.status.not_in(("closed", "resolved", "cancelled", "canceled")))
            .where(IncidentRecord.created_at >= family_cutoff)
            .where(IncidentRecord.created_at <= current_record.created_at)
            .order_by(IncidentRecord.created_at.desc())
            .limit(max(1, min(int(limit), 500)))
        )
        result = await self.session.execute(query)
        related: list[dict[str, Any]] = []
        normalized_category = str(category or "unknown").strip().lower()
        for record in result.scalars().all():
            if current_id is not None and record.id == current_id:
                continue
            payload = record.payload if isinstance(record.payload, dict) else {}
            metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            candidate = metadata.get("incident_candidate") if isinstance(metadata.get("incident_candidate"), dict) else {}
            candidate_category = str(candidate.get("category") or "unknown").strip().lower()
            if candidate_category != normalized_category:
                continue
            if not same_environment_family(environment, payload.get("environment") or record.environment):
                continue
            related.append(payload)
        return related

    async def governed_recovery_recommendation_id(self, *, tenant_id: str, incident_id: UUID) -> UUID | None:
        """The generation owning physical execution outranks background analysis."""
        latest = (await self.session.execute(
            select(ActionRecord.recommendation_id, ActionRecord.status)
            .join(ExecutionPlanRecord, ExecutionPlanRecord.id == ActionRecord.resolution_plan_id)
            .where(ActionRecord.tenant_id == tenant_id, ActionRecord.incident_id == incident_id,
                   ExecutionPlanRecord.tenant_id == tenant_id,
                   ExecutionPlanRecord.incident_id == incident_id,
                   ExecutionPlanRecord.recommendation_id == ActionRecord.recommendation_id,
                   ExecutionPlanRecord.fingerprint == ActionRecord.plan_fingerprint)
            .order_by(ActionRecord.created_at.desc(), ActionRecord.updated_at.desc()).limit(1)
        )).first()
        if latest is not None:
            return latest[0] if latest[1] in {
                "pending", "policy_checked", "approved", "dispatching", "executor_accepted",
                "running", "verifying", "succeeded",
            } else None
        current = await self.session.scalar(select(IncidentProjectionRecord.recommendation_id).where(
            IncidentProjectionRecord.tenant_id == tenant_id, IncidentProjectionRecord.incident_id == incident_id,
        ))
        if current is None:
            return None
        return await self.session.scalar(select(ExecutionPlanRecord.recommendation_id).where(
            ExecutionPlanRecord.tenant_id == tenant_id, ExecutionPlanRecord.incident_id == incident_id,
            ExecutionPlanRecord.recommendation_id == current, ExecutionPlanRecord.execution_ready.is_(True),
            ExecutionPlanRecord.resolution_selection_id.is_not(None),
        ).order_by(ExecutionPlanRecord.created_at.desc()).limit(1))

    async def get_latest_recommendation_for_incident(
        self,
        incident_id: Any,
        *,
        tenant_id: str | None = None,
    ) -> dict[str, Any] | None:
        incident_uuid = self._parse_uuid(incident_id)
        if incident_uuid is None:
            return None
        if tenant_id is not None:
            governed = await self.governed_recovery_recommendation_id(tenant_id=tenant_id, incident_id=incident_uuid)
            if governed is not None:
                audit = await self.session.get(AuditLogRecord, governed)
                if audit is not None and audit.tenant_id == tenant_id:
                    return audit.payload
            proj_row = (
                await self.session.execute(
                    select(IncidentProjectionRecord).where(
                        IncidentProjectionRecord.tenant_id == tenant_id,
                        IncidentProjectionRecord.incident_id == incident_uuid,
                    )
                )
            ).scalar_one_or_none()
            if proj_row is not None and proj_row.recommendation_id is not None:
                proj_audit = await self.session.get(AuditLogRecord, proj_row.recommendation_id)
                if proj_audit is not None and proj_audit.tenant_id == tenant_id and isinstance(proj_audit.payload, dict):
                    return proj_audit.payload
        audit_stmt = (
            select(AuditLogRecord)
            .where(AuditLogRecord.resource_type == "incident")
            .where(AuditLogRecord.resource_id == str(incident_uuid))
            .where(AuditLogRecord.action == "recommendation.generated")
            .order_by(AuditLogRecord.updated_at.desc(), AuditLogRecord.created_at.desc())
            .limit(1)
        )
        if tenant_id is not None:
            audit_stmt = audit_stmt.where(AuditLogRecord.tenant_id == self._require("tenant_id", tenant_id))
        audit_result = await self.session.execute(audit_stmt)
        audit_record = audit_result.scalar_one_or_none()
        if audit_record is not None and isinstance(audit_record.payload, dict):
            return audit_record.payload

        projection_stmt = select(IncidentProjectionRecord).where(
            IncidentProjectionRecord.incident_id == incident_uuid
        )
        if tenant_id is not None:
            projection_stmt = projection_stmt.where(
                IncidentProjectionRecord.tenant_id == self._require("tenant_id", tenant_id)
            )
        projection_result = await self.session.execute(projection_stmt)
        projection = projection_result.scalar_one_or_none()
        if projection is not None and projection.recommendation_id is not None:
            return {"id": str(projection.recommendation_id), "incident_id": str(incident_uuid)}
        return None

    async def save_approval(self, approval: Approval) -> None:
        await self._require_write_scope(
            ApprovalRecord, approval.id, tenant_id=approval.tenant_id, incident_id=approval.incident_id,
        )
        await self._require_write_scope(IncidentRecord, approval.incident_id, tenant_id=approval.tenant_id)
        await self.session.merge(
            ApprovalRecord(
                id=self._require("approval.id", approval.id),
                tenant_id=self._require("approval.tenant_id", approval.tenant_id),
                incident_id=self._require("approval.incident_id", approval.incident_id),
                recommendation_id=self._require("approval.recommendation_id", approval.recommendation_id),
                plan_id=approval.plan_id,
                plan_fingerprint=approval.plan_fingerprint,
                approval_expires_at=approval.approval_expires_at,
                approver_role=approval.approver_role,
                decision=self._require("approval.decision", approval.decision.value),
                approver=approval.approver,
                payload=approval.model_dump(mode="json"),
            )
        )

    async def has_accepted_approval(
        self,
        incident_id: Any,
        recommendation_id: Any,
        *,
        tenant_id: str = "default",
    ) -> bool:
        incident_uuid = self._parse_uuid(incident_id)
        recommendation_uuid = self._parse_uuid(recommendation_id)
        if incident_uuid is None or recommendation_uuid is None:
            return False
        result = await self.session.execute(
            select(ApprovalRecord.id)
            .where(ApprovalRecord.tenant_id == (str(tenant_id or "default").strip() or "default"))
            .where(ApprovalRecord.incident_id == incident_uuid)
            .where(ApprovalRecord.recommendation_id == recommendation_uuid)
            .where(ApprovalRecord.decision == ApprovalDecision.APPROVED.value)
            .limit(1)
        )
        return result.scalar_one_or_none() is not None

    async def has_accepted_approval_id(
        self,
        approval_id: Any,
        incident_id: Any,
        recommendation_id: Any,
        *,
        tenant_id: str,
        plan_id: Any,
        plan_fingerprint: str,
    ) -> bool:
        approval_uuid = self._parse_uuid(approval_id)
        incident_uuid = self._parse_uuid(incident_id)
        recommendation_uuid = self._parse_uuid(recommendation_id)
        if approval_uuid is None or incident_uuid is None or recommendation_uuid is None:
            return False
        normalized_tenant = str(tenant_id or "").strip()
        from common.config import get_settings
        if (not normalized_tenant or not plan_fingerprint
                or (normalized_tenant.lower() == "default" and get_settings().auth_mode != "local")):
            return False
        result = await self.session.execute(
            select(ApprovalRecord)
            .where(ApprovalRecord.id == approval_uuid)
            .where(ApprovalRecord.tenant_id == normalized_tenant)
            .where(ApprovalRecord.incident_id == incident_uuid)
            .where(ApprovalRecord.recommendation_id == recommendation_uuid)
            .where(ApprovalRecord.decision == ApprovalDecision.APPROVED.value)
            .limit(1)
        )
        record = result.scalar_one_or_none()
        if record is None or not isinstance(record.payload, dict):
            return False
        expires_at = record.approval_expires_at
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return (
            str(record.plan_id or record.payload.get("plan_id") or "") == str(plan_id or "")
            and str(record.plan_fingerprint or record.payload.get("plan_fingerprint") or "") == plan_fingerprint
            and str(record.payload.get("tenant_id") or "") == normalized_tenant
            and str(record.payload.get("authorization_scope") or "execution") == "execution"
            and expires_at is not None
            and expires_at > datetime.now(UTC)
        )

    async def update_incident_approval_status(
        self,
        incident_id: Any,
        *,
        status: str,
        approval: Approval | None = None,
    ) -> bool:
        incident_uuid = self._parse_uuid(incident_id)
        normalized_status = str(status or "").strip().lower()
        if incident_uuid is None or not normalized_status:
            return False

        updated = False
        now = utc_now()

        incident = await self.session.get(IncidentRecord, incident_uuid)
        if incident is not None:
            incident.status = normalized_status
            payload = dict(incident.payload or {})
            payload["status"] = normalized_status
            payload["state"] = normalized_status
            if approval is not None:
                payload["approval"] = approval.model_dump(mode="json")
                payload["approval_status"] = normalized_status
            incident.payload = payload
            incident.updated_at = now
            await self.session.merge(incident)
            updated = True

        projection = await self.session.get(IncidentProjectionRecord, incident_uuid)
        if projection is not None:
            projection.status = normalized_status
            if normalized_status == "approved":
                projection.lifecycle_state = "APPROVED"
                projection.lifecycle_version = int(projection.lifecycle_version or 1) + 1
            elif normalized_status == "awaiting_approval":
                projection.lifecycle_state = "AWAITING_APPROVAL"
                projection.lifecycle_version = int(projection.lifecycle_version or 1) + 1
            if approval is not None:
                projection.owner = str(approval.approver or "") or projection.owner
                projection.recommendation_id = self._parse_uuid(approval.recommendation_id) or projection.recommendation_id
            projection.latest_event_type = "incident.approval.recorded"
            projection.latest_event_at = now
            projection.updated_at = now
            projection_payload = dict(projection.projection_payload or {})
            projection_payload["status"] = normalized_status
            projection_payload["state"] = normalized_status
            projection_payload["approval_status"] = normalized_status
            if approval is not None:
                projection_payload["approval"] = approval.model_dump(mode="json")
            projection.projection_payload = projection_payload
            await self.session.merge(projection)
            updated = True

        pending = await self.session.get(PendingWorkflowRecord, incident_uuid)
        if pending is not None:
            pending.status = normalized_status
            pending.updated_at = now
            pending_payload = dict(pending.payload or {})
            pending_payload["status"] = normalized_status
            pending_payload["approval_status"] = normalized_status
            if approval is not None:
                pending_payload["approval"] = approval.model_dump(mode="json")
            pending.payload = pending_payload
            await self.session.merge(pending)
            updated = True

        return updated

    async def save_action(self, action: RemediationAction) -> None:
        tenant_id = action.tenant_id or "default"
        existing_action = await self._require_write_scope(
            ActionRecord, action.id, tenant_id=tenant_id, incident_id=action.incident_id,
        )
        if existing_action is not None and existing_action.approval_id is not None:
            incoming_approval_id = self._parse_uuid(action.approval_id)
            if incoming_approval_id != existing_action.approval_id:
                incoming = await self.session.get(ApprovalRecord, incoming_approval_id) if incoming_approval_id else None
                previous = await self.session.get(ApprovalRecord, existing_action.approval_id)
                if (incoming is None or previous is None or incoming.tenant_id != tenant_id
                        or incoming.incident_id != action.incident_id
                        or incoming.decision != "approved"
                        or incoming.created_at.replace(tzinfo=UTC) <= previous.created_at.replace(tzinfo=UTC)):
                    raise ValueError("Action write belongs to a superseded or unpersisted approval")
        await self._require_write_scope(IncidentRecord, action.incident_id, tenant_id=tenant_id)
        await self._require_write_scope(IncidentProjectionRecord, action.incident_id, tenant_id=tenant_id)
        action_status = self._require("action.status", action.status.value)
        parameters = action.parameters if isinstance(action.parameters, dict) else {}
        execution_plan = parameters.get("execution_plan") if isinstance(parameters.get("execution_plan"), dict) else {}
        recommendation_id = self._parse_uuid(
            action.recommendation_id or parameters.get("recommendation_id") or execution_plan.get("recommendation_id")
        )
        resolution_plan_id = self._parse_uuid(
            action.resolution_plan_id or parameters.get("resolution_plan_id") or execution_plan.get("plan_id")
        )
        plan_fingerprint = str(
            action.plan_fingerprint
            or parameters.get("approved_plan_fingerprint")
            or execution_plan.get("plan_fingerprint")
            or ""
        ).strip() or None
        await self.session.merge(
            ActionRecord(
                id=self._require("action.id", action.id),
                tenant_id=action.tenant_id or "default",
                incident_id=self._require("action.incident_id", action.incident_id),
                recommendation_id=recommendation_id,
                resolution_plan_id=resolution_plan_id,
                plan_fingerprint=plan_fingerprint,
                approval_id=self._parse_uuid(action.approval_id),
                action_type=self._require("action.action_type", action.action_type),
                target=self._require("action.target", action.target),
                idempotency_key=action.idempotency_key,
                status=action_status,
                payload=action.model_dump(mode="json"),
            )
        )
        # Keep the incident read model synchronized with the durable action.
        # Action persistence is the lifecycle source of truth; relying only on
        # asynchronous events leaves incidents permanently "remediating" when
        # a consumer is restarted or an older producer omits a terminal event.
        incident_status = {
            "pending": "remediating",
            "policy_checked": "remediating",
            "approved": "remediating",
            "dispatching": "remediating",
            "running": "remediating",
            "succeeded": "validating",
            "failed": "failed",
            "skipped": "failed",
            "execution_failed": "failed",
            "validation_failed": "failed",
            "dispatch_failed": "failed",
            "policy_blocked": "awaiting_approval",
            "awaiting_approval": "awaiting_approval",
            "rollback_failed": "failed",
            "timed_out": "failed",
            "cancelled": "failed",
            "manual_intervention_required": "failed",
            "rolled_back": "validating",
        }.get(str(action_status).lower())
        if action_status == "skipped" and action.action_type == "diagnostic_completion":
            incident_status = "validating"
        if (
            action_status == "skipped"
            and str(action.action_type or "").strip().lower().replace("_", "-") == "policy-blocked"
        ):
            # Policy enforcement succeeded: execution did not fail. Keep the
            # incident in investigation so the operator can collect evidence
            # or regenerate a safe plan instead of presenting false recovery
            # failure semantics.
            incident_status = "investigating"
        if incident_status:
            projection = await self.session.get(IncidentProjectionRecord, action.incident_id)
            if (
                projection is not None
                and projection.tenant_id == tenant_id
                and str(projection.status or "").strip().lower() not in _CLOSED_INCIDENT_STATUSES
            ):
                now = utc_now()
                projection.status = incident_status
                if incident_status == "remediating":
                    projection.lifecycle_state = "REMEDIATING"
                    projection.lifecycle_version = int(projection.lifecycle_version or 1) + 1
                elif incident_status == "validating":
                    projection.lifecycle_state = "VALIDATING"
                    projection.lifecycle_version = int(projection.lifecycle_version or 1) + 1
                elif incident_status == "awaiting_approval":
                    projection.lifecycle_state = "AWAITING_APPROVAL"
                    projection.lifecycle_version = int(projection.lifecycle_version or 1) + 1
                if projection.tenant_id == action.tenant_id and recommendation_id and resolution_plan_id:
                    governed = await self.session.get(ExecutionPlanRecord, resolution_plan_id)
                    if (governed is not None and governed.tenant_id == action.tenant_id
                            and governed.incident_id == action.incident_id
                            and governed.recommendation_id == recommendation_id
                            and governed.fingerprint == plan_fingerprint):
                        projection.recommendation_id = recommendation_id
                projection.latest_event_type = "incident.remediation.status"
                projection.latest_event_at = now
                projection.updated_at = now
                payload = dict(projection.projection_payload or {})
                payload["status"] = incident_status
                payload["state"] = incident_status
                payload["remediation_status"] = action_status
                payload["remediation_action"] = action.model_dump(mode="json")
                projection.projection_payload = payload
                await self.session.merge(projection)

    async def enqueue_resolution_event(
        self,
        *,
        event_id: str,
        aggregate_id: str,
        topic: str,
        partition_key: str,
        payload: dict[str, Any],
        tenant_id: str = "default",
        available_after_seconds: float = 60.0,
    ) -> bool:
        normalized_event_id = self._require("outbox.event_id", event_id)
        if await self.session.get(ResolutionOutboxRecord, normalized_event_id) is not None:
            return False
        from common.config import get_settings
        from common.outbox_context import compact_context

        if get_settings().outbox_snapshot_references_enabled:
            payload = await compact_context(
                self.session, payload=payload, tenant_id=tenant_id or "default",
                aggregate_id=aggregate_id, topic=topic,
            )
        self.session.add(
            ResolutionOutboxRecord(
                event_id=normalized_event_id,
                tenant_id=tenant_id or "default",
                aggregate_id=self._require("outbox.aggregate_id", aggregate_id),
                topic=self._require("outbox.topic", topic),
                partition_key=self._require("outbox.partition_key", partition_key),
                payload=payload,
                status="pending",
                attempts=0,
                next_attempt_at=utc_now() + timedelta(seconds=max(0.0, float(available_after_seconds))),
            )
        )
        return True

    async def list_pending_resolution_events(
        self, *, limit: int = 20, max_attempts: int = 5,
    ) -> list[ResolutionOutboxRecord]:
        rows = await self.session.execute(
            select(ResolutionOutboxRecord.event_id)
            .where(
                ResolutionOutboxRecord.published_at.is_(None),
                ResolutionOutboxRecord.status.in_(("pending", "retry")),
                ResolutionOutboxRecord.attempts < max(1, int(max_attempts)),
                ResolutionOutboxRecord.next_attempt_at <= utc_now(),
            )
            .order_by(ResolutionOutboxRecord.created_at.asc(), ResolutionOutboxRecord.event_id.asc())
            .limit(max(1, min(int(limit), 100)))
        )
        event_ids = list(rows.scalars().all())
        if not event_ids:
            return []
        # Never sort full context JSON in MySQL. Sorting a narrow ID projection
        # keeps batch memory bounded even when evidence snapshots are large.
        records = await self.session.execute(
            select(ResolutionOutboxRecord).where(ResolutionOutboxRecord.event_id.in_(event_ids))
        )
        by_id = {row.event_id: row for row in records.scalars().all()}
        return [by_id[event_id] for event_id in event_ids if event_id in by_id]

    async def dead_letter_exhausted_resolution_events(self, *, max_attempts: int = 5) -> int:
        result = await self.session.execute(
            update(ResolutionOutboxRecord)
            .where(
                ResolutionOutboxRecord.published_at.is_(None),
                ResolutionOutboxRecord.status.in_(("pending", "retry")),
                ResolutionOutboxRecord.attempts >= max(1, int(max_attempts)),
            )
            .values(status="dead_letter")
        )
        return int(result.rowcount or 0)

    async def coalesce_superseded_background_rca(
        self, *, tenant_id: str, incident_id: UUID, snapshot_id: UUID, request_id: UUID,
    ) -> str | None:
        """Retire only enrichment-generated work fully covered by a durable successor."""
        if request_id != uuid5(NAMESPACE_URL, f"kaims:enriched-analysis:{snapshot_id}"):
            return None
        if await self.get_analysis_request(request_id, tenant_id=tenant_id) is not None:
            return None  # Explicit operator requests always receive their own result.
        governed = await self.governed_recovery_recommendation_id(tenant_id=tenant_id, incident_id=incident_id)
        if governed is not None:
            return f"governed-recovery:{governed}"
        previous = await self.session.get(ContextSnapshotRecord, snapshot_id)
        if (previous is None or previous.tenant_id != tenant_id
                or previous.incident_id != str(incident_id) or previous.snapshot_stage != "enriched"
                or not previous.evidence_ids):
            return None
        # Sort narrow IDs, not megabyte-sized JSON snapshot rows. MySQL's
        # filesort otherwise exhausts its sort buffer under real evidence load.
        latest_id = await self.session.scalar(select(ContextSnapshotRecord.snapshot_id).where(
            ContextSnapshotRecord.tenant_id == tenant_id,
            ContextSnapshotRecord.incident_id == str(incident_id),
            ContextSnapshotRecord.snapshot_stage == "enriched",
        ).order_by(ContextSnapshotRecord.snapshot_version.desc()).limit(1))
        latest = await self.session.get(ContextSnapshotRecord, latest_id) if latest_id else None
        if latest is None or latest.snapshot_version <= previous.snapshot_version:
            return None
        expires = latest.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires <= utc_now() or not set(previous.evidence_ids).issubset(set(latest.evidence_ids or [])):
            return None
        metadata = (latest.payload or {}).get("metadata") or {}
        digest = str(metadata.get("evidence_set_digest") or "")
        successor = await self.session.get(ResolutionOutboxRecord, f"context-enriched:{incident_id}:{digest}")
        if (successor is None or successor.tenant_id != tenant_id
                or successor.aggregate_id != str(incident_id) or successor.topic != "context-events"
                or successor.status not in {"pending", "retry", "published"}):
            return None
        from common.outbox_context import hydrate_context
        try:
            successor_payload = await hydrate_context(self.session, successor)
        except (ValueError, TypeError):
            return None  # Unverifiable coverage must never retire older work.
        successor_context = successor_payload.get("context") or {}
        successor_metadata = successor_context.get("metadata") or {}
        if (successor is None or successor.tenant_id != tenant_id
                or successor.aggregate_id != str(incident_id) or successor.topic != "context-events"
                or successor.status not in {"pending", "retry", "published"}
                or str(successor_metadata.get("context_snapshot_id")) != str(latest.snapshot_id)
                or str(successor_metadata.get("analysis_request_id")) != str(uuid5(NAMESPACE_URL, f"kaims:enriched-analysis:{latest.snapshot_id}"))):
            return None
        audit_id = uuid5(NAMESPACE_URL, f"kaims:rca-coalesced:{tenant_id}:{request_id}")
        if await self.session.get(AuditLogRecord, audit_id) is None:
            self.session.add(AuditLogRecord(id=audit_id, tenant_id=tenant_id, actor="resolution-agent",
                action="rca.background.coalesced", resource_type="incident", resource_id=str(incident_id),
                payload={"request_id": str(request_id), "snapshot_id": str(snapshot_id),
                         "successor_event_id": successor.event_id, "successor_snapshot_id": str(latest.snapshot_id),
                         "reason": "newer_durable_enrichment_contains_all_prior_evidence"}))
        await self.session.flush()
        return successor.event_id

    async def mark_analysis_request_progress(
        self, request_id: UUID | str, *, tenant_id: str, stage: str,
    ) -> bool:
        """Transport/worker receipts advance active requests without reopening terminals."""
        request_uuid = self._parse_uuid(request_id)
        if request_uuid is None:
            return False
        if stage not in {"published", "running"}:
            raise ValueError("unsupported analysis progress stage")
        eligible = ("accepted", "queued") if stage == "published" else ("accepted", "queued", "published")
        result = await self.session.execute(
            update(AnalysisRequestRecord)
            .where(AnalysisRequestRecord.request_id == request_uuid,
                   AnalysisRequestRecord.tenant_id == tenant_id)
            .values(delivery="published", status=case(
                (AnalysisRequestRecord.status.in_(eligible), stage),
                else_=AnalysisRequestRecord.status,
            ))
        )
        return bool(result.rowcount)

    async def mark_resolution_event_published(self, event_id: str) -> None:
        row = await self.session.get(ResolutionOutboxRecord, event_id)
        if row is None:
            return
        if event_id.startswith("analysis-regeneration:"):
            await self.mark_analysis_request_progress(
                event_id.removeprefix("analysis-regeneration:"),
                tenant_id=row.tenant_id, stage="published",
            )
        row.status = "published"
        row.published_at = utc_now()
        row.last_error = None
        row.attempts = int(row.attempts or 0) + 1
        await self.session.merge(row)

    async def mark_resolution_event_retry(
        self, event_id: str, error: str, *, max_attempts: int = 5,
    ) -> None:
        row = await self.session.get(ResolutionOutboxRecord, event_id)
        if row is None:
            return
        attempts = int(row.attempts or 0) + 1
        row.attempts = attempts
        row.last_error = str(error)[:4000]
        if attempts >= max(1, int(max_attempts)) or "no_route" in str(error).lower():
            from common.telemetry import DEAD_LETTER_EVENTS
            row.status = "dead_letter"
            DEAD_LETTER_EVENTS.labels(
                "outbox",
                str(row.topic or "unknown"),
                "no_route" if "no_route" in str(error).lower() else "max_attempts_exceeded",
            ).inc()
        else:
            row.status = "retry"
            row.next_attempt_at = utc_now() + timedelta(seconds=min(300, 2 ** min(attempts, 8)))
        await self.session.merge(row)

    async def find_action_by_idempotency_key(self, idempotency_key: str) -> RemediationAction | None:
        """Look up a previously-persisted action by its deterministic idempotency key.

        Used by remediation-engine to detect a redelivered approval/resolution
        message and skip re-running a remediation plugin that already executed.
        """
        if not idempotency_key:
            return None
        result = await self.session.execute(
            select(ActionRecord).where(ActionRecord.idempotency_key == idempotency_key).limit(1)
        )
        record = result.scalar_one_or_none()
        if record is None:
            return None
        return RemediationAction.model_validate(record.payload)

    async def find_latest_action_by_incident(self, incident_id: UUID) -> RemediationAction | None:
        """Return authoritative execution state for UI/status polling."""
        result = await self.session.execute(
            select(ActionRecord)
            .where(ActionRecord.incident_id == incident_id)
            .order_by(ActionRecord.updated_at.desc(), ActionRecord.created_at.desc())
            .limit(1)
        )
        record = result.scalar_one_or_none()
        return RemediationAction.model_validate(record.payload) if record is not None else None

    async def find_action_by_id(self, action_id: UUID, *, tenant_id: str) -> RemediationAction | None:
        """Return an action only inside the authenticated tenant boundary."""
        result = await self.session.execute(
            select(ActionRecord).where(
                ActionRecord.id == action_id,
                ActionRecord.tenant_id == self._require("tenant_id", tenant_id),
            ).limit(1)
        )
        record = result.scalar_one_or_none()
        return RemediationAction.model_validate(record.payload) if record is not None else None

    async def save_action_audit(self, action: RemediationAction, actor: str = "remediation-engine") -> None:
        payload = action.model_dump(mode="json")
        policy_version = str(action.parameters.get("policy_version", "")).strip()
        policy_reason = str(action.parameters.get("policy_reason", "")).strip()
        if policy_version:
            payload["policy_version"] = policy_version
        if policy_reason:
            payload["policy_reason"] = policy_reason

        await self.session.merge(
            AuditLogRecord(
                id=uuid4(),
                tenant_id=action.tenant_id or "default",
                actor=self._require("audit.actor", actor),
                action=self._require("audit.action", "remediation.executed"),
                resource_type="incident",
                resource_id=self._require("audit.resource_id", str(action.incident_id)),
                payload=payload,
            )
        )

    async def get_runbook_governance(
        self, runbook_id: str, version: int = 1, *, tenant_id: str
    ) -> dict[str, Any] | None:
        normalized_tenant = self._require("tenant_id", tenant_id)
        result = await self.session.execute(
            select(RunbookVersionRecord).where(
                or_(
                    RunbookVersionRecord.tenant_id == normalized_tenant,
                    RunbookVersionRecord.tenant_id == "global",
                ),
                RunbookVersionRecord.runbook_id == self._parse_uuid(runbook_id),
                RunbookVersionRecord.version == int(version),
            )
            .order_by((RunbookVersionRecord.tenant_id == normalized_tenant).desc())
            .limit(1)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return {
            "runbook_id": str(row.runbook_id), "version": row.version, "status": row.approval_status,
            "approved_by": row.approved_by, "approved_at": row.approved_at,
            "success_count": row.success_count, "failure_count": row.failure_count,
            "suspended_reason": (row.content or {}).get("suspended_reason"), "payload": row.content or {},
        }

    @staticmethod
    def _extract_structured_runbook_content(
        *,
        tenant_id: str,
        runbook_id: UUID,
        version: int,
        title: str,
        markdown: str,
        source_ref: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        meta = dict(metadata or {})
        frontmatter: dict[str, str] = {}
        body_text = str(markdown or "")
        if body_text.startswith("---"):
            parts = body_text.split("---", 2)
            if len(parts) >= 3:
                for fm_line in parts[1].splitlines():
                    if ":" in fm_line:
                        k, v = fm_line.split(":", 1)
                        frontmatter[k.strip().lower()] = v.strip().strip("'\"")
                body_text = parts[2]

        sections: dict[str, list[str]] = {}
        current_section = ""
        for raw_line in body_text.splitlines():
            stripped = raw_line.strip()
            if stripped.startswith("## "):
                current_section = stripped[3:].strip().lower()
                sections.setdefault(current_section, [])
                continue
            if current_section and stripped:
                sections[current_section].append(stripped)

        def _clean_bullets(lines: list[str]) -> list[str]:
            items: list[str] = []
            for item in lines:
                cleaned = re.sub(r"^[-*•]\s*", "", item).strip()
                cleaned = re.sub(r"^\d+\.\s*", "", cleaned).strip()
                if cleaned.startswith("`") and cleaned.endswith("`") and len(cleaned) > 2:
                    cleaned = cleaned[1:-1].strip()
                if cleaned and cleaned.lower() not in {"none", "n/a", "tbd"}:
                    items.append(cleaned)
            return items

        def _section_lines(*names: str) -> list[str]:
            for name in names:
                if sections.get(name):
                    return sections[name]
            return []

        def _coerce_list(value: Any, *fallback_sections: str) -> list[str]:
            if isinstance(value, (list, tuple)):
                items = [
                    str(v).strip().strip("`").strip()
                    for v in value
                    if str(v).strip() and str(v).strip().lower() not in {"none", "n/a", "tbd"}
                ]
                if items:
                    return items
            elif isinstance(value, str) and value.strip():
                items = _clean_bullets([line for line in value.splitlines() if line.strip()])
                if items:
                    return items
            return _clean_bullets(_section_lines(*fallback_sections))

        remediation_steps = _coerce_list(
            meta.get("remediation_steps"), "remediation steps", "remediation", "recovery steps"
        )
        validation_steps = _coerce_list(
            meta.get("validation_steps"), "validation steps", "validation", "verification"
        )
        rollback_steps = _coerce_list(
            meta.get("rollback_steps"), "rollback steps", "rollback"
        )
        commands = _coerce_list(meta.get("commands"), "remediation steps", "remediation") or list(remediation_steps)

        symptom_and_root_cause = str(
            meta.get("symptom_and_root_cause")
            or meta.get("root_cause")
            or meta.get("observed_symptoms")
            or " ".join(
                _section_lines(
                    "symptom & root cause",
                    "observed symptoms & root cause",
                    "root cause",
                    "symptoms & root cause",
                )
            )
            or ""
        ).strip()
        business_impact = str(
            meta.get("business_impact")
            or meta.get("impact")
            or " ".join(_section_lines("business impact", "impact"))
            or ""
        ).strip()

        service = str(meta.get("service") or frontmatter.get("service") or "").strip()
        if not service:
            raw_services = meta.get("services") or meta.get("service_scope")
            if isinstance(raw_services, (list, tuple)) and raw_services:
                service = str(raw_services[0] or "").strip()
            elif isinstance(raw_services, str) and raw_services.strip():
                service = raw_services.split(",")[0].strip()
        if not service:
            for line in _section_lines("service scope", "overview"):
                m = re.search(r"\*{0,2}service\*{0,2}:\s*`?([^`\s]+)`?", line, flags=re.IGNORECASE)
                if m:
                    service = m.group(1).strip()
                    break

        alert_name = str(meta.get("alert_name") or frontmatter.get("alert_name") or "").strip()
        if not alert_name:
            for line in _section_lines("service scope", "overview"):
                m = re.search(r"\*{0,2}alert(?:\s+pattern|\s+name)?\*{0,2}:\s*`?([^`\n]+)`?", line, flags=re.IGNORECASE)
                if m:
                    alert_name = m.group(1).strip()
                    break

        raw_slug = str(meta.get("slug") or meta.get("runbook_slug") or "").strip()
        if not raw_slug:
            ref_tail = str(source_ref or "").strip()
            if "://" in ref_tail:
                ref_tail = ref_tail.split("://", 1)[1]
            slug_candidate = re.sub(r"[^a-z0-9]+", "-", ref_tail.lower()).strip("-")
            raw_slug = f"learned-{slug_candidate}" if slug_candidate else f"learned-runbook-{str(runbook_id)[:8]}"

        service_scope = list(meta.get("service_scope") or []) if isinstance(meta.get("service_scope"), (list, tuple)) else []
        if service and service not in service_scope:
            service_scope.insert(0, service)
        if not service_scope:
            service_scope = [tenant_id]

        checksum = str(meta.get("checksum") or "").strip()
        if not checksum:
            checksum = f"sha256:{hashlib.sha256(str(markdown or title or raw_slug).encode()).hexdigest()}"

        return {
            **meta,
            "runbook_id": str(runbook_id),
            "slug": raw_slug,
            "runbook_slug": raw_slug,
            "version": int(version),
            "title": str(title or raw_slug),
            "markdown": str(markdown or ""),
            "source_ref": str(source_ref or ""),
            "service": service,
            "service_scope": service_scope,
            "alert_name": alert_name,
            "symptom_and_root_cause": symptom_and_root_cause,
            "business_impact": business_impact,
            "remediation_steps": remediation_steps,
            "validation_steps": validation_steps,
            "rollback_steps": rollback_steps,
            "commands": commands,
            "risk_class": str(meta.get("risk_class") or meta.get("risk_level") or "medium"),
            "blast_radius": str(meta.get("blast_radius") or "single_service"),
            "requires_hitl": bool(meta.get("requires_hitl", True)),
            "status": str(meta.get("status") or "approved"),
            "approval_status": "approved",
            "checksum": checksum,
            "execution_Verification": dict(meta.get("execution_Verification") or {
                "validation_steps": validation_steps,
                "rollback_steps": rollback_steps,
                "verified": bool(validation_steps),
            }),
        }

    async def _upsert_runbook_governance_records(
        self,
        *,
        tenant_id: str,
        runbook_id: UUID,
        version: int,
        approved_by: str,
        approver_role: str = "HITL_APPROVER",
        reason: str | None = None,
        owner: str | None = None,
        risk_level: str = "medium",
        required_approval: str = "HITL_APPROVER",
        issue_signature: str | None = None,
        content: dict[str, Any],
        now: datetime | None = None,
    ) -> RunbookVersionRecord:
        ts = now or datetime.now(UTC)
        slug = str(content.get("slug") or content.get("runbook_slug") or f"learned-runbook-{str(runbook_id)[:8]}")[:255]
        service = str(content.get("service") or (content.get("service_scope") or ["unknown"])[0] or "unknown")[:255]
        alert_family = str(content.get("alert_name") or content.get("alert_family") or content.get("title") or slug)[:255]
        owner_val = str(owner or content.get("owner_team") or content.get("owner") or approved_by)[:255]
        sig_val = str(
            issue_signature
            or content.get("issue_signature")
            or hashlib.sha256(f"{tenant_id}:{service}:{alert_family}".encode()).hexdigest()
        )[:64]

        rb_master = await self.session.get(RunbookRecord, runbook_id)
        if rb_master is None:
            rb_by_slug = (
                await self.session.execute(
                    select(RunbookRecord).where(
                        RunbookRecord.tenant_id == tenant_id,
                        RunbookRecord.slug == slug,
                    ).limit(1)
                )
            ).scalar_one_or_none()
            if rb_by_slug is not None and rb_by_slug.runbook_id != runbook_id:
                slug = f"{slug[:240]}-{str(runbook_id)[:8]}"
            self.session.add(
                RunbookRecord(
                    runbook_id=runbook_id,
                    tenant_id=tenant_id,
                    slug=slug,
                    owner=owner_val,
                    service=service,
                    alert_family=alert_family,
                    created_at=ts,
                    updated_at=ts,
                )
            )
        else:
            rb_master.owner = owner_val
            rb_master.service = service
            rb_master.alert_family = alert_family
            rb_master.updated_at = ts

        rb_row = await self.session.get(RunbookVersionRecord, (runbook_id, int(version)))
        if rb_row is None:
            rb_row = RunbookVersionRecord(
                runbook_id=runbook_id,
                version=int(version),
                tenant_id=tenant_id,
                issue_signature=sig_val,
                approval_status="approved",
                owner=owner_val,
                risk_level=str(risk_level or "medium")[:32],
                required_approval=str(required_approval or "HITL_APPROVER")[:32],
                content=dict(content),
                approved_by=str(approved_by)[:255],
                approved_at=ts,
                created_at=ts,
            )
            self.session.add(rb_row)
        else:
            rb_row.approval_status = "approved"
            rb_row.approved_by = str(approved_by)[:255]
            rb_row.approved_at = ts
            rb_row.content = {**dict(rb_row.content or {}), **dict(content)}

        approval_row = (
            await self.session.execute(
                select(RunbookApprovalRecord).where(
                    RunbookApprovalRecord.runbook_id == runbook_id,
                    RunbookApprovalRecord.version == int(version),
                    RunbookApprovalRecord.status == "approved",
                ).limit(1)
            )
        ).scalar_one_or_none()
        if approval_row is None:
            self.session.add(
                RunbookApprovalRecord(
                    approval_id=uuid4(),
                    runbook_id=runbook_id,
                    version=int(version),
                    status="approved",
                    approver=str(approved_by)[:255],
                    approver_role=str(approver_role or "HITL_APPROVER")[:64],
                    reason=str(reason)[:1000] if reason else "Governed runbook version approved",
                    approved_at=ts,
                )
            )
        else:
            approval_row.approver = str(approved_by)[:255]
            approval_row.approver_role = str(approver_role or "HITL_APPROVER")[:64]
            approval_row.approved_at = ts
            if reason:
                approval_row.reason = str(reason)[:1000]

        return rb_row

    async def approve_runbook_version(
        self, *, runbook_id: str, version: int, approved_by: str,
        tenant_id: str, payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        tenant_id = self._require("tenant_id", tenant_id)
        parsed_rb_id = self._parse_uuid(runbook_id)
        if parsed_rb_id is None:
            raise ValueError("runbook_id must be a valid UUID")
        existing = await self.session.get(RunbookVersionRecord, (parsed_rb_id, int(version)))
        merged_meta = {**dict((existing.content if existing else None) or {}), **dict(payload or {})}
        structured_content = self._extract_structured_runbook_content(
            tenant_id=tenant_id,
            runbook_id=parsed_rb_id,
            version=int(version),
            title=str(merged_meta.get("title") or merged_meta.get("slug") or f"runbook-{str(parsed_rb_id)[:8]}"),
            markdown=str(merged_meta.get("markdown") or ""),
            source_ref=str(merged_meta.get("source_ref") or f"runbook://{parsed_rb_id}"),
            metadata=merged_meta,
        )
        row = await self._upsert_runbook_governance_records(
            tenant_id=tenant_id,
            runbook_id=parsed_rb_id,
            version=int(version),
            approved_by=str(approved_by),
            approver_role=str(merged_meta.get("approver_role") or "HITL_APPROVER"),
            reason=str(merged_meta.get("approval_reason") or "Approved via approve_runbook_version"),
            owner=str(merged_meta.get("owner") or approved_by),
            risk_level=str(merged_meta.get("risk_level") or "medium"),
            required_approval=str(merged_meta.get("required_approval") or "mandatory"),
            issue_signature=str(merged_meta.get("issue_signature") or "manual-approval")[:64],
            content=structured_content,
        )
        await self.session.flush()
        return {"runbook_id": str(row.runbook_id), "version": row.version, "status": row.approval_status}

    async def record_runbook_execution_outcome(
        self, *, runbook_id: str, version: int, successful: bool, modified: bool,
        actor: str, tenant_id: str, metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        tenant_id = self._require("tenant_id", tenant_id)
        result = await self.session.execute(
            select(RunbookVersionRecord).where(
                RunbookVersionRecord.tenant_id == tenant_id,
                RunbookVersionRecord.runbook_id == self._parse_uuid(runbook_id),
                RunbookVersionRecord.version == int(version),
            ).limit(1)
        )
        row = result.scalar_one_or_none()
        if row is None:
            row = RunbookVersionRecord(
                tenant_id=tenant_id, runbook_id=self._parse_uuid(runbook_id), version=int(version),
                issue_signature=str((metadata or {}).get("issue_signature") or "execution")[:64],
                approval_status=str((metadata or {}).get("runbook_status") or "draft"),
                owner=str(actor), risk_level=str((metadata or {}).get("risk_level") or "medium"),
                required_approval="mandatory", content=metadata or {},
            )
            self.session.add(row)
        row.success_count = int(row.success_count or 0) + int(successful)
        row.failure_count = int(row.failure_count or 0) + int(not successful)
        if modified or not successful:
            row.approval_status = "suspended"
            content = dict(row.content or {})
            content["suspended_reason"] = f"modified during execution by {actor}" if modified else f"execution failed; recorded by {actor}"
            row.content = content
        row.last_validated_at = datetime.now(UTC)
        outcome_payload = dict(metadata or {})
        incident_id = str(outcome_payload.get("incident_id") or outcome_payload.get("alert_id") or "unknown")[:128]
        outcome_key = f"{tenant_id}:{incident_id}:{row.runbook_id}:{row.version}"
        outcome_id = UUID(hashlib.md5(outcome_key.encode(), usedforsecurity=False).hexdigest())
        await self.session.merge(RunbookOutcomeRecord(
            outcome_id=outcome_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            runbook_id=row.runbook_id,
            runbook_version=row.version,
            reviewed=bool(outcome_payload.get("outcome_reviewed") and outcome_payload.get("outcome_reviewed_by")),
            successful=successful,
            validation=outcome_payload,
        ))
        audit_payload = {
            "successful": successful,
            "modified": modified,
            "runbook_version": row.version,
            "resulting_status": row.approval_status,
            "incident_id": incident_id,
        }
        canonical = json.dumps(audit_payload, sort_keys=True, separators=(",", ":"))
        self.session.add(LearningAuditRecord(
            tenant_id=tenant_id,
            actor=str(actor),
            action="runbook.execution.recorded",
            resource_type="runbook",
            resource_id=str(row.runbook_id),
            payload=audit_payload,
            payload_sha256=hashlib.sha256(canonical.encode()).hexdigest(),
        ))
        await self.session.flush()
        return {"runbook_id": str(row.runbook_id), "version": row.version, "status": row.approval_status}

    async def save_report(self, report: ResolutionReport, *, tenant_id: str | None = None) -> None:
        verified_tenant = require_tenant_id(report.tenant_id, source="resolution report persistence")
        if tenant_id is not None and require_tenant_id(tenant_id, source="resolution report persistence") != verified_tenant:
            raise ValueError("report tenant does not match persistence tenant")
        validation_checksum = str(report.validation_checksum or "").strip()
        if not validation_checksum:
            validation_material = json.dumps(report.validation, sort_keys=True, separators=(",", ":"))
            validation_checksum = f"sha256:{hashlib.sha256(validation_material.encode()).hexdigest()}"
        await self.session.merge(
            RcaReportRecord(
                id=self._require("report.id", report.id),
                tenant_id=verified_tenant,
                incident_id=self._require("report.incident_id", report.incident_id),
                recommendation_id=self._parse_uuid(report.recommendation_id),
                resolution_plan_id=self._parse_uuid(report.resolution_plan_id),
                plan_fingerprint=str(report.plan_fingerprint or "").strip() or None,
                approval_id=self._parse_uuid(report.approval_id),
                remediation_action_id=self._parse_uuid(report.remediation_action_id),
                validation_checksum=validation_checksum,
                closure_kind=str(report.closure_kind or report.metadata.get("closure_kind") or "").strip() or None,
                closure_status=str(
                    report.closure_status or ("closed" if report.health_restored else "validation_failed")
                ).strip(),
                root_cause=self._require("report.root_cause", report.root_cause),
                impact=self._require("report.impact", report.impact),
                payload=report.model_dump(mode="json"),
            )
        )
        await self._save_validation_observations(report, tenant_id=verified_tenant)

    async def _save_validation_observations(self, report: ResolutionReport, *, tenant_id: str) -> None:
        observations = [
            *(
                report.metadata.get("pre_state_validation_observations")
                if isinstance(report.metadata.get("pre_state_validation_observations"), list) else []
            ),
            *(
                report.metadata.get("independent_validation_observations")
                if isinstance(report.metadata.get("independent_validation_observations"), list) else []
            ),
        ]
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            observed_at = datetime.fromisoformat(str(observation.get("observed_at") or "").replace("Z", "+00:00"))
            material = ":".join((
                str(report.id), str(observation.get("validator_id") or ""),
                observed_at.isoformat(), str(observation.get("result_checksum") or ""),
            ))
            await self.session.merge(ValidationObservationRecord(
                id=hashlib.sha256(material.encode()).hexdigest(), tenant_id=tenant_id,
                incident_id=report.incident_id, report_id=report.id,
                remediation_action_id=report.remediation_action_id,
                validator_id=self._require("validation.validator_id", observation.get("validator_id")),
                connector_id=self._require("validation.connector_id", observation.get("connector_id")),
                target_resource_id=self._require("validation.target_resource_id", observation.get("target_resource_id")),
                phase=str(observation.get("phase") or "post_state"),
                observation_window_start=self._parse_datetime(observation.get("observation_window_start")),
                observation_window_end=self._parse_datetime(observation.get("observation_window_end")),
                observed_at=observed_at, collected_at=utc_now(),
                authoritative_source=self._require("validation.authoritative_source", observation.get("connector_id")),
                result_checksum=self._require("validation.result_checksum", observation.get("result_checksum")),
                passed=observation.get("passed") is True, payload=observation,
            ))

    async def save_recommendation_as_audit(self, recommendation: Recommendation, *, tenant_id: str | None = None) -> None:
        verified_tenant = require_tenant_id(recommendation.tenant_id, source="recommendation audit persistence")
        if tenant_id is not None and require_tenant_id(tenant_id, source="recommendation audit persistence") != verified_tenant:
            raise ValueError("recommendation tenant does not match persistence tenant")
        await self.session.merge(
            AuditLogRecord(
                id=self._require("recommendation.id", recommendation.id),
                tenant_id=verified_tenant,
                actor=self._require("audit.actor", "resolution-agent"),
                action=self._require("audit.action", "recommendation.generated"),
                resource_type="incident",
                resource_id=self._require("audit.resource_id", str(recommendation.incident_id)),
                payload=recommendation.model_dump(mode="json"),
            )
        )
        metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
        analysis_request_id = self._parse_uuid(metadata.get("analysis_request_id"))
        if analysis_request_id is not None:
            analysis_request = await self.session.get(AnalysisRequestRecord, analysis_request_id)
            if analysis_request is not None and analysis_request.tenant_id == verified_tenant:
                analysis_request.status = "complete"
                analysis_request.recommendation_id = recommendation.id
                analysis_request.terminal_reason = None
                analysis_request.completed_at = utc_now()
        context_snapshot_id = self._parse_uuid(metadata.get("context_snapshot_id"))
        alert_id = self._parse_uuid(metadata.get("alert_id"))
        context_fingerprint = str(metadata.get("context_fingerprint") or "").strip()
        try:
            rca_version = int(metadata.get("rca_version") or 0)
        except (TypeError, ValueError):
            rca_version = 0
        if not all((analysis_request_id, context_snapshot_id, alert_id, context_fingerprint, rca_version > 0)):
            # Historical recommendations remain readable but explicitly
            # unbound; never fabricate normalized identities for them.
            return
        snapshot = await self.session.get(ContextSnapshotRecord, context_snapshot_id)
        if (
            snapshot is None
            or snapshot.tenant_id != verified_tenant
            or str(snapshot.incident_id) != str(recommendation.incident_id)
            or snapshot.context_fingerprint != context_fingerprint
        ):
            raise ValueError("recommendation context binding is not valid for persistence")
        latest_snapshot_id = await self.session.scalar(
            select(ContextSnapshotRecord.snapshot_id)
            .where(
                ContextSnapshotRecord.tenant_id == verified_tenant,
                ContextSnapshotRecord.incident_id == str(recommendation.incident_id),
            )
            .order_by(ContextSnapshotRecord.snapshot_version.desc(), ContextSnapshotRecord.collected_at.desc())
            .with_for_update()
            .limit(1)
        )
        if latest_snapshot_id != context_snapshot_id:
            raise ValueError("recommendation context snapshot was superseded before persistence")
        evidence_ids = sorted({str(value) for value in metadata.get("evidence_ids") or [] if str(value).strip()})
        if not set(evidence_ids).issubset(set(snapshot.evidence_ids or [])):
            raise ValueError("recommendation cites evidence outside its context snapshot")
        evidence_set_digest = "sha256:" + hashlib.sha256(
            json.dumps(evidence_ids, separators=(",", ":")).encode()
        ).hexdigest()
        if str(metadata.get("evidence_set_digest") or "") != evidence_set_digest:
            raise ValueError("recommendation evidence-set digest is invalid")
        plan = metadata.get("execution_plan") if isinstance(metadata.get("execution_plan"), dict) else {}
        values = {
            "binding_id": recommendation.id,
            "tenant_id": verified_tenant,
            "project_id": self._require("recommendation.project_id", metadata.get("project_id")),
            "incident_id": recommendation.incident_id,
            "alert_id": alert_id,
            "analysis_request_id": analysis_request_id,
            "context_snapshot_id": context_snapshot_id,
            "context_fingerprint": context_fingerprint,
            "evidence_ids": evidence_ids,
            "evidence_set_digest": evidence_set_digest,
            "investigation_id": self._parse_uuid(metadata.get("investigation_id")),
            "model_version": self._require("recommendation.model_version", metadata.get("model_version")),
            "prompt_version": self._require("recommendation.prompt_version", metadata.get("prompt_version")),
            "tool_versions": dict(metadata.get("tool_versions") or {}),
            "generated_at": recommendation.created_at,
            "recommendation_id": recommendation.id,
            "rca_version": rca_version,
            "resolution_plan_id": self._parse_uuid(plan.get("plan_id") or plan.get("id")),
            "plan_fingerprint": str(plan.get("plan_fingerprint") or plan.get("fingerprint") or "") or None,
            "status": str(metadata.get("rca_status") or "pending"),
            "created_at": recommendation.created_at,
            "expires_at": snapshot.expires_at,
        }
        existing = await self.session.get(IncidentInvestigationBindingRecord, recommendation.id)
        if existing is not None:
            immutable = (
                existing.tenant_id, existing.project_id, existing.incident_id, existing.alert_id,
                existing.analysis_request_id, existing.context_snapshot_id, existing.context_fingerprint,
                tuple(existing.evidence_ids or []), existing.evidence_set_digest,
                existing.investigation_id, existing.model_version, existing.prompt_version,
                existing.tool_versions, existing.generated_at, existing.recommendation_id, existing.rca_version,
            )
            incoming_values = dict(values)
            incoming_values["evidence_ids"] = tuple(evidence_ids)
            incoming = tuple(incoming_values[key] for key in (
                "tenant_id", "project_id", "incident_id", "alert_id", "analysis_request_id",
                "context_snapshot_id", "context_fingerprint", "evidence_ids", "evidence_set_digest",
                "investigation_id", "model_version", "prompt_version", "tool_versions", "generated_at",
                "recommendation_id", "rca_version",
            ))
            if immutable != incoming:
                raise ValueError("immutable investigation binding already exists with different identities")
            return
        self.session.add(IncidentInvestigationBindingRecord(**values))
        await self._advance_incident_status_on_grounded_rca(
            incident_id=recommendation.incident_id, tenant_id=verified_tenant, rca_status=values["status"],
        )

    # Nothing else in this pipeline ever moves IncidentRecord.status forward -
    # the only other writer is update_incident_approval_status, driven
    # entirely by a human (or policy-engine) approval decision. That left a
    # genuinely grounded RCA with zero operator-visible signal: the incident
    # stayed "investigating" in every list view for as long as it took for
    # someone to separately select and approve a catalog option, even though
    # the investigation itself had already reached a real, corroborated
    # conclusion. Reproduced live across a 20-incident sample: 8 reached
    # "grounded" underneath while every one of their outer incidents still
    # read "investigating". Restricted to the early, pre-decision statuses so
    # this can only ever move a stalled-looking incident forward, never
    # regress one that already has real approval/execution progress.
    _EARLY_INCIDENT_STATUSES = frozenset({
        "", "open", "received", "normalized", "correlated", "triaging",
        "detected", "collecting", "context_ready", "investigating", "waiting_for_human",
    })

    async def _advance_incident_status_on_grounded_rca(
        self, *, incident_id: Any, tenant_id: str, rca_status: str,
    ) -> None:
        grounded = str(rca_status or "").strip().lower() == "grounded"
        incident_uuid = self._parse_uuid(incident_id)
        if incident_uuid is None:
            return
        incident = await self.session.get(IncidentRecord, incident_uuid)
        if incident is None or incident.tenant_id != tenant_id:
            return
        current_incident_status = str(incident.status or "").strip().lower()
        if grounded and current_incident_status in self._EARLY_INCIDENT_STATUSES:
            incident.status = "rca_ready"
            payload = dict(incident.payload or {})
            payload["status"] = "rca_ready"
            payload["state"] = "rca_ready"
            incident.payload = payload
            incident.updated_at = utc_now()
            await self.session.merge(incident)
        elif not grounded and current_incident_status == "rca_ready":
            # "rca_ready" claims the *current* analysis is grounded and
            # ready to act on - unlike the approval/remediation statuses
            # past it, nothing has actually been committed to yet, so
            # leaving it sticky when a later regeneration comes back
            # "insufficient_evidence" is actively misleading, not merely
            # stale: an operator opening this incident sees "ready to
            # resolve" for an incident whose own latest analysis just said
            # otherwise. Reproduced live: incident
            # fc99d4e6-687c-48e0-8b28-91f07a0cf49b reached "grounded" on RCA
            # v1, then two later regenerations (v2, v3) both came back
            # "insufficient_evidence" - IncidentRecord.status stayed
            # "rca_ready" throughout, permanently detached from what the
            # latest, actually-current analysis supports, while
            # IncidentProjectionRecord.status correctly tracked "investigating"
            # the whole time via the normal event-driven path (see
            # apply_incident_event's event_record.status assignment) -
            # confirming the projection side needs no equivalent fix here.
            # Retreating only from exactly "rca_ready" (never from
            # "awaiting_approval" or anything further along) preserves the
            # existing, deliberate rule that real human/policy-engine
            # progress must never be undone by a later regeneration.
            incident.status = "investigating"
            payload = dict(incident.payload or {})
            payload["status"] = "investigating"
            payload["state"] = "investigating"
            incident.payload = payload
            incident.updated_at = utc_now()
            await self.session.merge(incident)
        # IncidentRecord and IncidentProjectionRecord are two independent
        # tables, each with its own current status and its own guard against
        # regression - a run that finds IncidentRecord already advanced (and
        # so skips the block above) must still be free to advance the
        # projection, and vice versa. This function mutates IncidentRecord
        # directly, bypassing the incident-event stream that is
        # IncidentProjectionRecord's only normal writer (see
        # apply_incident_event's event_record.status assignment above).
        # Without also updating the projection here, this fix never reaches
        # the Triage queue or any other view built on the projection:
        # IncidentRecord.status correctly advanced to "rca_ready" while
        # IncidentProjectionRecord.status stayed "investigating"
        # indefinitely - reproduced live across every incident whose RCA
        # reached "grounded" underneath, still showing "Generating RCA" in
        # the queue no matter how many regenerations ran. A first attempt at
        # this fix gated the projection update on the same early-return as
        # IncidentRecord's own guard, which meant it could never actually run
        # for exactly the incidents already stuck this way - their
        # IncidentRecord had already reached "rca_ready" from before, so the
        # combined guard returned before ever reaching the projection at all.
        # Guarded independently by _status_rank so it can advance a
        # lagging projection on its own, while still never regressing one
        # that has already advanced further (e.g. via a real
        # approval/remediation event) even if its exact status string isn't
        # one of the early ones enumerated above.
        projection = await self.session.get(IncidentProjectionRecord, incident_uuid)
        if (
            grounded
            and projection is not None
            and projection.tenant_id == tenant_id
            and _status_rank(projection.status) < _status_rank("rca_ready")
        ):
            projection.status = "rca_ready"
            if projection.lifecycle_state in {"DETECTED", "REQUIREMENTS_IDENTIFIED", "COLLECTING", "CONTEXT_READY", "INVESTIGATING", "WAITING_FOR_HUMAN"}:
                projection.lifecycle_state = "RCA_READY"
                projection.lifecycle_version = int(projection.lifecycle_version or 1) + 1
            projection.updated_at = utc_now()
            await self.session.merge(projection)

    async def reserve_incident_rca_version(self, *, tenant_id: str, incident_id: UUID,
                                           recommendation_id: UUID) -> int:
        """Serialize allocations on the incident row; retries keep their version."""
        tenant = require_tenant_id(tenant_id, source="RCA version reservation")
        incident = await self.session.scalar(select(IncidentRecord).where(
            IncidentRecord.id == incident_id, IncidentRecord.tenant_id == tenant,
        ).with_for_update())
        if incident is None:
            raise ValueError("RCA version reservation requires an existing scoped incident")
        prior = await self.session.get(IncidentRcaVersionReservationRecord, recommendation_id)
        if prior is not None:
            if prior.tenant_id != tenant or prior.incident_id != incident_id:
                raise ValueError("RCA version reservation identity mismatch")
            committed_existing = await self.session.get(IncidentInvestigationBindingRecord, recommendation_id)
            if committed_existing is None:
                next_committed = await self.next_incident_rca_version(tenant_id=tenant, incident_id=incident_id)
                if prior.rca_version < next_committed:
                    reserved = await self.session.scalar(select(func.max(IncidentRcaVersionReservationRecord.rca_version)).where(
                        IncidentRcaVersionReservationRecord.tenant_id == tenant,
                        IncidentRcaVersionReservationRecord.incident_id == incident_id,
                    ))
                    prior.rca_version = max(next_committed, int(reserved or 0) + 1)
                    await self.session.flush()
            return prior.rca_version
        committed = await self.session.get(IncidentInvestigationBindingRecord, recommendation_id)
        if committed is not None:
            if committed.tenant_id != tenant or committed.incident_id != incident_id:
                raise ValueError("RCA binding identity mismatch")
            return committed.rca_version
        next_committed = await self.next_incident_rca_version(tenant_id=tenant, incident_id=incident_id)
        reserved = await self.session.scalar(select(func.max(IncidentRcaVersionReservationRecord.rca_version)).where(
            IncidentRcaVersionReservationRecord.tenant_id == tenant,
            IncidentRcaVersionReservationRecord.incident_id == incident_id,
        ))
        version = max(next_committed, int(reserved or 0) + 1)
        self.session.add(IncidentRcaVersionReservationRecord(recommendation_id=recommendation_id,
            tenant_id=tenant, incident_id=incident_id, rca_version=version))
        await self.session.flush()
        return version

    async def next_incident_rca_version(
        self, *, tenant_id: str, incident_id: UUID | str,
    ) -> int:
        """Return the next durable RCA generation for an incident.

        Context events produced by enrichment can legitimately omit an RCA
        version or carry the version whose evidence gap they are satisfying.
        Derive the new generation from persisted history so a regeneration
        never falls back to version 1 for an established incident.
        """
        tenant = require_tenant_id(tenant_id, source="RCA version allocation")
        incident_uuid = self._parse_uuid(incident_id)
        if incident_uuid is None:
            raise ValueError("RCA version allocation requires a valid incident UUID")
        current = await self.session.scalar(
            select(func.max(IncidentInvestigationBindingRecord.rca_version)).where(
                IncidentInvestigationBindingRecord.tenant_id == tenant,
                IncidentInvestigationBindingRecord.incident_id == incident_uuid,
            )
        )
        current_req = await self.session.scalar(
            select(func.max(ContextEvidenceRequirementRecord.rca_version)).where(
                ContextEvidenceRequirementRecord.tenant_id == tenant,
                ContextEvidenceRequirementRecord.incident_id == incident_uuid,
            )
        )
        return max(1, int(current or 0) + 1, int(current_req or 0) + 1)

    async def create_or_reuse_analysis_request(
        self,
        *,
        request_id: UUID,
        tenant_id: str,
        incident_id: UUID,
        alert_id: UUID,
        expected_recommendation_id: UUID,
        mode: str,
    ) -> tuple[AnalysisRequestRecord, bool]:
        active = (
            await self.session.execute(
                select(AnalysisRequestRecord)
                .where(
                    AnalysisRequestRecord.tenant_id == tenant_id,
                    AnalysisRequestRecord.incident_id == incident_id,
                    AnalysisRequestRecord.status.in_(("accepted", "queued", "published", "running")),
                )
                .order_by(AnalysisRequestRecord.created_at.desc())
                .with_for_update()
                .limit(1)
            )
        ).scalar_one_or_none()
        if active is not None:
            # A request whose own expires_at has already passed is not truly
            # "active" no matter what status it's still parked at - nothing
            # ever transitions it out of "published" on its own once its
            # underlying event is lost (dropped by a crashed consumer, a
            # message-bus outage, or - see resolution-agent's `handle()` - a
            # supersede path that never ran to completion). `expire_analysis_
            # request` already exists to terminal-ize exactly this case (used
            # by some periodic sweep elsewhere), so call it here too rather
            # than inventing a second, inconsistent way to treat expiry -
            # otherwise this one dead row permanently blocks every future
            # regeneration attempt for the same incident:
            # `_publish_analysis_regeneration_command` returns its stale
            # `delivery` value without ever publishing anything new, which
            # reads as a normal success ("delivery=published") while doing
            # nothing at all. Reproduced live: reprocessing the same 8
            # incidents a second time, well past their 15-minute expiry,
            # still returned "OK ... delivery=published" for all 8 with zero
            # new resolution-agent log activity for any of them.
            if not await self.expire_analysis_request(active):
                return active, False
        row = AnalysisRequestRecord(
            request_id=request_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert_id=alert_id,
            expected_recommendation_id=expected_recommendation_id,
            mode=mode,
            status="accepted",
            delivery="pending",
            expires_at=utc_now() + timedelta(minutes=15),
        )
        self.session.add(row)
        await self.session.flush()
        return row, True

    async def get_analysis_request(self, request_id: UUID, *, tenant_id: str) -> AnalysisRequestRecord | None:
        return (
            await self.session.execute(
                select(AnalysisRequestRecord).where(
                    AnalysisRequestRecord.request_id == request_id,
                    AnalysisRequestRecord.tenant_id == tenant_id,
                )
            )
        ).scalar_one_or_none()

    async def fail_analysis_request(
        self, request_id: UUID | str, *, tenant_id: str, reason: str,
    ) -> bool:
        request_uuid = self._parse_uuid(request_id)
        if request_uuid is None:
            return False
        row = await self.get_analysis_request(request_uuid, tenant_id=tenant_id)
        if row is None or row.status in {"complete", "failed", "timed_out", "superseded"}:
            return False
        row.status = "failed"
        row.terminal_reason = (str(reason).strip() or "analysis_handler_failed")[:255]
        row.completed_at = utc_now()
        return True

    async def expire_analysis_request(self, row: AnalysisRequestRecord, *, now: datetime | None = None) -> bool:
        current = now or utc_now()
        expires_at = row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if row.status not in {"accepted", "queued", "published", "running"} or expires_at > current:
            return False
        row.status = "timed_out"
        row.terminal_reason = "analysis_deadline_exceeded"
        row.completed_at = current
        return True

    async def save_knowledge_base(self, report: ResolutionReport, service: str = "unknown", *, tenant_id: str | None = None) -> None:
        verified_tenant = require_tenant_id(report.tenant_id, source="resolution knowledge persistence")
        if tenant_id is not None and require_tenant_id(tenant_id, source="resolution knowledge persistence") != verified_tenant:
            raise ValueError("report tenant does not match knowledge tenant")
        await self.session.merge(
            KnowledgeBaseRecord(
                id=self._require("knowledge_base.id", report.id),
                tenant_id=verified_tenant,
                service=self._require("knowledge_base.service", service),
                title=self._require("knowledge_base.title", f"RCA for incident {report.incident_id}"),
                content=self._require("knowledge_base.content", report.knowledge_base_entry),
                embedding_ref=self._require("knowledge_base.embedding_ref", str(report.id)),
                payload=report.model_dump(mode="json"),
            )
        )

    async def find_context_knowledge(
        self,
        *,
        tenant_id: str,
        service: str,
        environment: str,
        alert_name: str,
        alert_signature: str,
        not_before: datetime,
    ) -> dict[str, Any] | None:
        result = await self.session.execute(
            select(ContextKnowledgeRecord)
            .where(
                ContextKnowledgeRecord.tenant_id == tenant_id,
                ContextKnowledgeRecord.service == service,
                ContextKnowledgeRecord.environment == environment,
                or_(
                    ContextKnowledgeRecord.alert_signature == alert_signature,
                    func.lower(ContextKnowledgeRecord.alert_name) == alert_name.strip().lower(),
                ),
                ContextKnowledgeRecord.collected_at >= not_before,
            )
            .order_by(ContextKnowledgeRecord.collected_at.desc())
            .limit(1)
        )
        record = result.scalar_one_or_none()
        if record is None:
            return None
        # Transparently migrate knowledge created with an older, label-sensitive
        # signature. Subsequent occurrences use the stable alert-type key.
        match_type = "signature" if record.alert_signature == alert_signature else "alert_type"
        record.alert_signature = alert_signature
        record.reuse_count = int(record.reuse_count or 0) + 1
        return {
            "id": str(record.id),
            "source_alert_id": str(record.source_alert_id) if record.source_alert_id else None,
            "source_incident_id": str(record.source_incident_id) if record.source_incident_id else None,
            "reuse_count": record.reuse_count,
            "match_type": match_type,
            "payload": record.payload if isinstance(record.payload, dict) else {},
            "resolution_payload": record.resolution_payload if isinstance(record.resolution_payload, dict) else {},
            "collected_at": record.collected_at.isoformat(),
        }

    async def find_learned_runbooks(
        self,
        *,
        tenant_id: str,
        service: str | None = None,
        alert_name: str | None = None,
        alert_signature: str | None = None,
        environment: str | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        rows = (
            await self.session.execute(
                select(RunbookVersionRecord)
                .join(
                    RunbookApprovalRecord,
                    (RunbookApprovalRecord.runbook_id == RunbookVersionRecord.runbook_id)
                    & (RunbookApprovalRecord.version == RunbookVersionRecord.version)
                    & (RunbookApprovalRecord.status == "approved"),
                )
                .where(
                    RunbookVersionRecord.tenant_id == tenant_id,
                    RunbookVersionRecord.approval_status == "approved",
                )
                .order_by(RunbookVersionRecord.approved_at.desc(), RunbookVersionRecord.version.desc())
            )
        ).scalars().all()
        results: list[dict[str, Any]] = []
        svc_norm = (service or "").strip().lower()
        alert_norm = (alert_name or "").strip().lower()
        sig_norm = (alert_signature or "").strip()
        for row in rows:
            content = dict(row.content or {}) if isinstance(row.content, dict) else {}
            row_svc = str(content.get("service") or "").strip().lower()
            row_alert = str(content.get("alert_name") or "").strip().lower()
            row_sig = str(content.get("alert_signature") or row.issue_signature or "").strip()
            if svc_norm and row_svc and row_svc != svc_norm:
                continue
            if alert_norm and alert_norm != "unknown" and row_alert and row_alert != alert_norm:
                if not (sig_norm and row_sig == sig_norm):
                    continue
            cmds = list(content.get("commands") or content.get("remediation_steps") or [])
            results.append({
                **content,
                "runbook_id": str(row.runbook_id),
                "version": int(row.version),
                "tenant_id": row.tenant_id,
                "issue_signature": row.issue_signature,
                "approval_status": row.approval_status,
                "risk_level": row.risk_level,
                "required_approval": row.required_approval,
                "remediation_commands": cmds,
            })
            if len(results) >= max(1, int(limit)):
                break
        return results

    async def save_context_knowledge(
        self,
        *,
        tenant_id: str,
        service: str,
        environment: str,
        alert_name: str,
        alert_signature: str,
        source_alert_id: UUID,
        source_incident_id: UUID,
        payload: dict[str, Any],
    ) -> str:
        result = await self.session.execute(
            select(ContextKnowledgeRecord)
            .where(
                ContextKnowledgeRecord.tenant_id == tenant_id,
                ContextKnowledgeRecord.service == service,
                ContextKnowledgeRecord.environment == environment,
                ContextKnowledgeRecord.alert_signature == alert_signature,
            )
            .order_by(ContextKnowledgeRecord.updated_at.desc())
            .limit(1)
        )
        record = result.scalar_one_or_none()
        if record is None:
            record = ContextKnowledgeRecord(
                tenant_id=tenant_id,
                service=service,
                environment=environment,
                alert_name=alert_name,
                alert_signature=alert_signature,
            )
            self.session.add(record)
        record.alert_name = alert_name
        record.source_alert_id = source_alert_id
        record.source_incident_id = source_incident_id
        record.collected_at = utc_now()
        record.payload = payload
        record.resolution_payload = {}
        record.updated_at = utc_now()
        await self.session.flush()
        return str(record.id)

    async def attach_context_knowledge_resolution(
        self,
        knowledge_id: str | UUID,
        resolution_payload: dict[str, Any],
    ) -> bool:
        record_id = self._parse_uuid(knowledge_id)
        if record_id is None:
            return False
        record = await self.session.get(ContextKnowledgeRecord, record_id)
        if record is None:
            return False
        record.resolution_payload = resolution_payload
        await self.session.flush()
        return True

    async def save_context_snapshot(
        self,
        *,
        snapshot_id: UUID,
        tenant_id: str,
        incident_id: str,
        source_incident_id: str | None,
        alert_signature: str,
        subject_fingerprint: str,
        context_fingerprint: str,
        contract_version: str,
        quality_score: float,
        reusable: bool,
        source_manifest: dict[str, Any],
        payload: dict[str, Any],
        collected_at: datetime,
        expires_at: datetime,
    ) -> None:
        if await self.session.get(ContextSnapshotRecord, snapshot_id) is not None:
            return
        previous = (
            await self.session.execute(
                select(ContextSnapshotRecord)
                .where(
                    ContextSnapshotRecord.tenant_id == tenant_id,
                    ContextSnapshotRecord.incident_id == incident_id,
                )
                .order_by(
                    ContextSnapshotRecord.snapshot_version.desc(),
                    ContextSnapshotRecord.collected_at.desc(),
                )
                .with_for_update()
                .limit(1)
            )
        ).scalar_one_or_none()
        self.session.add(
            ContextSnapshotRecord(
                snapshot_id=snapshot_id,
                tenant_id=tenant_id,
                incident_id=self._require("context_snapshot.incident_id", incident_id),
                source_incident_id=source_incident_id,
                alert_signature=self._require("context_snapshot.alert_signature", alert_signature),
                subject_fingerprint=self._require("context_snapshot.subject_fingerprint", subject_fingerprint),
                context_fingerprint=self._require("context_snapshot.context_fingerprint", context_fingerprint),
                parent_snapshot_id=previous.snapshot_id if previous else None,
                snapshot_stage="collected",
                snapshot_version=int(previous.snapshot_version or 0) + 1 if previous else 1,
                contract_version=contract_version or "kaiops.context.v2",
                quality_score=max(0.0, min(float(quality_score), 1.0)),
                reusable=bool(reusable),
                source_manifest=source_manifest if isinstance(source_manifest, dict) else {},
                payload=payload if isinstance(payload, dict) else {},
                collected_at=collected_at,
                expires_at=expires_at,
            )
        )
        await self.session.flush()

    async def latest_context_snapshot(self, incident_id: str, *, tenant_id: str = "default") -> dict[str, Any] | None:
        row = (
            await self.session.execute(
                select(ContextSnapshotRecord)
                .where(
                    ContextSnapshotRecord.tenant_id == (tenant_id or "default"),
                    ContextSnapshotRecord.incident_id == incident_id,
                )
                .order_by(ContextSnapshotRecord.collected_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        return {
            "snapshot_id": str(row.snapshot_id),
            "tenant_id": row.tenant_id,
            "incident_id": row.incident_id,
            "source_incident_id": row.source_incident_id,
            "alert_signature": row.alert_signature,
            "subject_fingerprint": row.subject_fingerprint,
            "context_fingerprint": row.context_fingerprint,
            "parent_snapshot_id": str(row.parent_snapshot_id) if row.parent_snapshot_id else None,
            "snapshot_stage": row.snapshot_stage,
            "snapshot_version": row.snapshot_version,
            "evidence_ids": list(row.evidence_ids or []),
            "evidence_checksums": dict(row.evidence_checksums or {}),
            "contract_version": row.contract_version,
            "quality_score": float(row.quality_score or 0.0),
            "reusable": bool(row.reusable),
            "source_manifest": row.source_manifest if isinstance(row.source_manifest, dict) else {},
            "context": row.payload if isinstance(row.payload, dict) else {},
            "collected_at": row.collected_at.isoformat(),
            "expires_at": row.expires_at.isoformat(),
        }

    async def context_snapshot_by_id(
        self, snapshot_id: UUID | str, *, tenant_id: str, incident_id: UUID | str,
    ) -> dict[str, Any] | None:
        snapshot_uuid = self._parse_uuid(snapshot_id)
        if snapshot_uuid is None:
            return None
        row = (
            await self.session.execute(
                select(ContextSnapshotRecord).where(
                    ContextSnapshotRecord.snapshot_id == snapshot_uuid,
                    ContextSnapshotRecord.tenant_id == str(self._require("context_snapshot.tenant_id", tenant_id)),
                    ContextSnapshotRecord.incident_id
                    == str(self._require("context_snapshot.incident_id", incident_id)),
                )
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        return {
            "snapshot_id": str(row.snapshot_id),
            "tenant_id": row.tenant_id,
            "incident_id": row.incident_id,
            "context_fingerprint": row.context_fingerprint,
            "parent_snapshot_id": str(row.parent_snapshot_id) if row.parent_snapshot_id else None,
            "snapshot_stage": row.snapshot_stage,
            "snapshot_version": row.snapshot_version,
            "evidence_ids": list(row.evidence_ids or []),
            "evidence_checksums": dict(row.evidence_checksums or {}),
            "context": row.payload if isinstance(row.payload, dict) else {},
            "collected_at": row.collected_at.isoformat(),
            "expires_at": row.expires_at.isoformat(),
        }

    async def is_latest_context_snapshot(
        self, snapshot_id: UUID | str, *, tenant_id: str, incident_id: UUID | str,
    ) -> bool:
        """Cheap pre-check mirroring the supersede guard `save_recommendation_as_audit`
        already enforces at persistence time (see its "recommendation context
        snapshot was superseded before persistence" check) - but performed
        BEFORE running the expensive iterative investigation instead of only
        discovering the staleness after it completes.

        Context-agent's progressive enrichment can legitimately publish
        several successive newer snapshots for the same incident within
        seconds, each triggering its own resolution-agent investigation.
        Every investigation still in flight when a newer snapshot lands was
        always run to completion first (a real iterative investigation,
        tens of seconds of tool calls) only to then be discarded and
        recursively retried - reproduced live as a genuine livelock: 8
        distinct investigation attempts for one incident within 35 seconds,
        none of which ever reached a terminal state, because each one took
        longer to run than the interval between new snapshots. Skipping the
        investigation outright once its snapshot is already known stale
        lets whichever trigger holds the truly latest snapshot actually
        finish instead of guaranteed being pre-empted itself.
        """
        snapshot_uuid = self._parse_uuid(snapshot_id)
        if snapshot_uuid is None:
            return False
        latest_snapshot_id = await self.session.scalar(
            select(ContextSnapshotRecord.snapshot_id)
            .where(
                ContextSnapshotRecord.tenant_id == str(self._require("context_snapshot.tenant_id", tenant_id)),
                ContextSnapshotRecord.incident_id
                == str(self._require("context_snapshot.incident_id", incident_id)),
            )
            .order_by(ContextSnapshotRecord.snapshot_version.desc(), ContextSnapshotRecord.collected_at.desc())
            .limit(1)
        )
        return latest_snapshot_id == snapshot_uuid

    async def persist_final_investigation_snapshot(
        self, *, context: Any, report: dict[str, Any], parent_snapshot_id: UUID | str,
    ) -> ContextSnapshotRecord:
        parent_uuid = self._parse_uuid(parent_snapshot_id)
        parent = (await self.session.execute(select(ContextSnapshotRecord).where(
            ContextSnapshotRecord.snapshot_id == parent_uuid,
        ).with_for_update())).scalar_one_or_none() if parent_uuid else None
        if parent is None:
            raise RuntimeError("parent context snapshot does not exist")
        context_payload = context.model_dump(mode="json") if hasattr(context, "model_dump") else dict(context)
        if str(context_payload.get("tenant_id") or "") != parent.tenant_id:
            raise RuntimeError("final context snapshot tenant mismatch")
        if str(context_payload.get("incident_id") or "") != parent.incident_id:
            raise RuntimeError("final context snapshot incident mismatch")
        latest_id = await self.session.scalar(select(ContextSnapshotRecord.snapshot_id).where(
            ContextSnapshotRecord.tenant_id == parent.tenant_id,
            ContextSnapshotRecord.incident_id == parent.incident_id,
        ).order_by(ContextSnapshotRecord.snapshot_version.desc(), ContextSnapshotRecord.collected_at.desc()).limit(1).with_for_update())
        if latest_id != parent.snapshot_id:
            raise ValueError("parent context snapshot was superseded before investigation persistence")
        metadata = dict(context_payload.get("metadata") or {})
        metadata.pop("context_snapshot_id", None)
        metadata.pop("context_fingerprint", None)
        evidence_rows = [
            item for rows in (metadata.get("context_evidence") or {}).values()
            if isinstance(rows, list) for item in rows if isinstance(item, dict)
        ]
        evidence_ids = sorted({
            str(item.get("evidence_id") or item.get("id") or "").strip()
            for item in evidence_rows if str(item.get("evidence_id") or item.get("id") or "").strip()
        })
        evidence_by_id = {
            str(item.get("evidence_id") or item.get("id") or "").strip(): item
            for item in evidence_rows
        }
        evidence_checksums = {
            identity: f"sha256:{hashlib.sha256(json.dumps(
                evidence_by_id[identity], sort_keys=True, default=str, separators=(',', ':'),
            ).encode()).hexdigest()}"
            for identity in evidence_ids
        }
        metadata.pop("_final_investigation_report", None)
        metadata["investigation_report"] = dict(report)
        canonical = {**context_payload, "metadata": metadata}
        fingerprint = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, default=str, separators=(",", ":")).encode()
        ).hexdigest()
        snapshot_id = uuid4()
        version = int(parent.snapshot_version or 1) + 1
        service_info = context_payload.get("service") if isinstance(context_payload.get("service"), dict) else {}
        alert_info = context_payload.get("alert") if isinstance(context_payload.get("alert"), dict) else {}
        expires_at_iso = (
            parent.expires_at.isoformat()
            if hasattr(parent.expires_at, "isoformat")
            else str(parent.expires_at or "")
        )
        metadata.update({
            "context_snapshot_id": str(snapshot_id),
            "context_fingerprint": fingerprint,
            "snapshot_stage": "investigation_complete",
            "snapshot_version": version,
            "context_subject_fingerprint": parent.subject_fingerprint,
            "evidence_ids": list(evidence_ids),
            "evidence_content_checksums": dict(evidence_checksums),
            "context_expires_at": expires_at_iso,
            "service": str(service_info.get("name") or alert_info.get("service") or metadata.get("service") or ""),
            "environment": str(service_info.get("environment") or alert_info.get("environment") or metadata.get("environment") or ""),
        })
        if hasattr(context, "model_copy") and hasattr(context, "model_dump"):
            snapshot_payload = context.model_copy(update={"metadata": metadata}).model_dump(mode="json")
        else:
            snapshot_payload = json.loads(
                json.dumps({**context_payload, "metadata": metadata}, default=str)
            )
        row = ContextSnapshotRecord(
            snapshot_id=snapshot_id, tenant_id=parent.tenant_id, incident_id=parent.incident_id,
            source_incident_id=parent.source_incident_id, alert_signature=parent.alert_signature,
            subject_fingerprint=parent.subject_fingerprint, context_fingerprint=fingerprint,
            parent_snapshot_id=parent.snapshot_id, snapshot_stage="investigation_complete",
            snapshot_version=version, evidence_ids=evidence_ids,
            evidence_checksums=evidence_checksums, contract_version=parent.contract_version,
            # Investigation adds an immutable report to the same evidence
            # package; it does not make a reusable parent context unusable.
            # Execution readiness remains governed independently by the RCA
            # and plan gates.
            quality_score=parent.quality_score, reusable=bool(parent.reusable),
            source_manifest=dict(parent.source_manifest or {}),
            payload=snapshot_payload, collected_at=datetime.now(UTC),
            expires_at=parent.expires_at,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def get_bound_incident_investigation(
        self,
        *,
        tenant_id: str,
        incident_id: UUID | str,
        alert_id: UUID | str,
        recommendation_id: UUID | str | None,
    ) -> dict[str, Any]:
        """Load one immutable recommendation/context pair and verify its binding.

        This deliberately has no "latest snapshot" fallback.  Callers may still
        render the alert and incident when integrity fails, but must not present
        an independently selected context snapshot as RCA support.
        """
        normalized_tenant_id = str(self._require("tenant_id", tenant_id))
        incident_uuid = self._parse_uuid(incident_id)
        alert_uuid = self._parse_uuid(alert_id)
        recommendation_uuid = self._parse_uuid(recommendation_id)
        reasons: list[str] = []
        referenced_snapshot_id: UUID | None = None

        def result(
            status: str,
            *,
            recommendation: dict[str, Any] | None = None,
            snapshot: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            if not reasons:
                reasons.append(status.replace("_", " "))
            return {
                "recommendation": recommendation or {},
                "context_snapshot": snapshot or {},
                "investigation_integrity": {
                    "status": status,
                    "verified": status == "verified",
                    "blocking_reasons": [] if status == "verified" else list(dict.fromkeys(reasons)),
                    "recommendation_id": str(recommendation_uuid) if recommendation_uuid else None,
                    "context_snapshot_id": (
                        str((snapshot or {}).get("snapshot_id") or referenced_snapshot_id or "").strip() or None
                    ),
                },
            }

        if incident_uuid is None or alert_uuid is None:
            return result("contract_invalid")
        if recommendation_uuid is None:
            return result("missing_recommendation")

        recommendation_record = (
            await self.session.execute(
                select(AuditLogRecord).where(
                    AuditLogRecord.id == recommendation_uuid,
                    AuditLogRecord.tenant_id == normalized_tenant_id,
                    AuditLogRecord.resource_type == "incident",
                    AuditLogRecord.resource_id == str(incident_uuid),
                    AuditLogRecord.action == "recommendation.generated",
                )
            )
        ).scalar_one_or_none()
        if recommendation_record is None:
            return result("missing_recommendation")
        recommendation = (
            dict(recommendation_record.payload)
            if isinstance(recommendation_record.payload, dict)
            else {}
        )
        metadata = recommendation.get("metadata") if isinstance(recommendation.get("metadata"), dict) else {}
        binding_record = (
            await self.session.execute(select(IncidentInvestigationBindingRecord).where(
                IncidentInvestigationBindingRecord.tenant_id == normalized_tenant_id,
                IncidentInvestigationBindingRecord.recommendation_id == recommendation_uuid,
            ))
        ).scalar_one_or_none()
        if binding_record is None:
            reasons.append("recommendation predates the normalized investigation binding contract")
            return result("legacy_unbound", recommendation=recommendation)
        if binding_record.tenant_id != normalized_tenant_id:
            return result("tenant_mismatch", recommendation=recommendation)
        if binding_record.incident_id != incident_uuid:
            return result("incident_mismatch", recommendation=recommendation)
        if binding_record.alert_id != alert_uuid:
            return result("alert_mismatch", recommendation=recommendation)
        if binding_record.recommendation_id != recommendation_uuid:
            return result("contract_invalid", recommendation=recommendation)
        if str(metadata.get("analysis_request_id") or "") != str(binding_record.analysis_request_id):
            return result("contract_invalid", recommendation=recommendation)
        if str(metadata.get("project_id") or "") != binding_record.project_id:
            return result("project_mismatch", recommendation=recommendation)
        if binding_record.resolution_plan_id is not None:
            plan_record = await self.session.get(
                ExecutionPlanRecord,
                binding_record.resolution_plan_id,
            )
            if (
                plan_record is not None
                and plan_record.tenant_id == normalized_tenant_id
                and isinstance(plan_record.plan_payload, dict)
            ):
                metadata = dict(metadata)
                metadata["execution_plan"] = dict(plan_record.plan_payload)
                recommendation["metadata"] = metadata
                if isinstance(plan_record.plan_payload.get("commands"), list) and plan_record.plan_payload["commands"]:
                    recommendation["steps"] = list(plan_record.plan_payload["commands"])
        referenced_snapshot_id = self._parse_uuid(metadata.get("context_snapshot_id"))
        if referenced_snapshot_id is None:
            reasons.append("recommendation does not reference a context snapshot")
            status = "missing_snapshot_reference" if metadata.get("analysis_request_id") else "legacy_unbound"
            return result(status, recommendation=recommendation)
        if referenced_snapshot_id != binding_record.context_snapshot_id:
            return result("contract_invalid", recommendation=recommendation)

        # Query by immutable ID first so a cross-tenant record is distinguishable
        # from a missing record without ever returning its contents.
        snapshot_record = await self.session.get(ContextSnapshotRecord, referenced_snapshot_id)
        if snapshot_record is None:
            return result("snapshot_not_found", recommendation=recommendation)
        if snapshot_record.tenant_id != normalized_tenant_id:
            return result("tenant_mismatch", recommendation=recommendation)
        if str(snapshot_record.incident_id) != str(incident_uuid):
            return result("incident_mismatch", recommendation=recommendation)

        snapshot_payload = dict(snapshot_record.payload) if isinstance(snapshot_record.payload, dict) else {}
        snapshot_metadata = (
            snapshot_payload.get("metadata")
            if isinstance(snapshot_payload.get("metadata"), dict)
            else {}
        )
        bound_alert_id = str(
            metadata.get("alert_id")
            or snapshot_metadata.get("alert_id")
            or snapshot_payload.get("alert_id")
            or ""
        ).strip()
        if bound_alert_id and bound_alert_id != str(alert_uuid):
            return result("alert_mismatch", recommendation=recommendation)

        expected_fingerprint = str(metadata.get("context_fingerprint") or "").strip()
        if not expected_fingerprint or expected_fingerprint != str(snapshot_record.context_fingerprint):
            return result("fingerprint_mismatch", recommendation=recommendation)

        expected_project = str(metadata.get("project_id") or "").strip()
        snapshot_project = str(
            snapshot_metadata.get("project_id") or snapshot_payload.get("project_id") or ""
        ).strip()
        if expected_project and snapshot_project and expected_project != snapshot_project:
            return result("project_mismatch", recommendation=recommendation)

        now = datetime.now(UTC)
        expires_at = snapshot_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            return result("context_expired", recommendation=recommendation)

        evidence_buckets = snapshot_metadata.get("context_evidence")
        if not isinstance(evidence_buckets, dict):
            evidence_buckets = snapshot_payload.get("context_evidence")
        available_evidence_ids = {
            str(item.get("evidence_id") or item.get("id") or "").strip()
            for rows in (evidence_buckets.values() if isinstance(evidence_buckets, dict) else [])
            if isinstance(rows, list)
            for item in rows
            if isinstance(item, dict)
        }
        available_evidence_ids.discard("")
        accepted_evidence = metadata.get("evidence_ids")
        if not isinstance(accepted_evidence, list):
            rca_analysis = metadata.get("rca_analysis") if isinstance(metadata.get("rca_analysis"), dict) else {}
            accepted_evidence = rca_analysis.get("evidence_used", [])
        missing_ids = sorted(
            str(item).strip()
            for item in accepted_evidence
            if str(item).strip() and str(item).strip() not in available_evidence_ids
        )
        if missing_ids:
            reasons.append("accepted RCA evidence is absent from the bound context snapshot")
            return result("evidence_mismatch", recommendation=recommendation)

        snapshot = {
            "snapshot_id": str(snapshot_record.snapshot_id),
            "tenant_id": snapshot_record.tenant_id,
            "incident_id": snapshot_record.incident_id,
            "context_fingerprint": snapshot_record.context_fingerprint,
            "contract_version": snapshot_record.contract_version,
            "quality_score": float(snapshot_record.quality_score or 0.0),
            "reusable": bool(snapshot_record.reusable),
            "source_manifest": snapshot_record.source_manifest or {},
            "context": snapshot_payload,
            "collected_at": snapshot_record.collected_at.isoformat(),
            "expires_at": snapshot_record.expires_at.isoformat(),
        }
        return result("verified", recommendation=recommendation, snapshot=snapshot)

    async def current_incident_investigation_binding(
        self, *, tenant_id: str, incident_id: UUID | str, alert_id: UUID | str,
    ) -> dict[str, str] | None:
        incident_uuid = self._parse_uuid(incident_id)
        alert_uuid = self._parse_uuid(alert_id)
        if incident_uuid is None or alert_uuid is None:
            return None
        row = (
            await self.session.execute(
                select(IncidentProjectionRecord).where(
                    IncidentProjectionRecord.tenant_id == self._require("tenant_id", tenant_id),
                    IncidentProjectionRecord.incident_id == incident_uuid,
                    IncidentProjectionRecord.alert_id == alert_uuid,
                )
            )
        ).scalar_one_or_none()
        if row is None or row.recommendation_id is None:
            return None
        governed = await self.governed_recovery_recommendation_id(
            tenant_id=tenant_id, incident_id=incident_uuid,
        )
        return {
            "tenant_id": row.tenant_id,
            "incident_id": str(row.incident_id),
            "alert_id": str(row.alert_id),
            "recommendation_id": str(governed or row.recommendation_id),
        }

    @staticmethod
    def _evidence_draft_payload(row: EvidenceRagDraftRecord) -> dict[str, Any]:
        return {
            "draft_id": str(row.draft_id), "tenant_id": row.tenant_id,
            "tenant_scope": row.tenant_id, "project_id": row.project_id,
            "incident_id": str(row.incident_id), "alert_id": str(row.alert_id),
            "analysis_request_id": str(row.analysis_request_id),
            "context_snapshot_id": str(row.context_snapshot_id),
            "context_fingerprint": row.context_fingerprint,
            "recommendation_id": str(row.recommendation_id), "rca_version": row.rca_version,
            "document_kind": row.document_kind, "document_version": row.document_version,
            "status": row.status, "title": row.title, "content": row.content,
            "content_checksum": row.content_checksum, "evidence_ids": list(row.evidence_ids or []),
            "source_uris": list(row.source_uris or []), "owner_team": row.owner_team,
            "created_by": row.created_by, "reviewed_by": row.reviewed_by,
            "review_notes": row.review_notes,
            "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
            "approved_by": row.approved_by,
            "approved_at": row.approved_at.isoformat() if row.approved_at else None,
            "indexed_at": row.indexed_at.isoformat() if row.indexed_at else None,
            "row_version": row.row_version,
            "created_at": row.created_at.isoformat(), "updated_at": row.updated_at.isoformat(),
        }

    @staticmethod
    def _knowledge_draft_payload(row: KnowledgeRagDraftRecord) -> dict[str, Any]:
        return {
            "draft_id": str(row.draft_id), "tenant_id": row.tenant_id,
            "tenant_scope": row.tenant_id, "document_kind": row.document_kind,
            "document_version": row.document_version, "source_ref": row.source_ref,
            "title": row.title, "content": row.content,
            "content_checksum": row.content_checksum, "metadata": dict(row.metadata_payload or {}),
            "status": row.status, "created_by": row.created_by, "reviewed_by": row.reviewed_by,
            "review_notes": row.review_notes,
            "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
            "approved_by": row.approved_by,
            "approved_at": row.approved_at.isoformat() if row.approved_at else None,
            "row_version": row.row_version, "created_at": row.created_at.isoformat(),
            "updated_at": row.updated_at.isoformat(),
        }

    async def create_knowledge_rag_draft(
        self, *, tenant_id: str, created_by: str, document_kind: str, source_ref: str,
        title: str, content: str, metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        tenant = require_tenant_id(tenant_id, source="knowledge RAG draft")
        kind = self._require("document_kind", document_kind).lower()
        source = self._require("source_ref", source_ref)
        existing = (await self.session.execute(select(KnowledgeRagDraftRecord).where(
            KnowledgeRagDraftRecord.tenant_id == tenant,
            KnowledgeRagDraftRecord.source_ref == source,
            KnowledgeRagDraftRecord.document_kind == kind,
            KnowledgeRagDraftRecord.status.in_(("draft", "reviewed", "approved_pending_index")),
        ).order_by(KnowledgeRagDraftRecord.document_version.desc()).limit(1))).scalar_one_or_none()
        if existing is not None:
            return self._knowledge_draft_payload(existing)
        for attempt in range(3):
            latest = await self.session.scalar(select(func.max(KnowledgeRagDraftRecord.document_version)).where(
                KnowledgeRagDraftRecord.tenant_id == tenant,
                KnowledgeRagDraftRecord.source_ref == source,
                KnowledgeRagDraftRecord.document_kind == kind,
            ))
            now = datetime.now(UTC)
            row = KnowledgeRagDraftRecord(
                draft_id=uuid4(), tenant_id=tenant, document_kind=kind,
                document_version=int(latest or 0) + 1, source_ref=source,
                title=self._require("title", title), content=self._require("content", content),
                content_checksum=f"sha256:{hashlib.sha256(content.encode()).hexdigest()}",
                metadata_payload=dict(metadata or {}), status="draft", created_by=created_by,
                row_version=1, created_at=now, updated_at=now,
            )
            try:
                async with self.session.begin_nested():
                    self.session.add(row)
                    await self.session.flush()
                return self._knowledge_draft_payload(row)
            except IntegrityError:
                existing = (await self.session.execute(select(KnowledgeRagDraftRecord).where(
                    KnowledgeRagDraftRecord.tenant_id == tenant,
                    KnowledgeRagDraftRecord.source_ref == source,
                    KnowledgeRagDraftRecord.document_kind == kind,
                    KnowledgeRagDraftRecord.status.in_(("draft", "reviewed", "approved_pending_index")),
                ).order_by(KnowledgeRagDraftRecord.document_version.desc()).limit(1))).scalar_one_or_none()
                if existing is not None:
                    return self._knowledge_draft_payload(existing)
                if attempt == 2:
                    raise RuntimeError("concurrent knowledge draft creation could not be resolved") from None
        raise RuntimeError("knowledge draft creation failed")

    async def list_knowledge_rag_drafts(
        self, *, tenant_id: str, status: str | None = None,
    ) -> list[dict[str, Any]]:
        query = select(KnowledgeRagDraftRecord).where(KnowledgeRagDraftRecord.tenant_id == tenant_id)
        if status:
            query = query.where(KnowledgeRagDraftRecord.status == status)
        rows = (await self.session.execute(query.order_by(KnowledgeRagDraftRecord.updated_at.desc()))).scalars()
        return [self._knowledge_draft_payload(row) for row in rows]

    async def review_knowledge_rag_draft(
        self, *, tenant_id: str, draft_id: UUID | str, expected_row_version: int,
        title: str, content: str, review_notes: str | None, reviewed_by: str,
    ) -> dict[str, Any] | None:
        parsed = self._parse_uuid(draft_id)
        now = datetime.now(UTC)
        result = await self.session.execute(update(KnowledgeRagDraftRecord).where(
            KnowledgeRagDraftRecord.draft_id == parsed,
            KnowledgeRagDraftRecord.tenant_id == tenant_id,
            KnowledgeRagDraftRecord.row_version == expected_row_version,
            KnowledgeRagDraftRecord.status.in_(("draft", "reviewed")),
        ).values(
            title=title, content=content,
            content_checksum=f"sha256:{hashlib.sha256(content.encode()).hexdigest()}",
            review_notes=review_notes, reviewed_by=reviewed_by, reviewed_at=now,
            status="reviewed", row_version=KnowledgeRagDraftRecord.row_version + 1,
            updated_at=now,
        )) if parsed else None
        if result is None or result.rowcount != 1:
            return None
        return self._knowledge_draft_payload(await self.session.get(KnowledgeRagDraftRecord, parsed))

    async def approve_knowledge_rag_draft(
        self, *, tenant_id: str, draft_id: UUID | str, expected_row_version: int,
        approved_by: str,
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        parsed = self._parse_uuid(draft_id)
        row = (await self.session.execute(select(KnowledgeRagDraftRecord).where(
            KnowledgeRagDraftRecord.draft_id == parsed,
            KnowledgeRagDraftRecord.tenant_id == tenant_id,
        ).with_for_update())).scalar_one_or_none() if parsed else None
        if row is None:
            return None
        if row.status != "reviewed" or row.row_version != expected_row_version:
            raise RuntimeError("stale knowledge draft or direct approval is prohibited")
        reviewer = str(row.reviewed_by or "").strip().casefold()
        approver = str(approved_by or "").strip().casefold()
        if not reviewer or reviewer == approver:
            raise RuntimeError("knowledge draft approval requires a different reviewer")
        checksum = f"sha256:{hashlib.sha256(row.content.encode()).hexdigest()}"
        if checksum != row.content_checksum:
            raise RuntimeError("knowledge draft checksum mismatch")
        now = datetime.now(UTC)
        document = GovernedRagDocumentRecord(
            document_id=uuid4(), draft_id=row.draft_id, tenant_id=row.tenant_id,
            source_ref=row.source_ref, document_metadata=dict(row.metadata_payload or {}),
            document_kind=row.document_kind, document_version=row.document_version,
            title=row.title, content=row.content, content_checksum=checksum,
            evidence_ids=[], source_uris=[row.source_ref], corpus_classification="TENANT_CURATED",
            review_status="approved", approved_by=approved_by, approved_at=now,
            index_status="pending", created_at=now,
        )
        self.session.add(document)
        if row.document_kind == "runbook":
            rb_id = uuid5(NAMESPACE_URL, f"kaiops:runbook:{row.tenant_id}:{row.source_ref}")
            rb_row = await self.session.get(RunbookVersionRecord, (rb_id, int(row.document_version)))
            meta = {
                **(dict(rb_row.content or {}) if rb_row is not None else {}),
                **dict(row.metadata_payload or {}),
            }
            sig_seed = f"{row.tenant_id}:{meta.get('service') or row.source_ref}"
            issue_sig = hashlib.sha256(sig_seed.encode()).hexdigest()
            enriched_content = self._extract_structured_runbook_content(
                tenant_id=row.tenant_id,
                runbook_id=rb_id,
                version=int(row.document_version),
                title=row.title,
                markdown=row.content,
                source_ref=row.source_ref,
                metadata=meta,
            )
            await self._upsert_runbook_governance_records(
                tenant_id=row.tenant_id,
                runbook_id=rb_id,
                version=int(row.document_version),
                approved_by=approved_by,
                approver_role="HITL_APPROVER",
                reason=f"Approved governed knowledge runbook draft {row.draft_id}",
                owner=str(row.created_by or approved_by),
                risk_level="medium",
                required_approval="HITL_APPROVER",
                issue_signature=issue_sig,
                content=enriched_content,
                now=now,
            )
            inc_id_raw = meta.get("incident_id")
            if inc_id_raw:
                latest_snap = (await self.session.execute(
                    select(ContextSnapshotRecord).where(
                        ContextSnapshotRecord.tenant_id == row.tenant_id,
                        ContextSnapshotRecord.incident_id == str(inc_id_raw),
                    ).order_by(ContextSnapshotRecord.snapshot_version.desc()).limit(1)
                )).scalar_one_or_none()
                if latest_snap is not None:
                    snap_payload = json.loads(json.dumps(latest_snap.payload or {}, default=str))
                    snap_meta = snap_payload.setdefault("metadata", {})
                    learned_entry = {
                        "runbook_id": str(rb_id),
                        "version": int(row.document_version),
                        "tenant_id": row.tenant_id,
                        "issue_signature": issue_sig,
                        "approval_status": "approved",
                        "risk_level": "medium",
                        "required_approval": "HITL_APPROVER",
                        "title": str(enriched_content.get("title") or row.title),
                        "service": str(enriched_content.get("service") or meta.get("service") or ""),
                        "alert_name": str(enriched_content.get("alert_name") or meta.get("alert_name") or ""),
                        "markdown": str(enriched_content.get("markdown") or row.content),
                        "source_ref": str(row.source_ref),
                        "draft_id": str(row.draft_id),
                        "observed_symptoms": enriched_content.get("observed_symptoms"),
                        "root_cause": enriched_content.get("root_cause"),
                        "business_impact": enriched_content.get("business_impact"),
                        "remediation_steps": enriched_content.get("remediation_steps"),
                        "commands": list(enriched_content.get("commands") or []),
                        "execution_Verification": dict(enriched_content.get("execution_Verification") or {}),
                        "approved_at": now.isoformat(),
                    }
                    if not str(snap_payload.get("runbook") or "").strip():
                        snap_payload["runbook"] = row.content
                    snap_meta["document_available"] = True
                    snap_meta["matched_learned_runbook"] = learned_entry
                    snap_meta["learned_runbooks"] = [learned_entry]
                    snap_meta["context_subject_fingerprint"] = latest_snap.subject_fingerprint
                    cq = dict(snap_meta.get("context_quality") or {})
                    updated_score = max(float(latest_snap.quality_score or 0.0), float(cq.get("quality_score") or 0.0), 0.88)
                    cq.update({
                        "quality_score": updated_score,
                        "reusable": True,
                        "valid": True,
                        "rca_ready": True,
                        "impact_ready": True,
                        "execution_ready": True,
                        "discovery_degraded": False,
                        "missing_required": [],
                    })
                    snap_meta["context_quality"] = cq
                    latest_snap.payload = snap_payload
                    latest_snap.reusable = True
                    latest_snap.quality_score = updated_score
                    alert_obj = snap_payload.get("alert") if isinstance(snap_payload.get("alert"), dict) else {}
                    reusable_payload = json.loads(json.dumps(snap_payload, default=str))
                    reusable_meta = reusable_payload.setdefault("metadata", {})
                    if reusable_meta.get("human_guided_input") and not reusable_meta.get("historical_human_guidance"):
                        reusable_meta["historical_human_guidance"] = dict(reusable_meta.pop("human_guided_input"))
                    await self.save_context_knowledge(
                        tenant_id=row.tenant_id,
                        service=str(meta.get("service") or alert_obj.get("service") or "unknown-service"),
                        environment=str(meta.get("environment") or alert_obj.get("environment") or "prod"),
                        alert_name=str(meta.get("alert_name") or alert_obj.get("name") or row.title),
                        alert_signature=str(latest_snap.alert_signature or meta.get("alert_signature") or issue_sig),
                        source_alert_id=self._parse_uuid(alert_obj.get("id")) or self._parse_uuid(inc_id_raw) or rb_id,
                        source_incident_id=self._parse_uuid(inc_id_raw) or rb_id,
                        payload=reusable_payload,
                    )
        row.status = "approved_pending_index"
        row.approved_by = approved_by
        row.approved_at = now
        row.row_version += 1
        row.updated_at = now
        payload = {
            "document_id": str(document.document_id), "draft_id": str(row.draft_id),
            "tenant_id": row.tenant_id, "document_kind": row.document_kind,
            "document_version": row.document_version, "content_checksum": checksum,
            "source_ref": row.source_ref,
        }
        self.session.add(AuditLogRecord(
            tenant_id=tenant_id, actor=approved_by, action="rag.document.approved",
            resource_type="governed_rag_document", resource_id=str(document.document_id), payload=payload,
        ))
        await self.enqueue_resolution_event(
            event_id=f"rag-document-approved:{document.document_id}",
            aggregate_id=str(document.document_id), topic="rag.document.approved",
            partition_key=str(document.document_id), payload=payload, tenant_id=tenant_id,
            available_after_seconds=0,
        )
        await self.session.flush()
        return self._knowledge_draft_payload(row), payload

    async def _verified_draft_binding(
        self, *, tenant_id: str, incident_id: UUID | str, alert_id: UUID | str,
        analysis_request_id: UUID | str, context_snapshot_id: UUID | str,
        context_fingerprint: str, recommendation_id: UUID | str, rca_version: int,
        evidence_ids: list[str], source_uris: list[str], lock: bool = False,
        allow_snapshot_evidence: bool = False,
    ) -> IncidentInvestigationBindingRecord:
        tenant = require_tenant_id(tenant_id, source="evidence draft binding")
        identities = [self._parse_uuid(value) for value in (
            incident_id, alert_id, analysis_request_id, context_snapshot_id, recommendation_id,
        )]
        if any(value is None for value in identities):
            raise ValueError("malformed investigation UUID identity")
        incident_uuid, alert_uuid, analysis_uuid, snapshot_uuid, recommendation_uuid = identities
        fingerprint = str(context_fingerprint or "")
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("context_fingerprint must be 64 lowercase hexadecimal characters")
        projection_stmt = select(IncidentProjectionRecord).where(
            IncidentProjectionRecord.tenant_id == tenant,
            IncidentProjectionRecord.incident_id == incident_uuid,
            IncidentProjectionRecord.alert_id == alert_uuid,
        )
        if lock:
            projection_stmt = projection_stmt.with_for_update()
        projection = (await self.session.execute(projection_stmt)).scalar_one_or_none()
        binding = await self.session.get(IncidentInvestigationBindingRecord, recommendation_uuid)
        if projection is None or projection.recommendation_id != recommendation_uuid or binding is None:
            raise RuntimeError("stale or missing investigation binding")
        actual = (
            binding.tenant_id, binding.incident_id, binding.alert_id, binding.analysis_request_id,
            binding.context_snapshot_id, binding.context_fingerprint, binding.recommendation_id,
            int(binding.rca_version),
        )
        expected = (
            tenant, incident_uuid, alert_uuid, analysis_uuid, snapshot_uuid, fingerprint,
            recommendation_uuid, int(rca_version),
        )
        if actual != expected:
            raise RuntimeError("stale or mismatched investigation binding")
        verified = await self.get_bound_incident_investigation(
            tenant_id=tenant, incident_id=incident_uuid, alert_id=alert_uuid,
            recommendation_id=recommendation_uuid,
        )
        if not verified.get("investigation_integrity", {}).get("verified"):
            raise RuntimeError("investigation binding is no longer current")
        recommendation = verified.get("recommendation") or {}
        metadata = recommendation.get("metadata") if isinstance(recommendation.get("metadata"), dict) else {}
        accepted_ids = metadata.get("evidence_ids")
        if not isinstance(accepted_ids, list):
            analysis = metadata.get("rca_analysis") if isinstance(metadata.get("rca_analysis"), dict) else {}
            accepted_ids = analysis.get("evidence_used", [])
        accepted_id_set = {str(value).strip() for value in accepted_ids if str(value).strip()}
        snapshot = verified.get("context_snapshot") or {}
        context = snapshot.get("context") if isinstance(snapshot.get("context"), dict) else {}
        context_metadata = context.get("metadata") if isinstance(context.get("metadata"), dict) else {}
        buckets = context_metadata.get("context_evidence") or context.get("context_evidence") or {}
        evidence_rows = [
            item for rows in (buckets.values() if isinstance(buckets, dict) else [])
            if isinstance(rows, list) for item in rows if isinstance(item, dict)
        ]
        if allow_snapshot_evidence:
            accepted_id_set = {
                str(item.get("evidence_id") or item.get("id") or "").strip()
                for item in evidence_rows
                if str(item.get("evidence_id") or item.get("id") or "").strip()
            }
        accepted_uri_set = {
            str(item.get(key)).strip() for item in evidence_rows
            if str(item.get("evidence_id") or item.get("id") or "").strip() in accepted_id_set
            for key in ("source_reference", "uri", "source_uri", "path", "citation")
            if str(item.get(key) or "").strip()
        }
        requested_ids = {str(value).strip() for value in evidence_ids if str(value).strip()}
        requested_uris = {str(value).strip() for value in source_uris if str(value).strip()}
        if not requested_ids.issubset(accepted_id_set) or not requested_uris.issubset(accepted_uri_set):
            raise RuntimeError("evidence does not belong to the accepted bound snapshot")
        return binding

    async def create_evidence_rag_drafts(
        self, *, tenant_id: str, created_by: str, binding: dict[str, Any],
        documents: list[dict[str, str]], evidence_ids: list[str], source_uris: list[str],
        allow_snapshot_evidence: bool = False,
    ) -> list[dict[str, Any]]:
        verified = await self._verified_draft_binding(
            tenant_id=tenant_id, incident_id=binding.get("incident_id"),
            alert_id=binding.get("alert_id"), analysis_request_id=binding.get("analysis_request_id"),
            context_snapshot_id=binding.get("context_snapshot_id"),
            context_fingerprint=str(binding.get("context_fingerprint") or ""),
            recommendation_id=binding.get("recommendation_id"),
            rca_version=int(binding.get("rca_version") or 0),
            evidence_ids=evidence_ids, source_uris=source_uris,
            allow_snapshot_evidence=allow_snapshot_evidence,
        )
        alert_uuid = self._parse_uuid(binding["alert_id"])
        results: list[dict[str, Any]] = []
        for document in documents:
            kind = str(document["document_kind"])
            existing = (await self.session.execute(select(EvidenceRagDraftRecord).where(
                EvidenceRagDraftRecord.tenant_id == tenant_id,
                EvidenceRagDraftRecord.alert_id == alert_uuid,
                EvidenceRagDraftRecord.document_kind == kind,
                EvidenceRagDraftRecord.context_snapshot_id == verified.context_snapshot_id,
                EvidenceRagDraftRecord.recommendation_id == verified.recommendation_id,
                EvidenceRagDraftRecord.status.in_(("draft", "reviewed", "approved_pending_index")),
            ).order_by(EvidenceRagDraftRecord.document_version.desc()).limit(1))).scalar_one_or_none()
            if existing is not None:
                results.append(self._evidence_draft_payload(existing))
                continue
            for attempt in range(3):
                latest = await self.session.scalar(select(func.max(EvidenceRagDraftRecord.document_version)).where(
                    EvidenceRagDraftRecord.tenant_id == tenant_id,
                    EvidenceRagDraftRecord.alert_id == alert_uuid,
                    EvidenceRagDraftRecord.document_kind == kind,
                ))
                now = datetime.now(UTC)
                row = EvidenceRagDraftRecord(
                    draft_id=uuid4(), tenant_id=tenant_id, project_id=verified.project_id,
                    incident_id=verified.incident_id, alert_id=verified.alert_id,
                    analysis_request_id=verified.analysis_request_id,
                    context_snapshot_id=verified.context_snapshot_id,
                    context_fingerprint=verified.context_fingerprint,
                    recommendation_id=verified.recommendation_id, rca_version=verified.rca_version,
                    document_kind=kind, document_version=int(latest or 0) + 1, status="draft",
                    title=document["title"], content=document["content"],
                    content_checksum=f"sha256:{hashlib.sha256(document['content'].encode()).hexdigest()}",
                    evidence_ids=evidence_ids, source_uris=source_uris, created_by=created_by,
                    created_at=now, updated_at=now,
                )
                try:
                    async with self.session.begin_nested():
                        self.session.add(row)
                        await self.session.flush()
                    results.append(self._evidence_draft_payload(row))
                    break
                except IntegrityError:
                    existing = (await self.session.execute(select(EvidenceRagDraftRecord).where(
                        EvidenceRagDraftRecord.tenant_id == tenant_id,
                        EvidenceRagDraftRecord.alert_id == alert_uuid,
                        EvidenceRagDraftRecord.document_kind == kind,
                        EvidenceRagDraftRecord.context_snapshot_id == verified.context_snapshot_id,
                        EvidenceRagDraftRecord.recommendation_id == verified.recommendation_id,
                        EvidenceRagDraftRecord.status.in_(("draft", "reviewed", "approved_pending_index")),
                    ).order_by(EvidenceRagDraftRecord.document_version.desc()).limit(1))).scalar_one_or_none()
                    if existing is not None:
                        results.append(self._evidence_draft_payload(existing))
                        break
                    if attempt == 2:
                        raise RuntimeError("concurrent evidence draft creation could not be resolved") from None
        return results

    async def list_evidence_rag_drafts(
        self, *, tenant_id: str, alert_id: UUID | str | None = None,
        status: str | None = None, document_kind: str | None = None,
    ) -> list[dict[str, Any]]:
        query = select(EvidenceRagDraftRecord).where(EvidenceRagDraftRecord.tenant_id == tenant_id)
        if alert_id is not None:
            parsed = self._parse_uuid(alert_id)
            if parsed is None:
                raise ValueError("malformed alert UUID")
            query = query.where(EvidenceRagDraftRecord.alert_id == parsed)
        if status:
            query = query.where(EvidenceRagDraftRecord.status == status.lower())
        if document_kind:
            query = query.where(EvidenceRagDraftRecord.document_kind == document_kind.lower())
        rows = (await self.session.execute(query.order_by(EvidenceRagDraftRecord.updated_at.desc()))).scalars()
        return [self._evidence_draft_payload(row) for row in rows]

    async def review_evidence_rag_draft(
        self, *, tenant_id: str, draft_id: UUID | str, expected_row_version: int,
        title: str, content: str, review_notes: str | None, reviewed_by: str,
    ) -> dict[str, Any] | None:
        parsed = self._parse_uuid(draft_id)
        if parsed is None:
            return None
        now = datetime.now(UTC)
        result = await self.session.execute(update(EvidenceRagDraftRecord).where(
            EvidenceRagDraftRecord.draft_id == parsed,
            EvidenceRagDraftRecord.tenant_id == tenant_id,
            EvidenceRagDraftRecord.row_version == expected_row_version,
            EvidenceRagDraftRecord.status.in_(("draft", "reviewed")),
        ).values(
            title=title, content=content,
            content_checksum=f"sha256:{hashlib.sha256(content.encode()).hexdigest()}",
            status="reviewed", reviewed_by=reviewed_by, review_notes=review_notes,
            reviewed_at=now, updated_at=now,
            row_version=EvidenceRagDraftRecord.row_version + 1,
        ))
        if result.rowcount != 1:
            return None
        row = await self.session.get(EvidenceRagDraftRecord, parsed)
        return self._evidence_draft_payload(row)

    async def revise_evidence_rag_draft(
        self, *, tenant_id: str, draft_id: UUID | str, created_by: str,
    ) -> dict[str, Any] | None:
        parsed = self._parse_uuid(draft_id)
        source = await self.session.get(EvidenceRagDraftRecord, parsed) if parsed else None
        if source is None or source.tenant_id != tenant_id:
            return None
        if source.status not in ("approved_pending_index", "approved"):
            raise RuntimeError("only published evidence can be revised as a new version")
        existing = (await self.session.execute(select(EvidenceRagDraftRecord).where(
            EvidenceRagDraftRecord.tenant_id == tenant_id,
            EvidenceRagDraftRecord.alert_id == source.alert_id,
            EvidenceRagDraftRecord.document_kind == source.document_kind,
            EvidenceRagDraftRecord.document_version > source.document_version,
            EvidenceRagDraftRecord.status.in_(("draft", "reviewed")),
        ).order_by(EvidenceRagDraftRecord.document_version.desc()).limit(1))).scalar_one_or_none()
        if existing is not None:
            return self._evidence_draft_payload(existing)
        latest = await self.session.scalar(select(func.max(EvidenceRagDraftRecord.document_version)).where(
            EvidenceRagDraftRecord.tenant_id == tenant_id,
            EvidenceRagDraftRecord.alert_id == source.alert_id,
            EvidenceRagDraftRecord.document_kind == source.document_kind,
        ))
        now = datetime.now(UTC)
        revision = EvidenceRagDraftRecord(
            draft_id=uuid4(), tenant_id=source.tenant_id, project_id=source.project_id,
            incident_id=source.incident_id, alert_id=source.alert_id,
            analysis_request_id=source.analysis_request_id,
            context_snapshot_id=source.context_snapshot_id,
            context_fingerprint=source.context_fingerprint,
            recommendation_id=source.recommendation_id, rca_version=source.rca_version,
            document_kind=source.document_kind, document_version=int(latest or 0) + 1,
            status="draft", title=source.title, content=source.content,
            content_checksum=source.content_checksum, evidence_ids=list(source.evidence_ids or []),
            source_uris=list(source.source_uris or []), owner_team=source.owner_team,
            created_by=created_by, row_version=1, created_at=now, updated_at=now,
        )
        self.session.add(revision)
        await self.session.flush()
        return self._evidence_draft_payload(revision)

    async def approve_evidence_rag_draft(
        self, *, tenant_id: str, draft_id: UUID | str, expected_row_version: int,
        approved_by: str, owner_team: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        parsed = self._parse_uuid(draft_id)
        if parsed is None:
            return None
        row = (await self.session.execute(select(EvidenceRagDraftRecord).where(
            EvidenceRagDraftRecord.draft_id == parsed,
            EvidenceRagDraftRecord.tenant_id == tenant_id,
        ).with_for_update())).scalar_one_or_none()
        if row is None:
            return None
        if row.status != "reviewed" or row.row_version != expected_row_version:
            raise RuntimeError("stale evidence draft or direct approval is prohibited")
        reviewer = str(row.reviewed_by or "").strip().casefold()
        approver = str(approved_by or "").strip().casefold()
        if not reviewer or reviewer == approver:
            raise RuntimeError("evidence draft approval requires a different reviewer")
        if not row.evidence_ids or not row.source_uris:
            raise RuntimeError("accepted evidence IDs and validated source URIs are required")
        await self._verified_draft_binding(
            tenant_id=tenant_id, incident_id=row.incident_id, alert_id=row.alert_id,
            analysis_request_id=row.analysis_request_id, context_snapshot_id=row.context_snapshot_id,
            context_fingerprint=row.context_fingerprint, recommendation_id=row.recommendation_id,
            rca_version=row.rca_version, evidence_ids=list(row.evidence_ids),
            source_uris=list(row.source_uris), lock=True,
        )
        checksum = f"sha256:{hashlib.sha256(row.content.encode()).hexdigest()}"
        if checksum != row.content_checksum:
            raise RuntimeError("evidence draft checksum mismatch")
        if await self.session.scalar(select(func.count()).select_from(GovernedRagDocumentRecord).where(
            GovernedRagDocumentRecord.draft_id == row.draft_id,
        )):
            raise RuntimeError("approved evidence documents are immutable")
        now = datetime.now(UTC)
        document = GovernedRagDocumentRecord(
            document_id=uuid4(), draft_id=row.draft_id, tenant_id=row.tenant_id,
            incident_id=row.incident_id, alert_id=row.alert_id,
            context_snapshot_id=row.context_snapshot_id,
            context_fingerprint=row.context_fingerprint, recommendation_id=row.recommendation_id,
            rca_version=row.rca_version, document_kind=row.document_kind,
            document_version=row.document_version, title=row.title, content=row.content,
            content_checksum=checksum, evidence_ids=list(row.evidence_ids),
            source_uris=list(row.source_uris), corpus_classification="TENANT_CURATED",
            review_status="approved", approved_by=approved_by, approved_at=now,
            index_status="pending", created_at=now,
        )
        self.session.add(document)
        if row.document_kind == "runbook":
            source_ref = str(
                getattr(row, "source_ref", None)
                or (row.source_uris[0] if row.source_uris else f"evidence-runbook:{row.incident_id}:{row.alert_id}")
            )
            rb_id = uuid5(NAMESPACE_URL, f"kaiops:runbook:{row.tenant_id}:{source_ref}")
            rb_row = await self.session.get(RunbookVersionRecord, (rb_id, int(row.document_version)))
            meta = {
                **(dict(rb_row.content or {}) if rb_row is not None else {}),
                **dict(getattr(row, "metadata_payload", None) or {}),
            }
            sig_seed = f"{row.tenant_id}:{meta.get('service') or source_ref}"
            issue_sig = hashlib.sha256(sig_seed.encode()).hexdigest()
            enriched_content = self._extract_structured_runbook_content(
                tenant_id=row.tenant_id,
                runbook_id=rb_id,
                version=int(row.document_version),
                title=row.title,
                markdown=row.content,
                source_ref=source_ref,
                metadata=meta,
            )
            await self._upsert_runbook_governance_records(
                tenant_id=row.tenant_id,
                runbook_id=rb_id,
                version=int(row.document_version),
                approved_by=approved_by,
                approver_role="HITL_APPROVER",
                reason=f"Approved governed evidence runbook draft {row.draft_id}",
                owner=str(owner_team or row.created_by or approved_by),
                risk_level="medium",
                required_approval="HITL_APPROVER",
                issue_signature=issue_sig,
                content=enriched_content,
                now=now,
            )
        row.status = "approved_pending_index"
        row.owner_team = owner_team
        row.approved_by = approved_by
        row.approved_at = now
        row.updated_at = now
        row.row_version += 1
        payload = {
            "document_id": str(document.document_id), "draft_id": str(row.draft_id),
            "tenant_id": row.tenant_id, "incident_id": str(row.incident_id),
            "alert_id": str(row.alert_id), "context_snapshot_id": str(row.context_snapshot_id),
            "context_fingerprint": row.context_fingerprint,
            "recommendation_id": str(row.recommendation_id), "rca_version": row.rca_version,
            "document_kind": row.document_kind, "document_version": row.document_version,
            "content_checksum": checksum,
        }
        self.session.add(AuditLogRecord(
            tenant_id=tenant_id, actor=approved_by, action="rag.document.approved",
            resource_type="governed_rag_document", resource_id=str(document.document_id),
            payload=payload,
        ))
        await self.enqueue_resolution_event(
            event_id=f"rag-document-approved:{document.document_id}",
            aggregate_id=str(row.incident_id), topic="rag.document.approved",
            partition_key=str(row.incident_id), payload=payload, tenant_id=tenant_id,
            available_after_seconds=0,
        )
        await self.session.flush()
        return self._evidence_draft_payload(row), payload

    async def mark_governed_rag_document_indexed(
        self, *, tenant_id: str, document_id: UUID | str, index_receipt: dict[str, Any],
    ) -> dict[str, Any] | None:
        parsed = self._parse_uuid(document_id)
        document = await self.session.get(GovernedRagDocumentRecord, parsed) if parsed else None
        if document is None or document.tenant_id != tenant_id:
            return None
        receipt_checksum = str(index_receipt.get("content_checksum") or "")
        if receipt_checksum != document.content_checksum:
            raise RuntimeError("indexed document checksum does not match the authoritative document")
        now = datetime.now(UTC)
        document.index_status = "indexed"
        document.index_error = None
        document.index_receipt = dict(index_receipt)
        document.next_index_attempt_at = None
        document.indexed_at = now
        draft = await self.session.get(EvidenceRagDraftRecord, document.draft_id)
        if draft is not None and draft.tenant_id == tenant_id:
            draft.status = "approved"
            draft.indexed_at = now
            draft.updated_at = now
            draft.row_version += 1
        knowledge_draft = await self.session.get(KnowledgeRagDraftRecord, document.draft_id)
        if knowledge_draft is not None and knowledge_draft.tenant_id == tenant_id:
            knowledge_draft.status = "approved"
            knowledge_draft.updated_at = now
            knowledge_draft.row_version += 1
        if str(document.document_kind or "").strip().lower() == "runbook":
            source_ref = str(
                document.source_ref
                or (
                    document.source_uris[0]
                    if document.source_uris
                    else f"evidence-runbook:{document.incident_id}:{document.alert_id}"
                )
            )
            rb_id = uuid5(NAMESPACE_URL, f"kaiops:runbook:{tenant_id}:{source_ref}")
            rb_row = await self.session.get(
                RunbookVersionRecord, (rb_id, int(document.document_version or 1))
            )
            if rb_row is not None and rb_row.tenant_id == tenant_id:
                rb_content = dict(rb_row.content or {}) if isinstance(rb_row.content, dict) else {}
                rb_content["index_status"] = "indexed"
                rb_content["indexed_at"] = now.isoformat()
                rb_content["document_id"] = str(document.document_id)
                rb_row.content = rb_content
                rb_row.last_validated_at = now
        await self.session.flush()
        return {"document_id": str(document.document_id), "index_status": "indexed"}

    async def claim_governed_rag_document_for_indexing(
        self,
        *,
        tenant_id: str,
        document_id: UUID | str,
        stale_indexing_seconds: float = 60.0,
    ) -> GovernedRagDocumentRecord | None:
        parsed = self._parse_uuid(document_id)
        if parsed is None:
            return None
        now = datetime.now(UTC)
        stale_cutoff = now - timedelta(seconds=max(0.0, float(stale_indexing_seconds)))
        row = (await self.session.execute(select(GovernedRagDocumentRecord).where(
            GovernedRagDocumentRecord.document_id == parsed,
            GovernedRagDocumentRecord.tenant_id == tenant_id,
            GovernedRagDocumentRecord.review_status == "approved",
            GovernedRagDocumentRecord.corpus_classification == "TENANT_CURATED",
            or_(
                and_(
                    GovernedRagDocumentRecord.index_status.in_(("pending", "failed")),
                    or_(
                        GovernedRagDocumentRecord.next_index_attempt_at.is_(None),
                        GovernedRagDocumentRecord.next_index_attempt_at <= now,
                    ),
                ),
                and_(
                    GovernedRagDocumentRecord.index_status == "indexing",
                    or_(
                        GovernedRagDocumentRecord.last_index_attempt_at.is_(None),
                        GovernedRagDocumentRecord.last_index_attempt_at <= stale_cutoff,
                    ),
                ),
            ),
        ).with_for_update())).scalar_one_or_none()
        if row is None or row.index_status == "indexed":
            return None
        row.index_status = "indexing"
        row.index_attempts += 1
        row.index_error = None
        row.last_index_attempt_at = now
        await self.session.flush()
        return row

    async def mark_governed_rag_document_index_failed(
        self, *, tenant_id: str, document_id: UUID | str, error: str, retry_at: datetime,
        retry_limit: int = 5,
    ) -> dict[str, Any] | None:
        parsed = self._parse_uuid(document_id)
        row = (await self.session.execute(select(GovernedRagDocumentRecord).where(
            GovernedRagDocumentRecord.document_id == parsed,
            GovernedRagDocumentRecord.tenant_id == tenant_id,
        ).with_for_update())).scalar_one_or_none() if parsed else None
        if row is None:
            return None
        row.index_status = "failed"
        row.index_error = str(error)[:4000]
        row.next_index_attempt_at = retry_at
        dead_lettered = row.index_attempts >= max(1, retry_limit)
        self.session.add(AuditLogRecord(
            tenant_id=tenant_id, actor="rag-index-worker",
            action="rag.document.index_dead_lettered" if dead_lettered else "rag.document.index_failed",
            resource_type="governed_rag_document", resource_id=str(row.document_id),
            payload={"attempts": row.index_attempts, "error": row.index_error,
                     "retry_at": retry_at.isoformat(), "dead_lettered": dead_lettered},
        ))
        await self.session.flush()
        return {"document_id": str(row.document_id), "index_status": "failed",
                "index_attempts": row.index_attempts, "dead_lettered": dead_lettered}

    async def list_due_governed_rag_index_retries(
        self,
        *,
        retry_limit: int,
        limit: int = 25,
        stale_indexing_seconds: float = 60.0,
    ) -> list[GovernedRagDocumentRecord]:
        now = datetime.now(UTC)
        stale_cutoff = now - timedelta(seconds=max(0.0, float(stale_indexing_seconds)))
        rows = await self.session.execute(select(GovernedRagDocumentRecord).where(
            GovernedRagDocumentRecord.review_status == "approved",
            GovernedRagDocumentRecord.corpus_classification == "TENANT_CURATED",
            GovernedRagDocumentRecord.index_attempts < max(1, retry_limit),
            or_(
                and_(
                    GovernedRagDocumentRecord.index_status.in_(("pending", "failed")),
                    or_(
                        GovernedRagDocumentRecord.next_index_attempt_at.is_(None),
                        GovernedRagDocumentRecord.next_index_attempt_at <= now,
                    ),
                ),
                and_(
                    GovernedRagDocumentRecord.index_status == "indexing",
                    or_(
                        GovernedRagDocumentRecord.last_index_attempt_at.is_(None),
                        GovernedRagDocumentRecord.last_index_attempt_at <= stale_cutoff,
                    ),
                ),
            ),
        ).order_by(
            GovernedRagDocumentRecord.next_index_attempt_at.asc(),
            GovernedRagDocumentRecord.created_at.asc(),
        ).limit(max(1, min(limit, 100))))
        return list(rows.scalars())

    async def retry_failed_governed_rag_document(
        self, *, tenant_id: str, document_id: UUID | str,
    ) -> dict[str, Any] | None:
        parsed = self._parse_uuid(document_id)
        row = (await self.session.execute(select(GovernedRagDocumentRecord).where(
            GovernedRagDocumentRecord.document_id == parsed,
            GovernedRagDocumentRecord.tenant_id == tenant_id,
            GovernedRagDocumentRecord.index_status.in_(("failed", "pending", "indexing")),
        ).with_for_update())).scalar_one_or_none() if parsed else None
        if row is None:
            return None
        row.index_status = "pending"
        row.index_attempts = 0
        row.index_error = None
        row.next_index_attempt_at = None
        await self.session.flush()
        return {"document_id": str(row.document_id), "content_checksum": row.content_checksum}

    async def list_retrievable_governed_rag_documents(
        self, *, tenant_id: str, document_kind: str | None = None,
    ) -> list[GovernedRagDocumentRecord]:
        query = select(GovernedRagDocumentRecord).where(
            GovernedRagDocumentRecord.tenant_id == tenant_id,
            GovernedRagDocumentRecord.review_status == "approved",
            GovernedRagDocumentRecord.index_status == "indexed",
            GovernedRagDocumentRecord.corpus_classification == "TENANT_CURATED",
        )
        if document_kind:
            query = query.where(GovernedRagDocumentRecord.document_kind == document_kind)
        return list((await self.session.execute(query)).scalars())

    async def persist_governed_resolution_selection(
        self,
        *,
        tenant_id: str,
        incident_id: UUID | str,
        alert_id: UUID | str,
        analysis_request_id: UUID | str,
        context_snapshot_id: UUID | str,
        context_fingerprint: str,
        recommendation_id: UUID | str,
        rca_version: int,
        option: dict[str, Any],
        selected_by: str,
    ) -> dict[str, Any]:
        """Atomically persist one immutable, idempotent catalog selection."""
        tenant = require_tenant_id(tenant_id, source="governed resolution selection")
        incident_uuid = self._parse_uuid(incident_id)
        alert_uuid = self._parse_uuid(alert_id)
        analysis_uuid = self._parse_uuid(analysis_request_id)
        snapshot_uuid = self._parse_uuid(context_snapshot_id)
        recommendation_uuid = self._parse_uuid(recommendation_id)
        if not all((incident_uuid, alert_uuid, analysis_uuid, snapshot_uuid, recommendation_uuid)):
            raise ValueError("governed resolution selection requires complete UUID identities")

        projection = (
            await self.session.execute(
                select(IncidentProjectionRecord).where(
                    IncidentProjectionRecord.tenant_id == tenant,
                    IncidentProjectionRecord.incident_id == incident_uuid,
                ).with_for_update()
            )
        ).scalar_one_or_none()
        binding = await self.session.get(IncidentInvestigationBindingRecord, recommendation_uuid)
        if projection is None:
            raise ValueError("stale recommendation or incident projection")
        if projection.recommendation_id != recommendation_uuid:
            if binding is not None and binding.incident_id == incident_uuid and binding.tenant_id == tenant:
                projection.recommendation_id = recommendation_uuid
            else:
                raise ValueError("stale recommendation or incident projection")
        if binding is None:
            raise ValueError("normalized investigation binding is missing")
        expected = (
            tenant, incident_uuid, alert_uuid, analysis_uuid, snapshot_uuid,
            str(context_fingerprint), recommendation_uuid, int(rca_version),
        )
        actual = (
            binding.tenant_id, binding.incident_id, binding.alert_id, binding.analysis_request_id,
            binding.context_snapshot_id, binding.context_fingerprint, binding.recommendation_id,
            int(binding.rca_version),
        )
        if actual != expected:
            raise ValueError("stale investigation identity binding")

        option_id = self._require("catalog_option_id", option.get("id"))
        option_version = self._require("catalog_option_version", option.get("source"))
        if option.get("source") not in {"kaims-governed-catalog-v1", "tenant-learned-resolution-catalog"}:
            raise ValueError("unverified global knowledge cannot create a governed selection")

        key_material = ":".join((
            tenant, str(incident_uuid), str(rca_version), str(recommendation_uuid),
            option_id, str(context_fingerprint),
        ))
        idempotency_key = hashlib.sha256(key_material.encode()).hexdigest()
        existing = (
            await self.session.execute(
                select(GovernedResolutionPlanRecord).where(
                    GovernedResolutionPlanRecord.tenant_id == tenant,
                    GovernedResolutionPlanRecord.idempotency_key == idempotency_key,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return dict(existing.payload)

        previous = (
            await self.session.execute(
                select(GovernedResolutionPlanRecord).where(
                    GovernedResolutionPlanRecord.tenant_id == tenant,
                    GovernedResolutionPlanRecord.incident_id == incident_uuid,
                ).order_by(GovernedResolutionPlanRecord.plan_version.desc()).limit(1)
            )
        ).scalar_one_or_none()
        plan_id = uuid4()
        plan_version = int(previous.plan_version if previous else 0) + 1
        selected_at = utc_now()
        selection = ResolutionSelectionV1(
            selection_id=plan_id,
            tenant_id=tenant,
            incident_id=incident_uuid,
            recommendation_id=recommendation_uuid,
            rca_version=int(rca_version),
            context_snapshot_id=snapshot_uuid,
            context_fingerprint=context_fingerprint,
            catalog_option_id=option_id,
            catalog_option_version=option_version,
            selected_by=self._require("selected_by", selected_by),
            selected_at=selected_at,
            status="selected",
            compilation_blocks=[],
        ).model_dump(mode="json")
        selection_fingerprint = canonical_plan_fingerprint(selection)
        row = GovernedResolutionPlanRecord(
            plan_id=plan_id, tenant_id=tenant, project_id=binding.project_id,
            incident_id=incident_uuid, alert_id=alert_uuid, analysis_request_id=analysis_uuid,
            context_snapshot_id=snapshot_uuid, context_fingerprint=context_fingerprint,
            rca_version=int(rca_version), recommendation_id=recommendation_uuid,
            recommendation_version=int(rca_version), catalog_option_id=option_id,
            catalog_option_version=option_version, plan_version=plan_version,
            plan_fingerprint=selection_fingerprint, idempotency_key=idempotency_key,
            supersedes_plan_id=previous.plan_id if previous else None,
            target_resource=str(option.get("target_resource") or option.get("service") or ""),
            connector_id="", selected_by=selected_by, payload=selection, expires_at=binding.expires_at,
        )
        self.session.add(row)
        if previous is not None:
            self.session.add(ResolutionPlanSupersessionRecord(
                tenant_id=tenant, incident_id=incident_uuid,
                supersedes=previous.plan_id, superseded_by=plan_id,
            ))
        self.session.add(AuditLogRecord(
            tenant_id=tenant, actor=selected_by, action="resolution.plan.selected",
            resource_type="resolution_selection", resource_id=str(plan_id), payload=selection,
        ))
        event_payload = {
            "event_type": "incident.resolution.plan.selected", "tenant_id": tenant,
            "incident_id": str(incident_uuid), "alert_id": str(alert_uuid),
            "recommendation_id": str(recommendation_uuid), "resolution_selection": selection,
        }
        await self.enqueue_resolution_event(
            event_id=f"resolution-plan-selected:{plan_id}", aggregate_id=str(incident_uuid),
            topic="resolution.events", partition_key=str(incident_uuid), payload=event_payload,
            tenant_id=tenant, available_after_seconds=0,
        )
        transition_event_id = uuid5(NAMESPACE_URL, f"resolution-selection:{plan_id}")
        await self.record_resolution_transition({
            "tenant_id": tenant, "incident_id": str(incident_uuid),
            "recommendation_id": str(recommendation_uuid), "execution_plan_id": None,
            "previous_state": "hypotheses_ready", "new_state": "plan_selected",
            "event_id": str(transition_event_id), "actor": selected_by,
            "reason_code": "operator_catalog_selection", "evidence_ids": [],
            "idempotency_key": hashlib.sha256(
                f"{incident_uuid}:{transition_event_id}:plan_selected".encode()
            ).hexdigest(),
        })
        projection_payload = dict(projection.projection_payload or {})
        projection_payload["resolution_selection"] = selection
        projection_payload.pop("resolution_plan", None)
        projection_payload.pop("resolution_plan_id", None)
        projection.projection_payload = projection_payload
        projection.latest_event_type = "incident.resolution.plan.selected"
        projection.latest_event_at = utc_now()
        projection.updated_at = utc_now()
        await self.session.flush()
        return selection

    async def persist_compiled_execution_plan(
        self, *, selection_id: UUID | str, plan: dict[str, Any], blocking_reasons: list[str],
    ) -> dict[str, Any] | None:
        selection_uuid = self._parse_uuid(selection_id)
        row = await self.session.get(GovernedResolutionPlanRecord, selection_uuid) if selection_uuid else None
        if row is None:
            raise ValueError("resolution selection does not exist")
        selection = ResolutionSelectionV1.model_validate(row.payload)
        if blocking_reasons or plan.get("execution_ready") is not True:
            blocked = selection.model_copy(update={
                "status": "compilation_blocked",
                "compilation_blocks": sorted(set(str(item) for item in blocking_reasons if str(item))),
            })
            row.payload = blocked.model_dump(mode="json")
            await self.session.flush()
            return None
        if not str(plan.get("policy_version") or "").strip():
            plan = {**plan, "policy_version": "resolution-policy.v1"}
        validated = ExecutionPlanV2.model_validate(plan).finalized()
        payload = validated.model_dump(mode="json")
        if (
            validated.tenant_id != selection.tenant_id
            or validated.incident_id != selection.incident_id
            or validated.recommendation_id != selection.recommendation_id
            or validated.rca_version != selection.rca_version
            or validated.evidence_snapshot_id != selection.context_snapshot_id
            or validated.context_fingerprint != selection.context_fingerprint
            or validated.resolution_selection_id != selection.selection_id
        ):
            raise ValueError("compiled execution plan does not match its resolution selection")
        prior = await self.session.get(ExecutionPlanRecord, validated.plan_id)
        if prior is not None:
            if (prior.tenant_id != selection.tenant_id
                    or prior.resolution_selection_id != selection.selection_id):
                raise ValueError("execution plan identity belongs to another selection")
            validated = ExecutionPlanV2.model_validate(prior.plan_payload)
            payload = validated.model_dump(mode="json")
        else:
            existing = (await self.session.execute(select(ExecutionPlanRecord).where(
                ExecutionPlanRecord.tenant_id == selection.tenant_id,
                ExecutionPlanRecord.fingerprint == validated.plan_fingerprint,
            ))).scalar_one_or_none()
            if existing is None:
                existing = ExecutionPlanRecord(
                    id=validated.plan_id, tenant_id=validated.tenant_id, incident_id=validated.incident_id,
                    recommendation_id=validated.recommendation_id, rca_version=validated.rca_version,
                    context_snapshot_id=validated.evidence_snapshot_id,
                    context_fingerprint=validated.context_fingerprint,
                    resolution_selection_id=validated.resolution_selection_id,
                    policy_version=validated.policy_version or "resolution-policy.v1",
                    playbook_id=validated.playbook_id, schema_version=validated.schema_version,
                    fingerprint=validated.plan_fingerprint, target_service=validated.service,
                    target_environment=validated.environment, risk_tier=validated.risk_tier,
                    execution_mode=validated.execution_mode, approval_required=validated.approval_required,
                    execution_ready=validated.execution_ready, readiness_blocks=validated.readiness_blocks,
                    plan_payload=payload,
                )
                self.session.add(existing)
        compiled = selection.model_copy(update={
            "status": "compiled", "compiled_execution_plan_id": validated.plan_id,
            "compilation_blocks": [],
        })
        row.payload = compiled.model_dump(mode="json")
        from common.resolution_lifecycle import (
            ResolutionState,
            create_lifecycle,
            decide_resolution_control,
        )
        control = decide_resolution_control(payload, requires_approval=validated.approval_required)
        new_lifecycle = create_lifecycle(
            tenant_id=selection.tenant_id,
            incident_id=selection.incident_id,
            recommendation_id=selection.recommendation_id,
            plan=payload,
            state=ResolutionState.AWAITING_APPROVAL if validated.approval_required else ResolutionState.READY_TO_EXECUTE,
            reason_code=str(control.get("reason_code") or "human_approval_required"),
            control=control,
        )
        projection = (await self.session.execute(select(IncidentProjectionRecord).where(
            IncidentProjectionRecord.tenant_id == selection.tenant_id,
            IncidentProjectionRecord.incident_id == selection.incident_id,
        ).with_for_update())).scalar_one_or_none()
        incident_row = await self.session.get(IncidentRecord, selection.incident_id)
        prior_version = 0
        for candidate_holder in (
            (projection.projection_payload or {}) if projection is not None else {},
            ((incident_row.payload or {}).get("metadata") or {}) if incident_row is not None and isinstance(incident_row.payload, dict) else {},
        ):
            cand_lc = candidate_holder.get("resolution_lifecycle") if isinstance(candidate_holder, dict) else None
            if isinstance(cand_lc, dict):
                try:
                    prior_version = max(prior_version, int(cand_lc.get("state_version") or 0))
                except (TypeError, ValueError):
                    pass
        if prior_version >= 1:
            new_lifecycle["state_version"] = prior_version + 1
        if projection is not None:
            projection_payload = dict(projection.projection_payload or {})
            projection_payload["resolution_selection"] = row.payload
            projection_payload["execution_plan"] = payload
            if validated.execution_ready:
                projection_payload["resolution_lifecycle"] = new_lifecycle
            if isinstance(projection_payload.get("recommendation"), dict):
                proj_rec = dict(projection_payload["recommendation"])
                proj_rec_meta = dict(proj_rec.get("metadata") or {}) if isinstance(proj_rec.get("metadata"), dict) else {}
                proj_rec_meta["execution_plan"] = payload
                if validated.execution_ready:
                    proj_rec_meta["resolution_lifecycle"] = new_lifecycle
                    proj_rec_meta["resolution_control"] = control
                proj_rec["metadata"] = proj_rec_meta
                if validated.commands:
                    proj_rec["steps"] = list(validated.commands)
                projection_payload["recommendation"] = proj_rec
            projection.projection_payload = projection_payload
            if validated.execution_ready and str(projection.status or "").lower() not in {"remediating", "validating", "resolved", "closed"}:
                projection.status = "awaiting_approval" if validated.approval_required else "approved"
                projection.lifecycle_state = "AWAITING_APPROVAL" if validated.approval_required else "PLAN_READY"
                projection.recommendation_id = validated.recommendation_id
        rec_audit = await self.session.get(AuditLogRecord, selection.recommendation_id)
        if rec_audit is not None and rec_audit.tenant_id == selection.tenant_id and isinstance(rec_audit.payload, dict):
            rec_payload = dict(rec_audit.payload)
            rec_meta = dict(rec_payload.get("metadata") or {}) if isinstance(rec_payload.get("metadata"), dict) else {}
            rec_meta["execution_plan"] = payload
            if validated.execution_ready:
                rec_meta["resolution_lifecycle"] = new_lifecycle
                rec_meta["resolution_control"] = control
            rec_payload["metadata"] = rec_meta
            if validated.commands:
                rec_payload["steps"] = list(validated.commands)
            rec_audit.payload = rec_payload
        if incident_row is not None and validated.execution_ready and str(incident_row.status or "").lower() not in {"remediating", "validating", "resolved", "closed"}:
            new_inc_status = "awaiting_approval" if validated.approval_required else "approved"
            incident_row.status = new_inc_status
            inc_payload = dict(incident_row.payload or {}) if isinstance(incident_row.payload, dict) else {}
            inc_payload["status"] = new_inc_status
            inc_meta = dict(inc_payload.get("metadata") or {}) if isinstance(inc_payload.get("metadata"), dict) else {}
            inc_meta["resolution_lifecycle"] = new_lifecycle
            inc_payload["metadata"] = inc_meta
            incident_row.payload = inc_payload
        if validated.execution_ready:
            ownership_rows = (await self.session.execute(select(IncidentCorrelationOwnershipRecord).where(
                IncidentCorrelationOwnershipRecord.tenant_id == selection.tenant_id,
                IncidentCorrelationOwnershipRecord.canonical_incident_id == selection.incident_id,
            ))).scalars().all()
            for own_row in ownership_rows:
                if str(own_row.lifecycle_state or "").lower() not in {"remediating", "validating", "resolved", "closed", "cancelled", "canceled"}:
                    own_row.lifecycle_state = "awaiting_approval" if validated.approval_required else "approved"
        binding = await self.session.get(IncidentInvestigationBindingRecord, selection.recommendation_id)
        if binding is not None:
            binding.resolution_plan_id = validated.plan_id
            binding.plan_fingerprint = validated.plan_fingerprint
        if prior is not None:
            await self.session.flush()
            return payload
        self.session.add(AuditLogRecord(
            tenant_id=selection.tenant_id, actor=selection.selected_by,
            action="resolution.plan.compiled", resource_type="execution_plan",
            resource_id=str(validated.plan_id), payload=payload,
        ))
        await self.enqueue_resolution_event(
            event_id=f"execution-plan-compiled:{validated.plan_id}",
            aggregate_id=str(selection.incident_id), topic="resolution.events",
            partition_key=str(selection.incident_id), tenant_id=selection.tenant_id,
            payload={"event_type": "incident.resolution.plan.compiled", "tenant_id": selection.tenant_id,
                     "incident_id": str(selection.incident_id), "resolution_selection": row.payload,
                     "execution_plan": payload}, available_after_seconds=0,
        )
        transitions = [
            ("plan_selected", "plan_compiled", "registered_plan_compiled"),
            ("plan_compiled", "policy_checked", "execution_policy_checked"),
            ("policy_checked", "awaiting_approval" if validated.approval_required else "ready_to_execute",
             "human_approval_required" if validated.approval_required else "policy_execution_ready"),
        ]
        for index, (previous_state, new_state, reason_code) in enumerate(transitions, 1):
            event_id = uuid5(NAMESPACE_URL, f"execution-plan:{validated.plan_id}:{index}:{new_state}")
            await self.record_resolution_transition({
                "tenant_id": selection.tenant_id, "incident_id": str(selection.incident_id),
                "recommendation_id": str(selection.recommendation_id),
                "execution_plan_id": str(validated.plan_id), "previous_state": previous_state,
                "new_state": new_state, "event_id": str(event_id), "actor": "resolution-agent",
                "reason_code": reason_code, "evidence_ids": validated.evidence_references,
                "policy_decision": {"version": validated.policy_version,
                                    "decision": validated.approval_policy.decision},
                "idempotency_key": hashlib.sha256(
                    f"{selection.incident_id}:{event_id}:{new_state}".encode()
                ).hexdigest(),
            })
        await self.session.flush()
        return payload

    async def get_current_execution_plan_for_incident(
        self, *, tenant_id: str, incident_id: UUID | str,
        recommendation_id: UUID | str, rca_version: int,
    ) -> dict[str, Any] | None:
        incident_uuid = self._parse_uuid(incident_id)
        recommendation_uuid = self._parse_uuid(recommendation_id)
        if not incident_uuid or not recommendation_uuid:
            return None
        row = (await self.session.execute(select(ExecutionPlanRecord).where(
            ExecutionPlanRecord.tenant_id == require_tenant_id(tenant_id, source="execution plan lookup"),
            ExecutionPlanRecord.incident_id == incident_uuid,
            ExecutionPlanRecord.recommendation_id == recommendation_uuid,
            ExecutionPlanRecord.rca_version == int(rca_version),
        ).order_by(ExecutionPlanRecord.created_at.desc()).limit(1))).scalar_one_or_none()
        if row is None:
            return None
        return ExecutionPlanV2.model_validate(row.plan_payload).model_dump(mode="json")

    @staticmethod
    def build_incident_investigation_contract(
        *,
        tenant_id: str,
        project_id: str,
        incident_id: UUID | str,
        alert_id: UUID | str,
        recommendation: dict[str, Any],
        context_snapshot: dict[str, Any],
        approval: dict[str, Any] | None = None,
        remediation_action: dict[str, Any] | None = None,
        validation_status: str = "pending",
    ) -> dict[str, Any]:
        """Construct and validate the versioned runtime contract.

        Required immutable identifiers are intentionally not synthesized.  A
        malformed or legacy payload raises validation failure so its caller can
        downgrade integrity to ``contract_invalid``.
        """
        metadata = recommendation.get("metadata") if isinstance(recommendation.get("metadata"), dict) else {}
        context = context_snapshot.get("context") if isinstance(context_snapshot.get("context"), dict) else {}
        context_metadata = context.get("metadata") if isinstance(context.get("metadata"), dict) else {}
        quality = (
            context_metadata.get("context_quality")
            if isinstance(context_metadata.get("context_quality"), dict)
            else {}
        )
        source_manifest = (
            context_metadata.get("context_sources")
            if isinstance(context_metadata.get("context_sources"), dict)
            else {}
        )
        evidence_buckets = (
            context_metadata.get("context_evidence")
            if isinstance(context_metadata.get("context_evidence"), dict)
            else {}
        )
        evidence_rows = [
            item
            for bucket in evidence_buckets.values()
            if isinstance(bucket, list)
            for item in bucket
            if isinstance(item, dict)
        ]

        def contract_timestamp(value: Any) -> str | None:
            parsed = IncidentRepository._parse_datetime(value)
            normalized = _utc_dt(parsed)
            return normalized.isoformat().replace("+00:00", "Z") if normalized else None

        sources = []
        for source_id, details in source_manifest.items():
            row = details if isinstance(details, dict) else {}
            raw_status = str(row.get("status") or row.get("collection_status") or "skipped").lower()
            status_aliases = {
                "collected": "completed",
                "success": "completed",
                "stale": "completed",
                "fresh": "completed",
                "no_matches": "empty",
                "failed": "unavailable",
            }
            status = status_aliases.get(raw_status, raw_status)
            collected_at = contract_timestamp(
                row.get("collected_at") or context_snapshot.get("collected_at")
            )
            sources.append({
                "source_id": str(source_id),
                "category": str(row.get("category") or source_id),
                "connector": str(row.get("connector") or row.get("provider") or source_id),
                "status": status,
                "collected_at": collected_at,
                "error": str(row.get("error") or "") or None,
            })
        evidence = [{
            "evidence_id": item.get("evidence_id") or item.get("id"),
            "category": item.get("category") or item.get("source_type") or "unknown",
            "source_id": item.get("source_id") or item.get("source") or item.get("connector") or "unknown",
            "connector": item.get("connector") or item.get("source") or "unknown",
            "tenant_id": item.get("tenant_id") or tenant_id,
            "project_id": item.get("project_id") or project_id,
            "service": item.get("service") or context.get("alert", {}).get("service") or "unknown",
            "resource_id": item.get("resource_id"),
            "observed_at": contract_timestamp(item.get("observed_at")),
            "collected_at": contract_timestamp(
                item.get("collected_at")
                or (item.get("provenance") or {}).get("generated_at")
                or context_snapshot.get("collected_at")
            ),
            "observation_window": item.get("observation_window"),
            "freshness": str(item.get("freshness") or "unknown").lower(),
            "provenance": item.get("provenance") if isinstance(item.get("provenance"), dict) else {},
            "citation": (
                item.get("citation")
                or item.get("source_uri")
                or item.get("uri")
                or (item.get("provenance") or {}).get("primary_source")
            ),
            "epistemic_role": item.get("epistemic_role") or "current_observation",
            "current_observation": item.get("current_observation") is not False,
        } for item in evidence_rows if is_traceable_evidence_citation(
            item.get("citation") or item.get("source_uri") or item.get("uri")
            or (item.get("provenance") or {}).get("primary_source")
        )]
        analysis = metadata.get("rca_analysis") if isinstance(metadata.get("rca_analysis"), dict) else {}
        investigation = (
            metadata.get("iterative_investigation")
            if isinstance(metadata.get("iterative_investigation"), dict)
            else metadata.get("investigation_report")
            if isinstance(metadata.get("investigation_report"), dict)
            else {}
        )
        plan = metadata.get("execution_plan") if isinstance(metadata.get("execution_plan"), dict) else {}
        requested_accepted = (
            metadata.get("evidence_ids")
            if isinstance(metadata.get("evidence_ids"), list)
            else analysis.get("evidence_used", [])
        )
        evidence_ids = {str(item.get("evidence_id") or "") for item in evidence}
        accepted = [str(item) for item in requested_accepted if str(item) in evidence_ids]
        rejected_untraceable = [str(item) for item in requested_accepted if str(item) not in evidence_ids]
        missing = analysis.get("missing_evidence", []) if isinstance(analysis.get("missing_evidence"), list) else []
        conflicting = (
            analysis.get("conflicting_evidence", [])
            if isinstance(analysis.get("conflicting_evidence"), list)
            else []
        )
        conclusive = (
            investigation.get("conclusive") is True
            and str(investigation.get("status") or "").lower() == "conclusive"
        )
        grounded = str(metadata.get("rca_status") or "").lower() == "grounded" and bool(accepted)
        context_expires_at = IncidentRepository._parse_datetime(context_snapshot.get("expires_at"))
        context_identity_valid = bool(evidence) and all(
            str(item.get("tenant_id") or "") == tenant_id
            and str(item.get("project_id") or "") == project_id
            and bool(str(item.get("citation") or "").strip())
            for item in evidence
        )
        context_ready = bool(
            context_snapshot.get("snapshot_id")
            and context_snapshot.get("context_fingerprint")
            and (
                (
                    quality.get("valid", quality.get("reusable", False)) is True
                    and not quality.get("blocking_reasons")
                    and context_identity_valid
                    and context_expires_at is not None
                    and _utc_dt(context_expires_at) > datetime.now(UTC)
                )
                or (conclusive and grounded and not missing and not conflicting)
            )
        )
        rca_ready = bool(context_ready and conclusive and grounded and not missing and not conflicting)
        plan_blocks = plan.get("readiness_blocks") if isinstance(plan.get("readiness_blocks"), list) else []
        plan_id = plan.get("plan_id") or plan.get("id")
        plan_fingerprint = plan.get("plan_fingerprint") or plan.get("fingerprint")
        plan_integrity_valid = bool(plan_id and plan_fingerprint and verify_plan_fingerprint(plan))
        resolution_ready = bool(rca_ready and recommendation.get("id") and plan_integrity_valid)
        readiness_blocks = list(dict.fromkeys([
            *[str(item) for item in missing],
            *[str(item) for item in conflicting],
            *[str(item) for item in plan_blocks],
            *(["RCA references evidence without a traceable citation"] if rejected_untraceable else []),
            *([] if conclusive else ["investigation is not conclusive"]),
            *([] if grounded else ["RCA is not grounded in accepted evidence"]),
            *([] if plan_integrity_valid else ["exact resolution plan is not ready or its fingerprint is invalid"]),
        ]))
        approval_payload = approval if isinstance(approval, dict) else {}
        approval_status = str(approval_payload.get("decision") or approval_payload.get("status") or "not_ready").lower()
        if approval_status not in {"not_ready", "pending", "approved", "rejected", "stale"}:
            approval_status = "not_ready"
        readiness_receipt = (
            approval_payload.get("approval_readiness")
            if isinstance(approval_payload.get("approval_readiness"), dict)
            else plan.get("approval_readiness")
            if isinstance(plan.get("approval_readiness"), dict)
            else {}
        )
        approval_ready = bool(
            resolution_ready
            and (
                (
                    readiness_receipt.get("signature")
                    and str(readiness_receipt.get("state") or "").lower() == "execution_eligible"
                    and not readiness_receipt.get("missing_controls")
                )
                or (
                    plan.get("execution_ready") is True
                    and plan.get("mutating") is True
                    and not readiness_blocks
                )
            )
        )
        execution_ready = bool(
            approval_ready and approval_status == "approved"
            and plan.get("execution_ready") is True and plan.get("mutating") is True
            and not readiness_blocks
        )
        if not execution_ready and not readiness_blocks:
            if approval_ready and approval_status != "approved":
                readiness_blocks.append("awaiting_operator_approval")
            elif not bool(plan.get("mutating")):
                readiness_blocks.append("diagnostic_only_plan")
            elif not bool(plan.get("execution_ready")):
                readiness_blocks.append("plan_not_execution_ready")
            else:
                readiness_blocks.append("execution_not_ready")
        remediation_status = str((remediation_action or {}).get("status") or "not_started").lower()
        validation_ready = bool(execution_ready and remediation_status in {"succeeded", "completed"})
        closure_ready = bool(validation_ready and str(validation_status or "").lower() in {"validated", "passed", "closed"})
        raw_investigation_status = str(investigation.get("status") or "pending").lower()
        investigation_status = {
            "budget_exhausted": "inconclusive",
            "completed": "conclusive" if conclusive else "inconclusive",
            "running": "investigating",
        }.get(raw_investigation_status, raw_investigation_status)
        payload = {
            "contract_version": "kaiops.incident-investigation.v1",
            "tenant_id": tenant_id,
            "project_id": project_id,
            "incident_id": incident_id,
            "alert_id": alert_id,
            "analysis_request_id": metadata.get("analysis_request_id"),
            "context_snapshot_id": context_snapshot.get("snapshot_id"),
            "context_fingerprint": context_snapshot.get("context_fingerprint"),
            "context_contract_version": context_snapshot.get("contract_version"),
            "context_collected_at": contract_timestamp(context_snapshot.get("collected_at")),
            "context_expires_at": contract_timestamp(context_snapshot.get("expires_at")),
            "context_quality": {
                "evidence_count": len(evidence),
                "category_coverage": float(
                    quality.get("source_coverage_score")
                    if quality.get("source_coverage_score") is not None
                    else quality.get("category_coverage")
                    if quality.get("category_coverage") is not None
                    else quality.get("coverage_score") or 0
                ),
                "rca_readiness_score": float(quality.get("rca_readiness_score") or 0),
                "impact_readiness_score": float(quality.get("impact_readiness_score") or 0),
                "rca_ready": bool(quality.get("rca_ready", False)),
                "impact_ready": bool(quality.get("impact_ready", False)),
                "freshness_score": float(quality.get("freshness_score") or 0),
                "provenance_score": float(quality.get("provenance_score") or 0),
                "independent_source_count": int(quality.get("independent_source_count") or 0),
                "direct_observation_count": int(quality.get("direct_observation_count") or 0),
                "valid": bool(quality.get("valid", quality.get("reusable", False))),
                "blocking_reasons": [str(item) for item in quality.get("blocking_reasons", [])],
            },
            "context_sources": sources,
            "context_evidence": evidence,
            "investigation_id": investigation.get("investigation_id"),
            "investigation_status": investigation_status,
            "investigation_conclusive": conclusive,
            "rca_version": metadata.get("rca_version"),
            "rca_status": metadata.get("rca_status") or "pending",
            "accepted_evidence_ids": [str(item) for item in accepted],
            "missing_evidence": [str(item) for item in missing],
            "conflicting_evidence": [str(item) for item in conflicting],
            "recommendation_id": recommendation.get("id"),
            "resolution_plan_id": plan_id,
            "plan_fingerprint": plan_fingerprint,
            "execution_ready": execution_ready,
            "readiness_blocks": readiness_blocks,
            "approval_status": approval_status,
            "remediation_status": remediation_status,
            "validation_status": validation_status,
            "readiness": {
                "context_ready": context_ready,
                "rca_ready": rca_ready,
                "resolution_ready": resolution_ready,
                "approval_ready": approval_ready,
                "execution_ready": execution_ready,
                "validation_ready": validation_ready,
                "closure_ready": closure_ready,
                "blocking_reasons": readiness_blocks,
            },
        }
        return IncidentInvestigationContract.model_validate(payload).model_dump(mode="json")

    async def create_resolution_investigation(self, payload: dict[str, Any]) -> None:
        await self.session.execute(
            text(
                "INSERT INTO resolution_investigations "
                "(investigation_id,tenant_id,incident_id,alert_id,status,step_budget,steps_used,evidence_count,"
                "tool_budget,source_coverage,missing_sources,conclusion,payload,started_at) "
                "VALUES (:investigation_id,:tenant_id,:incident_id,:alert_id,:status,:step_budget,0,:evidence_count,"
                ":tool_budget,:source_coverage,:missing_sources,:conclusion,:payload,NOW(6)) "
                "ON DUPLICATE KEY UPDATE status=VALUES(status), updated_at=NOW(6)"
            ),
            {
                "investigation_id": self._require("investigation_id", payload.get("investigation_id")),
                "tenant_id": str(payload.get("tenant_id") or "default"),
                "incident_id": self._require("incident_id", payload.get("incident_id")),
                "alert_id": str(payload.get("alert_id") or "") or None,
                "status": str(payload.get("status") or "running"),
                "step_budget": int(payload.get("step_budget") or 1),
                "evidence_count": int(payload.get("evidence_count") or 0),
                "tool_budget": json.dumps({"max_steps": int(payload.get("step_budget") or 1)}),
                "source_coverage": json.dumps({}),
                "missing_sources": json.dumps([]),
                "conclusion": json.dumps({}),
                "payload": json.dumps(payload, default=str),
            },
        )

    async def append_resolution_investigation_step(self, payload: dict[str, Any]) -> None:
        await self.session.execute(
            text(
                "INSERT INTO resolution_investigation_steps "
                "(step_id,investigation_id,sequence_no,tool_name,query_payload,status,result_count,evidence_ids,"
                "hypothesis_updates,error_message,started_at,completed_at) "
                "VALUES (:step_id,:investigation_id,:sequence_no,:tool_name,:query_payload,:status,:result_count,"
                ":evidence_ids,:hypothesis_updates,:error_message,:started_at,:completed_at) "
                "ON DUPLICATE KEY UPDATE status=VALUES(status),result_count=VALUES(result_count),"
                "evidence_ids=VALUES(evidence_ids),hypothesis_updates=VALUES(hypothesis_updates),"
                "error_message=VALUES(error_message),completed_at=VALUES(completed_at)"
            ),
            {
                "step_id": self._require("step_id", payload.get("step_id")),
                "investigation_id": self._require("investigation_id", payload.get("investigation_id")),
                "sequence_no": int(payload.get("sequence_no") or 0),
                "tool_name": self._require("tool_name", payload.get("tool_name")),
                "query_payload": json.dumps(payload.get("query") or {}, default=str),
                "status": str(payload.get("status") or "completed"),
                "result_count": int(payload.get("result_count") or 0),
                "evidence_ids": json.dumps(payload.get("evidence_ids") or []),
                "hypothesis_updates": json.dumps(payload.get("hypothesis_updates") or [], default=str),
                "error_message": str(payload.get("error") or "")[:1000] or None,
                "started_at": payload.get("started_at") or utc_now(),
                "completed_at": payload.get("completed_at") or utc_now(),
            },
        )

    async def complete_resolution_investigation(self, payload: dict[str, Any]) -> None:
        investigation_id = self._require("investigation_id", payload.get("investigation_id"))
        await self.session.execute(
            text(
                "UPDATE resolution_investigations SET status=:status,stop_reason=:stop_reason,steps_used=:steps_used,"
                "evidence_count=:evidence_count,source_coverage=:source_coverage,missing_sources=:missing_sources,"
                "conclusion=:conclusion,payload=:payload,completed_at=NOW(6),updated_at=NOW(6) "
                "WHERE investigation_id=:investigation_id"
            ),
            {
                "investigation_id": investigation_id,
                "status": str(payload.get("status") or "inconclusive"),
                "stop_reason": str(payload.get("stop_reason") or "")[:128] or None,
                "steps_used": int(payload.get("steps_used") or 0),
                "evidence_count": int(payload.get("evidence_count") or 0),
                "source_coverage": json.dumps(payload.get("source_coverage") or {}),
                "missing_sources": json.dumps(payload.get("missing_sources") or []),
                "conclusion": json.dumps(payload.get("conclusion") or {}, default=str),
                "payload": json.dumps(payload, default=str),
            },
        )
        for hypothesis in payload.get("hypotheses") or []:
            if not isinstance(hypothesis, dict) or not str(hypothesis.get("claim") or "").strip():
                continue
            claim = str(hypothesis["claim"]).strip()
            digest = hashlib.sha256(claim.lower().encode()).hexdigest()
            await self.session.execute(
                text(
                    "INSERT INTO resolution_hypotheses "
                    "(hypothesis_id,investigation_id,claim_digest,claim_text,status,confidence,supporting_evidence_ids,"
                    "contradicting_evidence_ids,falsification_query,source,payload) "
                    "VALUES (:hypothesis_id,:investigation_id,:claim_digest,:claim_text,:status,:confidence,"
                    ":supporting,:contradicting,:falsification,:source,:payload) "
                    "ON DUPLICATE KEY UPDATE status=VALUES(status),confidence=VALUES(confidence),"
                    "supporting_evidence_ids=VALUES(supporting_evidence_ids),"
                    "contradicting_evidence_ids=VALUES(contradicting_evidence_ids),payload=VALUES(payload),updated_at=NOW(6)"
                ),
                {
                    "hypothesis_id": str(hypothesis.get("hypothesis_id") or uuid4()),
                    "investigation_id": investigation_id,
                    "claim_digest": digest,
                    "claim_text": claim,
                    "status": str(hypothesis.get("status") or "viable"),
                    "confidence": max(0.0, min(float(hypothesis.get("confidence") or 0.0), 1.0)),
                    "supporting": json.dumps(hypothesis.get("supporting_evidence_ids") or []),
                    "contradicting": json.dumps(hypothesis.get("contradicting_evidence_ids") or []),
                    "falsification": json.dumps(hypothesis.get("falsification_query") or {}, default=str),
                    "source": str(hypothesis.get("source") or "unknown")[:64],
                    "payload": json.dumps(hypothesis, default=str),
                },
            )

    async def latest_resolution_investigation(
        self, incident_id: str, *, tenant_id: str = "default"
    ) -> dict[str, Any] | None:
        row = (
            await self.session.execute(
                text(
                    "SELECT payload FROM resolution_investigations "
                    "WHERE tenant_id=:tenant_id AND incident_id=:incident_id "
                    "ORDER BY started_at DESC LIMIT 1"
                ),
                {"tenant_id": tenant_id or "default", "incident_id": incident_id},
            )
        ).scalar_one_or_none()
        if isinstance(row, dict):
            return row
        if isinstance(row, str):
            try:
                parsed = json.loads(row)
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
        return None

    async def record_resolution_transition(self, payload: dict[str, Any]) -> bool:
        """Append one idempotent lifecycle transition; duplicate events are no-ops."""
        insert_verb = "INSERT OR IGNORE" if self.session.bind and self.session.bind.dialect.name == "sqlite" else "INSERT IGNORE"
        result = await self.session.execute(
            text(
                f"{insert_verb} INTO resolution_state_transitions "
                "(transition_id,tenant_id,incident_id,recommendation_id,execution_plan_id,previous_state,new_state,"
                "event_id,correlation_id,causation_id,idempotency_key,actor,reason_code,evidence_ids,policy_decision,payload) "
                "VALUES (:transition_id,:tenant_id,:incident_id,:recommendation_id,:execution_plan_id,:previous_state,"
                ":new_state,:event_id,:correlation_id,:causation_id,:idempotency_key,:actor,:reason_code,"
                ":evidence_ids,:policy_decision,:payload)"
            ),
            {
                "transition_id": str(payload.get("transition_id") or uuid4()),
                "tenant_id": str(payload.get("tenant_id") or "default"),
                "incident_id": self._require("incident_id", payload.get("incident_id")),
                "recommendation_id": str(payload.get("recommendation_id") or "") or None,
                "execution_plan_id": str(payload.get("execution_plan_id") or "") or None,
                "previous_state": self._require("previous_state", payload.get("previous_state")),
                "new_state": self._require("new_state", payload.get("new_state")),
                "event_id": self._require("event_id", payload.get("event_id")),
                "correlation_id": str(payload.get("correlation_id") or "") or None,
                "causation_id": str(payload.get("causation_id") or "") or None,
                "idempotency_key": self._require("idempotency_key", payload.get("idempotency_key")),
                "actor": self._require("actor", payload.get("actor")),
                "reason_code": self._require("reason_code", payload.get("reason_code")),
                "evidence_ids": json.dumps(payload.get("evidence_ids") or []),
                "policy_decision": json.dumps(payload.get("policy_decision") or {}, default=str),
                "payload": json.dumps(payload, default=str),
            },
        )
        return bool(result.rowcount)

    async def get_approved_runbook_version(
        self, runbook_id: str, version: int, *, tenant_id: str = "default"
    ) -> dict[str, Any] | None:
        normalized_runbook_id = self._parse_uuid(runbook_id).hex
        row = (
            await self.session.execute(
                text(
                    "SELECT rv.content,rv.owner,rv.risk_level,rv.success_count,rv.failure_count,"
                    "ra.approver,ra.approver_role,ra.approved_at "
                    "FROM runbook_versions rv JOIN runbook_approvals ra "
                    "ON ra.runbook_id=rv.runbook_id AND ra.version=rv.version AND ra.status='approved' "
                    "WHERE rv.tenant_id=:tenant_id AND rv.runbook_id=:runbook_id AND rv.version=:version "
                    "AND rv.approval_status='approved' LIMIT 1"
                ),
                {"tenant_id": tenant_id, "runbook_id": normalized_runbook_id, "version": int(version)},
            )
        ).mappings().first()
        if row is None:
            return None
        content = row["content"]
        if isinstance(content, str):
            content = json.loads(content)
        attempts = int(row["success_count"] or 0) + int(row["failure_count"] or 0)
        return {
            **(content if isinstance(content, dict) else {}),
            "runbook_id": str(UUID(normalized_runbook_id)),
            "version": int(version),
            "status": "approved",
            "owner": row["owner"],
            "risk": row["risk_level"],
            "success_rate": int(row["success_count"] or 0) / attempts if attempts else 0.0,
            "approved_by": row["approver"],
            "approver_role": row["approver_role"],
            "approved_at": (
                row["approved_at"].isoformat()
                if hasattr(row["approved_at"], "isoformat")
                else (str(row["approved_at"]) if row["approved_at"] else None)
            ),
        }

    async def save_application(self, application: ApplicationRegistration) -> None:
        await self.session.merge(
            ApplicationRecord(
                id=self._require("application.id", application.id),
                tenant_id=self._require("application.tenant_id", application.tenant_id),
                name=self._require("application.name", application.name),
                owner_team=self._require("application.owner_team", application.owner_team),
                owner_email=application.owner_email,
                environment=self._require("application.environment", application.environment),
                namespace=self._require("application.namespace", application.namespace),
                region=self._require("application.region", application.region),
                technology=self._require("application.technology", application.technology),
                monitoring_platform=str(application.monitoring_platform),
                metrics_endpoint=self._require("application.metrics_endpoint", application.metrics_endpoint),
                status=str(application.status),
                payload=application.model_dump(mode="json"),
            )
        )
        from common.diagnostic_runbooks import ensure_diagnostic_runbook
        await ensure_diagnostic_runbook(self.session, tenant_id=application.tenant_id,
            application=application.name, service=application.name, environment=application.environment,
            owner=application.owner_team)
        await self.session.execute(delete(ApplicationEnvironmentRecord).where(ApplicationEnvironmentRecord.application_id == application.id))
        await self.session.execute(delete(ApplicationLabelRecord).where(ApplicationLabelRecord.application_id == application.id))
        self.session.add(
            ApplicationEnvironmentRecord(
                application_id=application.id,
                tenant_id=application.tenant_id,
                environment=application.environment,
                namespace=application.namespace,
                region=application.region,
                cluster=application.labels.get("cluster") if isinstance(application.labels, dict) else None,
                payload={"metrics_endpoint": application.metrics_endpoint},
            )
        )
        for key, value in (application.labels or {}).items():
            self.session.add(
                ApplicationLabelRecord(
                    application_id=application.id,
                    tenant_id=application.tenant_id,
                    label_key=str(key),
                    label_value=str(value),
                )
            )

    async def update_application_status(
        self,
        application_id: Any,
        *,
        status: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        record = await self.session.get(ApplicationRecord, application_id)
        if record is None:
            return
        record.status = str(status)
        if isinstance(payload, dict) and payload:
            merged_payload = dict(record.payload or {})
            merged_payload.update(payload)
            record.payload = merged_payload
        await self.session.merge(record)

    async def save_monitoring_integration(
        self,
        *,
        integration_id: Any,
        tenant_id: str,
        project_name: str,
        provider: str,
        status: str,
        active: bool,
        auth_type: str,
        endpoint_url: str | None,
        webhook_path: str,
        deployment_mode: str,
        config_payload: dict[str, Any],
        validation_payload: dict[str, Any],
    ) -> None:
        parsed_id = self._parse_uuid(integration_id)
        if parsed_id is None:
            raise ValueError("monitoring_integration.id is required")
        await self.session.merge(
            MonitoringIntegrationRecord(
                id=parsed_id,
                tenant_id=self._require("monitoring_integration.tenant_id", tenant_id),
                project_name=self._require("monitoring_integration.project_name", project_name),
                provider=self._require("monitoring_integration.provider", provider),
                status=self._require("monitoring_integration.status", status),
                active=bool(active),
                auth_type=self._require("monitoring_integration.auth_type", auth_type),
                endpoint_url=endpoint_url,
                webhook_path=self._require("monitoring_integration.webhook_path", webhook_path),
                deployment_mode=self._require("monitoring_integration.deployment_mode", deployment_mode),
                config_payload=config_payload or {},
                validation_payload=validation_payload or {},
            )
        )

    async def list_monitoring_integrations(self, tenant_id: str = "default") -> list[dict[str, Any]]:
        result = await self.session.execute(
            select(MonitoringIntegrationRecord)
            .where(MonitoringIntegrationRecord.tenant_id == str(tenant_id or "default"))
            .order_by(MonitoringIntegrationRecord.updated_at.desc())
        )
        rows = result.scalars().all()
        return [
            {
                "id": str(row.id),
                "tenant_id": row.tenant_id,
                "project_name": row.project_name,
                "provider": row.provider,
                "status": row.status,
                "active": row.active,
                "auth_type": row.auth_type,
                "endpoint_url": row.endpoint_url,
                "webhook_path": row.webhook_path,
                "deployment_mode": row.deployment_mode,
                "config_payload": row.config_payload,
                "validation_payload": row.validation_payload,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
            for row in rows
        ]

    async def resolve_context_integrations(
        self, *, tenant_id: str, project_candidates: list[str],
    ) -> list[dict[str, Any]]:
        """Resolve active onboarding connectors by exact tenant/project identity."""
        candidates = {str(value).strip().lower() for value in project_candidates if str(value).strip()}
        if not candidates:
            return []
        integrations = (
            await self.session.execute(
                select(MonitoringIntegrationRecord).where(
                    MonitoringIntegrationRecord.tenant_id
                    == self._require("monitoring_integration.tenant_id", tenant_id),
                    MonitoringIntegrationRecord.active.is_(True),
                    func.lower(MonitoringIntegrationRecord.project_name).in_(candidates),
                )
            )
        ).scalars().all()
        if not integrations:
            return []
        integration_ids = [row.id for row in integrations]
        credentials = (
            await self.session.execute(
                select(MonitoringCredentialRecord).where(
                    MonitoringCredentialRecord.integration_id.in_(integration_ids)
                )
            )
        ).scalars().all()
        credential_by_integration = {row.integration_id: row for row in credentials}
        return [
            {
                "integration_id": str(row.id),
                "tenant_id": row.tenant_id,
                "project_id": row.project_name,
                "provider": row.provider,
                "status": row.status,
                "endpoint_identity": row.endpoint_url,
                "auth_type": row.auth_type,
                "secret_ref": (
                    credential_by_integration[row.id].secret_ref
                    if row.id in credential_by_integration else None
                ),
                "config": dict(row.config_payload or {}),
            }
            for row in integrations
        ]

    async def get_monitoring_integration(self, integration_id: Any) -> dict[str, Any] | None:
        parsed_id = self._parse_uuid(integration_id)
        if parsed_id is None:
            return None
        result = await self.session.execute(
            select(MonitoringIntegrationRecord).where(MonitoringIntegrationRecord.id == parsed_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return {
            "id": str(row.id),
            "tenant_id": row.tenant_id,
            "project_name": row.project_name,
            "provider": row.provider,
            "status": row.status,
            "active": row.active,
            "auth_type": row.auth_type,
            "endpoint_url": row.endpoint_url,
            "webhook_path": row.webhook_path,
            "deployment_mode": row.deployment_mode,
            "config_payload": row.config_payload,
            "validation_payload": row.validation_payload,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    async def delete_monitoring_integration(self, integration_id: Any) -> int:
        parsed_id = self._parse_uuid(integration_id)
        if parsed_id is None:
            return 0
        result = await self.session.execute(
            delete(MonitoringIntegrationRecord).where(MonitoringIntegrationRecord.id == parsed_id)
        )
        return int(result.rowcount or 0)

    async def save_monitoring_credential(
        self,
        *,
        credential_id: Any,
        integration_id: Any,
        credential_type: str,
        secret_ref: str,
        encrypted_payload: dict[str, Any],
        redacted_payload: dict[str, Any],
    ) -> None:
        cred_id = self._parse_uuid(credential_id)
        int_id = self._parse_uuid(integration_id)
        if cred_id is None or int_id is None:
            raise ValueError("monitoring_credential ids are required")
        await self.session.merge(
            MonitoringCredentialRecord(
                id=cred_id,
                integration_id=int_id,
                credential_type=self._require("monitoring_credential.credential_type", credential_type),
                secret_ref=self._require("monitoring_credential.secret_ref", secret_ref),
                encrypted_payload=encrypted_payload or {},
                redacted_payload=redacted_payload or {},
            )
        )

    async def save_monitoring_webhook_endpoint(
        self,
        *,
        endpoint_id: Any,
        integration_id: Any,
        provider: str,
        webhook_path: str,
        token_hash: str | None,
        hmac_enabled: bool,
        m_tls_enabled: bool,
        active: bool,
        metadata_payload: dict[str, Any],
    ) -> None:
        endpoint_uuid = self._parse_uuid(endpoint_id)
        integration_uuid = self._parse_uuid(integration_id)
        if endpoint_uuid is None or integration_uuid is None:
            raise ValueError("monitoring_webhook_endpoint ids are required")
        await self.session.merge(
            MonitoringWebhookEndpointRecord(
                id=endpoint_uuid,
                integration_id=integration_uuid,
                provider=self._require("monitoring_webhook_endpoint.provider", provider),
                webhook_path=self._require("monitoring_webhook_endpoint.webhook_path", webhook_path),
                token_hash=token_hash,
                hmac_enabled=bool(hmac_enabled),
                m_tls_enabled=bool(m_tls_enabled),
                active=bool(active),
                metadata_payload=metadata_payload or {},
            )
        )

    async def list_monitoring_webhook_endpoints(
        self,
        integration_id: Any,
        provider: str | None = None,
    ) -> list[dict[str, Any]]:
        integration_uuid = self._parse_uuid(integration_id)
        if integration_uuid is None:
            return []
        query = select(MonitoringWebhookEndpointRecord).where(
            MonitoringWebhookEndpointRecord.integration_id == integration_uuid,
            MonitoringWebhookEndpointRecord.active.is_(True),
        )
        if provider:
            query = query.where(MonitoringWebhookEndpointRecord.provider == str(provider).strip().lower())
        result = await self.session.execute(query.order_by(MonitoringWebhookEndpointRecord.created_at.desc()))
        return [
            {
                "id": str(row.id),
                "integration_id": str(row.integration_id),
                "provider": row.provider,
                "webhook_path": row.webhook_path,
                "token_hash": row.token_hash,
                "hmac_enabled": row.hmac_enabled,
                "m_tls_enabled": row.m_tls_enabled,
                "active": row.active,
                "metadata_payload": row.metadata_payload,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
            for row in result.scalars().all()
        ]

    async def replace_monitoring_alert_mappings(
        self,
        *,
        integration_id: Any,
        provider: str,
        mappings: list[dict[str, Any]],
    ) -> int:
        integration_uuid = self._parse_uuid(integration_id)
        if integration_uuid is None:
            return 0
        await self.session.execute(
            delete(MonitoringAlertMappingRecord).where(MonitoringAlertMappingRecord.integration_id == integration_uuid)
        )
        inserted = 0
        for item in mappings:
            provider_field = str(item.get("provider_field") or "").strip()
            kaiops_field = str(item.get("kaiops_field") or "").strip()
            if not provider_field or not kaiops_field:
                continue
            self.session.add(
                MonitoringAlertMappingRecord(
                    id=uuid4(),
                    integration_id=integration_uuid,
                    provider=str(provider or "").strip(),
                    provider_field=provider_field,
                    kaiops_field=kaiops_field,
                    transform=str(item.get("transform") or "").strip() or None,
                    required=bool(item.get("required", False)),
                    mapping_payload=item if isinstance(item, dict) else {},
                )
            )
            inserted += 1
        return inserted

    async def list_monitoring_alert_mappings(self, integration_id: Any) -> list[dict[str, Any]]:
        integration_uuid = self._parse_uuid(integration_id)
        if integration_uuid is None:
            return []
        result = await self.session.execute(
            select(MonitoringAlertMappingRecord)
            .where(MonitoringAlertMappingRecord.integration_id == integration_uuid)
            .order_by(MonitoringAlertMappingRecord.provider_field)
        )
        rows = result.scalars().all()
        return [
            {
                "id": str(row.id),
                "integration_id": str(row.integration_id),
                "provider": row.provider,
                "provider_field": row.provider_field,
                "kaiops_field": row.kaiops_field,
                "transform": row.transform,
                "required": row.required,
                "mapping_payload": row.mapping_payload,
                "updated_at": row.updated_at,
            }
            for row in rows
        ]

    async def save_monitoring_connection_health(
        self,
        *,
        health_id: Any,
        integration_id: Any,
        provider: str,
        status: str,
        connectivity_ok: bool,
        authentication_ok: bool,
        webhook_ok: bool,
        last_received_alert_at: datetime | None,
        last_successful_test_at: datetime | None,
        rate_limit_remaining: int | None,
        payload: dict[str, Any],
    ) -> None:
        health_uuid = self._parse_uuid(health_id)
        integration_uuid = self._parse_uuid(integration_id)
        if health_uuid is None or integration_uuid is None:
            raise ValueError("monitoring_connection_health ids are required")
        await self.session.merge(
            MonitoringConnectionHealthRecord(
                id=health_uuid,
                integration_id=integration_uuid,
                provider=self._require("monitoring_connection_health.provider", provider),
                status=self._require("monitoring_connection_health.status", status),
                connectivity_ok=bool(connectivity_ok),
                authentication_ok=bool(authentication_ok),
                webhook_ok=bool(webhook_ok),
                last_received_alert_at=last_received_alert_at,
                last_successful_test_at=last_successful_test_at,
                rate_limit_remaining=rate_limit_remaining,
                payload=payload or {},
            )
        )

    async def list_monitoring_connection_health(self, tenant_id: str = "default") -> list[dict[str, Any]]:
        integration_rows = await self.list_monitoring_integrations(tenant_id=tenant_id)
        integration_ids = [self._parse_uuid(row.get("id")) for row in integration_rows]
        integration_ids = [item for item in integration_ids if item is not None]
        if not integration_ids:
            return []
        result = await self.session.execute(
            select(MonitoringConnectionHealthRecord)
            .where(MonitoringConnectionHealthRecord.integration_id.in_(integration_ids))
            .order_by(MonitoringConnectionHealthRecord.updated_at.desc())
        )
        rows = result.scalars().all()
        return [
            {
                "id": str(row.id),
                "integration_id": str(row.integration_id),
                "provider": row.provider,
                "status": row.status,
                "connectivity_ok": row.connectivity_ok,
                "authentication_ok": row.authentication_ok,
                "webhook_ok": row.webhook_ok,
                "last_received_alert_at": row.last_received_alert_at,
                "last_successful_test_at": row.last_successful_test_at,
                "rate_limit_remaining": row.rate_limit_remaining,
                "payload": row.payload,
                "updated_at": row.updated_at,
            }
            for row in rows
        ]

    async def save_monitoring_received_alert(
        self,
        *,
        received_alert_id: Any,
        integration_id: Any | None,
        tenant_id: str,
        provider: str,
        provider_alert_id: str | None,
        dedupe_key: str | None,
        signature_valid: bool,
        auth_valid: bool,
        status: str,
        raw_payload: dict[str, Any],
    ) -> None:
        record_id = self._parse_uuid(received_alert_id)
        integration_uuid = self._parse_uuid(integration_id)
        if record_id is None:
            raise ValueError("monitoring_received_alert.id is required")
        await self.session.merge(
            MonitoringReceivedAlertRecord(
                id=record_id,
                integration_id=integration_uuid,
                tenant_id=str(tenant_id or "default"),
                provider=self._require("monitoring_received_alert.provider", provider),
                provider_alert_id=provider_alert_id,
                dedupe_key=dedupe_key,
                signature_valid=bool(signature_valid),
                auth_valid=bool(auth_valid),
                status=self._require("monitoring_received_alert.status", status),
                raw_payload=raw_payload or {},
            )
        )

    async def save_monitoring_normalized_alert(
        self,
        *,
        normalized_alert_id: Any,
        received_alert_id: Any,
        integration_id: Any | None,
        tenant_id: str,
        provider: str,
        application: str | None,
        environment: str | None,
        severity: str | None,
        alert_name: str,
        resource: str | None,
        labels: dict[str, Any],
        annotations: dict[str, Any],
        normalized_payload: dict[str, Any],
    ) -> None:
        normalized_id = self._parse_uuid(normalized_alert_id)
        received_id = self._parse_uuid(received_alert_id)
        integration_uuid = self._parse_uuid(integration_id)
        if normalized_id is None or received_id is None:
            raise ValueError("monitoring_normalized_alert ids are required")
        await self.session.merge(
            MonitoringNormalizedAlertRecord(
                id=normalized_id,
                received_alert_id=received_id,
                integration_id=integration_uuid,
                tenant_id=str(tenant_id or "default"),
                provider=self._require("monitoring_normalized_alert.provider", provider),
                application=application,
                environment=environment,
                severity=severity,
                alert_name=self._require("monitoring_normalized_alert.alert_name", alert_name),
                resource=resource,
                labels=labels or {},
                annotations=annotations or {},
                normalized_payload=normalized_payload or {},
            )
        )

    async def list_monitoring_received_alerts(self, tenant_id: str = "default", limit: int = 200) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 1000))
        result = await self.session.execute(
            select(MonitoringReceivedAlertRecord)
            .where(MonitoringReceivedAlertRecord.tenant_id == str(tenant_id or "default"))
            .order_by(MonitoringReceivedAlertRecord.created_at.desc())
            .limit(safe_limit)
        )
        rows = result.scalars().all()
        return [
            {
                "id": str(row.id),
                "integration_id": str(row.integration_id) if row.integration_id else None,
                "tenant_id": row.tenant_id,
                "provider": row.provider,
                "provider_alert_id": row.provider_alert_id,
                "dedupe_key": row.dedupe_key,
                "signature_valid": row.signature_valid,
                "auth_valid": row.auth_valid,
                "status": row.status,
                "raw_payload": row.raw_payload,
                "created_at": row.created_at,
            }
            for row in rows
        ]

    async def save_monitoring_connection_audit(
        self,
        *,
        audit_id: Any,
        integration_id: Any | None,
        tenant_id: str,
        actor: str,
        action: str,
        provider: str | None,
        outcome: str,
        message: str | None,
        payload: dict[str, Any],
    ) -> None:
        record_id = self._parse_uuid(audit_id)
        integration_uuid = self._parse_uuid(integration_id)
        if record_id is None:
            raise ValueError("monitoring_connection_audit.id is required")
        await self.session.merge(
            MonitoringConnectionAuditRecord(
                id=record_id,
                integration_id=integration_uuid,
                tenant_id=str(tenant_id or "default"),
                actor=self._require("monitoring_connection_audit.actor", actor),
                action=self._require("monitoring_connection_audit.action", action),
                provider=provider,
                outcome=self._require("monitoring_connection_audit.outcome", outcome),
                message=message,
                payload=payload or {},
            )
        )

    async def list_monitoring_connection_audit(self, tenant_id: str = "default", limit: int = 200) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 2000))
        result = await self.session.execute(
            select(MonitoringConnectionAuditRecord)
            .where(MonitoringConnectionAuditRecord.tenant_id == str(tenant_id or "default"))
            .order_by(MonitoringConnectionAuditRecord.created_at.desc())
            .limit(safe_limit)
        )
        rows = result.scalars().all()
        return [
            {
                "id": str(row.id),
                "integration_id": str(row.integration_id) if row.integration_id else None,
                "tenant_id": row.tenant_id,
                "actor": row.actor,
                "action": row.action,
                "provider": row.provider,
                "outcome": row.outcome,
                "message": row.message,
                "payload": row.payload,
                "created_at": row.created_at,
            }
            for row in rows
        ]

    async def list_applications(self) -> list[dict[str, Any]]:
        result = await self.session.execute(select(ApplicationRecord).order_by(ApplicationRecord.updated_at.desc()))
        rows = result.scalars().all()
        return [
            {
                "id": str(row.id),
                "tenant_id": row.tenant_id,
                "name": row.name,
                "owner_team": row.owner_team,
                "owner_email": row.owner_email,
                "environment": row.environment,
                "namespace": row.namespace,
                "region": row.region,
                "technology": row.technology,
                "monitoring_platform": row.monitoring_platform,
                "metrics_endpoint": row.metrics_endpoint,
                "status": row.status,
                "payload": row.payload,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
            for row in rows
        ]

    async def get_application(self, application_id: Any) -> dict[str, Any] | None:
        record = await self.session.get(ApplicationRecord, application_id)
        if record is None:
            return None
        return {
            "id": str(record.id),
            "tenant_id": record.tenant_id,
            "name": record.name,
            "owner_team": record.owner_team,
            "owner_email": record.owner_email,
            "environment": record.environment,
            "namespace": record.namespace,
            "region": record.region,
            "technology": record.technology,
            "monitoring_platform": record.monitoring_platform,
            "metrics_endpoint": record.metrics_endpoint,
            "status": record.status,
            "payload": record.payload,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }

    async def delete_application(self, application_id: Any) -> int:
        await self.session.execute(delete(ApplicationEnvironmentRecord).where(ApplicationEnvironmentRecord.application_id == application_id))
        await self.session.execute(delete(ApplicationLabelRecord).where(ApplicationLabelRecord.application_id == application_id))
        result = await self.session.execute(delete(ApplicationRecord).where(ApplicationRecord.id == application_id))
        return int(result.rowcount or 0)

    async def save_monitoring_profile(self, result: MetricsValidationResult, governance_status: str | None = None) -> None:
        await self.session.merge(
            MonitoringProfileRecord(
                application_id=result.application_id,
                tenant_id=result.tenant_id,
                platform="prometheus",
                exporter=result.exporter,
                technology=result.technology,
                metrics_available=result.metrics_available,
                governance_status=governance_status,
                payload=result.model_dump(mode="json"),
            )
        )

    async def replace_rules(self, result: RulesGeneratedResult) -> None:
        await self.session.execute(delete(AlertRuleRecord).where(AlertRuleRecord.application_id == result.application_id))
        await self.session.execute(delete(RecordingRuleRecord).where(RecordingRuleRecord.application_id == result.application_id))
        for rule in result.alert_rules:
            self.session.add(
                AlertRuleRecord(
                    application_id=result.application_id,
                    tenant_id=result.tenant_id,
                    name=rule.name,
                    expression=rule.expr,
                    duration=rule.duration,
                    severity=rule.severity,
                    labels=rule.labels,
                    annotations=rule.annotations,
                    payload=rule.model_dump(mode="json"),
                )
            )
        for rule in result.recording_rules:
            self.session.add(
                RecordingRuleRecord(
                    application_id=result.application_id,
                    tenant_id=result.tenant_id,
                    name=rule.name,
                    expression=rule.expr,
                    labels=rule.labels,
                    payload=rule.model_dump(mode="json"),
                )
            )

    async def save_prometheus_update(self, result: PrometheusUpdateResult) -> None:
        for config_type, file_path in result.files.items():
            content = ""
            provider_response = result.provider_response if isinstance(result.provider_response, dict) else {}
            if config_type in provider_response and isinstance(provider_response.get(config_type), str):
                content = str(provider_response.get(config_type) or "")
            self.session.add(
                PrometheusConfigRecord(
                    application_id=result.application_id,
                    tenant_id=result.tenant_id,
                    config_type=config_type,
                    version=1,
                    file_path=file_path,
                    content=content,
                    payload=result.model_dump(mode="json"),
                )
            )

    async def save_validation_result(self, result: MonitoringValidationResult) -> None:
        self.session.add(
            ValidationHistoryRecord(
                application_id=result.application_id,
                tenant_id=result.tenant_id,
                target_up=result.target_up,
                metrics_available=result.metrics_available,
                alerts_loaded=result.alerts_loaded,
                recording_rules_loaded=result.recording_rules_loaded,
                service_discovery_ok=result.service_discovery_ok,
                dashboard_ready=result.dashboard_ready,
                payload=result.model_dump(mode="json"),
            )
        )

    async def save_dashboard_result(self, result: GrafanaDashboardResult) -> None:
        await self.session.merge(
            GrafanaDashboardRecord(
                application_id=result.application_id,
                tenant_id=result.tenant_id,
                dashboard_uid=result.dashboard_uid,
                title=result.title,
                url=result.url,
                payload=result.model_dump(mode="json"),
            )
        )

    async def save_monitoring_audit(self, audit_event: MonitoringAuditEvent) -> None:
        self.session.add(
            OnboardingHistoryRecord(
                application_id=audit_event.application_id,
                tenant_id=audit_event.tenant_id,
                event_type=audit_event.event_type,
                status=audit_event.decision,
                actor=audit_event.actor,
                agent=audit_event.agent,
                decision=audit_event.decision,
                execution_time_ms=audit_event.execution_time_ms,
                payload=audit_event.model_dump(mode="json"),
            )
        )
        self.session.add(
            AuditLogRecord(
                tenant_id=audit_event.tenant_id or "default",
                actor=audit_event.actor,
                action=audit_event.event_type,
                resource_type="application",
                resource_id=str(audit_event.application_id),
                payload=audit_event.model_dump(mode="json"),
            )
        )

    async def list_application_history(self, application_id: Any) -> list[dict[str, Any]]:
        result = await self.session.execute(
            select(OnboardingHistoryRecord)
            .where(OnboardingHistoryRecord.application_id == application_id)
            .order_by(OnboardingHistoryRecord.created_at.desc())
        )
        rows = result.scalars().all()
        return [
            {
                "id": str(row.id),
                "application_id": str(row.application_id),
                "tenant_id": row.tenant_id,
                "event_type": row.event_type,
                "status": row.status,
                "actor": row.actor,
                "agent": row.agent,
                "decision": row.decision,
                "execution_time_ms": row.execution_time_ms,
                "payload": row.payload,
                "created_at": row.created_at,
            }
            for row in rows
        ]

    async def list_application_dashboards(self, application_id: Any) -> list[dict[str, Any]]:
        result = await self.session.execute(
            select(GrafanaDashboardRecord)
            .where(GrafanaDashboardRecord.application_id == application_id)
            .order_by(GrafanaDashboardRecord.updated_at.desc())
        )
        rows = result.scalars().all()
        return [
            {
                "id": str(row.id),
                "application_id": str(row.application_id),
                "dashboard_uid": row.dashboard_uid,
                "title": row.title,
                "url": row.url,
                "payload": row.payload,
                "updated_at": row.updated_at,
            }
            for row in rows
        ]

    async def list_application_validations(self, application_id: Any) -> list[dict[str, Any]]:
        result = await self.session.execute(
            select(ValidationHistoryRecord)
            .where(ValidationHistoryRecord.application_id == application_id)
            .order_by(ValidationHistoryRecord.created_at.desc())
        )
        rows = result.scalars().all()
        return [
            {
                "id": str(row.id),
                "application_id": str(row.application_id),
                "tenant_id": row.tenant_id,
                "target_up": row.target_up,
                "metrics_available": row.metrics_available,
                "alerts_loaded": row.alerts_loaded,
                "recording_rules_loaded": row.recording_rules_loaded,
                "service_discovery_ok": row.service_discovery_ok,
                "dashboard_ready": row.dashboard_ready,
                "payload": row.payload,
                "created_at": row.created_at,
            }
            for row in rows
        ]

    async def save_onboarding_state(
        self,
        *,
        tenant_id: str = "default",
        project_name: str,
        provider_name: str,
        project_payload: dict[str, Any],
        connectivity_payload: dict[str, Any],
        owner_team: str | None = None,
        environment: str | None = None,
        region: str | None = None,
        endpoint_url: str | None = None,
        test_status: str | None = None,
        test_message: str | None = None,
        last_tested_at: datetime | None = None,
    ) -> None:
        await self.session.merge(
            OnboardingStateRecord(
                tenant_id=self._require("onboarding.tenant_id", tenant_id),
                project_name=self._require("onboarding.project_name", project_name),
                provider_name=self._require("onboarding.provider_name", provider_name),
                owner_team=owner_team,
                environment=environment,
                region=region,
                endpoint_url=endpoint_url,
                test_status=test_status,
                test_message=test_message,
                project_payload=self._require("onboarding.project_payload", project_payload),
                connectivity_payload=self._require("onboarding.connectivity_payload", connectivity_payload),
                last_tested_at=last_tested_at,
            )
        )

        scoped_environment = str(environment or project_payload.get("environment") or "").strip()
        if scoped_environment:
            from common.diagnostic_runbooks import ensure_diagnostic_runbook
            await ensure_diagnostic_runbook(self.session, tenant_id=tenant_id,
                application=project_name, service=project_name, environment=scoped_environment,
                owner=owner_team or "unassigned")

    async def list_onboarding_state(self, tenant_id: str = "default") -> list[dict[str, Any]]:
        result = await self.session.execute(
            select(
                OnboardingStateRecord.tenant_id,
                OnboardingStateRecord.project_name,
                OnboardingStateRecord.provider_name,
                OnboardingStateRecord.owner_team,
                OnboardingStateRecord.environment,
                OnboardingStateRecord.region,
                OnboardingStateRecord.endpoint_url,
                OnboardingStateRecord.test_status,
                OnboardingStateRecord.test_message,
                OnboardingStateRecord.project_payload,
                OnboardingStateRecord.connectivity_payload,
                OnboardingStateRecord.updated_at,
                OnboardingStateRecord.last_tested_at,
            )
            .where(OnboardingStateRecord.tenant_id == self._require("onboarding.tenant_id", tenant_id))
            .order_by(OnboardingStateRecord.project_name, OnboardingStateRecord.provider_name)
        )
        rows = result.all()
        return [
            {
                "tenant_id": row.tenant_id,
                "project_name": row.project_name,
                "provider_name": row.provider_name,
                "owner_team": row.owner_team,
                "environment": row.environment,
                "region": row.region,
                "endpoint_url": row.endpoint_url,
                "test_status": row.test_status,
                "test_message": row.test_message,
                "project_payload": row.project_payload,
                "connectivity_payload": row.connectivity_payload,
                "updated_at": row.updated_at,
                "last_tested_at": row.last_tested_at,
            }
            for row in rows
        ]

    async def save_onboarding_control_plane(self, payload: dict[str, Any]) -> None:
        onboarding_id = UUID(str(payload["onboarding_id"]))
        existing = await self.session.get(OnboardingControlPlaneRecord, onboarding_id)
        if existing is None:
            self.session.add(OnboardingControlPlaneRecord(
                onboarding_id=onboarding_id,
                tenant_id=self._require("onboarding.tenant_id", payload.get("tenant_id")),
                project_name=self._require("onboarding.project_name", payload.get("project", {}).get("name")),
                current_step=int(payload.get("current_step") or 1),
                status=str(payload.get("status") or "DRAFT"),
                version=int(payload.get("version") or 1),
                payload=payload,
            ))
            return
        existing.project_name = self._require("onboarding.project_name", payload.get("project", {}).get("name"))
        existing.current_step = int(payload.get("current_step") or 1)
        existing.status = str(payload.get("status") or "DRAFT")
        existing.version = int(payload.get("version") or 1)
        existing.payload = payload

    async def get_onboarding_control_plane(self, onboarding_id: UUID, tenant_id: str) -> dict[str, Any] | None:
        result = await self.session.execute(select(OnboardingControlPlaneRecord).where(
            OnboardingControlPlaneRecord.onboarding_id == onboarding_id,
            OnboardingControlPlaneRecord.tenant_id == require_tenant_id(tenant_id, source="onboarding lookup"),
        ))
        row = result.scalar_one_or_none()
        return dict(row.payload) if row else None

    async def get_onboarding_state_row(self, project_name: str, provider_name: str) -> dict[str, Any] | None:
        normalized_project = str(project_name or "").strip()
        normalized_provider = str(provider_name or "").strip().lower()
        if not normalized_project or not normalized_provider:
            return None
        result = await self.session.execute(
            select(OnboardingStateRecord).where(
                func.lower(func.trim(OnboardingStateRecord.project_name)) == normalized_project.lower(),
                func.lower(func.trim(OnboardingStateRecord.provider_name)) == normalized_provider,
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return {
            "project_name": row.project_name,
            "provider_name": row.provider_name,
            "owner_team": row.owner_team,
            "environment": row.environment,
            "region": row.region,
            "endpoint_url": row.endpoint_url,
            "test_status": row.test_status,
            "test_message": row.test_message,
            "project_payload": row.project_payload,
            "connectivity_payload": row.connectivity_payload,
            "updated_at": row.updated_at,
            "last_tested_at": row.last_tested_at,
        }

    async def delete_onboarding_state(self, project_name: str, provider_name: str | None = None) -> int:
        normalized_project = str(project_name or "").strip()
        if not normalized_project:
            return 0
        statement = delete(OnboardingStateRecord).where(
            func.lower(func.trim(OnboardingStateRecord.project_name)) == normalized_project.lower()
        )
        normalized_provider = str(provider_name or "").strip().lower()
        if normalized_provider:
            statement = statement.where(func.lower(func.trim(OnboardingStateRecord.provider_name)) == normalized_provider)
        result = await self.session.execute(statement)
        return int(result.rowcount or 0)

    async def save_agent_work_item(
        self,
        *,
        incident_id: Any,
        agent_name: str,
        work_item: str,
        status: str,
        sequence: int | None = None,
        trace_id: str | None = None,
        ticket_id: str | None = None,
        details: dict[str, Any] | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> None:
        self.session.add(
            AgentWorkItemRecord(
                incident_id=self._require("agent_work.incident_id", incident_id),
                agent_name=self._require("agent_work.agent_name", agent_name),
                trace_id=trace_id,
                ticket_id=ticket_id,
                work_item=self._require("agent_work.work_item", work_item),
                status=self._require("agent_work.status", status),
                sequence=sequence,
                details=details or {},
                started_at=started_at,
                completed_at=completed_at,
            )
        )

    async def save_pending_workflow(
        self,
        *,
        incident_id: Any,
        recommendation_id: Any,
        flow_id: str,
        trace_id: str | None,
        payload: dict[str, Any],
    ) -> None:
        incident_uuid = self._parse_uuid(incident_id)
        if incident_uuid is None:
            raise ValueError("pending_workflow.incident_id is required")
        recommendation_uuid = self._parse_uuid(recommendation_id)
        if recommendation_uuid is None:
            raise ValueError("pending_workflow.recommendation_id is required")

        result = await self.session.execute(
            select(PendingWorkflowRecord).where(PendingWorkflowRecord.incident_id == incident_uuid)
        )
        record = result.scalar_one_or_none()
        if record is None:
            record = PendingWorkflowRecord(
                incident_id=incident_uuid,
                recommendation_id=recommendation_uuid,
                flow_id=self._require("pending_workflow.flow_id", flow_id),
                trace_id=trace_id,
                status="pending",
                payload=payload,
                completed_payload=None,
                completed_at=None,
            )
            self.session.add(record)
            return

        record.recommendation_id = recommendation_uuid
        record.flow_id = self._require("pending_workflow.flow_id", flow_id)
        record.trace_id = trace_id
        record.status = "pending"
        record.payload = payload
        record.completed_payload = None
        record.completed_at = None
        await self.session.merge(record)

    async def get_pending_workflow(self, incident_id: Any) -> dict[str, Any] | None:
        incident_uuid = self._parse_uuid(incident_id)
        if incident_uuid is None:
            return None
        result = await self.session.execute(
            select(PendingWorkflowRecord).where(PendingWorkflowRecord.incident_id == incident_uuid)
        )
        record = result.scalar_one_or_none()
        if record is None:
            return None
        return {
            "incident_id": str(record.incident_id),
            "recommendation_id": str(record.recommendation_id),
            "flow_id": record.flow_id,
            "trace_id": record.trace_id,
            "status": record.status,
            "payload": record.payload if isinstance(record.payload, dict) else {},
            "completed_payload": record.completed_payload if isinstance(record.completed_payload, dict) else None,
            "completed_at": record.completed_at,
        }

    async def mark_pending_workflow_completed(self, incident_id: Any, completed_payload: dict[str, Any]) -> None:
        incident_uuid = self._parse_uuid(incident_id)
        if incident_uuid is None:
            return
        result = await self.session.execute(
            select(PendingWorkflowRecord).where(PendingWorkflowRecord.incident_id == incident_uuid)
        )
        record = result.scalar_one_or_none()
        if record is None:
            return
        record.status = "completed"
        record.completed_payload = completed_payload
        record.completed_at = datetime.utcnow()
        await self.session.merge(record)

    async def clear_pending_workflow(self, incident_id: Any) -> None:
        incident_uuid = self._parse_uuid(incident_id)
        if incident_uuid is None:
            return
        result = await self.session.execute(
            select(PendingWorkflowRecord).where(PendingWorkflowRecord.incident_id == incident_uuid)
        )
        record = result.scalar_one_or_none()
        if record is not None:
            await self.session.delete(record)

    async def list_agent_work_items(self, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 500))
        result = await self.session.execute(
            select(AgentWorkItemRecord)
            .order_by(AgentWorkItemRecord.updated_at.desc(), AgentWorkItemRecord.sequence.asc())
            .limit(safe_limit)
        )
        rows = result.scalars().all()
        return [
            {
                "incident_id": str(row.incident_id),
                "agent_name": row.agent_name,
                "trace_id": row.trace_id,
                "ticket_id": row.ticket_id,
                "work_item": row.work_item,
                "status": row.status,
                "sequence": row.sequence,
                "details": row.details,
                "started_at": row.started_at,
                "completed_at": row.completed_at,
                "updated_at": row.updated_at,
            }
            for row in rows
        ]

    @staticmethod
    def _parse_uuid(value: Any) -> UUID | None:
        token = str(value or "").strip()
        if not token:
            return None
        try:
            return UUID(token)
        except ValueError:
            return None

    @staticmethod
    def _parse_datetime(value: Any) -> datetime | None:
        token = str(value or "").strip()
        if not token:
            return None
        try:
            return datetime.fromisoformat(token.replace("Z", "+00:00"))
        except ValueError:
            return None

    async def _upsert_projection_from_record(self, event_record: IncidentEventRecord) -> None:
        if event_record.event_type == "incident.recommendation.generated":
            candidate = self._parse_uuid((event_record.payload or {}).get("recommendation_id"))
            protected = await self.governed_recovery_recommendation_id(
                tenant_id=event_record.tenant_id, incident_id=event_record.incident_id,
            )
            if protected and candidate != protected:
                request_id = self._parse_uuid((event_record.payload or {}).get("analysis_request_id"))
                explicit = await self.session.get(AnalysisRequestRecord, request_id) if request_id else None
                owned_action = await self.session.scalar(select(ActionRecord.id).where(
                    ActionRecord.tenant_id == event_record.tenant_id,
                    ActionRecord.incident_id == event_record.incident_id,
                    ActionRecord.recommendation_id == protected,
                ).limit(1))
                if explicit is None or owned_action is not None:
                    # Retain the candidate event/audit for investigation history;
                    # physical execution and recovery keep their reviewed binding.
                    return
        result = await self.session.execute(
            select(IncidentProjectionRecord).where(IncidentProjectionRecord.incident_id == event_record.incident_id)
        )
        projection = result.scalar_one_or_none()
        if projection is None:
            projection = IncidentProjectionRecord(
                incident_id=event_record.incident_id,
                first_seen_at=event_record.created_at,
                projection_payload={},
                service=event_record.service,
                environment=event_record.environment,
                status=event_record.status or "open",
            )

        # document_available is not part of the status lifecycle, so it must not be
        # dropped by the regression guard below when events share a timestamp.
        document_available = _extract_document_available(event_record.payload)
        if document_available is not None:
            projection.document_available = document_available

        incoming_status_token = str(event_record.status or "").strip().lower()
        existing_status_token = str(projection.status or "").strip().lower()
        if (
            existing_status_token in _CLOSED_INCIDENT_STATUSES
            and incoming_status_token not in _CLOSED_INCIDENT_STATUSES
            and event_record.event_type != "incident.reopened"
        ):
            # Event delivery is at-least-once and cross-service timestamps can
            # be tied at database precision. A late remediation/alert event is
            # not an authorized reopen operation, so terminal state wins.
            await self.session.merge(projection)
            return

        # Do not regress projection lifecycle when two events share the same timestamp.
        # In local/demo runs, recommendation and closed can be written within the same second.
        existing_latest = _utc_dt(projection.latest_event_at)
        incoming_latest = _utc_dt(event_record.created_at)
        if existing_latest is not None and incoming_latest is not None:
            if incoming_latest < existing_latest:
                await self.session.merge(projection)
                return
            if incoming_latest == existing_latest:
                existing_rank = _status_rank(projection.status)
                incoming_rank = _status_rank(event_record.status)
                if incoming_rank < existing_rank:
                    await self.session.merge(projection)
                    return

        recommendation_uuid = _extract_recommendation_uuid(event_record.payload)
        flow_id = _extract_flow_id(event_record.payload)
        preserves_bound_generation = bool(
            event_record.event_type == "incident.alert.enriched"
            and projection.recommendation_id is not None
            and recommendation_uuid is None
            and event_record.alert_id is not None
            and projection.alert_id is not None
            and event_record.alert_id != projection.alert_id
        )
        if event_record.alert_id is not None and not preserves_bound_generation:
            projection.alert_id = event_record.alert_id
        projection.trace_id = event_record.trace_id
        if recommendation_uuid is not None:
            can_replace_recommendation = True
            if (
                event_record.event_type == "incident.recommendation.generated"
                and projection.recommendation_id is not None
                and projection.recommendation_id != recommendation_uuid
            ):
                current_binding = await self.session.get(
                    IncidentInvestigationBindingRecord, projection.recommendation_id
                )
                incoming_binding = await self.session.get(
                    IncidentInvestigationBindingRecord, recommendation_uuid
                )
                if (
                    current_binding is not None
                    and incoming_binding is not None
                    and int(incoming_binding.rca_version or 0) < int(current_binding.rca_version or 0)
                ):
                    can_replace_recommendation = False
            if can_replace_recommendation:
                projection.recommendation_id = recommendation_uuid
        if flow_id:
            projection.flow_id = flow_id
        projection.tenant_id = event_record.tenant_id or "default"
        projection.service = event_record.service
        projection.environment = event_record.environment
        projection.severity = event_record.severity
        incoming_status = (
            projection.status
            if preserves_bound_generation
            else event_record.status or projection.status or "open"
        )
        if event_record.event_type == "incident.recommendation.generated" and str(incoming_status).lower() == "remediating":
            # A recommendation establishes readiness, never proof that an
            # executor started. This also protects projection rebuild/replay
            # from restoring the legacy false-remediating state.
            incoming_status = "awaiting_approval" if event_record.requires_approval else "approved"
        projection.status = incoming_status
        lifecycle_by_event = {
            "incident.detected": "DETECTED",
            "incident.context.enriching": "REQUIREMENTS_IDENTIFIED",
            "context.requirements.generated": "REQUIREMENTS_IDENTIFIED",
            "incident.context.collecting": "COLLECTING",
            "incident.context.enriched": "CONTEXT_READY",
            "context.ready": "CONTEXT_READY",
            "incident.investigating": "INVESTIGATING",
            "incident.recommendation.generated": (
                "WAITING_FOR_HUMAN"
                if str(incoming_status).lower() == "waiting_for_human"
                else "INVESTIGATING"
                if str(incoming_status).lower() == "investigating"
                else "AWAITING_APPROVAL"
                if str(incoming_status).lower() in {"awaiting_approval", "pending_approval"}
                else "PLAN_READY"
                if str(incoming_status).lower() in {"rca_ready", "approved", "plan_ready"}
                else ("AWAITING_APPROVAL" if event_record.requires_approval else "PLAN_READY")
            ),
            "incident.action.approved": "PLAN_READY",
            "incident.remediating": "EXECUTING",
            "action.started": "EXECUTING",
            "incident.validating": "VALIDATING",
            "incident.resolved": "CLOSED",
            "incident.closed": "CLOSED",
            "incident.closure.completed": (
                "VALIDATING"
                if str(incoming_status).lower() == "validating"
                else "VALIDATION_FAILED"
                if str(incoming_status).lower() == "failed"
                else "CLOSED"
            ),
            "incident.closure.recorded": "CLOSED",
            "incident.waiting_for_human": "WAITING_FOR_HUMAN",
            "context.human_requested": "WAITING_FOR_HUMAN",
            "context.human_enriched": "INVESTIGATING",
            "incident.human_enriched": "INVESTIGATING",
        }
        mapped_lifecycle = lifecycle_by_event.get(event_record.event_type)
        if mapped_lifecycle:
            projection.lifecycle_state = mapped_lifecycle
        if not preserves_bound_generation:
            projection.risk_tier = event_record.risk_tier
            projection.execution_mode = event_record.execution_mode
            projection.requires_approval = event_record.requires_approval
            projection.policy_version = event_record.policy_version
            projection.policy_reason = event_record.policy_reason
        projection.transport_provider = event_record.transport_provider
        projection.latest_event_id = event_record.id
        projection.latest_event_type = event_record.event_type
        projection.latest_event_at = event_record.created_at
        next_projection_payload = {
            "event_stage": event_record.event_stage,
            "event_type": event_record.event_type,
            "transport_channel": event_record.transport_channel,
            "event_payload": event_record.payload,
        }
        if preserves_bound_generation:
            next_projection_payload = dict(projection.projection_payload or {})
            next_projection_payload["latest_occurrence"] = {
                "alert_id": str(event_record.alert_id),
                "event_id": str(event_record.id),
                "event_type": event_record.event_type,
                "event_payload": event_record.payload,
                "observed_at": event_record.created_at.isoformat(),
            }
        projection.projection_payload = next_projection_payload
        await self.session.merge(projection)
        if projection.status and str(projection.status).strip().lower() not in {"open", "detected"}:
            own_rows = (await self.session.execute(
                select(IncidentCorrelationOwnershipRecord).where(
                    IncidentCorrelationOwnershipRecord.tenant_id == projection.tenant_id,
                    IncidentCorrelationOwnershipRecord.canonical_incident_id == projection.incident_id,
                )
            )).scalars().all()
            for own_row in own_rows:
                if str(own_row.lifecycle_state or "").strip().lower() not in _CLOSED_INCIDENT_STATUSES:
                    own_row.lifecycle_state = str(projection.status).strip().lower()

    async def save_incident_event(self, envelope: dict[str, Any]) -> None:
        identity = envelope.get("identity", {}) if isinstance(envelope.get("identity"), dict) else {}
        scope = envelope.get("scope", {}) if isinstance(envelope.get("scope"), dict) else {}
        state = envelope.get("state", {}) if isinstance(envelope.get("state"), dict) else {}
        policy = envelope.get("policy", {}) if isinstance(envelope.get("policy"), dict) else {}
        ai = envelope.get("ai", {}) if isinstance(envelope.get("ai"), dict) else {}
        transport = envelope.get("transport", {}) if isinstance(envelope.get("transport"), dict) else {}
        idempotency = envelope.get("idempotency", {}) if isinstance(envelope.get("idempotency"), dict) else {}

        incident_uuid = self._parse_uuid(identity.get("incident_id"))
        if incident_uuid is None:
            raise ValueError("identity.incident_id is required")

        record = IncidentEventRecord(
            id=self._parse_uuid(envelope.get("event_id")) or uuid4(),
            incident_id=incident_uuid,
            alert_id=self._parse_uuid(identity.get("alert_id")),
            trace_id=str(identity.get("trace_id") or "").strip() or None,
            correlation_id=str(identity.get("correlation_id") or "").strip() or None,
            causation_id=str(identity.get("causation_id") or "").strip() or None,
            parent_event_id=self._parse_uuid(identity.get("parent_event_id")),
            tenant_id=str(scope.get("tenant_id") or "default").strip() or "default",
            service=str(scope.get("service") or "unknown").strip() or "unknown",
            environment=str(scope.get("environment") or "prod").strip() or "prod",
            region=str(scope.get("region") or "").strip() or None,
            team=str(scope.get("team") or "").strip() or None,
            severity=str(state.get("severity") or "").strip() or None,
            status=str(state.get("status") or "").strip() or None,
            event_type=str(envelope.get("event_type") or "incident.event").strip(),
            event_stage=str(state.get("status") or "unknown").strip() or "unknown",
            risk_tier=str(policy.get("risk_tier") or "").strip() or None,
            execution_mode=str(policy.get("execution_mode") or "").strip() or None,
            requires_approval=bool(policy.get("requires_approval")) if "requires_approval" in policy else None,
            policy_version=str(policy.get("policy_version") or "").strip() or None,
            policy_reason=str(policy.get("policy_reason") or "").strip() or None,
            confidence=float(ai.get("confidence")) if ai.get("confidence") is not None else None,
            model_provider=str(ai.get("model_provider") or "").strip() or None,
            model_name=str(ai.get("model_name") or "").strip() or None,
            transport_provider=str(transport.get("provider") or "unknown").strip() or "unknown",
            transport_channel=str(transport.get("channel") or "unknown").strip() or "unknown",
            transport_partition=int(transport.get("partition")) if transport.get("partition") is not None else None,
            transport_offset=int(transport.get("offset")) if transport.get("offset") is not None else None,
            transport_delivery_tag=str(transport.get("delivery_tag") or "").strip() or None,
            idempotency_key=str(idempotency.get("idempotency_key") or "").strip() or None,
            fingerprint=str(idempotency.get("fingerprint") or "").strip() or None,
            payload=envelope.get("payload") if isinstance(envelope.get("payload"), dict) else {},
            created_at=self._parse_datetime(envelope.get("produced_at")) or datetime.utcnow(),
        )
        # event_id is rarely supplied idempotently by producers, so merge()'s
        # upsert-by-primary-key does not protect against a redelivered or
        # concurrently retried event: two different random ids for the same
        # logical event both attempt an insert, and the second only fails at
        # the (transport_provider, idempotency_key) unique constraint -- not
        # at merge()'s own existence check, since that checks the primary key.
        # A savepoint isolates that failure (and the autoflush it can trigger
        # via merge()'s internal SELECT) from the caller's outer transaction,
        # so a duplicate is coalesced instead of surfacing as a request
        # failure the caller has to interpret and retry by hand.
        try:
            async with self.session.begin_nested():
                await self.session.merge(record)
                await self.session.flush()
        except IntegrityError:
            return
        await self._upsert_projection_from_record(record)

    async def project_recent_incident_events(self, limit: int = 500) -> int:
        safe_limit = max(1, min(int(limit), 5000))
        result = await self.session.execute(
            select(IncidentEventRecord.id, IncidentEventRecord.incident_id, IncidentEventRecord.created_at)
            .order_by(IncidentEventRecord.created_at.desc(), IncidentEventRecord.id.desc())
            .limit(safe_limit)
        )
        identities = list(result.all())
        # This worker is a repair path, not a second lifecycle consumer. Replaying
        # historical events into an existing projection can undo a newer status
        # written by remediation/closure (especially for legacy events with tied
        # timestamps). Only reconstruct projections that are actually missing.
        incident_ids = {row.incident_id for row in identities}
        existing_ids: set[UUID] = set()
        if incident_ids:
            existing_result = await self.session.execute(
                select(IncidentProjectionRecord.incident_id).where(
                    IncidentProjectionRecord.incident_id.in_(incident_ids)
                )
            )
            existing_ids = set(existing_result.scalars().all())
        rebuilt_ids = incident_ids - existing_ids
        # Existing projections need no event JSON. Sort narrow identities first,
        # then fetch payloads only for incidents that actually require repair.
        repair_event_ids = [row.id for row in identities if row.incident_id in rebuilt_ids]
        rows = list((await self.session.scalars(select(IncidentEventRecord).where(
            IncidentEventRecord.id.in_(repair_event_ids),
        ))).all()) if repair_event_ids else []
        rows.sort(key=lambda row: row.created_at)
        for row in rows:
            if row.incident_id in rebuilt_ids:
                await self._upsert_projection_from_record(row)
        # Legacy batches may contain a recommendation marked remediating and a
        # policy-blocked action event with the same timestamp. Normalize after
        # the whole ordered replay so tie-breaking cannot leave a projection
        # claiming execution without an active executor action.
        await self.session.execute(
            text(
                "UPDATE incident_projections p SET "
                "p.status=CASE "
                "WHEN EXISTS (SELECT 1 FROM actions a WHERE a.incident_id=p.incident_id "
                "AND a.status IN ('awaiting_approval','policy_blocked')) THEN 'awaiting_approval' "
                "WHEN COALESCE(p.requires_approval,0)=1 THEN 'awaiting_approval' ELSE 'approved' END, "
                "p.projection_payload=JSON_SET(COALESCE(p.projection_payload, JSON_OBJECT()), '$.status', "
                "CASE WHEN EXISTS (SELECT 1 FROM actions a WHERE a.incident_id=p.incident_id "
                "AND a.status IN ('awaiting_approval','policy_blocked')) THEN 'awaiting_approval' "
                "WHEN COALESCE(p.requires_approval,0)=1 THEN 'awaiting_approval' ELSE 'approved' END) "
                "WHERE p.status='remediating' "
                "AND NOT EXISTS (SELECT 1 FROM actions active WHERE active.incident_id=p.incident_id "
                "AND active.status IN ('pending','dispatching','executor_accepted','running','verifying','rolling_back'))"
            )
        )

        return len(rebuilt_ids)

    @staticmethod
    def _incident_group_cursor(
        row: IncidentCorrelationOwnershipRecord,
        direction: str,
        filter_fingerprint: str,
    ) -> str:
        payload = json.dumps(
            {
                "at": row.first_seen_at.isoformat(),
                "id": str(row.id),
                "direction": direction,
                "filter": filter_fingerprint,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

    async def list_unified_inbox(
        self,
        *,
        tenant_id: str,
        limit: int = 25,
        cursor: str | None = None,
        project_id: str | None = None,
        risk_tier: str | None = None,
        execution_mode: str | None = None,
        transport_provider: str | None = None,
        status: str | None = None,
        service: str | None = None,
        inbox_view: str = "all",
        record_type: str = "incidents",
        severity: str | None = None,
    ) -> dict[str, Any]:
        """Return a snapshot-consistent, database-filtered incident and alert feed."""
        tenant_id = self._require("tenant_id", tenant_id)
        safe_limit = max(1, min(int(limit), 100))
        raw_project_id = str(project_id or "").strip().lower()
        if raw_project_id in {"all", "all applications", "all-applications", "unscoped", "all_applications"}:
            raw_project_id = ""
        normalized = {
            "tenant_id": tenant_id,
            "project_id": raw_project_id,
            "risk_tier": str(risk_tier or "").strip().lower(),
            "execution_mode": str(execution_mode or "").strip().lower(),
            "transport_provider": str(transport_provider or "").strip().lower(),
            "status": str(status or "").strip().lower(),
            "service": str(service or "").strip().lower(),
            "inbox_view": str(inbox_view or "all").strip().lower(),
            "record_type": str(record_type or "all").strip().lower(),
            "severity": str(severity or "").strip().lower(),
        }
        project_aliases = {normalized["project_id"]} if normalized["project_id"] else set()
        # KaiMS is the built-in platform workspace, while its canonical
        # incident ownership records use deployable component identities.
        # Keep this mapping explicit so project scoping remains fail-closed and
        # never pulls customer applications such as Online Boutique.
        if normalized["project_id"] in {"kaims", "kaiops", "kaims-core", "kaiops-core"}:
            project_aliases.update({
                "kaims", "kaiops", "api-gateway", "kaiops-platform", "mysql",
                "monitoring-adapter", "context-agent", "resolution-agent",
                "remediation-engine", "orchestrator", "approval-service",
                "closure-service", "discovery-mcp", "rabbitmq",
            })
        if normalized["project_id"]:
            application = (
                await self.session.execute(
                    select(ApplicationRecord).where(
                        ApplicationRecord.tenant_id == tenant_id,
                        func.lower(ApplicationRecord.name) == normalized["project_id"],
                    ).limit(1)
                )
            ).scalar_one_or_none()
            if application is not None:
                payload = application.payload if isinstance(application.payload, dict) else {}
                labels = payload.get("labels") if isinstance(payload.get("labels"), dict) else {}
                project_aliases.update(
                    str(value or "").strip().lower()
                    for value in (
                        application.name,
                        application.namespace,
                        payload.get("project_id"),
                        payload.get("project"),
                        payload.get("project_name"),
                        payload.get("application"),
                        labels.get("project_id"),
                        labels.get("project"),
                        labels.get("project_name"),
                        labels.get("application"),
                        labels.get("service"),
                    )
                    if str(value or "").strip()
                )
        views = ("all", "needs_me", "kai_handling", "critical", "watching", "resolved")
        if normalized["inbox_view"] not in views:
            raise ValueError("Unsupported inbox view")
        if normalized["record_type"] not in {"all", "incidents", "alerts"}:
            raise ValueError("Unsupported inbox record type")
        fingerprint = hashlib.sha256(
            json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        snapshot = datetime.now(UTC)
        cursor_score: int | None = None
        cursor_at: datetime | None = None
        cursor_id: UUID | None = None
        direction = "after"
        if cursor:
            try:
                padding = "=" * (-len(cursor) % 4)
                decoded = json.loads(base64.urlsafe_b64decode(cursor + padding).decode("utf-8"))
                if decoded.get("filter") != fingerprint:
                    raise ValueError("filter mismatch")
                snapshot = datetime.fromisoformat(str(decoded["snapshot"]).replace("Z", "+00:00"))
                cursor_score = int(decoded["score"])
                cursor_at = datetime.fromisoformat(str(decoded["at"]).replace("Z", "+00:00"))
                cursor_id = UUID(str(decoded["id"]))
                direction = str(decoded.get("direction") or "after")
                if direction not in {"before", "after"}:
                    raise ValueError("invalid cursor direction")
            except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
                raise ValueError("Invalid unified inbox cursor") from exc

        terminal = ("closed", "resolved", "recovered", "cancelled", "canceled")
        attention = (
            "failed",
            "blocked",
            "manual_intervention",
            "validation_failed",
            "rollback_failed",
            "awaiting_approval",
            "pending_approval",
            "approval_required", "waiting_for_human", "waiting_for_human_evidence", "collection_blocked",
        )
        latest_generation = (
            select(
                IncidentCorrelationOwnershipRecord.correlation_family_id.label("family_id"),
                func.max(IncidentCorrelationOwnershipRecord.correlation_generation).label("generation"),
            )
            .where(IncidentCorrelationOwnershipRecord.tenant_id == tenant_id)
            .group_by(IncidentCorrelationOwnershipRecord.correlation_family_id)
            .subquery()
        )
        incident_severity = func.lower(func.coalesce(
            IncidentProjectionRecord.severity,
            IncidentRecord.severity,
            "",
        ))
        # Materialize narrow current-work facts once, instead of expanding or
        # re-evaluating complete RCA histories for every inbox counter and row.
        from sqlalchemy import tuple_
        owner = IncidentCorrelationOwnershipRecord
        req = ContextEvidenceRequirementRecord
        human = HumanEvidenceRequestRecord
        job = ContextEnrichmentJobRecord
        # Resolve current ownership in the selected workspace before reading
        # evidence history. Other applications and old generations cannot
        # affect this inbox's progress or require tenant-wide materialization.
        work_scope = select(owner.canonical_incident_id).join(latest_generation, and_(
            latest_generation.c.family_id == owner.correlation_family_id,
            latest_generation.c.generation == owner.correlation_generation,
        )).where(owner.tenant_id == tenant_id, owner.last_seen_at <= snapshot)
        if normalized["project_id"]:
            work_scope = work_scope.where(or_(
                func.lower(owner.project_id).in_(project_aliases),
                func.lower(owner.service).in_(project_aliases),
                and_(normalized["project_id"] in {"kaims", "kaiops", "kaims-core", "kaiops-core"},
                     func.lower(owner.service).like("kaiops-%")),
            ))
        if normalized["record_type"] == "alerts":
            work_scope = work_scope.where(literal(False))
        binding_rows = (await self.session.execute(select(
            IncidentInvestigationBindingRecord.incident_id,
            IncidentInvestigationBindingRecord.rca_version,
            IncidentInvestigationBindingRecord.status,
        ).where(
            IncidentInvestigationBindingRecord.tenant_id == tenant_id,
            IncidentInvestigationBindingRecord.incident_id.in_(work_scope),
        ))).all()
        binding_versions: dict[Any, int] = {}
        binding_status_by_incident: dict[Any, str] = {}
        for inc_id, rca_ver, b_status in binding_rows:
            ver_int = int(rca_ver or 0)
            if inc_id not in binding_versions or ver_int >= binding_versions[inc_id]:
                binding_versions[inc_id] = ver_int
                binding_status_by_incident[inc_id] = str(b_status or "").strip().lower()
        conclusive_binding_incidents = {
            inc_id for inc_id, st in binding_status_by_incident.items()
            if st in {"grounded", "ready", "conclusive"}
        }
        investigating_binding_incidents = {
            inc_id for inc_id in binding_versions
            if inc_id not in conclusive_binding_incidents
        }
        all_req_rows = (await self.session.execute(select(
            req.requirement_id, req.incident_id, req.rca_version, req.category, req.status,
        ).where(
            req.tenant_id == tenant_id,
            req.incident_id.in_(work_scope),
        ))).all()
        reqs_by_incident: dict[Any, list[Any]] = {}
        for r_row in all_req_rows:
            reqs_by_incident.setdefault(r_row.incident_id, []).append(r_row)
        current_rows = []
        for inc_id, inc_reqs in reqs_by_incident.items():
            if inc_id in conclusive_binding_incidents:
                continue
            target_ver = binding_versions.get(
                inc_id,
                max((int(r.rca_version or 0) for r in inc_reqs), default=0),
            )
            cur_ver_reqs = [r for r in inc_reqs if int(r.rca_version or 0) == target_ver]
            cur_cats = {str(r.category or "").strip().lower() for r in cur_ver_reqs}
            carried: dict[str, Any] = {}
            if inc_id in binding_versions:
                for r in inc_reqs:
                    if int(r.rca_version or 0) >= target_ver:
                        continue
                    cat = str(r.category or "").strip().lower()
                    if cat in cur_cats:
                        continue
                    if str(r.status or "").strip().lower() in {
                        "open", "pending", "collecting", "human_requested", "assignment_blocked", "blocked",
                    }:
                        prev = carried.get(cat)
                        if prev is None or int(r.rca_version or 0) >= int(prev.rca_version or 0):
                            carried[cat] = r
            active_inc_reqs = [*cur_ver_reqs, *carried.values()]
            for r in active_inc_reqs:
                if str(r.status or "").strip().lower() not in {"collected", "answered", "satisfied", "cancelled"}:
                    current_rows.append(r)
        requirement_ids = [row.requirement_id for row in current_rows]
        waiting_ids = set()
        blocking_human_ids = set()
        assignment_blocked_ids = set()
        collecting_ids = set()
        latest_jobs = {}
        for offset in range(0, len(requirement_ids), 200):
            subset = requirement_ids[offset:offset + 200]
            human_rows = (await self.session.execute(select(
                human.requirement_id, human.status, human.investigation_can_continue,
            ).where(
                human.tenant_id == tenant_id, human.requirement_id.in_(subset),
                human.status.in_(("pending", "assigned", "open", "in_progress", "assignment_blocked")),
            ))).all()
            for request in human_rows:
                if request.status == "assignment_blocked":
                    assignment_blocked_ids.add(request.requirement_id)
                else:
                    waiting_ids.add(request.requirement_id)
                    if request.investigation_can_continue is not True:
                        blocking_human_ids.add(request.requirement_id)
            job_rows = (await self.session.execute(select(job.requirement_id, job.status, job.created_at, job.job_id).where(
                job.tenant_id == tenant_id, job.requirement_id.in_(subset),
            ))).all()
            for item in job_rows:
                previous = latest_jobs.get(item.requirement_id)
                if previous is None or (item.created_at, str(item.job_id)) > (previous.created_at, str(previous.job_id)):
                    latest_jobs[item.requirement_id] = item
        collecting_ids = {key for key, value in latest_jobs.items() if value.status in {"scheduled", "collecting", "retry"}}
        waiting_incidents = {
            row.incident_id for row in current_rows
            if row.requirement_id in waiting_ids
            or (row.requirement_id in assignment_blocked_ids and row.incident_id in binding_versions)
        }
        blocking_human_incidents = {row.incident_id for row in current_rows if row.requirement_id in blocking_human_ids}
        collecting_incidents = {row.incident_id for row in current_rows if row.requirement_id in collecting_ids}
        blocked_incidents = {row.incident_id for row in current_rows if row.status in {"blocked", "failed", "dead_letter"} or row.requirement_id in assignment_blocked_ids}
        unresolved_incidents = {row.incident_id for row in current_rows}
        legacy_status = func.lower(func.coalesce(
            func.nullif(IncidentProjectionRecord.status, ""),
            func.nullif(IncidentRecord.status, ""),
            IncidentCorrelationOwnershipRecord.lifecycle_state,
        ))
        lifecycle = func.lower(IncidentProjectionRecord.lifecycle_state)
        early_states = (
            "detected", "requirements_identified", "collecting",
            "waiting_for_human", "context_ready", "investigating",
            "collection_blocked", "rca_ready",
        )
        incident_status = case(
            (func.lower(IncidentRecord.status).in_(terminal), func.lower(IncidentRecord.status)),
            (legacy_status.in_(terminal), legacy_status),
            (and_(lifecycle.not_in(early_states), lifecycle != ""), lifecycle),
            (owner.canonical_incident_id.in_(blocking_human_incidents), "waiting_for_human"),
            (owner.canonical_incident_id.in_(collecting_incidents), "collecting"),
            (owner.canonical_incident_id.in_(waiting_incidents), "waiting_for_human"),
            (owner.canonical_incident_id.in_(conclusive_binding_incidents), "rca_ready"),
            (owner.canonical_incident_id.in_(investigating_binding_incidents), "investigating"),
            (owner.canonical_incident_id.in_(blocked_incidents), "collection_blocked"),
            (owner.canonical_incident_id.in_(unresolved_incidents), "requirements_identified"),
            (and_(lifecycle == "detected", legacy_status == "investigating",
                  owner.canonical_incident_id.notin_(tuple(binding_versions))), lifecycle),
            else_=func.coalesce(func.nullif(lifecycle, ""), legacy_status),
        )
        incident_score = case(
            (incident_status.in_(attention), 200), else_=100,
        ) + case((incident_severity == "critical", 80), else_=0)
        incident_query = (
            select(
                literal("incident").label("record_type"),
                IncidentCorrelationOwnershipRecord.canonical_incident_id.label("record_id"),
                IncidentCorrelationOwnershipRecord.last_seen_at.label("observed_at"),
                incident_score.label("score"),
                incident_status.label("row_status"),
                incident_severity.label("row_severity"),
            )
            .join(latest_generation, and_(
                latest_generation.c.family_id == IncidentCorrelationOwnershipRecord.correlation_family_id,
                latest_generation.c.generation == IncidentCorrelationOwnershipRecord.correlation_generation,
            ))
            .outerjoin(IncidentProjectionRecord, and_(
                IncidentProjectionRecord.incident_id == IncidentCorrelationOwnershipRecord.canonical_incident_id,
                IncidentProjectionRecord.tenant_id == tenant_id,
            ))
            .outerjoin(IncidentRecord, and_(
                IncidentRecord.id == IncidentCorrelationOwnershipRecord.canonical_incident_id,
                IncidentRecord.tenant_id == tenant_id,
            ))
            .where(
                IncidentCorrelationOwnershipRecord.tenant_id == tenant_id,
                IncidentCorrelationOwnershipRecord.last_seen_at <= snapshot,
                # The unified inbox is an operator action queue, not an alert
                # history. Warning/info incidents remain available by direct
                # incident lookup and in Live Alerts, but are not admitted here.
                incident_severity.in_(
                    ("high", "critical", "p1", "p2", "sev1", "sev2")
                ),
            )
        )
        if normalized["project_id"]:
            platform_component = and_(
                normalized["project_id"] in {"kaims", "kaiops", "kaims-core", "kaiops-core"},
                func.lower(IncidentCorrelationOwnershipRecord.service).like("kaiops-%"),
            )
            incident_query = incident_query.where(
                or_(
                    func.lower(IncidentCorrelationOwnershipRecord.project_id).in_(project_aliases),
                    func.lower(IncidentCorrelationOwnershipRecord.service).in_(project_aliases),
                    platform_component,
                )
            )
        if normalized["service"]:
            incident_query = incident_query.where(
                or_(
                    func.lower(IncidentCorrelationOwnershipRecord.service).contains(normalized["service"], autoescape=True),
                    func.lower(IncidentCorrelationOwnershipRecord.project_id).contains(normalized["service"], autoescape=True),
                    func.lower(IncidentRecord.title).contains(normalized["service"], autoescape=True),
                    func.lower(IncidentProjectionRecord.projection_payload["title"].as_string()).contains(normalized["service"], autoescape=True),
                )
            )
        if normalized["status"]:
            incident_query = incident_query.where(
                incident_status == normalized["status"]
            )
        if normalized["severity"]:
            incident_query = incident_query.where(
                incident_severity == normalized["severity"]
            )
        projection_filters = (
            ("risk_tier", IncidentProjectionRecord.risk_tier),
            ("execution_mode", IncidentProjectionRecord.execution_mode),
            ("transport_provider", IncidentProjectionRecord.transport_provider),
        )
        for field, column in projection_filters:
            if normalized[field]:
                incident_query = incident_query.where(func.lower(column) == normalized[field])

        alert_project = AlertRecord.inbox_project
        alert_service_scope = func.lower(AlertRecord.service)
        alert_score = case((func.lower(AlertRecord.severity) == "critical", 175), else_=75)
        alert_query = select(
            literal("alert").label("record_type"), AlertRecord.id.label("record_id"),
            AlertRecord.created_at.label("observed_at"), alert_score.label("score"),
            literal("open").label("row_status"), func.lower(AlertRecord.severity).label("row_severity"),
        ).where(
            AlertRecord.tenant_id == tenant_id,
            AlertRecord.created_at <= snapshot,
            func.lower(AlertRecord.severity).notin_(("warning", "warn")),
            ~exists(select(IncidentOccurrenceRecord.id).where(and_(
                IncidentOccurrenceRecord.tenant_id == tenant_id,
                IncidentOccurrenceRecord.occurrence_id == AlertRecord.id,
            ))),
            # Legacy/partially migrated occurrence rows may lack the normalized
            # occurrence-table record while still carrying an authoritative
            # canonical incident binding in the alert payload. They are linked
            # occurrences, not unlinked signals.
            AlertRecord.inbox_canonical_incident_id.is_(None),
        ).with_hint(AlertRecord, "FORCE INDEX (idx_alerts_inbox_cover)", dialect_name="mysql")
        # MySQL otherwise prefers the tenant-only index and recomputes indexed
        # virtual scope fields from large JSON documents for every alert.
        if normalized["project_id"]:
            alert_query = alert_query.where(or_(
                alert_project.in_(project_aliases),
                alert_service_scope.in_(project_aliases),
            ))
        if normalized["service"]:
            alert_query = alert_query.where(or_(
                alert_service_scope.contains(normalized["service"], autoescape=True),
                alert_project.contains(normalized["service"], autoescape=True),
                func.lower(AlertRecord.name).contains(normalized["service"], autoescape=True),
            ))
        if normalized["severity"]:
            alert_query = alert_query.where(func.lower(AlertRecord.severity) == normalized["severity"])
        if normalized["status"] and normalized["status"] != "open":
            alert_query = alert_query.where(literal(False))
        if any(normalized[key] for key in ("risk_tier", "execution_mode", "transport_provider")):
            alert_query = alert_query.where(literal(False))

        selected = []
        if normalized["record_type"] in {"all", "incidents"}:
            selected.append(incident_query)
        if normalized["record_type"] in {"all", "alerts"}:
            selected.append(alert_query)
        candidates = (selected[0] if len(selected) == 1 else union_all(*selected)).subquery()

        def view_clause(view: str):
            is_incident = candidates.c.record_type == "incident"
            is_terminal = candidates.c.row_status.in_(terminal)
            is_attention = candidates.c.row_status.in_(attention)
            if view == "needs_me":
                return or_(
                    and_(is_incident, is_attention),
                    and_(
                        ~is_incident,
                        candidates.c.row_severity.in_(("critical", "high", "p1", "p2", "sev1", "sev2")),
                    ),
                )
            if view == "kai_handling":
                return and_(~is_terminal, or_(~is_incident, ~is_attention))
            if view == "critical":
                return and_(~is_terminal, candidates.c.row_severity.in_(("critical", "p1", "sev1")))
            if view == "watching":
                return and_(~is_terminal, candidates.c.row_severity.in_(("medium", "warning", "low", "info")))
            if view == "resolved":
                return and_(is_incident, is_terminal)
            return literal(True)

        # Compute every counter in one scan of the scoped candidate feed.
        # Separate per-view counts repeat the expensive correlated alert lookup.
        counts = (await self.session.execute(select(
            *[func.coalesce(func.sum(case((view_clause(view), 1), else_=0)), 0).label(view)
              for view in views],
            func.coalesce(func.sum(case((candidates.c.record_type == "incident", 1), else_=0)), 0).label("incidents"),
            func.coalesce(func.sum(case((candidates.c.record_type == "alert", 1), else_=0)), 0).label("alerts"),
        ).select_from(candidates))).mappings().one()
        record_counts = {kind: int(counts[kind]) for kind in ("incidents", "alerts")}
        total_count = sum(record_counts.values())
        view_counts = {view: int(counts[view]) for view in views}
        page_query = select(candidates).where(view_clause(normalized["inbox_view"]))
        if cursor_score is not None and cursor_at is not None and cursor_id is not None:
            def beyond(column, value):
                return column > value if direction == "before" else column < value
            page_query = page_query.where(or_(
                beyond(candidates.c.observed_at, cursor_at),
                and_(candidates.c.observed_at == cursor_at, beyond(candidates.c.score, cursor_score)),
                and_(candidates.c.observed_at == cursor_at, candidates.c.score == cursor_score,
                     beyond(candidates.c.record_id, cursor_id)),
            ))
        ordering = [candidates.c.observed_at, candidates.c.score, candidates.c.record_id]
        page_rows = (await self.session.execute(page_query.order_by(
            *[column.asc() if direction == "before" else column.desc() for column in ordering],
        ).limit(safe_limit + 1))).mappings().all()
        has_more = len(page_rows) > safe_limit
        page_rows = page_rows[:safe_limit]
        if direction == "before":
            page_rows = list(reversed(page_rows))
        incident_ids = [row["record_id"] for row in page_rows if row["record_type"] == "incident"]
        alert_ids = [row["record_id"] for row in page_rows if row["record_type"] == "alert"]
        projections = await self.list_incident_projections(
            limit=safe_limit,
            tenant_id=tenant_id,
            include_enrichment=False,
            incident_ids=incident_ids,
        )
        projection_by_id = {str(row.get("incident_id") or row.get("id")): row for row in projections}
        incident_records = (
            (await self.session.execute(select(IncidentRecord).where(
                IncidentRecord.tenant_id == tenant_id,
                IncidentRecord.id.in_(incident_ids),
            ))).scalars().all()
            if incident_ids
            else []
        )
        incident_by_id = {str(row.id): row for row in incident_records}
        alert_rows = (
            (await self.session.execute(select(AlertRecord).where(AlertRecord.id.in_(alert_ids)))).scalars().all()
            if alert_ids
            else []
        )
        alert_by_id = {
            str(row.id): {
                **dict(row.payload or {}),
                "id": str(row.id),
                "alert_id": str(row.id),
                "service": row.service,
                "environment": row.environment,
                "severity": row.severity,
                "source": row.source,
                "created_at": row.created_at.isoformat(),
            }
            for row in alert_rows
        }
        rows = []
        for item in page_rows:
            record_id = str(item["record_id"])
            row = (
                dict(projection_by_id.get(record_id, {}))
                if item["record_type"] == "incident"
                else dict(alert_by_id.get(record_id, {}))
            )
            row.setdefault("id", record_id)
            if item["record_type"] == "incident":
                canonical = incident_by_id.get(record_id)
                canonical_payload = dict(canonical.payload or {}) if canonical is not None and isinstance(canonical.payload, dict) else {}
                if canonical is not None:
                    row.setdefault("service", canonical.service)
                    row.setdefault("environment", canonical.environment)
                    row.setdefault("severity", canonical.severity)
                    row.setdefault("title", canonical.title)
                    row.setdefault("ticket_id", canonical.ticket_id)
                    source_alert = canonical_payload.get("source_alert") if isinstance(canonical_payload.get("source_alert"), dict) else {}
                    canonical_alert_id = (
                        canonical_payload.get("alert_id")
                        or canonical_payload.get("source_alert_id")
                        or source_alert.get("alert_id")
                        or source_alert.get("id")
                    )
                    if canonical_alert_id:
                        row.setdefault("alert_id", str(canonical_alert_id))
                    row.setdefault("source_alert", source_alert or None)
                row.update({
                    "incident_id": record_id,
                    "status": item["row_status"],
                    "lifecycle_state": str(item["row_status"]).upper(),
                })
                if isinstance(row.get("projection_payload"), dict):
                    row["projection_payload"] = {
                        **row["projection_payload"],
                        "status": item["row_status"],
                        "lifecycle_state": str(item["row_status"]).upper(),
                    }
            rows.append(
                {
                    "record_type": item["record_type"],
                    "score": int(item["score"]),
                    "observed_at": item["observed_at"].isoformat(),
                    "row": row,
                }
            )

        def encode_cursor(item, cursor_direction):
            payload = json.dumps({
                "filter": fingerprint, "snapshot": snapshot.isoformat(),
                "score": int(item["score"]), "at": item["observed_at"].isoformat(),
                "id": str(item["record_id"]), "direction": cursor_direction,
            }, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        next_cursor = previous_cursor = None
        if page_rows:
            if (direction == "after" and has_more) or (direction == "before" and cursor):
                next_cursor = encode_cursor(page_rows[-1], "after")
            if (direction == "before" and has_more) or (direction == "after" and cursor):
                previous_cursor = encode_cursor(page_rows[0], "before")
        return {
            "rows": rows,
            "next_cursor": next_cursor,
            "previous_cursor": previous_cursor,
            "total_count": total_count,
            "filtered_count": view_counts[normalized["inbox_view"]],
            "record_counts": record_counts,
            "view_counts": view_counts,
            "snapshot_at": snapshot.isoformat(),
        }

    async def list_incident_groups(
        self,
        *,
        tenant_id: str,
        limit: int = 25,
        cursor: str | None = None,
        status: str | None = None,
        service: str | None = None,
        risk_tier: str | None = None,
        execution_mode: str | None = None,
    ) -> dict[str, Any]:
        """Return canonical correlation families before applying cursor pagination."""
        tenant_id = self._require("tenant_id", tenant_id)
        safe_limit = max(1, min(int(limit), 100))
        terminal = ("closed", "resolved", "cancelled", "canceled")
        attention = ("failed", "blocked", "awaiting_approval", "pending_approval", "approval_required")
        filter_fingerprint = hashlib.sha256(json.dumps({
            "tenant_id": tenant_id,
            "status": str(status or "").strip().lower(),
            "service": str(service or "").strip(),
            "risk_tier": str(risk_tier or "").strip().lower(),
            "execution_mode": str(execution_mode or "").strip().lower(),
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        latest_generation = (
            select(
                IncidentCorrelationOwnershipRecord.correlation_family_id.label("family_id"),
                func.max(IncidentCorrelationOwnershipRecord.correlation_generation).label("generation"),
            )
            .where(IncidentCorrelationOwnershipRecord.tenant_id == tenant_id)
            .group_by(IncidentCorrelationOwnershipRecord.correlation_family_id)
            .subquery()
        )

        def scoped_query(*, apply_filters: bool):
            query = (
                select(IncidentCorrelationOwnershipRecord)
                .outerjoin(
                    latest_generation,
                    and_(
                        latest_generation.c.family_id == IncidentCorrelationOwnershipRecord.correlation_family_id,
                        latest_generation.c.generation == IncidentCorrelationOwnershipRecord.correlation_generation,
                    ),
                )
                .outerjoin(
                    IncidentProjectionRecord,
                    IncidentProjectionRecord.incident_id == IncidentCorrelationOwnershipRecord.canonical_incident_id,
                )
                .where(
                    IncidentCorrelationOwnershipRecord.tenant_id == tenant_id,
                    or_(
                        latest_generation.c.generation.is_not(None),
                        IncidentCorrelationOwnershipRecord.lifecycle_state.in_(attention),
                        IncidentProjectionRecord.status.in_(attention),
                    ),
                )
            )
            if apply_filters:
                if status:
                    normalized_status = status.strip().lower()
                    query = query.where(
                        or_(
                            IncidentCorrelationOwnershipRecord.lifecycle_state == normalized_status,
                            IncidentProjectionRecord.status == normalized_status,
                        )
                    )
                if service:
                    query = query.where(IncidentCorrelationOwnershipRecord.service == service.strip())
                if risk_tier:
                    query = query.where(IncidentProjectionRecord.risk_tier == risk_tier.strip().lower())
                if execution_mode:
                    query = query.where(IncidentProjectionRecord.execution_mode == execution_mode.strip().lower())
            return query

        total_count = int(
            (await self.session.scalar(select(func.count()).select_from(scoped_query(apply_filters=False).subquery())))
            or 0
        )
        filtered_count = int(
            (await self.session.scalar(select(func.count()).select_from(scoped_query(apply_filters=True).subquery())))
            or 0
        )
        active_count = int((await self.session.scalar(
            select(func.count()).select_from(
                scoped_query(apply_filters=False)
                .where(IncidentCorrelationOwnershipRecord.lifecycle_state.not_in(terminal))
                .subquery()
            )
        )) or 0)
        needs_attention_count = int((await self.session.scalar(
            select(func.count()).select_from(
                scoped_query(apply_filters=False)
                .where(IncidentCorrelationOwnershipRecord.lifecycle_state.in_(attention))
                .subquery()
            )
        )) or 0)
        unlinked_signal_count = int((await self.session.scalar(
            select(func.count(AlertRecord.id))
            .select_from(AlertRecord)
            .outerjoin(
                IncidentOccurrenceRecord,
                and_(
                    IncidentOccurrenceRecord.tenant_id == AlertRecord.tenant_id,
                    IncidentOccurrenceRecord.occurrence_id == AlertRecord.id,
                ),
            )
            .where(AlertRecord.tenant_id == tenant_id, IncidentOccurrenceRecord.id.is_(None))
        )) or 0)

        # Expand/backfill/cutover safety: deployments can contain durable
        # incident projections before canonical ownership has been backfilled.
        # Keep those incidents visible instead of presenting an empty inbox.
        # The explicit legacy scope prevents unverified project attribution.
        if total_count == 0:
            legacy_rows = await self.list_incident_projections(
                limit=safe_limit,
                tenant_id=tenant_id,
                include_enrichment=False,
                risk_tier=risk_tier,
                execution_mode=execution_mode,
                status=status,
                service=service,
            )
            projection_scope = select(IncidentProjectionRecord).where(
                IncidentProjectionRecord.tenant_id == tenant_id
            )
            filtered_scope = projection_scope
            if status:
                filtered_scope = filtered_scope.where(
                    IncidentProjectionRecord.status == status.strip().lower()
                )
            if service:
                filtered_scope = filtered_scope.where(IncidentProjectionRecord.service == service.strip())
            if risk_tier:
                filtered_scope = filtered_scope.where(
                    IncidentProjectionRecord.risk_tier == risk_tier.strip().lower()
                )
            if execution_mode:
                filtered_scope = filtered_scope.where(
                    IncidentProjectionRecord.execution_mode == execution_mode.strip().lower()
                )
            legacy_total = int((await self.session.scalar(
                select(func.count()).select_from(projection_scope.subquery())
            )) or 0)
            legacy_filtered = int((await self.session.scalar(
                select(func.count()).select_from(filtered_scope.subquery())
            )) or 0)
            legacy_active = int((await self.session.scalar(
                select(func.count()).select_from(
                    projection_scope.where(IncidentProjectionRecord.status.not_in(terminal)).subquery()
                )
            )) or 0)
            legacy_attention = int((await self.session.scalar(
                select(func.count()).select_from(
                    projection_scope.where(IncidentProjectionRecord.status.in_(attention)).subquery()
                )
            )) or 0)
            response_rows = []
            for projection in legacy_rows:
                incident_id = str(projection.get("incident_id") or projection.get("id") or "")
                lifecycle = str(projection.get("status") or "open").strip().lower()
                first_seen = str(
                    projection.get("first_seen_at")
                    or projection.get("created_at")
                    or projection.get("latest_event_at")
                    or datetime.now(UTC).isoformat()
                )
                last_seen = str(projection.get("latest_event_at") or projection.get("updated_at") or first_seen)
                projection.update({
                    "canonical_incident_id": incident_id,
                    "incident_id": incident_id,
                    "correlation_family_id": str(uuid5(NAMESPACE_URL, f"kaims-legacy:{tenant_id}:{incident_id}")),
                    "generation": 1,
                    "correlation_generation": 1,
                    "canonical_status": lifecycle,
                    "status": lifecycle,
                    "active_occurrence_count": 0,
                    "total_occurrence_count": 0,
                    "first_seen_at": first_seen,
                    "last_seen_at": last_seen,
                    "latest_occurrences": [],
                    "terminal_history_count": 1 if lifecycle in terminal else 0,
                    "attention_state": (
                        "needs_attention" if lifecycle in attention
                        else "active" if lifecycle not in terminal else "terminal"
                    ),
                    "project_id": "legacy-unassigned",
                    "needs_scope_review": True,
                    "correlation_backfill_status": "pending",
                })
                response_rows.append(projection)
            return {
                "rows": response_rows,
                "next_cursor": None,
                "previous_cursor": None,
                "total_count": legacy_total,
                "filtered_count": legacy_filtered,
                "active_count": legacy_active,
                "needs_attention_count": legacy_attention,
                "unlinked_signal_count": unlinked_signal_count,
                "migration_state": "legacy_fallback",
                "generated_at": datetime.now(UTC).isoformat(),
            }

        direction = "next"
        cursor_at: datetime | None = None
        cursor_id: UUID | None = None
        if cursor:
            try:
                padding = "=" * (-len(cursor) % 4)
                decoded = json.loads(base64.urlsafe_b64decode(cursor + padding).decode("utf-8"))
                cursor_at = datetime.fromisoformat(str(decoded["at"]).replace("Z", "+00:00"))
                cursor_id = UUID(str(decoded["id"]))
                direction = "previous" if decoded.get("direction") == "previous" else "next"
            except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
                raise ValueError("Invalid incident group cursor") from exc
            if decoded.get("filter") != filter_fingerprint:
                raise ValueError("Incident group cursor does not match the active filters")

        page_query = scoped_query(apply_filters=True)
        if cursor_at is not None and cursor_id is not None:
            if direction == "previous":
                page_query = page_query.where(or_(
                    IncidentCorrelationOwnershipRecord.first_seen_at > cursor_at,
                    and_(
                        IncidentCorrelationOwnershipRecord.first_seen_at == cursor_at,
                        IncidentCorrelationOwnershipRecord.id > cursor_id,
                    ),
                ))
            else:
                page_query = page_query.where(or_(
                    IncidentCorrelationOwnershipRecord.first_seen_at < cursor_at,
                    and_(
                        IncidentCorrelationOwnershipRecord.first_seen_at == cursor_at,
                        IncidentCorrelationOwnershipRecord.id < cursor_id,
                    ),
                ))
        if direction == "previous":
            page_query = page_query.order_by(
                IncidentCorrelationOwnershipRecord.first_seen_at.asc(),
                IncidentCorrelationOwnershipRecord.id.asc(),
            )
        else:
            page_query = page_query.order_by(
                IncidentCorrelationOwnershipRecord.first_seen_at.desc(),
                IncidentCorrelationOwnershipRecord.id.desc(),
            )
        ownership_rows = list((await self.session.execute(page_query.limit(safe_limit + 1))).scalars().all())
        has_more = len(ownership_rows) > safe_limit
        ownership_rows = ownership_rows[:safe_limit]
        if direction == "previous":
            ownership_rows.reverse()

        canonical_ids = [row.canonical_incident_id for row in ownership_rows]
        projections = await self.list_incident_projections(
            limit=safe_limit,
            tenant_id=tenant_id,
            include_enrichment=False,
            incident_ids=canonical_ids,
        )
        projection_by_id = {str(row.get("incident_id") or row.get("id")): row for row in projections}
        occurrence_counts: dict[UUID, int] = {}
        occurrences_by_incident: dict[UUID, list[dict[str, Any]]] = {}
        terminal_history: dict[UUID, int] = {}
        if canonical_ids:
            count_rows = await self.session.execute(
                select(IncidentOccurrenceRecord.canonical_incident_id, func.count(IncidentOccurrenceRecord.id))
                .where(IncidentOccurrenceRecord.canonical_incident_id.in_(canonical_ids))
                .group_by(IncidentOccurrenceRecord.canonical_incident_id)
            )
            occurrence_counts = {incident_id: int(count) for incident_id, count in count_rows.all()}
            occurrence_rows = (
                await self.session.execute(
                    select(IncidentOccurrenceRecord)
                    .where(IncidentOccurrenceRecord.canonical_incident_id.in_(canonical_ids))
                    .order_by(IncidentOccurrenceRecord.observed_at.desc(), IncidentOccurrenceRecord.id.desc())
                )
            ).scalars().all()
            for occurrence in occurrence_rows:
                bucket = occurrences_by_incident.setdefault(occurrence.canonical_incident_id, [])
                if len(bucket) < 5:
                    bucket.append({
                        "occurrence_id": str(occurrence.occurrence_id),
                        "observed_at": occurrence.observed_at.isoformat(),
                        "idempotency_key": occurrence.idempotency_key,
                    })
            family_ids = [row.correlation_family_id for row in ownership_rows]
            history_rows = await self.session.execute(
                select(
                    IncidentCorrelationOwnershipRecord.correlation_family_id,
                    func.count(IncidentCorrelationOwnershipRecord.id),
                )
                .where(
                    IncidentCorrelationOwnershipRecord.correlation_family_id.in_(family_ids),
                    IncidentCorrelationOwnershipRecord.lifecycle_state.in_(terminal),
                )
                .group_by(IncidentCorrelationOwnershipRecord.correlation_family_id)
            )
            terminal_history = {family_id: int(count) for family_id, count in history_rows.all()}

        response_rows: list[dict[str, Any]] = []
        for ownership in ownership_rows:
            projection = dict(projection_by_id.get(str(ownership.canonical_incident_id), {}))
            count = occurrence_counts.get(ownership.canonical_incident_id, 0)
            ownership_lifecycle = str(ownership.lifecycle_state or "").strip().lower()
            projected_status = str(projection.get("status") or "").strip().lower()
            projected_lifecycle = str(projection.get("lifecycle_state") or "").strip().lower()
            if (
                projected_status
                and projected_status not in {"", "open", "investigating", "detected"}
            ):
                lifecycle = projected_status
            elif (
                ownership_lifecycle in {"", "open", "investigating", "detected"}
                and projected_lifecycle
                and projected_lifecycle not in {"open", "investigating", "detected"}
            ):
                lifecycle = projected_lifecycle
            else:
                lifecycle = ownership_lifecycle or projected_status or "open"
            projection.update({
                "canonical_incident_id": str(ownership.canonical_incident_id),
                "incident_id": str(ownership.canonical_incident_id),
                "correlation_family_id": str(ownership.correlation_family_id),
                "generation": ownership.correlation_generation,
                "correlation_generation": ownership.correlation_generation,
                "canonical_status": lifecycle,
                "status": lifecycle,
                "active_occurrence_count": count if lifecycle not in terminal else 0,
                "total_occurrence_count": count,
                "first_seen_at": ownership.first_seen_at.isoformat(),
                "last_seen_at": ownership.last_seen_at.isoformat(),
                "latest_occurrences": occurrences_by_incident.get(ownership.canonical_incident_id, []),
                "terminal_history_count": terminal_history.get(ownership.correlation_family_id, 0),
                "attention_state": (
                    "needs_attention"
                    if lifecycle in attention
                    else "active"
                    if lifecycle not in terminal
                    else "terminal"
                ),
                "project_id": ownership.project_id,
                "service": ownership.service,
                "environment": ownership.environment,
            })
            response_rows.append(projection)

        next_cursor = None
        previous_cursor = None
        if ownership_rows:
            if direction == "next" and has_more:
                next_cursor = self._incident_group_cursor(ownership_rows[-1], "next", filter_fingerprint)
            elif direction == "previous" or cursor:
                next_cursor = self._incident_group_cursor(ownership_rows[-1], "next", filter_fingerprint)
            if cursor or direction == "previous":
                previous_cursor = self._incident_group_cursor(ownership_rows[0], "previous", filter_fingerprint)
        return {
            "rows": response_rows,
            "next_cursor": next_cursor,
            "previous_cursor": previous_cursor,
            "total_count": total_count,
            "filtered_count": filtered_count,
            "active_count": active_count,
            "needs_attention_count": needs_attention_count,
            "unlinked_signal_count": unlinked_signal_count,
            "generated_at": datetime.now(UTC).isoformat(),
        }

    async def list_incident_projections(
        self,
        *,
        limit: int = 100,
        tenant_id: str | None = None,
        include_enrichment: bool = True,
        risk_tier: str | None = None,
        execution_mode: str | None = None,
        transport_provider: str | None = None,
        status: str | None = None,
        service: str | None = None,
        incident_id: str | None = None,
        incident_ids: list[UUID] | None = None,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 100))
        # Apply ordering and the limit to narrow scalar columns before loading
        # projection_payload. On databases that drifted without the updated_at
        # index, sorting full JSON-bearing rows can exhaust MySQL's sort buffer.
        latest_stmt = select(
            IncidentProjectionRecord.incident_id.label("incident_id"),
            IncidentProjectionRecord.updated_at.label("updated_at"),
        )
        if tenant_id is not None:
            latest_stmt = latest_stmt.where(
                IncidentProjectionRecord.tenant_id == self._require("tenant_id", tenant_id)
            )
        if incident_id:
            parsed_incident_id = self._parse_uuid(incident_id)
            if parsed_incident_id is None:
                return []
            latest_stmt = latest_stmt.where(IncidentProjectionRecord.incident_id == parsed_incident_id)
        if incident_ids is not None:
            if not incident_ids:
                return []
            latest_stmt = latest_stmt.where(IncidentProjectionRecord.incident_id.in_(incident_ids))
        if risk_tier:
            latest_stmt = latest_stmt.where(
                IncidentProjectionRecord.risk_tier == str(risk_tier).strip().lower()
            )
        if execution_mode:
            latest_stmt = latest_stmt.where(
                IncidentProjectionRecord.execution_mode == str(execution_mode).strip().lower()
            )
        if transport_provider:
            latest_stmt = latest_stmt.where(
                IncidentProjectionRecord.transport_provider == str(transport_provider).strip().lower()
            )
        if service:
            latest_stmt = latest_stmt.where(IncidentProjectionRecord.service == str(service).strip())
        # Status is intentionally filtered after lifecycle reduction below. The
        # projection value can lag a newer approval or remediation action, and
        # filtering it here would make the summary omit incidents whose visible
        # canonical status matches the requested filter.
        query_limit = min(200, safe_limit * 2) if status else safe_limit
        latest = latest_stmt.order_by(IncidentProjectionRecord.updated_at.desc()).limit(query_limit).subquery()
        stmt = (
            select(IncidentProjectionRecord)
            .join(latest, IncidentProjectionRecord.incident_id == latest.c.incident_id)
            .order_by(latest.c.updated_at.desc())
        )
        if not include_enrichment:
            # Inbox/dashboard reads must never hydrate multi-megabyte context
            # JSON for every row. The opened incident performs a separate,
            # exact enriched read.
            stmt = stmt.options(
                load_only(
                    IncidentProjectionRecord.incident_id,
                    IncidentProjectionRecord.alert_id,
                    IncidentProjectionRecord.trace_id,
                    IncidentProjectionRecord.recommendation_id,
                    IncidentProjectionRecord.flow_id,
                    IncidentProjectionRecord.tenant_id,
                    IncidentProjectionRecord.service,
                    IncidentProjectionRecord.environment,
                    IncidentProjectionRecord.severity,
                    IncidentProjectionRecord.status,
                    IncidentProjectionRecord.lifecycle_state,
                    IncidentProjectionRecord.lifecycle_version,
                    IncidentProjectionRecord.owner,
                    IncidentProjectionRecord.risk_tier,
                    IncidentProjectionRecord.execution_mode,
                    IncidentProjectionRecord.requires_approval,
                    IncidentProjectionRecord.policy_version,
                    IncidentProjectionRecord.policy_reason,
                    IncidentProjectionRecord.transport_provider,
                    IncidentProjectionRecord.latest_event_id,
                    IncidentProjectionRecord.latest_event_type,
                    IncidentProjectionRecord.latest_event_at,
                    IncidentProjectionRecord.first_seen_at,
                    IncidentProjectionRecord.document_available,
                    IncidentProjectionRecord.updated_at,
                )
            )
        result = await self.session.execute(stmt)
        rows = result.scalars().all()

        ticket_by_incident: dict[UUID, str] = {}
        canonical_status_by_incident: dict[UUID, str] = {}
        canonical_updated_at_by_incident: dict[UUID, datetime] = {}
        canonical_alert_by_incident: dict[UUID, UUID] = {}
        canonical_lifecycle_by_incident: dict[UUID, dict[str, Any]] = {}
        projection_incident_ids = [row.incident_id for row in rows]
        if projection_incident_ids:
            ticket_result = await self.session.execute(
                select(IncidentRecord.id, IncidentRecord.ticket_id, IncidentRecord.status, IncidentRecord.updated_at,
                       IncidentRecord.payload[("metadata", "resolution_lifecycle")]).where(
                    IncidentRecord.id.in_(projection_incident_ids),
                    IncidentRecord.tenant_id == tenant_id if tenant_id is not None else True
                )
            )
            incident_rows = ticket_result.all()
            ticket_by_incident = {
                incident_id: str(ticket_id).strip()
                for incident_id, ticket_id, _incident_status, _updated_at, _lifecycle in incident_rows
                if str(ticket_id or "").strip()
            }
            canonical_status_by_incident = {
                incident_id: str(incident_status).strip().lower()
                for incident_id, _ticket_id, incident_status, _updated_at, _lifecycle in incident_rows
                if str(incident_status or "").strip()
            }
            canonical_updated_at_by_incident = {
                incident_id: updated_at
                for incident_id, _ticket_id, _incident_status, updated_at, _lifecycle in incident_rows
                if updated_at is not None
            }
            canonical_lifecycle_by_incident = {
                incident_id: lifecycle for incident_id, _ticket, _status, _updated, lifecycle in incident_rows
                if isinstance(lifecycle, dict)
            }
            # Older projections predate the alert_id projection column, while
            # their immutable incident events still retain the canonical alert
            # relationship. Recover it in the read model so every incident
            # opens the same guided cockpit without rewriting production data.
            alert_event_result = await self.session.execute(
                select(IncidentEventRecord.incident_id, IncidentEventRecord.alert_id)
                .where(
                    IncidentEventRecord.incident_id.in_([row.incident_id for row in rows if row.alert_id is None]),
                    IncidentEventRecord.alert_id.is_not(None),
                )
                .order_by(IncidentEventRecord.created_at.desc())
            )
            for incident_id, alert_id in alert_event_result.all():
                if alert_id is not None:
                    canonical_alert_by_incident.setdefault(incident_id, alert_id)

        pending_by_incident: dict[UUID, PendingWorkflowRecord] = {}
        missing_context_incidents = [
            row.incident_id
            for row in rows
            if row.recommendation_id is None or not str(row.flow_id or "").strip()
        ]
        if missing_context_incidents:
            pending_result = await self.session.execute(
                select(PendingWorkflowRecord).where(PendingWorkflowRecord.incident_id.in_(missing_context_incidents))
                .options(load_only(PendingWorkflowRecord.incident_id,
                                   PendingWorkflowRecord.recommendation_id, PendingWorkflowRecord.flow_id))
            )
            pending_rows = pending_result.scalars().all()
            pending_by_incident = {pending.incident_id: pending for pending in pending_rows}

        action_by_incident: dict[UUID, ActionRecord] = {}
        incident_ids = [row.incident_id for row in rows]
        if incident_ids:
            action_stmt = (
                select(ActionRecord)
                .where(ActionRecord.incident_id.in_(incident_ids))
                .order_by(ActionRecord.updated_at.desc(), ActionRecord.created_at.desc())
            )
            if not include_enrichment:
                action_stmt = action_stmt.options(
                    load_only(
                        ActionRecord.id,
                        ActionRecord.incident_id,
                        ActionRecord.status,
                        ActionRecord.updated_at,
                        ActionRecord.created_at,
                    )
                )
            action_result = await self.session.execute(action_stmt)
            for action in action_result.scalars().all():
                action_by_incident.setdefault(action.incident_id, action)

        approval_by_incident: dict[UUID, ApprovalRecord] = {}
        if incident_ids:
            approval_result = await self.session.execute(
                select(ApprovalRecord)
                .where(ApprovalRecord.incident_id.in_(incident_ids))
                .order_by(ApprovalRecord.updated_at.desc(), ApprovalRecord.created_at.desc())
                .options(
                    load_only(
                        ApprovalRecord.id,
                        ApprovalRecord.incident_id,
                        ApprovalRecord.decision,
                        ApprovalRecord.updated_at,
                        ApprovalRecord.created_at,
                    )
                )
            )
            for approval in approval_result.scalars().all():
                approval_by_incident.setdefault(approval.incident_id, approval)

        evaluation_by_incident: dict[UUID, EvaluationRecord] = {}
        if include_enrichment and incident_ids:
            evaluation_result = await self.session.execute(
                select(EvaluationRecord)
                .where(EvaluationRecord.incident_id.in_(incident_ids))
                .order_by(EvaluationRecord.created_at.desc())
            )
            for evaluation in evaluation_result.scalars().all():
                evaluation_by_incident.setdefault(evaluation.incident_id, evaluation)

        source_alert_by_id: dict[UUID, dict[str, Any]] = {}
        if incident_ids:
            source_alert_ids = {
                row.alert_id or canonical_alert_by_incident.get(row.incident_id)
                for row in rows
                if row.alert_id is not None or canonical_alert_by_incident.get(row.incident_id) is not None
            }
            if source_alert_ids:
                compact_labels_by_id: dict[UUID, dict[str, Any]] = {}
                if not include_enrichment:
                    # Keep the affected resource on compact lists without loading
                    # full context/evidence JSON. Dropping labels made different
                    # endpoint investigations appear to be duplicate alerts.
                    identity_keys = ("operation", "http_route", "route", "method", "http_method",
                                     "job", "instance", "mountpoint", "device", "monitoring_scope",
                                     "synthetic", "event_mode", "event_authenticity")
                    identity_result = await self.session.execute(select(
                        AlertRecord.id,
                        *[AlertRecord.payload["labels"][key].as_string().label(key) for key in identity_keys],
                    ).where(AlertRecord.id.in_(source_alert_ids)))
                    compact_labels_by_id = {
                        values[0]: {key: value for key, value in zip(identity_keys, values[1:])
                                    if value not in (None, "")}
                        for values in identity_result.all()
                    }
                source_alert_stmt = select(AlertRecord).where(AlertRecord.id.in_(source_alert_ids))
                if not include_enrichment:
                    source_alert_stmt = source_alert_stmt.options(load_only(
                        AlertRecord.id, AlertRecord.source, AlertRecord.name, AlertRecord.service,
                        AlertRecord.environment, AlertRecord.severity, AlertRecord.fingerprint,
                        AlertRecord.correlation_id, AlertRecord.inbox_project,
                    ))
                source_alert_result = await self.session.execute(source_alert_stmt)
                for alert_record in source_alert_result.scalars().all():
                    alert_payload = (
                        dict(alert_record.payload)
                        if include_enrichment and isinstance(alert_record.payload, dict)
                        else {"project_id": alert_record.inbox_project,
                              "labels": compact_labels_by_id.get(alert_record.id, {})} if not include_enrichment else {}
                    )
                    alert_payload.setdefault("id", str(alert_record.id))
                    alert_payload.setdefault("source", alert_record.source)
                    alert_payload.setdefault("name", alert_record.name)
                    alert_payload.setdefault("service", alert_record.service)
                    alert_payload.setdefault("environment", alert_record.environment)
                    alert_payload.setdefault("severity", alert_record.severity)
                    alert_payload.setdefault("fingerprint", alert_record.fingerprint)
                    alert_payload.setdefault("correlation_id", alert_record.correlation_id)
                    source_alert_by_id[alert_record.id] = alert_payload

        historical_context_event_by_incident: dict[UUID, dict[str, Any]] = {}
        if include_enrichment and incident_ids:
            historical_context_result = await self.session.execute(
                select(IncidentEventRecord.incident_id, IncidentEventRecord.payload)
                .where(
                    IncidentEventRecord.incident_id.in_(incident_ids),
                    IncidentEventRecord.event_type == "incident.context.collected",
                )
                .order_by(IncidentEventRecord.created_at.desc())
            )
            for historical_incident_id, historical_payload in historical_context_result.all():
                if isinstance(historical_payload, dict):
                    historical_context_event_by_incident.setdefault(
                        historical_incident_id,
                        dict(historical_payload),
                    )

        recommendation_by_id: dict[UUID, dict[str, Any]] = {}
        recommendation_ids = [row.recommendation_id for row in rows if row.recommendation_id is not None]
        if include_enrichment and recommendation_ids:
            recommendation_result = await self.session.execute(
                select(AuditLogRecord).where(
                    AuditLogRecord.id.in_(recommendation_ids),
                    AuditLogRecord.action == "recommendation.generated",
                )
            )
            recommendation_by_id = {
                record.id: dict(record.payload or {})
                for record in recommendation_result.scalars().all()
            }

        # Keep completed RCA outcomes visible in compact lists without loading
        # full evidence, traces, or recommendation payloads for every incident.
        analysis_by_id: dict[UUID, dict[str, Any]] = {}
        if recommendation_ids:
            analysis_result = await self.session.execute(
                select(
                    AuditLogRecord.id,
                    AuditLogRecord.payload[('metadata', 'rca_status')],
                    AuditLogRecord.payload[('metadata', 'iterative_investigation', 'outcome')],
                    AuditLogRecord.payload[('metadata', 'iterative_investigation', 'completed_at')],
                    AuditLogRecord.payload[('metadata', 'execution_plan', 'readiness_blocks')],
                    AuditLogRecord.payload[('metadata', 'iterative_investigation', 'rca_result', 'missing_evidence')],
                ).where(
                    AuditLogRecord.id.in_(recommendation_ids),
                    AuditLogRecord.tenant_id == tenant_id,
                    AuditLogRecord.action == "recommendation.generated",
                ).with_hint(AuditLogRecord, "FORCE INDEX (PRIMARY)", dialect_name="mysql")
            )
            for rec_id, rca_status, outcome, completed_at, blockers, missing in analysis_result.all():
                analysis_by_id[rec_id] = {
                    "rca_status": rca_status, "outcome": outcome,
                    "completed_at": completed_at,
                    "blockers": blockers if isinstance(blockers, list) else [],
                    "missing_evidence": missing if isinstance(missing, list) else [],
                }

        context_snapshot_by_id: dict[str, ContextSnapshotRecord] = {}
        referenced_snapshot_ids: set[UUID] = set()
        for recommendation_payload in recommendation_by_id.values():
            metadata = (
                recommendation_payload.get("metadata")
                if isinstance(recommendation_payload.get("metadata"), dict)
                else {}
            )
            snapshot_uuid = self._parse_uuid(metadata.get("context_snapshot_id"))
            if snapshot_uuid is not None:
                referenced_snapshot_ids.add(snapshot_uuid)
        if include_enrichment and referenced_snapshot_ids:
            context_snapshot_result = await self.session.execute(
                select(ContextSnapshotRecord).where(ContextSnapshotRecord.snapshot_id.in_(referenced_snapshot_ids))
            )
            context_snapshot_by_id = {
                str(snapshot.snapshot_id): snapshot for snapshot in context_snapshot_result.scalars().all()
            }

        response_rows: list[dict[str, Any]] = []
        for row in rows:
            canonical_alert_id = row.alert_id or canonical_alert_by_incident.get(row.incident_id)
            # An immutable incident event can outlive (or predate) its durable
            # AlertRecord.  Such an identity is useful provenance, but it is
            # not a navigable alert contract: processed-result and analysis
            # regeneration are both keyed by a tenant-scoped AlertRecord.
            # Never advertise a dead alert link from incident metadata.
            navigable_alert_id = (
                canonical_alert_id
                if canonical_alert_id is not None and canonical_alert_id in source_alert_by_id
                else None
            )
            pending = pending_by_incident.get(row.incident_id)
            merged_recommendation_id = row.recommendation_id or (pending.recommendation_id if pending is not None else None)
            recommendation_payload = recommendation_by_id.get(merged_recommendation_id, {})
            recommendation_metadata = (
                recommendation_payload.get("metadata")
                if isinstance(recommendation_payload.get("metadata"), dict)
                else {}
            )
            merged_flow_id = row.flow_id or (pending.flow_id if pending is not None else None)
            projection_payload = dict(row.projection_payload or {}) if include_enrichment else {}
            if recommendation_payload:
                for stale_context_key in ("context", "context_metadata", "context_snapshot"):
                    projection_payload.pop(stale_context_key, None)
            if navigable_alert_id is not None:
                projection_payload["alert_id"] = str(navigable_alert_id)
            else:
                projection_payload.pop("alert_id", None)
            event_payload = (
                projection_payload.get("event_payload")
                if isinstance(projection_payload.get("event_payload"), dict)
                else {}
            )
            historical_context_event = (
                historical_context_event_by_incident.get(row.incident_id, {})
                if not recommendation_payload
                else {}
            )
            event_context = (
                event_payload.get("context")
                if isinstance(event_payload.get("context"), dict)
                else historical_context_event.get("context")
                if isinstance(historical_context_event.get("context"), dict)
                else {}
            )
            if event_context:
                projection_payload.setdefault("context", event_context)
            historical_context_metadata = historical_context_event.get("context_metadata")
            if isinstance(historical_context_metadata, dict) and historical_context_metadata:
                projection_payload.setdefault("context_metadata", historical_context_metadata)
            historical_context_snapshot = historical_context_event.get("context_snapshot")
            if isinstance(historical_context_snapshot, dict) and historical_context_snapshot:
                projection_payload.setdefault("context_snapshot", historical_context_snapshot)
            event_context_alert = (
                event_context.get("alert")
                if isinstance(event_context.get("alert"), dict)
                else {}
            )
            durable_source_alert = source_alert_by_id.get(canonical_alert_id, {}) if canonical_alert_id else {}
            if durable_source_alert:
                projection_payload["source_alert"] = durable_source_alert
            elif event_context_alert:
                projection_payload.setdefault("source_alert", event_context_alert)
            bound_snapshot_id = str(recommendation_metadata.get("context_snapshot_id") or "").strip()
            context_snapshot = context_snapshot_by_id.get(bound_snapshot_id)
            binding_status = "not_applicable"
            if recommendation_payload:
                binding_status = "missing_snapshot_reference" if not bound_snapshot_id else "snapshot_not_found"
            if context_snapshot is not None:
                if context_snapshot.tenant_id != row.tenant_id or str(context_snapshot.incident_id) != str(
                    row.incident_id
                ):
                    context_snapshot = None
                    binding_status = "identity_mismatch"
                elif str(context_snapshot.context_fingerprint) != str(
                    recommendation_metadata.get("context_fingerprint") or ""
                ):
                    context_snapshot = None
                    binding_status = "fingerprint_mismatch"
                else:
                    binding_status = "verified"
            if context_snapshot is not None:
                snapshot_context = (
                    dict(context_snapshot.payload)
                    if isinstance(context_snapshot.payload, dict)
                    else {}
                )
                if snapshot_context:
                    projection_payload["context"] = snapshot_context
                    snapshot_metadata = (
                        snapshot_context.get("metadata")
                        if isinstance(snapshot_context.get("metadata"), dict)
                        else {}
                    )
                    if snapshot_metadata:
                        projection_payload["context_metadata"] = snapshot_metadata
                projection_payload["context_snapshot"] = {
                    "snapshot_id": str(context_snapshot.snapshot_id),
                    "source_incident_id": context_snapshot.source_incident_id,
                    "context_fingerprint": context_snapshot.context_fingerprint,
                    "contract_version": context_snapshot.contract_version,
                    "quality_score": float(context_snapshot.quality_score or 0.0),
                    "reusable": bool(context_snapshot.reusable),
                    "source_manifest": context_snapshot.source_manifest or {},
                    "collected_at": context_snapshot.collected_at,
                    "expires_at": context_snapshot.expires_at,
                }
            projection_payload["investigation_integrity"] = {
                "status": binding_status,
                "verified": binding_status == "verified",
                "recommendation_id": str(merged_recommendation_id) if merged_recommendation_id else None,
                "context_snapshot_id": bound_snapshot_id or None,
            }
            evaluation = evaluation_by_incident.get(row.incident_id)
            if evaluation is not None:
                evaluation_payload = dict(evaluation.report_payload or {})
                projection_payload.setdefault("evaluation", evaluation_payload)
                projection_payload.setdefault(
                    "quality",
                    {
                        "overall_score": evaluation.overall_score,
                        "quality_label": evaluation.quality_label,
                        "requires_review": evaluation.requires_review,
                    },
                )
            action = action_by_incident.get(row.incident_id)
            approval_record = approval_by_incident.get(row.incident_id)
            canonical_status = canonical_status_by_incident.get(row.incident_id, "")
            if action is not None:
                action_status = str(action.status or "").lower()
                if include_enrichment:
                    projection_payload["remediation_action"] = action.payload or {}
                projection_payload["remediation_status"] = action_status

            action_payload = action.payload if include_enrichment and action is not None and isinstance(action.payload, dict) else {}
            lifecycle_candidates = (
                canonical_lifecycle_by_incident.get(row.incident_id),
                event_payload.get("resolution_lifecycle"),
                (action_payload.get("parameters") or {}).get("resolution_lifecycle") if isinstance(action_payload.get("parameters"), dict) else None,
                (action_payload.get("metadata") or {}).get("resolution_lifecycle") if isinstance(action_payload.get("metadata"), dict) else None,
            )
            resolution_lifecycle = select_current_lifecycle(
                *({"resolution_lifecycle": item} for item in lifecycle_candidates if isinstance(item, dict))
            )
            if resolution_lifecycle:
                projection_payload["resolution_lifecycle"] = resolution_lifecycle

            if recommendation_payload:
                # The projection stores the latest lifecycle event, while the
                # full RCA/recommendation is durably stored in the audit log.
                # Rejoin it into the read model so UI consumers do not have to
                # reconstruct a report from whichever event happened last.
                resolution_selection = (
                    projection_payload.get("resolution_selection")
                    if isinstance(projection_payload.get("resolution_selection"), dict)
                    else {}
                )
                compiled_plan = (
                    projection_payload.get("execution_plan")
                    if isinstance(projection_payload.get("execution_plan"), dict)
                    and projection_payload["execution_plan"].get("schema_version") == "kaims.execution-plan.v2"
                    else {}
                )
                if resolution_selection or compiled_plan:
                    recommendation_payload = dict(recommendation_payload)
                    hydrated_metadata = (
                        dict(recommendation_payload.get("metadata"))
                        if isinstance(recommendation_payload.get("metadata"), dict)
                        else {}
                    )
                    if resolution_selection:
                        hydrated_metadata["resolution_selection"] = resolution_selection
                    if compiled_plan:
                        hydrated_metadata["execution_plan"] = compiled_plan
                        hydrated_metadata["governed_resolution_plan"] = compiled_plan
                    else:
                        hydrated_metadata.pop("execution_plan", None)
                        hydrated_metadata.pop("execution_plan", None)
                        hydrated_metadata.pop("governed_resolution_plan", None)
                    recommendation_payload["metadata"] = hydrated_metadata
                projection_payload["recommendation"] = recommendation_payload
            elif any(
                event_payload.get(key) is not None
                for key in ("recommended_action", "root_cause", "impact", "risk")
            ):
                projection_payload.setdefault(
                    "recommendation",
                    {
                        "id": event_payload.get("recommendation_id"),
                        "recommended_action": event_payload.get("recommended_action"),
                        "root_cause": event_payload.get("root_cause"),
                        "impact": event_payload.get("impact"),
                        "risk": event_payload.get("risk"),
                        "confidence": event_payload.get("confidence"),
                    },
                )
            orchestration_path = (
                recommendation_metadata.get("orchestration_path")
                if isinstance(recommendation_metadata.get("orchestration_path"), dict)
                else {}
            )
            if not orchestration_path:
                lifecycle_control = (
                    resolution_lifecycle.get("control")
                    if isinstance(resolution_lifecycle, dict) and isinstance(resolution_lifecycle.get("control"), dict)
                    else {}
                )
                disposition = str(lifecycle_control.get("disposition") or "").strip().lower()
                analysis_reused = recommendation_metadata.get("analysis_reused") is True
                diagnostic = "diagnostic" in str(row.execution_mode or "").lower() or disposition in {"watch_only", "investigate"}
                path_id = "diagnostic" if diagnostic else "guided_reuse" if analysis_reused and row.requires_approval else "verified_fast_path" if analysis_reused else "guided" if row.requires_approval else "autonomous"
                labels = {
                    "diagnostic": "Diagnostic completion",
                    "guided_reuse": "Reused analysis with approval",
                    "verified_fast_path": "Verified context fast path",
                    "guided": "Fresh analysis guided path",
                    "autonomous": "Fresh analysis autonomous path",
                }
                orchestration_path = {
                    "schema_version": "kaims.orchestration-path.v1",
                    "id": path_id,
                    "label": labels[path_id],
                    "context_reused": bool(recommendation_metadata.get("context_reused")),
                    "analysis_reused": analysis_reused,
                    "disposition": disposition or ("investigate" if diagnostic else "approval_required" if row.requires_approval else "execution_ready"),
                    "skipped_stages": ["approval", "execution"] if diagnostic else ["context_collection", "rca_generation"] if analysis_reused else ["approval"] if not row.requires_approval else [],
                    "derived_for_legacy_record": True,
                }
            projection_payload["orchestration_path"] = orchestration_path

            approval_payload = projection_payload.get("approval") if isinstance(projection_payload.get("approval"), dict) else {}
            approval_event_payload = projection_payload.get("event_payload") if isinstance(projection_payload.get("event_payload"), dict) else {}
            approval_event_decision = (
                approval_event_payload.get("decision")
                if str(row.latest_event_type or "").strip().lower() == "incident.approval.recorded"
                else None
            )
            approval_status = str(
                (approval_record.decision if approval_record is not None else None)
                or projection_payload.get("approval_status")
                or approval_payload.get("status")
                or approval_payload.get("decision")
                or approval_event_decision
                or ""
            ).strip().lower().replace("-", "_").replace(" ", "_")
            closure_report = event_payload.get("report") if isinstance(event_payload.get("report"), dict) else {}
            closure_metadata = (
                closure_report.get("metadata")
                if isinstance(closure_report.get("metadata"), dict)
                else {}
            )
            lifecycle_validation = (
                resolution_lifecycle.get("validation")
                if isinstance(resolution_lifecycle, dict)
                and isinstance(resolution_lifecycle.get("validation"), dict)
                else {}
            )
            closure_kind = str(closure_metadata.get("closure_kind") or lifecycle_validation.get("closure_kind") or "").strip().lower()
            if not closure_kind and lifecycle_validation.get("administrative_disposition") is True:
                closure_kind = "manual"
            if not closure_kind and str((resolution_lifecycle or {}).get("reason_code") or "").strip().lower() == "watch_only_policy_completed":
                closure_kind = "diagnostic"
            _lifecycle_state_status_map = {
                "WAITING_FOR_HUMAN": "waiting_for_human",
                "RCA_READY": "rca_ready",
                "PLAN_READY": "plan_ready",
                "AWAITING_APPROVAL": "awaiting_approval",
                "EXECUTING": "remediating",
                "VALIDATING": "validating",
                "CLOSED": "closed",
                "COLLECTION_BLOCKED": "failed",
                "INVESTIGATION_FAILED": "failed",
                "EXECUTION_FAILED": "failed",
                "VALIDATION_FAILED": "failed",
                "ESCALATED": "failed",
            }
            raw_projection_status = str(row.status or "").strip().lower()
            mapped_lifecycle_status = _lifecycle_state_status_map.get(
                str(getattr(row, "lifecycle_state", "") or "").strip().upper()
            )
            effective_projection_status = (
                mapped_lifecycle_status
                if raw_projection_status in {"", "open", "investigating", "detected"} and mapped_lifecycle_status
                else row.status
            )
            lifecycle_status = reduce_incident_status(
                projection_status=effective_projection_status,
                projection_updated_at=row.updated_at,
                canonical_status=canonical_status,
                canonical_updated_at=canonical_updated_at_by_incident.get(row.incident_id),
                approval_status=approval_status,
                approval_updated_at=approval_record.updated_at if approval_record is not None else None,
                action_status=action.status if action is not None else None,
                action_updated_at=action.updated_at if action is not None else None,
                closure_kind=closure_kind,
                lifecycle_state=getattr(row, "lifecycle_state", None),
            )
            projected_status = lifecycle_status["status"]
            projection_payload["status"] = projected_status
            projection_payload["status_source"] = lifecycle_status["source"]
            projection_payload["status_reason"] = lifecycle_status["reason"]

            ticket_id = ticket_by_incident.get(row.incident_id) or projection_payload.get("ticket_id")

            import os
            jira_base = str(os.environ.get("JIRA_URL") or os.environ.get("JIRA_API_BASE_URL") or "").rstrip("/")
            jira_link = f"{jira_base}/browse/{ticket_id}" if (ticket_id and jira_base) else None

            status_lower = str(projected_status or "").strip().lower()
            if status_lower in {"closed", "resolved", "done"}:
                jira_status = "Done"
            elif status_lower in {"pending", "awaiting_approval"}:
                jira_status = "Awaiting Approval"
            else:
                jira_status = "In Progress"

            projection_payload["ticket_id"] = ticket_id or None
            projection_payload["jira_link"] = jira_link
            projection_payload["jira_status"] = jira_status
            projection_payload["jira_key"] = ticket_id or None
            projection_payload["jira_url"] = jira_link

            normalized_context = (
                projection_payload.get("context")
                if isinstance(projection_payload.get("context"), dict)
                else {}
            )
            normalized_source_alert = (
                projection_payload.get("source_alert")
                if isinstance(projection_payload.get("source_alert"), dict)
                else {}
            )
            normalized_recommendation = (
                projection_payload.get("recommendation")
                if isinstance(projection_payload.get("recommendation"), dict)
                else {}
            )
            source_labels = (
                normalized_source_alert.get("labels")
                if isinstance(normalized_source_alert.get("labels"), dict)
                else {}
            )
            source_annotations = (
                normalized_source_alert.get("annotations")
                if isinstance(normalized_source_alert.get("annotations"), dict)
                else {}
            )
            source_metadata = (
                normalized_source_alert.get("metadata")
                if isinstance(normalized_source_alert.get("metadata"), dict)
                else {}
            )
            deduplication = (
                source_metadata.get("deduplication")
                if isinstance(source_metadata.get("deduplication"), dict)
                else {}
            )
            root_cause = next(
                (
                    str(value).strip()
                    for value in (
                        normalized_recommendation.get("root_cause"),
                        event_payload.get("root_cause"),
                        projection_payload.get("root_cause"),
                        source_annotations.get("root_cause"),
                    )
                    if str(value or "").strip()
                ),
                None,
            )
            customer_impact = next(
                (
                    str(value).strip()
                    for value in (
                        normalized_recommendation.get("impact"),
                        event_payload.get("impact"),
                        projection_payload.get("customer_impact"),
                        projection_payload.get("business_impact"),
                        source_annotations.get("business_impact"),
                        source_annotations.get("summary"),
                        normalized_source_alert.get("description"),
                    )
                    if str(value or "").strip()
                ),
                None,
            )
            confidence = next(
                (
                    value
                    for value in (
                        normalized_recommendation.get("confidence"),
                        event_payload.get("confidence"),
                        projection_payload.get("confidence"),
                    )
                    if value is not None
                ),
                None,
            )
            deduplicated_count = next(
                (
                    value
                    for value in (
                        normalized_source_alert.get("deduplicated_count"),
                        normalized_source_alert.get("occurrence_count"),
                        event_context_alert.get("deduplicated_count"),
                        event_context_alert.get("occurrence_count"),
                    )
                    if value is not None
                ),
                None,
            )
            deduplication_reason = (
                deduplication.get("reason")
                or deduplication.get("disposition")
                or deduplication.get("match_type")
            )
            if not deduplication_reason:
                try:
                    if int(deduplicated_count or 0) > 1:
                        deduplication_reason = "Correlated monitoring occurrences"
                except (TypeError, ValueError):
                    pass
            source_name = next(
                (
                    str(value).strip()
                    for value in (
                        normalized_source_alert.get("source"),
                        source_labels.get("origin_system"),
                        source_labels.get("transport"),
                    )
                    if str(value or "").strip()
                ),
                None,
            )
            origin_system = next(
                (
                    str(value).strip()
                    for value in (
                        source_labels.get("origin_system"),
                        normalized_source_alert.get("origin_system"),
                        source_name,
                    )
                    if str(value or "").strip()
                ),
                None,
            )
            summary = next(
                (
                    str(value).strip()
                    for value in (
                        source_annotations.get("summary"),
                        normalized_source_alert.get("summary"),
                        normalized_source_alert.get("description"),
                        customer_impact,
                    )
                    if str(value or "").strip()
                ),
                None,
            )
            if include_enrichment:
                response_projection_payload = projection_payload
                response_context = normalized_context
                response_context_snapshot = projection_payload.get("context_snapshot")
                response_source_alert = normalized_source_alert
                response_recommendation = normalized_recommendation
            else:
                compact_projection_keys = {
                    "alert_id",
                    "approval_status",
                    "event_stage",
                    "event_type",
                    "flow_id",
                    "jira_key",
                    "jira_link",
                    "jira_status",
                    "jira_url",
                    "orchestration_path",
                    "remediation_status",
                    "resolution_lifecycle",
                    "status",
                    "status_reason",
                    "status_source",
                    "ticket_id",
                    "transport_channel",
                }
                response_projection_payload = {
                    key: value
                    for key, value in projection_payload.items()
                    if key in compact_projection_keys
                }
                if normalized_context:
                    compact_context_metadata = (
                        normalized_context.get("metadata")
                        if isinstance(normalized_context.get("metadata"), dict)
                        else {}
                    )
                    response_projection_payload["context_metadata"] = {
                        "available": True,
                        "contract_version": compact_context_metadata.get("contract_version"),
                        "recovered": compact_context_metadata.get("recovered") is True,
                    }
                response_context = {}
                response_context_snapshot = None
                response_source_alert = {"labels": source_labels} if source_labels else {}
                response_recommendation = {}

            response_rows.append(
                {
                    "incident_id": str(row.incident_id),
                    "alert_id": str(navigable_alert_id) if navigable_alert_id else None,
                    "trace_id": row.trace_id,
                    "recommendation_id": str(merged_recommendation_id) if merged_recommendation_id else None,
                    "analysis_summary": analysis_by_id.get(merged_recommendation_id, {}),
                    "flow_id": merged_flow_id,
                    "tenant_id": row.tenant_id,
                    "service": row.service,
                    "environment": row.environment,
                    "severity": row.severity,
                    "status": projected_status,
                    "lifecycle_state": getattr(row, "lifecycle_state", None),
                    "status_source": lifecycle_status["source"],
                    "status_reason": lifecycle_status["reason"],
                    "approval_status": approval_status or None,
                    "owner": row.owner,
                    "risk_tier": row.risk_tier,
                    "execution_mode": row.execution_mode,
                    "requires_approval": row.requires_approval,
                    "policy_version": row.policy_version,
                    "policy_reason": row.policy_reason,
                    "resolution_lifecycle": resolution_lifecycle,
                    "orchestration_path": orchestration_path,
                    "transport_provider": row.transport_provider,
                    "latest_event_id": str(row.latest_event_id) if row.latest_event_id else None,
                    "latest_event_type": row.latest_event_type,
                    "latest_event_at": row.latest_event_at,
                    "created_at": row.first_seen_at,
                    "updated_at": row.updated_at,
                    "ticket_id": ticket_id or None,
                    "jira_link": jira_link,
                    "jira_status": jira_status,
                    "jira_key": ticket_id or None,
                    "jira_url": jira_link,
                    "title": normalized_source_alert.get("name") or source_labels.get("alertname") or summary,
                    "operation": source_labels.get("operation") or source_labels.get("http_route") or source_labels.get("route"),
                    "summary": summary,
                    "source": source_name,
                    "origin_system": origin_system,
                    # Keep the durable alert identity available on compact incident
                    # responses.  The inbox uses these fields to collapse historical
                    # projections that were created for the same correlated signal.
                    "fingerprint": normalized_source_alert.get("fingerprint"),
                    "correlation_id": normalized_source_alert.get("correlation_id"),
                    "deduplicated_count": deduplicated_count,
                    "deduplication_reason": deduplication_reason,
                    "customer_impact": customer_impact,
                    "root_cause": root_cause,
                    "confidence": confidence,
                    "context": response_context,
                    "context_snapshot": response_context_snapshot,
                    "source_alert": response_source_alert,
                    "recommendation": response_recommendation,
                    "investigation_integrity": projection_payload.get("investigation_integrity"),
                    "execution_plan": projection_payload.get("execution_plan"),
                    "governed_resolution_plan": projection_payload.get("execution_plan"),
                    "projection_payload": response_projection_payload,
                }
            )

        if status:
            requested_status = str(status).strip().lower().replace("-", "_").replace(" ", "_")
            response_rows = [
                item
                for item in response_rows
                if str(item.get("status") or "").strip().lower().replace("-", "_").replace(" ", "_")
                == requested_status
            ]
        return response_rows[:safe_limit]

    async def list_closed_incidents(
        self,
        *,
        limit: int = 100,
        tenant_id: str,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 1000))
        normalized_tenant_id = self._require("tenant_id", tenant_id)
        stmt = (
            select(
                IncidentProjectionRecord.incident_id,
                IncidentProjectionRecord.alert_id,
                IncidentProjectionRecord.trace_id,
                IncidentProjectionRecord.recommendation_id,
                IncidentProjectionRecord.flow_id,
                IncidentProjectionRecord.service,
                IncidentProjectionRecord.environment,
                IncidentProjectionRecord.severity,
                IncidentProjectionRecord.status,
                IncidentProjectionRecord.risk_tier,
                IncidentProjectionRecord.execution_mode,
                IncidentProjectionRecord.transport_provider,
                IncidentProjectionRecord.first_seen_at,
                IncidentProjectionRecord.latest_event_at,
                IncidentProjectionRecord.updated_at,
                IncidentProjectionRecord.projection_payload,
            )
            # This endpoint feeds closure/MTTR reporting. Failed incidents are
            # unresolved terminal attempts and must not be counted as closures.
            .where(
                IncidentProjectionRecord.status.in_(["closed", "resolved"]),
                IncidentProjectionRecord.tenant_id == normalized_tenant_id,
            )
            .order_by(IncidentProjectionRecord.latest_event_at.desc(), IncidentProjectionRecord.incident_id.desc())
            .limit(safe_limit)
            .offset(max(0, int(offset)))
        )
        result = await self.session.execute(stmt)
        rows = result.all()

        incident_ids = [row.incident_id for row in rows]
        ticket_id_by_incident: dict[UUID, str] = {}
        if incident_ids:
            ticket_result = await self.session.execute(
                select(IncidentRecord.id, IncidentRecord.ticket_id)
                .where(
                    IncidentRecord.id.in_(incident_ids),
                    IncidentRecord.tenant_id == normalized_tenant_id,
                )
            )
            for inc_id, t_id in ticket_result.all():
                if t_id:
                    ticket_id_by_incident[inc_id] = t_id

        response_rows: list[dict[str, Any]] = []
        for row in rows:
            projection_payload = dict(row.projection_payload) if isinstance(row.projection_payload, dict) else {}
            event_payload = projection_payload.get("event_payload") if isinstance(projection_payload.get("event_payload"), dict) else {}
            source_alert = projection_payload.get("source_alert") if isinstance(projection_payload.get("source_alert"), dict) else {}
            alert_payload = event_payload.get("alert") if isinstance(event_payload.get("alert"), dict) else {}
            alert_labels = alert_payload.get("labels") if isinstance(alert_payload.get("labels"), dict) else {}
            closed_severity = next(
                (
                    str(value).strip()
                    for value in (
                        row.severity,
                        event_payload.get("severity"),
                        alert_payload.get("severity"),
                        alert_labels.get("severity"),
                        source_alert.get("severity"),
                    )
                    if str(value or "").strip()
                ),
                None,
            )

            ticket_id = ticket_id_by_incident.get(row.incident_id) or projection_payload.get("ticket_id")

            import os
            jira_base = str(os.environ.get("JIRA_URL") or os.environ.get("JIRA_API_BASE_URL") or "").rstrip("/")
            jira_link = f"{jira_base}/browse/{ticket_id}" if (ticket_id and jira_base) else None

            status_lower = str(row.status or "").strip().lower()
            if status_lower in {"closed", "resolved", "done"}:
                jira_status = "Done"
            else:
                jira_status = "In Progress"

            projection_payload["ticket_id"] = ticket_id or None
            projection_payload["jira_link"] = jira_link
            projection_payload["jira_status"] = jira_status
            projection_payload["jira_key"] = ticket_id or None
            projection_payload["jira_url"] = jira_link

            response_rows.append(
                {
                    "incident_id": str(row.incident_id),
                    "alert_id": str(row.alert_id) if row.alert_id else None,
                    "trace_id": row.trace_id,
                    "recommendation_id": str(row.recommendation_id) if row.recommendation_id else None,
                    "flow_id": row.flow_id,
                    "service": row.service,
                    "environment": row.environment,
                    "severity": closed_severity,
                    "status": row.status,
                    "risk_tier": row.risk_tier,
                    "execution_mode": row.execution_mode,
                    "transport_provider": row.transport_provider,
                    "health_restored": bool(event_payload.get("health_restored")) if "health_restored" in event_payload else None,
                    "alerts_cleared": bool(event_payload.get("alerts_cleared")) if "alerts_cleared" in event_payload else None,
                    "created_at": row.first_seen_at,
                    "closed_at": row.latest_event_at or row.updated_at,
                    "updated_at": row.updated_at,
                    "ticket_id": ticket_id or None,
                    "jira_link": jira_link,
                    "jira_status": jira_status,
                    "jira_key": ticket_id or None,
                    "jira_url": jira_link,
                    "projection_payload": projection_payload,
                }
            )
        return response_rows


class DraftPullRequestOutboxRepository:
    """Persistence boundary for bounded draft-PR delivery and reconciliation."""

    TERMINAL_STATUSES = frozenset({"completed", "dead_letter"})

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def enqueue(
        self,
        *,
        idempotency_key: str,
        tenant_id: str,
        proposal_id: UUID | str,
        request_payload: dict[str, Any],
        max_attempts: int = 3,
    ) -> tuple[str, bool]:
        normalized_key = str(idempotency_key).strip()
        normalized_tenant = require_tenant_id(tenant_id, source="draft PR outbox")
        if not normalized_key:
            raise ValueError("draft PR idempotency_key is required")
        existing = await self.session.scalar(
            select(DraftPullRequestOutboxRecord).where(
                DraftPullRequestOutboxRecord.idempotency_key == normalized_key
            ).limit(1)
        )
        if existing is not None:
            if existing.tenant_id != normalized_tenant or str(existing.proposal_id) != str(proposal_id):
                raise ValueError("draft PR idempotency key is already bound to another request")
            return str(existing.job_id), False
        job_id = uuid4()
        self.session.add(
            DraftPullRequestOutboxRecord(
                job_id=job_id,
                idempotency_key=normalized_key,
                tenant_id=normalized_tenant,
                proposal_id=UUID(str(proposal_id)),
                request_payload=request_payload,
                status="pending",
                attempts=0,
                max_attempts=max(1, min(int(max_attempts), 5)),
                next_attempt_at=utc_now(),
            )
        )
        return str(job_id), True

    async def list_due(self, *, now: datetime | None = None, limit: int = 25) -> list[DraftPullRequestOutboxRecord]:
        result = await self.session.execute(
            select(DraftPullRequestOutboxRecord).where(
                DraftPullRequestOutboxRecord.status.in_(("pending", "retry")),
                DraftPullRequestOutboxRecord.next_attempt_at <= (now or utc_now()),
            ).order_by(DraftPullRequestOutboxRecord.created_at.asc()).limit(max(1, min(int(limit), 100)))
        )
        return list(result.scalars().all())

    async def mark_completed(self, job_id: UUID | str, *, provider_response: dict[str, Any]) -> None:
        row = await self.session.get(DraftPullRequestOutboxRecord, UUID(str(job_id)))
        if row is None or row.status in self.TERMINAL_STATUSES:
            return
        row.status = "completed"
        row.attempts = int(row.attempts or 0) + 1
        row.provider_response = provider_response
        row.last_error = None
        row.completed_at = utc_now()
        self.session.add(AuditLogRecord(
            tenant_id=row.tenant_id,
            actor="draft-pr-outbox-worker",
            action="draft_pull_request.created",
            resource_type="code_patch_proposal",
            resource_id=str(row.proposal_id),
            payload={
                "job_id": str(row.job_id),
                "provider_pull_request_id": provider_response.get("provider_pull_request_id"),
                "url": provider_response.get("url"),
                "state": provider_response.get("state"),
                "attempts": row.attempts,
            },
        ))

    async def mark_failed(self, job_id: UUID | str, *, error: str, now: datetime | None = None) -> str:
        row = await self.session.get(DraftPullRequestOutboxRecord, UUID(str(job_id)))
        if row is None:
            raise ValueError("draft PR outbox job not found")
        if row.status in self.TERMINAL_STATUSES:
            return row.status
        attempts = int(row.attempts or 0) + 1
        row.attempts = attempts
        row.last_error = str(error)[:2000]
        if attempts >= int(row.max_attempts or 1):
            row.status = "dead_letter"
            action = "draft_pull_request.dead_lettered"
        else:
            row.status = "retry"
            row.next_attempt_at = (now or utc_now()) + timedelta(seconds=min(300, 2 ** attempts))
            action = "draft_pull_request.retry_scheduled"
        self.session.add(AuditLogRecord(
            tenant_id=row.tenant_id,
            actor="draft-pr-outbox-worker",
            action=action,
            resource_type="code_patch_proposal",
            resource_id=str(row.proposal_id),
            payload={"job_id": str(row.job_id), "attempts": attempts, "max_attempts": row.max_attempts},
        ))
        return row.status

    async def get_by_idempotency_key(self, idempotency_key: str, *, tenant_id: str) -> dict[str, Any] | None:
        row = await self.session.scalar(select(DraftPullRequestOutboxRecord).where(
            DraftPullRequestOutboxRecord.idempotency_key == str(idempotency_key).strip(),
            DraftPullRequestOutboxRecord.tenant_id == require_tenant_id(tenant_id, source="draft PR reconciliation"),
        ).limit(1))
        if row is None:
            return None
        return {
            "job_id": str(row.job_id), "proposal_id": str(row.proposal_id), "status": row.status,
            "attempts": row.attempts, "max_attempts": row.max_attempts,
            "provider_response": row.provider_response, "last_error": row.last_error,
            "completed_at": row.completed_at,
        }


class EvaluationRepository:
    """Persistence for AI Workbench evaluation reports.

    Kept separate from IncidentRepository so this new, additive capability
    can never change existing incident/alert/approval persistence behavior.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @staticmethod
    def _require(name: str, value: Any) -> Any:
        if value is None:
            raise ValueError(f"{name} is required")
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"{name} is required")
        return value

    @staticmethod
    def _to_uuid(value: UUID | str | None) -> UUID | None:
        if value is None:
            return None
        return value if isinstance(value, UUID) else UUID(str(value))

    @staticmethod
    def _parse_uuid(value: Any) -> UUID | None:
        if value in {None, ""}:
            return None
        if isinstance(value, UUID):
            return value
        try:
            return UUID(str(value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _row_to_dict(row: EvaluationRecord) -> dict[str, Any]:
        return {
            "id": str(row.id),
            "tenant_id": row.tenant_id,
            "expires_at": row.expires_at,
            "artifact_signature": row.artifact_signature,
            "incident_id": str(row.incident_id) if row.incident_id else None,
            "recommendation_id": str(row.recommendation_id) if row.recommendation_id else None,
            "agent": row.agent,
            "model_provider": row.model_provider,
            "model_name": row.model_name,
            "overall_score": row.overall_score,
            "quality_label": row.quality_label,
            "requires_review": row.requires_review,
            "report": row.report_payload,
            "feedback": row.feedback_payload,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    async def save_evaluation(
        self,
        *,
        report: dict[str, Any],
        agent: str,
        incident_id: UUID | str | None = None,
        recommendation_id: UUID | str | None = None,
        model_provider: str | None = None,
        model_name: str | None = None,
        evaluation_id: UUID | str | None = None,
        tenant_id: str = "default",
        expires_at: datetime | None = None,
        artifact_signature: str | None = None,
    ) -> str:
        record_id = self._to_uuid(evaluation_id) or uuid4()
        await self.session.merge(
            EvaluationRecord(
                id=record_id,
                tenant_id=self._require("tenant_id", tenant_id),
                expires_at=expires_at,
                artifact_signature=artifact_signature,
                incident_id=self._to_uuid(incident_id),
                recommendation_id=self._to_uuid(recommendation_id),
                agent=self._require("agent", agent),
                model_provider=model_provider,
                model_name=model_name,
                overall_score=report.get("overall_score"),
                quality_label=report.get("quality_label"),
                requires_review=bool(report.get("requires_review", False)),
                report_payload=report,
            )
        )
        return str(record_id)

    async def get_evaluation(self, evaluation_id: UUID | str, *, tenant_id: str = "default") -> dict[str, Any] | None:
        result = await self.session.execute(
            select(EvaluationRecord).where(
                EvaluationRecord.id == self._to_uuid(evaluation_id),
                EvaluationRecord.tenant_id == self._require("tenant_id", tenant_id),
            )
        )
        row = result.scalar_one_or_none()
        return self._row_to_dict(row) if row is not None else None

    async def list_evaluations(
        self,
        *,
        incident_id: UUID | str | None = None,
        agent: str | None = None,
        min_score: float | None = None,
        limit: int = 100,
        tenant_id: str = "default",
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 1000))
        stmt = select(EvaluationRecord).where(EvaluationRecord.tenant_id == self._require("tenant_id", tenant_id))
        if incident_id:
            stmt = stmt.where(EvaluationRecord.incident_id == self._to_uuid(incident_id))
        if agent:
            stmt = stmt.where(EvaluationRecord.agent == str(agent))
        if min_score is not None:
            stmt = stmt.where(EvaluationRecord.overall_score >= float(min_score))
        stmt = stmt.order_by(EvaluationRecord.created_at.desc()).limit(safe_limit)
        result = await self.session.execute(stmt)
        return [self._row_to_dict(row) for row in result.scalars().all()]

    async def purge_expired_evaluations(
        self,
        *,
        tenant_id: str,
        now: datetime,
        limit: int = 100,
        actor: str = "evaluation-retention-sweeper",
    ) -> list[str]:
        """Delete a bounded tenant slice while retaining non-sensitive audit evidence."""
        normalized_tenant = self._require("tenant_id", tenant_id)
        safe_limit = max(1, min(int(limit), 1000))
        result = await self.session.execute(
            select(EvaluationRecord).where(
                EvaluationRecord.tenant_id == normalized_tenant,
                EvaluationRecord.expires_at.is_not(None),
                EvaluationRecord.expires_at <= now,
            ).order_by(EvaluationRecord.expires_at.asc()).limit(safe_limit)
        )
        rows = list(result.scalars().all())
        for row in rows:
            expired_at = row.expires_at
            if expired_at is not None and expired_at.tzinfo is None:
                expired_at = expired_at.replace(tzinfo=UTC)
            await self.session.delete(row)
            self.session.add(
                AuditLogRecord(
                    tenant_id=normalized_tenant,
                    actor=self._require("audit.actor", actor),
                    action="evaluation.retention.expired",
                    resource_type="evaluation",
                    resource_id=str(row.id),
                    payload={
                        "expired_at": expired_at.isoformat() if expired_at else None,
                        "had_artifact_signature": bool(row.artifact_signature),
                    },
                )
            )
        await self.session.flush()
        return [str(row.id) for row in rows]

    async def summarize_evaluations(self, *, agent: str | None = None, limit: int = 1000) -> dict[str, Any]:
        safe_limit = max(1, min(int(limit), 5000))
        stmt = select(EvaluationRecord).order_by(EvaluationRecord.created_at.desc()).limit(safe_limit)
        if agent:
            stmt = stmt.where(EvaluationRecord.agent == str(agent))
        result = await self.session.execute(stmt)
        rows = result.scalars().all()

        total = len(rows)
        if total == 0:
            return {
                "total_evaluations": 0,
                "average_overall_score": 0.0,
                "requires_review_rate": 0.0,
                "quality_label_counts": {},
            }

        scores = [row.overall_score for row in rows if row.overall_score is not None]
        review_count = sum(1 for row in rows if row.requires_review)
        label_counts: dict[str, int] = {}
        for row in rows:
            label = row.quality_label or "unknown"
            label_counts[label] = label_counts.get(label, 0) + 1

        return {
            "total_evaluations": total,
            "average_overall_score": round(sum(scores) / len(scores), 4) if scores else 0.0,
            "requires_review_rate": round(review_count / total, 4),
            "quality_label_counts": label_counts,
        }

    async def attach_feedback_by_recommendation(
        self, recommendation_id: UUID | str, feedback: dict[str, Any]
    ) -> bool:
        """Attaches human feedback to the most recent evaluation for a recommendation.

        Returns False (not an error) when no evaluation exists for that
        recommendation yet -- e.g. evaluation-service was unreachable when
        the recommendation was generated.
        """
        result = await self.session.execute(
            select(EvaluationRecord)
            .where(EvaluationRecord.recommendation_id == self._to_uuid(recommendation_id))
            .order_by(EvaluationRecord.created_at.desc())
            .limit(1)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        row.feedback_payload = feedback
        return True

class ContextEnrichmentRepository(EvaluationRepository):
    _knowledge_draft_payload = staticmethod(IncidentRepository._knowledge_draft_payload)
    """Tenant-scoped persistence for autonomous and human evidence gaps."""

    async def enabled_reconciliation_tenants(self) -> list[str]:
        """Enumerate configured tenants plus tenants with active incident work."""
        configured = (await self.session.execute(select(OnboardingControlPlaneRecord.tenant_id).where(
            OnboardingControlPlaneRecord.status.in_(("ACTIVE", "COMPLETED", "READY")),
        ).distinct())).scalars().all()
        active = (await self.session.execute(select(IncidentProjectionRecord.tenant_id).where(
            IncidentProjectionRecord.lifecycle_state.notin_(("CLOSED",)),
            IncidentProjectionRecord.status.notin_(("closed", "resolved", "cancelled", "canceled")),
        ).distinct())).scalars().all()
        return sorted({require_tenant_id(value, source="reconciliation tenant") for value in [*configured, *active]})

    async def claim_reconciliation_lease(
        self, *, lease_key: str, owner: str, lease_seconds: int,
    ) -> bool:
        key = self._require("reconciliation.lease_key", lease_key)[:128]
        normalized_owner = self._require("reconciliation.owner", owner)[:255]
        now = datetime.now(UTC)
        dialect = self.session.get_bind().dialect.name
        values = {"lease_key": key, "version": 1, "updated_at": now}
        if dialect == "mysql":
            await self.session.execute(mysql_insert(ContextReconciliationLeaseRecord).values(**values).prefix_with("IGNORE"))
        elif dialect == "sqlite":
            await self.session.execute(sqlite_insert(ContextReconciliationLeaseRecord).values(**values).on_conflict_do_nothing(
                index_elements=[ContextReconciliationLeaseRecord.lease_key],
            ))
        row = await self.session.scalar(select(ContextReconciliationLeaseRecord).where(
            ContextReconciliationLeaseRecord.lease_key == key,
        ).with_for_update())
        if row is None:
            row = ContextReconciliationLeaseRecord(**values)
            self.session.add(row)
            await self.session.flush()
        expires = row.lease_expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if row.lease_owner and row.lease_owner != normalized_owner and expires and expires > now:
            return False
        row.lease_owner = normalized_owner
        row.lease_expires_at = now + timedelta(seconds=max(10, int(lease_seconds)))
        row.version = int(row.version or 0) + 1
        row.updated_at = now
        await self.session.execute(update(ContextReconciliationRunRecord).where(
            ContextReconciliationRunRecord.status == "running",
            ContextReconciliationRunRecord.started_at < now - timedelta(seconds=max(10, int(lease_seconds))),
        ).values(status="interrupted", completed_at=now))
        await self.session.flush()
        return True

    async def release_reconciliation_lease(self, *, lease_key: str, owner: str) -> None:
        row = await self.session.scalar(select(ContextReconciliationLeaseRecord).where(
            ContextReconciliationLeaseRecord.lease_key == lease_key,
        ).with_for_update())
        if row is not None and row.lease_owner == owner:
            row.lease_owner = None
            row.lease_expires_at = None
            row.version = int(row.version or 0) + 1

    async def start_reconciliation_run(
        self, *, owner: str, tenant_id: str | None,
    ) -> ContextReconciliationRunRecord:
        row = ContextReconciliationRunRecord(
            lease_owner=self._require("reconciliation.owner", owner),
            tenant_id=require_tenant_id(tenant_id, source="reconciliation run") if tenant_id else None,
            status="running", errors=[], started_at=datetime.now(UTC),
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def finish_reconciliation_run(
        self, *, run_id: UUID, summary: dict[str, Any], status: str,
    ) -> None:
        row = await self.session.get(ContextReconciliationRunRecord, run_id)
        if row is None:
            raise LookupError("reconciliation run not found")
        completed = datetime.now(UTC)
        started = row.started_at if row.started_at.tzinfo else row.started_at.replace(tzinfo=UTC)
        row.status = status
        for field in (
            "incidents_scanned", "gaps_found", "requirements_created", "jobs_scheduled",
            "human_requests_created", "skipped_incidents",
        ):
            setattr(row, field, int(summary.get(field) or 0))
        row.errors = list(summary.get("errors") or [])
        row.completed_at = completed
        row.duration_ms = max(0, int((completed - started).total_seconds() * 1000))

    async def upsert_context_evidence_requirements(
        self, requirements: list[Any],
    ) -> list[ContextEvidenceRequirementRecord]:
        rows: list[ContextEvidenceRequirementRecord] = []
        for requirement in requirements:
            item = requirement.model_dump() if hasattr(requirement, "model_dump") else dict(requirement)
            tenant_id = require_tenant_id(item.get("tenant_id"), source="evidence requirement")
            incident_id = self._to_uuid(item["incident_id"])
            category = self._require("evidence_requirement.category", item.get("category"))
            question = self._require("evidence_requirement.question", item.get("question"))
            requirement_key = hashlib.sha256(f"{category}:{question}".encode()).hexdigest()
            existing = (await self.session.execute(select(ContextEvidenceRequirementRecord).where(
                ContextEvidenceRequirementRecord.tenant_id == tenant_id,
                ContextEvidenceRequirementRecord.incident_id == incident_id,
                ContextEvidenceRequirementRecord.rca_version == int(item.get("rca_version") or 1),
                ContextEvidenceRequirementRecord.requirement_key == requirement_key,
            ))).scalar_one_or_none()
            if existing is None:
                candidate = ContextEvidenceRequirementRecord(
                    requirement_id=self._to_uuid(item["requirement_id"]), tenant_id=tenant_id,
                    incident_id=incident_id, rca_version=int(item.get("rca_version") or 1),
                    requirement_key=requirement_key, category=category, question=question,
                    reason=self._require("evidence_requirement.reason", item.get("reason")),
                    priority=str(item.get("priority") or "high"),
                    collection_mode=str(item.get("collection_mode") or "connector_required"),
                    candidate_connectors=list(item.get("candidate_connectors") or []),
                    status=str(item.get("status") or "identified"),
                    retry_count=int(item.get("retry_count") or 0), retry_after=item.get("retry_after"),
                    assigned_to=item.get("assigned_to"), jira_issue_key=item.get("jira_issue_key"),
                    evidence_ids=list(item.get("evidence_ids") or []), version=1,
                )
                try:
                    async with self.session.begin_nested():
                        self.session.add(candidate)
                        await self.session.flush()
                    existing = candidate
                except IntegrityError:
                    # A scheduler and an explicit reconciliation request can
                    # race on the same deterministic requirement. The
                    # savepoint keeps the outer transaction usable; the row
                    # committed by the winner is the authoritative result.
                    existing = (await self.session.execute(select(ContextEvidenceRequirementRecord).where(
                        ContextEvidenceRequirementRecord.tenant_id == tenant_id,
                        ContextEvidenceRequirementRecord.incident_id == incident_id,
                        ContextEvidenceRequirementRecord.rca_version == int(item.get("rca_version") or 1),
                        ContextEvidenceRequirementRecord.requirement_key == requirement_key,
                    ))).scalar_one_or_none()
                    if existing is None:
                        raise
            else:
                # Connector capabilities evolve independently of the stable
                # requirement identity. Refresh the discovery plan so an open
                # requirement created by an older release can use newly
                # available MCP/RAG fallbacks on the next reconciliation.
                candidate_connectors = list(item.get("candidate_connectors") or [])
                collection_mode = str(item.get("collection_mode") or "connector_required")
                if (
                    list(existing.candidate_connectors or []) != candidate_connectors
                    or existing.collection_mode != collection_mode
                ):
                    existing.candidate_connectors = candidate_connectors
                    existing.collection_mode = collection_mode
                    existing.version = int(existing.version or 0) + 1
                # A requirement can have been routed to HITL by an older
                # connector configuration even though the refreshed plan now
                # has an automatic connector (for example Jaeger for traces).
                # Keep the durable requirement identity, but reopen it so the
                # scheduler can create the automatic enrichment job.
                if (
                    existing.status == "human_requested"
                    and collection_mode == "automatic"
                    and candidate_connectors
                    and not list(existing.evidence_ids or [])
                ):
                    existing.status = "identified"
                    existing.assigned_to = None
                    existing.jira_issue_key = None
                    existing.retry_after = None
                    existing.version = int(existing.version or 0) + 1
            from common.context_enrichment_contract import legacy_discovery_category
            if legacy_discovery_category(question) == category:
                legacy_rows = (await self.session.execute(select(ContextEvidenceRequirementRecord).where(
                    ContextEvidenceRequirementRecord.tenant_id == tenant_id,
                    ContextEvidenceRequirementRecord.incident_id == incident_id,
                    ContextEvidenceRequirementRecord.rca_version == existing.rca_version,
                    ContextEvidenceRequirementRecord.category == "validation",
                    ContextEvidenceRequirementRecord.question == question,
                    ContextEvidenceRequirementRecord.status.in_(["identified", "human_requested", "blocked"]),
                ).with_for_update())).scalars().all()
                for legacy in legacy_rows:
                    human = (await self.session.execute(select(HumanEvidenceRequestRecord).where(
                        HumanEvidenceRequestRecord.tenant_id == tenant_id,
                        HumanEvidenceRequestRecord.requirement_id == legacy.requirement_id,
                    ).with_for_update())).scalar_one_or_none()
                    has_job = await self.session.scalar(select(ContextEnrichmentJobRecord.job_id).where(
                        ContextEnrichmentJobRecord.requirement_id == legacy.requirement_id,
                    ).limit(1))
                    if legacy.evidence_ids or has_job or (human and human.response_payload):
                        continue
                    legacy.status = "cancelled"
                    legacy.reason = f"Superseded by configured discovery requirement {existing.requirement_id}. " + legacy.reason
                    legacy.version += 1
                    if human and human.status in {"pending", "assigned", "blocked"}:
                        human.status = "cancelled"
                        human.jira_sync_status = "superseded"
                        human.version += 1
            rows.append(existing)
        for tenant, incident in {(row.tenant_id, row.incident_id) for row in rows}:
            await self.retire_superseded_collection_jobs(tenant_id=tenant, incident_id=incident, limit=25)
        return rows

    async def reconcile_requirement_coverage_from_ledger(
        self, *, tenant_id: str, incident_id: UUID | str, apply: bool,
    ) -> dict[str, list[str]]:
        """Treat the canonical ledger as truth and optionally repair requirement coverage."""
        tenant = require_tenant_id(tenant_id, source="requirement evidence reconciliation")
        incident_uuid = self._to_uuid(incident_id)
        evidence = (await self.session.execute(select(CanonicalEvidenceRecord).where(
            CanonicalEvidenceRecord.tenant_id == tenant,
            CanonicalEvidenceRecord.incident_id == incident_uuid,
        ).order_by(CanonicalEvidenceRecord.requirement_id, CanonicalEvidenceRecord.evidence_id))).scalars().all()
        by_requirement: dict[str, list[str]] = {}
        for row in evidence:
            by_requirement.setdefault(str(row.requirement_id), []).append(row.evidence_id)
        if apply and by_requirement:
            requirements = (await self.session.execute(select(ContextEvidenceRequirementRecord).where(
                ContextEvidenceRequirementRecord.tenant_id == tenant,
                ContextEvidenceRequirementRecord.incident_id == incident_uuid,
                ContextEvidenceRequirementRecord.requirement_id.in_([
                    self._to_uuid(value) for value in by_requirement
                ]),
            ).with_for_update())).scalars().all()
            for row in requirements:
                evidence_ids = by_requirement[str(row.requirement_id)]
                if row.status != "collected" or list(row.evidence_ids or []) != evidence_ids:
                    row.status = "collected"
                    row.evidence_ids = evidence_ids
                    row.retry_after = None
                    row.version = int(row.version or 0) + 1
        return by_requirement

    async def list_context_evidence_requirements(
        self, *, tenant_id: str, incident_id: UUID | str,
    ) -> list[dict[str, Any]]:
        tenant = require_tenant_id(tenant_id, source="context gaps")
        result = await self.session.execute(
            select(ContextEvidenceRequirementRecord).where(
                ContextEvidenceRequirementRecord.tenant_id == tenant,
                ContextEvidenceRequirementRecord.incident_id == self._to_uuid(incident_id),
            ).order_by(ContextEvidenceRequirementRecord.created_at.asc())
        )
        return [{
            "requirement_id": str(row.requirement_id), "tenant_id": row.tenant_id,
            "incident_id": str(row.incident_id), "rca_version": row.rca_version,
            "category": row.category, "question": row.question, "reason": row.reason,
            "priority": row.priority, "collection_mode": row.collection_mode,
            "candidate_connectors": list(row.candidate_connectors or []), "status": row.status,
            "retry_count": row.retry_count, "retry_after": row.retry_after,
            "assigned_to": row.assigned_to, "jira_issue_key": row.jira_issue_key,
            "evidence_ids": list(row.evidence_ids or []), "version": row.version,
            "created_at": row.created_at, "updated_at": row.updated_at,
        } for row in result.scalars().all()]

    async def cancel_inapplicable_context_requirements(
        self, *, tenant_id: str, incident_id: UUID | str, categories: set[str], reason: str,
        questions: set[str] | None = None,
    ) -> int:
        """Close stale requirements that a refreshed investigation proves inapplicable."""
        tenant = require_tenant_id(tenant_id, source="context requirement reconciliation")
        if not categories:
            return 0
        if questions is not None and not questions:
            return 0
        question_filter = (
            [ContextEvidenceRequirementRecord.question.in_(questions)]
            if questions is not None else []
        )
        result = await self.session.execute(
            update(ContextEvidenceRequirementRecord)
            .where(
                ContextEvidenceRequirementRecord.tenant_id == tenant,
                ContextEvidenceRequirementRecord.incident_id == self._to_uuid(incident_id),
                ContextEvidenceRequirementRecord.category.in_(categories),
                *question_filter,
                ContextEvidenceRequirementRecord.status.not_in(("collected", "answered", "resolved", "cancelled")),
            )
            .values(status="cancelled", reason=reason, retry_after=None)
        )
        return int(result.rowcount or 0)

    async def context_evidence_requirement(
        self, *, tenant_id: str, requirement_id: UUID | str,
    ) -> dict[str, Any] | None:
        tenant = require_tenant_id(tenant_id, source="context evidence requirement")
        row = await self.session.get(ContextEvidenceRequirementRecord, self._to_uuid(requirement_id))
        if row is None or row.tenant_id != tenant:
            return None
        return {
            "requirement_id": str(row.requirement_id), "tenant_id": row.tenant_id,
            "incident_id": str(row.incident_id), "rca_version": row.rca_version,
            "category": row.category, "question": row.question, "reason": row.reason,
            "priority": row.priority, "collection_mode": row.collection_mode,
            "candidate_connectors": list(row.candidate_connectors or []), "status": row.status,
            "retry_count": row.retry_count, "retry_after": row.retry_after,
            "assigned_to": row.assigned_to, "jira_issue_key": row.jira_issue_key,
            "evidence_ids": list(row.evidence_ids or []), "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    async def active_incident_gap_candidates(
        self, *, tenant_id: str, limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return the latest governed RCA with gaps for active tenant incidents."""
        tenant = require_tenant_id(tenant_id, source="context enrichment reconciliation")
        rows = (await self.session.execute(
            select(IncidentInvestigationBindingRecord).join(
                IncidentRecord, IncidentRecord.id == IncidentInvestigationBindingRecord.incident_id,
            ).join(
                IncidentProjectionRecord,
                and_(
                    IncidentProjectionRecord.tenant_id == IncidentInvestigationBindingRecord.tenant_id,
                    IncidentProjectionRecord.incident_id == IncidentInvestigationBindingRecord.incident_id,
                    IncidentProjectionRecord.alert_id == IncidentInvestigationBindingRecord.alert_id,
                    IncidentProjectionRecord.recommendation_id
                    == IncidentInvestigationBindingRecord.recommendation_id,
                ),
            ).where(
                IncidentInvestigationBindingRecord.tenant_id == tenant,
                IncidentRecord.status.notin_([
                    "closed", "resolved", "cancelled", "canceled",
                    "waiting_for_human", "awaiting_approval", "approved",
                    "remediating", "validating", "failed",
                ]),
                or_(
                    IncidentProjectionRecord.lifecycle_state.is_(None),
                    IncidentProjectionRecord.lifecycle_state.notin_([
                        "CLOSED", "RESOLVED", "CANCELLED",
                        "WAITING_FOR_HUMAN", "COLLECTION_BLOCKED",
                        "AWAITING_APPROVAL", "EXECUTING", "VERIFYING", "FAILED",
                    ]),
                ),
            ).order_by(
                IncidentInvestigationBindingRecord.incident_id,
                IncidentInvestigationBindingRecord.rca_version.desc(),
            ).limit(max(1, min(int(limit), 25)))
        )).scalars().all()
        latest: dict[UUID, IncidentInvestigationBindingRecord] = {}
        for row in rows:
            latest.setdefault(row.incident_id, row)
        candidates: list[dict[str, Any]] = []
        incident_repository = IncidentRepository(self.session)
        from common.investigation_gaps import investigation_gaps
        for binding in latest.values():
            audit = await self.session.get(AuditLogRecord, binding.recommendation_id)
            recommendation = dict(audit.payload or {}) if audit and isinstance(audit.payload, dict) else {}
            metadata = recommendation.get("metadata") if isinstance(recommendation.get("metadata"), dict) else {}
            analysis = metadata.get("rca_analysis") if isinstance(metadata.get("rca_analysis"), dict) else {}
            gaps = investigation_gaps(analysis, {})
            if not gaps:
                continue
            verified = await incident_repository.get_bound_incident_investigation(
                tenant_id=tenant, incident_id=binding.incident_id,
                alert_id=binding.alert_id, recommendation_id=binding.recommendation_id,
            )
            if not verified.get("investigation_integrity", {}).get("verified"):
                continue
            incident = await self.session.get(IncidentRecord, binding.incident_id)
            snapshot = await self.session.get(ContextSnapshotRecord, binding.context_snapshot_id)
            context = dict(snapshot.payload or {}) if snapshot and isinstance(snapshot.payload, dict) else {}
            context_metadata = context.get("metadata") if isinstance(context.get("metadata"), dict) else {}
            evidence_buckets = context_metadata.get("context_evidence") or context.get("context_evidence") or {}
            accepted_ids = metadata.get("evidence_ids")
            if not isinstance(accepted_ids, list):
                accepted_ids = analysis.get("evidence_used", [])
            accepted_id_set = {str(value).strip() for value in accepted_ids if str(value).strip()}
            accepted_evidence = [
                item for bucket in (evidence_buckets.values() if isinstance(evidence_buckets, dict) else [])
                if isinstance(bucket, list) for item in bucket
                if isinstance(item, dict)
                and str(item.get("evidence_id") or item.get("id") or "").strip() in accepted_id_set
            ][:50]
            snapshot_evidence = [
                item for bucket in (evidence_buckets.values() if isinstance(evidence_buckets, dict) else [])
                if isinstance(bucket, list) for item in bucket if isinstance(item, dict)
            ][:50]
            lightweight_context = {
                k: v for k, v in context.items()
                if k not in {"metadata", "context_evidence", "discovery_report"}
            }
            lightweight_context["metadata"] = {
                k: v for k, v in context_metadata.items()
                if k not in {"context_evidence", "discovery_report"}
            }
            if snapshot is not None:
                self.session.expunge(snapshot)
            candidates.append({
                "incident_id": str(binding.incident_id), "rca_version": binding.rca_version,
                "alert_id": str(binding.alert_id), "gaps": gaps, "context": lightweight_context,
                "reviewed_sources": dict((metadata.get("iterative_investigation") or {}).get("source_coverage") or {}),
                "incident": dict(incident.payload or {}) if incident and isinstance(incident.payload, dict) else {},
                "binding": {
                    "incident_id": str(binding.incident_id), "alert_id": str(binding.alert_id),
                    "analysis_request_id": str(binding.analysis_request_id),
                    "context_snapshot_id": str(binding.context_snapshot_id),
                    "context_fingerprint": binding.context_fingerprint,
                    "recommendation_id": str(binding.recommendation_id),
                    "rca_version": binding.rca_version,
                },
                "accepted_evidence": accepted_evidence,
                "snapshot_evidence": snapshot_evidence,
            })
        return candidates

    async def list_context_enrichment_activity(
        self, *, tenant_id: str, incident_id: UUID | str, requirement_ids: list[str] | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Return the durable machine and human work associated with a gap."""
        tenant = require_tenant_id(tenant_id, source="context enrichment activity")
        incident_uuid = self._to_uuid(incident_id)
        from sqlalchemy.orm import load_only
        selected_ids = [self._to_uuid(value) for value in requirement_ids] if requirement_ids is not None else None
        if selected_ids == []:
            return {"jobs": [], "human_requests": []}

        # Activity summaries never use the potentially multi-megabyte query payload.
        # Keep immutable evidence in storage; fetch only fields rendered here.
        jobs = (await self.session.execute(
            select(ContextEnrichmentJobRecord).options(load_only(
                ContextEnrichmentJobRecord.job_id, ContextEnrichmentJobRecord.requirement_id,
                ContextEnrichmentJobRecord.connector_id, ContextEnrichmentJobRecord.status,
                ContextEnrichmentJobRecord.attempt_count, ContextEnrichmentJobRecord.available_at,
                ContextEnrichmentJobRecord.lease_owner, ContextEnrichmentJobRecord.lease_expires_at,
                ContextEnrichmentJobRecord.last_error, ContextEnrichmentJobRecord.updated_at,
                raiseload=True,
            )).where(
                ContextEnrichmentJobRecord.tenant_id == tenant,
                ContextEnrichmentJobRecord.incident_id == incident_uuid,
                ContextEnrichmentJobRecord.requirement_id.in_(selected_ids) if selected_ids is not None else True,
            ).order_by(ContextEnrichmentJobRecord.created_at.asc(), ContextEnrichmentJobRecord.job_id.asc())
        )).scalars().all()
        requests = (await self.session.execute(
            select(HumanEvidenceRequestRecord).where(
                HumanEvidenceRequestRecord.tenant_id == tenant,
                HumanEvidenceRequestRecord.incident_id == incident_uuid,
                HumanEvidenceRequestRecord.requirement_id.in_(selected_ids) if selected_ids is not None else True,
            ).order_by(HumanEvidenceRequestRecord.created_at.asc(), HumanEvidenceRequestRecord.request_id.asc())
        )).scalars().all()
        return {
            "jobs": [{
                "job_id": str(row.job_id), "requirement_id": str(row.requirement_id),
                "connector_id": row.connector_id, "status": row.status,
                "attempt_count": row.attempt_count, "available_at": row.available_at,
                "lease_owner": row.lease_owner, "lease_expires_at": row.lease_expires_at,
                "last_error": row.last_error, "updated_at": row.updated_at,
            } for row in jobs],
            "human_requests": [{
                "request_id": str(row.request_id), "requirement_id": str(row.requirement_id),
                "expected_responder": row.expected_responder, "due_at": row.due_at,
                "assignment_source": row.assignment_source,
                "assignment_failure_reason": row.assignment_failure_reason,
                "acceptable_format": row.acceptable_format, "status": row.status,
                "investigation_can_continue": row.investigation_can_continue,
                "jira": {
                    "issue_key": row.jira_issue_key, "url": row.jira_issue_url,
                    "version": row.jira_version, "assignee_id": row.jira_assignee_id,
                    "sync_status": row.jira_sync_status,
                } if row.jira_issue_key else None,
                "updated_at": row.updated_at,
            } for row in requests],
        }

    async def schedule_context_enrichment_job(
        self, *, tenant_id: str, incident_id: UUID | str, requirement_id: UUID | str,
        connector_id: str, query_payload: dict[str, Any], observation_start: datetime,
        observation_end: datetime,
    ) -> ContextEnrichmentJobRecord:
        tenant = require_tenant_id(tenant_id, source="context enrichment job")
        active_id = await self.session.scalar(select(ContextEnrichmentJobRecord.job_id).where(
            ContextEnrichmentJobRecord.tenant_id == tenant,
            ContextEnrichmentJobRecord.requirement_id == self._to_uuid(requirement_id),
            ContextEnrichmentJobRecord.connector_id == connector_id,
        ).order_by(ContextEnrichmentJobRecord.created_at.desc()).limit(1))
        if active_id is not None:
            return await self.session.get(ContextEnrichmentJobRecord, active_id)
        priority = await self.session.scalar(select(AuditLogRecord.payload).where(
            AuditLogRecord.tenant_id == tenant,
            AuditLogRecord.resource_id == str(incident_id),
            AuditLogRecord.action == "context.collection.prioritized",
        ).order_by(AuditLogRecord.created_at.desc()).limit(1))
        if isinstance(priority, dict):
            priority_until = IncidentRepository._parse_datetime(priority.get("expires_at"))
            if priority_until and priority_until.replace(tzinfo=UTC) > datetime.now(UTC):
                query_payload = {**query_payload, "operator_priority": True,
                                 "operator_priority_until": priority_until.replace(tzinfo=UTC).isoformat()}
        material = json.dumps({
            "tenant": tenant, "incident": str(incident_id), "requirement": str(requirement_id),
            "connector": connector_id, "query": query_payload,
            "start": observation_start.isoformat(), "end": observation_end.isoformat(),
        }, sort_keys=True, separators=(",", ":"))
        key = hashlib.sha256(material.encode()).hexdigest()
        existing = (await self.session.execute(select(ContextEnrichmentJobRecord).where(
            ContextEnrichmentJobRecord.tenant_id == tenant,
            ContextEnrichmentJobRecord.idempotency_key == key,
        ))).scalar_one_or_none()
        if existing is not None:
            return existing
        requirement = await self.session.get(ContextEvidenceRequirementRecord, self._to_uuid(requirement_id))
        prior_attempts = 0
        available_at = datetime.now(UTC)
        if requirement is not None:
            # A new RCA version must not reset the retry budget/backoff for
            # the same source, question and historical observation window, nor
            # re-run an automatic connector that already succeeded unless an
            # operator explicitly prioritized recollection.
            previous_requirement = aliased(ContextEvidenceRequirementRecord)
            if not query_payload.get("operator_priority") and int(requirement.rca_version or 1) > 1:
                already_collected_id = await self.session.scalar(select(
                    ContextEnrichmentJobRecord.job_id,
                ).join(
                    previous_requirement,
                    previous_requirement.requirement_id == ContextEnrichmentJobRecord.requirement_id,
                ).where(
                    ContextEnrichmentJobRecord.tenant_id == tenant,
                    ContextEnrichmentJobRecord.incident_id == self._to_uuid(incident_id),
                    ContextEnrichmentJobRecord.connector_id == connector_id,
                    ContextEnrichmentJobRecord.status == "collected",
                    previous_requirement.tenant_id == tenant,
                    or_(
                        previous_requirement.requirement_key == requirement.requirement_key,
                        previous_requirement.category == requirement.category,
                    ),
                    previous_requirement.rca_version < requirement.rca_version,
                ).order_by(ContextEnrichmentJobRecord.created_at.desc()).limit(1))
                if already_collected_id is not None:
                    requirement.status = "collected"
                    return await self.session.get(ContextEnrichmentJobRecord, already_collected_id)
            previous = (await self.session.execute(select(
                ContextEnrichmentJobRecord.attempt_count, ContextEnrichmentJobRecord.available_at,
            ).join(previous_requirement,
                previous_requirement.requirement_id == ContextEnrichmentJobRecord.requirement_id,
            ).where(
                ContextEnrichmentJobRecord.tenant_id == tenant,
                ContextEnrichmentJobRecord.incident_id == self._to_uuid(incident_id),
                ContextEnrichmentJobRecord.connector_id == connector_id,
                ContextEnrichmentJobRecord.observation_start == observation_start,
                previous_requirement.tenant_id == tenant,
                or_(
                    previous_requirement.requirement_key == requirement.requirement_key,
                    previous_requirement.category == requirement.category,
                ),
                previous_requirement.rca_version < requirement.rca_version,
                or_(ContextEnrichmentJobRecord.status.in_(["retry", "dead_letter"]), and_(
                    ContextEnrichmentJobRecord.status == "cancelled",
                    ContextEnrichmentJobRecord.last_error == "SUPERSEDED_EVIDENCE_REQUIREMENT")),
            ).order_by(ContextEnrichmentJobRecord.attempt_count.desc()).limit(1))).first()
            if previous:
                prior_attempts = int(previous[0] or 0)
                retry_at = previous[1]
                if retry_at is not None:
                    available_at = max(available_at, retry_at.replace(tzinfo=UTC) if retry_at.tzinfo is None else retry_at)
        row = ContextEnrichmentJobRecord(
            tenant_id=tenant, incident_id=self._to_uuid(incident_id),
            requirement_id=self._to_uuid(requirement_id), connector_id=self._require("connector_id", connector_id),
            idempotency_key=key, query_payload=dict(query_payload), observation_start=observation_start,
            observation_end=observation_end, status="dead_letter" if prior_attempts >= MAX_COLLECTION_ATTEMPTS else "scheduled",
            attempt_count=prior_attempts, available_at=available_at,
            last_error="COLLECTION_RETRY_EXHAUSTED" if prior_attempts >= MAX_COLLECTION_ATTEMPTS else None,
        )
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
            requirement = await self.session.get(
                ContextEvidenceRequirementRecord, self._to_uuid(requirement_id),
            )
            if requirement is not None and requirement.tenant_id == tenant:
                requirement.status = "blocked" if row.status == "dead_letter" else "scheduled"
                requirement.retry_after = None
                requirement.version = int(requirement.version or 0) + 1
            return row
        except IntegrityError:
            existing = (await self.session.execute(select(ContextEnrichmentJobRecord).where(
                ContextEnrichmentJobRecord.tenant_id == tenant,
                ContextEnrichmentJobRecord.idempotency_key == key,
            ))).scalar_one_or_none()
            if existing is None:
                raise RuntimeError("concurrent enrichment job scheduling could not be resolved") from None
            return existing

    async def prioritize_context_collection(self, *, tenant_id: str, incident_id: str,
                                           actor: str, reason: str) -> dict[str, Any]:
        tenant = require_tenant_id(tenant_id, source="collection priority")
        incident_uuid = self._to_uuid(incident_id)
        incident = await self.session.get(IncidentRecord, incident_uuid)
        if incident is None or incident.tenant_id != tenant:
            raise LookupError("Incident not found")
        if incident.status in {"closed", "resolved", "cancelled", "canceled"}:
            raise ValueError("Closed incident collection cannot be prioritized")
        jobs = (await self.session.execute(select(ContextEnrichmentJobRecord).where(
            ContextEnrichmentJobRecord.tenant_id == tenant,
            ContextEnrichmentJobRecord.incident_id == incident_uuid,
            ContextEnrichmentJobRecord.status.in_(["scheduled", "retry"]),
        ).with_for_update())).scalars().all()
        priority_until = (datetime.now(UTC) + timedelta(minutes=15)).isoformat()
        for job in jobs:
            job.query_payload = {**dict(job.query_payload or {}), "operator_priority": True,
                                 "operator_priority_until": priority_until}
        audit_id = uuid4()
        self.session.add(AuditLogRecord(id=audit_id, tenant_id=tenant, actor=actor,
            action="context.collection.prioritized", resource_type="incident", resource_id=str(incident_uuid),
            payload={"reason": reason, "job_ids": [str(job.job_id) for job in jobs],
                     "expires_at": priority_until}))
        await self.session.flush()
        return {"incident_id": str(incident_uuid), "jobs_prioritized": len(jobs), "audit_id": str(audit_id)}

    async def retire_superseded_collection_jobs(
        self, *, tenant_id: str, incident_id: UUID | str, limit: int = 500,
    ) -> dict[str, Any]:
        """Retire unleased work replaced by a committed RCA's requirements.

        Keep every evidence observation and live collector. A newer binding
        alone is insufficient: its requirement set must also be persisted.
        """
        tenant = require_tenant_id(tenant_id, source="superseded collection cleanup")
        incident_uuid = self._to_uuid(incident_id)
        latest_binding = await self.session.scalar(select(func.max(IncidentInvestigationBindingRecord.rca_version)).where(
            IncidentInvestigationBindingRecord.tenant_id == tenant,
            IncidentInvestigationBindingRecord.incident_id == incident_uuid,
        ))
        latest_requirements = await self.session.scalar(select(func.max(ContextEvidenceRequirementRecord.rca_version)).where(
            ContextEvidenceRequirementRecord.tenant_id == tenant,
            ContextEvidenceRequirementRecord.incident_id == incident_uuid,
        ))
        cutoff = min(int(latest_binding or 0), int(latest_requirements or 0))
        if cutoff <= 1:
            return {"jobs_retired": 0}
        old_requirements = select(ContextEvidenceRequirementRecord.requirement_id).where(
            ContextEvidenceRequirementRecord.tenant_id == tenant,
            ContextEvidenceRequirementRecord.incident_id == incident_uuid,
            ContextEvidenceRequirementRecord.rca_version < cutoff,
        )
        statement = select(ContextEnrichmentJobRecord).options(load_only(
            ContextEnrichmentJobRecord.status, ContextEnrichmentJobRecord.last_error,
            ContextEnrichmentJobRecord.lease_owner, ContextEnrichmentJobRecord.lease_expires_at,
            ContextEnrichmentJobRecord.version,
        )).where(
            ContextEnrichmentJobRecord.tenant_id == tenant,
            ContextEnrichmentJobRecord.incident_id == incident_uuid,
            ContextEnrichmentJobRecord.requirement_id.in_(old_requirements),
            ContextEnrichmentJobRecord.status.in_(["scheduled", "retry"]),
        ).order_by(ContextEnrichmentJobRecord.job_id).limit(max(1, min(int(limit), 500)))
        if self.session.bind and self.session.bind.dialect.name != "sqlite":
            statement = statement.with_for_update(skip_locked=True)
        rows = (await self.session.execute(statement)).scalars().all()
        for row in rows:
            row.status = "cancelled"
            row.last_error = "SUPERSEDED_EVIDENCE_REQUIREMENT"
            row.lease_owner = None
            row.lease_expires_at = None
            row.version = int(row.version or 0) + 1
        if rows:
            self.session.add(AuditLogRecord(
                id=uuid4(), tenant_id=tenant, actor="context-scheduler",
                action="context.collection.superseded_jobs_retired", resource_type="incident",
                resource_id=str(incident_uuid), payload={"rca_version": cutoff,
                    "job_ids": [str(row.job_id) for row in rows]},
            ))
            await self.session.flush()
        return {"jobs_retired": len(rows), "rca_version": cutoff}

    async def retire_closed_incident_collection_jobs(
        self, *, tenant_id: str, actor: str, limit: int = 500, dry_run: bool = False,
    ) -> dict[str, Any]:
        """Retire obsolete work without deleting history or stealing a live lease."""
        tenant = require_tenant_id(tenant_id, source="closed incident collection cleanup")
        now = datetime.now(UTC)
        # Read terminal identities separately: a locking EXISTS query can
        # also lock incident rows owned by unrelated workflow transactions.
        terminal_ids = list((await self.session.scalars(select(IncidentRecord.id).where(
            IncidentRecord.tenant_id == tenant,
            IncidentRecord.status.in_(["closed", "resolved", "cancelled", "canceled"]),
        ))).all())
        eligible = or_(
            ContextEnrichmentJobRecord.status.in_(["scheduled", "retry"]),
            and_(ContextEnrichmentJobRecord.status == "collecting", or_(
                ContextEnrichmentJobRecord.lease_expires_at.is_(None),
                ContextEnrichmentJobRecord.lease_expires_at < now)),
        )
        statement = select(ContextEnrichmentJobRecord).where(
            ContextEnrichmentJobRecord.tenant_id == tenant, ContextEnrichmentJobRecord.incident_id.in_(terminal_ids), eligible,
        ).order_by(ContextEnrichmentJobRecord.job_id).limit(max(1, min(int(limit), 500)))
        if not dry_run and self.session.bind and self.session.bind.dialect.name != "sqlite":
            statement = statement.with_for_update(skip_locked=True)
        jobs = (await self.session.execute(statement)).scalars().all()
        previous = [{"job_id": str(row.job_id), "status": row.status,
                     "last_error": row.last_error, "lease_owner": row.lease_owner,
                     "lease_expires_at": str(row.lease_expires_at) if row.lease_expires_at else None}
                    for row in jobs]
        if jobs and not dry_run:
            for row in jobs:
                row.status = "cancelled"
                row.last_error = "INCIDENT_TERMINAL_COLLECTION_RETIRED"
                row.lease_owner = None
                row.lease_expires_at = None
                row.version += 1
            # Keep the requirement state consistent with its retired jobs, but
            # do not cancel a requirement still owned by a live collector.
            retired_requirements = []
            for requirement_id in {row.requirement_id for row in jobs}:
                pending = await self.session.scalar(select(ContextEnrichmentJobRecord.job_id).where(
                    ContextEnrichmentJobRecord.requirement_id == requirement_id,
                    ContextEnrichmentJobRecord.tenant_id == tenant,
                    ContextEnrichmentJobRecord.status.in_(["scheduled", "retry", "collecting"]),
                    ContextEnrichmentJobRecord.job_id.notin_([row.job_id for row in jobs]),
                ).limit(1))
                requirement = await self.session.get(ContextEvidenceRequirementRecord, requirement_id)
                if pending is None and requirement is not None and requirement.tenant_id == tenant and requirement.incident_id in {job.incident_id for job in jobs if job.requirement_id == requirement_id} and requirement.status in {"identified", "scheduled", "collecting", "blocked"}:
                    retired_requirements.append({"requirement_id": str(requirement_id), "status": requirement.status})
                    requirement.status = "cancelled"
                    requirement.retry_after = None
                    requirement.version += 1
            self.session.add(AuditLogRecord(id=uuid4(), tenant_id=tenant, actor=actor,
                action="context.collection.terminal_jobs_retired", resource_type="tenant",
                resource_id=tenant, payload={"reason": "Incident is terminal; collection is no longer actionable.",
                                            "jobs": previous, "requirements": retired_requirements}))
            await self.session.flush()
        return {"tenant_id": tenant, "jobs_retired": len(jobs) if not dry_run else 0,
                "eligible_jobs": len(jobs), "dry_run": dry_run}

    async def claim_context_enrichment_jobs(
        self, *, worker_id: str, limit: int = 10, lease_seconds: int = 120, lane: str | None = None,
    ) -> list[dict[str, Any]]:
        """Lease due jobs for one worker using row locks across replicas."""
        now = datetime.now(UTC)
        owner = self._require("context_enrichment.worker_id", worker_id)
        bounded_limit = max(1, min(limit, 50))
        expired = and_(
            ContextEnrichmentJobRecord.status == "collecting",
            ContextEnrichmentJobRecord.attempt_count < MAX_COLLECTION_ATTEMPTS,
            or_(ContextEnrichmentJobRecord.lease_expires_at.is_(None),
                ContextEnrichmentJobRecord.lease_expires_at < now),
        )
        due = and_(ContextEnrichmentJobRecord.status.in_(["scheduled", "retry"]),
                   ContextEnrichmentJobRecord.attempt_count < MAX_COLLECTION_ATTEMPTS,
                   ContextEnrichmentJobRecord.available_at <= now)
        rows = []
        active_incident = ~exists(select(IncidentRecord.id).where(
            IncidentRecord.id == ContextEnrichmentJobRecord.incident_id,
            IncidentRecord.tenant_id == ContextEnrichmentJobRecord.tenant_id,
            IncidentRecord.status.in_(["closed", "resolved", "cancelled", "canceled"]),
        ))

        async def take(predicate, count):
            statement = select(ContextEnrichmentJobRecord).where(predicate, active_incident)
            if rows:
                statement = statement.where(ContextEnrichmentJobRecord.job_id.notin_([row.job_id for row in rows]))
            statement = statement.order_by(ContextEnrichmentJobRecord.available_at.asc(),
                                           ContextEnrichmentJobRecord.job_id.asc()).limit(count)
            if self.session.bind and self.session.bind.dialect.name != "sqlite":
                statement = statement.with_for_update(skip_locked=True)
            rows.extend((await self.session.execute(statement)).scalars().all())

        async def take_fair(count):
            history = aliased(ContextEnrichmentJobRecord)
            last_served = select(func.max(history.updated_at)).where(
                history.tenant_id == ContextEnrichmentJobRecord.tenant_id,
                history.incident_id == ContextEnrichmentJobRecord.incident_id,
                history.attempt_count > 0,
            ).correlate(ContextEnrichmentJobRecord).scalar_subquery()
            candidates = select(ContextEnrichmentJobRecord.tenant_id, ContextEnrichmentJobRecord.incident_id).where(
                or_(due, expired), active_incident,
            ).group_by(ContextEnrichmentJobRecord.tenant_id, ContextEnrichmentJobRecord.incident_id).order_by(
                func.coalesce(last_served, datetime(1970, 1, 1)),
                func.min(ContextEnrichmentJobRecord.available_at),
                ContextEnrichmentJobRecord.tenant_id, ContextEnrichmentJobRecord.incident_id,
            ).limit(max(16, count * 4))
            for tenant_id, incident_id in (await self.session.execute(candidates)).all():
                if count <= 0:
                    break
                before = len(rows)
                await take(and_(or_(due, expired), ContextEnrichmentJobRecord.tenant_id == tenant_id,
                                ContextEnrichmentJobRecord.incident_id == incident_id), 1)
                count -= len(rows) - before

        if lane is not None:
            predicates = {
                "recovery": expired,
                "retry": and_(due, ContextEnrichmentJobRecord.status == "retry"),
                "priority": and_(due, ContextEnrichmentJobRecord.query_payload["operator_priority"].as_boolean().is_(True),
                    ContextEnrichmentJobRecord.query_payload["operator_priority_until"].as_string() > now.isoformat()),
            }
            if lane not in {*predicates, "fair"}:
                raise ValueError("Unknown evidence collection lane")
            if lane in predicates:
                await take(predicates[lane], 1)
            if len(rows) < bounded_limit:
                await take_fair(bounded_limit - len(rows))

        # Reserve recovery, retry and new-work capacity. Remaining slots use
        # oldest-due order, preventing a continuous arrival stream starving
        # retries or leases abandoned by a crashed worker.
        if lane is None and bounded_limit >= 3:
            await take(expired, 1)
            await take(and_(due, ContextEnrichmentJobRecord.status == "retry"), 1)
            await take(and_(due, ContextEnrichmentJobRecord.status == "scheduled"), 1)
        if len(rows) < bounded_limit:
            await take_fair(bounded_limit - len(rows))
        if len(rows) < bounded_limit:
            await take(or_(due, expired), bounded_limit - len(rows))
        result = []
        lease_expires_at = now + timedelta(seconds=max(1, int(lease_seconds)))
        for row in rows:
            row.status = "collecting"
            row.lease_owner = owner
            row.lease_expires_at = lease_expires_at
            row.attempt_count = int(row.attempt_count or 0) + 1
            row.version += 1
            result.append({
                "job_id": str(row.job_id), "tenant_id": row.tenant_id,
                "incident_id": str(row.incident_id),
                "requirement_id": str(row.requirement_id),
                "connector_id": row.connector_id, "attempt_count": row.attempt_count,
                "query_payload": dict(row.query_payload or {}),
                "observation_start": row.observation_start,
                "observation_end": row.observation_end,
                "lease_owner": owner, "lease_expires_at": lease_expires_at,
            })
        await self.session.flush()
        return result

    async def persist_enrichment_result_atomically(
        self, *, job_id: UUID | str, worker_id: str,
        accepted_records: list[Any], rejected_records: list[dict[str, Any]],
        source_response_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Commit the exact validated evidence, snapshot, and RCA handoff once."""
        job_uuid = self._to_uuid(job_id)
        job = (await self.session.execute(select(ContextEnrichmentJobRecord).where(
            ContextEnrichmentJobRecord.job_id == job_uuid,
        ).with_for_update())).scalar_one_or_none()
        if job is None:
            raise LookupError("context enrichment job not found")
        if job.status != "collecting" or job.lease_owner != worker_id:
            raise RuntimeError("context enrichment job lease is not owned by this worker")
        requirement = (await self.session.execute(select(ContextEvidenceRequirementRecord).where(
            ContextEvidenceRequirementRecord.requirement_id == job.requirement_id,
        ).with_for_update())).scalar_one_or_none()
        if requirement is None or requirement.tenant_id != job.tenant_id:
            raise RuntimeError("enrichment requirement binding is invalid")
        # RCA versions commonly advance while a connector is collecting. The
        # observation remains valid for the same incident and equivalent gap;
        # rejecting it here caused successful telemetry calls to loop through
        # retry/dead-letter while successive RCAs kept recreating the gap.
        # Lock the newest equivalent requirement and satisfy both revisions
        # after all tenant/incident/provenance checks below have passed.
        latest_equivalent = (await self.session.execute(select(
            ContextEvidenceRequirementRecord,
        ).where(
            ContextEvidenceRequirementRecord.tenant_id == job.tenant_id,
            ContextEvidenceRequirementRecord.incident_id == job.incident_id,
            ContextEvidenceRequirementRecord.category == requirement.category,
            ContextEvidenceRequirementRecord.question == requirement.question,
        ).order_by(ContextEvidenceRequirementRecord.rca_version.desc()).limit(1).with_for_update())).scalar_one_or_none()
        attempt_key = f"{job.job_id}:{job.attempt_count}"
        accepted_ids: list[str] = []
        accepted_payloads: list[dict[str, Any]] = []
        for record in accepted_records:
            payload = record.model_dump(mode="python") if hasattr(record, "model_dump") else dict(record)
            if (
                payload.get("tenant_id") != job.tenant_id
                or str(payload.get("incident_id")) != str(job.incident_id)
                or str(payload.get("requirement_id")) != str(job.requirement_id)
            ):
                raise RuntimeError("EVIDENCE_BINDING_MISMATCH")
            evidence_id = self._require("evidence_id", payload.get("evidence_id"))
            existing = await self.session.get(CanonicalEvidenceRecord, evidence_id)
            if existing is None:
                content = dict(payload.get("content") or {})
                self.session.add(CanonicalEvidenceRecord(
                    evidence_id=evidence_id, requirement_id=job.requirement_id,
                    tenant_id=job.tenant_id, incident_id=job.incident_id,
                    category=payload["category"], source_id=payload["source_id"],
                    connector=payload["connector"], source_reference=payload["source_reference"],
                    service=payload.get("service"), resource=payload.get("resource"),
                    project_id=payload.get("project_id"), observed_at=payload["observed_at"],
                    collected_at=payload["collected_at"],
                    observation_window_start=payload.get("observation_window_start"),
                    observation_window_end=payload.get("observation_window_end"),
                    freshness=payload["freshness"], content=content,
                    provenance=dict(payload.get("provenance") or {}),
                    current_observation=bool(payload.get("current_observation")),
                    contradiction_status=payload.get("contradiction_status"),
                    content_digest=hashlib.sha256(json.dumps(
                        content, sort_keys=True, separators=(",", ":"), default=str,
                    ).encode()).hexdigest(),
                ))
            accepted_ids.append(evidence_id)
            accepted_payloads.append(
                record.model_dump(mode="json") if hasattr(record, "model_dump")
                else json.loads(json.dumps(payload, default=str))
            )
        for index, rejection in enumerate(rejected_records):
            exists_rejection = (await self.session.execute(select(EvidenceRejectionRecord).where(
                EvidenceRejectionRecord.tenant_id == job.tenant_id,
                EvidenceRejectionRecord.attempt_key == attempt_key,
                EvidenceRejectionRecord.record_index == index,
            ))).scalar_one_or_none()
            if exists_rejection is None:
                self.session.add(EvidenceRejectionRecord(
                    tenant_id=job.tenant_id, incident_id=job.incident_id,
                    requirement_id=job.requirement_id, job_id=job.job_id,
                    attempt_key=attempt_key, record_index=index,
                    reason_code=str(rejection.get("code") or "EVIDENCE_REJECTED")[:128],
                    reason_detail=str(rejection.get("detail") or "")[:4000] or None,
                    sanitized_record=dict(rejection),
                    source_response_metadata=dict(source_response_metadata),
                ))
        if not accepted_ids:
            await self.session.flush()
            return {"accepted": False, "evidence_ids": [], "snapshot_id": None, "outbox_event_id": None}
        previous = (await self.session.execute(select(ContextSnapshotRecord).where(
            ContextSnapshotRecord.tenant_id == job.tenant_id,
            ContextSnapshotRecord.incident_id == str(job.incident_id),
        ).order_by(ContextSnapshotRecord.snapshot_version.desc()).limit(1).with_for_update())).scalar_one_or_none()
        if previous is None:
            raise RuntimeError("CONTEXT_SNAPSHOT_MISSING")
        snapshot_payload = json.loads(json.dumps(previous.payload or {}, default=str))
        metadata = snapshot_payload.setdefault("metadata", {})
        buckets = metadata.setdefault("context_evidence", {})
        bucket = buckets.setdefault(requirement.category, [])
        known_ids = {str(item.get("evidence_id")) for item in bucket if isinstance(item, dict)}
        known_signatures = {
            (
                str(item.get("connector") or ""),
                str(item.get("source_reference") or item.get("citation") or ""),
                hashlib.sha256(
                    json.dumps(
                        {
                            k: v for k, v in dict(item.get("content") or {}).items()
                            if k not in {"collected_at", "last_attempt_at", "observed_at"}
                        },
                        sort_keys=True, separators=(",", ":"), default=str,
                    ).encode()
                ).hexdigest(),
            )
            for item in bucket if isinstance(item, dict)
        }
        new_bucket_items: list[dict[str, Any]] = []
        for item in accepted_payloads:
            sig = (
                str(item.get("connector") or ""),
                str(item.get("source_reference") or item.get("citation") or ""),
                hashlib.sha256(
                    json.dumps(
                        {
                            k: v for k, v in dict(item.get("content") or {}).items()
                            if k not in {"collected_at", "last_attempt_at", "observed_at"}
                        },
                        sort_keys=True, separators=(",", ":"), default=str,
                    ).encode()
                ).hexdigest(),
            )
            if item["evidence_id"] not in known_ids and sig not in known_signatures:
                known_ids.add(item["evidence_id"])
                known_signatures.add(sig)
                new_bucket_items.append(item)
        bucket.extend(new_bucket_items)
        # The initial collection manifest may say skipped/no matches. Accepted
        # enrichment replaces that outcome without asserting that every row is fresh.
        sources = metadata.setdefault("context_sources", {})
        source = dict(sources.get(requirement.category) or {})
        for key in ("fresh_count", "inferred_timestamp_count", "incident_aligned_count",
                    "untraceable_count", "newest_observed_at", "oldest_observed_at"):
            source.pop(key, None)
        source.update({"status": "collected", "collection_status": "collected", "attempted": True,
                       "error": None, "required_configuration": None, "result_count": len(bucket),
                       "evidence_ids": list(dict.fromkeys(str(item["evidence_id"]) for item in bucket
                                                         if isinstance(item, dict) and item.get("evidence_id"))),
                       "last_attempt_at": datetime.now(UTC).isoformat()})
        sources[requirement.category] = source
        evidence_ids = list(dict.fromkeys([*(previous.evidence_ids or []), *(item["evidence_id"] for item in new_bucket_items)]))
        evidence_digest = hashlib.sha256("\n".join(evidence_ids).encode()).hexdigest()
        context_fingerprint = hashlib.sha256(json.dumps(
            snapshot_payload, sort_keys=True, separators=(",", ":"), default=str,
        ).encode()).hexdigest()
        canonical_payload = json.loads(json.dumps(snapshot_payload, default=str))
        canonical_meta = canonical_payload.get("metadata") if isinstance(canonical_payload.get("metadata"), dict) else {}
        for volatile_key in ("context_snapshot_id", "context_fingerprint", "evidence_set_digest", "analysis_request_id"):
            canonical_meta.pop(volatile_key, None)
        for src_info in (canonical_meta.get("context_sources") or {}).values():
            if isinstance(src_info, dict):
                src_info.pop("last_attempt_at", None)
        for ev_list in (canonical_meta.get("context_evidence") or {}).values():
            if isinstance(ev_list, list):
                for ev_item in ev_list:
                    if isinstance(ev_item, dict):
                        ev_item.pop("collected_at", None)
        context_fingerprint = hashlib.sha256(json.dumps(
            canonical_payload, sort_keys=True, separators=(",", ":"), default=str,
        ).encode()).hexdigest()
        if (
            previous.snapshot_stage in {"enriched", "investigation_complete"}
            and not new_bucket_items
            and set(evidence_ids).issubset(set(previous.evidence_ids or []))
        ):
            requirement.status = "collected"
            requirement.evidence_ids = accepted_ids
            requirement.version += 1
            if latest_equivalent is not None and latest_equivalent.requirement_id != requirement.requirement_id:
                latest_equivalent.status = "collected"
                latest_equivalent.evidence_ids = list(dict.fromkeys([
                    *(latest_equivalent.evidence_ids or []), *accepted_ids,
                ]))
                latest_equivalent.retry_after = None
                latest_equivalent.version += 1
            job.status = "collected"; job.last_error = None; job.version += 1
            job.lease_owner = None; job.lease_expires_at = None
            await self.session.flush()
            return {
                "accepted": True,
                "deduplicated": True,
                "evidence_ids": accepted_ids,
                "snapshot_id": str(previous.snapshot_id),
                "snapshot_version": previous.snapshot_version,
                "outbox_event_id": None,
                "outbox_payload": None,
            }
        snapshot_id = uuid5(NAMESPACE_URL, f"kaims:enriched-snapshot:{job.incident_id}:{evidence_digest}")
        analysis_request_id = uuid5(NAMESPACE_URL, f"kaims:enriched-analysis:{snapshot_id}")
        metadata.update({"context_snapshot_id": str(snapshot_id), "context_fingerprint": context_fingerprint,
                         "evidence_ids": evidence_ids, "evidence_set_digest": evidence_digest,
                         "analysis_request_id": str(analysis_request_id)})
        snapshot = await self.session.get(ContextSnapshotRecord, snapshot_id)
        if snapshot is None:
            previous_expiry = previous.expires_at
            if previous_expiry.tzinfo is None:
                previous_expiry = previous_expiry.replace(tzinfo=UTC)
            snapshot = ContextSnapshotRecord(
                snapshot_id=snapshot_id, tenant_id=job.tenant_id,
                incident_id=str(job.incident_id), source_incident_id=previous.source_incident_id,
                alert_signature=previous.alert_signature, subject_fingerprint=previous.subject_fingerprint,
                context_fingerprint=context_fingerprint, parent_snapshot_id=previous.snapshot_id,
                snapshot_stage="enriched", snapshot_version=int(previous.snapshot_version or 0) + 1,
                evidence_ids=evidence_ids,
                evidence_checksums={**dict(previous.evidence_checksums or {}), **{
                    row.evidence_id: hashlib.sha256(json.dumps(
                        row.content, sort_keys=True, separators=(",", ":"), default=str,
                    ).encode()).hexdigest() for row in accepted_records
                }},
                contract_version="kaiops.evidence.v1", quality_score=previous.quality_score,
                reusable=False, source_manifest={**dict(previous.source_manifest or {}),
                                                 requirement.category: source_response_metadata},
                payload=snapshot_payload, collected_at=datetime.now(UTC),
                expires_at=max(previous_expiry, datetime.now(UTC) + timedelta(hours=1)),
            )
            self.session.add(snapshot)
        context_payload = snapshot_payload
        event_id = f"context-enriched:{job.incident_id}:{evidence_digest}"
        outbox_payload = {
            "context": context_payload,
            "incident": dict(job.query_payload.get("incident") or {}),
            "decision": {**dict(job.query_payload.get("decision") or {}),
                         "context_snapshot_id": str(snapshot_id), "evidence_set_digest": evidence_digest,
                         "analysis_request_id": str(analysis_request_id)},
            "transport": "outbox", "event_contract": {"event_id": event_id},
        }
        if await self.session.get(ResolutionOutboxRecord, event_id) is None:
            await self.session.flush()
            from common.config import get_settings
            from common.outbox_context import compact_context
            stored_outbox_payload = (
                await compact_context(
                    self.session,
                    payload=outbox_payload,
                    tenant_id=job.tenant_id,
                    aggregate_id=str(job.incident_id),
                    topic="context-events",
                )
                if get_settings().outbox_snapshot_references_enabled
                else outbox_payload
            )
            self.session.add(ResolutionOutboxRecord(
                event_id=event_id, tenant_id=job.tenant_id, aggregate_id=str(job.incident_id),
                topic="context-events", partition_key=str(job.incident_id), payload=stored_outbox_payload,
                status="pending", attempts=0, next_attempt_at=datetime.now(UTC),
            ))
        requirement.status = "collected"
        requirement.evidence_ids = accepted_ids
        requirement.version += 1
        if latest_equivalent is not None and latest_equivalent.requirement_id != requirement.requirement_id:
            latest_equivalent.status = "collected"
            latest_equivalent.evidence_ids = list(dict.fromkeys([
                *(latest_equivalent.evidence_ids or []), *accepted_ids,
            ]))
            latest_equivalent.retry_after = None
            latest_equivalent.version += 1
        job.status = "collected"; job.last_error = None; job.version += 1
        job.lease_owner = None; job.lease_expires_at = None
        await self.session.flush()
        return {"accepted": True, "evidence_ids": accepted_ids, "snapshot_id": str(snapshot_id),
                "snapshot_version": snapshot.snapshot_version, "outbox_event_id": event_id,
                "outbox_payload": outbox_payload}

    async def incident_operations_state(
        self, *, tenant_id: str, incident_id: UUID | str,
    ) -> dict[str, Any] | None:
        """Build the deterministic backend-owned incident operations projection."""
        tenant = require_tenant_id(tenant_id, source="incident operations state")
        incident_uuid = self._to_uuid(incident_id)
        incident = await self.session.scalar(select(IncidentRecord).where(
            IncidentRecord.id == incident_uuid, IncidentRecord.tenant_id == tenant,
        ))
        projection = await self.session.scalar(select(IncidentProjectionRecord).where(
            IncidentProjectionRecord.incident_id == incident_uuid,
            IncidentProjectionRecord.tenant_id == tenant,
        ))
        if incident is None and projection is None:
            return None

        # Sort narrow identity rows; sorting complete JSON evidence payloads can
        # exhaust MySQL sort memory even when the result is limited to one row.
        snapshot_id = await self.session.scalar(
            select(ContextSnapshotRecord.snapshot_id).where(
                ContextSnapshotRecord.tenant_id == tenant,
                ContextSnapshotRecord.incident_id == str(incident_uuid),
            ).order_by(
                ContextSnapshotRecord.snapshot_version.desc(),
                ContextSnapshotRecord.collected_at.desc(),
                ContextSnapshotRecord.snapshot_id.desc(),
            ).limit(1)
        )
        snapshot = await self.session.get(ContextSnapshotRecord, snapshot_id) if snapshot_id else None
        governed_recommendation = await IncidentRepository(self.session).governed_recovery_recommendation_id(
            tenant_id=tenant, incident_id=incident_uuid,
        )
        binding_id = await self.session.scalar(
            select(IncidentInvestigationBindingRecord.binding_id).where(
                IncidentInvestigationBindingRecord.tenant_id == tenant,
                IncidentInvestigationBindingRecord.incident_id == incident_uuid,
                (IncidentInvestigationBindingRecord.recommendation_id == governed_recommendation)
                if governed_recommendation else literal(True),
            ).order_by(
                IncidentInvestigationBindingRecord.rca_version.desc(),
                IncidentInvestigationBindingRecord.created_at.desc(),
                IncidentInvestigationBindingRecord.binding_id.desc(),
            ).limit(1)
        )
        binding = await self.session.get(IncidentInvestigationBindingRecord, binding_id) if binding_id else None
        bound_snapshot = (
            await self.session.get(ContextSnapshotRecord, binding.context_snapshot_id)
            if binding is not None else None
        )
        if (
            binding is not None
            and bound_snapshot is not None
            and snapshot is not None
            and snapshot.snapshot_stage == "investigation_complete"
            and snapshot.snapshot_id != binding.context_snapshot_id
        ):
            # A final investigation snapshot is only canonical once its
            # immutable recommendation binding commits. A retried/redelivered
            # analysis can persist another final snapshot before its binding
            # loses an idempotency race; treating that orphan as "latest
            # context" immediately makes the valid RCA appear stale.
            snapshot = bound_snapshot
        recommendation = await self.session.get(AuditLogRecord, binding.recommendation_id) if binding else None
        recommendation_payload = (
            dict(recommendation.payload or {})
            if recommendation is not None and isinstance(recommendation.payload, dict) else {}
        )
        recommendation_metadata = (
            recommendation_payload.get("metadata")
            if isinstance(recommendation_payload.get("metadata"), dict) else {}
        )
        iterative_investigation = (
            recommendation_metadata.get("iterative_investigation")
            if isinstance(recommendation_metadata.get("iterative_investigation"), dict) else {}
        )
        typed_rca_result = (
            iterative_investigation.get("rca_result")
            if isinstance(iterative_investigation.get("rca_result"), dict) else {}
        )
        typed_claims = [
            dict(claim) for claim in typed_rca_result.get("claims", [])
            if isinstance(claim, dict)
        ]
        causal_claim = next((
            claim for claim in typed_claims if str(claim.get("kind") or "").upper() == "CAUSAL"
        ), None)
        impact_claim = next((
            claim for claim in typed_claims if str(claim.get("kind") or "").upper() == "IMPACT"
        ), None)
        execution_plan_record = (
            await self.session.get(ExecutionPlanRecord, binding.resolution_plan_id)
            if binding and binding.resolution_plan_id else None
        )
        governed_plan = (
            dict(execution_plan_record.plan_payload or {})
            if execution_plan_record is not None and isinstance(execution_plan_record.plan_payload, dict)
            else dict(recommendation_metadata.get("execution_plan") or {})
            if isinstance(recommendation_metadata.get("execution_plan"), dict)
            else {}
        )
        governed_actions = governed_plan.get("actions") if isinstance(governed_plan.get("actions"), list) else []
        governed_action = governed_actions[0] if len(governed_actions) >= 1 and isinstance(governed_actions[0], dict) else {}
        governed_safety = governed_action.get("safety_binding") if isinstance(governed_action.get("safety_binding"), dict) else {}
        governed_capability = governed_safety.get("capability") if isinstance(governed_safety.get("capability"), dict) else {}
        governed_credential = governed_safety.get("credential") if isinstance(governed_safety.get("credential"), dict) else {}
        analysis = (
            recommendation_metadata.get("rca_analysis")
            if isinstance(recommendation_metadata.get("rca_analysis"), dict) else {}
        )
        # Surface synthesis failures for existing records as well as new runs.
        # This read model must not silently turn a provider fallback into
        # an apparently ongoing investigation with no explanation.
        analysis = dict(analysis)
        for field in ("causal_chain", "supporting_signals", "contradictions", "alternative_causes"):
            if isinstance(analysis.get(field), str):
                analysis[field] = [analysis[field]] if analysis[field].strip() else []
        model_usage = recommendation_metadata.get("model_usage") or []
        synthesis_fallback = any(
            isinstance(call, dict) and call.get("task") == "rca"
            and (call.get("fallback") is True or "fallback" in str(call.get("model") or ""))
            for call in model_usage
        )
        if binding and synthesis_fallback and str(binding.status or "").lower() not in {"grounded", "conclusive"}:
            from common.investigation_gaps import blocking_investigation_gaps
            analysis["missing_evidence"] = blocking_investigation_gaps(
                analysis, recommendation_metadata.get("iterative_investigation") or {},
            )
            analysis["grounding_notes"] = " ".join(filter(None, [
                str(analysis.get("grounding_notes") or ""),
                "RCA synthesis used a model fallback and did not produce a validated causal conclusion. Retained context is available; review model availability and rerun the analysis.",
            ]))
        quality = (
            recommendation_metadata.get("quality_gate")
            if isinstance(recommendation_metadata.get("quality_gate"), dict) else {}
        )
        approval = await self.session.scalar(
            select(ApprovalRecord).where(
                ApprovalRecord.tenant_id == tenant,
                ApprovalRecord.incident_id == incident_uuid,
                ApprovalRecord.recommendation_id == binding.recommendation_id,
            ).order_by(ApprovalRecord.updated_at.desc(), ApprovalRecord.id.desc()).limit(1)
        ) if binding else None
        action = await self.session.scalar(
            select(ActionRecord).where(
                ActionRecord.tenant_id == tenant,
                ActionRecord.incident_id == incident_uuid,
                ActionRecord.recommendation_id == binding.recommendation_id,
                ActionRecord.resolution_plan_id == binding.resolution_plan_id,
                ActionRecord.plan_fingerprint == binding.plan_fingerprint,
                ActionRecord.approval_id == approval.id,
            ).order_by(ActionRecord.updated_at.desc(), ActionRecord.id.desc()).limit(1)
        ) if binding and approval and binding.resolution_plan_id and binding.plan_fingerprint else None
        report = await self.session.scalar(
            select(RcaReportRecord).where(
                RcaReportRecord.tenant_id == tenant,
                RcaReportRecord.incident_id == incident_uuid,
                RcaReportRecord.recommendation_id == binding.recommendation_id,
                RcaReportRecord.resolution_plan_id == binding.resolution_plan_id,
                RcaReportRecord.plan_fingerprint == binding.plan_fingerprint,
                RcaReportRecord.approval_id == approval.id,
                RcaReportRecord.remediation_action_id == action.id,
            ).order_by(RcaReportRecord.updated_at.desc(), RcaReportRecord.id.desc()).limit(1)
        ) if binding and approval and action else None
        # Observed recovery has no approval, plan or corrective action. Read
        # only the report named by this incident's committed closure assessment.
        closure_payload = dict(projection.projection_payload or {}) if projection else {}
        closure_lifecycle = closure_payload.get("incident_lifecycle") or {}
        assessment_id = self._to_uuid(closure_lifecycle.get("assessment_id")) if closure_lifecycle.get("assessment_id") else None
        if projection and projection.lifecycle_state == "CLOSED" and assessment_id:
            assessment = await self.session.scalar(select(AuditLogRecord).where(
                AuditLogRecord.id == assessment_id, AuditLogRecord.tenant_id == tenant,
                AuditLogRecord.resource_id == str(incident_uuid),
                AuditLogRecord.action == "recovery.assessment.requested",
            ))
            assessed = dict(assessment.payload or {}) if assessment else {}
            report_id = self._to_uuid(assessed.get("report_id")) if assessed.get("report_id") else None
            if assessed.get("status") == "closed" and report_id:
                observed_report = await self.session.scalar(select(RcaReportRecord).where(
                    RcaReportRecord.id == report_id, RcaReportRecord.tenant_id == tenant,
                    RcaReportRecord.incident_id == incident_uuid,
                    RcaReportRecord.closure_kind == "observed_recovery",
                    RcaReportRecord.closure_status == "closed",
                ))
                if (observed_report and observed_report.validation_checksum
                        and observed_report.validation_checksum == assessed.get("validation_checksum")
                        and (observed_report.payload or {}).get("metadata", {}).get("assessment_id") == str(assessment_id)):
                    report = observed_report
        if incident and incident.status in {"closed", "resolved"}:
            administrative_report = await IncidentRepository(self.session).committed_non_execution_closure_report(
                tenant_id=tenant, incident_id=incident_uuid,
            )
            if administrative_report is not None:
                report = administrative_report
        report_payload = dict(report.payload or {}) if report and isinstance(report.payload, dict) else {}
        recovery_observation = await self.session.get(AuditLogRecord, observation_id(tenant, incident_uuid))
        report_metadata = report_payload.get("metadata") if isinstance(report_payload.get("metadata"), dict) else {}
        pre_state_observations = (
            report_metadata.get("pre_state_validation_observations")
            if isinstance(report_metadata.get("pre_state_validation_observations"), list) else []
        )
        post_state_observations = (
            report_metadata.get("independent_validation_observations")
            if isinstance(report_metadata.get("independent_validation_observations"), list) else []
        )
        knowledge_draft = await self.session.scalar(select(KnowledgeRagDraftRecord).where(
            KnowledgeRagDraftRecord.tenant_id == tenant,
            KnowledgeRagDraftRecord.source_ref == f"report://{report.id}",
        ).order_by(
            KnowledgeRagDraftRecord.document_version.desc(),
            KnowledgeRagDraftRecord.updated_at.desc(),
        ).limit(1)) if report else None

        requirements = await self.list_context_evidence_requirements(
            tenant_id=tenant, incident_id=incident_uuid,
        )
        current_rca_version = binding.rca_version if binding else max(
            (int(row["rca_version"]) for row in requirements), default=0,
        )
        current_version_requirements = [
            row for row in requirements if int(row["rca_version"]) == current_rca_version
        ]
        current_categories = {str(row.get("category") or "").strip().lower() for row in current_version_requirements}
        carried_forward_by_category: dict[str, dict[str, Any]] = {}
        current_binding_conclusive = bool(
            binding is not None
            and str(binding.status or "").lower() in {"grounded", "ready", "conclusive"}
            and not list(analysis.get("missing_evidence") or [])
        )
        if binding is not None and not current_binding_conclusive:
            for row in requirements:
                if int(row["rca_version"]) >= current_rca_version:
                    continue
                cat = str(row.get("category") or "").strip().lower()
                if cat in current_categories:
                    continue
                if str(row.get("status") or "").lower() in {
                    "open", "pending", "collecting", "human_requested", "assignment_blocked", "blocked",
                }:
                    prev = carried_forward_by_category.get(cat)
                    if prev is None or int(row["rca_version"]) >= int(prev["rca_version"]):
                        carried_forward_by_category[cat] = {
                            **row,
                            "carried_forward_from_rca_version": row["rca_version"],
                            "rca_version": current_rca_version,
                        }
        active_requirements = [*current_version_requirements, *carried_forward_by_category.values()]
        # Historical requirements remain available for audit. Only active or
        # carried-forward unresolved requirements are queried here.
        activity = await self.list_context_enrichment_activity(
            tenant_id=tenant, incident_id=incident_uuid,
            requirement_ids=[row["requirement_id"] for row in active_requirements],
        )
        jobs_by_requirement: dict[str, dict[str, Any]] = {}
        for job in activity["jobs"]:
            # Activity is ascending, so assignment deterministically retains the latest attempt.
            jobs_by_requirement[job["requirement_id"]] = job
        active_human_statuses = {"pending", "assigned", "open", "in_progress", "assignment_blocked"}
        human_by_requirement: dict[str, dict[str, Any]] = {}
        human_history_by_requirement: dict[str, list[dict[str, Any]]] = {}
        for request in activity["human_requests"]:
            key = request["requirement_id"]
            human_history_by_requirement.setdefault(key, []).append(request)
            if str(request["status"]).lower() in active_human_statuses:
                human_by_requirement[key] = request

        requirement_projection = [{
            **row,
            "latest_job": jobs_by_requirement.get(row["requirement_id"]),
            "active_human_request": human_by_requirement.get(row["requirement_id"]),
            "human_request_history": human_history_by_requirement.get(row["requirement_id"], []),
        } for row in active_requirements]

        snapshot_payload_for_evidence = (
            dict(snapshot.payload or {})
            if snapshot and isinstance(snapshot.payload, dict) else {}
        )
        snapshot_metadata_for_evidence = (
            snapshot_payload_for_evidence.get("metadata")
            if isinstance(snapshot_payload_for_evidence.get("metadata"), dict) else {}
        )
        snapshot_evidence_buckets = (
            snapshot_metadata_for_evidence.get("context_evidence")
            or snapshot_payload_for_evidence.get("context_evidence") or {}
        )
        current_evidence_ids = list(snapshot.evidence_ids or []) if snapshot else []
        for rows in snapshot_evidence_buckets.values() if isinstance(snapshot_evidence_buckets, dict) else []:
            for item in rows if isinstance(rows, list) else []:
                if not isinstance(item, dict):
                    continue
                evidence_id = str(item.get("evidence_id") or item.get("id") or "").strip()
                if evidence_id and evidence_id not in current_evidence_ids:
                    current_evidence_ids.append(evidence_id)
        evidence_rows = (
            (await self.session.execute(select(CanonicalEvidenceRecord).where(
                CanonicalEvidenceRecord.tenant_id == tenant,
                CanonicalEvidenceRecord.incident_id == incident_uuid,
                CanonicalEvidenceRecord.evidence_id.in_(current_evidence_ids),
            ).order_by(CanonicalEvidenceRecord.category, CanonicalEvidenceRecord.evidence_id))).scalars().all()
            if current_evidence_ids else []
        )
        evidence_count_by_category: dict[str, int] = {}
        for row in evidence_rows:
            evidence_count_by_category[row.category] = evidence_count_by_category.get(row.category, 0) + 1

        unresolved = (
            []
            if current_binding_conclusive
            else [
                row for row in requirement_projection
                if str(row["status"]).lower() not in {"collected", "answered", "satisfied", "cancelled"}
            ]
        )
        active_jobs = [row["latest_job"] for row in unresolved if row.get("latest_job")]
        human_requests = [row["active_human_request"] for row in unresolved
                          if row.get("active_human_request")]
        waiting_human = any(
            request.get("status") != "assignment_blocked" or binding is not None
            for request in human_requests
        )
        blocking_human = any(request.get("status") != "assignment_blocked"
                             and request.get("investigation_can_continue") is not True
                             for request in human_requests)
        collecting = any(str(job.get("status")).lower() in {"scheduled", "collecting", "retry"}
                         for job in active_jobs)
        if blocking_human or waiting_human:
            lifecycle_state = "WAITING_FOR_HUMAN"
            next_action = {"type": "HUMAN_EVIDENCE", "message": "KaiMS is waiting for assigned human evidence."}
        elif collecting:
            lifecycle_state = "COLLECTING"
            next_action = {"type": "AUTONOMOUS_COLLECTION", "message": "KaiMS is collecting governed evidence."}
        elif waiting_human:
            lifecycle_state = "WAITING_FOR_HUMAN"
            next_action = {"type": "HUMAN_EVIDENCE", "message": "KaiMS is waiting for assigned human evidence."}
        elif binding is not None:
            lifecycle_state = "RCA_READY" if str(binding.status).lower() in {"grounded", "ready", "conclusive"} else "INVESTIGATING"
            next_action = {"type": "REVIEW_RCA", "message": "Review the current governed RCA version."}
        elif unresolved:
            blocked = (any(str(row["status"]).lower() in {"blocked", "failed", "dead_letter"} for row in unresolved)
                       or any(request.get("status") == "assignment_blocked" for request in human_requests))
            if snapshot and not any(request.get("investigation_can_continue") is False for request in human_requests):
                lifecycle_state = "CONTEXT_READY"
                next_action = {"type": "INVESTIGATE", "message": "KaiMS is preparing a governed investigation with available evidence."}
            else:
                lifecycle_state = "COLLECTION_BLOCKED" if blocked else "REQUIREMENTS_IDENTIFIED"
                next_action = {"type": "REVIEW_EVIDENCE_GAPS", "message": "Review unresolved evidence requirements."}
        elif snapshot:
            lifecycle_state = "CONTEXT_READY"
            next_action = {"type": "INVESTIGATE", "message": "KaiMS is preparing a governed investigation."}
        else:
            lifecycle_state = "DETECTED"
            next_action = {"type": "IDENTIFY_REQUIREMENTS", "message": "KaiMS is identifying evidence requirements."}

        if projection is not None:
            try:
                persisted_state = IncidentLifecycleState(projection.lifecycle_state)
            except ValueError:
                persisted_state = None
            # Evidence requirements and immutable RCA bindings can advance
            # before the asynchronous lifecycle projection is reduced.  Do
            # not let a stale early projection send the cockpit backwards to
            # "identifying requirements" after work is already scheduled,
            # blocked for review, or analysed.
            stale_early_projection = bool(
                persisted_state
                in {
                    IncidentLifecycleState.DETECTED,
                    IncidentLifecycleState.REQUIREMENTS_IDENTIFIED,
                    IncidentLifecycleState.COLLECTING,
                    IncidentLifecycleState.WAITING_FOR_HUMAN,
                    IncidentLifecycleState.CONTEXT_READY,
                    IncidentLifecycleState.INVESTIGATING,
                }
                and (
                    binding is not None
                    or bool(requirement_projection)
                )
                and persisted_state.value != lifecycle_state
            )
            if persisted_state is not None and not stale_early_projection:
                lifecycle_state = persisted_state.value
                next_action = {
                    IncidentLifecycleState.DETECTED: {
                        "type": "IDENTIFY_REQUIREMENTS", "message": "KaiMS is identifying evidence requirements.",
                    },
                    IncidentLifecycleState.REQUIREMENTS_IDENTIFIED: {
                        "type": "SCHEDULE_COLLECTION", "message": "KaiMS is scheduling governed evidence collection.",
                    },
                    IncidentLifecycleState.COLLECTING: {
                        "type": "AUTONOMOUS_COLLECTION", "message": "KaiMS is collecting governed evidence.",
                    },
                    IncidentLifecycleState.WAITING_FOR_HUMAN: {
                        "type": "HUMAN_EVIDENCE", "message": "KaiMS is waiting for assigned human evidence.",
                    },
                    IncidentLifecycleState.CONTEXT_READY: {
                        "type": "INVESTIGATE", "message": "KaiMS is preparing a governed investigation.",
                    },
                }.get(persisted_state, next_action)

        collection_counts = {state: sum(str(job.get("status")).lower() == state for job in active_jobs)
                             for state in ("scheduled", "retry", "collecting", "dead_letter")}
        collection_phase = ("collecting" if collection_counts["collecting"] else
                            "queued" if collection_counts["scheduled"] else
                            "retry_wait" if collection_counts["retry"] else
                            "blocked" if unresolved else "complete")
        if lifecycle_state == "COLLECTING":
            next_action = {"type": "AUTONOMOUS_COLLECTION", "message": (
                f"Evidence jobs: {collection_counts['collecting']} collecting, "
                f"{collection_counts['scheduled']} queued, {collection_counts['retry']} waiting to retry."
            )}
        recorded_status = str(incident.status if incident is not None else "").upper()
        if recorded_status in {"CLOSED", "RESOLVED", "CANCELLED"}:
            lifecycle_state = recorded_status
        if lifecycle_state in {"CLOSED", "RESOLVED", "CANCELLED"}:
            next_action = {"type": "REVIEW_CLOSURE", "message": "Review the recorded closure and its evidence. Earlier investigation tasks are historical."}
        if projection is not None and str(projection.lifecycle_state) != str(lifecycle_state):
            projection.lifecycle_state = str(lifecycle_state)
            projection.updated_at = datetime.now(UTC)
        if lifecycle_state == "RCA_READY":
            if incident is not None and str(incident.status or "").lower() in {"open", "investigating", "waiting_for_human"}:
                incident.status = "rca_ready"
                incident.updated_at = datetime.now(UTC)
            if projection is not None and str(projection.status or "").lower() in {"open", "investigating", "waiting_for_human"}:
                projection.status = "rca_ready"
                projection.updated_at = datetime.now(UTC)

        rca_ready = bool(binding and str(binding.status).lower() in {"grounded", "ready", "conclusive"}) and bool(quality.get("passed"))
        governed_plan_ready = bool(
            governed_plan.get("execution_ready") is True
            and governed_plan.get("mutating") is True
            and governed_plan.get("plan_fingerprint")
            and verify_plan_fingerprint(governed_plan)
            and governed_action
            and governed_capability.get("capability_id")
        )
        resolution_ready = rca_ready and governed_plan_ready
        raw_blocked_reasons = list(quality.get("blocking_reasons") or quality.get("blockers") or []) + list(analysis.get("missing_evidence") or [])
        blocked_reasons = [
            str(reason.get("reason") or reason.get("question") or reason.get("category") or "EVIDENCE_REQUIRED")
            if isinstance(reason, dict) else str(reason)
            for reason in raw_blocked_reasons
            if reason
        ]
        if binding is None:
            blocked_reasons = ["RCA_NOT_READY"]
        elif causal_claim is not None and str(causal_claim.get("status") or "").lower() not in {"grounded", "conclusive", "confirmed", "supported"}:
            blocked_reasons.append("CAUSAL_CLAIM_NOT_CONFIRMED")
        if not rca_ready and not blocked_reasons:
            blocked_reasons.append("RCA_NOT_GROUNDED")
        if binding is not None and not governed_plan_ready:
            blocked_reasons.extend(
                str(reason) for reason in governed_plan.get("readiness_blocks", []) if str(reason).strip()
            )
            if not governed_plan:
                blocked_reasons.append("GOVERNED_EXECUTION_PLAN_NOT_PUBLISHED")
            elif not governed_capability.get("capability_id"):
                blocked_reasons.append("REGISTERED_CAPABILITY_NOT_BOUND")
            elif not verify_plan_fingerprint(governed_plan):
                blocked_reasons.append("EXECUTION_PLAN_FINGERPRINT_INVALID")
        blocked_reasons = list(dict.fromkeys(blocked_reasons))
        analysis_evidence_ids = (
            analysis.get("evidence_used")
            if isinstance(analysis.get("evidence_used"), list)
            else None
        )
        # Prefer the recommendation's explicit RCA citations. Older bindings
        # incorrectly stored the entire snapshot evidence set, which made
        # collected context appear to be accepted RCA proof.
        accepted_evidence_ids = list(dict.fromkeys(
            str(value) for value in (
                analysis_evidence_ids
                if analysis_evidence_ids is not None
                else list(binding.evidence_ids or []) if binding else []
            )
            if str(value).strip()
        ))
        accepted_evidence_set = set(accepted_evidence_ids)
        workspace_snapshot = bound_snapshot or snapshot
        workspace_evidence_ids = list(workspace_snapshot.evidence_ids or []) if workspace_snapshot else []
        workspace_evidence_rows = (
            (await self.session.execute(select(CanonicalEvidenceRecord).where(
                CanonicalEvidenceRecord.tenant_id == tenant,
                CanonicalEvidenceRecord.incident_id == incident_uuid,
                CanonicalEvidenceRecord.evidence_id.in_(workspace_evidence_ids),
            ).order_by(CanonicalEvidenceRecord.category, CanonicalEvidenceRecord.evidence_id))).scalars().all()
            if workspace_evidence_ids else []
        )
        workspace_evidence = [{
            "evidence_id": row.evidence_id,
            "category": row.category,
            "source_id": row.source_id,
            "connector": row.connector,
            "citation": row.source_reference,
            "summary": str((row.content or {}).get("message") or (row.content or {}).get("summary") or "")[:1600],
            "freshness": row.freshness,
            "observed_at": row.observed_at,
            "collected_at": row.collected_at,
            "current_observation": bool(row.current_observation),
            "accepted_for_rca": row.evidence_id in accepted_evidence_set,
            "contradiction_status": row.contradiction_status,
        } for row in workspace_evidence_rows]
        represented_evidence_ids = {row["evidence_id"] for row in workspace_evidence}
        workspace_snapshot_payload = (
            dict(workspace_snapshot.payload or {})
            if workspace_snapshot and isinstance(workspace_snapshot.payload, dict) else {}
        )
        workspace_snapshot_metadata = (
            workspace_snapshot_payload.get("metadata")
            if isinstance(workspace_snapshot_payload.get("metadata"), dict) else {}
        )
        snapshot_buckets = (
            workspace_snapshot_metadata.get("context_evidence")
            or workspace_snapshot_payload.get("context_evidence") or {}
        )
        for category, rows in snapshot_buckets.items() if isinstance(snapshot_buckets, dict) else []:
            for item in rows if isinstance(rows, list) else []:
                if not isinstance(item, dict):
                    continue
                evidence_id = str(item.get("evidence_id") or item.get("id") or "").strip()
                if not evidence_id or evidence_id in represented_evidence_ids:
                    continue
                workspace_evidence.append({
                    "evidence_id": evidence_id,
                    "category": str(item.get("category") or category),
                    "source_id": str(item.get("source_id") or item.get("source") or "snapshot"),
                    "connector": str(item.get("connector") or item.get("provider") or "snapshot"),
                    # Structured evidence planes (traces/changes/database/resource/
                    # dependency - anything shaped by resolution-agent's
                    # investigation.py, as opposed to the flatter code/logs/
                    # topology/telemetry rows) carry their real URI under
                    # `source_uri`, not `citation`/`uri`/`source_reference`.
                    # Missing that key here meant every such row's citation
                    # silently fell back to "", which is never traceable -
                    # reproduced live: incident 417fc764acf342b1bdc8e815d18e8f1f
                    # had 11 RCA-bound records (mostly trace-sourced) but only 1
                    # counted as a traceable citation, capping grounding
                    # coverage at 9% and permanently blocking RCA_NOT_GROUNDED
                    # regardless of how much real evidence had been collected.
                    "citation": str(
                        item.get("source_reference") or item.get("citation")
                        or item.get("uri") or item.get("source_uri") or ""
                    ),
                    "freshness": str(item.get("freshness") or "snapshot"),
                    "summary": str(item.get("summary") or item.get("message") or item.get("snippet") or "")[:1600],
                    "observed_at": item.get("observed_at") or item.get("timestamp"),
                    "collected_at": item.get("collected_at") or workspace_snapshot.collected_at,
                    # Same field-name mismatch as above: these same five
                    # evidence planes stamp `current_operational_evidence`, not
                    # `current_observation` - the latter never exists on their
                    # rows, so this silently read as False (a stale/historical
                    # reading) for every one of them regardless of how fresh
                    # the underlying query actually was.
                    "current_observation": bool(
                        item.get("current_observation", item.get("current_operational_evidence", False))
                    ),
                    "accepted_for_rca": evidence_id in accepted_evidence_set,
                    "contradiction_status": str(item.get("contradiction_status") or "none"),
                })
                represented_evidence_ids.add(evidence_id)
        traceable_citation_count = sum(
            1 for row in workspace_evidence
            if row["accepted_for_rca"] and is_traceable_evidence_citation(row["citation"])
        )
        represented_evidence_set = {row["evidence_id"] for row in workspace_evidence}
        resolved_accepted_evidence_ids = [
            evidence_id for evidence_id in accepted_evidence_ids
            if evidence_id in represented_evidence_set
        ]
        unresolved_accepted_evidence_ids = [
            evidence_id for evidence_id in accepted_evidence_ids
            if evidence_id not in represented_evidence_set
        ]
        hypothesis = str(
            (causal_claim or {}).get("statement")
            or analysis.get("root_cause") or analysis.get("leading_hypothesis")
            or recommendation_payload.get("root_cause") or ""
        ).strip()
        investigation_status = str(binding.status).lower() if binding else "not_started"
        analysis_missing = list(analysis.get("missing_evidence") or [])
        analysis_conflicts = list(analysis.get("conflicting_evidence") or [])
        claim_status = str((causal_claim or {}).get("status") or investigation_status).lower()
        grounded = investigation_status in {"grounded", "conclusive"} and claim_status in {"grounded", "conclusive", "confirmed", "supported"} and bool(
            resolved_accepted_evidence_ids
            and traceable_citation_count == len(resolved_accepted_evidence_ids)
            and not unresolved_accepted_evidence_ids
            and not analysis_missing
            and not analysis_conflicts
            and not unresolved
        )
        impact_statement = str(
            (impact_claim or {}).get("statement")
            or analysis.get("customer_impact") or analysis.get("business_impact")
            or recommendation_payload.get("customer_impact") or recommendation_payload.get("business_impact")
            or analysis.get("impact") or recommendation_payload.get("impact")
            or ""
        ).strip()
        timestamps = [
            value if value.tzinfo else value.replace(tzinfo=UTC)
            for value in (
            getattr(projection, "updated_at", None), getattr(snapshot, "collected_at", None),
            getattr(binding, "created_at", None), getattr(incident, "updated_at", None),
            ) if value is not None
        ]
        updated_at = max(timestamps) if timestamps else datetime.now(UTC)
        snapshot_payload = dict(snapshot.payload or {}) if snapshot and isinstance(snapshot.payload, dict) else {}
        snapshot_metadata = snapshot_payload.get("metadata") if isinstance(snapshot_payload.get("metadata"), dict) else {}
        return {
            "schema_version": "kaiops.operations-state.v1",
            "incident_id": str(incident_uuid), "tenant_id": tenant,
            "lifecycle_state": lifecycle_state,
            "lifecycle_version": int(projection.lifecycle_version or 1) if projection else 0,
            "lifecycle_failure": {
                "code": projection.lifecycle_failure_code,
                "reason": projection.lifecycle_failure_reason,
            } if projection and projection.lifecycle_failure_code else None,
            "context": {
                "snapshot_id": str(snapshot.snapshot_id) if snapshot else None,
                "version": int(snapshot.snapshot_version) if snapshot else 0,
                "evidence_ids": current_evidence_ids,
                "evidence_count_by_category": evidence_count_by_category,
                "quality": dict(snapshot_metadata.get("context_quality") or {}),
                "missing_requirements": [row["requirement_id"] for row in unresolved],
            },
            "investigation": {
                "investigation_id": str(binding.investigation_id) if binding and binding.investigation_id else None,
                "rca_version": int(binding.rca_version) if binding else 0,
                "status": str(binding.status) if binding else "not_started",
                "confidence": float(recommendation_payload.get("confidence") or 0.0),
                "snapshot_id": str(binding.context_snapshot_id) if binding else None,
                "evidence_ids": list(binding.evidence_ids or []) if binding else [],
                "evidence_set_digest": binding.evidence_set_digest if binding else None,
            },
            "requirements": requirement_projection,
            "requirement_history": [row for row in requirements if int(row["rca_version"]) != current_rca_version],
            "resolution": {
                "status": "ready" if resolution_ready else "blocked",
                "readiness": quality,
                "recommendation_version": str(binding.recommendation_id) if binding else None,
                "plan_version": str(binding.resolution_plan_id) if binding and binding.resolution_plan_id else None,
                "catalog_operation_id": governed_capability.get("operation"),
                "capability_id": governed_capability.get("capability_id"),
                "connector_id": governed_action.get("connector_id") or governed_plan.get("connector_id"),
                "target_resource_id": governed_action.get("target_resource_id") or governed_plan.get("remediation_target"),
                "credential_bound": bool(str(governed_credential.get("reference") or "").strip()),
                "rollback_bound": bool(governed_action.get("rollback_action") or governed_plan.get("rollback")),
                "policy_decision": dict(governed_plan.get("policy_decision") or {}),
                "plan_fingerprint": governed_plan.get("plan_fingerprint"),
                "rca_version": governed_plan.get("rca_version"),
                "evidence_snapshot_id": governed_plan.get("evidence_snapshot_id"),
            },
            "approval": {
                "approval_id": str(approval.id) if approval else None,
                "incident_id": str(approval.incident_id) if approval else str(incident_uuid),
                "recommendation_id": str(approval.recommendation_id) if approval else (
                    str(binding.recommendation_id) if binding else None
                ),
                "plan_id": str(approval.plan_id) if approval and approval.plan_id else None,
                "plan_fingerprint": approval.plan_fingerprint if approval else None,
                "status": str(approval.decision).lower() if approval else "not_requested",
                "approver": approval.approver if approval else None,
                "approver_role": approval.approver_role if approval else None,
                "expires_at": approval.approval_expires_at if approval else None,
                "updated_at": approval.updated_at if approval else None,
                "blocked_reasons": (
                    [] if approval or resolution_ready else blocked_reasons or ["RCA_NOT_READY"]
                ),
            },
            "execution": {
                "action_id": str(action.id) if action else None,
                "status": str(action.status).lower() if action else "not_started",
                "action_type": action.action_type if action else None,
                "target": action.target if action else None,
                "recommendation_id": str(action.recommendation_id) if action and action.recommendation_id else None,
                "plan_id": str(action.resolution_plan_id) if action and action.resolution_plan_id else None,
                "plan_fingerprint": action.plan_fingerprint if action else None,
                "approval_id": str(action.approval_id) if action and action.approval_id else None,
                "updated_at": action.updated_at if action else None,
            },
            "recovery_observation": project_observation(recovery_observation.payload if recovery_observation else None),
            "validation": {
                "report_id": str(report.id) if report else None,
                "status": "closed" if report and report.closure_kind == "manual" and incident and incident.status in {"closed", "resolved"}
                else str(report.closure_status).lower() if report and report.closure_status else "not_started",
                "closure_kind": report.closure_kind if report else None,
                "validation_checksum": report.validation_checksum if report else None,
                "action_id": str(report.remediation_action_id) if report and report.remediation_action_id else None,
                "health_restored": bool((report.payload or {}).get("health_restored")) if report else False,
                "alerts_cleared": bool((report.payload or {}).get("alerts_cleared")) if report else False,
                "details": {
                    **report_payload,
                    "pre_state": pre_state_observations,
                    "post_state": post_state_observations,
                } if report else {},
                "pre_state_observations": pre_state_observations,
                "post_state_observations": post_state_observations,
                "observation_window": dict(report_metadata.get("stability_window") or {}),
                "outcome_decision": dict(report_metadata.get("outcome_validation") or {}),
                "knowledge_draft": self._knowledge_draft_payload(knowledge_draft) if knowledge_draft else None,
                "updated_at": report.updated_at if report else None,
            },
            "next_action": next_action,
            "collection": {"phase": collection_phase, **collection_counts,
                           "rca_version": current_rca_version},
            "investigation_workspace": {
                "schema_version": "kaiops.investigation-workspace.v1",
                "binding": {
                    "incident_id": str(incident_uuid),
                    "alert_id": str(binding.alert_id) if binding else None,
                    "analysis_request_id": str(binding.analysis_request_id) if binding else None,
                    "snapshot_id": str(binding.context_snapshot_id) if binding else None,
                    "context_snapshot_id": str(binding.context_snapshot_id) if binding else None,
                    "context_fingerprint": str(binding.context_fingerprint) if binding else None,
                    "snapshot_version": int(workspace_snapshot.snapshot_version) if workspace_snapshot else 0,
                    "investigation_id": str(binding.investigation_id) if binding and binding.investigation_id else None,
                    "rca_version": int(binding.rca_version) if binding else 0,
                    "recommendation_id": str(binding.recommendation_id) if binding else None,
                },
                "impact": {
                    "status": str((impact_claim or {}).get("status") or (
                        "unconfirmed" if impact_statement else "not_established"
                    )).lower(),
                    "statement": impact_statement or None,
                    "claim": impact_claim,
                },
                "rca": {
                    "status": "grounded" if grounded else (
                        "insufficient_evidence" if claim_status in {"grounded", "conclusive", "confirmed"}
                        else claim_status
                    ),
                    "grounded": grounded,
                    "hypothesis": hypothesis or None,
                    "supporting_signals": list(analysis.get("supporting_signals") or []),
                    "causal_chain": causal_steps(analysis.get("causal_chain")),
                    "timeline": build_rca_timeline(analysis.get("event_sequence"), workspace_evidence, accepted_evidence_ids),
                    "grounding_notes": str(analysis.get("grounding_notes") or ""),
                    "contradictions": list(analysis.get("contradictions") or []),
                    "alternative_causes": list(analysis.get("alternative_causes") or []),
                    "confidence": float(recommendation_payload.get("confidence") or 0.0),
                    "accepted_evidence_ids": accepted_evidence_ids,
                    "resolved_evidence_ids": resolved_accepted_evidence_ids,
                    "unresolved_evidence_ids": unresolved_accepted_evidence_ids,
                    "traceable_citation_count": traceable_citation_count,
                    "missing_evidence": list(analysis.get("missing_evidence") or []),
                    "conflicting_evidence": list(analysis.get("conflicting_evidence") or []),
                    "claims": typed_claims,
                },
                "evidence": workspace_evidence,
                "evidence_summary": {
                    "latest_context_records": len(current_evidence_ids),
                    "bound_snapshot_records": len(workspace_evidence),
                    "rca_bound_records": len(resolved_accepted_evidence_ids),
                    "traceable_citations": traceable_citation_count,
                    "unresolved_bindings": len(unresolved_accepted_evidence_ids),
                },
                "requirements": requirement_projection,
                "resolution": {
                    "proposed_remedy": str(recommendation_payload.get("recommended_action") or recommendation_payload.get("action") or ""),
                    "status": "ready" if resolution_ready and grounded else "blocked",
                    "recommendation_id": str(binding.recommendation_id) if binding else None,
                    "plan_id": str(binding.resolution_plan_id) if binding and binding.resolution_plan_id else None,
                    "blocking_reasons": [] if resolution_ready and grounded else blocked_reasons or ["RCA_NOT_GROUNDED"],
                    "catalog_operation_id": governed_capability.get("operation"),
                    "capability_id": governed_capability.get("capability_id"),
                    "connector_id": governed_action.get("connector_id") or governed_plan.get("connector_id"),
                    "target_resource_id": governed_action.get("target_resource_id") or governed_plan.get("remediation_target"),
                    "credential_bound": bool(str(governed_credential.get("reference") or "").strip()),
                    "rollback_bound": bool(governed_action.get("rollback_action") or governed_plan.get("rollback")),
                    "policy_decision": dict(governed_plan.get("policy_decision") or {}),
                    "plan_fingerprint": governed_plan.get("plan_fingerprint"),
                    "rca_version": governed_plan.get("rca_version"),
                    "evidence_snapshot_id": governed_plan.get("evidence_snapshot_id"),
                },
                "operator_review": {
                    "required": not grounded,
                    "mode": "evidence_response",
                    "message": "Review the AI hypothesis, replace unsupported claims with verified observations, and cite the source.",
                },
            },
            "updated_at": updated_at,
        }

    async def transition_incident_lifecycle(
        self, *, tenant_id: str, incident_id: UUID | str, target_state: str,
        expected_version: int, actor: str, reason: str, idempotency_key: str,
        failure_code: str | None = None,
    ) -> dict[str, Any]:
        """Atomically validate, audit, project, and enqueue one lifecycle transition."""
        tenant = require_tenant_id(tenant_id, source="incident lifecycle transition")
        incident_uuid = self._to_uuid(incident_id)
        key = self._require("incident_lifecycle.idempotency_key", idempotency_key)[:160]
        existing = await self.session.scalar(select(IncidentLifecycleTransitionRecord).where(
            IncidentLifecycleTransitionRecord.tenant_id == tenant,
            IncidentLifecycleTransitionRecord.idempotency_key == key,
        ))
        if existing is not None:
            if existing.incident_id != incident_uuid or existing.new_state != str(target_state):
                raise ValueError("incident lifecycle idempotency key was reused for a different transition")
            return self._lifecycle_transition_payload(existing, idempotent=True)

        projection = await self.session.scalar(select(IncidentProjectionRecord).where(
            IncidentProjectionRecord.incident_id == incident_uuid,
            IncidentProjectionRecord.tenant_id == tenant,
        ).with_for_update())
        if projection is None:
            raise LookupError("incident projection not found")
        if int(projection.lifecycle_version or 1) != int(expected_version):
            raise RuntimeError("STALE_LIFECYCLE_VERSION")
        current, target = validate_incident_transition(projection.lifecycle_state, target_state)
        await self._validate_incident_transition_prerequisites(
            tenant_id=tenant, incident_id=incident_uuid, target=target,
        )
        normalized_reason = self._require("incident_lifecycle.reason", reason)
        normalized_actor = self._require("incident_lifecycle.actor", actor)[:160]
        normalized_failure = str(failure_code or "").strip()[:128] or None
        if target in FAILURE_INCIDENT_STATES and normalized_failure is None:
            raise ValueError("failure lifecycle transitions require a machine-readable failure_code")
        transition = IncidentLifecycleTransitionRecord(
            tenant_id=tenant, incident_id=incident_uuid,
            sequence_no=int(projection.lifecycle_version or 1),
            previous_state=current.value, new_state=target.value,
            actor=normalized_actor, reason=normalized_reason,
            failure_code=normalized_failure, idempotency_key=key,
        )
        self.session.add(transition)
        await self.session.flush()
        projection.lifecycle_state = target.value
        projection.lifecycle_version = int(projection.lifecycle_version or 1) + 1
        projection.lifecycle_failure_code = normalized_failure
        projection.lifecycle_failure_reason = normalized_reason if normalized_failure else None
        _lifecycle_status_sync_map = {
            IncidentLifecycleState.COLLECTING: "investigating",
            IncidentLifecycleState.CONTEXT_READY: "investigating",
            IncidentLifecycleState.INVESTIGATING: "investigating",
            IncidentLifecycleState.WAITING_FOR_HUMAN: "waiting_for_human",
            IncidentLifecycleState.RCA_READY: "rca_ready",
            IncidentLifecycleState.PLAN_READY: "plan_ready",
            IncidentLifecycleState.AWAITING_APPROVAL: "awaiting_approval",
            IncidentLifecycleState.EXECUTING: "remediating",
            IncidentLifecycleState.VALIDATING: "validating",
            IncidentLifecycleState.CLOSED: "closed",
            IncidentLifecycleState.COLLECTION_BLOCKED: "failed",
            IncidentLifecycleState.INVESTIGATION_FAILED: "failed",
            IncidentLifecycleState.EXECUTION_FAILED: "failed",
            IncidentLifecycleState.VALIDATION_FAILED: "failed",
            IncidentLifecycleState.ESCALATED: "failed",
        }
        synced_status = _lifecycle_status_sync_map.get(target)
        if synced_status and str(projection.status or "").strip().lower() not in _CLOSED_INCIDENT_STATUSES:
            projection.status = synced_status
            await self.session.execute(
                update(IncidentRecord)
                .where(
                    IncidentRecord.tenant_id == tenant,
                    IncidentRecord.id == incident_uuid,
                    IncidentRecord.status.not_in(tuple(_CLOSED_INCIDENT_STATUSES)),
                )
                .values(status=synced_status)
            )
            await self.session.execute(
                update(IncidentCorrelationOwnershipRecord)
                .where(
                    IncidentCorrelationOwnershipRecord.tenant_id == tenant,
                    IncidentCorrelationOwnershipRecord.canonical_incident_id == incident_uuid,
                    IncidentCorrelationOwnershipRecord.lifecycle_state.not_in(tuple(_CLOSED_INCIDENT_STATUSES)),
                )
                .values(lifecycle_state=synced_status)
            )
        projection.projection_payload = {
            **dict(projection.projection_payload or {}),
            "incident_lifecycle": {
                "state": target.value, "version": projection.lifecycle_version,
                "transition_id": str(transition.transition_id), "actor": normalized_actor,
                "reason": normalized_reason, "failure_code": normalized_failure,
                "occurred_at": transition.occurred_at.isoformat(),
            },
        }
        event_id = f"incident-lifecycle:{transition.transition_id}"
        self.session.add(ResolutionOutboxRecord(
            event_id=event_id, tenant_id=tenant, aggregate_id=str(incident_uuid),
            topic="incident-lifecycle-events", partition_key=str(incident_uuid),
            payload={
                "schema_version": "kaiops.incident-lifecycle.v1",
                "transition_id": str(transition.transition_id), "incident_id": str(incident_uuid),
                "tenant_id": tenant, "previous_state": current.value, "new_state": target.value,
                "version": projection.lifecycle_version, "actor": normalized_actor,
                "reason": normalized_reason, "failure_code": normalized_failure,
            },
            status="pending", attempts=0, next_attempt_at=datetime.now(UTC),
        ))
        await self.session.flush()
        return self._lifecycle_transition_payload(transition, idempotent=False)

    @staticmethod
    def _lifecycle_transition_payload(
        row: IncidentLifecycleTransitionRecord, *, idempotent: bool,
    ) -> dict[str, Any]:
        return {
            "transition_id": str(row.transition_id), "incident_id": str(row.incident_id),
            "tenant_id": row.tenant_id, "previous_state": row.previous_state,
            "new_state": row.new_state, "version": row.sequence_no + 1,
            "actor": row.actor, "reason": row.reason, "failure_code": row.failure_code,
            "occurred_at": row.occurred_at, "idempotent": idempotent,
        }

    async def _validate_incident_transition_prerequisites(
        self, *, tenant_id: str, incident_id: UUID, target: IncidentLifecycleState,
    ) -> None:
        if target in FAILURE_INCIDENT_STATES:
            return
        if target == IncidentLifecycleState.REQUIREMENTS_IDENTIFIED:
            exists_row = await self.session.scalar(select(func.count()).select_from(
                ContextEvidenceRequirementRecord,
            ).where(
                ContextEvidenceRequirementRecord.tenant_id == tenant_id,
                ContextEvidenceRequirementRecord.incident_id == incident_id,
            ))
            if not exists_row:
                raise ValueError("REQUIREMENTS_MISSING")
        elif target == IncidentLifecycleState.COLLECTING:
            exists_row = await self.session.scalar(select(func.count()).select_from(
                ContextEnrichmentJobRecord,
            ).where(
                ContextEnrichmentJobRecord.tenant_id == tenant_id,
                ContextEnrichmentJobRecord.incident_id == incident_id,
                ContextEnrichmentJobRecord.status.in_(("scheduled", "collecting", "retry")),
            ))
            if not exists_row:
                raise ValueError("COLLECTION_JOB_MISSING")
        elif target == IncidentLifecycleState.WAITING_FOR_HUMAN:
            exists_row = await self.session.scalar(select(func.count()).select_from(
                HumanEvidenceRequestRecord,
            ).where(
                HumanEvidenceRequestRecord.tenant_id == tenant_id,
                HumanEvidenceRequestRecord.incident_id == incident_id,
                HumanEvidenceRequestRecord.status.in_(("pending", "assigned", "open", "in_progress")),
            ))
            if not exists_row:
                raise ValueError("ACTIVE_HUMAN_REQUEST_MISSING")
        elif target == IncidentLifecycleState.CONTEXT_READY:
            snapshot = await self.session.scalar(select(ContextSnapshotRecord.snapshot_id).where(
                ContextSnapshotRecord.tenant_id == tenant_id,
                ContextSnapshotRecord.incident_id == str(incident_id),
            ).limit(1))
            unresolved = await self.session.scalar(select(func.count()).select_from(
                ContextEvidenceRequirementRecord,
            ).where(
                ContextEvidenceRequirementRecord.tenant_id == tenant_id,
                ContextEvidenceRequirementRecord.incident_id == incident_id,
                ContextEvidenceRequirementRecord.status.notin_(("collected", "answered", "satisfied")),
            ))
            if snapshot is None or unresolved:
                raise ValueError("CONTEXT_NOT_READY")
        elif target in {IncidentLifecycleState.INVESTIGATING, IncidentLifecycleState.RCA_READY}:
            binding = await self.session.scalar(select(IncidentInvestigationBindingRecord).where(
                IncidentInvestigationBindingRecord.tenant_id == tenant_id,
                IncidentInvestigationBindingRecord.incident_id == incident_id,
            ).order_by(IncidentInvestigationBindingRecord.rca_version.desc()).limit(1))
            if target == IncidentLifecycleState.RCA_READY:
                latest_snapshot = await self.session.scalar(select(ContextSnapshotRecord.snapshot_id).where(
                    ContextSnapshotRecord.tenant_id == tenant_id,
                    ContextSnapshotRecord.incident_id == str(incident_id),
                ).order_by(ContextSnapshotRecord.snapshot_version.desc()).limit(1))
                if binding is None or binding.context_snapshot_id != latest_snapshot:
                    raise ValueError("CURRENT_RCA_BINDING_MISSING")
            if target == IncidentLifecycleState.INVESTIGATING:
                snapshot = await self.session.scalar(select(ContextSnapshotRecord.snapshot_id).where(
                    ContextSnapshotRecord.tenant_id == tenant_id,
                    ContextSnapshotRecord.incident_id == str(incident_id),
                ).limit(1))
                if snapshot is None:
                    raise ValueError("CONTEXT_SNAPSHOT_MISSING")
        elif target in {IncidentLifecycleState.PLAN_READY, IncidentLifecycleState.AWAITING_APPROVAL}:
            plan = await self.session.scalar(select(IncidentInvestigationBindingRecord.resolution_plan_id).where(
                IncidentInvestigationBindingRecord.tenant_id == tenant_id,
                IncidentInvestigationBindingRecord.incident_id == incident_id,
            ).order_by(IncidentInvestigationBindingRecord.rca_version.desc()).limit(1))
            if plan is None:
                raise ValueError("RESOLUTION_PLAN_MISSING")
        elif target == IncidentLifecycleState.EXECUTING:
            binding = await self.session.scalar(select(IncidentInvestigationBindingRecord).where(
                IncidentInvestigationBindingRecord.tenant_id == tenant_id,
                IncidentInvestigationBindingRecord.incident_id == incident_id,
            ).order_by(IncidentInvestigationBindingRecord.rca_version.desc()).limit(1))
            approval = await self.session.scalar(select(ApprovalRecord.id).where(
                ApprovalRecord.tenant_id == tenant_id, ApprovalRecord.incident_id == incident_id,
                ApprovalRecord.recommendation_id == binding.recommendation_id if binding else literal(False),
                ApprovalRecord.decision == "approved",
            ).order_by(ApprovalRecord.updated_at.desc()).limit(1))
            if approval is None:
                raise ValueError("APPROVAL_MISSING")
        elif target == IncidentLifecycleState.VALIDATING:
            succeeded = await self.session.scalar(select(ActionRecord.id).where(
                ActionRecord.tenant_id == tenant_id, ActionRecord.incident_id == incident_id,
                ActionRecord.status.in_(("succeeded", "completed")),
            ).order_by(ActionRecord.updated_at.desc()).limit(1))
            if succeeded is None:
                raise ValueError("EXECUTION_EVIDENCE_MISSING")
        elif target == IncidentLifecycleState.CLOSED:
            incident_status = await self.session.scalar(select(IncidentRecord.status).where(
                IncidentRecord.tenant_id == tenant_id, IncidentRecord.id == incident_id,
            ))
            if str(incident_status or "").lower() not in {"resolved", "closed"}:
                raise ValueError("VALIDATED_CLOSURE_MISSING")
    async def finish_context_enrichment_job(
        self, *, job_id: UUID | str, worker_id: str, collected: bool, error: str | None = None,
        retry_after_seconds: int = 60, maximum_attempts: int = 4,
        evidence_ids: list[str] | None = None,
    ) -> str:
        row = await self.session.get(ContextEnrichmentJobRecord, self._to_uuid(job_id))
        if row is None:
            raise LookupError("context enrichment job not found")
        if row.status != "collecting" or row.lease_owner != worker_id:
            raise RuntimeError("context enrichment job lease is not owned by this worker")
        requirement = await self.session.get(ContextEvidenceRequirementRecord, row.requirement_id)
        if collected:
            row.status = "collected"
            row.last_error = None
            if requirement is not None:
                requirement.status = "collected"
                requirement.evidence_ids = list(dict.fromkeys([
                    *(requirement.evidence_ids or []), *(evidence_ids or []),
                ]))
                requirement.version += 1
        elif int(row.attempt_count or 0) < maximum_attempts:
            row.status = "retry"
            row.available_at = datetime.now(UTC) + timedelta(seconds=max(1, retry_after_seconds))
            row.last_error = str(error or "evidence was not returned")[:4000]
            if requirement is not None:
                requirement.status = "scheduled"
                requirement.retry_count = int(requirement.retry_count or 0) + 1
                requirement.retry_after = row.available_at
                requirement.version += 1
        else:
            row.status = "dead_letter"
            row.last_error = str(error or "maximum collection attempts reached")[:4000]
            if requirement is not None:
                requirement.status = "blocked"
                requirement.retry_count = int(requirement.retry_count or 0) + 1
                requirement.version += 1
        row.version += 1
        row.lease_owner = None
        row.lease_expires_at = None
        await self.session.flush()
        return row.status

    async def enqueue_resolution_event(
        self,
        *,
        event_id: str,
        aggregate_id: str,
        topic: str,
        partition_key: str,
        payload: dict[str, Any],
        tenant_id: str = "default",
        available_after_seconds: float = 60.0,
    ) -> bool:
        """Persist the governed context-to-resolution handoff transactionally."""
        normalized_event_id = self._require("outbox.event_id", event_id)
        if await self.session.get(ResolutionOutboxRecord, normalized_event_id) is not None:
            return False
        from common.config import get_settings
        from common.outbox_context import compact_context

        normalized_tenant = require_tenant_id(tenant_id, source="resolution outbox")
        if get_settings().outbox_snapshot_references_enabled:
            payload = await compact_context(
                self.session,
                payload=payload,
                tenant_id=normalized_tenant,
                aggregate_id=aggregate_id,
                topic=topic,
            )
        self.session.add(
            ResolutionOutboxRecord(
                event_id=normalized_event_id,
                tenant_id=normalized_tenant,
                aggregate_id=self._require("outbox.aggregate_id", aggregate_id),
                topic=self._require("outbox.topic", topic),
                partition_key=self._require("outbox.partition_key", partition_key),
                payload=payload,
                status="pending",
                attempts=0,
                next_attempt_at=utc_now() + timedelta(seconds=max(0.0, float(available_after_seconds))),
            )
        )
        await self.session.flush()
        return True

    async def create_human_evidence_request(
        self, *, tenant_id: str, incident_id: UUID | str, requirement_id: UUID | str,
        expected_responder: str | None, due_at: datetime, acceptable_format: str,
        evidence_already_checked: list[str], hypothesis_impact: str,
        investigation_can_continue: bool = True, assignment_source: str | None = None,
        assignment_failure_reason: str | None = None, automatic_fallback: bool = False,
    ) -> HumanEvidenceRequestRecord | None:
        tenant = require_tenant_id(tenant_id, source="human evidence request")
        requirement_uuid = self._to_uuid(requirement_id)
        if automatic_fallback:
            requirement = await self.session.get(ContextEvidenceRequirementRecord, requirement_uuid)
            if requirement is None or requirement.tenant_id != tenant or requirement.incident_id != self._to_uuid(incident_id):
                raise ValueError("evidence requirement binding mismatch")
            if requirement.category not in {"ownership", "business_impact", "runbook", "ticket"}:
                # Failed automation is a collection problem, not a mandatory human questionnaire.
                # Keep every gap unsatisfied and preserve any submitted evidence.
                if requirement.status not in {"collected", "answered", "satisfied", "cancelled"}:
                    requests = (await self.session.scalars(select(HumanEvidenceRequestRecord).where(
                        HumanEvidenceRequestRecord.tenant_id == tenant,
                        HumanEvidenceRequestRecord.requirement_id == requirement_uuid,
                        HumanEvidenceRequestRecord.status.in_(["pending", "assignment_blocked"]),
                    ))).all()
                    if requirement.status == "blocked" and not requests:
                        return None
                    requirement.status = "blocked"
                    requirement.assigned_to = None
                    requirement.version = int(requirement.version or 0) + 1
                    for request in requests:
                        request.status = "cancelled"
                        request.assignment_failure_reason = "TECHNICAL_COLLECTION_REQUIRES_SOURCE"
                        request.version = int(request.version or 0) + 1
                    self.session.add(AuditLogRecord(id=uuid4(), tenant_id=tenant, actor="evidence-routing",
                        action="context.technical_collection.blocked", resource_type="evidence_requirement",
                        resource_id=str(requirement_uuid), payload={"category": requirement.category,
                            "reason": "Configured technical source or collector repair required", "evidence_satisfied": False}))
                    await self.session.flush()
                return None
        existing = (await self.session.execute(select(HumanEvidenceRequestRecord).where(
            HumanEvidenceRequestRecord.tenant_id == tenant,
            HumanEvidenceRequestRecord.requirement_id == requirement_uuid,
        ))).scalar_one_or_none()
        if existing is not None:
            return existing
        responder = str(expected_responder or "").strip() or None
        placeholders = {"incident-owner", "incident_owner", "unassigned", "admin", "operator", "unknown"}
        if responder and responder.lower() in placeholders:
            raise ValueError("placeholder HITL responder is not actionable")
        blocked = responder is None
        row = HumanEvidenceRequestRecord(
            tenant_id=tenant, incident_id=self._to_uuid(incident_id), requirement_id=requirement_uuid,
            expected_responder=responder, due_at=due_at,
            assignment_source=assignment_source,
            assignment_failure_reason=(
                str(assignment_failure_reason or "NO_AUTHORIZED_RESPONDER")[:512] if blocked else None
            ),
            acceptable_format=self._require("acceptable_format", acceptable_format),
            investigation_can_continue=investigation_can_continue,
            evidence_already_checked=list(evidence_already_checked),
            hypothesis_impact=self._require("hypothesis_impact", hypothesis_impact),
            status="assignment_blocked" if blocked else "pending", response_payload={},
            jira_sync_status=None if blocked else "pending", version=1,
        )
        self.session.add(row)
        requirement = await self.session.get(ContextEvidenceRequirementRecord, requirement_uuid)
        if requirement is not None and requirement.tenant_id == tenant:
            requirement.status = "assignment_blocked" if blocked else "human_requested"
            requirement.assigned_to = responder
            requirement.version += 1
        if not blocked:
            inc_uuid = self._to_uuid(incident_id)
            incident_row = await self.session.get(IncidentRecord, inc_uuid)
            if incident_row is not None and incident_row.tenant_id == tenant and incident_row.status in {"open", "acknowledged", "investigating", "collecting"}:
                incident_row.status = "waiting_for_human"
                incident_row.updated_at = datetime.now(UTC)
            projection_row = await self.session.scalar(select(IncidentProjectionRecord).where(
                IncidentProjectionRecord.tenant_id == tenant,
                IncidentProjectionRecord.incident_id == inc_uuid,
            ))
            if projection_row is not None and projection_row.status in {"open", "acknowledged", "investigating", "collecting"}:
                projection_row.status = "waiting_for_human"
                projection_row.lifecycle_state = "WAITING_FOR_HUMAN"
                projection_row.lifecycle_version = int(projection_row.lifecycle_version or 1) + 1
                projection_row.updated_at = datetime.now(UTC)
        await self.session.flush()
        return row

    async def list_human_evidence_request_queue(
        self, *, tenant_id: str, responder: str | None = None,
        statuses: tuple[str, ...] = ("pending", "assignment_blocked"), limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Cross-incident queue view: every unanswered human evidence request a
        responder (or, unfiltered, anyone) can act on, with enough incident and
        requirement context to work through the backlog without opening each
        incident individually first."""
        tenant = require_tenant_id(tenant_id, source="human evidence request queue")
        conditions = [
            HumanEvidenceRequestRecord.tenant_id == tenant,
            HumanEvidenceRequestRecord.status.in_(statuses),
        ]
        if responder:
            conditions.append(func.lower(HumanEvidenceRequestRecord.expected_responder) == responder.strip().lower())
        statement = select(HumanEvidenceRequestRecord).where(*conditions).order_by(
            HumanEvidenceRequestRecord.due_at, HumanEvidenceRequestRecord.created_at,
        ).limit(max(1, min(int(limit), 500)))
        rows = (await self.session.execute(statement)).scalars().all()
        result: list[dict[str, Any]] = []
        for row in rows:
            requirement = await self.session.get(ContextEvidenceRequirementRecord, row.requirement_id)
            incident = await self.session.get(IncidentRecord, row.incident_id)
            result.append({
                "request_id": str(row.request_id), "incident_id": str(row.incident_id),
                "requirement_id": str(row.requirement_id), "status": row.status,
                "expected_responder": row.expected_responder,
                "assignment_source": row.assignment_source,
                "assignment_failure_reason": row.assignment_failure_reason,
                "due_at": row.due_at, "created_at": row.created_at,
                "category": requirement.category if requirement else None,
                "question": requirement.question if requirement else row.acceptable_format,
                "reason": requirement.reason if requirement else row.hypothesis_impact,
                "incident_title": incident.title if incident else None,
                "incident_service": incident.service if incident else None,
                "incident_status": incident.status if incident else None,
            })
        return result

    async def resolve_human_evidence_responder(
        self, *, tenant_id: str, incident_id: UUID | str,
    ) -> dict[str, str] | None:
        """Resolve a real responder in governed precedence order."""
        tenant = require_tenant_id(tenant_id, source="human evidence responder")
        incident_uuid = self._to_uuid(incident_id)
        projection = await self.session.scalar(select(IncidentProjectionRecord).where(
            IncidentProjectionRecord.tenant_id == tenant,
            IncidentProjectionRecord.incident_id == incident_uuid,
        ))
        candidates: list[tuple[Any, str]] = []
        if projection is not None:
            candidates.append((projection.owner, "incident_assignment"))
        assignment = await self.session.scalar(select(ApprovalAssignmentRecord).where(
            ApprovalAssignmentRecord.tenant_id == tenant,
            ApprovalAssignmentRecord.incident_id == str(incident_uuid),
            ApprovalAssignmentRecord.status.in_(("assigned", "active")),
        ).order_by(ApprovalAssignmentRecord.updated_at.desc()).limit(1))
        if assignment is not None:
            candidates.append((assignment.assignee, "incident_assignment"))
        service = str(getattr(projection, "service", None) or "").strip()
        incident_row = await self.session.get(IncidentRecord, incident_uuid)
        if incident_row is not None:
            if not service:
                service = str(getattr(incident_row, "service", None) or "").strip()
            inc_payload = dict(incident_row.payload or {}) if isinstance(incident_row.payload, dict) else {}
            if inc_payload.get("owner"):
                candidates.append((inc_payload["owner"], "incident_assignment"))
        if service:
            application = await self.session.scalar(select(ApplicationRecord).where(
                ApplicationRecord.tenant_id == tenant,
                ApplicationRecord.name == service,
                ApplicationRecord.status.in_(("registered", "active", "ready")),
            ).order_by(ApplicationRecord.updated_at.desc()).limit(1))
            if application is not None:
                candidates.append((application.owner_email, "service_ownership"))
                candidates.append((application.owner_team, "service_ownership"))
            onboarding = await self.session.scalar(select(OnboardingStateRecord).where(
                OnboardingStateRecord.tenant_id == tenant,
                OnboardingStateRecord.project_name == service,
            ).order_by(OnboardingStateRecord.updated_at.desc()).limit(1))
            if onboarding is not None:
                candidates.append((onboarding.owner_team, "service_onboarding"))
        control = await self.session.scalar(select(OnboardingControlPlaneRecord).where(
            OnboardingControlPlaneRecord.tenant_id == tenant,
            OnboardingControlPlaneRecord.status.in_(("ACTIVE", "COMPLETED", "READY")),
        ).order_by(OnboardingControlPlaneRecord.updated_at.desc()).limit(1))
        payload = dict(control.payload or {}) if control and isinstance(control.payload, dict) else {}
        candidates.extend([
            (payload.get("escalation_responder") or payload.get("escalation_manager"), "escalation_policy"),
            (payload.get("default_responder") or payload.get("default_approver_group"), "tenant_default"),
            (payload.get("fallback_responder") or "sre-oncall@kaims.local", "tenant_fallback"),
        ])
        placeholders = {"", "incident-owner", "incident_owner", "unassigned", "admin", "operator", "unknown"}
        for value, source in candidates:
            identity = str(value or "").strip()
            if identity.lower() not in placeholders:
                return {"identity": identity, "source": source}
        return None

    async def claim_human_evidence_jira_requests(self, *, limit: int = 20) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        statement = select(HumanEvidenceRequestRecord).where(
            HumanEvidenceRequestRecord.status == "pending",
            HumanEvidenceRequestRecord.expected_responder.is_not(None),
            or_(
                HumanEvidenceRequestRecord.jira_sync_status == "pending",
                and_(
                    HumanEvidenceRequestRecord.jira_sync_status == "failed",
                    HumanEvidenceRequestRecord.updated_at < now - timedelta(minutes=5),
                ),
                and_(
                    HumanEvidenceRequestRecord.jira_sync_status == "syncing",
                    HumanEvidenceRequestRecord.updated_at < now - timedelta(minutes=5),
                ),
            ),
        ).order_by(HumanEvidenceRequestRecord.created_at, HumanEvidenceRequestRecord.request_id).limit(
            max(1, min(int(limit), 100))
        )
        if self.session.bind and self.session.bind.dialect.name != "sqlite":
            statement = statement.with_for_update(skip_locked=True)
        rows = (await self.session.execute(statement)).scalars().all()
        result: list[dict[str, Any]] = []
        for row in rows:
            requirement = await self.session.get(ContextEvidenceRequirementRecord, row.requirement_id)
            row.jira_sync_status = "syncing"
            row.version = int(row.version or 0) + 1
            result.append({
                "tenant_id": row.tenant_id, "incident_id": str(row.incident_id),
                "request_id": str(row.request_id), "requirement_id": str(row.requirement_id),
                "assignee_id": row.expected_responder, "due_at": row.due_at,
                "requested_evidence": requirement.question if requirement else row.acceptable_format,
                "reason": requirement.reason if requirement else row.hypothesis_impact,
            })
        await self.session.flush()
        return result

    async def fail_human_evidence_jira_sync(self, *, request_id: UUID | str, error: str) -> None:
        row = await self.session.get(HumanEvidenceRequestRecord, self._to_uuid(request_id))
        if row is not None and row.jira_sync_status != "synchronized":
            row.jira_sync_status = "failed"
            row.assignment_failure_reason = f"JIRA_SYNC_FAILED:{str(error)[:450]}"
            row.version = int(row.version or 0) + 1

    async def bind_human_evidence_jira(
        self, *, tenant_id: str, incident_id: UUID | str, request_id: UUID | str,
        requirement_id: UUID | str, jira_issue_key: str, jira_issue_url: str,
        jira_version: str | None, jira_assignee_id: str, sync_status: str,
    ) -> dict[str, Any]:
        tenant = require_tenant_id(tenant_id, source="human evidence Jira binding")
        row = await self.session.scalar(select(HumanEvidenceRequestRecord).where(
            HumanEvidenceRequestRecord.request_id == self._to_uuid(request_id),
            HumanEvidenceRequestRecord.requirement_id == self._to_uuid(requirement_id),
            HumanEvidenceRequestRecord.incident_id == self._to_uuid(incident_id),
            HumanEvidenceRequestRecord.tenant_id == tenant,
        ).with_for_update())
        if row is None:
            raise LookupError("human evidence request not found")
        if not row.expected_responder or row.expected_responder.casefold() != jira_assignee_id.casefold():
            raise ValueError("Jira assignee does not match the governed responder")
        key = self._require("jira_issue_key", jira_issue_key)
        if row.jira_issue_key and row.jira_issue_key != key:
            raise ValueError("human evidence request is already bound to another Jira issue")
        row.jira_issue_key = key
        row.jira_issue_url = self._require("jira_issue_url", jira_issue_url)
        row.jira_version = str(jira_version or "").strip() or None
        row.jira_assignee_id = jira_assignee_id
        row.jira_sync_status = self._require("jira_sync_status", sync_status)
        requirement = await self.session.get(ContextEvidenceRequirementRecord, row.requirement_id)
        if requirement is not None and requirement.tenant_id == tenant:
            requirement.jira_issue_key = key
        await self.session.flush()
        return {
            "request_id": str(row.request_id), "requirement_id": str(row.requirement_id),
            "jira_issue_key": key, "jira_issue_url": row.jira_issue_url,
            "jira_version": row.jira_version, "jira_assignee_id": row.jira_assignee_id,
            "jira_sync_status": row.jira_sync_status,
        }

    async def synchronize_human_evidence_jira_assignee(
        self, *, tenant_id: str, jira_issue_key: str, jira_assignee_id: str,
        jira_version: str | None, sync_status: str,
    ) -> dict[str, Any]:
        tenant = require_tenant_id(tenant_id, source="human evidence Jira synchronization")
        row = await self.session.scalar(select(HumanEvidenceRequestRecord).where(
            HumanEvidenceRequestRecord.tenant_id == tenant,
            HumanEvidenceRequestRecord.jira_issue_key == jira_issue_key,
        ).with_for_update())
        if row is None:
            raise LookupError("human evidence Jira request not found")
        if row.status != "pending":
            raise ValueError("completed human evidence request cannot be reassigned")
        row.expected_responder = self._require("jira_assignee_id", jira_assignee_id)
        row.jira_assignee_id = jira_assignee_id
        row.jira_version = str(jira_version or "").strip() or None
        row.jira_sync_status = self._require("jira_sync_status", sync_status)
        row.assignment_source = "jira_reassignment"
        row.version = int(row.version or 0) + 1
        requirement = await self.session.get(ContextEvidenceRequirementRecord, row.requirement_id)
        if requirement is not None and requirement.tenant_id == tenant:
            requirement.assigned_to = jira_assignee_id
            requirement.version = int(requirement.version or 0) + 1
        return {"request_id": str(row.request_id), "expected_responder": row.expected_responder,
                "jira_issue_key": jira_issue_key, "jira_sync_status": row.jira_sync_status}

    async def human_evidence_request_by_jira(
        self, *, tenant_id: str, jira_issue_key: str,
    ) -> dict[str, Any] | None:
        tenant = require_tenant_id(tenant_id, source="human evidence Jira lookup")
        row = await self.session.scalar(select(HumanEvidenceRequestRecord).where(
            HumanEvidenceRequestRecord.tenant_id == tenant,
            HumanEvidenceRequestRecord.jira_issue_key == jira_issue_key,
        ))
        if row is None:
            return None
        return {
            "request_id": str(row.request_id), "incident_id": str(row.incident_id),
            "requirement_id": str(row.requirement_id), "status": row.status,
            "expected_responder": row.expected_responder, "jira_version": row.jira_version,
        }

    async def record_human_evidence_response(
        self, *, tenant_id: str, incident_id: UUID | str, requirement_id: UUID | str,
        response: dict[str, Any],
    ) -> dict[str, Any]:
        from common.context_enrichment_contract import _CANONICAL_CATEGORY
        tenant = require_tenant_id(tenant_id, source="human evidence response")
        incident_uuid = self._to_uuid(incident_id)
        requirement_uuid = self._to_uuid(requirement_id)
        requirement = await self.session.get(ContextEvidenceRequirementRecord, requirement_uuid)
        request = (await self.session.execute(select(HumanEvidenceRequestRecord).where(
            HumanEvidenceRequestRecord.tenant_id == tenant,
            HumanEvidenceRequestRecord.incident_id == incident_uuid,
            HumanEvidenceRequestRecord.requirement_id == requirement_uuid,
        ))).scalar_one_or_none()
        responder = self._require("responder_id", response.get("responder_id"))
        manual_claim = bool(response.get("allow_manual_claim"))
        if request is None:
            if requirement is None or requirement.tenant_id != tenant or requirement.incident_id != incident_uuid:
                raise LookupError("human evidence request not found")
            request = HumanEvidenceRequestRecord(
                tenant_id=tenant, incident_id=incident_uuid, requirement_id=requirement_uuid,
                expected_responder=responder, due_at=datetime.now(UTC) + timedelta(hours=1),
                assignment_source="authenticated-operator-submission",
                assignment_failure_reason=None,
                acceptable_format=str(requirement.question or "Verified observation")[:512],
                investigation_can_continue=True,
                evidence_already_checked=list(requirement.candidate_connectors or []),
                hypothesis_impact=str(requirement.reason or "Human evidence submitted")[:512],
                status="pending", response_payload={}, jira_sync_status="pending", version=1,
            )
            self.session.add(request)
            await self.session.flush()
        if (not request.expected_responder or request.status == "assignment_blocked") and manual_claim:
            request.expected_responder = responder
            request.assignment_source = "authenticated-operator-manual-claim"
            request.assignment_failure_reason = None
            request.status = "pending"
            request.version += 1
        elif request.assignment_source == "tenant_fallback" and request.status == "pending":
            request.expected_responder = responder
            request.assignment_source = "authenticated-operator-fallback-claim"
            request.version += 1
        if not request.expected_responder or request.status == "assignment_blocked":
            raise ValueError("human evidence request has no authorized responder")
        if responder.casefold() != request.expected_responder.casefold():
            if manual_claim:
                request.expected_responder = responder
                request.assignment_source = "authenticated-operator-manual-claim"
                request.version += 1
            else:
                raise PermissionError("authenticated responder is not assigned to this evidence request")
        if request.status == "answered" and request.response_payload.get("evidence_id"):
            return {
                "request_id": str(request.request_id),
                "evidence_id": str(request.response_payload["evidence_id"]),
                "context_snapshot_id": request.response_payload.get("context_snapshot_id"),
                "knowledge_draft_id": request.response_payload.get("knowledge_draft_id"),
                "status": "answered", "idempotent": True,
            }
        source_reference = str(response.get("source_reference") or "").strip()
        if not source_reference:
            source_reference = f"kaiops://human-evidence/{incident_uuid}/{requirement_uuid}"
        responded_at = response.get("responded_at")
        observed_at = responded_at if isinstance(responded_at, datetime) else datetime.fromisoformat(
            str(responded_at or datetime.now(UTC).isoformat()).replace("Z", "+00:00")
        )
        if observed_at.tzinfo is None:
            observed_at = observed_at.replace(tzinfo=UTC)
        if requirement is None or requirement.tenant_id != tenant:
            raise LookupError("evidence requirement not found")
        observed_symptoms = str(response.get("observed_symptoms") or "").strip() or None
        root_cause_input = str(response.get("root_cause") or "").strip() or None
        business_impact_input = str(response.get("business_impact") or "").strip() or None
        remediation_steps_input = str(response.get("remediation_steps") or "").strip() or None
        assertion_text = self._require("human_evidence.response", response.get("response"))
        content: dict[str, Any] = {
            "assertion": assertion_text,
            "requirement_category": requirement.category,
            "question": requirement.question,
        }
        if observed_symptoms:
            content["observed_symptoms"] = observed_symptoms
        if root_cause_input:
            content["root_cause"] = root_cause_input
        if business_impact_input:
            content["business_impact"] = business_impact_input
        if remediation_steps_input:
            content["remediation_steps"] = remediation_steps_input
        identity = json.dumps({
            "tenant_id": tenant, "incident_id": str(incident_uuid),
            "requirement_id": str(requirement_uuid), "connector": "human-response",
            "source_reference": source_reference, "responder": responder,
            "content_digest": hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest(),
        }, sort_keys=True, separators=(",", ":"))
        evidence_id = f"EVD-{hashlib.sha256(identity.encode()).hexdigest()}"
        canonical_category = _CANONICAL_CATEGORY.get(requirement.category, "tickets")
        incident_row = await self.session.get(IncidentRecord, incident_uuid)
        projection_row = await self.session.scalar(select(IncidentProjectionRecord).where(
            IncidentProjectionRecord.tenant_id == tenant,
            IncidentProjectionRecord.incident_id == incident_uuid,
        ))
        incident_service = (
            str(getattr(incident_row, "service", None) or getattr(projection_row, "service", None) or "").strip() or None
        )
        incident_title = (
            str(getattr(incident_row, "title", None) or getattr(projection_row, "title", None) or "").strip() or None
        )
        if await self.session.get(CanonicalEvidenceRecord, evidence_id) is None:
            self.session.add(CanonicalEvidenceRecord(
                evidence_id=evidence_id, requirement_id=requirement_uuid,
                tenant_id=tenant, incident_id=incident_uuid, category=canonical_category,
                source_id=f"human:{responder}", connector="human-response",
                source_reference=source_reference, service=incident_service, resource=str(request.request_id),
                project_id=None, observed_at=observed_at, collected_at=datetime.now(UTC),
                observation_window_start=None, observation_window_end=None, freshness="fresh",
                content=content, provenance={
                    "responder_id": responder, "request_id": str(request.request_id),
                    "retrieval": "authenticated-human-submission",
                    "manual_claim": manual_claim,
                    "responder_role": str(response.get("responder_role") or ""),
                }, current_observation=True, contradiction_status=None,
                content_digest=hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest(),
            ))
        request.response_payload = {**dict(response), "source_type": "human_assertion", "evidence_id": evidence_id}
        request.status = "answered"
        request.version += 1
        requirement.status = "collected"
        requirement.evidence_ids = list(dict.fromkeys([*(requirement.evidence_ids or []), evidence_id]))
        requirement.version += 1
        remaining_pending = await self.session.scalar(select(func.count()).select_from(HumanEvidenceRequestRecord).where(
            HumanEvidenceRequestRecord.tenant_id == tenant,
            HumanEvidenceRequestRecord.incident_id == incident_uuid,
            HumanEvidenceRequestRecord.status == "pending",
            HumanEvidenceRequestRecord.request_id != request.request_id,
        ))
        remaining_human_reqs = await self.session.scalar(select(func.count()).select_from(ContextEvidenceRequirementRecord).where(
            ContextEvidenceRequirementRecord.tenant_id == tenant,
            ContextEvidenceRequirementRecord.incident_id == incident_uuid,
            ContextEvidenceRequirementRecord.requirement_id != requirement_uuid,
            ContextEvidenceRequirementRecord.collection_mode == "human_required",
            ContextEvidenceRequirementRecord.status.in_(("identified", "open", "pending", "human_requested", "blocked")),
        ))
        all_human_requirements_satisfied = not int(remaining_pending or 0) and not int(remaining_human_reqs or 0)
        if all_human_requirements_satisfied:
            if incident_row is not None and incident_row.tenant_id == tenant and incident_row.status == "waiting_for_human":
                incident_row.status = "investigating"
                if isinstance(getattr(incident_row, "payload", None), dict):
                    incident_row.payload = {**dict(incident_row.payload), "status": "investigating"}
                incident_row.updated_at = datetime.now(UTC)
            if projection_row is not None and projection_row.status == "waiting_for_human":
                projection_row.status = "investigating"
                projection_row.lifecycle_state = "INVESTIGATING"
                projection_row.lifecycle_version = int(projection_row.lifecycle_version or 1) + 1
                projection_row.updated_at = datetime.now(UTC)
        previous_snapshot = (await self.session.execute(
            select(ContextSnapshotRecord).where(
                ContextSnapshotRecord.tenant_id == tenant,
                ContextSnapshotRecord.incident_id == str(incident_uuid),
            ).order_by(ContextSnapshotRecord.snapshot_version.desc()).limit(1)
        )).scalar_one_or_none()
        snapshot_id: UUID | None = None
        knowledge_draft_id: str | None = None
        governed_document_payload: dict[str, Any] | None = None
        runbook_status: str | None = None
        learned_runbook_entry: dict[str, Any] | None = None
        has_runbook_guidance = bool(
            requirement.category == "runbook"
            or remediation_steps_input
            or root_cause_input
            or observed_symptoms
        )
        create_runbook_draft = bool(response.get("create_runbook_draft", False))
        if "auto_approve_runbook" in response and response.get("auto_approve_runbook") is not None:
            auto_approve_runbook = bool(response.get("auto_approve_runbook"))
        else:
            auto_approve_runbook = False
        if has_runbook_guidance and create_runbook_draft:
            alert_payload = (previous_snapshot.payload or {}).get("alert") if previous_snapshot and isinstance(previous_snapshot.payload, dict) else {}
            alert_name = str((alert_payload or {}).get("name") or incident_title or requirement.question or "incident").strip()
            svc = incident_service or str((alert_payload or {}).get("service") or "unknown-service").strip()
            env_name = str((alert_payload or {}).get("environment") or getattr(incident_row, "environment", None) or "prod").strip()
            alert_sig = str(getattr(previous_snapshot, "alert_signature", None) or "").strip()
            draft_source_ref = f"kaiops://learned-runbook/{tenant}/{svc}/{hashlib.sha256(alert_name.lower().encode()).hexdigest()[:16]}"
            draft_title = f"Runbook: {svc} - {alert_name}"[:240]
            frontmatter_lines = [
                f"title: {draft_title}",
                f"services: {svc}",
                f"alert_name: {alert_name}",
                f"environment: {env_name}",
                f"tenant_scope: {tenant}",
                "corpus_classification: TENANT_CURATED",
                f"source_ref: {draft_source_ref}",
                "",
                f"# {draft_title}",
                "",
                "## Symptoms & Root Cause",
                root_cause_input or observed_symptoms or assertion_text,
            ]
            if observed_symptoms and root_cause_input and observed_symptoms != root_cause_input:
                frontmatter_lines.extend(["", "### Observed Symptoms", observed_symptoms])
            if business_impact_input:
                frontmatter_lines.extend(["", "## Business Impact", business_impact_input])
            if remediation_steps_input:
                frontmatter_lines.extend(["", "## Remediation Steps", remediation_steps_input])
                cmd_lines = [
                    re.sub(r"^(?:[-*+]\s+|\d+[.)]\s+)", "", line.strip()).strip().strip("`").strip()
                    for line in remediation_steps_input.splitlines()
                    if line.strip() and any(
                        re.sub(r"^(?:[-*+]\s+|\d+[.)]\s+)", "", line.strip()).strip().strip("`").strip().lower().startswith(prefix)
                        for prefix in ("kubectl ", "docker ", "systemctl ", "curl ", "mysql ", "redis-cli ", "terraform ", "ansible-playbook ", "bash ", "sh ", "python ")
                    )
                ]
                if cmd_lines:
                    frontmatter_lines.extend(["", "## Remediation Script", "```bash", *cmd_lines, "```"])
            verification_steps_input = str(response.get("verification_steps") or "").strip()
            rollback_plan_input = str(response.get("rollback_plan") or "").strip()
            if verification_steps_input:
                frontmatter_lines.extend(["", "## Validation", verification_steps_input])
            elif remediation_steps_input:
                frontmatter_lines.extend(["", "## Validation", f"Verify {svc} health metrics and error rate return to baseline."])
            if rollback_plan_input:
                frontmatter_lines.extend(["", "## Rollback", rollback_plan_input])
            elif remediation_steps_input:
                frontmatter_lines.extend(["", "## Rollback", f"Revert the change or rollout undo on {svc} if metrics degrade."])
            draft_content = "\n".join(frontmatter_lines)
            if len(draft_content) < 40:
                draft_content = draft_content + "\n\nVerified operational guidance submitted by responder."
            draft_repo = IncidentRepository(self.session)
            draft_meta = {
                "incident_id": str(incident_uuid),
                "requirement_id": str(requirement_uuid),
                "evidence_id": evidence_id,
                "service": svc,
                "services": [svc],
                "environment": env_name,
                "alert_name": alert_name,
                "alert_signature": alert_sig,
                "observed_symptoms": observed_symptoms,
                "root_cause": root_cause_input,
                "business_impact": business_impact_input,
                "remediation_steps": remediation_steps_input,
            }
            draft = await draft_repo.create_knowledge_rag_draft(
                tenant_id=tenant,
                created_by=responder,
                document_kind="runbook",
                source_ref=draft_source_ref,
                title=draft_title,
                content=draft_content,
                metadata=draft_meta,
            )
            knowledge_draft_id = str(draft["draft_id"])
            runbook_status = str(draft.get("status") or "draft")
            rb_id = uuid5(NAMESPACE_URL, f"kaiops:runbook:{tenant}:{draft_source_ref}")
            rb_version = int(draft["document_version"])
            structured_draft_content = draft_repo._extract_structured_runbook_content(
                tenant_id=tenant,
                runbook_id=rb_id,
                version=rb_version,
                title=draft_title,
                markdown=draft_content,
                source_ref=draft_source_ref,
                metadata=draft_meta,
            )
            parent_rb = await self.session.get(RunbookRecord, rb_id)
            if parent_rb is None:
                self.session.add(RunbookRecord(
                    runbook_id=rb_id,
                    tenant_id=tenant,
                    slug=str(structured_draft_content.get("slug") or f"{svc}-{alert_name}".lower())[:255],
                    owner=str(responder or "hitl-responder")[:255],
                    service=str(svc or "unknown")[:255],
                    alert_family=str(alert_name or "incident_remediation")[:255],
                ))
            if await self.session.get(RunbookVersionRecord, (rb_id, rb_version)) is None:
                self.session.add(RunbookVersionRecord(
                    runbook_id=rb_id, version=rb_version, tenant_id=tenant,
                    issue_signature=hashlib.sha256(f"{tenant}:{svc}".encode()).hexdigest(),
                    approval_status="draft", owner=responder, risk_level="medium",
                    required_approval="HITL_APPROVER",
                    content={
                        **structured_draft_content,
                        "draft_id": knowledge_draft_id,
                        "approval_status": "draft",
                    },
                    created_at=datetime.now(UTC),
                ))
                await self.session.flush()
            if auto_approve_runbook:
                reviewed_draft = await draft_repo.review_knowledge_rag_draft(
                    tenant_id=tenant,
                    draft_id=knowledge_draft_id,
                    expected_row_version=int(draft["row_version"]),
                    title=draft_title,
                    content=draft_content,
                    review_notes="Automatically reviewed from verified responder runbook guidance",
                    reviewed_by=responder,
                )
                if reviewed_draft is not None:
                    approved_result = await draft_repo.approve_knowledge_rag_draft(
                        tenant_id=tenant,
                        draft_id=knowledge_draft_id,
                        expected_row_version=int(reviewed_draft["row_version"]),
                        approved_by=responder,
                    )
                    if approved_result is not None:
                        approved_draft, governed_document_payload = approved_result
                        runbook_status = str(approved_draft.get("status") or "approved_pending_index")
                        enriched_rb = draft_repo._extract_structured_runbook_content(
                            tenant_id=tenant,
                            runbook_id=rb_id,
                            version=rb_version,
                            title=draft_title,
                            markdown=draft_content,
                            source_ref=draft_source_ref,
                            metadata=draft_meta,
                        )
                        learned_runbook_entry = {
                            "runbook_id": str(rb_id),
                            "version": rb_version,
                            "tenant_id": tenant,
                            "issue_signature": hashlib.sha256(f"{tenant}:{svc}".encode()).hexdigest(),
                            "approval_status": "approved",
                            "risk_level": "medium",
                            "required_approval": "HITL_APPROVER",
                            "title": draft_title,
                            "service": svc,
                            "environment": env_name,
                            "alert_name": alert_name,
                            "alert_signature": alert_sig,
                            "markdown": draft_content,
                            "source_ref": draft_source_ref,
                            "draft_id": knowledge_draft_id,
                            "document_id": governed_document_payload.get("document_id"),
                            "observed_symptoms": enriched_rb.get("observed_symptoms"),
                            "root_cause": enriched_rb.get("root_cause"),
                            "business_impact": enriched_rb.get("business_impact"),
                            "remediation_steps": enriched_rb.get("remediation_steps"),
                            "commands": list(enriched_rb.get("commands") or []),
                            "execution_Verification": dict(enriched_rb.get("execution_Verification") or {}),
                            "approved_at": datetime.now(UTC).isoformat(),
                        }
            request.response_payload = {
                **request.response_payload,
                "knowledge_draft_id": knowledge_draft_id,
                "runbook_status": runbook_status,
                "governed_document_id": governed_document_payload.get("document_id") if governed_document_payload else None,
            }
        if previous_snapshot is not None:
            snapshot_payload = json.loads(json.dumps(previous_snapshot.payload or {}, default=str))
            if not incident_service:
                incident_service = str((snapshot_payload.get("alert") or {}).get("service") or "").strip() or None
            metadata = snapshot_payload.setdefault("metadata", {})
            metadata.pop("iterative_investigation", None)
            metadata.pop("investigation_report", None)
            if previous_snapshot.subject_fingerprint:
                metadata["context_subject_fingerprint"] = previous_snapshot.subject_fingerprint
            if knowledge_draft_id:
                metadata["knowledge_draft_id"] = knowledge_draft_id
                metadata["runbook_draft_id"] = knowledge_draft_id
            if learned_runbook_entry is not None:
                metadata["matched_learned_runbook"] = learned_runbook_entry
                metadata["learned_runbooks"] = [learned_runbook_entry]
            evidence = metadata.setdefault("context_evidence", {})
            evidence_uri = f"human-evidence://{tenant}/{incident_uuid}/{evidence_id}"
            evidence_entry = {
                "evidence_id": evidence_id, "requirement_id": str(requirement_uuid),
                "tenant_id": tenant, "incident_id": str(incident_uuid), "category": canonical_category,
                "source": canonical_category,
                "service": incident_service, "summary": assertion_text,
                "source_id": f"human:{responder}", "connector": "human-response",
                "uri": evidence_uri, "citation": evidence_uri, "source_ref": source_reference,
                "source_reference": source_reference, "observed_at": observed_at.isoformat(),
                "collected_at": datetime.now(UTC).isoformat(), "freshness": "fresh",
                "content": content, "provenance": {"responder_id": responder, "primary_source": evidence_uri},
                "current_observation": True,
            }
            bucket = evidence.setdefault(canonical_category, [])
            bucket.append(evidence_entry)
            if requirement.category != canonical_category:
                req_bucket = evidence.setdefault(requirement.category, [])
                req_bucket.append({**evidence_entry, "category": requirement.category})
            if has_runbook_guidance:
                sections = [
                    f"# Operational Runbook: {incident_service or 'Service'} ({incident_title or requirement.question})",
                    "",
                    "## Observed Symptoms & Root Cause",
                    root_cause_input or observed_symptoms or assertion_text,
                ]
                if observed_symptoms and root_cause_input and observed_symptoms != root_cause_input:
                    sections.extend(["", "### Observed Symptoms", observed_symptoms])
                if business_impact_input:
                    sections.extend(["", "## Business Impact", business_impact_input])
                if remediation_steps_input:
                    cmd_lines = [
                        re.sub(r"^(?:[-*+]\s+|\d+[.)]\s+)", "", line.strip()).strip().strip("`").strip()
                        for line in remediation_steps_input.splitlines()
                        if line.strip() and any(
                            re.sub(r"^(?:[-*+]\s+|\d+[.)]\s+)", "", line.strip()).strip().strip("`").strip().lower().startswith(prefix)
                            for prefix in ("kubectl ", "docker ", "systemctl ", "curl ", "mysql ", "redis-cli ", "terraform ", "ansible-playbook ", "bash ", "sh ", "python ")
                        )
                    ]
                    sections.extend(["", "## Remediation Steps", remediation_steps_input])
                    if cmd_lines:
                        sections.extend(["", "## Remediation Script", "```bash", *cmd_lines, "```"])
                runbook_markdown = "\n".join(sections)
                if not str(snapshot_payload.get("runbook") or "").strip() or requirement.category == "runbook":
                    snapshot_payload["runbook"] = runbook_markdown
                    metadata["document_available"] = True
                human_guided = dict(metadata.get("human_guided_input") or {})
                human_guided.update({
                    "evidence_id": evidence_id,
                    "requirement_id": str(requirement_uuid),
                    "responder_id": responder,
                    "source_reference": source_reference,
                    "assertion": assertion_text,
                    "observed_symptoms": observed_symptoms,
                    "root_cause": root_cause_input or observed_symptoms or (assertion_text if requirement.category == "runbook" else None),
                    "business_impact": business_impact_input or (assertion_text if requirement.category == "business_impact" else None),
                    "remediation_steps": remediation_steps_input,
                    "knowledge_draft_id": knowledge_draft_id,
                })
                metadata["human_guided_input"] = human_guided
                cq = dict(metadata.get("context_quality") or {})
                cq["rca_ready"] = True
                cq["discovery_degraded"] = False
                metadata["context_quality"] = cq
            elif requirement.category == "business_impact":
                human_guided = dict(metadata.get("human_guided_input") or {})
                human_guided.update({
                    "evidence_id": evidence_id,
                    "requirement_id": str(requirement_uuid),
                    "responder_id": responder,
                    "source_reference": source_reference,
                    "business_impact": business_impact_input or assertion_text,
                })
                metadata["human_guided_input"] = human_guided
                cq = dict(metadata.get("context_quality") or {})
                cq["rca_ready"] = True
                cq["discovery_degraded"] = False
                metadata["context_quality"] = cq
            new_snapshot_id = uuid4()
            human_analysis_request_id = uuid5(
                NAMESPACE_URL,
                f"kaims:human-enriched-analysis:{new_snapshot_id}",
            )
            new_snapshot_version = int(previous_snapshot.snapshot_version or 0) + 1
            new_evidence_ids = list(dict.fromkeys([*(previous_snapshot.evidence_ids or []), evidence_id]))
            cq = dict(metadata.get("context_quality") or {})
            satisfied_cats = {str(requirement.category).strip().lower(), str(canonical_category).strip().lower()}
            if has_runbook_guidance:
                satisfied_cats.update({"runbook", "knowledge"})
            existing_missing = [
                str(item).strip()
                for item in (cq.get("missing_required") or [])
                if str(item).strip() and str(item).strip().lower() not in satisfied_cats
            ]
            existing_present = list(dict.fromkeys([
                *(str(item).strip() for item in (cq.get("present") or []) if str(item).strip()),
                str(requirement.category).strip(),
                str(canonical_category).strip(),
            ]))
            cq["missing_required"] = existing_missing
            cq["present"] = existing_present
            all_requirements_satisfied = bool(all_human_requirements_satisfied and not existing_missing)
            is_reusable_snapshot = bool(
                all_requirements_satisfied
                and (
                    (has_runbook_guidance and auto_approve_runbook and governed_document_payload is not None)
                    or (not has_runbook_guidance and bool(snapshot_payload.get("runbook")))
                )
            )
            updated_quality_score = (
                max(float(previous_snapshot.quality_score or 0.0), 0.88)
                if is_reusable_snapshot
                else float(previous_snapshot.quality_score or 0.0)
            )
            if is_reusable_snapshot:
                cq.update({
                    "quality_score": updated_quality_score,
                    "reusable": True,
                    "valid": True,
                    "rca_ready": True,
                    "impact_ready": True,
                    "execution_ready": True,
                    "discovery_degraded": False,
                    "missing_required": [],
                })
            metadata["context_quality"] = cq
            metadata.update({
                "context_snapshot_id": str(new_snapshot_id),
                "analysis_request_id": str(human_analysis_request_id),
                "snapshot_stage": "human_enriched", "snapshot_version": new_snapshot_version,
                "evidence_ids": new_evidence_ids,
            })
            fingerprint = hashlib.sha256(
                json.dumps(snapshot_payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            metadata["context_fingerprint"] = fingerprint
            previous_expiry = previous_snapshot.expires_at
            if previous_expiry.tzinfo is None:
                previous_expiry = previous_expiry.replace(tzinfo=UTC)
            manifest_updates = {
                canonical_category: {
                    "connector": "human-response", "source_reference": source_reference,
                },
            }
            if requirement.category != canonical_category:
                manifest_updates[requirement.category] = {
                    "connector": "human-response", "source_reference": source_reference,
                }
            snapshot = ContextSnapshotRecord(
                snapshot_id=new_snapshot_id, tenant_id=tenant, incident_id=str(incident_uuid),
                source_incident_id=previous_snapshot.source_incident_id,
                alert_signature=previous_snapshot.alert_signature,
                subject_fingerprint=previous_snapshot.subject_fingerprint,
                context_fingerprint=fingerprint, parent_snapshot_id=previous_snapshot.snapshot_id,
                snapshot_stage="human_enriched",
                snapshot_version=new_snapshot_version, evidence_ids=new_evidence_ids,
                evidence_checksums={
                    **dict(previous_snapshot.evidence_checksums or {}),
                    evidence_id: hashlib.sha256(str(response.get("response") or "").encode()).hexdigest(),
                },
                contract_version=previous_snapshot.contract_version,
                quality_score=updated_quality_score, reusable=is_reusable_snapshot,
                source_manifest={**dict(previous_snapshot.source_manifest or {}), **manifest_updates},
                payload=snapshot_payload, collected_at=datetime.now(UTC),
                expires_at=max(previous_expiry, datetime.now(UTC) + timedelta(hours=1)),
            )
            self.session.add(snapshot)
            await self.session.flush()
            snapshot_id = snapshot.snapshot_id
            bindings = (await self.session.execute(select(IncidentInvestigationBindingRecord).where(
                IncidentInvestigationBindingRecord.tenant_id == tenant,
                IncidentInvestigationBindingRecord.incident_id == incident_uuid,
                IncidentInvestigationBindingRecord.status.notin_(["superseded", "invalidated"]),
            ))).scalars().all()
            for binding in bindings:
                binding.status = "invalidated"
            recommendation_ids = [binding.recommendation_id for binding in bindings]
            approvals = (await self.session.execute(select(ApprovalRecord).where(
                ApprovalRecord.tenant_id == tenant,
                ApprovalRecord.incident_id == incident_uuid,
                ApprovalRecord.recommendation_id.in_(recommendation_ids),
            ))).scalars().all() if recommendation_ids else []
            for approval in approvals:
                approval.decision = "stale"
                approval.payload = {**dict(approval.payload or {}),
                                    "invalidated_by_context_snapshot_id": str(snapshot_id)}
            jira_bindings = (await self.session.execute(select(JiraIncidentBindingRecord).where(
                JiraIncidentBindingRecord.tenant_id == tenant,
                JiraIncidentBindingRecord.incident_id == incident_uuid,
                JiraIncidentBindingRecord.status.notin_(["closed", "superseded", "stale"]),
            ))).scalars().all()
            for jira_binding in jira_bindings:
                jira_binding.status = "stale"
            outbox_event_id = f"context-human-enriched:{incident_uuid}:{snapshot.snapshot_id}"
            raw_inc = (
                dict(incident_row.payload)
                if incident_row is not None and isinstance(getattr(incident_row, "payload", None), dict)
                else {}
            )
            alert_dict = snapshot_payload.get("alert") if isinstance(snapshot_payload.get("alert"), dict) else {}
            resolved_service = (
                incident_service
                or str(raw_inc.get("service") or alert_dict.get("service") or "unknown-service").strip()
            )
            resolved_title = (
                incident_title
                or str(
                    raw_inc.get("title")
                    or alert_dict.get("name")
                    or requirement.question
                    or f"{resolved_service} incident"
                ).strip()
            )
            resolved_env = str(
                getattr(incident_row, "environment", None)
                or getattr(projection_row, "environment", None)
                or raw_inc.get("environment")
                or alert_dict.get("environment")
                or "prod"
            ).strip()
            resolved_sev = str(
                getattr(incident_row, "severity", None)
                or getattr(projection_row, "severity", None)
                or raw_inc.get("severity")
                or alert_dict.get("severity")
                or "warning"
            ).strip().lower()
            resolved_status = str(
                getattr(incident_row, "status", None)
                or getattr(projection_row, "status", None)
                or raw_inc.get("status")
                or "investigating"
            ).strip().lower()
            valid_statuses = {
                "open", "investigating", "waiting_for_human", "rca_ready",
                "awaiting_approval", "approved", "remediating", "validating",
                "resolved", "closed", "failed", "cancelled",
            }
            incident_outbox_payload = {
                "id": str(incident_uuid),
                "tenant_id": tenant,
                "service": resolved_service,
                "environment": resolved_env,
                "severity": resolved_sev if resolved_sev in {"info", "warning", "high", "critical"} else "warning",
                "status": resolved_status if resolved_status in valid_statuses else "investigating",
                "title": resolved_title,
                "summary": str(raw_inc.get("summary") or alert_dict.get("description") or resolved_title),
                "ticket_id": str(getattr(incident_row, "ticket_id", None) or raw_inc.get("ticket_id") or "") or None,
            }
            await self.enqueue_resolution_event(
                event_id=outbox_event_id,
                tenant_id=tenant,
                aggregate_id=str(incident_uuid),
                topic="context-events",
                partition_key=str(incident_uuid),
                available_after_seconds=0,
                payload={
                    "context": snapshot_payload,
                    "incident": incident_outbox_payload,
                    "decision": {
                        "context_snapshot_id": str(snapshot.snapshot_id),
                        "analysis_request_id": str(human_analysis_request_id),
                        "human_evidence": True,
                    },
                    "transport": "outbox",
                    "event_contract": {"event_id": outbox_event_id},
                },
            )
            request.response_payload = {
                **request.response_payload, "context_snapshot_id": str(snapshot.snapshot_id),
                "outbox_event_id": outbox_event_id,
            }
            if is_reusable_snapshot:
                inc_repo_for_knowledge = IncidentRepository(self.session)
                reusable_payload = json.loads(json.dumps(snapshot_payload, default=str))
                reusable_meta = reusable_payload.setdefault("metadata", {})
                if reusable_meta.get("human_guided_input"):
                    reusable_meta["historical_human_guidance"] = dict(reusable_meta.pop("human_guided_input"))
                source_alert_uuid = (
                    inc_repo_for_knowledge._parse_uuid(alert_dict.get("id"))
                    or inc_repo_for_knowledge._parse_uuid(raw_inc.get("alert_id"))
                    or incident_uuid
                )
                knowledge_id = await inc_repo_for_knowledge.save_context_knowledge(
                    tenant_id=tenant,
                    service=resolved_service,
                    environment=resolved_env,
                    alert_name=str(alert_dict.get("name") or resolved_title),
                    alert_signature=str(previous_snapshot.alert_signature or hashlib.sha256(f"{tenant}:{resolved_service}:{resolved_title}".lower().encode()).hexdigest()),
                    source_alert_id=source_alert_uuid,
                    source_incident_id=incident_uuid,
                    payload=reusable_payload,
                )
                metadata["context_knowledge_id"] = knowledge_id
                snapshot.payload = snapshot_payload
        self.session.add(AuditLogRecord(
            tenant_id=tenant, actor=responder, action="context.human-evidence.recorded",
            resource_type="incident", resource_id=str(incident_uuid),
            payload={"requirement_id": str(requirement_uuid), "evidence_id": evidence_id,
                     "category": canonical_category, "requirement_category": requirement.category,
                     "context_snapshot_id": str(snapshot_id) if snapshot_id else None,
                     "knowledge_draft_id": knowledge_draft_id,
                     "runbook_status": runbook_status,
                     "stale_approvals_invalidated": snapshot_id is not None},
        ))
        await self.session.flush()
        return {
            "request_id": str(request.request_id), "evidence_id": evidence_id,
            "category": canonical_category, "requirement_category": requirement.category,
            "context_snapshot_id": str(snapshot_id) if snapshot_id else None,
            "knowledge_draft_id": knowledge_draft_id,
            "runbook_status": runbook_status,
            "governed_document": governed_document_payload,
            "reusable": bool(snapshot.reusable) if previous_snapshot is not None else False,
            "context": snapshot.payload if previous_snapshot is not None else None,
            "status": "answered",
            "idempotent": False,
        }

    @staticmethod
    def _jira_binding_dict(row: JiraIncidentBindingRecord) -> dict[str, Any]:
        return {
            "binding_id": str(row.binding_id), "tenant_id": row.tenant_id,
            "incident_id": str(row.incident_id), "jira_issue_key": row.jira_issue_key,
            "jira_project_key": row.jira_project_key, "assignee_id": row.assignee_id,
            "assignee_group": row.assignee_group,
            "recommendation_id": str(row.recommendation_id) if row.recommendation_id else None,
            "rca_version": row.rca_version, "context_snapshot_id": str(row.context_snapshot_id),
            "context_fingerprint": row.context_fingerprint,
            "resolution_selection_id": str(row.resolution_selection_id) if row.resolution_selection_id else None,
            "execution_plan_id": str(row.execution_plan_id) if row.execution_plan_id else None,
            "plan_fingerprint": row.plan_fingerprint, "approval_expires_at": row.approval_expires_at,
            "status": row.status, "jira_status": row.jira_status, "ownership": row.ownership,
            "closure_policy": dict(row.closure_policy or {}),
            "last_jira_updated_at": row.last_jira_updated_at, "last_synced_at": row.last_synced_at,
            "binding_version": row.binding_version,
        }

    async def bind_jira_incident(
        self, *, tenant_id: str, incident_id: UUID | str, jira_issue_key: str,
        jira_project_key: str, assignee_id: str, assignee_group: str | None,
        recommendation_id: UUID | str, rca_version: int, context_snapshot_id: UUID | str,
        context_fingerprint: str, resolution_selection_id: UUID | str | None,
        execution_plan_id: UUID | str, plan_fingerprint: str,
        approval_expires_at: datetime, ownership: str, closure_policy: dict[str, Any],
        jira_status: str = "approval pending",
    ) -> dict[str, Any]:
        tenant = require_tenant_id(tenant_id, source="Jira incident binding")
        incident_uuid = self._to_uuid(incident_id)
        current = (await self.session.execute(
            select(IncidentInvestigationBindingRecord).where(
                IncidentInvestigationBindingRecord.tenant_id == tenant,
                IncidentInvestigationBindingRecord.incident_id == incident_uuid,
                IncidentInvestigationBindingRecord.status.notin_(["superseded", "invalidated"]),
            ).order_by(IncidentInvestigationBindingRecord.rca_version.desc()).limit(1)
        )).scalar_one_or_none()
        if current is None:
            raise ValueError("Jira HITL binding requires a current investigation")
        supplied = {
            "recommendation_id": str(recommendation_id), "rca_version": int(rca_version),
            "context_snapshot_id": str(context_snapshot_id), "context_fingerprint": context_fingerprint,
        }
        expected = {
            "recommendation_id": str(current.recommendation_id), "rca_version": current.rca_version,
            "context_snapshot_id": str(current.context_snapshot_id),
            "context_fingerprint": current.context_fingerprint,
        }
        if supplied != expected:
            raise ValueError("Jira HITL binding does not match the current investigation")
        plan = await self.session.get(ExecutionPlanRecord, self._to_uuid(execution_plan_id))
        if (
            plan is None or plan.tenant_id != tenant or plan.incident_id != incident_uuid
            or str(plan.fingerprint) != str(plan_fingerprint)
            or plan.context_snapshot_id != current.context_snapshot_id
        ):
            raise ValueError("Jira HITL binding does not match the current execution plan")
        previous = (await self.session.execute(select(JiraIncidentBindingRecord).where(
            JiraIncidentBindingRecord.tenant_id == tenant,
            JiraIncidentBindingRecord.incident_id == incident_uuid,
            JiraIncidentBindingRecord.status.notin_(["superseded", "closed"]),
        ).order_by(JiraIncidentBindingRecord.binding_version.desc()).limit(1))).scalar_one_or_none()
        next_version = 1
        if previous is not None:
            if previous.jira_issue_key == jira_issue_key and previous.execution_plan_id == plan.id:
                return self._jira_binding_dict(previous)
            previous.status = "superseded"
            next_version = previous.binding_version + 1
        row = JiraIncidentBindingRecord(
            tenant_id=tenant, incident_id=incident_uuid,
            jira_issue_key=self._require("jira_issue_key", jira_issue_key),
            jira_project_key=self._require("jira_project_key", jira_project_key),
            assignee_id=self._require("assignee_id", assignee_id), assignee_group=assignee_group,
            recommendation_id=self._to_uuid(recommendation_id), rca_version=rca_version,
            context_snapshot_id=self._to_uuid(context_snapshot_id),
            context_fingerprint=self._require("context_fingerprint", context_fingerprint),
            resolution_selection_id=self._to_uuid(resolution_selection_id),
            execution_plan_id=plan.id, plan_fingerprint=plan.fingerprint,
            approval_expires_at=approval_expires_at, status="pending", jira_status=jira_status,
            ownership=ownership, closure_policy=dict(closure_policy), binding_version=next_version,
        )
        self.session.add(row)
        await self.session.flush()
        audit_payload = json.loads(json.dumps(self._jira_binding_dict(row), default=str))
        self.session.add(AuditLogRecord(
            tenant_id=tenant, actor="jira-lifecycle", action="hitl.assignment.created",
            resource_type="incident", resource_id=str(incident_uuid),
            payload=audit_payload,
        ))
        await self.session.flush()
        return self._jira_binding_dict(row)

    async def get_jira_incident_binding(
        self, *, tenant_id: str, jira_issue_key: str, jira_project_key: str,
    ) -> dict[str, Any] | None:
        tenant = require_tenant_id(tenant_id, source="Jira binding lookup")
        row = (await self.session.execute(select(JiraIncidentBindingRecord).where(
            JiraIncidentBindingRecord.tenant_id == tenant,
            JiraIncidentBindingRecord.jira_issue_key == jira_issue_key,
            JiraIncidentBindingRecord.jira_project_key == jira_project_key,
        ).order_by(JiraIncidentBindingRecord.binding_version.desc()).limit(1))).scalar_one_or_none()
        return self._jira_binding_dict(row) if row else None

    async def current_governed_identity(
        self, *, tenant_id: str, incident_id: UUID | str,
    ) -> dict[str, Any]:
        tenant = require_tenant_id(tenant_id, source="current governed identity")
        incident_uuid = self._to_uuid(incident_id)
        investigation = (await self.session.execute(
            select(IncidentInvestigationBindingRecord).where(
                IncidentInvestigationBindingRecord.tenant_id == tenant,
                IncidentInvestigationBindingRecord.incident_id == incident_uuid,
                IncidentInvestigationBindingRecord.status.notin_(["superseded", "invalidated"]),
            ).order_by(IncidentInvestigationBindingRecord.rca_version.desc()).limit(1)
        )).scalar_one_or_none()
        plan = (await self.session.execute(
            select(ExecutionPlanRecord).where(
                ExecutionPlanRecord.tenant_id == tenant,
                ExecutionPlanRecord.incident_id == incident_uuid,
            ).order_by(ExecutionPlanRecord.created_at.desc()).limit(1)
        )).scalar_one_or_none()
        if investigation is None or plan is None:
            return {}
        return {
            "recommendation_id": str(investigation.recommendation_id),
            "rca_version": investigation.rca_version,
            "context_snapshot_id": str(investigation.context_snapshot_id),
            "context_fingerprint": investigation.context_fingerprint,
            "execution_plan_id": str(plan.id), "plan_fingerprint": plan.fingerprint,
        }

    async def record_jira_webhook_outcome(
        self, *, tenant_id: str, event_id: str, jira_issue_key: str, action: str,
        actor_id: str | None, outcome: str, payload: dict[str, Any],
    ) -> tuple[bool, JiraWebhookEventRecord]:
        tenant = require_tenant_id(tenant_id, source="Jira webhook event")
        existing = (await self.session.execute(select(JiraWebhookEventRecord).where(
            JiraWebhookEventRecord.tenant_id == tenant,
            JiraWebhookEventRecord.event_id == event_id,
        ))).scalar_one_or_none()
        if existing is not None:
            return False, existing
        checksum = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        row = JiraWebhookEventRecord(
            tenant_id=tenant, event_id=event_id, jira_issue_key=jira_issue_key,
            action=action, actor_id=actor_id, outcome=outcome, payload_checksum=checksum,
        )
        self.session.add(row)
        await self.session.flush()
        return True, row

    async def update_jira_binding_status(
        self, *, tenant_id: str, jira_issue_key: str, status: str,
        jira_status: str, jira_updated_at: datetime | None = None,
    ) -> dict[str, Any]:
        tenant = require_tenant_id(tenant_id, source="Jira binding update")
        row = (await self.session.execute(select(JiraIncidentBindingRecord).where(
            JiraIncidentBindingRecord.tenant_id == tenant,
            JiraIncidentBindingRecord.jira_issue_key == jira_issue_key,
        ).order_by(JiraIncidentBindingRecord.binding_version.desc()).limit(1))).scalar_one_or_none()
        if row is None:
            raise LookupError("Jira incident binding not found")
        row.status = status
        row.jira_status = jira_status
        row.last_jira_updated_at = jira_updated_at or datetime.now(UTC)
        row.last_synced_at = datetime.now(UTC)
        self.session.add(AuditLogRecord(
            tenant_id=tenant, actor="jira-lifecycle", action=f"jira.issue.{status}",
            resource_type="incident", resource_id=str(row.incident_id),
            payload={"jira_issue_key": jira_issue_key, "binding_id": str(row.binding_id)},
        ))
        await self.session.flush()
        return self._jira_binding_dict(row)

    async def save_jira_sync_cursor(
        self, *, tenant_id: str, jira_project_key: str, poll_status: str,
        last_successful_poll_at: datetime | None, last_jira_updated_timestamp: datetime | None,
        last_issue_key: str | None, poll_error: str | None,
    ) -> JiraSyncCursorRecord:
        tenant = require_tenant_id(tenant_id, source="Jira sync cursor")
        row = (await self.session.execute(select(JiraSyncCursorRecord).where(
            JiraSyncCursorRecord.tenant_id == tenant,
            JiraSyncCursorRecord.jira_project_key == jira_project_key,
        ))).scalar_one_or_none()
        if row is None:
            row = JiraSyncCursorRecord(tenant_id=tenant, jira_project_key=jira_project_key)
            self.session.add(row)
        row.poll_status = poll_status
        row.last_successful_poll_at = last_successful_poll_at
        row.last_jira_updated_timestamp = last_jira_updated_timestamp
        row.last_issue_key = last_issue_key
        row.poll_error = poll_error
        row.version = int(row.version or 0) + 1
        await self.session.flush()
        return row

    async def list_jira_sync_cursors(self, *, jira_project_key: str) -> list[JiraSyncCursorRecord]:
        result = await self.session.execute(select(JiraSyncCursorRecord).where(
            JiraSyncCursorRecord.jira_project_key == jira_project_key,
        ))
        return list(result.scalars().all())

    async def find_learned_runbooks(
        self,
        *,
        tenant_id: str,
        service: str | None = None,
        alert_name: str | None = None,
        alert_signature: str | None = None,
        environment: str | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        return await IncidentRepository(self.session).find_learned_runbooks(
            tenant_id=tenant_id,
            service=service,
            alert_name=alert_name,
            alert_signature=alert_signature,
            environment=environment,
            limit=limit,
        )
