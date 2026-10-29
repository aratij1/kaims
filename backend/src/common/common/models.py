from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from common.tenant_identity import require_tenant_id
from common.remediation_plan import RemediationPlan


def utc_now() -> datetime:
    return datetime.now(UTC)


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    WAITING_FOR_HUMAN = "waiting_for_human"
    # A grounded, conclusive RCA with no ready-to-execute plan yet - real
    # forward progress past "investigating", not yet in the approval/
    # execution flow (see repository.py's `_STATUS_PRECEDENCE`, which has
    # ranked this between "investigating" and "awaiting_approval" since the
    # very first fix of this pipeline). `IncidentRecord.status` (a plain
    # string column) has been able to hold this value since then, but this
    # enum - used to validate the `Incident` model wherever a persisted
    # incident is loaded and re-validated, e.g.
    # `_load_analysis_regeneration_subject`'s `Incident.model_validate` -
    # never included it. Reproduced live: regenerating analysis for any
    # incident that had reached "rca_ready" failed closed with a 409
    # ("Persisted alert or incident context is incomplete"), masking the
    # real pydantic ValidationError - permanently blocking a "Refresh
    # analysis" attempt on exactly the incidents furthest along the
    # pipeline, for as long as this status existed with nothing able to
    # regenerate it back out of that state.
    RCA_READY = "rca_ready"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REMEDIATING = "remediating"
    VALIDATING = "validating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ApprovalDecision(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"
    EVIDENCE_REQUESTED = "evidence_requested"


class RemediationStatus(StrEnum):
    DRAFT = "draft"
    POLICY_CHECKED = "policy_checked"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    DISPATCHING = "dispatching"
    EXECUTOR_ACCEPTED = "executor_accepted"
    PENDING = "pending"
    RUNNING = "running"
    VERIFYING = "verifying"
    PENDING_STABILITY = "pending_stability"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    POLICY_BLOCKED = "policy_blocked"
    DISPATCH_FAILED = "dispatch_failed"
    EXECUTION_FAILED = "execution_failed"
    VALIDATION_FAILED = "validation_failed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"


class SafetyDecision(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class MonitoringPlatform(StrEnum):
    PROMETHEUS = "prometheus"
    DATADOG = "datadog"
    NEW_RELIC = "new_relic"
    DYNATRACE = "dynatrace"
    SPLUNK = "splunk"


class ApplicationStatus(StrEnum):
    REGISTERED = "registered"
    DISCOVERING = "discovering"
    DISCOVERED = "discovered"
    METRICS_VALIDATED = "metrics_validated"
    RULES_GENERATED = "rules_generated"
    PROMETHEUS_UPDATED = "prometheus_updated"
    VALIDATED = "validated"
    DASHBOARD_CREATED = "dashboard_created"
    FAILED = "failed"
    DELETED = "deleted"


class GovernanceDecision(StrEnum):
    APPROVED = "approved"
    REQUIRES_APPROVAL = "requires_approval"
    REJECTED = "rejected"


class BaseEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=utc_now)
    trace_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApplicationRegistration(BaseEvent):
    tenant_id: str = "default"
    name: str
    owner_team: str
    owner_email: str | None = None
    environment: str = "prod"
    namespace: str
    region: str = "us-east-1"
    technology: str
    monitoring_platform: MonitoringPlatform = MonitoringPlatform.PROMETHEUS
    metrics_endpoint: str
    labels: dict[str, str] = Field(default_factory=dict)
    status: ApplicationStatus = ApplicationStatus.REGISTERED


class ApplicationDiscoveryResult(BaseEvent):
    application_id: UUID
    tenant_id: str = "default"
    name: str
    environment: str = "prod"
    namespace: str
    technology: str
    resource_kind: str = "deployment"
    discovered_resources: list[dict[str, Any]] = Field(default_factory=list)
    metrics_endpoint: str
    labels: dict[str, str] = Field(default_factory=dict)
    status: ApplicationStatus = ApplicationStatus.DISCOVERED


class MetricsValidationResult(BaseEvent):
    application_id: UUID
    tenant_id: str = "default"
    metrics_endpoint: str
    metrics_available: bool = False
    technology: str = "unknown"
    exporter: str = "unknown"
    labels: dict[str, str] = Field(default_factory=dict)
    metric_families: list[str] = Field(default_factory=list)
    sample_metrics: list[str] = Field(default_factory=list)
    status: ApplicationStatus = ApplicationStatus.METRICS_VALIDATED


class PrometheusRuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    expr: str
    duration: str = "5m"
    severity: str = "warning"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)


class RecordingRuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    expr: str
    labels: dict[str, str] = Field(default_factory=dict)


class ScrapeConfigSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_name: str
    targets: list[str] = Field(default_factory=list)
    metrics_path: str = "/metrics"
    scheme: str = "http"
    labels: dict[str, str] = Field(default_factory=dict)


class RulesGeneratedResult(BaseEvent):
    application_id: UUID
    tenant_id: str = "default"
    platform: MonitoringPlatform = MonitoringPlatform.PROMETHEUS
    scrape_config: ScrapeConfigSpec
    alert_rules: list[PrometheusRuleSpec] = Field(default_factory=list)
    recording_rules: list[RecordingRuleSpec] = Field(default_factory=list)
    governance: dict[str, Any] = Field(default_factory=dict)
    status: ApplicationStatus = ApplicationStatus.RULES_GENERATED


class PrometheusUpdateResult(BaseEvent):
    application_id: UUID
    tenant_id: str = "default"
    platform: MonitoringPlatform = MonitoringPlatform.PROMETHEUS
    files: dict[str, str] = Field(default_factory=dict)
    reload_ok: bool = False
    provider_response: dict[str, Any] = Field(default_factory=dict)
    status: ApplicationStatus = ApplicationStatus.PROMETHEUS_UPDATED


class MonitoringValidationResult(BaseEvent):
    application_id: UUID
    tenant_id: str = "default"
    target_up: bool = False
    metrics_available: bool = False
    alerts_loaded: bool = False
    recording_rules_loaded: bool = False
    service_discovery_ok: bool = False
    dashboard_ready: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
    status: ApplicationStatus = ApplicationStatus.VALIDATED


class GrafanaDashboardResult(BaseEvent):
    application_id: UUID
    tenant_id: str = "default"
    dashboard_uid: str
    title: str
    url: str | None = None
    dashboard: dict[str, Any] = Field(default_factory=dict)
    status: ApplicationStatus = ApplicationStatus.DASHBOARD_CREATED


class MonitoringAuditEvent(BaseEvent):
    application_id: UUID
    tenant_id: str = "default"
    event_type: str
    actor: str
    agent: str
    decision: str
    execution_time_ms: float = 0.0
    input: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] = Field(default_factory=dict)


class Alert(BaseEvent):
    tenant_id: str = "default"
    source: str
    name: str
    service: str
    environment: str = "prod"
    severity: AlertSeverity = AlertSeverity.WARNING
    description: str
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    starts_at: datetime = Field(default_factory=utc_now)
    ends_at: datetime | None = None
    fingerprint: str | None = None
    correlation_id: str | None = None
    deduplicated_count: int = 1

    @field_validator("source")
    @classmethod
    def normalize_source(cls, value: str) -> str:
        return value.strip().lower()


class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    source: str
    uri: str
    summary: str
    observed_at: datetime | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    attributes: dict[str, Any] = Field(default_factory=dict)


class RawAlert(BaseEvent):
    """Canonical, source-neutral alert accepted by Monitoring Adapters."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    source_event_id: str
    idempotency_key: str
    source: str
    source_type: str
    application: str
    service: str
    environment: str = "prod"
    observed_severity: AlertSeverity = AlertSeverity.WARNING
    title: str
    description: str
    observed_at: datetime = Field(default_factory=utc_now)
    raw_payload_ref: str
    fingerprint: str
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    evidence: list[EvidenceReference] = Field(default_factory=list)


class IncidentCandidate(BaseEvent):
    """Structured output of Discovery before deterministic policy/Jira."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    jira_key: str | None = None
    source_event_ids: list[str] = Field(default_factory=list)
    idempotency_key: str
    correlation_key: str
    application: str
    service: str
    environment: str = "prod"
    category: str
    title: str
    description: str
    initial_hypothesis: str
    technical_impact: str
    business_impact: str
    affected_users: str = "unknown"
    scope: str = "single-service"
    urgency: str = "normal"
    actionable: bool = True
    actionability_reason: str = ""
    recommended_severity: AlertSeverity
    final_severity: AlertSeverity | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    similar_incidents: list[dict[str, Any]] = Field(default_factory=list)
    model_provider: str = "heuristic-fallback"
    model_name: str = "deterministic-discovery-v1"
    model_version: str = "v1"
    reasoning: str = ""


class SeverityPolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommended_severity: AlertSeverity
    final_severity: AlertSeverity
    service_criticality: str
    environment: str
    impact: str
    urgency: str
    affected_users: str
    scope: str
    rules_fired: list[str] = Field(default_factory=list)
    policy_version: str = "incident-severity-policy-v1"


class JiraIncidentSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    jira_key: str
    status: str
    owner: str | None = None
    severity: AlertSeverity
    priority: str
    application: str
    service: str
    environment: str
    correlated_source_event_ids: list[str] = Field(default_factory=list)
    initial_hypothesis: str
    business_impact: str
    evidence: list[EvidenceReference] = Field(default_factory=list)
    similar_incidents: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    resolution_status: str = "unresolved"
    managed_by_kaiops: bool = True
    kaiops_incident_id: str
    event_origin: str = "kaiops"


class Incident(BaseEvent):
    tenant_id: str = "default"
    alert_ids: list[UUID] = Field(default_factory=list)
    service: str
    environment: str = "prod"
    severity: AlertSeverity = AlertSeverity.WARNING
    status: IncidentStatus = IncidentStatus.OPEN
    title: str
    summary: str = ""
    owner_team: str | None = None
    ticket_id: str | None = None
    # Jira enrichment is added after incident creation and is persisted with
    # the incident projection. Keep these fields in the shared contract so
    # downstream agents can validate enriched incidents without discarding
    # their ticket provenance or failing the workflow.
    jira_key: str | None = None
    jira_url: str | None = None
    jira_link: str | None = None
    jira_status: str | None = None
    closed_at: datetime | None = None


class Recommendation(BaseEvent):
    tenant_id: str
    incident_id: UUID
    root_cause: str
    confidence: float = Field(ge=0.0, le=1.0)
    impact: str
    recommended_action: str
    severity: AlertSeverity
    rationale: str
    commands: list[str] = Field(default_factory=list)
    risk: str = "medium"
    remediation_plan: RemediationPlan | None = None

    @field_validator("tenant_id")
    @classmethod
    def tenant_must_be_verified(cls, value: str) -> str:
        return require_tenant_id(value, source="recommendation identity")


class Approval(BaseEvent):
    tenant_id: str
    incident_id: UUID
    recommendation_id: UUID
    plan_id: UUID | None = None
    plan_fingerprint: str | None = None
    approval_expires_at: datetime | None = None
    approver_role: str | None = None
    authorization_scope: Literal["dry_run", "execution"] = "execution"
    decision: ApprovalDecision = ApprovalDecision.PENDING
    approver: str | None = None
    channel: str = "web"
    comment: str | None = None
    modified_action: str | None = None

    @field_validator("tenant_id")
    @classmethod
    def tenant_must_be_verified(cls, value: str) -> str:
        return require_tenant_id(value, source="approval identity")


class RemediationAction(BaseEvent):
    tenant_id: str
    incident_id: UUID
    approval_id: UUID | None = None
    recommendation_id: UUID | None = None
    resolution_plan_id: UUID | None = None
    plan_fingerprint: str | None = None
    action_type: str
    target: str
    # Deterministic sha256(incident_id:recommendation_id:action_type). Stable
    # across a redelivered approval/resolution message even though `id`
    # above is a fresh uuid4 every time — used to detect and skip re-executing
    # a remediation that already ran. None for actions with no execution risk.
    idempotency_key: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: RemediationStatus = RemediationStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    output: str = ""
    error: str | None = None

    @field_validator("tenant_id")
    @classmethod
    def tenant_must_be_verified(cls, value: str) -> str:
        return require_tenant_id(value, source="remediation action identity")


class ResolutionReport(BaseEvent):
    tenant_id: str
    incident_id: UUID
    ticket_id: str | None = None
    recommendation_id: UUID | None = None
    resolution_plan_id: UUID | None = None
    plan_fingerprint: str | None = None
    approval_id: UUID | None = None
    remediation_action_id: UUID | None = None
    validation_checksum: str | None = None
    closure_kind: str | None = None
    closure_status: str | None = None
    root_cause: str
    impact: str
    action_taken: str
    validation: dict[str, bool] = Field(default_factory=dict)
    alerts_cleared: bool = False
    health_restored: bool = False
    knowledge_base_entry: str = ""
    lessons_learned: list[str] = Field(default_factory=list)

    @field_validator("tenant_id")
    @classmethod
    def tenant_must_be_verified(cls, value: str) -> str:
        return require_tenant_id(value, source="resolution report identity")


class SafetyCheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: SafetyDecision = SafetyDecision.ALLOW
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    categories: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    provider: str = "local"


class GatewayAuditEvent(BaseEvent):
    method: str
    path: str
    target_url: str | None = None
    status_code: int | None = None
    latency_ms: float = 0.0
    safety: SafetyCheckResult = Field(default_factory=SafetyCheckResult)
    request_preview: dict[str, Any] = Field(default_factory=dict)
    response_preview: dict[str, Any] = Field(default_factory=dict)


class AgentEventContractV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    flow_id: str
    incident_id: str
    trace_id: str
    correlation_id: str | None = None
    timestamp: datetime = Field(default_factory=utc_now)
    agent: str
    version: str = "v1"
    payload: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""
    citations: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
