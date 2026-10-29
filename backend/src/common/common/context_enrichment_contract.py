from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from common.models import Alert, Incident
from common.evidence_source_policy import is_alert_artifact, is_derived_observation
from common.evidence_subject import metric_matches_subject, service_matches

EvidenceCategory = Literal[
    "metrics",
    "logs",
    "traces",
    "topology",
    "deployment",
    "change",
    "source_code",
    "database",
    "ticket",
    "runbook",
    "ownership",
    "business_impact",
    "validation",
]
CanonicalEvidenceCategory = Literal[
    "metrics", "logs", "traces", "topology", "changes", "source_code", "knowledge", "tickets",
]


def authorized_enrichment_connectors(
    *, alert_metadata: dict[str, Any], context_payload: dict[str, Any]
) -> set[str]:
    """Return tenant-resolved or canonically proven connectors for gap collection."""

    authorized = {"discovery-mcp", "local-evidence", "vector-db"}
    resolved = alert_metadata.get("resolved_context_connectors", [])
    if isinstance(resolved, list):
        authorized.update(
            str(item.get("provider") or "").strip().lower()
            for item in resolved
            if isinstance(item, dict) and str(item.get("provider") or "").strip()
        )

    metadata = context_payload.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    graph = metadata.get("context_graph")
    graph = graph if isinstance(graph, dict) else {}
    connectors = graph.get("connectors")
    connectors = connectors if isinstance(connectors, dict) else {}
    authorized.update(
        str(name).strip().lower()
        for name, state in connectors.items()
        if str(name).strip()
        and isinstance(state, dict)
        and str(state.get("status") or "").strip().lower() == "completed"
    )
    return authorized


def next_authorized_enrichment_connector(
    *, candidate_connectors: list[str], authorized_connectors: set[str],
    attempted_connectors: set[str] | None = None,
) -> str | None:
    attempted = {str(name).strip().lower() for name in (attempted_connectors or set())}
    authorized = {str(name).strip().lower() for name in authorized_connectors}
    return next(
        (
            name for name in candidate_connectors
            if str(name).strip().lower() in authorized
            and str(name).strip().lower() not in attempted
        ),
        None,
    )


class EvidenceRecord(BaseModel):
    """Canonical governed evidence shared by collection, context, RCA, and APIs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str = Field(min_length=1)
    requirement_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    category: CanonicalEvidenceCategory
    source_id: str = Field(min_length=1)
    connector: str = Field(min_length=1)
    source_reference: str = Field(min_length=1)
    service: str | None = None
    resource: str | None = None
    project_id: str | None = None
    observed_at: datetime
    collected_at: datetime
    observation_window_start: datetime | None = None
    observation_window_end: datetime | None = None
    freshness: Literal["fresh", "cached", "stale", "unknown"]
    content: dict[str, Any]
    provenance: dict[str, Any]
    current_observation: bool
    contradiction_status: str | None = None

    @model_validator(mode="after")
    def validate_binding(self) -> EvidenceRecord:
        UUID(self.incident_id)
        UUID(self.requirement_id)
        if self.observation_window_start and self.observation_window_end:
            if self.observation_window_end < self.observation_window_start:
                raise ValueError("observation window end precedes start")
        return self


class ConnectorNormalization(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[EvidenceRecord]
    metadata: dict[str, Any]
    rejected: list[dict[str, Any]] = Field(default_factory=list)


_CANONICAL_CATEGORY = {
    "metrics": "metrics", "logs": "logs", "traces": "traces",
    "topology": "topology",
    "deployment": "changes", "change": "changes", "source_code": "source_code",
    "database": "metrics",
    "ticket": "tickets",
    "runbook": "knowledge",
    "validation": "knowledge",
}


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=UTC)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _stable_evidence_id(
    *, requirement: EvidenceRequirement, connector: str, source_reference: str,
    observation_identity: Any, content: dict[str, Any],
) -> str:
    material = json.dumps({
        "tenant_id": requirement.tenant_id,
        "incident_id": str(requirement.incident_id),
        "category": _CANONICAL_CATEGORY.get(requirement.category, requirement.category),
        "connector": connector,
        "source_reference": source_reference,
        "observation_identity": observation_identity,
        "content_digest": hashlib.sha256(
            json.dumps(content, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest(),
    }, sort_keys=True, separators=(",", ":"), default=str)
    return f"EVD-{hashlib.sha256(material.encode()).hexdigest()}"


def normalize_connector_response(
    *, raw_response: dict[str, Any], requirement: EvidenceRequirement,
    incident: Incident, connector: str, collected_at: datetime,
) -> ConnectorNormalization:
    """Normalize a raw connector wrapper without discarding wrapper provenance."""
    now = collected_at if collected_at.tzinfo else collected_at.replace(tzinfo=UTC)
    wrapper = _redact_secrets(dict(raw_response))
    provenance = dict(wrapper.get("provenance") or {})
    query = str(wrapper.get("query") or provenance.get("query") or "").strip()
    endpoint = str(
        wrapper.get("endpoint") or wrapper.get("endpoint_identity")
        or provenance.get("endpoint") or connector
    ).strip()
    window_start_raw = wrapper.get("observation_window_start") or provenance.get("observation_window_start")
    window_end_raw = wrapper.get("observation_window_end") or provenance.get("observation_window_end")
    window_start = _parse_timestamp(window_start_raw) if window_start_raw is not None else None
    window_end = _parse_timestamp(window_end_raw) if window_end_raw is not None else None
    category = _CANONICAL_CATEGORY.get(requirement.category)
    if category is None:
        return ConnectorNormalization(
            records=[], metadata={"connector": connector, "endpoint": endpoint, "query": query},
            rejected=[{"code": "UNSUPPORTED_EVIDENCE_CATEGORY", "category": requirement.category}],
        )
    if requirement.tenant_id != incident.tenant_id or requirement.incident_id != incident.id:
        return ConnectorNormalization(
            records=[], metadata={"connector": connector, "endpoint": endpoint, "query": query},
            rejected=[{"code": "EVIDENCE_BINDING_MISMATCH"}],
        )
    raw_records = (
        wrapper.get("series") or wrapper.get("records") or wrapper.get("evidence")
        or wrapper.get("matches")
        # LocalEvidenceConnector reports its findings as separate code_matches/
        # log_matches lists rather than one of the envelope keys above; without
        # this, every local-evidence response normalized to zero records
        # regardless of what it actually found.
        or [*(wrapper.get("code_matches") or []), *(wrapper.get("log_matches") or [])]
    )
    if not isinstance(raw_records, list):
        raw_records = []
    if category == "topology" and not raw_records and any(
        wrapper.get(field) not in (None, "", [], {})
        for field in ("dependencies", "owner_team", "tier", "service", "resource")
    ):
        # CMDB connectors commonly return one service-inventory document
        # rather than a records envelope. Preserve that attributable response
        # as a single topology observation.
        raw_records = [wrapper]
    normalized: list[EvidenceRecord] = []
    rejected: list[dict[str, Any]] = []
    if category == "metrics":
        for index, raw in enumerate(raw_records):
            if not isinstance(raw, dict):
                rejected.append({"code": "INVALID_RECORD_TYPE", "record_index": index})
                continue
            record_query = str(raw.get("query") or query).strip()
            record_endpoint = str(raw.get("endpoint") or endpoint).strip()
            source_reference = str(raw.get("source_reference") or raw.get("uri") or
                                   f"prometheus://{record_endpoint}/query?expr={record_query}")
            try:
                record_start = _parse_timestamp(raw["observation_window_start"]) if raw.get("observation_window_start") else window_start
                record_end = _parse_timestamp(raw["observation_window_end"]) if raw.get("observation_window_end") else window_end
                if record_start and record_end and record_end <= record_start:
                    raise ValueError("reversed window")
            except (TypeError, ValueError, OSError):
                rejected.append({"code": "INVALID_OBSERVATION_WINDOW", "record_index": index})
                continue
            # Docker stats are numeric observations, not Prometheus series. Preserve
            # their real provider and observation time without claiming a past window.
            if raw.get("source") == "resource" and str(raw.get("uri") or "").startswith("docker://"):
                measurements = {key: raw[key] for key in (
                    "cpu_percent", "cpu_throttled_ratio", "mem_percent", "mem_working_set_bytes", "mem_limit_bytes"
                ) if isinstance(raw.get(key), (int, float)) and not isinstance(raw.get(key), bool)}
                try:
                    observed_at = _parse_timestamp(raw["observed_at"])
                    if not measurements or raw.get("provider_error"):
                        raise ValueError("missing samples")
                except (KeyError, TypeError, ValueError, OSError):
                    rejected.append({"code": "RESOURCE_SAMPLES_INCOMPLETE", "record_index": index})
                    continue
                content = {**raw, "measurements": measurements, "series_kind": "resource_snapshot"}
                normalized.append(EvidenceRecord(
                    evidence_id=_stable_evidence_id(requirement=requirement, connector=connector,
                        source_reference=source_reference, observation_identity=observed_at.isoformat(), content=content),
                    requirement_id=str(requirement.requirement_id), tenant_id=requirement.tenant_id,
                    incident_id=str(incident.id), category="metrics", source_id="docker", connector=connector,
                    source_reference=source_reference, service=incident.service if service_matches(raw.get("service") or incident.service, incident.service) else str(raw["service"]),
                    observed_at=observed_at, collected_at=now,
                    freshness="fresh" if abs((now - observed_at).total_seconds()) <= 900 else "stale",
                    content=content, provenance={"endpoint": source_reference, "observation_scope": "current_snapshot"},
                    current_observation=True,
                ))
                continue
            labels = raw.get("metric") if isinstance(raw.get("metric"), dict) else {}
            metric_name = str(labels.get("__name__") or "").strip()
            samples_raw = raw.get("values") if isinstance(raw.get("values"), list) else []
            if not samples_raw and isinstance(raw.get("value"), list):
                samples_raw = [raw["value"]]
            samples: list[dict[str, Any]] = []
            for sample_index, sample in enumerate(samples_raw):
                if not isinstance(sample, (list, tuple)) or len(sample) != 2:
                    rejected.append({"code": "INVALID_PROMETHEUS_SAMPLE", "record_index": index,
                                     "sample_index": sample_index})
                    continue
                try:
                    observed = _parse_timestamp(sample[0])
                except (TypeError, ValueError, OSError):
                    rejected.append({"code": "INVALID_OBSERVATION_TIMESTAMP", "record_index": index,
                                     "sample_index": sample_index})
                    continue
                samples.append({"timestamp": observed.isoformat(), "value": str(sample[1])})
            if not (metric_name or record_query) or not samples:
                rejected.append({"code": "PROMETHEUS_SERIES_INCOMPLETE", "record_index": index})
                continue
            if not metric_matches_subject(labels, incident.service,
                    target_labels=wrapper.get("preserved_labels") or {}, query=record_query):
                rejected.append({"code": "METRIC_SUBJECT_MISMATCH", "record_index": index})
                continue
            content = {"metric_name": metric_name or None, "expression": record_query or None,
                       "series_kind": "named_metric" if metric_name else "query_result",
                       "labels": dict(labels), "samples": samples,
                       "result_type": "matrix" if "values" in raw else "vector"}
            observed_at = max(_parse_timestamp(sample["timestamp"]) for sample in samples)
            evidence_id = _stable_evidence_id(
                requirement=requirement, connector=connector, source_reference=source_reference,
                observation_identity={"labels": labels, "samples": samples}, content=content,
            )
            normalized.append(EvidenceRecord(
                evidence_id=evidence_id, requirement_id=str(requirement.requirement_id),
                tenant_id=requirement.tenant_id, incident_id=str(incident.id), category="metrics",
                source_id=record_endpoint, connector=connector, source_reference=source_reference,
                service=incident.service,
                resource=str(labels.get("instance") or "") or None,
                project_id=str(labels.get("project_id") or "") or None,
                observed_at=observed_at, collected_at=now,
                observation_window_start=record_start, observation_window_end=record_end,
                freshness="fresh" if abs((now - observed_at).total_seconds()) <= 900 else "stale",
                content=content,
                provenance={**provenance, "query": record_query, "endpoint": record_endpoint,
                            "raw_result_type": "matrix" if "values" in raw else "vector"},
                current_observation=True, contradiction_status=None,
            ))
    else:
        required_fields = {
            "logs": ("message", "log"),
            "traces": ("trace_id", "span_id", "spans"),
            "topology": ("dependencies", "owner_team", "tier", "service", "resource"),
            "changes": ("change_id", "deployment_id", "commit_sha"),
            "source_code": ("commit_sha", "path", "repository"),
            "knowledge": ("document_id", "version"),
            "tickets": ("issue_key", "comment_id"),
        }
        for index, raw in enumerate(raw_records):
            if not isinstance(raw, dict):
                rejected.append({"code": "INVALID_RECORD_TYPE", "record_index": index})
                continue
            if category == "logs" and not (raw.get("message") or raw.get("log")) and raw.get("snippet"):
                raw = {**raw, "message": raw["snippet"]}
            if category == "knowledge":
                raw = {
                    **raw,
                    "version": raw.get("version") or raw.get("document_version") or raw.get("content_version"),
                    "approved": raw.get("approved") is True
                    or str(raw.get("review_status") or "").strip().lower() == "approved",
                    "source_reference": raw.get("source_reference") or raw.get("source_ref"),
                }
            if not any(raw.get(field) not in (None, "", [], {}) for field in required_fields[category]):
                rejected.append({"code": "EVIDENCE_REQUIRED_FIELD_MISSING", "record_index": index,
                                 "category": category})
                continue
            if category == "knowledge" and raw.get("approved") is not True:
                rejected.append({"code": "KNOWLEDGE_NOT_APPROVED", "record_index": index})
                continue
            source_reference = str(
                raw.get("source_reference") or raw.get("url") or raw.get("uri")
                or raw.get("repository_url") or raw.get("citation") or raw.get("source_uri") or ""
            ).strip()
            if category == "topology" and not source_reference:
                source_reference = f"cmdb://{endpoint}/service/{incident.service}"
            if not source_reference:
                rejected.append({"code": "EVIDENCE_SOURCE_REFERENCE_MISSING", "record_index": index})
                continue
            if category == "logs" and is_alert_artifact(raw):
                rejected.append({"code": "ALERT_ARTIFACT_NOT_OPERATIONAL_LOG", "record_index": index})
                continue
            if category == "logs" and is_derived_observation(raw):
                rejected.append({"code": "DERIVED_SUMMARY_NOT_SOURCE_LOG", "record_index": index})
                continue
            timestamp_missing = not any(raw.get(key) for key in ("observed_at", "timestamp", "updated_at", "created_at"))
            observed_raw = (
                raw.get("observed_at") or raw.get("timestamp") or raw.get("updated_at")
                or raw.get("created_at") or window_end_raw or now
            )
            try:
                observed_at = _parse_timestamp(observed_raw)
            except (TypeError, ValueError, OSError):
                rejected.append({"code": "INVALID_OBSERVATION_TIMESTAMP", "record_index": index})
                continue
            content = {
                key: value for key, value in raw.items()
                if key not in {"source_reference", "url", "uri", "repository_url", "provenance"}
            }
            identity = {
                key: raw.get(key) for key in (
                    "trace_id", "span_id", "change_id", "deployment_id", "commit_sha",
                    "document_id", "version", "issue_key", "comment_id", "timestamp",
                ) if raw.get(key) not in (None, "")
            } or {"source_reference": source_reference, "index": index}
            evidence_id = _stable_evidence_id(
                requirement=requirement, connector=connector, source_reference=source_reference,
                observation_identity=identity, content=content,
            )
            normalized.append(EvidenceRecord(
                evidence_id=evidence_id, requirement_id=str(requirement.requirement_id),
                tenant_id=requirement.tenant_id, incident_id=str(incident.id), category=category,
                source_id=endpoint, connector=connector, source_reference=source_reference,
                service=incident.service if service_matches(raw.get("service") or incident.service, incident.service) else str(raw["service"]),
                resource=str(raw.get("resource") or "") or None,
                project_id=str(raw.get("project_id") or "") or None,
                observed_at=observed_at, collected_at=now,
                observation_window_start=window_start, observation_window_end=window_end,
                freshness="unknown" if timestamp_missing else "fresh" if abs((now - observed_at).total_seconds()) <= 900 else "stale",
                content=content, provenance={**provenance, **dict(raw.get("provenance") or {}),
                                             "endpoint": endpoint, "timestamp_missing": timestamp_missing},
                current_observation=not timestamp_missing and bool(raw.get("current_observation", True)),
                contradiction_status=raw.get("contradiction_status"),
            ))
    return ConnectorNormalization(
        records=normalized,
        metadata={"connector": connector, "endpoint": endpoint, "query": query,
                  "observation_window_start": window_start.isoformat() if window_start else None,
                  "observation_window_end": window_end.isoformat() if window_end else None},
        rejected=rejected,
    )
RequirementStatus = Literal[
    "identified",
    "scheduled",
    "collecting",
    "collected",
    "blocked",
    "assignment_blocked",
    "human_requested",
    "answered",
    "expired",
    "cancelled",
]


class EvidenceRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requirement_id: UUID
    tenant_id: str = Field(min_length=1, max_length=128)
    incident_id: UUID
    rca_version: int = Field(ge=1)
    category: EvidenceCategory
    question: str = Field(min_length=1, max_length=2000)
    reason: str = Field(min_length=1, max_length=4000)
    priority: Literal["critical", "high", "medium", "low"]
    collection_mode: Literal["automatic", "connector_required", "human_required"]
    candidate_connectors: list[str] = Field(default_factory=list)
    status: RequirementStatus = "identified"
    retry_count: int = Field(default=0, ge=0)
    retry_after: datetime | None = None
    assigned_to: str | None = None
    jira_issue_key: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class EnrichmentPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    maximum_attempts: int = Field(default=4, ge=1, le=20)
    maximum_duration_seconds: int = Field(default=1800, ge=30, le=86400)
    source_timeout_seconds: int = Field(default=20, ge=1, le=300)
    retry_backoff_seconds: list[int] = Field(default_factory=lambda: [15, 60, 300])
    freshness_refresh_seconds: int = Field(default=300, ge=30, le=86400)
    stop_when_conclusive: bool = True


class EnrichmentResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scheduled_requirement_ids: list[UUID] = Field(default_factory=list)
    human_requirement_ids: list[UUID] = Field(default_factory=list)
    blocked_requirement_ids: list[UUID] = Field(default_factory=list)
    idempotency_keys: dict[UUID, str] = Field(default_factory=dict)


class EnrichmentValidationResult(BaseModel):
    accepted: bool
    accepted_evidence: list[dict[str, Any]] = Field(default_factory=list)
    rejected_evidence: list[dict[str, Any]] = Field(default_factory=list)
    rejection_reasons: list[str] = Field(default_factory=list)
    category: EvidenceCategory
    freshness_status: str


_SECRET_KEYS = {"password", "secret", "token", "authorization", "api_key", "apikey", "credential"}
_CATEGORY_MARKERS: dict[str, set[str]] = {
    "metrics": {"metric", "metrics", "prometheus"},
    "logs": {"log", "logs", "opensearch"},
    "traces": {"trace", "traces", "span", "jaeger"},
    "topology": {"topology", "dependency", "cmdb"},
    "deployment": {"deployment", "release", "jenkins", "kubernetes"},
    "change": {"change", "commit"},
    "source_code": {"source_code", "code", "github"},
    "database": {"database", "mysql", "query"},
    "ticket": {"ticket", "jira", "issue"},
    "runbook": {"runbook", "knowledge"},
    "ownership": {"ownership", "owner"},
    "business_impact": {"business_impact", "impact"},
    "validation": {"validation", "health"},
}


def _redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if str(key).lower() in _SECRET_KEYS else _redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value]
    return value


def validate_enrichment_observation(
    requirement: EvidenceRequirement,
    connector_id: str,
    observation: dict[str, Any],
    incident: Incident,
    alert: Alert,
    now: datetime,
) -> EnrichmentValidationResult:
    """Accept only attributable, fresh evidence for the exact declared category."""
    category = requirement.category
    rows: list[dict[str, Any]] = []
    for key in (
        "evidence",
        "records",
        "series",
        "matches",
        "spans",
        "logs",
        "recent_deployments",
        "recent_commits",
        "change_records",
        "dependencies",
    ):
        value = observation.get(key)
        if isinstance(value, list):
            rows.extend(dict(item) for item in value if isinstance(item, dict))
    if not rows and isinstance(observation, dict):
        rows = [dict(observation)]
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    reasons: list[str] = []
    expected_markers = _CATEGORY_MARKERS[category]
    for raw in rows:
        item = _redact_secrets(raw)
        marker = str(
            item.get("category") or item.get("kind") or item.get("source_type") or item.get("source") or connector_id
        ).lower()
        searchable_markers = {marker}
        if not any(expected in token for expected in expected_markers for token in searchable_markers):
            rejected.append(item)
            reasons.append(f"evidence category does not match {category}")
            continue
        tenant = str(item.get("tenant_id") or alert.tenant_id or "")
        service = str(item.get("service") or item.get("resource") or alert.service or "")
        if tenant != requirement.tenant_id or (alert.service and service != str(alert.service)):
            rejected.append(item)
            reasons.append("evidence tenant or service identity does not match")
            continue
        collected_raw = item.get("collected_at") or item.get("timestamp") or item.get("observed_at")
        try:
            collected_at = datetime.fromisoformat(str(collected_raw).replace("Z", "+00:00")) if collected_raw else now
            collected_at = (
                collected_at.replace(tzinfo=UTC) if collected_at.tzinfo is None else collected_at.astimezone(UTC)
            )
        except ValueError:
            rejected.append(item)
            reasons.append("evidence timestamp is invalid")
            continue
        if abs((now.astimezone(UTC) - collected_at).total_seconds()) > 86400:
            rejected.append(item)
            reasons.append("evidence is stale")
            continue
        required = {
            "metrics": bool(item.get("metric_name") or item.get("query"))
            and bool(item.get("value") is not None or item.get("values") or item.get("samples")),
            "logs": bool(item.get("message") or item.get("log") or item.get("records")),
            "traces": bool(item.get("trace_id") or item.get("span_id") or item.get("spans")),
            "runbook": bool(item.get("approved") is True and (item.get("version") or item.get("document_version"))),
        }.get(
            category,
            any(
                value not in (None, "", [], {})
                for key, value in item.items()
                if key not in {"provenance", "_source_status"}
            ),
        )
        if not required:
            rejected.append(item)
            reasons.append(f"{category} evidence is missing required factual fields")
            continue
        normalized = {
            **item,
            "category": category,
            "connector_id": connector_id,
            "tenant_id": requirement.tenant_id,
            "incident_id": str(incident.id),
            "service": service,
            "collected_at": collected_at.isoformat(),
            "source_reference": item.get("source_uri")
            or item.get("uri")
            or item.get("source_reference")
            or item.get("authoritative_source"),
        }
        if not normalized["source_reference"]:
            rejected.append(item)
            reasons.append("authoritative source reference is missing")
            continue
        normalized["evidence_id"] = str(
            item.get("evidence_id") or uuid5(NAMESPACE_URL, json.dumps(normalized, sort_keys=True, default=str))
        )
        normalized["integrity"] = {
            "sha256": hashlib.sha256(json.dumps(normalized, sort_keys=True, default=str).encode()).hexdigest()
        }
        normalized["provenance"] = {
            **(item.get("provenance") if isinstance(item.get("provenance"), dict) else {}),
            "connector_id": connector_id,
        }
        accepted.append(normalized)
    return EnrichmentValidationResult(
        accepted=bool(accepted),
        accepted_evidence=accepted,
        rejected_evidence=rejected,
        rejection_reasons=list(dict.fromkeys(reasons)),
        category=category,
        freshness_status="fresh" if accepted else "rejected",
    )


class HitlRoutingConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_approver_group: str
    l2_group: str
    l3_group: str
    service_owner: str
    escalation_manager: str | None = None
    timezone: str
    business_hours: dict
    severity_sla_minutes: dict[str, int]
    jira_project_key: str
    jira_issue_type: str
    jira_transition_mapping: dict[str, str]
    fallback_assignment_group: str

    @field_validator(
        "default_approver_group",
        "l2_group",
        "l3_group",
        "service_owner",
        "fallback_assignment_group",
    )
    @classmethod
    def reject_placeholder_assignees(cls, value: str) -> str:
        normalized = str(value or "").strip()
        if not normalized or normalized.lower() in {
            "admin", "operator", "unknown", "incident-owner", "incident_owner", "unassigned",
        }:
            raise ValueError("HITL assignees must be explicit governed identities")
        return normalized


class HitlAssignment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    incident_id: UUID
    assignee: str
    assignment_type: Literal["user", "group"]
    source: Literal[
        "incident_assignment",
        "service_owner",
        "environment_support",
        "application_support",
        "on_call",
        "tenant_fallback",
    ]
    approval_type: str
    due_at: datetime


class TicketClosurePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ownership: Literal["kaims", "human", "external"]
    kaims_may_close: bool
    requires_validation: bool = True
    requires_human_confirmation: bool = False
    reopen_on_regression: bool = True
    stability_window_seconds: int = Field(default=300, ge=0, le=604800)


class HumanEvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    response: str = Field(min_length=1, max_length=10000)
    responder_id: str = Field(min_length=1, max_length=255)
    source_reference: str | None = Field(default=None, max_length=1536)
    responded_at: datetime
    allow_manual_claim: bool = False
    responder_role: str | None = Field(default=None, max_length=128)
    observed_symptoms: str | None = Field(default=None, max_length=8000)
    root_cause: str | None = Field(default=None, max_length=8000)
    business_impact: str | None = Field(default=None, max_length=8000)
    remediation_steps: str | None = Field(default=None, max_length=10000)
    verification_steps: str | None = Field(default=None, max_length=8000)
    rollback_plan: str | None = Field(default=None, max_length=8000)
    create_runbook_draft: bool = False
    auto_approve_runbook: bool | None = None


class HumanEvidenceJiraRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    incident_id: UUID
    request_id: UUID
    requirement_id: UUID
    assignee_id: str = Field(min_length=1, max_length=255)
    due_at: datetime
    requested_evidence: str = Field(min_length=1, max_length=4000)
    reason: str = Field(min_length=1, max_length=4000)
    kaims_deep_link: str = Field(pattern=r"^https?://", max_length=1536)


_REQUIREMENT_CONNECTORS: dict[str, list[str]] = {
    # Prefer one registry-aware operational gateway. Preserve a dedicated
    # source fallback for deployments authorized only for that source.
    # Explicit bindings override defaults; knowledge is not live diagnostics.
    "metrics": ["discovery-mcp", "prometheus"],
    "logs": ["discovery-mcp", "opensearch"],
    "traces": ["discovery-mcp", "jaeger"],
    "topology": ["discovery-mcp"],
    "deployment": ["discovery-mcp"],
    "change": ["discovery-mcp"],
    "source_code": ["discovery-mcp"],
    "database": ["discovery-mcp", "prometheus"],
    "ticket": ["discovery-mcp", "jira", "vector-db"],
    "runbook": ["vector-db", "discovery-mcp", "local-evidence"],
    "validation": ["discovery-mcp", "local-evidence"],
}
_HUMAN_CATEGORIES = {"ownership", "business_impact"}
_CATEGORY_ALIASES = {
    "metric": "metrics",
    "telemetry": "metrics",
    "prometheus": "metrics",
    "log": "logs",
    "opensearch": "logs",
    "trace": "traces",
    "jaeger": "traces",
    "deployments": "deployment",
    "changes": "change",
    "dependency": "topology",
    "dependencies": "topology",
    "code": "source_code",
    "tickets": "ticket",
    "jira": "ticket",
    "rag": "runbook",
    "knowledge": "runbook",
    "runbooks": "runbook",
    "db": "database",
    "data": "database",
}


def legacy_discovery_category(question: str) -> str | None:
    """Recognize known older RCA request templates, not arbitrary prose."""
    text = " ".join(question.casefold().split()).rstrip(".")
    if text.startswith("deployment history or recent changes for "):
        return "deployment"
    if text == "resource telemetry and data-path health during the incident window":
        return "metrics"
    if text == "dependency health and saturation metrics":
        return "topology"
    return None


def evidence_category_reviewed(category: str, coverage: dict[str, int]) -> bool:
    sources = {"metrics": ("telemetry", "metrics"), "deployment": ("changes", "deployment"),
               "change": ("changes", "change"), "source_code": ("code", "source_code")}
    return any(coverage.get(source, 0) > 0 for source in sources.get(category, (category,)))


def discovery_evidence_requirements(*, previous_requirements: list[dict[str, Any]] | None = None,
                                  reviewed_sources: dict[str, int] | None = None,
                                  **kwargs: Any) -> list[EvidenceRequirement]:
    """Keep unresolved questions, and actively discover evidence to answer them."""
    requirements = build_evidence_requirements(**kwargs)
    if not any(row.category == "validation" and not row.candidate_connectors for row in requirements):
        return requirements
    # These are discovery questions, not inferred answers to the original gap.
    # Every result still passes source, tenant and observation-window validation.
    categories = {row.category for row in requirements}
    previous_questions = {str(row.get("question") or "").strip().casefold()
                          for row in previous_requirements or []
                          if int(row.get("rca_version") or 0) < int(kwargs["rca_version"])}
    probes = [
        {"category": category, "question": question,
         "reason": "Discover attributable evidence for unresolved RCA questions before requiring manual investigation."}
        for category, question in (
            ("metrics", "Discover service and dependency health measurements during the incident window."),
            ("logs", "Discover service errors and configuration failures during the incident window."),
            ("deployment", "Discover deployment and configuration changes around incident onset."),
            ("topology", "Discover the affected service resources and dependencies for targeted investigation."),
        ) if category not in categories and question.casefold() not in previous_questions
        and not evidence_category_reviewed(category, reviewed_sources or {})
    ]
    return requirements + build_evidence_requirements(**{**kwargs, "missing_evidence": probes})


def build_evidence_requirements(
    *,
    tenant_id: str,
    incident_id: UUID | str,
    rca_version: int,
    missing_evidence: list[object],
    now: datetime,
) -> list[EvidenceRequirement]:
    """Create deterministic work items from an RCA's declared evidence gaps.

    This lives in the shared contract package so the resolution service that
    discovers a gap and the context service that fulfils it cannot drift.
    """
    tenant = str(tenant_id or "").strip()
    if not tenant:
        raise ValueError("tenant_id is required to plan evidence")
    incident = UUID(str(incident_id))
    version = max(1, int(rca_version or 1))
    requirements: list[EvidenceRequirement] = []
    seen_requirement_ids: set[UUID] = set()
    valid_categories = set(EvidenceCategory.__args__)
    for raw in missing_evidence or []:
        gap = raw if isinstance(raw, dict) else {}
        token = str((gap.get("category") or gap.get("question") or "") if gap else raw).strip().lower()
        category = _CATEGORY_ALIASES.get(token, token)
        if not token or token == "none":
            continue
        legacy_category = legacy_discovery_category(str(raw)) if isinstance(raw, str) else None
        if legacy_category:
            category = legacy_category
            gap = {"question": raw, "reason": "Collect the requested evidence through the configured discovery sources."}
        if category not in valid_categories:
            # Preserve prose and unfamiliar gap codes as explicit review work.
            # Guessing a connector can falsely mark an unanswered question collected.
            gap = {**gap, "question": gap.get("question") or str(raw),
                   "reason": gap.get("reason") or "The RCA declared this evidence gap; collection needs a scoped source.",
                   "candidate_connectors": []}
            category = "validation"
        connectors = list((gap.get("candidate_connectors") or []) if "candidate_connectors" in gap else _REQUIREMENT_CONNECTORS.get(category, []))
        if category not in _CANONICAL_CATEGORY:
            # Do not schedule a source category that the evidence contract cannot ingest.
            connectors = []
        mode = (
            "human_required" if category in _HUMAN_CATEGORIES or gap.get("collection_mode") == "human_required" else ("automatic" if connectors else "connector_required")
        )
        question = " ".join(
            str(gap.get("question") or f"Collect {category} evidence for this incident.").split()
        )
        query_fingerprint = hashlib.sha256(question.casefold().encode()).hexdigest()
        identity = f"{tenant}:{incident}:{version}:{category}:{query_fingerprint}"
        requirement_id = uuid5(NAMESPACE_URL, identity)
        if requirement_id in seen_requirement_ids:
            continue
        seen_requirement_ids.add(requirement_id)
        requirements.append(
            EvidenceRequirement(
                requirement_id=requirement_id,
                tenant_id=tenant,
                incident_id=incident,
                rca_version=version,
                category=category,
                question=question,
                reason=str(gap.get("reason") or "Required to test the current RCA hypothesis."),
                priority=str(gap.get("priority") or "high"),
                collection_mode=mode,
                candidate_connectors=connectors,
                status="identified",
                created_at=now,
                updated_at=now,
            )
        )
    return requirements


def initial_causal_collection_gaps(
    *, source: str = "", environment: str = "",
) -> list[dict[str, Any]]:
    """Return the mandatory first-pass observations used to test causality.

    These are deliberately observations, not prerequisites for claiming that an
    incident exists.  A missing source remains an explicit gap and never becomes
    fabricated evidence.
    """
    gaps = [
        {
            "category": "traces",
            "question": "Collect fresh distributed traces for the affected service and incident window.",
            "reason": "Identify the slow or failing span and its upstream-to-downstream causal path.",
            "priority": "critical",
            "candidate_connectors": ["discovery-mcp", "jaeger"],
        },
        {
            "category": "topology",
            "question": "Collect fresh dependency health telemetry for the affected service.",
            "reason": "Determine whether an unhealthy downstream dependency explains the observed signal.",
            "priority": "critical",
            "candidate_connectors": ["discovery-mcp", "cmdb", "kubernetes"],
        },
        {
            "category": "topology",
            "question": "Collect the current runtime topology for the affected service.",
            "reason": "Bind the signal and trace path to the exact workloads and dependencies in scope.",
            "priority": "high",
            "candidate_connectors": ["discovery-mcp", "cmdb", "kubernetes"],
        },
    ]
    external_probe = (
        "blackbox" in str(source).lower()
        or "synthetic" in str(source).lower()
        or "public-internet" in str(environment).lower()
        or "public internet" in str(environment).lower()
    )
    if external_probe:
        return [{
            "category": "metrics",
            "question": "Collect timestamped HTTP status, probe success, DNS and TLS diagnostics for the exact monitored endpoint and incident window.",
            "reason": "Distinguish HTTP application responses from DNS, TLS or transport failures. A failed HTTP check alone does not establish packet loss or customer impact.",
            "priority": "critical",
            "candidate_connectors": ["prometheus", "discovery-mcp"],
        }]
    return gaps


class HitlJiraRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    incident_id: UUID
    service: str
    environment: str
    severity: str
    approval_type: str
    summary: str
    recommendation_id: UUID
    rca_version: int = Field(ge=1)
    context_snapshot_id: UUID
    context_fingerprint: str = Field(min_length=64, max_length=64)
    resolution_selection_id: UUID
    execution_plan_id: UUID
    plan_fingerprint: str = Field(min_length=64, max_length=71)
    risk: str
    rollback_plan: str
    approval_expires_at: datetime
    evidence_summary_url: str
    routing: HitlRoutingConfiguration
    closure_policy: TicketClosurePolicy


class JiraClosureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    incident_id: UUID
    jira_issue_key: str
    transition_id: str
    expected_jira_status: str
    remediation_status: str
    validation_status: str
    required_validators_complete: bool
    alerts_cleared: bool
    stability_window_passed: bool
    rollback_not_active: bool
    critical_contradictions: list[str] = Field(default_factory=list)
    current_plan_matches_approved_plan: bool
    human_confirmation: bool = False


class JiraRegressionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    incident_id: UUID
    jira_issue_key: str
    transition_id: str
    regression_evidence_ids: list[str] = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=2000)
