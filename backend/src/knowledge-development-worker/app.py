from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from common.config import get_settings
from common.continuous_learning import FailurePattern, FailurePatternAnalyzer, IncidentEvidence, issue_signature
from common.database import ActionRecord, FailurePatternRecord, IncidentEvidenceRecord, IncidentRecord, KnowledgeBaseRecord, KnowledgeRagDraftRecord, LearningAuditRecord, RcaReportRecord, RunbookOutcomeRecord, RunbookVersionRecord
from common.learning_workflows import Mode02Worker
from common.models import EvidenceReference
from common.service import create_app
from common.tenant_identity import require_tenant_id
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.orm import load_only

settings = get_settings()
settings.service_name = "knowledge-development-worker"
interval_seconds = max(300, int(os.getenv("KNOWLEDGE_DEVELOPMENT_INTERVAL_SECONDS", "21600")))
batch_size = max(25, min(int(os.getenv("KNOWLEDGE_DEVELOPMENT_BATCH_SIZE", "500")), 2000))
task: asyncio.Task | None = None
run_lock = asyncio.Lock()
schedule_wakeup = asyncio.Event()
last_result: dict[str, Any] = {"status": "not_run"}
schedule_config: dict[str, Any] = {
    "enabled": True, "interval_seconds": interval_seconds, "lookback_days": 30,
    "application_scope": "all", "collect_logs": True, "collect_metrics": True,
    "collect_traces": True, "collect_tickets": True, "collect_changes": True,
    "minimum_occurrences": 3, "minimum_confidence": 0.70,
    "minimum_success_rate": 0.80, "minimum_reviewed_incidents": 2,
}
configuration_id = uuid5(NAMESPACE_URL, "kaims:knowledge-development:configuration:default")


class ScheduleConfig(BaseModel):
    enabled: bool = True
    interval_hours: int = Field(default=6, ge=1, le=168)
    lookback_days: int = Field(default=30, ge=1, le=365)
    application_scope: str = Field(default="all", max_length=255)
    collect_logs: bool = True
    collect_metrics: bool = True
    collect_traces: bool = True
    collect_tickets: bool = True
    collect_changes: bool = True
    minimum_occurrences: int = Field(default=3, ge=2, le=100)
    minimum_confidence: float = Field(default=0.70, ge=0.5, le=0.99)
    minimum_success_rate: float = Field(default=0.80, ge=0.5, le=1.0)
    minimum_reviewed_incidents: int = Field(default=2, ge=1, le=100)


class IncidentBootstrapRequest(BaseModel):
    incident: dict[str, Any]
    context: dict[str, Any]
    recommendation: dict[str, Any] = Field(default_factory=dict)


class RunRequest(BaseModel):
    tenant_id: str
    application_scope: str = Field(default="all", max_length=255)


class CatalogPromotionRequest(BaseModel):
    tenant_id: str
    actor: str = Field(min_length=1, max_length=255)
    decision: Literal["approve", "reject"]
    expected_content_sha256: str = Field(min_length=64, max_length=64)
    risk_level: Literal["low", "medium", "high"] = "medium"
    reason: str = Field(default="", max_length=2000)


def _promotion_readiness(content: dict[str, Any], *, reviewed_success: bool) -> list[str]:
    quality = content.get("knowledge_quality") if isinstance(content.get("knowledge_quality"), dict) else {}
    reasons = []
    if quality.get("passed") is not True:
        reasons.append("knowledge quality gate has not passed")
    if content.get("catalog_stage") != "resolution_candidate":
        reasons.append("candidate has not reached resolution stage")
    if not reviewed_success:
        reasons.append("a reviewed successful recovery is required")
    for field in ("remediation_steps", "validation_steps", "rollback_steps"):
        if not isinstance(content.get(field), list) or not any(str(value).strip() for value in content[field]):
            reasons.append(f"{field.replace('_', ' ')} are incomplete")
    return reasons


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    value = _utc(value)
    return value.isoformat() if value else None


def _hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _in_application_scope(scope: str, *, service: str, application: str = "") -> bool:
    normalized = scope.strip().lower()
    # KaiMS/Platform are aggregate workspace labels in the UI, not literal
    # service names. Treat both as the tenant-wide operational scope.
    return normalized in {"", "all", "kaims", "platform"} or normalized in {service.lower(), application.lower()}


def _quality_gate(pattern: FailurePattern, evidence_by_id: dict[str, IncidentEvidence]) -> dict[str, Any]:
    rows = [evidence_by_id[item] for item in pattern.incident_ids if item in evidence_by_id]
    reviewed = sum(row.reviewed for row in rows)
    successful = sum(row.resolution_successful is True for row in rows)
    resolved = sum(row.resolution_successful is not None for row in rows)
    success_rate = successful / resolved if resolved else 0.0
    sources = len({ref.source for ref in pattern.evidence_references})
    checks = {
        "occurrences": pattern.occurrence_frequency >= int(schedule_config["minimum_occurrences"]),
        "confidence": pattern.confidence >= float(schedule_config["minimum_confidence"]),
        "reviewed_incidents": reviewed >= int(schedule_config["minimum_reviewed_incidents"]),
        "success_rate": success_rate >= float(schedule_config["minimum_success_rate"]),
        "independent_sources": sources >= 2,
        "successful_resolution": bool(pattern.successful_resolutions),
        "no_conflicts": not pattern.conflicts,
    }
    return {
        "passed": all(checks.values()), "checks": checks,
        "metrics": {"occurrences": pattern.occurrence_frequency, "confidence": round(pattern.confidence, 4), "reviewed_incidents": reviewed, "resolved_incidents": resolved, "success_rate": round(success_rate, 4), "independent_sources": sources},
        "policy_version": "kaims.knowledge-quality.v2",
    }


def _state_id(tenant_id: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"kaims:knowledge-development:state:{tenant_id}")


async def _load_state(app: FastAPI, tenant_id: str = "default") -> dict[str, Any]:
    if not settings.database_enabled:
        return {}
    async with app.state.session_factory() as session:
        row = await session.get(KnowledgeBaseRecord, _state_id(tenant_id))
        return dict(row.payload) if row and isinstance(row.payload, dict) else {}


async def _save_state(session: Any, payload: dict[str, Any], tenant_id: str = "default") -> None:
    await session.merge(KnowledgeBaseRecord(id=_state_id(tenant_id), tenant_id=tenant_id, service="KaiMS", title="Periodic knowledge development durable state", content=json.dumps(payload, sort_keys=True), embedding_ref=None, payload=payload))


async def _draft_candidate(
    session: Any,
    pattern: FailurePattern,
    quality: dict[str, Any],
    *,
    allow_evidence_work: bool = False,
    tenant_id: str = "default",
) -> bool:
    checks = quality.get("checks") or {}
    diagnostic_only = not quality["passed"]
    # Cold-start candidates may describe read-only diagnostics, but never a
    # production mutation. Two independent sources and no known conflicts are
    # still mandatory so the catalog is not populated from a lone alert.
    if diagnostic_only and not checks.get("no_conflicts"):
        return False
    if diagnostic_only and not allow_evidence_work and not checks.get("independent_sources"):
        return False
    tenant_id = require_tenant_id(tenant_id, source="knowledge development candidate")
    runbook_id = uuid5(NAMESPACE_URL, f"kaims:runbook:{tenant_id}:{pattern.issue_signature}")
    latest = (await session.execute(select(RunbookVersionRecord).where(RunbookVersionRecord.tenant_id == tenant_id, RunbookVersionRecord.runbook_id == runbook_id).order_by(RunbookVersionRecord.version.desc()).limit(1))).scalar_one_or_none()
    if diagnostic_only:
        payload = {
            "issue_signature": pattern.issue_signature,
            "service_scope": [pattern.service],
            "prerequisites": ["Confirm the live incident matches the observed failure signature."],
            "diagnostic_steps": [
                *([f"Verify symptom: {item}" for item in pattern.common_symptoms]
                  or ["Collect incident-window logs, metrics, traces, changes, and ticket evidence."]),
                "Compare the affected target with a healthy peer and the last known-good baseline.",
                "Record the verified causal mechanism or explicitly record that it remains unknown.",
            ],
            "remediation_steps": [],
            "validation_steps": [],
            "rollback_steps": [],
            "risk_level": "low",
            "required_approval": "mandatory",
            "evidence_references": [item.model_dump(mode="json") for item in pattern.evidence_references[:50]],
            "owner": "unassigned",
        }
    else:
        draft = Mode02Worker._draft_runbook(pattern)
        payload = draft.model_dump(mode="json", exclude={"runbook_id", "created_at", "version"})
    payload.update({
        "runbook_id": str(runbook_id), "name": f"Resolve {pattern.alert_type} for {pattern.service}",
        "application": pattern.service, "environment": pattern.environment,
        "matching_conditions": {"issue_signature": pattern.issue_signature},
        "supporting_evidence": [item.model_dump(mode="json") for item in pattern.evidence_references[:50]],
        "review_state": "awaiting_hitl_review", "knowledge_quality": quality,
        "catalog_stage": (
            "evidence_work_candidate"
            if diagnostic_only and allow_evidence_work and not checks.get("independent_sources")
            else "diagnostic_candidate" if diagnostic_only else "resolution_candidate"
        ),
        "execution_eligible": False,
        "promotion_requirements": ([] if not diagnostic_only else [
            "Operator-confirmed causal mechanism",
            "At least one reviewed successful resolution outcome",
            "Complete remediation, validation, and rollback steps",
            "Fresh human approval of the promoted version",
        ]),
        "generation_policy": "immutable-challenger-v2",
    })
    candidate_hash = _hash(payload)
    latest_payload = latest.content if latest and isinstance(latest.content, dict) else {}
    if latest and latest_payload.get("content_sha256") == candidate_hash:
        return False
    version = latest.version + 1 if latest else 1
    payload.update({"version": version, "content_sha256": candidate_hash})
    session.add(RunbookVersionRecord(runbook_id=runbook_id, version=version, tenant_id=tenant_id, issue_signature=pattern.issue_signature, approval_status="draft", owner=str(payload.get("owner") or "unassigned"), risk_level=str(payload.get("risk_level") or "low"), required_approval="mandatory", content=payload))
    audit = {"status": "draft", "version": version, "issue_signature": pattern.issue_signature, "content_sha256": candidate_hash, "quality_gate": quality, "catalog_stage": payload["catalog_stage"], "execution_eligible": False, "requires_human_approval": True}
    session.add(LearningAuditRecord(event_id=uuid5(NAMESPACE_URL, f"kaims:audit:runbook-drafted:{runbook_id}:{version}"), tenant_id=tenant_id, actor="knowledge-development-worker", action="runbook.challenger_drafted", resource_type="runbook", resource_id=str(runbook_id), payload=audit, payload_sha256=_hash(audit), occurred_at=datetime.now(timezone.utc)))
    return True


def _knowledge_documents(evidence: IncidentEvidence, signature: str) -> list[dict[str, Any]]:
    """Build attributable, non-executable documents from observed incident evidence."""
    references = [
        reference
        for collection in (evidence.logs, evidence.metrics, evidence.traces, evidence.related_tickets, evidence.recent_changes)
        for reference in collection
    ]
    citations = [f"- [{ref.source}]({ref.uri}): {ref.summary}" for ref in references]
    citation_text = "\n".join(citations) if citations else "- No attributable source was collected; this draft records an evidence gap."
    symptoms = "\n".join(f"- {item}" for item in evidence.symptoms) or "- No verified symptom description was collected."
    dependencies = "\n".join(f"- {item}" for item in evidence.dependencies) or "- No verified dependency inventory was collected."
    changes = "\n".join(f"- [{ref.source}]({ref.uri}): {ref.summary}" for ref in evidence.recent_changes) or "- No verified change record was collected for the incident window."
    resolution = evidence.resolution or "No verified corrective action has been recorded."
    root_causes = "\n".join(f"- {item}" for item in evidence.root_causes) or "- Root cause is not established by the collected evidence."
    common = {
        "incident_id": evidence.incident_id, "service": evidence.service,
        "environment": evidence.environment, "alert_type": evidence.alert_type,
        "issue_signature": signature, "evidence_ids": [ref.evidence_id for ref in references],
        "source_uris": [ref.uri for ref in references], "reviewed_source_incident": evidence.reviewed,
    }
    return [
        {**common, "kind": "runbook", "title": f"Runbook draft · {evidence.alert_type} · {evidence.service}", "content": f"# Diagnostic runbook draft\n\n## Scope\nService: {evidence.service}\nEnvironment: {evidence.environment}\nAlert: {evidence.alert_type}\n\n## Verified symptoms\n{symptoms}\n\n## Evidence to inspect\n{citation_text}\n\n## Current causal status\n{root_causes}\n\n## Safety boundary\nThis draft contains no executable remediation. Add verified corrective, validation, and rollback steps during review."},
        {**common, "kind": "change", "title": f"Change evidence · {evidence.service} · {evidence.incident_id}", "content": f"# Incident-window change record\n\n## Scope\nService: {evidence.service}\nEnvironment: {evidence.environment}\n\n## Verified changes\n{changes}\n\n## Interpretation\nA listed change is temporal evidence, not proof of causation. Confirm or reject its relationship to the incident during review."},
        {**common, "kind": "deployment", "title": f"Deployment and topology · {evidence.service}", "content": f"# Deployment and topology context\n\n## Observed workload\nService: {evidence.service}\nEnvironment: {evidence.environment}\n\n## Known dependencies\n{dependencies}\n\n## Sources\n{citation_text}\n\nUnlisted deployment properties remain unknown until verified from an attributable source."},
        {**common, "kind": "validation", "title": f"Validation evidence · {evidence.service} · {evidence.incident_id}", "content": f"# Recovery validation record\n\n## Recorded resolution\n{resolution}\n\n## Outcome\n{('Verified successful recovery' if evidence.resolution_successful is True else 'Recorded failed recovery' if evidence.resolution_successful is False else 'Recovery outcome has not been verified.')}\n\n## Supporting sources\n{citation_text}"},
        {**common, "kind": "resolution_catalog", "title": f"Resolution catalog candidate · {evidence.alert_type} · {evidence.service}", "content": f"# Resolution catalog candidate\n\n## Matching signature\n{signature}\n\n## Verified symptoms\n{symptoms}\n\n## Causal findings\n{root_causes}\n\n## Recorded corrective action\n{resolution}\n\n## Promotion rule\nKeep as non-executable draft until causal mechanism, corrective steps, validation, rollback, and human approval are complete.\n\n## Sources\n{citation_text}"},
    ]


async def _upsert_knowledge_documents(session: Any, evidence: IncidentEvidence, *, tenant_id: str) -> dict[str, int]:
    created = updated = unchanged = 0
    now = datetime.now(timezone.utc)
    signature = issue_signature(evidence)
    for document in _knowledge_documents(evidence, signature):
        kind = str(document["kind"])
        source_ref = f"incident://{evidence.incident_id}/knowledge/{kind}"
        content = str(document["content"])
        checksum = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"
        latest = (await session.execute(select(KnowledgeRagDraftRecord).where(
            KnowledgeRagDraftRecord.tenant_id == tenant_id,
            KnowledgeRagDraftRecord.source_ref == source_ref,
            KnowledgeRagDraftRecord.document_kind == kind,
        ).order_by(KnowledgeRagDraftRecord.document_version.desc()).limit(1))).scalar_one_or_none()
        if latest is not None and latest.content_checksum == checksum:
            unchanged += 1
            continue
        metadata = {key: value for key, value in document.items() if key not in {"kind", "title", "content"}}
        metadata.update({"generated_by": "knowledge-development-worker", "trust_state": "draft_unverified", "context_eligible": False})
        if latest is not None and latest.status == "draft" and latest.created_by == "knowledge-development-worker":
            latest.title = str(document["title"])[:160]
            latest.content = content
            latest.content_checksum = checksum
            latest.metadata_payload = metadata
            latest.row_version = int(latest.row_version or 1) + 1
            latest.updated_at = now
            updated += 1
            continue
        version = int(await session.scalar(select(func.max(KnowledgeRagDraftRecord.document_version)).where(
            KnowledgeRagDraftRecord.tenant_id == tenant_id,
            KnowledgeRagDraftRecord.source_ref == source_ref,
            KnowledgeRagDraftRecord.document_kind == kind,
        )) or 0) + 1
        session.add(KnowledgeRagDraftRecord(
            tenant_id=tenant_id, document_kind=kind, document_version=version,
            source_ref=source_ref, title=str(document["title"])[:160], content=content,
            content_checksum=checksum, metadata_payload=metadata, status="draft",
            created_by="knowledge-development-worker", row_version=1,
            created_at=now, updated_at=now,
        ))
        created += 1
    return {"created": created, "updated": updated, "unchanged": unchanged}


def _reference_from_context(row: Any) -> EvidenceReference | None:
    if not isinstance(row, dict):
        return None
    evidence_id = str(row.get("evidence_id") or row.get("id") or "").strip()
    source = str(row.get("source") or row.get("provider") or row.get("type") or "").strip().lower()
    uri = str(row.get("uri") or row.get("source_uri") or row.get("citation") or "").strip()
    summary = str(row.get("summary") or row.get("observation") or row.get("content") or "").strip()
    if not evidence_id or not source or not uri or not summary:
        return None
    try:
        return EvidenceReference(
            evidence_id=evidence_id,
            source=source,
            uri=uri,
            summary=summary[:2000],
            confidence=max(0.0, min(float(row.get("confidence", 1.0)), 1.0)),
        )
    except (TypeError, ValueError):
        return None


def _bootstrap_evidence(request: IncidentBootstrapRequest) -> IncidentEvidence:
    incident, context, recommendation = request.incident, request.context, request.recommendation
    alert = context.get("alert") if isinstance(context.get("alert"), dict) else {}
    metadata = context.get("metadata") if isinstance(context.get("metadata"), dict) else {}
    discovery = metadata.get("discovery_report") if isinstance(metadata.get("discovery_report"), dict) else {}
    raw_evidence = discovery.get("evidence") if isinstance(discovery.get("evidence"), list) else []
    references = [ref for ref in (_reference_from_context(row) for row in raw_evidence) if ref is not None]
    by_kind: dict[str, list[EvidenceReference]] = {key: [] for key in ("logs", "metrics", "traces", "tickets", "changes")}
    for ref in references:
        token = f"{ref.source} {ref.uri}".lower()
        kind = "traces" if any(value in token for value in ("trace", "jaeger")) else "metrics" if any(value in token for value in ("metric", "prometheus")) else "tickets" if any(value in token for value in ("jira", "ticket", "itsm")) else "changes" if any(value in token for value in ("change", "git", "deploy")) else "logs"
        by_kind[kind].append(ref)
    observed_at = incident.get("created_at") or alert.get("starts_at")
    try:
        timestamp = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        timestamp = datetime.now(timezone.utc)
    root_cause = str(recommendation.get("root_cause") or "").strip()
    return IncidentEvidence(
        incident_id=str(incident.get("id") or context.get("incident_id")),
        service=str(incident.get("service") or alert.get("service") or "unknown"),
        environment=str(incident.get("environment") or alert.get("environment") or "prod"),
        alert_type=str(alert.get("name") or incident.get("title") or "unknown"),
        symptoms=[value for value in [str(incident.get("summary") or "").strip(), str(alert.get("description") or "").strip()] if value],
        timestamps=[timestamp],
        logs=by_kind["logs"], metrics=by_kind["metrics"], traces=by_kind["traces"],
        related_tickets=by_kind["tickets"], recent_changes=by_kind["changes"],
        dependencies=[str(value) for value in context.get("dependency_services", []) if str(value).strip()],
        resolution=str(recommendation.get("recommended_action") or "").strip() or None,
        root_causes=[root_cause] if root_cause and root_cause.lower() not in {"unknown", "insufficient evidence"} else [],
        reviewed=False,
    )


def _build_evidence(report: RcaReportRecord, incident: IncidentRecord, latest_action: ActionRecord | None) -> IncidentEvidence:
    report_payload = report.payload if isinstance(report.payload, dict) else {}
    action_payload = latest_action.payload if latest_action and isinstance(latest_action.payload, dict) else {}
    validation = action_payload.get("validation") if isinstance(action_payload.get("validation"), dict) else {}
    action_status = str(getattr(latest_action, "status", "") or "").lower()
    validated = bool(action_status.endswith("succeeded") and report_payload.get("health_restored") and report_payload.get("alerts_cleared") and validation.get("passed", True))
    failed = action_status.endswith("failed") or action_status.endswith("rolled_back")
    return IncidentEvidence(
        incident_id=str(incident.id), service=incident.service, environment=incident.environment,
        alert_type=str((incident.payload or {}).get("alert_type") or incident.title),
        symptoms=[str((incident.payload or {}).get("summary") or incident.title)],
        timestamps=[value for value in [_utc(incident.created_at)] if value],
        logs=[EvidenceReference(evidence_id=f"report-{report.id}", source="incident-history", uri=f"report://{report.id}", summary=report.root_cause)] if schedule_config["collect_logs"] else [],
        related_tickets=[EvidenceReference(evidence_id=f"ticket-{incident.ticket_id}", source="itsm", uri=f"ticket://{incident.ticket_id}", summary=incident.title)] if incident.ticket_id and schedule_config["collect_tickets"] else [],
        resolution=str(report_payload.get("action_taken") or action_payload.get("action_type") or "") or None,
        root_causes=[report.root_cause] if report.root_cause else [],
        resolution_successful=True if validated else (False if failed else None), reviewed=validated,
    )


async def _analyze_locked(app: FastAPI, trigger: str, *, tenant_id: str = "default", application_scope: str | None = None) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    cutoff = started - timedelta(days=int(schedule_config["lookback_days"]))
    tenant_id = require_tenant_id(tenant_id, source="knowledge development run")
    previous = await _load_state(app, tenant_id)
    checkpoint = _utc(datetime.fromisoformat(str(previous["checkpoint_at"]))) if previous.get("checkpoint_at") else None
    checkpoint_id = str(previous.get("checkpoint_id") or "").strip()
    scope = str(application_scope or schedule_config["application_scope"]).strip().lower()
    async with app.state.session_factory() as session:
        report_query = select(RcaReportRecord).where(RcaReportRecord.tenant_id == tenant_id)
        if checkpoint and checkpoint_id:
            report_query = report_query.where(
                or_(
                    RcaReportRecord.created_at > checkpoint,
                    and_(RcaReportRecord.created_at == checkpoint, RcaReportRecord.id > UUID(checkpoint_id)),
                )
            )
        elif checkpoint:
            report_query = report_query.where(RcaReportRecord.created_at > checkpoint)
        else:
            report_query = report_query.where(RcaReportRecord.created_at >= cutoff)
        reports = (await session.execute(report_query.order_by(RcaReportRecord.created_at.asc(), RcaReportRecord.id.asc()).limit(batch_size))).scalars().all()
        incident_ids = {row.incident_id for row in reports}
        incidents = {str(row.id): row for row in (await session.execute(select(IncidentRecord).where(IncidentRecord.tenant_id == tenant_id, IncidentRecord.id.in_(incident_ids)))).scalars().all()} if incident_ids else {}
        actions: dict[str, list[ActionRecord]] = {}
        if incident_ids:
            for row in (await session.execute(select(ActionRecord).where(ActionRecord.tenant_id == tenant_id, ActionRecord.incident_id.in_(incident_ids)))).scalars().all():
                actions.setdefault(str(row.incident_id), []).append(row)
        collected = 0
        document_changes = {"created": 0, "updated": 0, "unchanged": 0}
        max_checkpoint = checkpoint
        max_checkpoint_id = checkpoint_id or None
        for report in reports:
            # Advance the scan cursor even for orphaned or out-of-scope reports.
            report_time = _utc(report.created_at)
            if report_time and (
                max_checkpoint is None
                or report_time > max_checkpoint
                or (report_time == max_checkpoint and str(report.id) > str(max_checkpoint_id or ""))
            ):
                max_checkpoint = report_time
                max_checkpoint_id = str(report.id)
            incident = incidents.get(str(report.incident_id))
            if not incident:
                continue
            service = str(incident.service or "").lower()
            application = str((incident.payload or {}).get("application") or "").lower()
            if not _in_application_scope(scope, service=service, application=application):
                continue
            action_rows = actions.get(str(report.incident_id), [])
            evidence = _build_evidence(report, incident, max(action_rows, key=lambda row: row.created_at) if action_rows else None)
            evidence_id = uuid5(NAMESPACE_URL, f"kaims:incident-evidence:{tenant_id}:{evidence.incident_id}")
            await session.merge(IncidentEvidenceRecord(id=evidence_id, tenant_id=tenant_id, incident_id=evidence.incident_id, issue_signature=issue_signature(evidence), service=evidence.service, environment=evidence.environment, alert_type=evidence.alert_type, evidence=evidence.model_dump(mode="json"), reviewed=evidence.reviewed, collected_at=max(evidence.timestamps) if evidence.timestamps else started))
            collected += 1
        await session.flush()
        stored = (await session.execute(select(IncidentEvidenceRecord).where(IncidentEvidenceRecord.tenant_id == tenant_id, IncidentEvidenceRecord.collected_at >= cutoff).order_by(IncidentEvidenceRecord.collected_at.desc()).limit(5000))).scalars().all()
        evidence_rows = []
        for row in stored:
            try:
                evidence = IncidentEvidence.model_validate(row.evidence)
            except Exception:
                continue
            if _in_application_scope(scope, service=evidence.service):
                evidence_rows.append(evidence)
        # Develop documents from the retained evidence window, not only from
        # reports newer than the checkpoint. This makes scheduled runs repair
        # or backfill missing documents while checksum comparison keeps the
        # operation idempotent.
        for evidence in evidence_rows:
            changes = await _upsert_knowledge_documents(session, evidence, tenant_id=tenant_id)
            for key, value in changes.items():
                document_changes[key] += value
        patterns = FailurePatternAnalyzer().analyze(evidence_rows)
        evidence_by_id = {row.incident_id: row for row in evidence_rows}
        drafts = gated = 0
        for pattern in patterns:
            quality = _quality_gate(pattern, evidence_by_id)
            gated += int(not quality["passed"])
            record_id = uuid5(NAMESPACE_URL, f"kaims:failure-pattern:{tenant_id}:{pattern.issue_signature}")
            payload = pattern.model_dump(mode="json")
            payload["evidence_references"] = payload.get("evidence_references", [])[:100]
            payload.update({"knowledge_status": "challenger" if quality["passed"] else "observed", "requires_human_approval": True, "source": "periodic-knowledge-development", "quality_gate": quality})
            summary = {"issue_signature": pattern.issue_signature, "service": pattern.service, "environment": pattern.environment, "alert_type": pattern.alert_type, "probable_causes": pattern.probable_causes, "successful_resolutions": pattern.successful_resolutions, "quality_gate": quality}
            await session.merge(KnowledgeBaseRecord(id=record_id, tenant_id=tenant_id, service=pattern.service, title=f"Recurring failure pattern: {pattern.alert_type}"[:255], content=json.dumps(summary, indent=2), embedding_ref=None, payload=payload))
            await session.merge(FailurePatternRecord(pattern_id=record_id, tenant_id=tenant_id, issue_signature=pattern.issue_signature, service=pattern.service, environment=pattern.environment, analysis=payload, confidence=pattern.confidence, analyzed_at=pattern.analyzed_at))
            drafts += int(await _draft_candidate(session, pattern, quality, tenant_id=tenant_id))
        completed = datetime.now(timezone.utc)
        backlog_remaining = len(reports) >= batch_size
        next_delay = 30 if backlog_remaining else int(schedule_config["interval_seconds"])
        result = {"status": "completed", "trigger": trigger, "started_at": started.isoformat(), "completed_at": completed.isoformat(), "duration_seconds": round((completed - started).total_seconds(), 3), "reports_scanned": len(reports), "evidence_collected": collected, "evidence_in_window": len(evidence_rows), "patterns": len(patterns), "quality_gated_patterns": gated, "reviewable_runbook_candidates": drafts, "knowledge_documents": document_changes, "checkpoint_at": _iso(max_checkpoint), "checkpoint_id": max_checkpoint_id, "backlog_remaining": backlog_remaining, "next_run_at": (completed + timedelta(seconds=next_delay)).isoformat(), "application_scope": schedule_config["application_scope"], "lookback_days": schedule_config["lookback_days"], "batch_size": batch_size, "quality_policy": "kaims.knowledge-quality.v2"}
        result["tenant_id"] = tenant_id
        result["application_scope"] = application_scope or schedule_config["application_scope"]
        await _save_state(session, result, tenant_id)
        await session.commit()
        return result


async def analyze_history(app: FastAPI, trigger: str = "manual", *, tenant_id: str = "default", application_scope: str | None = None) -> dict[str, Any]:
    if not settings.database_enabled:
        return {"status": "disabled", "reason": "database is disabled"}
    if run_lock.locked():
        return {"status": "skipped", "reason": "knowledge development cycle already running"}
    async with run_lock:
        scoped_lock = f"kaims_knowledge_development_{hashlib.sha256(tenant_id.encode()).hexdigest()[:20]}"
        async with app.state.db_engine.connect() as connection:
            acquired = await connection.scalar(text("SELECT GET_LOCK(:name, 0)"), {"name": scoped_lock})
            if int(acquired or 0) != 1:
                return {"status": "skipped", "reason": "another replica owns the knowledge development lease"}
            try:
                return await _analyze_locked(app, trigger, tenant_id=tenant_id, application_scope=application_scope)
            finally:
                await connection.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": scoped_lock})


async def periodic_loop(app: FastAPI) -> None:
    global last_result
    while True:
        try:
            state = await _load_state(app)
            next_run = None
            if state.get("next_run_at"):
                try:
                    next_run = _utc(datetime.fromisoformat(str(state["next_run_at"])))
                except ValueError:
                    pass
            now = datetime.now(timezone.utc)
            if schedule_config["enabled"] and (next_run is None or next_run <= now):
                last_result = await analyze_history(app, "schedule")
                continue
            timeout = max(1.0, min(300.0, (next_run - now).total_seconds())) if schedule_config["enabled"] and next_run else 60.0
            schedule_wakeup.clear()
            try:
                await asyncio.wait_for(schedule_wakeup.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            last_result = {"status": "failed", "error": str(exc)[:1000], "failed_at": datetime.now(timezone.utc).isoformat()}
            await asyncio.sleep(30)


async def startup(app: FastAPI) -> None:
    global task, last_result
    if settings.database_enabled:
        async with app.state.session_factory() as session:
            persisted = await session.get(KnowledgeBaseRecord, configuration_id)
            if persisted and isinstance(persisted.payload, dict):
                schedule_config.update({key: value for key, value in persisted.payload.items() if key in schedule_config})
        last_result = (await _load_state(app)) or last_result
    task = asyncio.create_task(periodic_loop(app), name="periodic-knowledge-development")


async def shutdown(_: FastAPI) -> None:
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = create_app(title="KaiMS Knowledge Development Worker", settings=settings, startup=startup, shutdown=shutdown)


@app.post("/incidents/bootstrap")
async def bootstrap_incident_catalog(request: IncidentBootstrapRequest) -> dict[str, Any]:
    """Persist current evidence and bootstrap an idempotent, non-executable candidate."""
    if not settings.database_enabled:
        return {"status": "disabled", "reason": "database is disabled"}
    evidence = _bootstrap_evidence(request)
    tenant_id = require_tenant_id(
        str(request.context.get("tenant_id") or request.incident.get("tenant_id") or ""),
        source="incident catalog bootstrap",
    )
    if not evidence.incident_id or evidence.incident_id.lower() == "none":
        return {"status": "rejected", "reason": "incident identity is required"}
    signature = issue_signature(evidence)
    async with app.state.session_factory() as session:
        evidence_id = uuid5(NAMESPACE_URL, f"kaims:incident-evidence:{tenant_id}:{evidence.incident_id}")
        await session.merge(IncidentEvidenceRecord(
            id=evidence_id, tenant_id=tenant_id, incident_id=evidence.incident_id,
            issue_signature=signature, service=evidence.service, environment=evidence.environment,
            alert_type=evidence.alert_type, evidence=evidence.model_dump(mode="json"), reviewed=False,
            collected_at=max(evidence.timestamps) if evidence.timestamps else datetime.now(timezone.utc),
        ))
        await session.flush()
        matching = (await session.execute(
            select(IncidentEvidenceRecord).where(IncidentEvidenceRecord.tenant_id == tenant_id, IncidentEvidenceRecord.issue_signature == signature)
            .order_by(IncidentEvidenceRecord.collected_at.desc()).limit(100)
        )).scalars().all()
        evidence_rows = []
        for row in matching:
            try:
                evidence_rows.append(IncidentEvidence.model_validate(row.evidence))
            except Exception:
                continue
        patterns = FailurePatternAnalyzer().analyze(evidence_rows)
        pattern = next((item for item in patterns if item.issue_signature == signature), None)
        if pattern is None:
            return {"status": "rejected", "reason": "evidence could not be normalized"}
        quality = _quality_gate(pattern, {row.incident_id: row for row in evidence_rows})
        pattern_id = uuid5(NAMESPACE_URL, f"kaims:failure-pattern:{tenant_id}:{signature}")
        pattern_payload = pattern.model_dump(mode="json")
        pattern_payload.update({
            "knowledge_status": "challenger" if quality["passed"] else "observed",
            "requires_human_approval": True,
            "source": "incident-event-bootstrap",
            "quality_gate": quality,
        })
        await session.merge(FailurePatternRecord(
            pattern_id=pattern_id, tenant_id=tenant_id, issue_signature=signature,
            service=pattern.service, environment=pattern.environment, analysis=pattern_payload,
            confidence=pattern.confidence, analyzed_at=pattern.analyzed_at,
        ))
        created = await _draft_candidate(session, pattern, quality, allow_evidence_work=True, tenant_id=tenant_id)
        document_changes = await _upsert_knowledge_documents(session, evidence, tenant_id=tenant_id)
        await session.commit()
    return {
        "status": "created" if created else "updated",
        "incident_id": evidence.incident_id,
        "issue_signature": signature,
        "candidate_stage": (
            "resolution_candidate" if quality["passed"]
            else "diagnostic_candidate" if quality["checks"].get("independent_sources")
            else "evidence_work_candidate"
        ),
        "execution_eligible": False,
        "evidence_sources": quality["metrics"]["independent_sources"],
        "knowledge_documents": document_changes,
    }


@app.get("/incidents/{incident_id}/catalog-status")
async def incident_catalog_status(incident_id: str, tenant_id: str) -> dict[str, Any]:
    tenant_id = require_tenant_id(tenant_id, source="incident catalog status")
    async with app.state.session_factory() as session:
        evidence = (await session.execute(
            select(IncidentEvidenceRecord).where(
                IncidentEvidenceRecord.tenant_id == tenant_id,
                IncidentEvidenceRecord.incident_id == incident_id,
            ).order_by(IncidentEvidenceRecord.collected_at.desc()).limit(1)
        )).scalar_one_or_none()
        if evidence is None:
            return {"status": "awaiting_evidence", "incident_id": incident_id, "execution_eligible": False}
        runbook_id = uuid5(NAMESPACE_URL, f"kaims:runbook:{tenant_id}:{evidence.issue_signature}")
        candidate = (await session.execute(
            select(RunbookVersionRecord).where(
                RunbookVersionRecord.tenant_id == tenant_id,
                RunbookVersionRecord.runbook_id == runbook_id,
            ).order_by(RunbookVersionRecord.version.desc()).limit(1)
        )).scalar_one_or_none()
    if candidate is None:
        return {"status": "analyzing_evidence", "incident_id": incident_id, "execution_eligible": False}
    content = candidate.content if isinstance(candidate.content, dict) else {}
    quality = content.get("knowledge_quality") if isinstance(content.get("knowledge_quality"), dict) else {}
    return {
        "status": candidate.approval_status,
        "incident_id": incident_id,
        "runbook_id": str(candidate.runbook_id),
        "version": candidate.version,
        "candidate_stage": content.get("catalog_stage"),
        "execution_eligible": bool(content.get("execution_eligible", False)),
        "evidence_sources": (quality.get("metrics") or {}).get("independent_sources", 0),
        "promotion_requirements": content.get("promotion_requirements", []),
    }


@app.post("/runbooks/{runbook_id}/approve")
async def approve_runbook_draft(
    runbook_id: UUID,
    version: int = 1,
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Approve an operator-submitted or catalog runbook draft into active guided reuse."""
    payload = request or {}
    tenant_id = require_tenant_id(str(payload.get("tenant_id") or "default"), source="runbook draft approval")
    actor = str(payload.get("actor") or "admin")
    async with app.state.session_factory() as session:
        candidate = (await session.execute(select(RunbookVersionRecord).where(
            RunbookVersionRecord.tenant_id == tenant_id,
            RunbookVersionRecord.runbook_id == runbook_id,
            RunbookVersionRecord.version == version,
        ).limit(1))).scalar_one_or_none()
        if candidate is None:
            raise HTTPException(status_code=404, detail="runbook draft was not found")
        now = datetime.now(timezone.utc)
        content = dict(candidate.content or {})
        candidate.approval_status = "approved"
        candidate.approved_by = actor
        candidate.approved_at = now
        content.update({
            "review_state": "approved",
            "approved_by": actor,
            "approved_at": now.isoformat(),
            "autonomy_policy": str(content.get("autonomy_policy") or "repeat-match-hitl"),
        })
        candidate.content = content
        audit = {
            "decision": "approve",
            "version": version,
            "risk_level": str(candidate.risk_level or "medium"),
            "self_heal_eligible": bool(content.get("self_heal_eligible", False)),
            "reason": str(payload.get("reason") or "approved for active catalog reuse"),
            "content_sha256": str(content.get("content_sha256") or ""),
        }
        session.add(LearningAuditRecord(
            tenant_id=tenant_id,
            actor=actor,
            action="runbook.draft_approved",
            resource_type="runbook",
            resource_id=str(runbook_id),
            payload=audit,
            payload_sha256=_hash(audit),
            occurred_at=now,
        ))
        await session.commit()
    return {
        "status": candidate.approval_status,
        "runbook_id": str(runbook_id),
        "version": version,
        "lifecycle_mode": "active",
        "approved_by": actor,
        "approved_at": now.isoformat(),
        "self_heal_eligible": bool(content.get("self_heal_eligible", False)),
        "autonomy_policy": content.get("autonomy_policy"),
    }


@app.post("/catalog/{runbook_id}/versions/{version}/review")
async def review_catalog_candidate(
    runbook_id: UUID, version: int, request: CatalogPromotionRequest,
) -> dict[str, Any]:
    """Promote or reject one immutable learned recovery version."""
    tenant_id = require_tenant_id(request.tenant_id, source="catalog promotion")
    async with app.state.session_factory() as session:
        candidate = (await session.execute(select(RunbookVersionRecord).where(
            RunbookVersionRecord.tenant_id == tenant_id,
            RunbookVersionRecord.runbook_id == runbook_id,
            RunbookVersionRecord.version == version,
        ).limit(1))).scalar_one_or_none()
        if candidate is None:
            raise HTTPException(status_code=404, detail="catalog candidate was not found")
        content = dict(candidate.content or {})
        stored_sha = str(content.get("content_sha256") or "")
        if stored_sha and stored_sha != request.expected_content_sha256:
            raise HTTPException(status_code=409, detail="catalog candidate changed; refresh before reviewing")
        if request.decision == "reject":
            candidate.approval_status = "suspended"
            content.update({"review_state": "rejected", "execution_eligible": False,
                            "self_heal_eligible": False, "rejection_reason": request.reason or "rejected by reviewer"})
            audit_action = "runbook.challenger_rejected"
        else:
            reviewed_success = bool(await session.scalar(select(func.count()).select_from(IncidentEvidenceRecord).where(
                IncidentEvidenceRecord.tenant_id == tenant_id,
                IncidentEvidenceRecord.issue_signature == candidate.issue_signature,
                IncidentEvidenceRecord.reviewed.is_(True),
            )))
            is_operator_draft = str(content.get("source") or "") == "operator_evidence_response"
            blockers = [] if is_operator_draft else _promotion_readiness(content, reviewed_success=reviewed_success)
            if blockers:
                raise HTTPException(status_code=409, detail={"code": "catalog_promotion_blocked", "blocking_reasons": blockers})
            self_heal = (request.risk_level == "low") and not is_operator_draft
            candidate.approval_status = "approved"
            candidate.approved_by = request.actor
            candidate.approved_at = datetime.now(timezone.utc)
            candidate.risk_level = request.risk_level
            content.update({
                "review_state": "approved", "risk_level": request.risk_level,
                "execution_eligible": self_heal, "self_heal_eligible": self_heal,
                "promotion_requirements": [], "approved_by": request.actor,
                "approved_at": candidate.approved_at.isoformat(),
                "autonomy_policy": "repeat-match-auto" if self_heal else "repeat-match-hitl",
            })
            audit_action = "runbook.challenger_promoted"
        candidate.content = content
        audit = {
            "decision": request.decision, "version": version, "risk_level": request.risk_level,
            "self_heal_eligible": bool(content.get("self_heal_eligible")), "reason": request.reason,
            "content_sha256": request.expected_content_sha256,
        }
        session.add(LearningAuditRecord(
            tenant_id=tenant_id, actor=request.actor, action=audit_action,
            resource_type="runbook", resource_id=str(runbook_id), payload=audit,
            payload_sha256=_hash(audit), occurred_at=datetime.now(timezone.utc),
        ))
        await session.commit()
    return {
        "status": candidate.approval_status, "runbook_id": str(runbook_id), "version": version,
        "self_heal_eligible": bool(content.get("self_heal_eligible")),
        "autonomy_policy": content.get("autonomy_policy"),
    }


@app.post("/run")
async def run_now(request: RunRequest) -> dict[str, Any]:
    global last_result
    try:
        last_result = await analyze_history(app, "manual", tenant_id=request.tenant_id, application_scope=request.application_scope)
    except Exception as exc:
        last_result = {"status": "failed", "error": str(exc)[:1000], "failed_at": datetime.now(timezone.utc).isoformat()}
    finally:
        # A manual cycle can replace a distant periodic deadline with a short
        # backlog catch-up deadline. Wake the scheduler so it reloads the
        # durable state instead of continuing to wait on the old deadline.
        schedule_wakeup.set()
    return last_result


@app.get("/status")
async def status() -> dict[str, Any]:
    summary = (await _load_state(app)) or last_result
    completed = None
    if summary.get("completed_at"):
        try:
            completed = _utc(datetime.fromisoformat(str(summary["completed_at"])))
        except ValueError:
            pass
    stale = bool(schedule_config["enabled"] and completed and (datetime.now(timezone.utc) - completed).total_seconds() > int(schedule_config["interval_seconds"]) * 2)
    return {**summary, "stale": stale, "running": run_lock.locked(), "schedule": schedule_config}


@app.get("/configuration")
async def get_configuration() -> dict[str, Any]:
    return {**schedule_config, "interval_hours": max(1, int(schedule_config["interval_seconds"]) // 3600)}


@app.put("/configuration")
async def update_configuration(configuration: ScheduleConfig) -> dict[str, Any]:
    schedule_config.update(configuration.model_dump(exclude={"interval_hours"}))
    schedule_config["interval_seconds"] = configuration.interval_hours * 3600
    if settings.database_enabled:
        async with app.state.session_factory() as session:
            await session.merge(KnowledgeBaseRecord(id=configuration_id, tenant_id="default", service="KaiMS", title="Periodic knowledge development configuration", content=json.dumps(schedule_config, indent=2), embedding_ref=None, payload=dict(schedule_config)))
            await session.commit()
    schedule_wakeup.set()
    return await get_configuration()


def _recent_report_records(model, tenant: str, timestamp, limit: int):
    # Sort only identifiers before fetching the selected document bodies.
    # Sorting whole ORM rows makes MySQL read large JSON/TEXT for every
    # historical candidate, even though the report returns a small page.
    keys = list(model.__mapper__.primary_key)
    recent = select(*keys).where(model.tenant_id == tenant).order_by(timestamp.desc(), *keys).limit(limit).subquery()
    return select(model).join(recent, and_(*(key == recent.c[key.key] for key in keys))).order_by(timestamp.desc(), *keys)


@app.get("/report")
async def report(tenant_id: str = "default") -> dict[str, Any]:
    if not settings.database_enabled:
        return {"status": "disabled", "summary": last_result, "patterns": [], "drafts": []}
    async with app.state.session_factory() as session:
        tenant = str(tenant_id or "default").strip() or "default"
        patterns_total = int(
            await session.scalar(select(func.count()).select_from(FailurePatternRecord).where(FailurePatternRecord.tenant_id == tenant)) or 0
        )
        drafts_total = int(
            await session.scalar(select(func.count()).select_from(RunbookVersionRecord).where(RunbookVersionRecord.tenant_id == tenant)) or 0
        )
        evidence_total = int(
            await session.scalar(select(func.count()).select_from(IncidentEvidenceRecord).where(IncidentEvidenceRecord.tenant_id == tenant)) or 0
        )
        documents_total = int(
            await session.scalar(select(func.count()).select_from(KnowledgeRagDraftRecord).where(KnowledgeRagDraftRecord.tenant_id == tenant)) or 0
        )
        outcomes_total = int(
            await session.scalar(select(func.count()).select_from(RunbookOutcomeRecord).where(RunbookOutcomeRecord.tenant_id == tenant)) or 0
        )
        outcomes_reviewed = int(
            await session.scalar(
                select(func.count()).select_from(RunbookOutcomeRecord).where(
                    RunbookOutcomeRecord.tenant_id == tenant,
                    RunbookOutcomeRecord.reviewed.is_(True),
                )
            ) or 0
        )
        outcomes_successful = int(
            await session.scalar(
                select(func.count()).select_from(RunbookOutcomeRecord).where(
                    RunbookOutcomeRecord.tenant_id == tenant,
                    RunbookOutcomeRecord.successful.is_(True),
                )
            ) or 0
        )
        patterns = (await session.execute(_recent_report_records(FailurePatternRecord, tenant, FailurePatternRecord.analyzed_at, 100))).scalars().all()
        drafts = (await session.execute(_recent_report_records(RunbookVersionRecord, tenant, RunbookVersionRecord.created_at, 200))).scalars().all()
        # The report displays metadata only. Avoid loading large raw evidence
        # documents just to show a count and recent evidence rows.
        evidence = (await session.execute(select(IncidentEvidenceRecord).options(load_only(
            IncidentEvidenceRecord.incident_id, IncidentEvidenceRecord.service,
            IncidentEvidenceRecord.environment, IncidentEvidenceRecord.alert_type,
            IncidentEvidenceRecord.reviewed, IncidentEvidenceRecord.collected_at,
            raiseload=True,
        )).where(IncidentEvidenceRecord.tenant_id == tenant).order_by(IncidentEvidenceRecord.collected_at.desc()).limit(200))).scalars().all()
        outcomes = (await session.execute(_recent_report_records(RunbookOutcomeRecord, tenant, RunbookOutcomeRecord.created_at, 200))).scalars().all()
        audit_rows = (await session.execute(_recent_report_records(LearningAuditRecord, tenant, LearningAuditRecord.occurred_at, 100))).scalars().all()
        documents = (await session.execute(_recent_report_records(KnowledgeRagDraftRecord, tenant, KnowledgeRagDraftRecord.updated_at, 200))).scalars().all()
    audits = []
    for row in audit_rows:
        canonical = json.dumps(row.payload or {}, sort_keys=True, separators=(",", ":"), default=str)
        audits.append({"event_id": str(row.event_id), "action": row.action, "actor": row.actor, "resource_type": row.resource_type, "resource_id": row.resource_id, "occurred_at": _iso(row.occurred_at), "payload_sha256": row.payload_sha256, "hash_verified": hashlib.sha256(canonical.encode()).hexdigest() == row.payload_sha256})
    return {
        "status": "ok",
        "summary": (await _load_state(app)) or last_result,
        "patterns_total": patterns_total,
        "drafts_total": drafts_total,
        "documents_total": documents_total,
        "evidence_count": evidence_total,
        "outcome_summary": {
            "total": outcomes_total,
            "reviewed": outcomes_reviewed,
            "successful": outcomes_successful,
            "failed": max(0, outcomes_total - outcomes_successful),
            "success_rate": round(outcomes_successful / outcomes_total, 4) if outcomes_total else None,
        },
        "patterns": [
            {
                "id": str(row.pattern_id),
                "service": row.service,
                "environment": row.environment,
                "issue_signature": row.issue_signature,
                "confidence": float(row.confidence),
                "analyzed_at": _iso(row.analyzed_at),
                "quality_gate": (row.analysis or {}).get("quality_gate", {}),
            }
            for row in patterns
        ],
        "drafts": [
            {
                "runbook_id": str(row.runbook_id),
                "version": row.version,
                "status": row.approval_status,
                "lifecycle_mode": "active" if str(row.approval_status or "").lower() == "approved" else "draft",
                "owner": row.owner,
                "risk_level": row.risk_level,
                "created_at": _iso(row.created_at),
                "approved_at": _iso(row.approved_at),
                "incident_id": (
                    (row.content or {}).get("incident_id")
                    or (row.content or {}).get("source_incident_id")
                    or (((row.content or {}).get("supporting_incident_ids") or [None])[0])
                ),
                "content": row.content or {},
                "quality_gate": (row.content or {}).get("knowledge_quality", {}),
            }
            for row in drafts
        ],
        "documents": [
            {
                "draft_id": str(row.draft_id),
                "document_kind": row.document_kind,
                "document_version": row.document_version,
                "source_ref": row.source_ref,
                "title": row.title,
                "content": row.content,
                "content_checksum": row.content_checksum,
                "status": row.status,
                "row_version": row.row_version,
                "metadata": row.metadata_payload or {},
                "updated_at": _iso(row.updated_at),
            }
            for row in documents
        ],
        "outcomes": [
            {
                "outcome_id": str(row.outcome_id),
                "incident_id": row.incident_id,
                "runbook_id": str(row.runbook_id),
                "runbook_version": row.runbook_version,
                "reviewed": row.reviewed,
                "successful": row.successful,
                "created_at": _iso(row.created_at),
            }
            for row in outcomes
        ],
        "learning_audit": audits[:50],
        "recent_evidence": [
            {
                "incident_id": row.incident_id,
                "service": row.service,
                "environment": row.environment,
                "alert_type": row.alert_type,
                "reviewed": row.reviewed,
                "collected_at": _iso(row.collected_at),
            }
            for row in evidence
        ],
    }
