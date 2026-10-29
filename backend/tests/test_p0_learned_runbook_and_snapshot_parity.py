from __future__ import annotations

from datetime import UTC, datetime, timedelta
import importlib.util
from pathlib import Path
import sys
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

ROOT = Path(__file__).resolve().parents[2]
for rel in (
    "backend/src/common",
    "ai-workbench/src/common",
    "ai-workbench/src/resolution-agent",
):
    candidate = str(ROOT / rel)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from ai_workbench_common.models import Context
from common.config import get_settings
from common.database import (
    Base,
    ContextSnapshotRecord,
    ResolutionOutboxRecord,
    RunbookApprovalRecord,
    RunbookRecord,
    RunbookVersionRecord,
)
from common.models import Alert, AlertSeverity as Severity, Incident, Recommendation
import common.outbox_context as outbox_context
from common.outbox_context import (
    CONTEXT_TOPICS,
    REFERENCE_VERSION,
    compact_context,
    context_checksum,
    hydrate_context,
)
from common.outbox_dispatch import flush_resolution_outbox
from common.repository import IncidentRepository
from resolution_agent.catalog import register_learned_runbooks

_resolution_app_path = ROOT / "ai-workbench/src/resolution-agent/app.py"
_resolution_app_spec = importlib.util.spec_from_file_location("resolution_agent_app_p0", _resolution_app_path)
assert _resolution_app_spec is not None and _resolution_app_spec.loader is not None
resolution_app_module = importlib.util.module_from_spec(_resolution_app_spec)
sys.modules["resolution_agent_app_p0"] = resolution_app_module
_resolution_app_spec.loader.exec_module(resolution_app_module)


class _OfflineModelGateway:
    async def generate(self, request):
        raise RuntimeError("offline unit test - use deterministic fallback")


async def _noop_async(*_args, **_kwargs):
    return None


resolution_app_module.agent.model_gateway = _OfflineModelGateway()
resolution_app_module.agent.runtime.max_attempts = 1
resolution_app_module.agent._judge_groundedness = _noop_async
resolution_app_module.agent._publish_evaluation = lambda **_kwargs: None
resolution_app_module._ensure_global_knowledge_loaded = _noop_async


def _sample_runbook_markdown(
    *,
    service: str = "Geo-Service",
    alert_name: str = "ExternalEndpointDown",
    runbook_id: str = "rb-geo-endpoint-down-v1",
) -> str:
    return f"""---
document_type: runbook
runbook_id: {runbook_id}
version: 1
service: {service}
alert_name: {alert_name}
approval_status: approved
---
# Runbook: {service} - {alert_name}

## Overview
- **Service**: `{service}`
- **Alert**: `{alert_name}`
- **Environment**: `prod`
- **Severity**: `critical`

## Observed Symptoms & Root Cause
Geo-Service upstream DNS resolver cache poisoning and stale upstream socket pool causing HTTP 502 probe failures.

## Business Impact
Public map tile and geocoding requests fail for external clients.

## Preconditions
1. Confirm Geo-Service pod status in namespace prod.

## Remediation Steps
1. `kubectl rollout restart deployment/geo-service -n prod`
2. `kubectl rollout status deployment/geo-service -n prod --timeout=120s`

## Validation
1. `curl -fsS https://geo.example.com/healthz`
2. Verify ExternalEndpointDown alert clears in Alertmanager.

## Rollback
1. `kubectl rollout undo deployment/geo-service -n prod`
"""


@pytest.fixture()
async def session_factory(tmp_path: Path):
    db_file = tmp_path / "p0_verification.sqlite"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")

    @event.listens_for(engine.sync_engine, "connect")
    def _register_sqlite_locks(dbapi_connection, _connection_record):
        dbapi_connection.create_function("GET_LOCK", 2, lambda _name, _timeout: 1)
        dbapi_connection.create_function("RELEASE_LOCK", 1, lambda _name: 1)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        await engine.dispose()


async def _create_and_approve_knowledge_runbook(
    repo: IncidentRepository,
    *,
    tenant_id: str,
    service: str,
    alert_name: str,
    markdown: str,
    source_ref: str = "kaiops://human-evidence/geo-service/runbook-v1",
    approved_by: str = "sre-lead@example.com",
) -> UUID:
    draft = await repo.create_knowledge_rag_draft(
        tenant_id=tenant_id,
        created_by="human-operator@example.com",
        document_kind="runbook",
        source_ref=source_ref,
        title=f"Runbook: {service} - {alert_name}",
        content=markdown,
        metadata={
            "service": service,
            "alert_name": alert_name,
            "root_cause": "Geo-Service upstream DNS resolver cache poisoning and stale socket pool.",
        },
    )
    reviewed = await repo.review_knowledge_rag_draft(
        tenant_id=tenant_id,
        draft_id=draft["draft_id"],
        expected_row_version=draft["row_version"],
        title=draft["title"],
        content=draft["content"],
        review_notes="Verified remediation and rollback steps.",
        reviewed_by=approved_by,
    )
    await repo.approve_knowledge_rag_draft(
        tenant_id=tenant_id,
        draft_id=draft["draft_id"],
        expected_row_version=reviewed["row_version"],
        approved_by=approved_by,
    )
    return uuid5(NAMESPACE_URL, f"kaiops:runbook:{tenant_id}:{source_ref}")


# ============================================================================
# P0-A Tests: Runbook Governance Approval & Learned Runbook Reuse
# ============================================================================


@pytest.mark.asyncio
async def test_p0a_approve_knowledge_draft_creates_governance_records_idempotently(
    session_factory,
) -> None:
    tenant_id = "tenant-p0-test"
    markdown = _sample_runbook_markdown(service="Geo-Service", alert_name="ExternalEndpointDown")

    async with session_factory() as session:
        repo = IncidentRepository(session)
        rb_uuid = await _create_and_approve_knowledge_runbook(
            repo,
            tenant_id=tenant_id,
            service="Geo-Service",
            alert_name="ExternalEndpointDown",
            markdown=markdown,
            approved_by="sre-lead@example.com",
        )
        await session.commit()

        # get_approved_runbook_version must succeed because runbook_approvals is populated
        governed = await repo.get_approved_runbook_version(
            tenant_id=tenant_id,
            runbook_id=rb_uuid,
            version=1,
        )
        assert governed is not None
        assert governed["runbook_id"] == str(rb_uuid)
        assert governed["version"] == 1
        assert governed["approved_by"] == "sre-lead@example.com"
        assert governed["service"] == "Geo-Service"
        assert governed["alert_name"] == "ExternalEndpointDown"
        assert "kubectl rollout restart deployment/geo-service -n prod" in governed["remediation_steps"]
        assert "curl -fsS https://geo.example.com/healthz" in governed["validation_steps"]
        assert "kubectl rollout undo deployment/geo-service -n prod" in governed["rollback_steps"]

        # Second approval via approve_runbook_version (idempotency check)
        approved2 = await repo.approve_runbook_version(
            tenant_id=tenant_id,
            runbook_id=str(rb_uuid),
            version=1,
            approved_by="sre-lead@example.com",
            payload={"approval_reason": "Idempotent re-approval"},
        )
        await session.commit()
        assert approved2["runbook_id"] == str(rb_uuid)
        assert approved2["status"] == "approved"

        approvals = (
            await session.execute(
                select(RunbookApprovalRecord).where(
                    RunbookApprovalRecord.runbook_id == rb_uuid,
                    RunbookApprovalRecord.version == 1,
                )
            )
        ).scalars().all()
        assert len(approvals) == 1

        runbooks = (
            await session.execute(
                select(RunbookRecord).where(
                    RunbookRecord.tenant_id == tenant_id,
                    RunbookRecord.runbook_id == rb_uuid,
                )
            )
        ).scalars().all()
        assert len(runbooks) == 1
        assert runbooks[0].service == "Geo-Service"


@pytest.mark.asyncio
async def test_p0a_approve_runbook_version_creates_approval_and_parent_runbook(
    session_factory,
) -> None:
    tenant_id = "tenant-p0-test"
    rb_id = uuid4()

    async with session_factory() as session:
        repo = IncidentRepository(session)
        session.add(
            RunbookVersionRecord(
                runbook_id=rb_id,
                tenant_id=tenant_id,
                version=2,
                issue_signature="geo-service-endpoint-down",
                content={
                    "title": "Geo-Service Recovery",
                    "service": "Geo-Service",
                    "alert_name": "ExternalEndpointDown",
                    "markdown": _sample_runbook_markdown(service="Geo-Service", alert_name="ExternalEndpointDown"),
                },
                approval_status="draft",
                risk_level="medium",
                owner="sre-team",
                required_approval="HITL_APPROVER",
            )
        )
        await session.commit()

        # Before approval, get_approved_runbook_version must return None
        assert await repo.get_approved_runbook_version(tenant_id=tenant_id, runbook_id=rb_id, version=2) is None

        res = await repo.approve_runbook_version(
            tenant_id=tenant_id,
            runbook_id=str(rb_id),
            version=2,
            approved_by="gov-approver",
        )
        await session.commit()
        assert res["status"] == "approved"

        governed = await repo.get_approved_runbook_version(tenant_id=tenant_id, runbook_id=rb_id, version=2)
        assert governed is not None
        assert governed["approved_by"] == "gov-approver"
        assert governed["version"] == 2
        assert governed["remediation_steps"] == [
            "kubectl rollout restart deployment/geo-service -n prod",
            "kubectl rollout status deployment/geo-service -n prod --timeout=120s",
        ]


@pytest.mark.asyncio
async def test_p0a_unapproved_or_missing_approval_record_cannot_become_executable(
    session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = "tenant-p0-test"
    rb_id = uuid4()

    # Insert a RunbookVersionRecord marked "approved" but WITHOUT a RunbookApprovalRecord
    async with session_factory() as session:
        session.add(
            RunbookVersionRecord(
                runbook_id=rb_id,
                tenant_id=tenant_id,
                version=1,
                issue_signature="tampered-sig",
                content={
                    "title": "Tampered Runbook Without Approval Row",
                    "service": "Geo-Service",
                    "alert_name": "ExternalEndpointDown",
                    "remediation_steps": ["kubectl rollout restart deployment/geo-service -n prod"],
                    "validation_steps": ["curl -fsS https://geo.example.com/healthz"],
                    "rollback_steps": ["kubectl rollout undo deployment/geo-service -n prod"],
                },
                approval_status="approved",
                risk_level="low",
                owner="sre-team",
                required_approval="HITL_APPROVER",
            )
        )
        await session.commit()

    monkeypatch.setattr(resolution_app_module.settings, "database_enabled", True)
    monkeypatch.setattr(resolution_app_module.app.state, "session_factory", session_factory, raising=False)

    alert = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        source="prometheus",
        name="ExternalEndpointDown",
        service="Geo-Service",
        environment="prod",
        severity=Severity.CRITICAL,
        description="Endpoint https://geo.example.com is down",
    )
    context = Context(
        tenant_id=tenant_id,
        incident_id=uuid4(),
        alert=alert,
        runbook=_sample_runbook_markdown(
            service="Geo-Service",
            alert_name="ExternalEndpointDown",
            runbook_id=str(rb_id),
        ),
        metadata={
            "document_available": True,
            "rag_matches": [
                {
                    "kind": "runbook",
                    "title": "Tampered Runbook Without Approval Row",
                    "path": f"governed://{tenant_id}/{rb_id}/v1",
                    "similarity": 0.91,
                }
            ],
        },
    )

    loaded = await resolution_app_module._load_learned_runbooks_for_context(context)
    assert loaded.metadata.get("matched_learned_runbook") is None


def test_p0a_catalog_rejects_unapproved_stale_malformed_and_mismatched_runbooks() -> None:
    tenant_id = "tenant-p0-test"
    valid_md = _sample_runbook_markdown(service="Geo-Service", alert_name="ExternalEndpointDown")

    rejected_candidates = [
        # 1. Draft / pending_review / stale / unindexed
        {
            "runbook_id": str(uuid4()),
            "version": 1,
            "approval_status": "pending_review",
            "tenant_id": tenant_id,
            "content": {"service": "Geo-Service", "alert_name": "ExternalEndpointDown", "markdown": valid_md},
        },
        {
            "runbook_id": str(uuid4()),
            "version": 1,
            "approval_status": "draft",
            "tenant_id": tenant_id,
            "content": {"service": "Geo-Service", "alert_name": "ExternalEndpointDown", "markdown": valid_md},
        },
        {
            "runbook_id": str(uuid4()),
            "version": 1,
            "approval_status": "approved",
            "stale": True,
            "tenant_id": tenant_id,
            "content": {"service": "Geo-Service", "alert_name": "ExternalEndpointDown", "markdown": valid_md},
        },
        {
            "runbook_id": str(uuid4()),
            "version": 1,
            "approval_status": "approved",
            "index_status": "pending",
            "tenant_id": tenant_id,
            "content": {"service": "Geo-Service", "alert_name": "ExternalEndpointDown", "markdown": valid_md},
        },
        # 2. Tenant mismatch
        {
            "runbook_id": str(uuid4()),
            "version": 1,
            "approval_status": "approved",
            "tenant_id": "other-tenant",
            "content": {"service": "Geo-Service", "alert_name": "ExternalEndpointDown", "markdown": valid_md},
        },
        # 3. Service mismatch
        {
            "runbook_id": str(uuid4()),
            "version": 1,
            "approval_status": "approved",
            "tenant_id": tenant_id,
            "content": {"service": "Payments-Service", "alert_name": "ExternalEndpointDown", "markdown": "# Runbook: Payments\n- **Service**: `Payments-Service`\n## Remediation Steps\n1. `kubectl rollout restart deployment/payments -n prod`"},
        },
        # 4. Malformed / empty remediation steps
        {
            "runbook_id": str(uuid4()),
            "version": 1,
            "approval_status": "approved",
            "tenant_id": tenant_id,
            "content": {
                "service": "Geo-Service",
                "alert_name": "ExternalEndpointDown",
                "remediation_steps": [],
                "markdown": "# Runbook without any steps",
            },
        },
        # 5. Unresolved placeholder in command
        {
            "runbook_id": str(uuid4()),
            "version": 1,
            "approval_status": "approved",
            "tenant_id": tenant_id,
            "content": {
                "service": "Geo-Service",
                "alert_name": "ExternalEndpointDown",
                "remediation_steps": ["kubectl rollout restart deployment/<service_name> -n prod"],
            },
        },
    ]

    matches = register_learned_runbooks(
        tenant_id=tenant_id,
        issue="ExternalEndpointDown probe failure",
        service="Geo-Service",
        alert_name="ExternalEndpointDown",
        runbooks=rejected_candidates,
    )
    assert matches == []


@pytest.mark.asyncio
async def test_p0a_subsequent_incident_ingests_learned_runbook_without_fabricating_conclusive_rca(
    session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When an approved learned runbook matches a subsequent incident without human-guided input
    and independent causal evidence is insufficient:
    - The learned runbook ID, slug, and version ARE retained (never generic-kaiops-triage-playbook).
    - rca_status remains 'insufficient_evidence' (no fabricated conclusive RCA).
    - execution_plan.execution_ready is False (diagnostic-only gate remains enforced).
    - recommendation.remediation_plan and metadata['runbook_guidance'] and metadata['candidate_execution_plan']
      are populated with the learned runbook's structured steps and marked guidance_only / non-executable.
    """
    tenant_id = "tenant-p0-test"
    markdown = _sample_runbook_markdown(service="Geo-Service", alert_name="ExternalEndpointDown")

    async with session_factory() as session:
        repo = IncidentRepository(session)
        rb_uuid = await _create_and_approve_knowledge_runbook(
            repo,
            tenant_id=tenant_id,
            service="Geo-Service",
            alert_name="ExternalEndpointDown",
            markdown=markdown,
            source_ref="kaiops://human-evidence/geo-service/subsequent-incident-v1",
            approved_by="approver@example.com",
        )
        await session.commit()
        learned_runbook_id = str(rb_uuid)

    monkeypatch.setattr(resolution_app_module.settings, "database_enabled", True)
    monkeypatch.setattr(resolution_app_module.app.state, "session_factory", session_factory, raising=False)

    subsequent_incident_id = uuid4()
    alert = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        source="prometheus",
        name="ExternalEndpointDown",
        service="Geo-Service",
        environment="prod",
        severity=Severity.CRITICAL,
        description="Synthetic blackbox probe failed for Geo-Service endpoint",
    )
    context = Context(
        tenant_id=tenant_id,
        incident_id=subsequent_incident_id,
        alert=alert,
        runbook=markdown,
        metadata={
            "analysis_request_id": str(uuid4()),
            "document_available": True,
            "rag_documents": 1,
            "rag_top_similarity": 0.88,
            "rag_service_tagged_match": True,
            "rag_matches": [
                {
                    "kind": "runbook",
                    "title": "Runbook: Geo-Service - ExternalEndpointDown",
                    "path": f"governed://{tenant_id}/{learned_runbook_id}/v1",
                    "similarity": 0.88,
                }
            ],
            "_final_investigation_report": {
                "investigation_id": str(uuid4()),
                "status": "inconclusive",
                "conclusive": False,
                "outcome": "INSUFFICIENT_EVIDENCE",
                "evidence": [],
                "hypotheses": [],
                "conclusion": {
                    "hypothesis_id": None,
                    "confidence": 0.35,
                    "conclusive_threshold": 0.65,
                    "independent_source_count": 0,
                    "minimum_independent_sources": 2,
                    "causally_eligible": False,
                    "evidence_ids": [],
                    "contradicting_evidence_ids": [],
                },
                "missing_sources": ["logs", "metrics"],
                "next_evidence": [{"source": "logs", "reason": "Inspect Geo-Service error logs"}],
            },
        },
    )

    recommendation = await resolution_app_module._resolve_context(context)
    plan = resolution_app_module._apply_catalog_plan(recommendation, context, {})

    # 1. Must NOT fabricate conclusive RCA
    assert recommendation.metadata["rca_status"] == "insufficient_evidence"
    assert recommendation.root_cause.startswith("Hypothesis")
    assert plan["execution_ready"] is False
    assert plan["diagnostic_only"] is True
    assert plan["commands"] == []

    # 2. Must retain the learned runbook ID, version, and slug (NOT generic-kaiops-triage-playbook)
    assert recommendation.metadata["runbook_id"] == learned_runbook_id
    assert recommendation.metadata["runbook_version"] == 1
    assert recommendation.metadata["runbook_slug"] != "generic-kaiops-triage-playbook"
    assert plan["runbook_governance_id"] == learned_runbook_id
    assert plan["playbook_version"] == 1
    assert plan["playbook_id"] == recommendation.metadata["runbook_slug"]

    # 3. Must preserve structured runbook guidance and candidate remediation plan (not None)
    guidance = recommendation.metadata.get("runbook_guidance")
    assert isinstance(guidance, dict)
    assert guidance["runbook_id"] == learned_runbook_id
    assert guidance["runbook_version"] == 1
    assert guidance["guidance_only"] is True
    assert guidance["evidence_classification"] == "operational_runbook_guidance"
    assert "kubectl rollout restart deployment/geo-service -n prod" in guidance["remediation_steps"]
    assert "curl -fsS https://geo.example.com/healthz" in guidance["validation_steps"]
    assert "kubectl rollout undo deployment/geo-service -n prod" in guidance["rollback_steps"]

    assert recommendation.remediation_plan is not None
    assert recommendation.remediation_plan.required_parameters["runbook_id"] == learned_runbook_id
    assert recommendation.remediation_plan.required_parameters["runbook_version"] == 1
    assert "kubectl rollout restart deployment/geo-service -n prod" in (
        recommendation.remediation_plan.required_parameters["remediation_steps"]
    )
    assert recommendation.metadata["remediation_plan_status"]["execution_eligible"] is False
    assert recommendation.metadata["remediation_plan_status"]["guidance_only"] is True

    candidate_plan = recommendation.metadata.get("candidate_execution_plan")
    assert isinstance(candidate_plan, dict)
    assert "kubectl rollout restart deployment/geo-service -n prod" in candidate_plan["commands"]


@pytest.mark.asyncio
async def test_p0a_conclusive_incident_with_learned_runbook_produces_grounded_bound_plan(
    session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When independent causal evidence IS conclusive and an approved learned runbook matches:
    - The learned runbook ID, slug, and version are bound onto the execution plan and remediation plan.
    - Structured remediation, validation, and rollback commands are bound to the learned runbook.
    """
    tenant_id = "tenant-p0-test"
    markdown = _sample_runbook_markdown(service="Geo-Service", alert_name="ExternalEndpointDown")

    async with session_factory() as session:
        repo = IncidentRepository(session)
        rb_uuid = await _create_and_approve_knowledge_runbook(
            repo,
            tenant_id=tenant_id,
            service="Geo-Service",
            alert_name="ExternalEndpointDown",
            markdown=markdown,
            source_ref="kaiops://human-evidence/geo-service/conclusive-v1",
            approved_by="approver@example.com",
        )
        await session.commit()
        learned_runbook_id = str(rb_uuid)

    monkeypatch.setattr(resolution_app_module.settings, "database_enabled", True)
    monkeypatch.setattr(resolution_app_module.app.state, "session_factory", session_factory, raising=False)

    alert = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        source="prometheus",
        name="ExternalEndpointDown",
        service="Geo-Service",
        environment="prod",
        severity=Severity.CRITICAL,
        description="Geo-Service HTTP 502 due to upstream DNS cache poisoning",
    )
    conclusive_report = {
        "investigation_id": str(uuid4()),
        "status": "conclusive",
        "conclusive": True,
        "outcome": "ROOT_CAUSE_IDENTIFIED",
        "evidence": [
            {
                "evidence_id": "ev-log-1",
                "source": "logs",
                "service": "Geo-Service",
                "snippet": "ERROR upstream DNS resolver cache poisoned; socket pool stale",
            },
            {
                "evidence_id": "ev-metric-1",
                "source": "metrics",
                "service": "Geo-Service",
                "snippet": "geo_service_upstream_502_total=142",
            },
        ],
        "hypotheses": [
            {
                "hypothesis_id": "hyp-1",
                "claim": "Geo-Service upstream DNS resolver cache poisoning and stale socket pool",
                "confidence": 0.91,
                "evidence_ids": ["ev-log-1", "ev-metric-1"],
                "contradicting_evidence_ids": [],
            }
        ],
        "conclusion": {
            "hypothesis_id": "hyp-1",
            "claim": "Geo-Service upstream DNS resolver cache poisoning and stale socket pool",
            "confidence": 0.91,
            "conclusive_threshold": 0.65,
            "independent_source_count": 2,
            "minimum_independent_sources": 2,
            "causally_eligible": True,
            "evidence_ids": ["ev-log-1", "ev-metric-1"],
            "contradicting_evidence_ids": [],
        },
        "missing_sources": [],
        "next_evidence": [],
    }
    context = Context(
        tenant_id=tenant_id,
        incident_id=uuid4(),
        alert=alert,
        runbook=markdown,
        metadata={
            "analysis_request_id": str(uuid4()),
            "document_available": True,
            "rag_documents": 1,
            "rag_top_similarity": 0.93,
            "rag_service_tagged_match": True,
            "rag_matches": [
                {
                    "kind": "runbook",
                    "title": "Runbook: Geo-Service - ExternalEndpointDown",
                    "path": f"governed://{tenant_id}/{learned_runbook_id}/v1",
                    "similarity": 0.93,
                }
            ],
            "iterative_investigation": {k: v for k, v in conclusive_report.items() if k != "evidence"},
            "_final_investigation_report": conclusive_report,
        },
    )

    recommendation = await resolution_app_module._resolve_context(context)
    recommendation.metadata["rca_status"] = "grounded"
    recommendation.metadata["rca_analysis"] = {
        **(recommendation.metadata.get("rca_analysis") or {}),
        "evidence_used": ["ev-log-1", "ev-metric-1"],
        "missing_evidence": [],
        "conflicting_evidence": [],
        "context_readiness": {"ready": True, "score": 0.95},
    }
    plan = resolution_app_module._apply_catalog_plan(recommendation, context, {})

    assert recommendation.metadata["runbook_id"] == learned_runbook_id
    assert recommendation.metadata["runbook_version"] == 1
    assert plan["runbook_governance_id"] == learned_runbook_id
    assert plan["playbook_version"] == 1
    assert plan["playbook_id"] != "generic-kaiops-triage-playbook"
    assert plan["runbook_status"] == "approved"
    assert plan["commands"] == [
        "kubectl rollout restart deployment/geo-service -n prod",
        "kubectl rollout status deployment/geo-service -n prod --timeout=120s",
    ]
    assert plan["validation_commands"] == [
        "curl -fsS https://geo.example.com/healthz",
        "Verify ExternalEndpointDown alert clears in Alertmanager.",
    ]
    assert plan["rollback_commands"] == [
        "kubectl rollout undo deployment/geo-service -n prod",
    ]
    assert recommendation.remediation_plan is not None
    assert recommendation.remediation_plan.required_parameters["runbook_id"] == learned_runbook_id


# ============================================================================
# P0-B Tests: Resolution-Event Snapshot-to-Outbox SHA-256 Parity & Compaction
# ============================================================================


@pytest.mark.asyncio
async def test_p0b_snapshot_to_outbox_sha256_parity_and_metadata_completeness(
    session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that:
    1. persist_final_investigation_snapshot and bind_context_to_snapshot + _persist_resolution_event
       produce byte-for-byte identical canonical context payloads (matching SHA-256 context_checksum).
    2. Both snapshot.payload['metadata'] and outbox payload['context']['metadata'] include
       investigation_report and snapshot_version.
    3. Neither snapshot.payload['metadata'] nor outbox payload['context']['metadata'] contains
       the transient _final_investigation_report key.
    4. Production CONTEXT_TOPICS includes 'resolution-events' for snapshot reference compaction.
    """
    assert "resolution-events" in CONTEXT_TOPICS

    tenant_id = "tenant-p0-test"
    incident_id = uuid4()
    alert = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        source="prometheus",
        name="ExternalEndpointDown",
        service="Geo-Service",
        environment="prod",
        severity=Severity.CRITICAL,
        description="Endpoint https://geo.example.com is unreachable",
    )
    parent_snapshot_id = uuid4()
    now = datetime.now(UTC)
    initial_context = Context(
        tenant_id=tenant_id,
        incident_id=incident_id,
        alert=alert,
        metadata={
            "context_snapshot_id": str(parent_snapshot_id),
            "context_fingerprint": "a" * 64,
            "context_subject_fingerprint": "subj-geo-1",
            "analysis_request_id": str(uuid4()),
            "rca_version": 1,
            "context_evidence": {
                "logs": [
                    {
                        "evidence_id": "ev-init-1",
                        "source": "logs",
                        "service": "Geo-Service",
                        "snippet": "ERROR connection refused",
                    }
                ]
            },
        },
    )

    async with session_factory() as session:
        session.add(
            ContextSnapshotRecord(
                snapshot_id=parent_snapshot_id,
                tenant_id=tenant_id,
                incident_id=str(incident_id),
                alert_signature=f"{alert.service}:{alert.name}",
                snapshot_version=1,
                snapshot_stage="initial",
                subject_fingerprint="subj-geo-1",
                context_fingerprint="a" * 64,
                evidence_ids=["ev-init-1"],
                evidence_checksums={"ev-init-1": "sha256:" + "1" * 64},
                payload=initial_context.model_dump(mode="json"),
                collected_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        await session.commit()

    report = {
        "investigation_id": str(uuid4()),
        "status": "conclusive",
        "conclusive": True,
        "outcome": "ROOT_CAUSE_IDENTIFIED",
        "evidence": [
            {
                "evidence_id": "ev-init-1",
                "source": "logs",
                "service": "Geo-Service",
                "snippet": "ERROR connection refused",
                "content_checksum": "sha256:" + "1" * 64,
            }
        ],
        "hypotheses": [
            {
                "hypothesis_id": "h-1",
                "claim": "Geo-Service upstream connection refused",
                "confidence": 0.88,
                "evidence_ids": ["ev-init-1"],
                "contradicting_evidence_ids": [],
            }
        ],
        "conclusion": {
            "hypothesis_id": "h-1",
            "claim": "Geo-Service upstream connection refused",
            "confidence": 0.88,
            "conclusive_threshold": 0.65,
            "independent_source_count": 2,
            "minimum_independent_sources": 2,
            "causally_eligible": True,
            "evidence_ids": ["ev-init-1"],
            "contradicting_evidence_ids": [],
        },
    }

    ctx_with_transient = initial_context.model_copy(
        update={
            "metadata": {
                **initial_context.metadata,
                "_final_investigation_report": report,
            }
        }
    )

    monkeypatch.setattr(resolution_app_module.settings, "database_enabled", True)
    monkeypatch.setattr(resolution_app_module.app.state, "session_factory", session_factory, raising=False)

    recommendation = Recommendation(
        id=uuid4(),
        tenant_id=tenant_id,
        incident_id=incident_id,
        severity=Severity.CRITICAL,
        root_cause="Geo-Service upstream connection refused",
        confidence=0.88,
        impact="Geo-Service requests failing",
        recommended_action="Restart Geo-Service deployment",
        rationale="Supported by log evidence ev-init-1",
        risk="medium",
        metadata={
            "rca_status": "grounded",
            "rca_version": 1,
            "evidence_ids": ["ev-init-1"],
            "rca_analysis": {
                "evidence_used": ["ev-init-1"],
                "missing_evidence": [],
                "conflicting_evidence": [],
                "context_readiness": {"ready": True, "score": 0.9},
            },
            "iterative_investigation": {k: v for k, v in report.items() if k != "evidence"},
        },
    )

    bound_context = await resolution_app_module._commit_investigation_recommendation(
        ctx_with_transient,
        report,
        parent_snapshot_id,
        recommendation,
        {},
    )

    incident = Incident(
        id=incident_id,
        tenant_id=tenant_id,
        service="Geo-Service",
        environment="prod",
        severity=Severity.CRITICAL,
        title="Geo-Service: ExternalEndpointDown",
    )

    await resolution_app_module._persist_resolution_event(
        app=resolution_app_module.app,
        context=bound_context,
        incident=incident,
        recommendation=recommendation,
        decision_payload={},
    )

    async with session_factory() as session:
        final_snapshot_id = UUID(str(bound_context.metadata["context_snapshot_id"]))
        snapshot_row = await session.get(ContextSnapshotRecord, final_snapshot_id)
        assert snapshot_row is not None

        outbox_rows = (
            await session.execute(
                select(ResolutionOutboxRecord).where(
                    ResolutionOutboxRecord.tenant_id == tenant_id,
                    ResolutionOutboxRecord.aggregate_id == str(incident_id),
                    ResolutionOutboxRecord.topic == "resolution-events",
                )
            )
        ).scalars().all()
        assert len(outbox_rows) == 1
        outbox_row = outbox_rows[0]

    snapshot_payload = snapshot_row.payload
    outbox_context_payload = outbox_row.payload["context"]

    # Neither may contain transient _final_investigation_report
    assert "_final_investigation_report" not in snapshot_payload["metadata"]
    assert "_final_investigation_report" not in outbox_context_payload["metadata"]

    # Both must contain investigation_report and snapshot_version
    assert "investigation_report" in snapshot_payload["metadata"]
    assert "investigation_report" in outbox_context_payload["metadata"]
    assert snapshot_payload["metadata"]["investigation_report"] == outbox_context_payload["metadata"]["investigation_report"]
    assert snapshot_payload["metadata"]["snapshot_version"] == 2
    assert outbox_context_payload["metadata"]["snapshot_version"] == 2

    # Exact SHA-256 parity between persisted snapshot payload and enqueued outbox context
    assert context_checksum(snapshot_payload) == context_checksum(outbox_context_payload)
    assert snapshot_payload == outbox_context_payload


@pytest.mark.asyncio
async def test_p0b_resolution_events_compaction_hydration_and_fail_closed_guards(
    session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that when 'resolution-events' is enabled in CONTEXT_TOPICS (via isolated monkeypatch):
    1. compact_context replaces payload['context'] with payload['context_ref'] using the
       exact snapshot_id and context_sha256 when payload size >= 64KB.
    2. hydrate_context and flush_resolution_outbox restore the full context without hash mismatch.
    3. Missing snapshot and tampered snapshot payload fail closed with ValueError.
    4. Legacy inline resolution-events payloads (without context_ref) still hydrate cleanly.
    """
    monkeypatch.setattr(
        outbox_context,
        "CONTEXT_TOPICS",
        frozenset({*outbox_context.CONTEXT_TOPICS, "resolution-events"}),
    )
    monkeypatch.setattr(get_settings(), "outbox_snapshot_references_enabled", True)
    monkeypatch.setattr(get_settings(), "database_enabled", True)

    tenant_id = "tenant-p0-test"
    incident_id = uuid4()
    alert = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        source="prometheus",
        name="ExternalEndpointDown",
        service="Geo-Service",
        environment="prod",
        severity=Severity.CRITICAL,
        description="Endpoint down",
    )
    parent_snapshot_id = uuid4()
    now = datetime.now(UTC)
    # Include >=64KB of log lines in metadata so compact_context triggers snapshot reference compaction
    large_logs = [f"ERROR Geo-Service upstream probe timeout line={i} " + ("x" * 160) for i in range(450)]
    initial_context = Context(
        tenant_id=tenant_id,
        incident_id=incident_id,
        alert=alert,
        metadata={
            "context_snapshot_id": str(parent_snapshot_id),
            "context_fingerprint": "b" * 64,
            "context_subject_fingerprint": "subj-geo-2",
            "large_log_dump": large_logs,
        },
    )

    async with session_factory() as session:
        session.add(
            ContextSnapshotRecord(
                snapshot_id=parent_snapshot_id,
                tenant_id=tenant_id,
                incident_id=str(incident_id),
                alert_signature=f"{alert.service}:{alert.name}",
                snapshot_version=1,
                snapshot_stage="initial",
                subject_fingerprint="subj-geo-2",
                context_fingerprint="b" * 64,
                evidence_ids=[],
                evidence_checksums={},
                payload=initial_context.model_dump(mode="json"),
                collected_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        await session.commit()

        repo = IncidentRepository(session)
        report = {"investigation_id": str(uuid4()), "status": "inconclusive", "conclusive": False, "evidence": []}
        snapshot = await repo.persist_final_investigation_snapshot(
            context=initial_context,
            report=report,
            parent_snapshot_id=parent_snapshot_id,
        )
        bound = resolution_app_module.bind_context_to_snapshot(initial_context, snapshot=snapshot)
        event_id = f"res-ev-{uuid4()}"
        event_payload = {
            "context": bound.model_dump(mode="json"),
            "incident": {"id": str(incident_id), "service": "Geo-Service"},
            "recommendation": {"id": str(uuid4()), "root_cause": "Hypothesis: test"},
            "event_contract": {"event_id": event_id},
        }
        await repo.enqueue_resolution_event(
            event_id=event_id,
            tenant_id=tenant_id,
            aggregate_id=str(incident_id),
            topic="resolution-events",
            partition_key=str(incident_id),
            payload=event_payload,
            available_after_seconds=0.0,
        )
        await session.commit()

        outbox_row = await session.get(ResolutionOutboxRecord, event_id)
        assert outbox_row is not None

        # 1. Verify compaction replaced inline context with context_ref
        assert "context" not in outbox_row.payload
        assert "context_ref" in outbox_row.payload
        assert outbox_row.payload["context_ref"]["snapshot_id"] == str(snapshot.snapshot_id)
        assert outbox_row.payload["context_ref"]["context_sha256"] == context_checksum(snapshot.payload)

        # 2. Verify hydrate_context restores full context with investigation_report and snapshot_version
        hydrated = await hydrate_context(session, outbox_row)
        assert hydrated["context"] == snapshot.payload
        assert hydrated["context"]["metadata"]["investigation_report"] == report
        assert hydrated["context"]["metadata"]["snapshot_version"] == 2
        assert "_final_investigation_report" not in hydrated["context"]["metadata"]
        assert "context_ref" not in hydrated

    # 3. Verify flush_resolution_outbox publishes hydrated payload cleanly
    published: list[tuple[str, dict, str | None]] = []

    class DummyProducer:
        async def publish(self, topic: str, value: dict, key: str | None = None) -> None:
            published.append((topic, value, key))

    class DummyApp:
        class state:
            pass

    DummyApp.state.session_factory = session_factory
    DummyApp.state.db_engine = session_factory.kw["bind"]
    DummyApp.state.producer = DummyProducer()

    dispatched = await flush_resolution_outbox(DummyApp, get_settings())
    assert dispatched == 1
    assert len(published) == 1
    pub_topic, pub_payload, _ = published[0]
    assert pub_topic == "resolution-events"
    assert pub_payload["context"] == snapshot.payload
    assert "context_ref" not in pub_payload

    async with session_factory() as session:
        # 4. Verify hash mismatch fails closed
        tampered_row = ResolutionOutboxRecord(
            event_id=f"tampered-{uuid4()}",
            tenant_id=tenant_id,
            aggregate_id=str(incident_id),
            topic="resolution-events",
            partition_key=str(incident_id),
            payload={
                "context_ref": {
                    "schema_version": REFERENCE_VERSION,
                    "snapshot_id": str(snapshot.snapshot_id),
                    "tenant_id": tenant_id,
                    "incident_id": str(incident_id),
                    "context_fingerprint": snapshot.context_fingerprint,
                    "context_sha256": "0" * 64,
                },
                "incident": {"id": str(incident_id)},
            },
        )
        with pytest.raises(ValueError, match="Outbox context snapshot binding or checksum mismatch"):
            await hydrate_context(session, tampered_row)

        # 5. Verify missing snapshot fails closed
        missing_row = ResolutionOutboxRecord(
            event_id=f"missing-{uuid4()}",
            tenant_id=tenant_id,
            aggregate_id=str(incident_id),
            topic="resolution-events",
            partition_key=str(incident_id),
            payload={
                "context_ref": {
                    "schema_version": REFERENCE_VERSION,
                    "snapshot_id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "incident_id": str(incident_id),
                    "context_fingerprint": snapshot.context_fingerprint,
                    "context_sha256": context_checksum(snapshot.payload),
                },
                "incident": {"id": str(incident_id)},
            },
        )
        with pytest.raises(ValueError, match="Outbox context snapshot binding or checksum mismatch"):
            await hydrate_context(session, missing_row)

        # 6. Verify legacy inline payload hydrates cleanly without context_ref
        legacy_inline_row = ResolutionOutboxRecord(
            event_id=f"legacy-{uuid4()}",
            tenant_id=tenant_id,
            aggregate_id=str(incident_id),
            topic="resolution-events",
            partition_key=str(incident_id),
            payload={
                "context": snapshot.payload,
                "incident": {"id": str(incident_id)},
            },
        )
        hydrated_inline = await hydrate_context(session, legacy_inline_row)
        assert hydrated_inline["context"] == snapshot.payload


@pytest.mark.asyncio
async def test_p0a_generic_playbook_fallback_and_human_evidence_workflow_preserved(
    session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no learned runbook or catalog playbook matches an incident,
    generic-kaiops-triage-playbook diagnostic fallback behavior is preserved.
    """
    tenant_id = "tenant-p0-test"
    monkeypatch.setattr(resolution_app_module.settings, "database_enabled", True)
    monkeypatch.setattr(resolution_app_module.app.state, "session_factory", session_factory, raising=False)

    alert = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        source="prometheus",
        name="UnmappedNovelAlert",
        service="Unmapped-Novel-Service",
        environment="prod",
        severity=Severity.WARNING,
        description="Novel unmapped symptom without any runbook",
    )
    context = Context(
        tenant_id=tenant_id,
        incident_id=uuid4(),
        alert=alert,
        metadata={
            "analysis_request_id": str(uuid4()),
            "document_available": False,
            "rag_matches": [],
        },
    )
    recommendation = await resolution_app_module._resolve_context(context)
    plan = resolution_app_module._apply_catalog_plan(recommendation, context, {})

    assert plan["playbook_id"] == "generic-kaiops-triage-playbook"
    assert plan["diagnostic_only"] is True
    assert plan["execution_ready"] is False
    assert recommendation.metadata.get("runbook_guidance") is None


@pytest.mark.asyncio
async def test_p0b_context_events_compaction_and_mutation_rejection_preserved(
    session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify:
    1. Existing context-events compaction and hydration behavior remains intact.
    2. Post-snapshot context metadata mutations cannot silently create a mismatched reference
       because compact_context verifies context_checksum(context) == context_checksum(snapshot.payload)
       before writing context_ref.
    """
    monkeypatch.setattr(
        outbox_context,
        "CONTEXT_TOPICS",
        frozenset({*outbox_context.CONTEXT_TOPICS, "resolution-events"}),
    )
    monkeypatch.setattr(get_settings(), "outbox_snapshot_references_enabled", True)

    tenant_id = "tenant-p0-test"
    incident_id = uuid4()
    snapshot_id = uuid4()
    now = datetime.now(UTC)
    large_logs = [f"INFO context-events log line={i} " + ("z" * 160) for i in range(450)]
    alert = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        source="prometheus",
        name="HighLatency",
        service="Geo-Service",
        environment="prod",
        severity=Severity.WARNING,
        description="High latency",
    )
    ctx = Context(
        tenant_id=tenant_id,
        incident_id=incident_id,
        alert=alert,
        metadata={
            "context_snapshot_id": str(snapshot_id),
            "context_fingerprint": "c" * 64,
            "context_subject_fingerprint": "subj-geo-3",
            "large_log_dump": large_logs,
        },
    )
    canonical_ctx = ctx.model_dump(mode="json")

    async with session_factory() as session:
        session.add(
            ContextSnapshotRecord(
                snapshot_id=snapshot_id,
                tenant_id=tenant_id,
                incident_id=str(incident_id),
                alert_signature="Geo-Service:HighLatency",
                snapshot_version=1,
                snapshot_stage="initial",
                subject_fingerprint="subj-geo-3",
                context_fingerprint="c" * 64,
                evidence_ids=[],
                evidence_checksums={},
                payload=canonical_ctx,
                collected_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        await session.commit()

        # 1. Existing context-events compaction & hydration
        compacted_ctx_event = await compact_context(
            session,
            payload={"context": canonical_ctx, "incident": {"id": str(incident_id)}},
            tenant_id=tenant_id,
            aggregate_id=str(incident_id),
            topic="context-events",
        )
        assert "context_ref" in compacted_ctx_event
        assert "context" not in compacted_ctx_event
        row = ResolutionOutboxRecord(
            event_id=f"ctx-ev-{uuid4()}",
            tenant_id=tenant_id,
            aggregate_id=str(incident_id),
            topic="context-events",
            partition_key=str(incident_id),
            payload=compacted_ctx_event,
        )
        hydrated = await hydrate_context(session, row)
        assert hydrated["context"] == canonical_ctx

        # 2. Mutating context metadata after snapshot persistence prevents creating a mismatched context_ref
        mutated_ctx = {
            **canonical_ctx,
            "metadata": {
                **canonical_ctx["metadata"],
                "unexpected_post_snapshot_mutation": "drifted-value",
            },
        }
        compacted_after_mutation = await compact_context(
            session,
            payload={"context": mutated_ctx, "incident": {"id": str(incident_id)}},
            tenant_id=tenant_id,
            aggregate_id=str(incident_id),
            topic="resolution-events",
        )
        # compact_context refuses to emit a mismatched context_ref when checksum != snapshot checksum
        assert "context_ref" not in compacted_after_mutation
        assert compacted_after_mutation["context"] == mutated_ctx

