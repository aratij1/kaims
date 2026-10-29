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
    "backend/src/closure-service",
    "ai-workbench/src/common",
    "ai-workbench/src/resolution-agent",
):
    candidate = str(ROOT / rel)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from ai_workbench_common.models import Context
from common.database import (
    AuditLogRecord,
    Base,
    CanonicalEvidenceRecord,
    ContextSnapshotRecord,
    GovernedRagDocumentRecord,
    IncidentInvestigationBindingRecord,
    IncidentProjectionRecord,
    IncidentRecord,
    KnowledgeRagDraftRecord,
    RcaReportRecord,
    ResolutionOutboxRecord,
    RunbookVersionRecord,
)
from common.models import (
    Alert,
    AlertSeverity,
    Incident,
    RemediationAction,
    RemediationStatus,
    ResolutionReport,
)
from common.outbox_context import (
    CONTEXT_TOPICS,
    compact_context,
    context_checksum,
    hydrate_context,
)
from common.repository import ContextEnrichmentRepository, IncidentRepository
from resolution_agent.catalog import register_learned_runbooks

_resolution_app_path = ROOT / "ai-workbench/src/resolution-agent/app.py"
_resolution_app_spec = importlib.util.spec_from_file_location(
    "resolution_agent_app_lifecycle_e2e", _resolution_app_path
)
assert _resolution_app_spec is not None and _resolution_app_spec.loader is not None
resolution_app_module = importlib.util.module_from_spec(_resolution_app_spec)
sys.modules["resolution_agent_app_lifecycle_e2e"] = resolution_app_module
_resolution_app_spec.loader.exec_module(resolution_app_module)

_closure_app_path = ROOT / "backend/src/closure-service/app.py"
_closure_app_spec = importlib.util.spec_from_file_location(
    "closure_service_app_lifecycle_e2e", _closure_app_path
)
assert _closure_app_spec is not None and _closure_app_spec.loader is not None
closure_app_module = importlib.util.module_from_spec(_closure_app_spec)
sys.modules["closure_service_app_lifecycle_e2e"] = closure_app_module
_closure_app_spec.loader.exec_module(closure_app_module)


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


@pytest.fixture()
async def session_factory(tmp_path: Path):
    db_file = tmp_path / "lifecycle_e2e.sqlite"
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


def _sample_runbook_markdown(
    *,
    service: str = "billing-worker",
    alert_name: str = "BillingWorkerConsumerStall",
    runbook_id: str = "rb-billing-worker-stall-v1",
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
Billing worker consumer thread pool deadlocked on poison invoice payload batch.

## Business Impact
Subscription invoice generation delayed for enterprise tenants.

## Preconditions
1. Verify billing-worker consumer lag in prod.

## Remediation Steps
1. `kubectl rollout restart deployment/{service} -n prod`
2. `kubectl rollout status deployment/{service} -n prod --timeout=120s`

## Validation
1. `curl -fsS http://{service}.prod.svc/healthz`

## Rollback
1. `kubectl rollout undo deployment/{service} -n prod`
"""


async def _seed_incident_and_snapshot(
    session,
    *,
    tenant_id: str,
    incident_id: UUID,
    alert: Alert,
    runbook: str = "",
    document_available: bool = False,
) -> Context:
    now = datetime.now(UTC)
    snapshot_id = uuid4()
    alert_ev_id = f"alert:{alert.id}"
    session.add(
        CanonicalEvidenceRecord(
            evidence_id=alert_ev_id,
            requirement_id=uuid4(),
            tenant_id=tenant_id,
            incident_id=incident_id,
            category="telemetry",
            source_id=f"alert:{alert.id}",
            connector="alert-receiver",
            source_reference=f"alert://{alert.id}",
            service=alert.service,
            resource=str(alert.id),
            project_id=None,
            observed_at=now,
            collected_at=now,
            observation_window_start=None,
            observation_window_end=None,
            freshness="fresh",
            content={"alert_id": str(alert.id), "description": alert.description},
            provenance={"collector": "alert-receiver"},
            current_observation=True,
            contradiction_status=None,
            content_digest="1" * 64,
        )
    )
    context = Context(
        tenant_id=tenant_id,
        incident_id=incident_id,
        alert=alert,
        runbook=runbook,
        metadata={
            "analysis_request_id": str(uuid4()),
            "document_available": document_available,
            "context_snapshot_id": str(snapshot_id),
            "correlation_id": f"corr-{incident_id}",
            "rca_version": 1,
            "_final_investigation_report": {
                "investigation_id": str(uuid4()),
                "status": "inconclusive",
                "conclusive": False,
                "outcome": "INSUFFICIENT_EVIDENCE",
                "evidence": [
                    {
                        "evidence_id": alert_ev_id,
                        "source": "telemetry",
                        "service": alert.service,
                        "snippet": alert.description,
                    }
                ],
                "hypotheses": [],
                "conclusion": {
                    "hypothesis_id": None,
                    "confidence": 0.35,
                    "conclusive_threshold": 0.65,
                    "independent_source_count": 1,
                    "minimum_independent_sources": 2,
                    "causally_eligible": False,
                    "evidence_ids": [alert_ev_id],
                    "contradicting_evidence_ids": [],
                },
                "missing_sources": ["logs", "runbooks"],
                "next_evidence": [{"source": "runbooks", "reason": "Inspect runbook for service"}],
            },
            "context_evidence": {
                "telemetry": [
                    {
                        "evidence_id": alert_ev_id,
                        "source": "telemetry",
                        "connector": "alert-receiver",
                        "service": alert.service,
                        "snippet": alert.description,
                        "relevant_content": alert.description,
                        "observed_at": now.isoformat(),
                    }
                ]
            },
        },
    )
    session.add(
        IncidentRecord(
            id=incident_id,
            tenant_id=tenant_id,
            title=alert.name,
            severity=alert.severity.value,
            status="investigating",
            service=alert.service,
            environment=alert.environment,
            payload={
                "id": str(incident_id),
                "tenant_id": tenant_id,
                "title": alert.name,
                "severity": alert.severity.value,
                "status": "investigating",
                "service": alert.service,
                "environment": alert.environment,
                "ticket_id": "KAI-901",
                "alert_ids": [str(alert.id)],
                "timeline": [{"event": "incident.opened", "timestamp": now.isoformat()}],
            },
        )
    )
    session.add(
        IncidentProjectionRecord(
            incident_id=incident_id,
            tenant_id=tenant_id,
            service=alert.service,
            environment=alert.environment,
            severity=alert.severity.value,
            status="investigating",
            lifecycle_state="INVESTIGATING",
            projection_payload={
                "incident": {"id": str(incident_id), "status": "investigating"},
                "correlation_id": f"corr-{incident_id}",
            },
        )
    )
    session.add(
        ContextSnapshotRecord(
            snapshot_id=snapshot_id,
            tenant_id=tenant_id,
            incident_id=str(incident_id),
            source_incident_id=str(incident_id),
            alert_signature=f"sig-{alert.name}",
            subject_fingerprint="s" * 64,
            context_fingerprint="c" * 64,
            snapshot_stage="final",
            snapshot_version=1,
            evidence_ids=[alert_ev_id],
            evidence_checksums={alert_ev_id: "3" * 64},
            contract_version="kaiops.context.v2",
            quality_score=0.5,
            reusable=False,
            source_manifest={
                "telemetry": {
                    "connector": "alert-receiver",
                    "source_reference": f"alert://{alert.id}",
                }
            },
            payload=context.model_dump(mode="json"),
            collected_at=now,
            expires_at=now + timedelta(hours=1),
        )
    )
    await session.commit()
    return context


# ============================================================================
# Scenario A: Approved Runbook (Pending & Indexed) Matches & Populates Guidance
# ============================================================================


@pytest.mark.asyncio
async def test_scenario_a_known_learned_runbook_matches_when_pending_and_after_indexing(
    session_factory,
) -> None:
    tenant_id = "tenant-scenario-a"
    service = "billing-worker"
    alert_name = "BillingWorkerConsumerStall"
    source_ref = "kaiops://human-evidence/billing-worker/runbook-v1"
    markdown = _sample_runbook_markdown(service=service, alert_name=alert_name)

    resolution_app_module.settings.database_enabled = True
    resolution_app_module.app.state.session_factory = session_factory

    async with session_factory() as session:
        repo = IncidentRepository(session)
        draft = await repo.create_knowledge_rag_draft(
            tenant_id=tenant_id,
            created_by="operator@example.com",
            document_kind="runbook",
            source_ref=source_ref,
            title=f"Runbook: {service} - {alert_name}",
            content=markdown,
            metadata={
                "service": service,
                "alert_name": alert_name,
                "root_cause": "Billing worker consumer thread pool deadlocked on poison invoice payload batch.",
            },
        )
        reviewed = await repo.review_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft["draft_id"],
            expected_row_version=draft["row_version"],
            title=draft["title"],
            content=draft["content"],
            review_notes="Approved billing-worker runbook",
            reviewed_by="sre-lead@example.com",
        )
        approved_res = await repo.approve_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft["draft_id"],
            expected_row_version=reviewed["row_version"],
            approved_by="release-owner@example.com",
        )
        await session.commit()
        assert approved_res is not None
        _, approved_doc = approved_res
        rb_uuid = uuid5(NAMESPACE_URL, f"kaiops:runbook:{tenant_id}:{source_ref}")

        # 1. Immediately after approval, GovernedRagDocumentRecord.index_status is "pending"
        # while RunbookVersionRecord is approved and ready for governed catalog matching
        doc_row = await session.get(GovernedRagDocumentRecord, UUID(approved_doc["document_id"]))
        assert doc_row is not None
        assert doc_row.index_status == "pending"

        rv = (
            await session.execute(
                select(RunbookVersionRecord).where(
                    RunbookVersionRecord.tenant_id == tenant_id,
                    RunbookVersionRecord.runbook_id == rb_uuid,
                    RunbookVersionRecord.version == 1,
                )
            )
        ).scalars().first()
        assert rv is not None
        assert rv.approval_status == "approved"

        # 2. Newly approved runbook is matched by _load_learned_runbooks_for_context even before async RAG indexing
        incident_id = uuid4()
        alert = Alert(
            tenant_id=tenant_id,
            source="prometheus",
            name=alert_name,
            description="billing-worker consumer lag stuck on partition 0",
            service=service,
            environment="prod",
            severity=AlertSeverity.CRITICAL,
        )
        context = await _seed_incident_and_snapshot(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
            runbook="",
            document_available=False,
        )

    recommendation = await resolution_app_module._resolve_context(context)
    resolution_app_module._apply_catalog_plan(recommendation, context, {})
    matched = (context.metadata or {}).get("matched_learned_runbook")
    assert isinstance(matched, dict)
    assert matched["runbook_id"] == str(rb_uuid)
    assert context.metadata.get("document_available") is True
    assert "kubectl rollout restart deployment/billing-worker -n prod" in context.runbook
    assert isinstance(recommendation.metadata.get("runbook_guidance"), dict)
    assert recommendation.metadata["runbook_guidance"]["runbook_id"] == str(rb_uuid)
    assert isinstance(recommendation.metadata.get("candidate_execution_plan"), dict)
    assert any(
        "kubectl rollout restart deployment/billing-worker -n prod" in cmd
        for cmd in recommendation.metadata["candidate_execution_plan"].get("commands", [])
    )

    # 3. Verify mark_governed_rag_document_indexed updates RunbookVersionRecord.content["index_status"] = "indexed"
    async with session_factory() as session:
        repo = IncidentRepository(session)
        await repo.mark_governed_rag_document_indexed(
            tenant_id=tenant_id,
            document_id=UUID(approved_doc["document_id"]),
            index_receipt={
                "content_checksum": approved_doc["content_checksum"],
                "indexed_chunk_count": 3,
            },
        )
        await session.commit()
        rv_after = (
            await session.execute(
                select(RunbookVersionRecord).where(
                    RunbookVersionRecord.tenant_id == tenant_id,
                    RunbookVersionRecord.runbook_id == rb_uuid,
                    RunbookVersionRecord.version == 1,
                )
            )
        ).scalars().first()
        assert rv_after is not None
        assert rv_after.content.get("index_status") == "indexed"


# ============================================================================
# Scenario B & C: Missing Runbook -> WAITING_FOR_HUMAN -> Human Input -> Grounded RCA -> Reuse
# ============================================================================


@pytest.mark.asyncio
async def test_scenario_b_and_c_missing_runbook_lifecycle_and_second_incident_reuse(
    session_factory,
) -> None:
    tenant_id = "tenant-scenario-bc"
    service = "ledger-sync-worker"
    alert_name = "LedgerSyncDeadlockDetected"
    incident_1_id = uuid4()

    resolution_app_module.settings.database_enabled = True
    resolution_app_module.app.state.session_factory = session_factory
    register_learned_runbooks(
        tenant_id=tenant_id,
        issue=alert_name,
        service=service,
        alert_name=alert_name,
        runbooks=[],
    )

    alert_1 = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name=alert_name,
        description="ledger-sync-worker batch commit deadlock on shard 2",
        service=service,
        environment="prod",
        severity=AlertSeverity.CRITICAL,
    )

    async with session_factory() as session:
        context_1 = await _seed_incident_and_snapshot(
            session,
            tenant_id=tenant_id,
            incident_id=incident_1_id,
            alert=alert_1,
            runbook="",
            document_available=False,
        )

    # 1. First incident has no runbook -> _resolve_context & _persist_resolution_event
    rec_1 = await resolution_app_module._resolve_context(context_1)
    incident_1 = Incident(
        id=incident_1_id,
        tenant_id=tenant_id,
        service=service,
        environment="prod",
        severity=AlertSeverity.CRITICAL,
        title=alert_name,
    )
    await resolution_app_module._persist_resolution_event(
        app=resolution_app_module.app,
        context=context_1,
        incident=incident_1,
        recommendation=rec_1,
        decision_payload={},
    )

    async with session_factory() as session:
        inc_1 = await session.get(IncidentRecord, incident_1_id)
        proj_1 = (
            await session.execute(
                select(IncidentProjectionRecord).where(
                    IncidentProjectionRecord.tenant_id == tenant_id,
                    IncidentProjectionRecord.incident_id == incident_1_id,
                )
            )
        ).scalars().first()
        assert inc_1 is not None
        assert proj_1 is not None
        # Both IncidentRecord and IncidentProjectionRecord transition to waiting_for_human / WAITING_FOR_HUMAN
        assert inc_1.status == "waiting_for_human"
        assert proj_1.status == "waiting_for_human"
        assert proj_1.lifecycle_state == "WAITING_FOR_HUMAN"

        # 2. Verify incident_operations_state preserves WAITING_FOR_HUMAN even if rca_version advances to 2
        enrichment_repo = ContextEnrichmentRepository(session)
        reqs_v1 = await enrichment_repo.list_context_evidence_requirements(
            tenant_id=tenant_id, incident_id=incident_1_id
        )
        runbook_req = next(
            (r for r in reqs_v1 if str(r.get("category")) in {"runbook", "knowledge"}),
            None,
        )
        assert runbook_req is not None

        # Simulate a newer rca_version=2 binding without superseding the runbook requirement
        binding = (
            await session.execute(
                select(IncidentInvestigationBindingRecord).where(
                    IncidentInvestigationBindingRecord.tenant_id == tenant_id,
                    IncidentInvestigationBindingRecord.incident_id == incident_1_id,
                )
            )
        ).scalars().first()
        if binding is not None:
            binding.rca_version = 2
            await session.commit()

        ops_state = await enrichment_repo.incident_operations_state(
            tenant_id=tenant_id, incident_id=incident_1_id
        )
        assert ops_state["lifecycle_state"] == "WAITING_FOR_HUMAN"
        assert ops_state["next_action"]["type"] == "HUMAN_EVIDENCE"

        # 3. Operator supplies missing runbook & root-cause information
        submission = {
            "response": "Shard 2 out-of-order ledger sequence lock; restart ledger-sync-worker.",
            "responder_id": "sre-oncall@kaims.local",
            "responded_at": datetime.now(UTC).isoformat(),
            "observed_symptoms": "ledger-sync-worker shard 2 consumer blocked waiting on row lock.",
            "root_cause": "Concurrent batch replay acquired inverse lock order on ledger_entries shard 2.",
            "business_impact": "Merchant payout reconciliation delayed by 15 minutes.",
            "remediation_steps": "Restart worker deployment:\n1. `kubectl rollout restart deployment/ledger-sync-worker -n prod`\n2. `kubectl rollout status deployment/ledger-sync-worker -n prod --timeout=120s`",
            "validation_steps": "1. `curl -fsS http://ledger-sync-worker.prod.svc/healthz`",
            "rollback_steps": "1. `kubectl rollout undo deployment/ledger-sync-worker -n prod`",
            "create_runbook_draft": True,
        }
        recorded = await enrichment_repo.record_human_evidence_response(
            tenant_id=tenant_id,
            incident_id=incident_1_id,
            requirement_id=UUID(str(runbook_req["requirement_id"])),
            response=submission,
        )
        await session.commit()

        assert recorded["knowledge_draft_id"] is not None
        draft_id = UUID(str(recorded["knowledge_draft_id"]))
        new_snapshot = await session.get(
            ContextSnapshotRecord, UUID(str(recorded["context_snapshot_id"]))
        )
        assert new_snapshot is not None
        resumed_context = Context.model_validate(new_snapshot.payload)

    # 4. Re-run _resolve_context on the human_enriched snapshot -> grounded RCA + commands preserved!
    resumed_rec = await resolution_app_module._resolve_context(resumed_context)
    assert resumed_rec.metadata.get("rca_status") == "grounded"
    assert recorded["evidence_id"] in resumed_rec.metadata["rca_analysis"]["evidence_used"]
    assert resumed_rec.metadata["rca_analysis"].get("missing_evidence") == []
    assert "Concurrent batch replay acquired inverse lock order" in resumed_rec.root_cause
    assert any(
        "kubectl rollout restart deployment/ledger-sync-worker -n prod" in cmd
        for cmd in resumed_rec.commands
    )

    # 5. Approve the generated KnowledgeRagDraftRecord so it becomes a governed learned runbook
    async with session_factory() as session:
        inc_repo = IncidentRepository(session)
        draft_obj = await session.get(KnowledgeRagDraftRecord, draft_id)
        assert draft_obj is not None
        reviewed = await inc_repo.review_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft_id,
            expected_row_version=draft_obj.row_version,
            title=draft_obj.title,
            content=draft_obj.content,
            review_notes="Approved ledger-sync-worker deadlock runbook",
            reviewed_by="sre-lead@kaims.local",
        )
        approved_res = await inc_repo.approve_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft_id,
            expected_row_version=reviewed["row_version"],
            approved_by="release-owner@kaims.local",
        )
        await session.commit()
        assert approved_res is not None

        # Scenario C: Second similar incident arrives with empty runbook
        incident_2_id = uuid4()
        alert_2 = Alert(
            tenant_id=tenant_id,
            source="prometheus",
            name=alert_name,
            description="ledger-sync-worker batch commit deadlock on shard 4",
            service=service,
            environment="prod",
            severity=AlertSeverity.CRITICAL,
        )
        context_2 = await _seed_incident_and_snapshot(
            session,
            tenant_id=tenant_id,
            incident_id=incident_2_id,
            alert=alert_2,
            runbook="",
            document_available=False,
        )

    # 6. Resolve second incident -> automatically matches learned runbook & does NOT ask human for runbook again
    rec_2 = await resolution_app_module._resolve_context(context_2)
    matched_2 = (context_2.metadata or {}).get("matched_learned_runbook")
    assert isinstance(matched_2, dict)
    assert matched_2["service"] == service
    assert context_2.metadata.get("document_available") is True

    incident_2 = Incident(
        id=incident_2_id,
        tenant_id=tenant_id,
        service=service,
        environment="prod",
        severity=AlertSeverity.CRITICAL,
        title=alert_name,
    )
    await resolution_app_module._persist_resolution_event(
        app=resolution_app_module.app,
        context=context_2,
        incident=incident_2,
        recommendation=rec_2,
        decision_payload={},
    )

    async with session_factory() as session:
        enrichment_repo = ContextEnrichmentRepository(session)
        reqs_2 = await enrichment_repo.list_context_evidence_requirements(
            tenant_id=tenant_id, incident_id=incident_2_id
        )
        runbook_reqs_2 = [
            r for r in reqs_2 if str(r.get("category")) in {"runbook", "knowledge"}
        ]
        assert runbook_reqs_2 == []


# ============================================================================
# Scenario D: Incident Closure Paths (Automated Validation & Manual Jira-Safe)
# ============================================================================


@pytest.mark.asyncio
async def test_scenario_d_automated_and_manual_closure_paths(
    session_factory, monkeypatch
) -> None:
    tenant_id = "tenant-scenario-d"
    closure_app_module.settings.database_enabled = True
    closure_app_module.settings.service_internal_token = "test-internal-token-123"
    closure_app_module.app.state.session_factory = session_factory

    # --- Path 1: Automated validation closure via _persist_closure_event ---
    auto_incident_id = uuid4()
    auto_alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="CheckoutServiceHighLatency",
        description="checkout-service p99 latency > 2.5s",
        service="checkout-service",
        environment="prod",
        severity=AlertSeverity.HIGH,
    )
    async with session_factory() as session:
        await _seed_incident_and_snapshot(
            session,
            tenant_id=tenant_id,
            incident_id=auto_incident_id,
            alert=auto_alert,
            runbook="# Checkout Runbook",
            document_available=True,
        )

    auto_action = RemediationAction(
        tenant_id=tenant_id,
        incident_id=auto_incident_id,
        action_type="kubernetes_rollout_restart",
        target="checkout-service",
        status=RemediationStatus.SUCCEEDED,
        completed_at=datetime.now(UTC),
        output="Rollout restart completed",
        parameters={},
    )
    auto_report = ResolutionReport(
        tenant_id=tenant_id,
        incident_id=auto_incident_id,
        remediation_action_id=auto_action.id,
        root_cause="Connection pool saturation on checkout-service",
        closure_kind="validation",
        closure_status="closed",
        impact="Elevated checkout latency",
        action_taken="Restarted checkout-service deployment",
        validation={"technical_recovery_verified": True, "stability_window_passed": True},
        alerts_cleared=True,
        health_restored=True,
        metadata={"closure_kind": "validation", "technical_recovery_verified": True},
    )
    auto_res = await closure_app_module._persist_closure_event(
        app=closure_app_module.app,
        action=auto_action,
        report=auto_report,
        source_payload={"source": "closure-validation"},
        sync_jira=False,
    )
    assert auto_res.get("outbox_enqueued") is True

    async with session_factory() as session:
        inc_auto = await session.get(IncidentRecord, auto_incident_id)
        assert inc_auto is not None
        assert inc_auto.status == "closed"

    # --- Path 2: Administrative Manual Closure when Jira Sync Fails ---
    manual_incident_id = uuid4()
    manual_alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="LegacyReportingStaleAlert",
        description="reporting-job lag alert fired during maintenance window",
        service="reporting-job",
        environment="prod",
        severity=AlertSeverity.WARNING,
    )
    async with session_factory() as session:
        await _seed_incident_and_snapshot(
            session,
            tenant_id=tenant_id,
            incident_id=manual_incident_id,
            alert=manual_alert,
            runbook="",
            document_available=False,
        )

    async def _failing_jira_sync(_incident_payload, _report):
        raise RuntimeError("Jira HTTP 400: Field customfield_10012 is required")

    monkeypatch.setattr(closure_app_module, "_sync_closure_to_jira", _failing_jira_sync)

    req = closure_app_module.ManualClosureRequest(
        comment="Planned reporting maintenance window completed; closing administratively.",
        actor_id="admin@kaims.local",
        actor_role="admin",
        tenant_id=tenant_id,
        auth_jti=f"jti-{uuid4()}",
    )
    manual_resp = await closure_app_module.manual_close_incident(
        incident_id=str(manual_incident_id),
        request=req,
        x_kaiops_internal_token="test-internal-token-123",
    )
    assert manual_resp["status"] == "closed"
    assert manual_resp["closure_kind"] == "manual"
    assert manual_resp["technical_recovery_verified"] is False
    assert manual_resp["jira_sync_status"] == "failed"
    assert "Jira HTTP 400" in str(manual_resp["jira"].get("error") or "")

    async with session_factory() as session:
        inc_manual = await session.get(IncidentRecord, manual_incident_id)
        proj_manual = (
            await session.execute(
                select(IncidentProjectionRecord).where(
                    IncidentProjectionRecord.tenant_id == tenant_id,
                    IncidentProjectionRecord.incident_id == manual_incident_id,
                )
            )
        ).scalars().first()
        rca_manual = (
            await session.execute(
                select(RcaReportRecord).where(
                    RcaReportRecord.tenant_id == tenant_id,
                    RcaReportRecord.incident_id == manual_incident_id,
                )
            )
        ).scalars().first()
        assert inc_manual is not None and inc_manual.status == "closed"
        assert proj_manual is not None and proj_manual.status == "closed"
        assert rca_manual is not None
        assert rca_manual.closure_kind == "manual"
        assert rca_manual.closure_status == "closed"
        assert rca_manual.payload.get("metadata", {}).get("jira_sync_status") == "failed"


# ============================================================================
# Scenario E: Outbox Context Compaction on resolution-events & Polling Guard
# ============================================================================


@pytest.mark.asyncio
async def test_scenario_e_resolution_events_outbox_compaction_and_gap_polling_guard(
    session_factory,
) -> None:
    tenant_id = "tenant-scenario-e"
    incident_id = uuid4()
    parent_snapshot_id = uuid4()

    # 1. Verify resolution-events is in CONTEXT_TOPICS
    assert "resolution-events" in CONTEXT_TOPICS

    large_log_blob = "ERROR connection reset by peer\n" * 3000  # ~93 KB > 64 KB threshold
    alert = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        source="prometheus",
        name="ApiGatewayHighErrorRate",
        description="5xx rate > 10%",
        service="api-gateway",
        environment="prod",
        severity=AlertSeverity.CRITICAL,
    )
    initial_context = Context(
        tenant_id=tenant_id,
        incident_id=incident_id,
        alert=alert,
        metadata={
            "context_snapshot_id": str(parent_snapshot_id),
            "context_fingerprint": "c" * 64,
            "context_subject_fingerprint": "subj-api-gw",
            "correlation_id": f"corr-{incident_id}",
            "rca_version": 1,
            "large_log_dump": [large_log_blob],
        },
    )

    now = datetime.now(UTC)
    async with session_factory() as session:
        session.add(
            ContextSnapshotRecord(
                snapshot_id=parent_snapshot_id,
                tenant_id=tenant_id,
                incident_id=str(incident_id),
                source_incident_id=str(incident_id),
                alert_signature="sig-api-gw",
                subject_fingerprint="subj-api-gw",
                context_fingerprint="c" * 64,
                snapshot_stage="initial",
                snapshot_version=1,
                evidence_ids=[],
                evidence_checksums={},
                contract_version="kaiops.context.v2",
                quality_score=0.8,
                reusable=False,
                source_manifest={},
                payload=initial_context.model_dump(mode="json"),
                collected_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        await session.commit()

        repo = IncidentRepository(session)
        report = {
            "investigation_id": str(uuid4()),
            "status": "conclusive",
            "conclusive": True,
            "evidence": [],
        }
        final_snapshot = await repo.persist_final_investigation_snapshot(
            context=initial_context,
            report=report,
            parent_snapshot_id=parent_snapshot_id,
        )
        bound_ctx = resolution_app_module.bind_context_to_snapshot(
            initial_context, snapshot=final_snapshot
        )
        canonical_bound = bound_ctx.model_dump(mode="json")

        resolution_event_payload = {
            "event_type": "incident.resolution.recommended",
            "tenant_id": tenant_id,
            "incident_id": str(incident_id),
            "context": canonical_bound,
            "recommendation": {"root_cause": "Upstream saturation"},
        }

        compacted = await compact_context(
            session,
            payload=resolution_event_payload,
            tenant_id=tenant_id,
            aggregate_id=str(incident_id),
            topic="resolution-events",
        )
        assert "context" not in compacted
        assert "context_ref" in compacted
        assert compacted["context_ref"]["snapshot_id"] == str(final_snapshot.snapshot_id)
        assert compacted["context_ref"]["context_sha256"] == context_checksum(
            final_snapshot.payload
        )

        outbox_row = ResolutionOutboxRecord(
            event_id=f"res-ev-{uuid4()}",
            tenant_id=tenant_id,
            aggregate_id=str(incident_id),
            topic="resolution-events",
            partition_key=str(incident_id),
            payload=compacted,
        )
        hydrated = await hydrate_context(session, outbox_row)
        assert "context" in hydrated
        assert hydrated["context"] == final_snapshot.payload
        assert hydrated["context"]["metadata"]["large_log_dump"] == [large_log_blob]

    # 2. Verify active_incident_gap_candidates skips waiting_for_human and COLLECTION_BLOCKED incidents
    waiting_inc_id = uuid4()
    blocked_inc_id = uuid4()
    active_no_gaps_inc_id = uuid4()

    async with session_factory() as session:
        for inc_id, inc_status, lifecycle_state in (
            (waiting_inc_id, "waiting_for_human", "WAITING_FOR_HUMAN"),
            (blocked_inc_id, "investigating", "COLLECTION_BLOCKED"),
            (active_no_gaps_inc_id, "investigating", "INVESTIGATING"),
        ):
            session.add(
                IncidentRecord(
                    id=inc_id,
                    tenant_id=tenant_id,
                    title="Test Incident",
                    severity="high",
                    status=inc_status,
                    service="api-gateway",
                    environment="prod",
                    payload={"id": str(inc_id), "status": inc_status},
                )
            )
            session.add(
                IncidentProjectionRecord(
                    incident_id=inc_id,
                    tenant_id=tenant_id,
                    service="api-gateway",
                    environment="prod",
                    severity="high",
                    status=inc_status,
                    lifecycle_state=lifecycle_state,
                    projection_payload={},
                )
            )
            session.add(
                AuditLogRecord(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    actor="resolution-agent",
                    action="rca.analysis.completed",
                    resource_type="incident",
                    resource_id=str(inc_id),
                    payload={"status": "grounded", "missing_evidence": []},
                    created_at=now,
                )
            )
        await session.commit()

        enrichment_repo = ContextEnrichmentRepository(session)
        candidates = await enrichment_repo.active_incident_gap_candidates(tenant_id=tenant_id, limit=25)
        candidate_ids = {str(c.get("incident_id")) for c in candidates}
        assert str(waiting_inc_id) not in candidate_ids
        assert str(blocked_inc_id) not in candidate_ids
        assert str(active_no_gaps_inc_id) not in candidate_ids
