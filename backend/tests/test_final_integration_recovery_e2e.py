from __future__ import annotations

from datetime import UTC, datetime, timedelta
import importlib.util
from pathlib import Path
import sys
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

ROOT = Path(__file__).resolve().parents[2]
for rel in (
    "backend/src/common",
    "backend/src/context-agent",
    "ai-workbench/src/ai_workbench_common",
    "ai-workbench/src/resolution-agent",
):
    candidate = str(ROOT / rel)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from ai_workbench_common.models import Context
from common.context_enrichment_contract import build_evidence_requirements
from common.database import (
    ApprovalRecord,
    CanonicalEvidenceRecord,
    ContextEvidenceRequirementRecord,
    ContextSnapshotRecord,
    GovernedRagDocumentRecord,
    HumanEvidenceRequestRecord,
    IncidentInvestigationBindingRecord,
    IncidentProjectionRecord,
    IncidentRecord,
    KnowledgeRagDraftRecord,
    ResolutionOutboxRecord,
    RunbookApprovalRecord,
    RunbookRecord,
    RunbookVersionRecord,
)
from common.incident_lifecycle import IncidentLifecycleState
from common.models import (
    Alert,
    AlertSeverity,
    Approval,
    ApprovalDecision,
    Incident,
    IncidentStatus,
    RemediationAction,
    RemediationStatus,
    ResolutionReport,
)
from common.repository import ContextEnrichmentRepository, IncidentRepository
from context_agent.connectors import VectorDBConnector
from resolution_agent.graph import ResolutionIntelligenceAgent as ResolutionAgent

_resolution_app_path = ROOT / "ai-workbench/src/resolution-agent/app.py"
_resolution_app_spec = importlib.util.spec_from_file_location("resolution_agent_app_final_e2e", _resolution_app_path)
assert _resolution_app_spec is not None and _resolution_app_spec.loader is not None
resolution_app = importlib.util.module_from_spec(_resolution_app_spec)
sys.modules["resolution_agent_app_final_e2e"] = resolution_app
_resolution_app_spec.loader.exec_module(resolution_app)


class _OfflineModelGateway:
    async def generate(self, request):
        raise RuntimeError("offline unit test - use deterministic fallback")


async def _noop_async(*_args, **_kwargs):
    return None


resolution_app.agent.model_gateway = _OfflineModelGateway()
resolution_app.agent.runtime.max_attempts = 1
resolution_app.agent._judge_groundedness = _noop_async
resolution_app.agent._publish_evaluation = lambda **_kwargs: None
resolution_app._ensure_global_knowledge_loaded = _noop_async


def _make_alert(*, suffix: str = "1") -> Alert:
    now = datetime.now(UTC)
    return Alert(
        id=uuid4(),
        tenant_id="default",
        source="prometheus",
        name="PaymentWorkerQueueStall",
        severity=AlertSeverity.CRITICAL,
        service="payments-worker",
        environment="prod",
        description="payments-worker consumer lag exceeded threshold and healthcheck /healthz is failing with HTTP 503",
        labels={
            "alertname": "PaymentWorkerQueueStall",
            "service": "payments-worker",
            "namespace": "prod",
            "severity": "critical",
            "owner": "sre-payments-oncall@example.com",
            "source_event_id": f"evt-payments-{suffix}",
        },
        starts_at=now - timedelta(minutes=5),
        created_at=now - timedelta(minutes=5),
        metadata={
            "authorized_connectors": ["prometheus", "loki", "kubernetes"],
            "owner": "sre-payments-oncall@example.com",
        },
    )


@pytest.mark.asyncio
async def test_12_step_happy_path_missing_runbook_to_reuse_and_closure(sqlite_session_factory, tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    now = datetime.now(UTC)
    incident_1_uuid = uuid4()
    incident_1_id = str(incident_1_uuid)
    alert_1 = _make_alert(suffix="1")
    snapshot_1_uuid = uuid4()
    connector = VectorDBConnector(rag_root=tmp_path)

    # Step 1 & Step 2: Ingest alert for service with no matching runbook; persist incident & initial context snapshot
    initial_context_payload = {
        "incident_id": incident_1_id,
        "tenant_id": "default",
        "alert": alert_1.model_dump(mode="json"),
        "runbook": "",
        "metadata": {
            "alert_id": str(alert_1.id),
            "project_id": "payments-prod",
            "context_snapshot_id": str(snapshot_1_uuid),
            "snapshot_stage": "initial",
            "snapshot_version": 1,
            "document_available": False,
            "rag_status": "empty",
            "rag_matches": [],
            "owner": "sre-payments-oncall@example.com",
            "authorized_connectors": ["prometheus", "loki", "kubernetes"],
            "context_evidence": {
                "telemetry": [
                    {
                        "evidence_id": "ev-prom-lag-1",
                        "category": "telemetry",
                        "source": "prometheus",
                        "connector": "prometheus",
                        "service": "payments-worker",
                        "summary": "payments-worker consumer_lag=14820 and http_5xx_rate=0.42",
                        "snippet": "payments-worker consumer_lag=14820 and http_5xx_rate=0.42",
                        "observed_at": now.isoformat(),
                        "freshness": "fresh",
                        "reliability_score": 0.92,
                        "diagnostic_signals": ["metric_anomaly"],
                        "content": {"consumer_lag": 14820, "http_5xx_rate": 0.42},
                    }
                ],
                "logs": [
                    {
                        "evidence_id": "ev-loki-log-1",
                        "category": "logs",
                        "source": "loki",
                        "connector": "loki",
                        "service": "payments-worker",
                        "summary": "ERROR payments-worker deadlock on worker pool thread-9; /healthz returning 503",
                        "snippet": "ERROR payments-worker deadlock on worker pool thread-9; /healthz returning 503",
                        "observed_at": now.isoformat(),
                        "freshness": "fresh",
                        "reliability_score": 0.90,
                        "diagnostic_signals": ["error_code", "stack_trace"],
                        "content": {"message": "ERROR payments-worker deadlock on worker pool thread-9; /healthz returning 503"},
                    }
                ],
            },
            "context_quality": {
                "rca_ready": False,
                "rca_readiness_score": 0.45,
                "discovery_degraded": True,
                "coverage_score": 0.5,
            },
        },
    }

    async with sqlite_session_factory() as session:
        inc_repo = IncidentRepository(session)
        session.add(
            CanonicalEvidenceRecord(
                evidence_id="ev-prom-lag-1",
                requirement_id=uuid4(),
                tenant_id="default",
                incident_id=incident_1_uuid,
                category="telemetry",
                source_id="prom:lag:1",
                connector="prometheus",
                source_reference="prometheus://payments-worker/lag",
                service="payments-worker",
                resource="payments-worker",
                project_id="payments-prod",
                observed_at=now,
                collected_at=now,
                freshness="fresh",
                content={"consumer_lag": 14820, "http_5xx_rate": 0.42},
                provenance={"collector": "prometheus"},
                current_observation=True,
                content_digest="a" * 64,
            )
        )
        session.add(
            CanonicalEvidenceRecord(
                evidence_id="ev-loki-log-1",
                requirement_id=uuid4(),
                tenant_id="default",
                incident_id=incident_1_uuid,
                category="logs",
                source_id="loki:log:1",
                connector="loki",
                source_reference="loki://payments-worker/error",
                service="payments-worker",
                resource="payments-worker",
                project_id="payments-prod",
                observed_at=now,
                collected_at=now,
                freshness="fresh",
                content={"message": "ERROR payments-worker deadlock on worker pool thread-9; /healthz returning 503"},
                provenance={"collector": "loki"},
                current_observation=True,
                content_digest="b" * 64,
            )
        )
        await inc_repo.save_incident(
            Incident(
                id=incident_1_uuid,
                tenant_id="default",
                title="PaymentWorkerQueueStall on payments-worker",
                summary=alert_1.description,
                severity=AlertSeverity.CRITICAL,
                status=IncidentStatus.INVESTIGATING,
                service="payments-worker",
                environment="prod",
                alert_ids=[alert_1.id],
                metadata={"owner": "sre-payments-oncall@example.com"},
            )
        )
        session.add(
            IncidentProjectionRecord(
                incident_id=incident_1_uuid,
                alert_id=alert_1.id,
                tenant_id="default",
                service="payments-worker",
                environment="prod",
                severity="critical",
                status="investigating",
                lifecycle_state="INVESTIGATING",
                lifecycle_version=1,
                owner="sre-payments-oncall@example.com",
                projection_payload={"status": "investigating", "title": "PaymentWorkerQueueStall on payments-worker"},
            )
        )
        session.add(
            ContextSnapshotRecord(
                snapshot_id=snapshot_1_uuid,
                tenant_id="default",
                incident_id=incident_1_id,
                source_incident_id=incident_1_id,
                alert_signature="sig-payment-worker-stall",
                subject_fingerprint="fp-payment-worker",
                context_fingerprint="ctx-fp-v1",
                snapshot_stage="initial",
                snapshot_version=1,
                evidence_ids=["ev-prom-lag-1", "ev-loki-log-1"],
                evidence_checksums={"ev-prom-lag-1": "chk1", "ev-loki-log-1": "chk2"},
                contract_version="1.0",
                quality_score=0.5,
                reusable=False,
                source_manifest={"telemetry": {"connector": "prometheus"}, "logs": {"connector": "loki"}},
                payload=initial_context_payload,
                collected_at=now,
                expires_at=now + timedelta(hours=2),
            )
        )
        await session.commit()

        # Step 3: Verify existing runbook search returns no approved match
        initial_rag_matches = connector.search(
            "PaymentWorkerQueueStall payments-worker deadlock",
            tenant_id="default",
            service="payments-worker",
            preferred_kind="runbook",
        )
        assert initial_rag_matches == []

    # Step 4 & Step 5: Run real resolution pipeline (_resolve_context, _apply_catalog_plan, _persist_resolution_event)
    # on initial context (where investigation is inconclusive because no runbook exists yet)
    monkeypatch.setattr(resolution_app.settings, "database_enabled", True)
    monkeypatch.setattr(resolution_app.app.state, "session_factory", sqlite_session_factory, raising=False)
    from common.config import get_settings
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setattr(get_settings(), "outbox_snapshot_references_enabled", False)

    agent = resolution_app.agent
    context_v1 = Context.model_validate(initial_context_payload)
    rec_v1 = await agent.resolve(context_v1)
    rec_v1.metadata["rca_status"] = "insufficient_evidence"
    rec_v1.metadata["iterative_investigation"] = {
        "investigation_id": str(uuid4()),
        "status": "inconclusive",
        "conclusive": False,
        "missing_sources": ["runbook"],
        "conclusion": {
            "hypothesis_id": "hyp-1",
            "confidence": 0.42,
            "conclusive_threshold": 0.65,
            "independent_source_count": 1,
            "minimum_independent_sources": 2,
            "evidence_ids": ["ev-prom-lag-1"],
        },
        "hypotheses": [
            {
                "hypothesis_id": "hyp-1",
                "claim": "Possible worker pool thread deadlock in payments-worker",
                "confidence": 0.42,
                "supporting_evidence_ids": ["ev-prom-lag-1"],
            }
        ],
    }
    plan_v1 = resolution_app._apply_catalog_plan(rec_v1, context_v1, {})
    assert plan_v1["execution_ready"] is False

    inc_v1 = Incident(
        id=incident_1_uuid,
        tenant_id="default",
        title="PaymentWorkerQueueStall on payments-worker",
        summary=alert_1.description,
        severity=AlertSeverity.CRITICAL,
        status=IncidentStatus.INVESTIGATING,
        service="payments-worker",
        environment="prod",
        alert_ids=[alert_1.id],
        metadata={"owner": "sre-payments-oncall@example.com"},
    )
    await resolution_app._persist_resolution_event(
        app=resolution_app.app,
        context=context_v1,
        incident=inc_v1,
        recommendation=rec_v1,
        decision_payload={},
    )

    # Verify Step 5: Human evidence request for missing runbook was created and assigned to sre-payments-oncall@example.com
    async with sqlite_session_factory() as session:
        enrichment_repo = ContextEnrichmentRepository(session)
        human_queue = await enrichment_repo.list_human_evidence_request_queue(tenant_id="default")
        assert len(human_queue) >= 1
        runbook_req = next(
            (r for r in human_queue if r.get("incident_id") == incident_1_id and r.get("category") == "runbook"),
            human_queue[0],
        )
        assert runbook_req["status"] == "pending"
        assert runbook_req["expected_responder"] == "sre-payments-oncall@example.com"
        requirement_id = UUID(str(runbook_req["requirement_id"]))

        # Step 6: Submit human response with root cause, business impact, and executable remediation/validation/rollback
        human_response_result = await enrichment_repo.record_human_evidence_response(
            tenant_id="default",
            incident_id=incident_1_uuid,
            requirement_id=requirement_id,
            response={
                "responder_id": "sre-payments-oncall@example.com",
                "responder_role": "sre-approver",
                "responded_at": datetime.now(UTC).isoformat(),
                "response": "Confirmed worker thread pool deadlock in payments-worker when AMQP prefetch exceeds 250.",
                "observed_symptoms": "payments-worker consumer lag spikes above 10,000 and /healthz returns HTTP 503.",
                "root_cause": "Confirmed worker thread pool deadlock in payments-worker under burst AMQP prefetch.",
                "business_impact": "Delayed asynchronous settlement processing for merchant payouts.",
                "remediation_steps": (
                    "- kubectl rollout restart deployment/payments-worker -n prod\n"
                    "- kubectl rollout status deployment/payments-worker -n prod --timeout=120s"
                ),
                "create_runbook_draft": True,
            },
        )
        await session.commit()

        # Step 7: Verify automatic continuation snapshot & outbox event & runbook draft creation
        assert human_response_result["status"] == "answered"
        assert human_response_result["context_snapshot_id"] is not None
        assert human_response_result["knowledge_draft_id"] is not None
        draft_id = str(human_response_result["knowledge_draft_id"])
        snapshot_v2_id = UUID(str(human_response_result["context_snapshot_id"]))

        snap_v2 = await session.get(ContextSnapshotRecord, snapshot_v2_id)
        assert snap_v2 is not None
        assert snap_v2.snapshot_stage == "human_enriched"
        assert snap_v2.snapshot_version == 2
        assert "iterative_investigation" not in (snap_v2.payload.get("metadata") or {})
        assert snap_v2.payload["metadata"]["document_available"] is True
        assert snap_v2.payload["metadata"]["human_guided_input"]["knowledge_draft_id"] == draft_id
        assert snap_v2.payload["metadata"]["context_quality"]["rca_ready"] is True

        outbox_row = await session.get(
            ResolutionOutboxRecord,
            f"context-human-enriched:{incident_1_uuid}:{snapshot_v2_id}",
        )
        assert outbox_row is not None
        assert outbox_row.topic == "context-events"

        draft_row = await session.get(KnowledgeRagDraftRecord, UUID(draft_id))
        assert draft_row is not None
        assert draft_row.metadata_payload["incident_id"] == incident_1_id
        assert draft_row.metadata_payload["service"] == "payments-worker"

        context_v2_payload = dict(snap_v2.payload)

    # Step 8: Resume automated resolution pipeline using the human-enriched snapshot v2 (NO fake overrides!)
    context_v2 = Context.model_validate(context_v2_payload)
    context_v2 = await resolution_app._bind_next_rca_version(context_v2)
    context_v2, report_v2 = await resolution_app.investigate_context(context_v2)
    rec_v2 = await resolution_app._resolve_context(context_v2)
    assert rec_v2.metadata["rca_status"] == "grounded"
    assert rec_v2.metadata["iterative_investigation"]["conclusive"] is True
    assert rec_v2.metadata["rca_analysis"]["missing_evidence"] == []
    assert len(rec_v2.metadata["rca_analysis"]["evidence_used"]) >= 1

    plan_v2 = resolution_app._apply_catalog_plan(rec_v2, context_v2, {"human_evidence": True})
    assert plan_v2["execution_ready"] is True
    assert plan_v2["mutating"] is True
    assert rec_v2.metadata["quality_gate"]["passed"] is True
    assert rec_v2.metadata["runbook_draft_id"] == draft_id

    context_v2 = await resolution_app._commit_investigation_recommendation(
        context_v2,
        report_v2,
        snapshot_v2_id,
        rec_v2,
        {"human_evidence": True},
    )

    inc_v2 = Incident(
        id=incident_1_uuid,
        tenant_id="default",
        title="PaymentWorkerQueueStall on payments-worker",
        summary=alert_1.description,
        severity=AlertSeverity.CRITICAL,
        status=IncidentStatus.INVESTIGATING,
        service="payments-worker",
        environment="prod",
        alert_ids=[alert_1.id],
        metadata={"owner": "sre-payments-oncall@example.com"},
    )
    await resolution_app._persist_resolution_event(
        app=resolution_app.app,
        context=context_v2,
        incident=inc_v2,
        recommendation=rec_v2,
        decision_payload={"human_evidence": True},
    )

    async with sqlite_session_factory() as session:
        enrichment_repo = ContextEnrichmentRepository(session)
        inc_repo = IncidentRepository(session)

        ops_v2 = await enrichment_repo.incident_operations_state(tenant_id="default", incident_id=incident_1_uuid)
        assert ops_v2["investigation_workspace"]["rca"]["grounded"] is True
        assert ops_v2["investigation_workspace"]["rca"]["status"] == "grounded"
        assert ops_v2["investigation_workspace"]["resolution"]["status"] == "ready"
        assert ops_v2["investigation_workspace"]["resolution"]["blocking_reasons"] == []

        # Step 9: Review & approve the runbook draft and verify governed indexing and RAG retrieval
        draft_obj = await session.get(KnowledgeRagDraftRecord, UUID(draft_id))
        reviewed = await inc_repo.review_knowledge_rag_draft(
            tenant_id="default",
            draft_id=draft_obj.draft_id,
            expected_row_version=draft_obj.row_version,
            title=draft_obj.title,
            content=draft_obj.content,
            review_notes="Verified remediation steps for payments-worker deadlock.",
            reviewed_by="sre-lead@example.com",
        )
        approved_res = await inc_repo.approve_knowledge_rag_draft(
            tenant_id="default",
            draft_id=draft_obj.draft_id,
            expected_row_version=reviewed["row_version"],
            approved_by="sre-lead@example.com",
        )
        await session.commit()
        assert approved_res is not None
        approved_draft, approved_payload = approved_res
        assert approved_draft["status"] == "approved_pending_index"

        gov_doc = await session.get(GovernedRagDocumentRecord, UUID(str(approved_payload["document_id"])))
        assert gov_doc is not None
        indexed = await connector.index_governed_document(gov_doc)
        assert indexed["indexed"] == 1

        rag_hits = connector.search(
            "PaymentWorkerQueueStall payments-worker deadlock",
            tenant_id="default",
            service="payments-worker",
            preferred_kind="runbook",
        )
        assert len(rag_hits) >= 1
        assert "kubectl rollout restart deployment/payments-worker -n prod" in rag_hits[0]["content"]

        # Verify RunbookRecord, RunbookVersionRecord, RunbookApprovalRecord were populated by approve_knowledge_rag_draft
        rb_approvals = (await session.scalars(select(RunbookApprovalRecord))).all()
        assert len(rb_approvals) >= 1
        approved_rb_id = str(rb_approvals[0].runbook_id)

    # Step 10: Process a second similar incident and verify approved runbook is retrieved and reused
    # without creating a duplicate human request or duplicate runbook draft
    incident_2_uuid = uuid4()
    incident_2_id = str(incident_2_uuid)
    alert_2 = _make_alert(suffix="2")
    snapshot_2_uuid = uuid4()

    second_context_payload = {
        "incident_id": incident_2_id,
        "tenant_id": "default",
        "alert": alert_2.model_dump(mode="json"),
        "runbook": rag_hits[0]["content"],
        "metadata": {
            "alert_id": str(alert_2.id),
            "analysis_request_id": str(uuid4()),
            "project_id": "payments-prod",
            "context_snapshot_id": str(snapshot_2_uuid),
            "snapshot_stage": "initial",
            "snapshot_version": 1,
            "document_available": True,
            "rag_status": "matched",
            "rag_matches": [
                {
                    **rag_hits[0],
                    "path": f"governed://default/{approved_rb_id}/v1",
                    "runbook_id": approved_rb_id,
                    "version": 1,
                    "approval_status": "approved",
                    "approved_by": "sre-lead@example.com",
                    "service": "payments-worker",
                    "alert_name": "PaymentWorkerQueueStall",
                    "remediation_steps": [
                        "kubectl rollout restart deployment/payments-worker -n prod",
                        "kubectl rollout status deployment/payments-worker -n prod --timeout=120s",
                    ],
                    "validation_steps": ["kubectl rollout status deployment/payments-worker -n prod --timeout=120s"],
                    "rollback_steps": ["kubectl rollout undo deployment/payments-worker -n prod"],
                }
            ],
            "owner": "sre-payments-oncall@example.com",
            "authorized_connectors": ["prometheus", "loki", "kubernetes"],
            "context_evidence": {
                "telemetry": [
                    {
                        "evidence_id": "ev-prom-lag-2",
                        "category": "telemetry",
                        "source": "prometheus",
                        "connector": "prometheus",
                        "service": "payments-worker",
                        "summary": "payments-worker consumer_lag=15200 and http_5xx_rate=0.45",
                        "snippet": "payments-worker consumer_lag=15200 and http_5xx_rate=0.45",
                        "observed_at": now.isoformat(),
                        "freshness": "fresh",
                        "reliability_score": 0.92,
                        "diagnostic_signals": ["metric_anomaly"],
                        "content": {"consumer_lag": 15200, "http_5xx_rate": 0.45},
                    }
                ],
                "logs": [
                    {
                        "evidence_id": "ev-loki-log-2",
                        "category": "logs",
                        "source": "loki",
                        "connector": "loki",
                        "service": "payments-worker",
                        "summary": "ERROR payments-worker deadlock on worker pool thread-4; /healthz returning 503",
                        "snippet": "ERROR payments-worker deadlock on worker pool thread-4; /healthz returning 503",
                        "observed_at": now.isoformat(),
                        "freshness": "fresh",
                        "reliability_score": 0.90,
                        "diagnostic_signals": ["error_code", "stack_trace"],
                        "content": {"message": "ERROR payments-worker deadlock on worker pool thread-4; /healthz returning 503"},
                    }
                ],
            },
            "context_quality": {
                "rca_ready": True,
                "rca_readiness_score": 0.88,
                "discovery_degraded": False,
                "coverage_score": 0.88,
            },
        },
    }
    async with sqlite_session_factory() as session:
        inc_repo = IncidentRepository(session)
        session.add(
            CanonicalEvidenceRecord(
                evidence_id="ev-prom-lag-2",
                requirement_id=uuid4(),
                tenant_id="default",
                incident_id=incident_2_uuid,
                category="telemetry",
                source_id="prom:lag:2",
                connector="prometheus",
                source_reference="prometheus://payments-worker/lag2",
                service="payments-worker",
                resource="payments-worker",
                project_id="payments-prod",
                observed_at=now,
                collected_at=now,
                freshness="fresh",
                content={"consumer_lag": 15200, "http_5xx_rate": 0.45},
                provenance={"collector": "prometheus"},
                current_observation=True,
                content_digest="c" * 64,
            )
        )
        session.add(
            CanonicalEvidenceRecord(
                evidence_id="ev-loki-log-2",
                requirement_id=uuid4(),
                tenant_id="default",
                incident_id=incident_2_uuid,
                category="logs",
                source_id="loki:log:2",
                connector="loki",
                source_reference="loki://payments-worker/error2",
                service="payments-worker",
                resource="payments-worker",
                project_id="payments-prod",
                observed_at=now,
                collected_at=now,
                freshness="fresh",
                content={"message": "ERROR payments-worker deadlock on worker pool thread-4; /healthz returning 503"},
                provenance={"collector": "loki"},
                current_observation=True,
                content_digest="d" * 64,
            )
        )
        await inc_repo.save_incident(
            Incident(
                id=incident_2_uuid,
                tenant_id="default",
                title="PaymentWorkerQueueStall on payments-worker",
                summary=alert_2.description,
                severity=AlertSeverity.CRITICAL,
                status=IncidentStatus.INVESTIGATING,
                service="payments-worker",
                environment="prod",
                alert_ids=[alert_2.id],
                metadata={"owner": "sre-payments-oncall@example.com"},
            )
        )
        session.add(
            IncidentProjectionRecord(
                incident_id=incident_2_uuid,
                alert_id=alert_2.id,
                tenant_id="default",
                service="payments-worker",
                environment="prod",
                severity="critical",
                status="investigating",
                lifecycle_state="INVESTIGATING",
                lifecycle_version=1,
                owner="sre-payments-oncall@example.com",
                projection_payload={"status": "investigating", "title": "PaymentWorkerQueueStall on payments-worker"},
            )
        )
        session.add(
            ContextSnapshotRecord(
                snapshot_id=snapshot_2_uuid,
                tenant_id="default",
                incident_id=incident_2_id,
                source_incident_id=incident_2_id,
                alert_signature="sig-payment-worker-stall",
                subject_fingerprint="fp-payment-worker",
                context_fingerprint="ctx-fp-inc2-v1",
                snapshot_stage="initial",
                snapshot_version=1,
                evidence_ids=["ev-prom-lag-2", "ev-loki-log-2"],
                evidence_checksums={"ev-prom-lag-2": "chk21", "ev-loki-log-2": "chk22"},
                contract_version="1.0",
                quality_score=0.88,
                reusable=False,
                source_manifest={"telemetry": {"connector": "prometheus"}, "logs": {"connector": "loki"}},
                payload=second_context_payload,
                collected_at=now,
                expires_at=now + timedelta(hours=2),
            )
        )
        await session.commit()

    context_inc2 = Context.model_validate(second_context_payload)
    context_inc2 = await resolution_app._bind_next_rca_version(context_inc2)
    context_inc2, report_inc2 = await resolution_app.investigate_context(context_inc2)
    resolved_learned = context_inc2.metadata.get("matched_learned_runbook")
    assert resolved_learned is not None
    assert str(resolved_learned["runbook_id"]) == approved_rb_id

    rec_inc2 = await resolution_app._resolve_context(context_inc2)
    assert any("kubectl rollout restart deployment/payments-worker -n prod" in cmd for cmd in rec_inc2.commands)
    plan_inc2 = resolution_app._apply_catalog_plan(rec_inc2, context_inc2, {})
    assert str(plan_inc2["runbook_governance_id"]) == approved_rb_id

    context_inc2 = await resolution_app._commit_investigation_recommendation(
        context_inc2,
        report_inc2,
        snapshot_2_uuid,
        rec_inc2,
        {},
    )

    inc_2_model = Incident(
        id=incident_2_uuid,
        tenant_id="default",
        title="PaymentWorkerQueueStall on payments-worker",
        summary=alert_2.description,
        severity=AlertSeverity.CRITICAL,
        status=IncidentStatus.INVESTIGATING,
        service="payments-worker",
        environment="prod",
        alert_ids=[alert_2.id],
        metadata={"owner": "sre-payments-oncall@example.com"},
    )
    await resolution_app._persist_resolution_event(
        app=resolution_app.app,
        context=context_inc2,
        incident=inc_2_model,
        recommendation=rec_inc2,
        decision_payload={},
    )

    async with sqlite_session_factory() as session:
        enrichment_repo = ContextEnrichmentRepository(session)
        inc2_human_reqs = (
            await session.scalars(
                select(HumanEvidenceRequestRecord).where(
                    HumanEvidenceRequestRecord.incident_id == incident_2_uuid
                )
            )
        ).all()
        assert inc2_human_reqs == [], "Second incident must reuse learned runbook without requesting human input"

        all_drafts = (await session.scalars(select(KnowledgeRagDraftRecord))).all()
        assert len(all_drafts) == 1, "Second incident must not create a duplicate runbook draft"

        # Step 11 & Step 12: Execute governed approval, remediation action, and verified recovery closure on Incident 1
        inc_repo = IncidentRepository(session)
        binding_v2 = await session.scalar(
            select(IncidentInvestigationBindingRecord)
            .where(IncidentInvestigationBindingRecord.incident_id == incident_1_uuid)
            .order_by(IncidentInvestigationBindingRecord.rca_version.desc())
            .limit(1)
        )
        assert binding_v2 is not None

        approval = Approval(
            id=uuid4(),
            tenant_id="default",
            incident_id=incident_1_uuid,
            recommendation_id=binding_v2.recommendation_id,
            plan_id=binding_v2.resolution_plan_id,
            plan_fingerprint=binding_v2.plan_fingerprint,
            approver="sre-lead@example.com",
            decision=ApprovalDecision.APPROVED,
            comment="Approved governed remediation plan.",
        )
        await inc_repo.save_approval(approval)
        await inc_repo.update_incident_approval_status(
            incident_1_uuid,
            status=IncidentStatus.APPROVED.value,
            approval=approval,
        )
        proj_approved = await session.get(IncidentProjectionRecord, incident_1_uuid)
        assert proj_approved.status == "approved"
        assert proj_approved.lifecycle_state == "APPROVED"

        action = RemediationAction(
            id=uuid4(),
            tenant_id="default",
            incident_id=incident_1_uuid,
            recommendation_id=binding_v2.recommendation_id,
            resolution_plan_id=binding_v2.resolution_plan_id,
            plan_fingerprint=binding_v2.plan_fingerprint,
            approval_id=approval.id,
            action_type="kubernetes.rollout_restart",
            target="deployment/payments-worker",
            status=RemediationStatus.SUCCEEDED,
            output="deployment.apps/payments-worker restarted",
        )
        await inc_repo.save_action(action)
        proj_validating = await session.get(IncidentProjectionRecord, incident_1_uuid)
        assert proj_validating.status == "validating"
        assert proj_validating.lifecycle_state == "VALIDATING"

        obs_start = (now - timedelta(minutes=2)).isoformat()
        obs_end = now.isoformat()
        report = ResolutionReport(
            id=uuid4(),
            tenant_id="default",
            incident_id=incident_1_uuid,
            recommendation_id=binding_v2.recommendation_id,
            resolution_plan_id=binding_v2.resolution_plan_id,
            plan_fingerprint=binding_v2.plan_fingerprint,
            approval_id=approval.id,
            remediation_action_id=action.id,
            root_cause=rec_v2.root_cause,
            impact=rec_v2.impact,
            action_taken=action.action_type,
            validation={"rollout_healthy": True, "error_rate_normal": True},
            health_restored=True,
            alerts_cleared=True,
            closure_kind="remediation_verified",
            closure_status="closed",
            metadata={
                "independent_validation_observations": [
                    {
                        "validator_id": "prom-recovery-validator",
                        "connector_id": "prometheus",
                        "target_resource_id": "deployment/payments-worker",
                        "phase": "post_state",
                        "observation_window_start": obs_start,
                        "observation_window_end": obs_end,
                        "observed_at": obs_end,
                        "result_checksum": "sha256:" + ("e" * 64),
                        "passed": True,
                    }
                ],
            },
        )
        await inc_repo.save_report(report)
        inc_closed = inc_v2.model_copy(update={"status": IncidentStatus.CLOSED, "closed_at": now})
        await inc_repo.save_incident(inc_closed)
        await session.commit()

        inc_final = await session.get(IncidentRecord, incident_1_uuid)
        proj_final = await session.get(IncidentProjectionRecord, incident_1_uuid)
        ops_final = await enrichment_repo.incident_operations_state(tenant_id="default", incident_id=incident_1_uuid)
        assert inc_final.status == "closed"
        assert proj_final.status == "closed"
        assert proj_final.lifecycle_state == "CLOSED"
        assert ops_final["lifecycle_state"] == "CLOSED"


@pytest.mark.asyncio
async def test_8_failure_paths(sqlite_session_factory, monkeypatch):
    from common.config import get_settings
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setattr(get_settings(), "outbox_snapshot_references_enabled", False)

    now = datetime.now(UTC)
    inc_uuid = uuid4()
    inc_id = str(inc_uuid)
    alert_uuid = uuid4()

    async with sqlite_session_factory() as session:
        inc_repo = IncidentRepository(session)
        enrichment_repo = ContextEnrichmentRepository(session)

        # Seed an incident for failure path testing
        await inc_repo.save_incident(
            Incident(
                id=inc_uuid,
                tenant_id="default",
                title="Failure path test incident",
                summary="Testing failure paths",
                severity=AlertSeverity.HIGH,
                status=IncidentStatus.INVESTIGATING,
                service="payments-worker",
                environment="prod",
            )
        )
        session.add(
            IncidentProjectionRecord(
                incident_id=inc_uuid,
                alert_id=alert_uuid,
                tenant_id="default",
                service="payments-worker",
                environment="prod",
                severity="high",
                status="investigating",
                lifecycle_state="INVESTIGATING",
                lifecycle_version=1,
                projection_payload={"status": "investigating", "title": "Failure path test incident"},
            )
        )
        snap_uuid = uuid4()
        session.add(
            ContextSnapshotRecord(
                snapshot_id=snap_uuid,
                tenant_id="default",
                incident_id=inc_id,
                source_incident_id=inc_id,
                alert_signature="sig-fail",
                subject_fingerprint="fp-fail",
                context_fingerprint="ctx-fail-1",
                snapshot_stage="initial",
                snapshot_version=1,
                evidence_ids=[],
                evidence_checksums={},
                contract_version="1.0",
                quality_score=0.4,
                reusable=False,
                source_manifest={},
                payload={"incident_id": inc_id, "tenant_id": "default", "alert": {"name": "FailAlert", "service": "payments-worker"}},
                collected_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        await session.commit()

        # 1. Unsupported evidence category -> empty candidate_connectors & blocked on automatic fallback
        reqs = build_evidence_requirements(
            tenant_id="default",
            incident_id=inc_uuid,
            rca_version=1,
            missing_evidence=[{"category": "quantum_flux_capacitor", "question": "Collect quantum flux state"}],
            now=now,
        )
        assert len(reqs) == 1
        assert reqs[0].collection_mode == "connector_required"
        assert reqs[0].candidate_connectors == []
        unsupported_saved = await enrichment_repo.upsert_context_evidence_requirements(reqs)
        fallback_res = await enrichment_repo.create_human_evidence_request(
            automatic_fallback=True,
            tenant_id="default",
            incident_id=inc_uuid,
            requirement_id=unsupported_saved[0].requirement_id,
            expected_responder="sre-oncall@example.com",
            due_at=now + timedelta(hours=1),
            acceptable_format="text",
            evidence_already_checked=[],
            hypothesis_impact="Unsupported category fallback",
        )
        assert fallback_res is None
        unsupported_row = await session.get(ContextEvidenceRequirementRecord, unsupported_saved[0].requirement_id)
        assert unsupported_row.status == "blocked"

        # 2. Connector failure / retry exhaustion -> dead_letter and blocked
        tech_reqs = build_evidence_requirements(
            tenant_id="default",
            incident_id=inc_uuid,
            rca_version=1,
            missing_evidence=[{"category": "logs", "question": "Collect application error logs"}],
            now=now,
        )
        saved_tech = await enrichment_repo.upsert_context_evidence_requirements(tech_reqs)
        job = await enrichment_repo.schedule_context_enrichment_job(
            tenant_id="default",
            incident_id=inc_uuid,
            requirement_id=saved_tech[0].requirement_id,
            connector_id="loki",
            query_payload={"service": "payments-worker"},
            observation_start=now - timedelta(minutes=15),
            observation_end=now,
        )
        for attempt in range(1, 5):
            job.available_at = datetime.now(UTC) - timedelta(seconds=5)
            await session.flush()
            claimed = await enrichment_repo.claim_context_enrichment_jobs(
                worker_id="worker-1",
                limit=5,
                lease_seconds=60,
            )
            assert len(claimed) == 1
            status = await enrichment_repo.finish_context_enrichment_job(
                job_id=job.job_id,
                worker_id="worker-1",
                collected=False,
                error="Loki connection timeout",
                retry_after_seconds=1,
                maximum_attempts=4,
            )
            if attempt < 4:
                assert status == "retry"
            else:
                assert status == "dead_letter"
        req_after = await session.get(ContextEvidenceRequirementRecord, saved_tech[0].requirement_id)
        assert req_after.status == "blocked"

        # 3. Unresolved responder & placeholder responder rejection
        human_only_reqs = build_evidence_requirements(
            tenant_id="default",
            incident_id=inc_uuid,
            rca_version=1,
            missing_evidence=[{"category": "business_impact", "question": "Confirm merchant settlement SLA window"}],
            now=now,
        )
        assert human_only_reqs[0].collection_mode == "human_required"
        human_reqs = await enrichment_repo.upsert_context_evidence_requirements(human_only_reqs)
        with pytest.raises(ValueError, match="placeholder HITL responder"):
            await enrichment_repo.create_human_evidence_request(
                tenant_id="default",
                incident_id=inc_uuid,
                requirement_id=human_reqs[0].requirement_id,
                expected_responder="incident-owner",
                due_at=now + timedelta(hours=1),
                acceptable_format="text",
                evidence_already_checked=[],
                hypothesis_impact="Blocked without responder",
            )
        blocked_req = await enrichment_repo.create_human_evidence_request(
            tenant_id="default",
            incident_id=inc_uuid,
            requirement_id=human_reqs[0].requirement_id,
            expected_responder=None,
            due_at=now + timedelta(hours=1),
            acceptable_format="text",
            evidence_already_checked=[],
            hypothesis_impact="Blocked without responder",
        )
        assert blocked_req is not None
        assert blocked_req.status == "assignment_blocked"
        assert blocked_req.assignment_failure_reason == "NO_AUTHORIZED_RESPONDER"

        # 4. Duplicate alert / outbox event redelivery idempotency
        first_enq = await enrichment_repo.enqueue_resolution_event(
            event_id=f"dedup-test:{inc_id}",
            aggregate_id=inc_id,
            topic="context-events",
            partition_key=inc_id,
            payload={"test": True},
            tenant_id="default",
        )
        second_enq = await enrichment_repo.enqueue_resolution_event(
            event_id=f"dedup-test:{inc_id}",
            aggregate_id=inc_id,
            topic="context-events",
            partition_key=inc_id,
            payload={"test": True},
            tenant_id="default",
        )
        assert first_enq is True
        assert second_enq is False

        # 5. Duplicate human response submission idempotency
        rb_reqs = build_evidence_requirements(
            tenant_id="default",
            incident_id=inc_uuid,
            rca_version=1,
            missing_evidence=[{"category": "runbook", "question": "Provide runbook for FailAlert"}],
            now=now,
        )
        saved_rb_reqs = await enrichment_repo.upsert_context_evidence_requirements(rb_reqs)
        await enrichment_repo.create_human_evidence_request(
            tenant_id="default",
            incident_id=inc_uuid,
            requirement_id=saved_rb_reqs[0].requirement_id,
            expected_responder="sre-oncall@example.com",
            due_at=now + timedelta(hours=1),
            acceptable_format="markdown",
            evidence_already_checked=[],
            hypothesis_impact="Need runbook",
        )
        resp_payload = {
            "responder_id": "sre-oncall@example.com",
            "responder_role": "sre-approver",
            "responded_at": now.isoformat(),
            "response": "Restart worker pod.",
            "root_cause": "Memory leak in worker.",
            "remediation_steps": "- kubectl rollout restart deployment/payments-worker -n prod",
            "create_runbook_draft": True,
        }
        sub_1 = await enrichment_repo.record_human_evidence_response(
            tenant_id="default",
            incident_id=inc_uuid,
            requirement_id=saved_rb_reqs[0].requirement_id,
            response=resp_payload,
        )
        sub_2 = await enrichment_repo.record_human_evidence_response(
            tenant_id="default",
            incident_id=inc_uuid,
            requirement_id=saved_rb_reqs[0].requirement_id,
            response=resp_payload,
        )
        assert sub_1["evidence_id"] == sub_2["evidence_id"]
        assert sub_1["context_snapshot_id"] == sub_2["context_snapshot_id"]
        assert sub_2.get("idempotent") is True

        # 6. Unapproved runbook draft is never returned as usable runbook
        gov_rb = await inc_repo.get_approved_runbook_version(
            tenant_id="default",
            runbook_id=uuid4(),
            version=1,
        )
        assert gov_rb is None

        # 7 & 8. Remediation/validation failure and missing recovery observation block closure
        proj = await session.get(IncidentProjectionRecord, inc_uuid)
        proj.lifecycle_state = "VALIDATING"
        proj.lifecycle_version = 2
        await session.flush()
        with pytest.raises(ValueError, match="VALIDATED_CLOSURE_MISSING"):
            await enrichment_repo.transition_incident_lifecycle(
                tenant_id="default",
                incident_id=inc_uuid,
                target_state=IncidentLifecycleState.CLOSED,
                expected_version=2,
                actor="closure-service",
                reason="Attempted premature closure without validated recovery",
                idempotency_key=f"premature-close:{inc_id}",
            )
