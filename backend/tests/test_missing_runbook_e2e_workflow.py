from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from common.context_enrichment_contract import HumanEvidenceResponse, build_evidence_requirements
from common.database import (
    Base,
    CanonicalEvidenceRecord,
    ContextSnapshotRecord,
    IncidentInvestigationBindingRecord,
    IncidentProjectionRecord,
    IncidentRecord,
    KnowledgeRagDraftRecord,
    ResolutionOutboxRecord,
    RunbookVersionRecord,
)
from ai_workbench_common.models import Context
from common.models import Alert, AlertSeverity
from common.repository import ContextEnrichmentRepository, IncidentRepository
from context_agent.connectors import VectorDBConnector
from resolution_agent.graph import ResolutionIntelligenceAgent as ResolutionAgent


def test_human_evidence_response_does_not_opt_into_runbook_draft_creation():
    response = HumanEvidenceResponse(
        response="A factual observation.",
        responder_id="sre@example.com",
        responded_at=datetime.now(UTC),
    )

    assert response.create_runbook_draft is False


@pytest.mark.asyncio
async def test_human_evidence_without_draft_opt_in_does_not_persist_a_runbook(e2e_session_factory):
    tenant_id = "tenant-no-draft-opt-in"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="UncataloguedQueueStall",
        description="A queue consumer stopped advancing.",
        service="uncatalogued-worker",
        environment="test",
        severity=AlertSeverity.HIGH,
    )
    async with e2e_session_factory() as session:
        await _seed_incident_and_snapshot(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
        )
        repository = ContextEnrichmentRepository(session)
        requirement = build_evidence_requirements(
            tenant_id=tenant_id,
            incident_id=incident_id,
            rca_version=1,
            missing_evidence=[{
                "category": "runbook",
                "question": "Provide the reviewed response for uncatalogued-worker.",
                "reason": "No approved runbook was retrieved.",
                "collection_mode": "human_required",
                "candidate_connectors": [],
            }],
            now=datetime.now(UTC),
        )[0]
        await repository.upsert_context_evidence_requirements([requirement])
        await repository.create_human_evidence_request(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=requirement.requirement_id,
            expected_responder="sre@example.com",
            assignment_source="test",
            due_at=datetime.now(UTC) + timedelta(hours=1),
            acceptable_format="Verified runbook observation",
            evidence_already_checked=[],
            hypothesis_impact=requirement.reason,
        )
        await session.commit()

        result = await repository.record_human_evidence_response(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=requirement.requirement_id,
            response={
                "response": "The worker stalled after a transient broker disconnect.",
                "responder_id": "sre@example.com",
                "responded_at": datetime.now(UTC).isoformat(),
                "root_cause": "The worker did not resume after the broker reconnected.",
                "remediation_steps": "Restart the disposable test worker.",
            },
        )
        drafts = await IncidentRepository(session).list_knowledge_rag_drafts(tenant_id=tenant_id)

    assert result["knowledge_draft_id"] is None
    assert drafts == []


@pytest.fixture
async def e2e_session_factory(sqlite_session_factory):
    yield sqlite_session_factory


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
    analysis_id = uuid4()
    recommendation_id = uuid4()
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
            "document_available": document_available,
            "context_snapshot_id": str(snapshot_id),
            "correlation_id": f"corr-{incident_id}",
            "rca_version": 1,
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
            payload={"alert_ids": [str(alert.id)], "timeline": [{"event": "incident.opened", "timestamp": now.isoformat()}]},
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
            source_manifest={"telemetry": {"connector": "alert-receiver", "source_reference": f"alert://{alert.id}"}},
            payload=context.model_dump(mode="json"),
            collected_at=now,
            expires_at=now + timedelta(hours=1),
        )
    )
    session.add(
        IncidentInvestigationBindingRecord(
            tenant_id=tenant_id,
            project_id="project-e2e",
            incident_id=incident_id,
            alert_id=alert.id,
            analysis_request_id=analysis_id,
            context_snapshot_id=snapshot_id,
            context_fingerprint="c" * 64,
            recommendation_id=recommendation_id,
            rca_version=1,
            status="insufficient_evidence",
            created_at=now,
            expires_at=now + timedelta(hours=1),
        )
    )
    await session.commit()
    return context


@pytest.mark.asyncio
async def test_step5_known_runbook_incident_end_to_end(e2e_session_factory):
    """Step 5.1: Verify one known-runbook incident processes end-to-end without regressions."""
    tenant_id = "tenant-e2e"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="MySQLExporterReplicationClientDenied",
        description="Error 1227 (42000): Access denied; you need (at least one of) the REPLICATION CLIENT privilege(s) for this operation on slave_status",
        service="mysql-exporter",
        environment="prod",
        severity=AlertSeverity.HIGH,
    )
    known_runbook = (
        "# Runbook: mysql-exporter Error 1227\n"
        "Service: mysql-exporter\n"
        "Remediation:\n"
        "`mysql -e \"SELECT CURRENT_USER(); SHOW GRANTS FOR CURRENT_USER();\"`\n"
        "`mysql -e \"SHOW REPLICA STATUS\\\\G\"`"
    )
    async with e2e_session_factory() as session:
        context = await _seed_incident_and_snapshot(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
            runbook=known_runbook,
            document_available=True,
        )
        agent = ResolutionAgent()
        recommendation = await agent.resolve(context)
        assert "REPLICATION CLIENT privilege" in recommendation.root_cause
        assert "mysql-exporter" in recommendation.impact
        assert len(recommendation.commands) >= 1
        assert recommendation.confidence >= 0.4


@pytest.mark.asyncio
async def test_step5_unknown_incident_waiting_human_input_approval_and_replay_reuse(e2e_session_factory, tmp_path):
    """Step 5.2 & 5.3: Unknown runbook -> waiting_for_human -> user input -> resumed RCA/impact/fix -> approval -> replay reuse."""
    tenant_id = "tenant-e2e"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="InvoiceWorkerQueueStall",
        description="invoice-worker consumer group lag exceeded 1200 messages for 10m in prod",
        service="invoice-worker",
        environment="prod",
        severity=AlertSeverity.CRITICAL,
    )
    connector = VectorDBConnector(rag_root=tmp_path)

    async with e2e_session_factory() as session:
        # 1. Verify no runbook exists initially
        initial_hits = connector.search(
            f"{alert.service} {alert.name} {alert.description}",
            tenant_id=tenant_id,
            service=alert.service,
            preferred_kind="runbook",
        )
        assert initial_hits == []

        await _seed_incident_and_snapshot(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
            runbook="",
            document_available=False,
        )

        # 2. Missing runbook creates pending human request & transitions incident to waiting_for_human
        enrichment_repo = ContextEnrichmentRepository(session)
        reqs = build_evidence_requirements(
            tenant_id=tenant_id,
            incident_id=incident_id,
            rca_version=1,
            missing_evidence=[
                {
                    "category": "runbook",
                    "question": "Provide runbook, observed symptoms/root cause, business impact, and remediation steps for invoice-worker.",
                    "reason": "No approved runbook was retrieved for invoice-worker.",
                    "collection_mode": "human_required",
                    "candidate_connectors": [],
                }
            ],
            now=datetime.now(UTC),
        )
        await enrichment_repo.upsert_context_evidence_requirements(reqs)
        runbook_req = reqs[0]
        assignment = await enrichment_repo.resolve_human_evidence_responder(
            tenant_id=tenant_id, incident_id=incident_id
        )
        human_req = await enrichment_repo.create_human_evidence_request(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=runbook_req.requirement_id,
            expected_responder=assignment["identity"],
            assignment_source=assignment["source"],
            due_at=datetime.now(UTC) + timedelta(hours=1),
            acceptable_format="Verified runbook observation",
            evidence_already_checked=[],
            hypothesis_impact=runbook_req.reason,
            automatic_fallback=True,
        )
        await session.commit()

        inc = await session.get(IncidentRecord, incident_id)
        assert human_req.status == "pending"
        assert inc.status == "waiting_for_human"
        assert inc.payload["alert_ids"] == [str(alert.id)]

        # 3. Submit human input (symptoms/root-cause, business impact, remediation steps)
        submission = {
            "response": "Dead-letter poison message blocked invoice-worker partition 3 consumer.",
            "responder_id": "oncall-sre@example.com",
            "responded_at": datetime.now(UTC).isoformat(),
            "observed_symptoms": "invoice-worker partition 3 offset stuck on malformed payload batch #8841.",
            "root_cause": "Unescaped currency symbol in batch #8841 caused poison-pill retry loop on invoice-worker partition 3.",
            "business_impact": "Enterprise invoice PDF generation delayed by 20 minutes for 140 accounts.",
            "remediation_steps": "Quarantine poison batch and restart worker:\n`kubectl rollout restart deployment/invoice-worker -n prod`",
            "create_runbook_draft": True,
            "auto_approve_runbook": False,
        }
        recorded = await enrichment_repo.record_human_evidence_response(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=runbook_req.requirement_id,
            response=submission,
        )
        await session.commit()

        # Verify evidence category is 'knowledge', incident resumed to 'investigating', outbox event queued
        ev = await session.get(CanonicalEvidenceRecord, recorded["evidence_id"])
        assert ev is not None
        assert ev.category == "knowledge"
        assert ev.source_reference.startswith(f"kaiops://human-evidence/{incident_id}/")

        inc_after = await session.get(IncidentRecord, incident_id)
        assert inc_after.id == incident_id
        assert inc_after.status == "investigating"
        assert inc_after.payload["alert_ids"] == [str(alert.id)]

        outbox = await session.get(
            ResolutionOutboxRecord,
            f"context-human-enriched:{incident_id}:{recorded['context_snapshot_id']}",
        )
        assert outbox is not None

        # 4. Resume resolution on the updated context snapshot & verify grounded RCA, impact, and remediation
        new_snapshot = await session.get(ContextSnapshotRecord, UUID(recorded["context_snapshot_id"]))
        resumed_context = Context.model_validate(new_snapshot.payload)
        agent = ResolutionAgent()
        resumed_rec = await agent.resolve(resumed_context)

        assert "poison-pill retry loop" in resumed_rec.root_cause
        assert "Enterprise invoice PDF generation delayed" in resumed_rec.impact
        assert any("kubectl rollout restart deployment/invoice-worker -n prod" in cmd for cmd in resumed_rec.commands)
        assert recorded["evidence_id"] in resumed_rec.metadata["rca_analysis"]["evidence_used"]
        assert resumed_rec.confidence >= 0.45

        # 5. Verify governed runbook draft requires explicit approval before reuse
        draft_id = UUID(recorded["knowledge_draft_id"])
        draft = await session.get(KnowledgeRagDraftRecord, draft_id)
        assert draft.status == "draft"
        unapproved_hits = connector.search(
            f"{alert.service} {alert.name}",
            tenant_id=tenant_id,
            service=alert.service,
            preferred_kind="runbook",
        )
        assert unapproved_hits == []

        inc_repo = IncidentRepository(session)
        from common.database import GovernedRagDocumentRecord
        reviewed = await inc_repo.review_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft_id,
            expected_row_version=draft.row_version,
            title=draft.title,
            content=draft.content,
            review_notes="Approved invoice-worker poison batch runbook.",
            reviewed_by="sre-lead@example.com",
        )
        with pytest.raises(RuntimeError, match="different reviewer"):
            await inc_repo.approve_knowledge_rag_draft(
                tenant_id=tenant_id,
                draft_id=draft_id,
                expected_row_version=reviewed["row_version"],
                approved_by="SRE-LEAD@example.com",
            )
        approved_res = await inc_repo.approve_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft_id,
            expected_row_version=reviewed["row_version"],
            approved_by="release-owner@example.com",
        )
        await session.commit()
        assert approved_res is not None
        approved_draft, approved_payload = approved_res
        assert approved_draft["status"] == "approved_pending_index"
        approved_doc = await session.get(GovernedRagDocumentRecord, UUID(approved_payload["document_id"]))
        indexed = await connector.index_governed_document(approved_doc)
        assert indexed["indexed"] == 1

        # 6. Replay a similar alert and verify approved runbook is retrieved without needing human runbook input
        replay_hits = connector.search(
            "invoice-worker consumer group lag exceeded in prod",
            tenant_id=tenant_id,
            service="invoice-worker",
            preferred_kind="runbook",
        )
        assert len(replay_hits) >= 1
        retrieved_runbook = replay_hits[0]["content"]
        assert "kubectl rollout restart deployment/invoice-worker -n prod" in retrieved_runbook

        replay_incident_id = uuid4()
        replay_alert = Alert(
            tenant_id=tenant_id,
            source="prometheus",
            name="InvoiceWorkerQueueStall",
            description="invoice-worker consumer group lag exceeded 1500 messages in prod",
            service="invoice-worker",
            environment="prod",
            severity=AlertSeverity.CRITICAL,
        )
        replay_context = await _seed_incident_and_snapshot(
            session,
            tenant_id=tenant_id,
            incident_id=replay_incident_id,
            alert=replay_alert,
            runbook=retrieved_runbook,
            document_available=True,
        )
        replay_rec = await agent.resolve(replay_context)
        assert bool(replay_context.runbook and replay_context.metadata.get("document_available")) is True
        assert any("kubectl rollout restart deployment/invoice-worker -n prod" in cmd for cmd in replay_rec.commands)


@pytest.mark.asyncio
@pytest.mark.parametrize("batch_size", [3, 5])
async def test_step5_batch_incidents_end_to_end(e2e_session_factory, tmp_path, batch_size: int):
    """Step 5.4: Test batches of 3 and then 5 incidents end-to-end."""
    tenant_id = f"tenant-batch-{batch_size}"
    connector = VectorDBConnector(rag_root=tmp_path)
    agent = ResolutionAgent()

    async with e2e_session_factory() as session:
        enrichment_repo = ContextEnrichmentRepository(session)
        inc_repo = IncidentRepository(session)

        for idx in range(batch_size):
            service_name = f"batch-svc-{idx}"
            incident_id = uuid4()
            alert = Alert(
                tenant_id=tenant_id,
                source="prometheus",
                name=f"ServiceDegradation_{idx}",
                description=f"{service_name} connection pool exhaustion on shard {idx}",
                service=service_name,
                environment="prod",
                severity=AlertSeverity.HIGH,
            )
            await _seed_incident_and_snapshot(
                session,
                tenant_id=tenant_id,
                incident_id=incident_id,
                alert=alert,
                runbook="",
                document_available=False,
            )
            req = build_evidence_requirements(
                tenant_id=tenant_id,
                incident_id=incident_id,
                rca_version=1,
                missing_evidence=[
                    {
                        "category": "runbook",
                        "question": f"Provide runbook and remediation steps for {service_name}.",
                        "collection_mode": "human_required",
                        "candidate_connectors": [],
                    }
                ],
                now=datetime.now(UTC),
            )[0]
            await enrichment_repo.upsert_context_evidence_requirements([req])
            assignment = await enrichment_repo.resolve_human_evidence_responder(
                tenant_id=tenant_id, incident_id=incident_id
            )
            await enrichment_repo.create_human_evidence_request(
                tenant_id=tenant_id,
                incident_id=incident_id,
                requirement_id=req.requirement_id,
                expected_responder=assignment["identity"],
                assignment_source=assignment["source"],
                due_at=datetime.now(UTC) + timedelta(hours=1),
                acceptable_format="Verified runbook observation",
                evidence_already_checked=[],
                hypothesis_impact=req.reason,
                automatic_fallback=True,
            )
            await session.commit()

            inc_waiting = await session.get(IncidentRecord, incident_id)
            assert inc_waiting.status == "waiting_for_human"

            recorded = await enrichment_repo.record_human_evidence_response(
                tenant_id=tenant_id,
                incident_id=incident_id,
                requirement_id=req.requirement_id,
                response={
                    "response": f"Connection pool leak in {service_name} shard {idx}.",
                    "responder_id": f"operator-{idx}@example.com",
                    "responded_at": datetime.now(UTC).isoformat(),
                    "observed_symptoms": f"Active connections pinned at 100% on {service_name}.",
                    "root_cause": f"Idle transaction timeout misconfigured on {service_name} shard {idx}.",
                    "business_impact": f"API latency increased for {service_name} requests.",
                    "remediation_steps": f"Restart deployment:\n`kubectl rollout restart deployment/{service_name} -n prod`",
                    "create_runbook_draft": True,
                    "auto_approve_runbook": False,
                },
            )
            await session.commit()

            snap = await session.get(ContextSnapshotRecord, UUID(recorded["context_snapshot_id"]))
            resumed_ctx = Context.model_validate(snap.payload)
            rec = await agent.resolve(resumed_ctx)
            assert f"Idle transaction timeout misconfigured on {service_name}" in rec.root_cause
            assert f"API latency increased for {service_name}" in rec.impact
            assert any(f"kubectl rollout restart deployment/{service_name} -n prod" in c for c in rec.commands)

            from common.database import GovernedRagDocumentRecord
            draft_obj = await session.get(KnowledgeRagDraftRecord, UUID(recorded["knowledge_draft_id"]))
            reviewed = await inc_repo.review_knowledge_rag_draft(
                tenant_id=tenant_id,
                draft_id=draft_obj.draft_id,
                expected_row_version=draft_obj.row_version,
                title=draft_obj.title,
                content=draft_obj.content,
                review_notes=f"Approved runbook for {service_name}",
                reviewed_by="lead-sre@example.com",
            )
            approved_res = await inc_repo.approve_knowledge_rag_draft(
                tenant_id=tenant_id,
                draft_id=draft_obj.draft_id,
                expected_row_version=reviewed["row_version"],
                approved_by="release-owner@example.com",
            )
            await session.commit()
            _, approved_payload = approved_res
            approved_doc = await session.get(GovernedRagDocumentRecord, UUID(approved_payload["document_id"]))
            indexed = await connector.index_governed_document(approved_doc)
            assert indexed["indexed"] == 1
            hits = connector.search(
                f"{service_name} connection pool exhaustion",
                tenant_id=tenant_id,
                service=service_name,
                preferred_kind="runbook",
            )
            assert len(hits) >= 1
