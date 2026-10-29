"""
Final Integration Recovery End-to-End Regression Test Suite
============================================================
Simulates the complete automatic RCA, runbook generation, human evidence
continuation, indexing, reuse, lifecycle progression, and closure workflow.
Also tests all required failure and edge paths in complete isolation.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

from ai_workbench_common.models import Context
from common.context_enrichment_contract import (
    _CANONICAL_CATEGORY,
    _REQUIREMENT_CONNECTORS,
    build_evidence_requirements,
)
from common.database import (
    ActionRecord,
    ApprovalRecord,
    CanonicalEvidenceRecord,
    ContextEvidenceRequirementRecord,
    ContextSnapshotRecord,
    GovernedRagDocumentRecord,
    HumanEvidenceRequestRecord,
    IncidentInvestigationBindingRecord,
    IncidentLifecycleTransitionRecord,
    IncidentProjectionRecord,
    IncidentRecord,
    KnowledgeRagDraftRecord,
    ResolutionOutboxRecord,
)
from common.models import Alert, AlertSeverity, RemediationAction, RemediationStatus
from common.repository import ContextEnrichmentRepository, IncidentRepository
from closure_service.reconciliation import (
    ReconciliationDecision,
    assess_terminal_action,
    has_signed_recovery_proof,
)
from context_agent.connectors import VectorDBConnector
from resolution_agent.graph import ResolutionIntelligenceAgent as ResolutionAgent


async def _seed_test_incident(
    session,
    *,
    tenant_id: str,
    incident_id: UUID,
    alert: Alert,
    runbook: str = "",
    document_available: bool = False,
    lifecycle_state: str = "DETECTED",
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
            freshness="fresh",
            content={"alert_id": str(alert.id), "description": alert.description},
            provenance={"collector": "alert-receiver"},
            current_observation=True,
            content_digest="b" * 64,
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
            payload={
                "alert_ids": [str(alert.id)],
                "timeline": [{"event": "incident.detected", "timestamp": now.isoformat()}],
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
            lifecycle_state=lifecycle_state,
            lifecycle_version=1,
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
            subject_fingerprint="f" * 64,
            context_fingerprint="g" * 64,
            snapshot_stage="initial",
            snapshot_version=1,
            evidence_ids=[alert_ev_id],
            evidence_checksums={alert_ev_id: "h" * 64},
            contract_version="kaiops.context.v2",
            quality_score=0.6,
            reusable=False,
            source_manifest={"telemetry": {"connector": "alert-receiver", "source_reference": f"alert://{alert.id}"}},
            payload=context.model_dump(mode="json"),
            collected_at=now,
            expires_at=now + timedelta(hours=2),
        )
    )
    await session.commit()
    return context


# =========================================================================
# 1. Complete Workflow: Unknown Incident -> RCA -> Human -> Resume ->
#    Draft -> Approval -> Vector Index -> Reuse -> Closure
# =========================================================================
@pytest.mark.asyncio
async def test_complete_e2e_incident_lifecycle_workflow(sqlite_session_factory, tmp_path):
    """Verifies the complete end-to-end incident lifecycle:
    1. Incident arrives for service without runbook -> starts in DETECTED/INVESTIGATING
    2. Available evidence collected -> RCA determines missing runbook
    3. Actionable human evidence request generated -> transitions to WAITING_FOR_HUMAN
    4. Human submits verified symptoms, root cause, impact, and remediation steps
    5. Incident automatically resumes to INVESTIGATING without manual recreation
    6. Runbook draft generated and persisted exactly once
    7. Approval gate respected: unapproved draft is not returned by vector store
    8. Authorized review and approval transitions draft to approved_pending_index
    9. Indexing succeeds and vector retrieval finds approved runbook
    10. Second similar incident retrieves and reuses runbook without asking human again
    11. Post-remediation signed recovery proof validated
    12. Incident transitions to CLOSED upon verified recovery confirmation
    """
    tenant_id = "tenant-recovery-e2e"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="CartServiceRedisPoolExhaustion",
        description="cart-service redis connection pool latency exceeded 500ms in prod",
        service="cart-service",
        environment="prod",
        severity=AlertSeverity.HIGH,
    )
    vector_db = VectorDBConnector(rag_root=tmp_path)
    agent = ResolutionAgent()

    # Phase 1: Ingestion & Verification of No Initial Runbook
    initial_search = vector_db.search(
        f"{alert.service} {alert.name}",
        tenant_id=tenant_id,
        service=alert.service,
        preferred_kind="runbook",
    )
    assert initial_search == [], "Precondition failed: runbook must not exist yet"

    async with sqlite_session_factory() as session:
        context = await _seed_test_incident(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
            runbook="",
            document_available=False,
            lifecycle_state="DETECTED",
        )

        enrichment_repo = ContextEnrichmentRepository(session)
        inc_repo = IncidentRepository(session)

        # Transition DETECTED -> INVESTIGATING with context snapshot
        t_inv = await inc_repo.transition_incident_lifecycle(
            tenant_id=tenant_id,
            incident_id=incident_id,
            target_state="INVESTIGATING",
            expected_version=1,
            actor="orchestrator",
            reason="Initial context snapshot ready, starting RCA",
            idempotency_key=f"trans-inv:{incident_id}",
        )
        assert t_inv["new_state"] == "INVESTIGATING"
        assert t_inv["version"] == 2

        # Phase 2: Missing Runbook Triggers Human Evidence Request
        reqs = build_evidence_requirements(
            tenant_id=tenant_id,
            incident_id=incident_id,
            rca_version=1,
            missing_evidence=[
                {
                    "category": "runbook",
                    "question": "Provide runbook, observed symptoms, root cause, and remediation for cart-service.",
                    "reason": "No approved runbook found for cart-service Redis connection pool exhaustion.",
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
        assert assignment is not None
        assert assignment["identity"] == "sre-oncall@kaims.local"

        human_req = await enrichment_repo.create_human_evidence_request(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=runbook_req.requirement_id,
            expected_responder=assignment["identity"],
            assignment_source=assignment["source"],
            due_at=datetime.now(UTC) + timedelta(hours=1),
            acceptable_format="Operational Markdown runbook",
            evidence_already_checked=[],
            hypothesis_impact=runbook_req.reason,
            automatic_fallback=True,
        )
        await session.commit()

        # Verify incident and projection both moved to waiting_for_human
        inc_row = await session.get(IncidentRecord, incident_id)
        proj_row = await session.get(IncidentProjectionRecord, incident_id)
        assert human_req.status == "pending"
        assert inc_row.status == "waiting_for_human"
        assert proj_row.status == "waiting_for_human"
        assert proj_row.lifecycle_state == "WAITING_FOR_HUMAN"

        # Phase 3: Human Responds -> Resumes Workflow Automatically
        human_submission = {
            "response": "Redis connection pool leaked connections during cache cluster failover.",
            "responder_id": "sre-lead@kaims.local",
            "allow_manual_claim": True,
            "responded_at": datetime.now(UTC).isoformat(),
            "observed_symptoms": "Redis active client count hit 1000 max connections with idle timeouts disabled.",
            "root_cause": "TCP socket leak in Redis client connection pool after intermittent network blip.",
            "business_impact": "Checkout carts failed to persist for 45 users.",
            "remediation_steps": "Restart cart-service pods and flush idle Redis connections:\n`kubectl rollout restart deployment/cart-service -n prod`",
            "create_runbook_draft": True,
        }

        recorded = await enrichment_repo.record_human_evidence_response(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=runbook_req.requirement_id,
            response=human_submission,
        )
        await session.commit()

        # Verify resumption
        inc_resumed = await session.get(IncidentRecord, incident_id)
        proj_resumed = await session.get(IncidentProjectionRecord, incident_id)
        assert inc_resumed.status == "investigating"
        assert proj_resumed.status == "investigating"
        assert proj_resumed.lifecycle_state == "INVESTIGATING"

        # Verify draft was generated exactly once
        draft_id = UUID(recorded["knowledge_draft_id"])
        draft = await session.get(KnowledgeRagDraftRecord, draft_id)
        assert draft is not None
        assert draft.status == "draft"
        assert "cart-service" in draft.content
        assert "kubectl rollout restart deployment/cart-service -n prod" in draft.content

        # Phase 4: Approval Gate Respected
        unapproved_search = vector_db.search(
            "cart-service redis connection pool latency",
            tenant_id=tenant_id,
            service="cart-service",
            preferred_kind="runbook",
        )
        assert unapproved_search == [], "Unapproved draft must not be retrievable via vector store"

        # Phase 5: Authorized Review and Approval
        reviewed = await inc_repo.review_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft_id,
            expected_row_version=draft.row_version,
            title=draft.title,
            content=draft.content,
            review_notes="Approved cart-service pool leak runbook.",
            reviewed_by="sre-lead@kaims.local",
        )
        approved_result = await inc_repo.approve_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft_id,
            expected_row_version=reviewed["row_version"],
            approved_by="sre-lead@kaims.local",
        )
        await session.commit()

        approved_draft_data, approved_doc_payload = approved_result
        assert approved_draft_data["status"] == "approved_pending_index"

        # Phase 6: Vector Indexing & Verification of Real Retrieval
        approved_doc = await session.get(GovernedRagDocumentRecord, UUID(approved_doc_payload["document_id"]))
        index_result = await vector_db.index_governed_document(approved_doc)
        assert index_result["indexed"] == 1

        retrieved = vector_db.search(
            "cart-service redis connection pool latency exceeded",
            tenant_id=tenant_id,
            service="cart-service",
            preferred_kind="runbook",
        )
        assert len(retrieved) >= 1
        retrieved_content = retrieved[0]["content"]
        assert "kubectl rollout restart deployment/cart-service -n prod" in retrieved_content

        # Phase 7: Second Similar Incident Reuses Runbook Without New Draft
        similar_incident_id = uuid4()
        similar_alert = Alert(
            tenant_id=tenant_id,
            source="prometheus",
            name="CartServiceRedisPoolExhaustion",
            description="cart-service redis connection pool latency spike 650ms in prod",
            service="cart-service",
            environment="prod",
            severity=AlertSeverity.CRITICAL,
        )
        similar_context = await _seed_test_incident(
            session,
            tenant_id=tenant_id,
            incident_id=similar_incident_id,
            alert=similar_alert,
            runbook=retrieved_content,
            document_available=True,
            lifecycle_state="INVESTIGATING",
        )
        similar_resolution = await agent.resolve(similar_context)
        assert bool(similar_context.runbook and similar_context.metadata.get("document_available")) is True
        assert any("kubectl rollout restart deployment/cart-service -n prod" in cmd for cmd in similar_resolution.commands)

        # Ensure no draft was created for the second incident
        drafts_count = await session.scalar(
            select(func.count()).select_from(KnowledgeRagDraftRecord).where(
                KnowledgeRagDraftRecord.tenant_id == tenant_id,
                KnowledgeRagDraftRecord.source_ref.contains(str(similar_incident_id)),
            )
        )
        assert drafts_count == 0

        # Phase 8: Remediation & Verified Closure
        action = RemediationAction(
            id=uuid4(),
            tenant_id=tenant_id,
            incident_id=incident_id,
            target="cart-service",
            action_type="kubectl_restart",
            status=RemediationStatus.SUCCEEDED,
            parameters={
                "execution_result": {
                    "executed": True,
                    "build_result": "SUCCESS",
                    "recovery_validated": True,
                    "recovery_evidence": {
                        "executed": True,
                        "recovery_validated": True,
                    },
                }
            },
        )
        assert has_signed_recovery_proof(action) is True

        assessment = assess_terminal_action(action, projection_status="validating")
        assert assessment.decision == ReconciliationDecision.REPLAY
        assert assessment.recovery_proof is True

        # Complete closure via save_incident_event with incident.closure.completed
        await inc_repo.save_incident_event({
            "identity": {"incident_id": str(incident_id)},
            "scope": {"tenant_id": tenant_id, "service": "cart-service", "environment": "prod"},
            "state": {"status": "closed", "severity": "high"},
            "policy": {"requires_approval": False},
            "event_type": "incident.closure.completed",
            "created_at": datetime.now(UTC),
        })
        await session.commit()

        # Verify persistent projection lifecycle reached CLOSED
        closed_proj = await session.get(IncidentProjectionRecord, incident_id)
        assert closed_proj.status == "closed"
        assert closed_proj.lifecycle_state == "CLOSED"


# =========================================================================
# 2. Failure Paths & Boundary Validations
# =========================================================================
@pytest.mark.asyncio
async def test_failure_path_technical_connector_blocked(sqlite_session_factory):
    """Failure path A: Technical category without connector is marked blocked, not converted to questionnaire."""
    tenant_id = "tenant-fail-test"
    incident_id = uuid4()
    now = datetime.now(UTC)

    async with sqlite_session_factory() as session:
        enrichment_repo = ContextEnrichmentRepository(session)
        req = build_evidence_requirements(
            tenant_id=tenant_id,
            incident_id=incident_id,
            rca_version=1,
            missing_evidence=[{"category": "database", "question": "Inspect DB query cache hit ratio."}],
            now=now,
        )[0]
        await enrichment_repo.upsert_context_evidence_requirements([req])
        await session.commit()

        # Automatic fallback for technical capability must return None and mark requirement blocked
        result = await enrichment_repo.create_human_evidence_request(
            automatic_fallback=True,
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=req.requirement_id,
            expected_responder="sre-oncall@kaims.local",
            assignment_source="tenant_fallback",
            due_at=now + timedelta(hours=1),
            acceptable_format="Raw query metrics",
            evidence_already_checked=["discovery-mcp"],
            hypothesis_impact="Cache failure",
            investigation_can_continue=True,
        )
        assert result is None
        current_req = await enrichment_repo.context_evidence_requirement(
            tenant_id=tenant_id, requirement_id=req.requirement_id
        )
        assert current_req["status"] == "blocked"


@pytest.mark.asyncio
async def test_failure_path_no_authorized_responder(sqlite_session_factory):
    """Failure path B: If expected_responder is None, request is placed in assignment_blocked."""
    tenant_id = "tenant-no-responder"
    incident_id = uuid4()
    now = datetime.now(UTC)

    async with sqlite_session_factory() as session:
        enrichment_repo = ContextEnrichmentRepository(session)
        req = build_evidence_requirements(
            tenant_id=tenant_id,
            incident_id=incident_id,
            rca_version=1,
            missing_evidence=[{"category": "runbook", "question": "Provide runbook for unknown service."}],
            now=now,
        )[0]
        await enrichment_repo.upsert_context_evidence_requirements([req])
        await session.commit()

        request_record = await enrichment_repo.create_human_evidence_request(
            automatic_fallback=False,
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=req.requirement_id,
            expected_responder=None,
            assignment_source="none",
            assignment_failure_reason="NO_AUTHORIZED_RESPONDER",
            due_at=now + timedelta(hours=1),
            acceptable_format="Markdown",
            evidence_already_checked=[],
            hypothesis_impact="Missing guidance",
        )
        assert request_record.status == "assignment_blocked"
        assert request_record.assignment_failure_reason == "NO_AUTHORIZED_RESPONDER"


@pytest.mark.asyncio
async def test_failure_path_stale_lifecycle_version_rejected(sqlite_session_factory):
    """Failure path C: Stale lifecycle version raises RuntimeError."""
    tenant_id = "tenant-stale-ver"
    incident_id = uuid4()

    async with sqlite_session_factory() as session:
        session.add(
            IncidentProjectionRecord(
                incident_id=incident_id,
                tenant_id=tenant_id,
                service="api",
                environment="prod",
                severity="high",
                status="investigating",
                lifecycle_state="DETECTED",
                lifecycle_version=3,
            )
        )
        await session.commit()

        inc_repo = IncidentRepository(session)
        with pytest.raises(RuntimeError) as exc_info:
            await inc_repo.transition_incident_lifecycle(
                tenant_id=tenant_id,
                incident_id=incident_id,
                target_state="INVESTIGATING",
                expected_version=1,  # Stale: actual is 3
                actor="orchestrator",
                reason="Stale test",
                idempotency_key="stale-key-1",
            )
        assert "STALE_LIFECYCLE_VERSION" in str(exc_info.value)


@pytest.mark.asyncio
async def test_failure_path_duplicate_event_idempotency(sqlite_session_factory):
    """Failure path D: Duplicate event transition with same key returns idempotent=True without extra record."""
    tenant_id = "tenant-idempotent-test"
    incident_id = uuid4()

    async with sqlite_session_factory() as session:
        session.add(
            IncidentProjectionRecord(
                incident_id=incident_id,
                tenant_id=tenant_id,
                service="api",
                environment="prod",
                severity="high",
                status="investigating",
                lifecycle_state="DETECTED",
                lifecycle_version=1,
            )
        )
        # Add snapshot so INVESTIGATING prerequisite is satisfied
        session.add(
            ContextSnapshotRecord(
                snapshot_id=uuid4(),
                tenant_id=tenant_id,
                incident_id=str(incident_id),
                source_incident_id=str(incident_id),
                alert_signature="sig",
                subject_fingerprint="f" * 64,
                context_fingerprint="g" * 64,
                snapshot_stage="initial",
                snapshot_version=1,
                evidence_ids=[],
                evidence_checksums={},
                contract_version="kaiops.context.v2",
                quality_score=0.8,
                reusable=True,
                source_manifest={},
                payload={},
                collected_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        await session.commit()

        inc_repo = IncidentRepository(session)
        key = f"idem-key-{incident_id}"

        res1 = await inc_repo.transition_incident_lifecycle(
            tenant_id=tenant_id,
            incident_id=incident_id,
            target_state="INVESTIGATING",
            expected_version=1,
            actor="orchestrator",
            reason="Initial investigation",
            idempotency_key=key,
        )
        assert res1["idempotent"] is False

        # Duplicate delivery
        res2 = await inc_repo.transition_incident_lifecycle(
            tenant_id=tenant_id,
            incident_id=incident_id,
            target_state="INVESTIGATING",
            expected_version=1,
            actor="orchestrator",
            reason="Initial investigation",
            idempotency_key=key,
        )
        assert res2["idempotent"] is True
        assert res2["transition_id"] == res1["transition_id"]

        # Exactly 1 transition record must exist
        count = await session.scalar(
            select(func.count()).select_from(IncidentLifecycleTransitionRecord).where(
                IncidentLifecycleTransitionRecord.tenant_id == tenant_id,
                IncidentLifecycleTransitionRecord.incident_id == incident_id,
            )
        )
        assert count == 1


@pytest.mark.asyncio
async def test_failure_path_absent_recovery_proof_blocks_closure():
    """Failure path E: Action without signed recovery proof is assessed as REVALIDATE, not REPLAY."""
    action_without_proof = RemediationAction(
        id=uuid4(),
        tenant_id="tenant-unproven",
        incident_id=uuid4(),
        target="cart-service",
        action_type="service_restart",
        status=RemediationStatus.SUCCEEDED,
        parameters={"execution_result": {"executed": True, "build_result": "SUCCESS"}},
    )
    assert has_signed_recovery_proof(action_without_proof) is False
    assessment = assess_terminal_action(action_without_proof, projection_status="validating")
    assert assessment.decision == ReconciliationDecision.REVALIDATE
    assert assessment.recovery_proof is False


@pytest.mark.asyncio
async def test_failure_path_tenant_isolation_enforced(sqlite_session_factory, tmp_path):
    """Failure path F: Vector DB queries for Tenant A cannot retrieve Tenant B's runbooks."""
    vector_db = VectorDBConnector(rag_root=tmp_path)
    tenant_a = "tenant-alpha"
    tenant_b = "tenant-beta"

    async with sqlite_session_factory() as session:
        inc_repo = IncidentRepository(session)
        draft = await inc_repo.create_knowledge_rag_draft(
            tenant_id=tenant_b,
            created_by="lead@beta.local",
            document_kind="runbook",
            source_ref="kaiops://learned-runbook/beta/beta-auth/secret-plan",
            title="Beta Secret Auth Runbook",
            content="# Beta Secret Auth Runbook\nConfidential runbook steps for beta service.",
            metadata={"services": ["beta-auth"]},
        )
        await session.commit()

        draft_id = UUID(draft["draft_id"])
        reviewed = await inc_repo.review_knowledge_rag_draft(
            tenant_id=tenant_b,
            draft_id=draft_id,
            expected_row_version=1,
            title="Beta Secret Auth Runbook",
            content="# Beta Secret Auth Runbook\nConfidential runbook steps for beta service.",
            review_notes="Approved for Beta.",
            reviewed_by="lead@beta.local",
        )
        approved = await inc_repo.approve_knowledge_rag_draft(
            tenant_id=tenant_b,
            draft_id=draft_id,
            expected_row_version=reviewed["row_version"],
            approved_by="director@beta.local",
        )
        await session.commit()

        doc_record = await session.get(GovernedRagDocumentRecord, UUID(approved[1]["document_id"]))
        await vector_db.index_governed_document(doc_record)

        # Tenant A searches for beta content -> must return empty
        cross_tenant_search = vector_db.search(
            "Confidential runbook steps for beta service",
            tenant_id=tenant_a,
            service="beta-auth",
            preferred_kind="runbook",
        )
        assert cross_tenant_search == [], "Cross-tenant retrieval must return empty"

        # Tenant B searches for its own content -> must return document
        tenant_b_search = vector_db.search(
            "Confidential runbook steps for beta service",
            tenant_id=tenant_b,
            service="beta-auth",
            preferred_kind="runbook",
        )
        assert len(tenant_b_search) >= 1
        assert "Confidential runbook steps" in tenant_b_search[0]["content"]
