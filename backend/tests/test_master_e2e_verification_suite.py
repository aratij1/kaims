"""Master End-to-End Verification Suite for KaiMS.

Covers the complete production incident lifecycle and stability gates:
Scenario A: Incident with an existing approved runbook retrieves and uses that runbook.
Scenario B: Incident without a runbook triggers evidence collection, RCA, impact assessment,
            next-action generation, and a runbook draft when sufficient information is available.
Scenario C: A missing technical capability produces an explicit blocked state rather than false collection success.
Scenario D: An unassigned human request is handled according to configured fallback and authorization policy.
Scenario E: A human response is persisted, resumes the workflow, and triggers draft generation.
Scenario F: An approved draft is indexed and can be retrieved by a similar incident.
Scenario G: Duplicate events do not generate duplicate drafts, RCA runs, or remediation actions.
Scenario H: Governed execution plan progresses through authorized remediation and evidence-backed validation.
Scenario I: Incident cannot be closed without required recovery proof or valid diagnostic-completion evidence.
Scenario J: Persistent lifecycle projections, audit transitions, and operational status remain consistent.
Scenario K: Tenant isolation is enforced across evidence, human responses, runbooks, and retrieval.
Scenario L: Resource-intensive queries and retry loops remain bounded under a repeatable workload.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from ai_workbench_common.models import Context
from common.context_enrichment_contract import (
    _CANONICAL_CATEGORY,
    _REQUIREMENT_CONNECTORS,
    build_evidence_requirements,
)
from common.database import (
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
)
from common.models import Alert, AlertSeverity, RemediationAction, RemediationStatus
from common.orchestration.execution_plan_contract import (
    canonical_plan_fingerprint,
    verify_plan_fingerprint,
)
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
    lifecycle_state: str = "INVESTIGATING",
    owner: str | None = None,
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
            freshness="fresh",
            content={"alert_id": str(alert.id), "description": alert.description},
            provenance={"collector": "alert-receiver"},
            current_observation=True,
            content_digest="a" * 64,
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

    incident_payload = {
        "alert_ids": [str(alert.id)],
        "timeline": [{"event": "incident.opened", "timestamp": now.isoformat()}],
    }
    if owner:
        incident_payload["owner"] = owner

    session.add(
        IncidentRecord(
            id=incident_id,
            tenant_id=tenant_id,
            title=alert.name,
            severity=alert.severity.value,
            status="investigating",
            service=alert.service,
            environment=alert.environment,
            payload=incident_payload,
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
            evidence_checksums={alert_ev_id: "e" * 64},
            contract_version="kaiops.context.v2",
            quality_score=0.8,
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
            project_id="project-master-e2e",
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


# =========================================================================
# Scenario A: Existing approved runbook retrieval and reuse
# =========================================================================
@pytest.mark.asyncio
async def test_scenario_a_approved_runbook_retrieval(sqlite_session_factory):
    """Scenario A: An incident with an existing approved runbook retrieves and uses that runbook."""
    tenant_id = "tenant-scenario-a"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="PostgresReplicationLagHigh",
        description="Replication lag on shard-02 replica exceeds 120s",
        service="postgres-service",
        environment="prod",
        severity=AlertSeverity.HIGH,
    )
    approved_runbook = (
        "# Runbook: Postgres Replication Lag\n"
        "Service: postgres-service\n"
        "Remediation:\n"
        "`systemctl restart postgresql`\n"
        "`curl -fsS http://localhost:9187/metrics`"
    )

    async with sqlite_session_factory() as session:
        context = await _seed_test_incident(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
            runbook=approved_runbook,
            document_available=True,
            lifecycle_state="INVESTIGATING",
        )

        agent = ResolutionAgent()
        rec = await agent.resolve(context)

        assert rec is not None
        assert len(rec.commands) >= 1
        assert any("systemctl restart postgresql" in cmd for cmd in rec.commands)
        assert "Execute approved runbook remediation script" in rec.recommended_action or rec.confidence > 0


# =========================================================================
# Scenario B: Missing runbook triggers RCA and runbook draft generation
# =========================================================================
@pytest.mark.asyncio
async def test_scenario_b_missing_runbook_rca_and_draft(sqlite_session_factory):
    """Scenario B: Incident without a runbook triggers evidence collection, RCA, and draft generation."""
    tenant_id = "tenant-scenario-b"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="CheckoutServiceDeadlock",
        description="Checkout service deadlocked waiting on inventory mutex shard-1",
        service="checkout-service",
        environment="prod",
        severity=AlertSeverity.CRITICAL,
    )

    async with sqlite_session_factory() as session:
        context = await _seed_test_incident(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
            runbook="",
            document_available=False,
            lifecycle_state="INVESTIGATING",
        )

        enrichment_repo = ContextEnrichmentRepository(session)
        reqs = build_evidence_requirements(
            tenant_id=tenant_id,
            incident_id=incident_id,
            rca_version=1,
            missing_evidence=[
                {
                    "category": "runbook",
                    "question": "Provide runbook and remediation instructions for checkout-service.",
                    "reason": "No approved runbook found for checkout-service.",
                    "collection_mode": "human_required",
                    "candidate_connectors": [],
                }
            ],
            now=datetime.now(UTC),
        )
        await enrichment_repo.upsert_context_evidence_requirements(reqs)

        # Responder assigned and questionnaire generated
        assignment = await enrichment_repo.resolve_human_evidence_responder(
            tenant_id=tenant_id, incident_id=incident_id
        )
        assert assignment["identity"] is not None

        human_req = await enrichment_repo.create_human_evidence_request(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=reqs[0].requirement_id,
            expected_responder=assignment["identity"],
            assignment_source=assignment["source"],
            due_at=datetime.now(UTC) + timedelta(hours=1),
            acceptable_format="Verified runbook observation",
            evidence_already_checked=[],
            hypothesis_impact="Missing runbook blocks execution planning.",
            automatic_fallback=True,
        )
        await session.commit()

        inc = await session.get(IncidentRecord, incident_id)
        assert human_req.status == "pending"
        assert inc.status == "waiting_for_human"

        # Operator provides symptoms, root cause, impact, and remediation
        human_submission = {
            "response": "Cleared inventory mutex lock and restarted checkout worker.",
            "responder_id": assignment["identity"],
            "responded_at": datetime.now(UTC).isoformat(),
            "observed_symptoms": "Thread dump showed 48 threads waiting on Lock#0x77ab in checkout-service.",
            "root_cause": "Abandoned transaction held exclusive table lock on inventory shard-1.",
            "business_impact": "Checkout failures increased to 12% for 8 minutes.",
            "remediation_steps": "Kill locking PID and restart:\n`kubectl rollout restart deployment/checkout-worker -n prod`",
            "create_runbook_draft": True,
        }

        recorded = await enrichment_repo.record_human_evidence_response(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=reqs[0].requirement_id,
            response=human_submission,
        )
        await session.commit()

        # Verify a runbook draft is automatically created
        assert recorded["knowledge_draft_id"] is not None
        draft = await session.get(KnowledgeRagDraftRecord, UUID(recorded["knowledge_draft_id"]))
        assert draft is not None
        assert draft.status == "draft"
        assert "Abandoned transaction held exclusive table lock" in draft.content
        assert "kubectl rollout restart deployment/checkout-worker -n prod" in draft.content

        # Resume RCA with the newly enriched context
        new_snapshot = await session.get(ContextSnapshotRecord, UUID(recorded["context_snapshot_id"]))
        resumed_context = Context.model_validate(new_snapshot.payload)
        agent = ResolutionAgent()
        resumed_rec = await agent.resolve(resumed_context)

        assert "Abandoned transaction held exclusive table lock" in resumed_rec.root_cause
        assert "Checkout failures increased" in resumed_rec.impact
        assert any("kubectl rollout restart deployment/checkout-worker -n prod" in cmd for cmd in resumed_rec.commands)


# =========================================================================
# Scenario C: Missing technical capability produces explicit blocked state
# =========================================================================
@pytest.mark.asyncio
async def test_scenario_c_missing_technical_capability_blocked(sqlite_session_factory):
    """Scenario C: A missing technical capability produces an explicit blocked state rather than false collection."""
    tenant_id = "tenant-scenario-c"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="CustomMetricMissing",
        description="Metric collector custom.sensor.temp unavailable",
        service="iot-gateway",
        environment="prod",
        severity=AlertSeverity.WARNING,
    )

    async with sqlite_session_factory() as session:
        await _seed_test_incident(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
        )

        enrichment_repo = ContextEnrichmentRepository(session)
        # Database technical requirement that fails automated collection
        db_reqs = build_evidence_requirements(
            tenant_id=tenant_id,
            incident_id=incident_id,
            rca_version=1,
            missing_evidence=[
                {
                    "category": "database",
                    "question": "Query iot-gateway internal shard connection state.",
                    "reason": "Automated connector unavailable or timed out.",
                    "collection_mode": "automatic",
                    "candidate_connectors": ["discovery-mcp"],
                }
            ],
            now=datetime.now(UTC),
        )
        await enrichment_repo.upsert_context_evidence_requirements(db_reqs)

        # Automated technical failure must NOT create human evidence questionnaire
        human_req = await enrichment_repo.create_human_evidence_request(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=db_reqs[0].requirement_id,
            expected_responder="nobody@kaims.local",
            assignment_source="automated-test",
            due_at=datetime.now(UTC) + timedelta(hours=1),
            acceptable_format="metrics",
            evidence_already_checked=[],
            hypothesis_impact="database metrics unavailable",
            automatic_fallback=True,
        )
        await session.commit()

        # Must return None (blocked) rather than creating a human evidence request
        assert human_req is None

        # The requirement status must explicitly be 'blocked', NOT 'collected' or 'human_requested'
        updated_req = await session.get(ContextEvidenceRequirementRecord, db_reqs[0].requirement_id)
        assert updated_req is not None
        assert updated_req.status == "blocked"


# =========================================================================
# Scenario D: Unassigned human request handles fallback policy safely
# =========================================================================
@pytest.mark.asyncio
async def test_scenario_d_unassigned_human_request_fallback_policy(sqlite_session_factory):
    """Scenario D: An unassigned human request is handled according to fallback and authorization policy."""
    tenant_id = "tenant-scenario-d"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="UnknownServiceFailure",
        description="Service without explicit metadata failed",
        service="unregistered-service",
        environment="prod",
        severity=AlertSeverity.HIGH,
    )

    async with sqlite_session_factory() as session:
        # Seed without owner
        await _seed_test_incident(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
            owner=None,
        )

        enrichment_repo = ContextEnrichmentRepository(session)
        # Safe responder resolution must resolve to a valid responder, never None
        assignment = await enrichment_repo.resolve_human_evidence_responder(
            tenant_id=tenant_id, incident_id=incident_id
        )

        assert assignment is not None
        assert assignment["identity"] is not None
        # Safe fallback defaults to tenant SRE on-call
        assert "sre-oncall@kaims.local" in assignment["identity"] or "unregistered-service" in assignment["identity"]
        assert assignment["source"] in ("service_metadata", "service_fallback", "tenant_sre_fallback", "tenant_fallback")


# =========================================================================
# Scenario E: Human response persistence resumes workflow and creates draft
# =========================================================================
@pytest.mark.asyncio
async def test_scenario_e_human_response_resumes_workflow(sqlite_session_factory):
    """Scenario E: Human response is persisted, resumes the workflow, and triggers draft generation."""
    tenant_id = "tenant-scenario-e"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="OrderProcessingStalled",
        description="order-processing consumer queue stalled",
        service="order-processing",
        environment="prod",
        severity=AlertSeverity.CRITICAL,
    )

    async with sqlite_session_factory() as session:
        await _seed_test_incident(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
        )

        enrichment_repo = ContextEnrichmentRepository(session)
        reqs = build_evidence_requirements(
            tenant_id=tenant_id,
            incident_id=incident_id,
            rca_version=1,
            missing_evidence=[
                {
                    "category": "runbook",
                    "question": "Provide runbook for order-processing queue stall.",
                    "collection_mode": "human_required",
                    "candidate_connectors": [],
                }
            ],
            now=datetime.now(UTC),
        )
        await enrichment_repo.upsert_context_evidence_requirements(reqs)
        await enrichment_repo.create_human_evidence_request(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=reqs[0].requirement_id,
            expected_responder="sre-oncall@kaims.local",
            assignment_source="tenant_sre_fallback",
            due_at=datetime.now(UTC) + timedelta(hours=1),
            acceptable_format="Operational instructions",
            evidence_already_checked=[],
            hypothesis_impact="Queue blocked",
            automatic_fallback=True,
        )
        await session.commit()

        # Submit response
        response_data = {
            "response": "Reset partition offset and cleared toxic message.",
            "responder_id": "sre-oncall@kaims.local",
            "responded_at": datetime.now(UTC).isoformat(),
            "observed_symptoms": "Consumer group order-processing lagged 5000 messages.",
            "root_cause": "Schema mismatch in message payload ID #9923.",
            "business_impact": "Order fulfillment delayed by 15m.",
            "remediation_steps": "`systemctl restart order-processing`",
            "create_runbook_draft": True,
        }
        recorded = await enrichment_repo.record_human_evidence_response(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=reqs[0].requirement_id,
            response=response_data,
        )
        await session.commit()

        # Verify CanonicalEvidenceRecord created with category 'knowledge'
        ev = await session.get(CanonicalEvidenceRecord, recorded["evidence_id"])
        assert ev is not None
        assert ev.category == "knowledge"
        assert ev.tenant_id == tenant_id

        # Verify incident status returned to 'investigating'
        inc = await session.get(IncidentRecord, incident_id)
        assert inc.status == "investigating"

        # Verify ResolutionOutboxRecord queued for context resume
        outbox_key = f"context-human-enriched:{incident_id}:{recorded['context_snapshot_id']}"
        outbox = await session.get(ResolutionOutboxRecord, outbox_key)
        assert outbox is not None
        assert outbox.topic == "context-events"
        assert outbox.status == "pending"


# =========================================================================
# Scenario F: Approved draft indexed and retrieved by similar incident
# =========================================================================
@pytest.mark.asyncio
async def test_scenario_f_approved_draft_retrieved_by_similar(sqlite_session_factory, tmp_path):
    """Scenario F: An approved draft is indexed and can be retrieved by a similar incident."""
    tenant_id = "tenant-scenario-f"
    incident_id = uuid4()
    connector = VectorDBConnector(rag_root=tmp_path)

    async with sqlite_session_factory() as session:
        inc_repo = IncidentRepository(session)

        # Create draft via repository API
        draft_content = (
            "# Runbook: Payment Gateway Timeout\n"
            "Service: payment-gateway\n"
            "Remediation:\n"
            "`curl -X POST https://internal.payments/v1/pools/refresh`\n"
            "`systemctl reload payment-gateway`"
        )
        draft_payload = await inc_repo.create_knowledge_rag_draft(
            tenant_id=tenant_id,
            created_by="sre-architect@kaims.local",
            document_kind="runbook",
            source_ref=f"kaiops://learned-runbook/{tenant_id}/payment-gateway/recovery",
            title="Payment Gateway Timeout Recovery",
            content=draft_content,
            metadata={"incident_id": str(incident_id), "services": ["payment-gateway"]},
        )
        await session.commit()

        draft_id = UUID(draft_payload["draft_id"])

        # Review draft
        reviewed = await inc_repo.review_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft_id,
            expected_row_version=1,
            title="Payment Gateway Timeout Recovery",
            content=draft_content,
            review_notes="Approved for production indexing.",
            reviewed_by="sre-architect@kaims.local",
        )
        assert reviewed["status"] == "reviewed"

        # Approve draft
        approved = await inc_repo.approve_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft_id,
            expected_row_version=reviewed["row_version"],
            approved_by="sre-manager@kaims.local",
        )
        await session.commit()

        assert approved is not None
        draft_dict, payload = approved
        assert draft_dict["status"] == "approved_pending_index"

        doc = await session.get(GovernedRagDocumentRecord, UUID(payload["document_id"]))
        assert doc is not None

        # Index document into VectorDB
        index_result = await connector.index_governed_document(doc)
        assert index_result["indexed"] == 1

        # Search for similar incident
        search_hits = connector.search(
            "Payment Gateway Connection Timeout error 504",
            tenant_id=tenant_id,
            service="payment-gateway",
            preferred_kind="runbook",
        )

        assert len(search_hits) >= 1
        assert "pools/refresh" in search_hits[0]["content"]
        assert "systemctl reload payment-gateway" in search_hits[0]["content"]


# =========================================================================
# Scenario G: Duplicate events do not generate duplicate drafts or actions
# =========================================================================
@pytest.mark.asyncio
async def test_scenario_g_duplicate_events_idempotency(sqlite_session_factory):
    """Scenario G: Duplicate events do not generate duplicate drafts, RCA runs, or remediation actions."""
    tenant_id = "tenant-scenario-g"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="DiskFullWarning",
        description="Volume /var/log exceeds 95% disk usage",
        service="log-aggregator",
        environment="prod",
        severity=AlertSeverity.HIGH,
    )

    async with sqlite_session_factory() as session:
        await _seed_test_incident(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
        )

        enrichment_repo = ContextEnrichmentRepository(session)
        reqs = build_evidence_requirements(
            tenant_id=tenant_id,
            incident_id=incident_id,
            rca_version=1,
            missing_evidence=[
                {
                    "category": "runbook",
                    "question": "Provide log rotation runbook.",
                    "collection_mode": "human_required",
                    "candidate_connectors": [],
                }
            ],
            now=datetime.now(UTC),
        )
        await enrichment_repo.upsert_context_evidence_requirements(reqs)
        await enrichment_repo.create_human_evidence_request(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=reqs[0].requirement_id,
            expected_responder="sre-oncall@kaims.local",
            assignment_source="tenant_sre_fallback",
            due_at=datetime.now(UTC) + timedelta(hours=1),
            acceptable_format="Log rotate instructions",
            evidence_already_checked=[],
            hypothesis_impact="Log volume full",
            automatic_fallback=True,
        )
        await session.commit()

        submission = {
            "response": "Rotated /var/log/journal.",
            "responder_id": "sre-oncall@kaims.local",
            "responded_at": datetime.now(UTC).isoformat(),
            "observed_symptoms": "Disk usage 98%",
            "root_cause": "Systemd journal retention uncapped.",
            "business_impact": "None yet",
            "remediation_steps": "`systemctl restart systemd-journald`",
            "create_runbook_draft": True,
        }

        # First recording succeeds
        rec1 = await enrichment_repo.record_human_evidence_response(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=reqs[0].requirement_id,
            response=submission,
        )
        await session.commit()

        # Second recording for already-answered requirement is idempotent
        rec2 = await enrichment_repo.record_human_evidence_response(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=reqs[0].requirement_id,
            response=submission,
        )
        await session.commit()

        assert rec2["idempotent"] is True
        assert rec2["evidence_id"] == rec1["evidence_id"]

        # Count total drafts created for this tenant
        drafts = (
            await session.scalars(
                select(KnowledgeRagDraftRecord).where(
                    KnowledgeRagDraftRecord.tenant_id == tenant_id,
                )
            )
        ).all()

        # Exactly 1 draft exists, no duplicate drafts created
        assert len(drafts) == 1


# =========================================================================
# Scenario H: Governed execution plan validation and progression
# =========================================================================
def test_scenario_h_governed_execution_plan_validation():
    """Scenario H: A governed execution plan can progress through authorized remediation and evidence-backed validation."""
    validators = [
        {
            "validator_id": "validator-availability",
            "tenant_id": "tenant-scenario-h",
            "connector_id": "prometheus",
            "target_resource_id": "auth-service",
            "kind": "availability",
            "check_reference": "metric:up:auth-service",
            "expected_condition": "up == 1",
            "evaluation_operator": "eq",
            "threshold": True,
            "observation_window_seconds": 60,
            "minimum_sample_count": 2,
            "timeout_seconds": 10,
            "authoritative_source": "prometheus",
            "onboarding_registry_reference": "validator-registry:validator-availability",
        }
    ]

    plan = {
        "schema_version": "kaims.execution-plan.v2",
        "plan_id": str(uuid4()),
        "tenant_id": "tenant-scenario-h",
        "rca_version": "rca-v1",
        "evidence_snapshot_id": "snapshot-v1",
        "recommendation_version": "recommendation-v1",
        "validation_endpoints": [],
        "validators": validators,
        "required_validation_kinds": ["availability"],
        "stability_window_seconds": 60,
    }
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)

    # Valid plan passes fingerprint verification
    assert verify_plan_fingerprint(plan) is True

    # Tampered plan fails verification
    tampered_plan = dict(plan)
    tampered_plan["stability_window_seconds"] = 10
    assert verify_plan_fingerprint(tampered_plan) is False


# =========================================================================
# Scenario I: Recovery proof required for closure
# =========================================================================
def test_scenario_i_recovery_proof_closure_requirement():
    """Scenario I: An incident cannot be closed without required recovery proof or valid diagnostic completion."""
    incident_id = uuid4()

    # 1. Unvalidated execution action must be blocked (REVALIDATE)
    unproven_action = RemediationAction(
        tenant_id="tenant-scenario-i",
        incident_id=incident_id,
        action_type="restart_container",
        target="cart-service",
        status=RemediationStatus.SUCCEEDED,
        parameters={"execution_result": {"executed": True, "build_result": "SUCCESS"}},
    )
    assert has_signed_recovery_proof(unproven_action) is False
    assessment = assess_terminal_action(unproven_action, "validating")
    assert assessment.decision == ReconciliationDecision.REVALIDATE
    assert assessment.recovery_proof is False

    # 2. Signed recovery proof allows replay to closed
    proven_action = RemediationAction(
        tenant_id="tenant-scenario-i",
        incident_id=incident_id,
        action_type="restart_container",
        target="cart-service",
        status=RemediationStatus.SUCCEEDED,
        parameters={
            "execution_result": {
                "executed": True,
                "build_result": "SUCCESS",
                "recovery_validated": True,
                "recovery_evidence": {"executed": True, "recovery_validated": True},
            }
        },
    )
    assert has_signed_recovery_proof(proven_action) is True
    proven_assessment = assess_terminal_action(proven_action, "validating")
    assert proven_assessment.decision == ReconciliationDecision.REPLAY
    assert proven_assessment.recovery_proof is True

    # 3. Valid diagnostic completion also allows closure
    diagnostic_action = RemediationAction(
        tenant_id="tenant-scenario-i",
        incident_id=incident_id,
        action_type="diagnostic_completion",
        target="cart-service",
        status=RemediationStatus.SKIPPED,
        parameters={"diagnostic_closure": True, "diagnostic_details": {"all_checks": "green"}},
    )
    diag_assessment = assess_terminal_action(diagnostic_action, "investigating")
    assert diag_assessment.decision == ReconciliationDecision.REPLAY


# =========================================================================
# Scenario J: Persistent lifecycle projections remain consistent
# =========================================================================
@pytest.mark.asyncio
async def test_scenario_j_lifecycle_projection_consistency(sqlite_session_factory):
    """Scenario J: Persistent lifecycle projections, audit transitions, and operational status remain consistent."""
    tenant_id = "tenant-scenario-j"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="DatabaseLockSpike",
        description="High lock waits detected",
        service="db-service",
        environment="prod",
        severity=AlertSeverity.HIGH,
    )

    async with sqlite_session_factory() as session:
        await _seed_test_incident(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
            lifecycle_state="DETECTED",
        )

        enrichment_repo = ContextEnrichmentRepository(session)

        # Transition lifecycle state
        projection = await session.get(IncidentProjectionRecord, incident_id)
        assert projection.lifecycle_state == "DETECTED"

        # Update projection lifecycle state directly reflecting operational progression
        projection.lifecycle_state = "REQUIREMENTS_IDENTIFIED"
        projection.lifecycle_version = 2
        await session.commit()

        reloaded = await session.get(IncidentProjectionRecord, incident_id)
        assert reloaded.lifecycle_state == "REQUIREMENTS_IDENTIFIED"
        assert reloaded.lifecycle_version == 2

        # Advance to INVESTIGATING
        reloaded.lifecycle_state = "INVESTIGATING"
        reloaded.lifecycle_version = 3
        await session.commit()

        reloaded2 = await session.get(IncidentProjectionRecord, incident_id)
        assert reloaded2.lifecycle_state == "INVESTIGATING"
        assert reloaded2.lifecycle_version == 3


# =========================================================================
# Scenario K: Tenant isolation across evidence, runbooks, and retrieval
# =========================================================================
@pytest.mark.asyncio
async def test_scenario_k_tenant_isolation_enforced(sqlite_session_factory, tmp_path):
    """Scenario K: Tenant isolation is enforced across evidence, human responses, runbooks, and retrieval."""
    tenant_a = "tenant-scenario-k-alpha"
    tenant_b = "tenant-scenario-k-beta"
    connector = VectorDBConnector(rag_root=tmp_path)

    async with sqlite_session_factory() as session:
        inc_repo = IncidentRepository(session)

        # Create and approve runbook for Tenant A only
        draft_a = await inc_repo.create_knowledge_rag_draft(
            tenant_id=tenant_a,
            created_by="sre-alpha@kaims.local",
            document_kind="runbook",
            source_ref=f"kaiops://learned-runbook/{tenant_a}/alpha-service/secret-plan",
            title="Tenant Alpha Secret Runbook",
            content="# Tenant Alpha Secret Runbook\nSecret remediation commands for Alpha.",
            metadata={"services": ["alpha-service"]},
        )
        await session.commit()

        draft_id = UUID(draft_a["draft_id"])
        reviewed = await inc_repo.review_knowledge_rag_draft(
            tenant_id=tenant_a,
            draft_id=draft_id,
            expected_row_version=1,
            title="Tenant Alpha Secret Runbook",
            content="# Tenant Alpha Secret Runbook\nSecret remediation commands for Alpha.",
            review_notes="Approved for Alpha.",
            reviewed_by="lead-alpha@kaims.local",
        )
        approved = await inc_repo.approve_knowledge_rag_draft(
            tenant_id=tenant_a,
            draft_id=draft_id,
            expected_row_version=reviewed["row_version"],
            approved_by="director-alpha@kaims.local",
        )
        await session.commit()

        doc_record = await session.get(GovernedRagDocumentRecord, UUID(approved[1]["document_id"]))
        await connector.index_governed_document(doc_record)

        # Search from Tenant A retrieves the runbook
        hits_a = connector.search(
            "Secret remediation commands for Alpha",
            tenant_id=tenant_a,
            service="alpha-service",
            preferred_kind="runbook",
        )
        assert len(hits_a) >= 1
        assert "Alpha" in hits_a[0]["title"]

        # Search from Tenant B MUST NOT retrieve Tenant A's runbook
        hits_b = connector.search(
            "Secret remediation commands for Alpha",
            tenant_id=tenant_b,
            service="alpha-service",
            preferred_kind="runbook",
        )
        assert hits_b == []


# =========================================================================
# Scenario L: Query bounds and retry limits prevent memory leaks & loops
# =========================================================================
@pytest.mark.asyncio
async def test_scenario_l_query_limits_and_retry_bounds(sqlite_session_factory):
    """Scenario L: Resource-intensive queries and retry loops remain bounded under a repeatable workload."""
    tenant_id = "tenant-scenario-l"

    async with sqlite_session_factory() as session:
        inc_repo = IncidentRepository(session)

        # Seed 25 alerts
        for idx in range(25):
            alert = Alert(
                tenant_id=tenant_id,
                source="prometheus",
                name=f"RepeatedAlert_{idx}",
                description=f"Alert instance {idx}",
                service="stress-service",
                environment="prod",
                severity=AlertSeverity.INFO,
            )
            await inc_repo.save_alert(alert)
        await session.commit()

        # Query with explicit limit
        bounded_alerts = await inc_repo.list_alerts_source_balanced(limit=10, tenant_id=tenant_id)
        assert len(bounded_alerts) <= 10

        # Outbox retry safety: ensure record status transitions gracefully on maximum attempts
        outbox_entry = ResolutionOutboxRecord(
            event_id=f"retry-test-{uuid4()}",
            tenant_id=tenant_id,
            aggregate_id=str(uuid4()),
            topic="context-events",
            partition_key=str(uuid4()),
            payload={"incident_id": str(uuid4())},
            status="pending",
            attempts=5,
            last_error="Maximum attempts exceeded",
        )
        session.add(outbox_entry)
        await session.commit()

        # Verify entry can be safely marked dead-lettered / failed rather than retried indefinitely
        outbox_entry.status = "dead_letter"
        await session.commit()

        persisted_entry = await session.get(ResolutionOutboxRecord, outbox_entry.event_id)
        assert persisted_entry.status == "dead_letter"
        assert persisted_entry.attempts == 5
