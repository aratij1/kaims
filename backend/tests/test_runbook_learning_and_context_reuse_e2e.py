from __future__ import annotations

from datetime import UTC, datetime, timedelta
import importlib.util
from pathlib import Path
import sys
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

ROOT = Path(__file__).resolve().parents[2]
for rel in (
    "backend/src/common",
    "ai-workbench/src/common",
    "ai-workbench/src/context-agent",
    "ai-workbench/src/resolution-agent",
):
    candidate = str(ROOT / rel)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from ai_workbench_common.models import Context
from common.context_enrichment_contract import (
    HumanEvidenceResponse,
    build_evidence_requirements,
)
from common.database import (
    CanonicalEvidenceRecord,
    ContextSnapshotRecord,
    IncidentInvestigationBindingRecord,
    IncidentProjectionRecord,
    IncidentRecord,
    KnowledgeRagDraftRecord,
    ResolutionOutboxRecord,
    RunbookRecord,
    RunbookVersionRecord,
)
from common.models import Alert, AlertSeverity
from common.repository import ContextEnrichmentRepository, IncidentRepository
from context_agent.context_quality import assess_context
from resolution_agent.catalog import register_learned_runbooks


def _load_module(name: str, rel_path: str):
    path = ROOT / rel_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


context_agent_module = _load_module("context_agent_e2e_learning_app", "ai-workbench/src/context-agent/app.py")
resolution_agent_module = _load_module("resolution_agent_e2e_learning_app", "ai-workbench/src/resolution-agent/app.py")


class _OfflineModelGateway:
    async def generate(self, request):
        raise RuntimeError("offline unit test - use deterministic fallback")


async def _noop_async(*_args, **_kwargs):
    return None


resolution_agent_module.agent.model_gateway = _OfflineModelGateway()
resolution_agent_module.agent.runtime.max_attempts = 1
resolution_agent_module.agent._judge_groundedness = _noop_async
resolution_agent_module.agent._publish_evaluation = lambda **_kwargs: None
resolution_agent_module._ensure_global_knowledge_loaded = _noop_async


async def _seed_incident_and_snapshot(
    session,
    *,
    tenant_id: str,
    incident_id: UUID,
    alert: Alert,
    runbook: str = "",
    document_available: bool = False,
) -> tuple[Context, UUID]:
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
            payload={
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
            quality_score=0.42,
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

    enrichment_repo = ContextEnrichmentRepository(session)
    reqs = build_evidence_requirements(
        tenant_id=tenant_id,
        incident_id=incident_id,
        rca_version=1,
        missing_evidence=[
            {
                "category": "runbook",
                "question": f"Provide the verified runbook and remediation steps for {alert.service} {alert.name}.",
                "reason": "No matching runbook or reusable context exists for this alert signature.",
                "collection_mode": "human_required",
                "candidate_connectors": [],
            }
        ],
        now=now,
    )
    await enrichment_repo.upsert_context_evidence_requirements(reqs)
    req = reqs[0]
    await enrichment_repo.create_human_evidence_request(
        tenant_id=tenant_id,
        incident_id=incident_id,
        requirement_id=req.requirement_id,
        expected_responder="sre-oncall@example.com",
        assignment_source="on_call",
        due_at=now + timedelta(hours=1),
        acceptable_format="Verified runbook observation and remediation steps",
        evidence_already_checked=["telemetry"],
        hypothesis_impact=req.reason,
        automatic_fallback=True,
    )
    await session.commit()
    return context, req.requirement_id


@pytest.mark.asyncio
async def test_complete_missing_runbook_learning_and_reuse_e2e_workflow(
    sqlite_session_factory,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Verifies the complete end-to-end workflow:
    1. First incident with no runbook -> identifies missing required info and asks user only for missing details
    2. Human submits missing information -> resumes investigation
    3. Structured, reusable runbook is created, approved, persisted, and indexed into Qdrant
    4. Enriched context becomes reusable (snapshot + ContextKnowledgeRecord + context_quality flags)
    5. RCA, business & technical impact, prioritized next actions, and recommended + actual resolution generated
    6. Second similar incident retrieves saved runbook + reusable context without repeating answered questions
    7. RCA, business & technical impact, prioritized next actions, and resolution generated for second incident
    8. Risky remediation actions are gated by governance/approval policy even when a runbook exists
    """
    monkeypatch.setattr(context_agent_module.settings, "database_enabled", True)
    context_agent_module.app.state.session_factory = sqlite_session_factory
    resolution_agent_module.app.state.session_factory = None
    resolution_agent_module.app.state.session_factory = None
    indexed_documents: list[dict[str, Any]] = []

    async def _mock_index_governed_document(_app, doc: dict[str, Any]) -> None:
        indexed_documents.append(doc)

    monkeypatch.setattr(context_agent_module, "_index_governed_document", _mock_index_governed_document)

    tenant_id = "tenant-e2e-learn"
    service = "checkout-api"
    environment = "prod"
    alert_name = "RedisConnectionPoolExhausted"

    # -------------------------------------------------------------------------
    # STEP 1: First incident arrives with NO runbook and NO reusable context
    # -------------------------------------------------------------------------
    incident_1_id = uuid4()
    alert_1 = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name=alert_name,
        description="checkout-api Redis connection pool exhausted (active=500/500, timeout rate 38% on checkout-redis-primary)",
        severity=AlertSeverity.CRITICAL,
        service=service,
        environment=environment,
        labels={
            "alertname": alert_name,
            "service": service,
            "namespace": "prod",
            "pod": "checkout-api-7f8b9c-x2k9p",
        },
    )

    async with sqlite_session_factory() as session:
        initial_context_1, requirement_1_id = await _seed_incident_and_snapshot(
            session,
            tenant_id=tenant_id,
            incident_id=incident_1_id,
            alert=alert_1,
            runbook="",
            document_available=False,
        )

    initial_quality = assess_context(initial_context_1)
    assert initial_quality["reusable"] is False
    assert initial_quality["rca_ready"] is False

    _, initial_report_1 = await resolution_agent_module.investigate_context(initial_context_1)
    assert initial_report_1.get("conclusive") is False

    # -------------------------------------------------------------------------
    # STEP 2: Human submits missing information via respond_to_context_gap
    # -------------------------------------------------------------------------
    human_payload = HumanEvidenceResponse(
        response=(
            "Root cause is leaked Redis connections in checkout-api worker threads after upstream timeout spikes. "
            "Drain stale connections and perform a rolling restart of deployment/checkout-api in namespace prod."
        ),
        responder_id="sre-oncall@example.com",
        responded_at=datetime.now(UTC),
        observed_symptoms=(
            "Redis connection pool saturated at 500/500 connections with HTTP 504 gateway timeouts on checkout-api pods."
        ),
        root_cause=(
            "checkout-api Redis connection pool exhaustion caused by unclosed client sessions during flash-sale "
            "retry storms against checkout-redis-primary."
        ),
        business_impact="Checkout completion rate dropped by 38% for production shoppers.",
        remediation_steps=(
            "1. Verify active client connections on checkout-redis-primary via redis-cli info clients\n"
            "2. Restart deployment:\n"
            "`kubectl rollout restart deployment/checkout-api -n prod`\n"
            "`kubectl rollout status deployment/checkout-api -n prod --timeout=120s`"
        ),
        verification_steps=(
            "1. Confirm checkout_redis_pool_active_connections drops below 150\n"
            "2. Confirm checkout HTTP 5xx error rate returns below 0.5% for 5 minutes"
        ),
        rollback_plan="1. `kubectl rollout undo deployment/checkout-api -n prod`",
        auto_approve_runbook=True,
    )

    response_1 = await context_agent_module.respond_to_context_gap(
        str(incident_1_id),
        str(requirement_1_id),
        human_payload,
        tenant_id=tenant_id,
    )

    # -------------------------------------------------------------------------
    # STEP 3 & 4: Verify runbook creation, persistence, Qdrant indexing, and reusable context
    # -------------------------------------------------------------------------
    assert response_1["learning_complete"] is True
    assert response_1["indexing_status"] == "indexed"
    assert response_1.get("governed_document") is not None
    assert len(indexed_documents) == 1
    assert indexed_documents[0]["tenant_id"] == tenant_id
    assert indexed_documents[0]["document_id"] == response_1["governed_document"]["document_id"]

    async with sqlite_session_factory() as session:
        gov_docs = (
            await session.execute(
                select(KnowledgeRagDraftRecord).where(
                    KnowledgeRagDraftRecord.tenant_id == tenant_id,
                    # KnowledgeRagDraftRecord filtered by tenant_id
                )
            )
        ).scalars().all()
        assert len(gov_docs) == 1
        assert gov_docs[0].status in {"approved", "approved_pending_index"}
        assert "## Validation" in gov_docs[0].content
        assert "## Rollback" in gov_docs[0].content

        rb_records = (
            await session.execute(
                select(RunbookRecord).where(
                    RunbookRecord.tenant_id == tenant_id,
                    RunbookRecord.service == service,
                )
            )
        ).scalars().all()
        assert len(rb_records) == 1
        assert rb_records[0].service == service

        rb_versions = (
            await session.execute(
                select(RunbookVersionRecord).where(
                    RunbookVersionRecord.tenant_id == tenant_id,
                    RunbookVersionRecord.runbook_id == rb_records[0].runbook_id,
                )
            )
        ).scalars().all()
        assert len(rb_versions) == 1
        assert rb_versions[0].approval_status == "approved"

        latest_snap_1 = (
            await session.execute(
                select(ContextSnapshotRecord)
                .where(ContextSnapshotRecord.incident_id == str(incident_1_id))
                .order_by(ContextSnapshotRecord.snapshot_version.desc())
            )
        ).scalars().first()
        assert latest_snap_1 is not None
        assert latest_snap_1.reusable is True
        assert latest_snap_1.quality_score >= 0.70

        outbox_rows = (
            await session.execute(
                select(ResolutionOutboxRecord).where(
                    ResolutionOutboxRecord.aggregate_id == str(incident_1_id),
                )
            )
        ).scalars().all()
        assert len(outbox_rows) >= 1

        inc_repo = IncidentRepository(session)
        learned_runbooks = await inc_repo.find_learned_runbooks(
            tenant_id=tenant_id,
            service=service,
            alert_name=alert_name,
            environment=environment,
        )
        assert len(learned_runbooks) >= 1
        register_learned_runbooks(
            tenant_id=tenant_id,
            issue=f"{alert_name} {alert_1.description}",
            service=service,
            alert_name=alert_name,
            runbooks=learned_runbooks,
        )

        reusable_ctx = await inc_repo.find_context_knowledge(
            tenant_id=tenant_id,
            service=service,
            environment=environment,
            alert_signature=f"{alert_name.lower()}|{service.lower()}|{environment.lower()}", not_before=datetime.now(UTC) - timedelta(hours=1),
            alert_name=alert_name,
        )
        assert reusable_ctx is not None

    # -------------------------------------------------------------------------
    # STEP 5: Verify resumed investigation for Incident 1 generates RCA, Impact,
    #         Prioritized Next Actions, and Recommended + Actual Resolution
    # -------------------------------------------------------------------------
    enriched_context_1 = Context.model_validate(response_1["context"])
    quality_after_human = assess_context(enriched_context_1)
    assert quality_after_human["reusable"] is True
    assert quality_after_human["rca_ready"] is True
    assert quality_after_human["impact_ready"] is True

    _, resumed_report_1 = await resolution_agent_module.investigate_context(enriched_context_1)
    rec_1 = await resolution_agent_module._resolve_context(enriched_context_1)

    assert resumed_report_1.get("conclusive") is True
    assert rec_1.root_cause
    assert "redis" in rec_1.root_cause.lower()
    assert rec_1.metadata.get("impact_analysis", {}).get("business_impact")
    assert rec_1.metadata.get("impact_analysis", {}).get("technical_impact")
    assert rec_1.metadata.get("next_actions", {}).get("prioritized_actions")
    assert rec_1.metadata.get("recommended_resolution", {}).get("steps")
    assert rec_1.metadata.get("actual_resolution", {}).get("status") in {
        "verified_by_operator",
        "pending_execution_verification",
    }

    # Governance safety policy: rollout restart is a mutating action and must not auto-execute blindly
    gov_policy_1 = rec_1.metadata.get("governance_policy", {})
    assert gov_policy_1.get("requires_approval") is True
    assert gov_policy_1.get("auto_execution_allowed") is False

    # -------------------------------------------------------------------------
    # STEP 6: Subsequent similar incident arrives -> retrieves saved runbook and
    #         reusable context without asking for already-answered information
    # -------------------------------------------------------------------------
    incident_2_id = uuid4()
    alert_2 = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name=alert_name,
        description="checkout-api Redis connection pool exhausted (active=500/500, timeout rate 41% on checkout-redis-primary)",
        severity=AlertSeverity.CRITICAL,
        service=service,
        environment=environment,
        labels={
            "alertname": alert_name,
            "service": service,
            "namespace": "prod",
            "pod": "checkout-api-7f8b9c-z9m4q",
        },
    )

    reusable_payload = reusable_ctx.get("payload") if isinstance(reusable_ctx.get("payload"), dict) else {}
    reusable_meta = reusable_payload.get("metadata") if isinstance(reusable_payload.get("metadata"), dict) else {}

    context_2 = Context(
        tenant_id=tenant_id,
        incident_id=incident_2_id,
        alert=alert_2,
        runbook=gov_docs[0].content,
        metadata={
            "document_available": True, "analysis_request_id": str(uuid4()),
            "matched_learned_runbook": learned_runbooks[0],
            "learned_runbooks": learned_runbooks,
            "historical_human_guidance": reusable_meta.get("human_guided_input"),
            "context_evidence": {
                "telemetry": [
                    {
                        "evidence_id": f"alert:{alert_2.id}",
                        "source": "telemetry",
                        "connector": "alert-receiver",
                        "service": service,
                        "snippet": alert_2.description,
                        "relevant_content": alert_2.description,
                        "observed_at": datetime.now(UTC).isoformat(),
                    }
                ],
                "runbook": [
                    {
                        "evidence_id": f"runbook:{learned_runbooks[0]['runbook_id']}",
                        "source": "runbook",
                        "connector": "governed_runbook_registry",
                        "source_reference": f"runbook://{learned_runbooks[0]['runbook_id']}@v1",
                        "service": service,
                        "snippet": gov_docs[0].content[:400],
                        "relevant_content": gov_docs[0].content[:400],
                        "observed_at": datetime.now(UTC).isoformat(),
                    }
                ],
            },
        },
    )

    quality_2 = assess_context(context_2)
    assert quality_2["reusable"] is True
    assert quality_2["rca_ready"] is True
    assert quality_2["impact_ready"] is True

    investigated_ctx_2, report_2 = await resolution_agent_module.investigate_context(context_2)
    rec_2 = await resolution_agent_module._resolve_context(investigated_ctx_2)

    # Must validate learned runbook against current evidence and NOT ask duplicate questions
    assert investigated_ctx_2.metadata.get("runbook_validation", {}).get("validated") is True
    assert report_2.get("conclusive") is True
    assert not report_2.get("followup_questions")
    assert rec_2.root_cause
    assert rec_2.metadata.get("impact_analysis", {}).get("business_impact")
    assert rec_2.metadata.get("impact_analysis", {}).get("technical_impact")
    assert rec_2.metadata.get("next_actions", {}).get("prioritized_actions")
    assert rec_2.metadata.get("recommended_resolution", {}).get("steps")
    assert rec_2.metadata.get("runbook_validation", {}).get("validated") is True
    assert rec_2.metadata.get("governance_policy", {}).get("auto_execution_allowed") is False


@pytest.mark.asyncio
async def test_conflicting_evidence_on_similar_incident_triggers_followup_questions():
    """
    Verifies that when a subsequent incident shares the same service/alert name
    but current evidence contradicts the learned runbook (e.g. TLS certificate
    expiration or OOMKilled instead of Redis pool leak), KaiMS does NOT blindly
    reuse the learned root cause and instead triggers follow-up questions.
    """
    tenant_id = "tenant-conflict-check"
    service = "checkout-api"
    alert_name = "RedisConnectionPoolExhausted"

    learned_rb = {
        "runbook_id": "rb-checkout-redis-pool-v1",
        "version": 1,
        "title": "Runbook: checkout-api - RedisConnectionPoolExhausted",
        "service": service,
        "alert_name": alert_name,
        "environment": "prod",
        "approval_status": "approved",
        "root_cause_guidance": "Leaked Redis client connections in checkout-api worker pool during retry storms.",
        "business_impact": "Checkout latency and HTTP 504 errors for shoppers.",
        "observed_symptoms": "Redis connection pool saturated at 500/500 active sockets.",
        "steps": ["kubectl rollout restart deployment/checkout-api -n prod"],
        "markdown": (
            "# Runbook: checkout-api - RedisConnectionPoolExhausted\n"
            "## Observed Symptoms & Root Cause\n"
            "Leaked Redis client connections in checkout-api worker pool.\n"
            "## Remediation Steps\n"
            "1. `kubectl rollout restart deployment/checkout-api -n prod`\n"
        ),
        "content": {
            "service": service,
            "alert_name": alert_name,
            "title": "Runbook: checkout-api - RedisConnectionPoolExhausted",
            "root_cause": "Leaked Redis client connections in checkout-api worker pool during retry storms.",
            "remediation_steps": ["kubectl rollout restart deployment/checkout-api -n prod"],
            "markdown": (
                "# Runbook: checkout-api - RedisConnectionPoolExhausted\n"
                "## Observed Symptoms & Root Cause\n"
                "Leaked Redis client connections in checkout-api worker pool.\n"
                "## Remediation Steps\n"
                "1. `kubectl rollout restart deployment/checkout-api -n prod`\n"
            ),
        },
    }

    alert_conflict = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name=alert_name,
        description="TLS certificate expired on checkout-redis-primary: x509 certificate has expired",
        severity=AlertSeverity.CRITICAL,
        service=service,
        environment="prod",
        labels={"alertname": alert_name, "service": service, "namespace": "prod"},
    )

    conflict_context = Context(
        tenant_id=tenant_id,
        incident_id=uuid4(),
        alert=alert_conflict,
        runbook=learned_rb["markdown"],
        metadata={
            "document_available": True, "analysis_request_id": str(uuid4()),
            "matched_learned_runbook": learned_rb,
            "learned_runbooks": [learned_rb],
            "conflicting_evidence": (
                "Learned runbook assumes leaked Redis connections, but current logs show x509 TLS certificate expired on checkout-redis-primary."
            ),
        },
    )

    investigated_ctx, report = await resolution_agent_module.investigate_context(conflict_context)
    validation = investigated_ctx.metadata.get("runbook_validation", {})
    assert validation.get("validated") is False
    assert validation.get("status") in {"conflicting_evidence", "divergent_evidence"}
    assert report.get("conclusive") is False
    assert len(validation.get("followup_questions", [])) >= 1


@pytest.mark.asyncio
async def test_failed_qdrant_indexing_does_not_falsely_report_successful_learning(
    sqlite_session_factory,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Verifies that if Qdrant indexing fails when saving/approving a learned runbook,
    the response explicitly reports indexing_status='failed' and learning_complete=False.
    """
    monkeypatch.setattr(context_agent_module.settings, "database_enabled", True)
    context_agent_module.app.state.session_factory = sqlite_session_factory

    async def _failing_index_governed_document(_app, _doc: dict[str, Any]) -> None:
        raise RuntimeError("Qdrant collection connection refused")

    monkeypatch.setattr(context_agent_module, "_index_governed_document", _failing_index_governed_document)

    tenant_id = "tenant-index-fail"
    incident_id = uuid4()
    alert = Alert(
        tenant_id=tenant_id,
        source="prometheus",
        name="PaymentGatewayTimeout",
        description="payment-service upstream gateway timeout rate > 25%",
        severity=AlertSeverity.CRITICAL,
        service="payment-service",
        environment="prod",
        labels={"alertname": "PaymentGatewayTimeout", "service": "payment-service", "namespace": "prod"},
    )

    async with sqlite_session_factory() as session:
        _, requirement_id = await _seed_incident_and_snapshot(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert=alert,
            runbook="",
            document_available=False,
        )

    human_payload = HumanEvidenceResponse(
        response="Failover payment-service upstream endpoint and restart deployment.",
        responder_id="sre-oncall@example.com",
        responded_at=datetime.now(UTC),
        observed_symptoms="Upstream HTTPS connection timeouts on payment-service pods.",
        root_cause="Primary payment gateway regional endpoint degraded.",
        business_impact="Card payments failing for 25% of checkout requests.",
        remediation_steps="`kubectl rollout restart deployment/payment-service -n prod`",
        auto_approve_runbook=True,
    )

    response = await context_agent_module.respond_to_context_gap(
        str(incident_id),
        str(requirement_id),
        human_payload,
        tenant_id=tenant_id,
    )

    assert response["indexing_status"] == "failed"
    assert response["learning_complete"] is False
    assert "Qdrant collection connection refused" in (response.get("indexing_error") or "")
