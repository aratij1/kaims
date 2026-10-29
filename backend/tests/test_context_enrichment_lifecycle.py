from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from ai_workbench_common.models import Context
from common.context_enrichment_contract import (
    EvidenceRecord,
    EvidenceRequirement,
    HitlRoutingConfiguration,
    build_evidence_requirements,
    initial_causal_collection_gaps,
    validate_enrichment_observation,
)
from common.database import (
    ContextEnrichmentJobRecord,
    ActionRecord,
    ApprovalRecord,
    AuditLogRecord,
    CanonicalEvidenceRecord,
    ContextSnapshotRecord,
    ContextReconciliationRunRecord,
    IncidentLifecycleTransitionRecord,
    IncidentProjectionRecord,
    IncidentInvestigationBindingRecord,
    IncidentRecord,
    RcaReportRecord,
    ResolutionOutboxRecord,
)
from common.incident_command_contract import build_incident_command_workspace
from common.models import Alert, AlertSeverity, Incident
from common.repository import ContextEnrichmentRepository, IncidentRepository
from context_agent.connectors import execute_enrichment_plan
from context_agent.context_quality import plan_missing_evidence
from sqlalchemy import select


@pytest.mark.asyncio
async def test_new_rca_retires_old_queued_jobs_but_preserves_live_collectors_and_other_tenants(sqlite_session_factory):
    now = datetime.now(UTC)
    incident_id = uuid4()
    def requirement(version, tenant="tenant-a"):
        return build_evidence_requirements(tenant_id=tenant, incident_id=incident_id,
            rca_version=version, missing_evidence=[{"category": "logs", "question": "Which errors preceded the alert?"}], now=now)[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        old, other = requirement(1), requirement(1, "tenant-b")
        await repo.upsert_context_evidence_requirements([old, other])
        async def schedule(req, connector):
            return await repo.schedule_context_enrichment_job(tenant_id=req.tenant_id,
                incident_id=incident_id, requirement_id=req.requirement_id, connector_id=connector,
                query_payload={}, observation_start=now-timedelta(minutes=15), observation_end=now)
        queued = await schedule(old, "discovery-mcp")
        live = await schedule(old, "opensearch")
        live.status = "collecting"
        live.lease_owner = "live-worker"
        live.lease_expires_at = now + timedelta(minutes=2)
        foreign = await schedule(other, "discovery-mcp")
        session.add(IncidentInvestigationBindingRecord(tenant_id="tenant-a", project_id="project-a",
            incident_id=incident_id, alert_id=uuid4(), analysis_request_id=uuid4(),
            context_snapshot_id=uuid4(), context_fingerprint="c"*64, recommendation_id=uuid4(),
            rca_version=2, status="insufficient_evidence", created_at=now, expires_at=now+timedelta(hours=1)))
        await session.flush()
        # Do not discard work while the new RCA's gap set is not persisted.
        assert (await repo.retire_superseded_collection_jobs(tenant_id="tenant-a", incident_id=incident_id))["jobs_retired"] == 0
        current = requirement(2)
        await repo.upsert_context_evidence_requirements([current])
        new_job = await schedule(current, "discovery-mcp")
        await session.commit()
        assert queued.status == "cancelled"
        assert queued.last_error == "SUPERSEDED_EVIDENCE_REQUIREMENT"
        assert live.status == "collecting" and live.lease_owner == "live-worker"
        assert foreign.status == "scheduled"
        assert new_job.status == "scheduled"


def context_for(incident_id, *, tenant_id="tenant-a") -> Context:
    alert = Alert(
        tenant_id=tenant_id, source="prometheus", name="LatencyHigh",
        service="checkout-api", environment="prod", severity=AlertSeverity.CRITICAL,
        description="p99 latency is above threshold",
    )
    return Context(tenant_id=tenant_id, incident_id=incident_id, alert=alert)


def test_duplicate_rca_gaps_produce_one_durable_requirement() -> None:
    incident_id = uuid4()
    gap = {"category": "logs", "question": "Which errors preceded the alert?"}

    requirements = build_evidence_requirements(
        tenant_id="tenant-a",
        incident_id=incident_id,
        rca_version=3,
        missing_evidence=[gap, gap],
        now=datetime.now(UTC),
    )

    assert len(requirements) == 1


def test_initial_causal_collection_wave_is_complete_and_deterministic() -> None:
    incident_id = uuid4()
    gaps = initial_causal_collection_gaps()
    requirements = build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=1,
        missing_evidence=gaps, now=datetime.now(UTC),
    )

    assert [row.category for row in requirements] == ["traces", "topology", "topology"]
    assert "dependency health" in requirements[1].question.lower()
    assert len({row.requirement_id for row in requirements}) == 3
    assert all("discovery-mcp" in row.candidate_connectors for row in requirements)


def test_external_synthetic_probe_does_not_require_internal_topology() -> None:
    gaps = initial_causal_collection_gaps(
        source="public-internet-blackbox",
        environment="public-internet",
    )

    assert [row["category"] for row in gaps] == ["metrics"]
    assert "HTTP status" in gaps[0]["question"]
    assert "prometheus" in gaps[0]["candidate_connectors"]


def test_trace_gap_rejects_metric_only_observation() -> None:
    incident_id = uuid4()
    context = context_for(incident_id)
    now = datetime.now(UTC)
    requirement = EvidenceRequirement(
        requirement_id=uuid4(), tenant_id="tenant-a", incident_id=incident_id,
        rca_version=1, category="traces", question="Which span failed?", reason="Test the causal path",
        priority="high", collection_mode="automatic", candidate_connectors=["jaeger"],
        created_at=now, updated_at=now,
    )
    result = validate_enrichment_observation(
        requirement, "jaeger", {
            "evidence": [{"category": "metrics", "metric_name": "latency", "value": 4,
                          "source_uri": "prometheus://latency", "collected_at": now.isoformat()}],
        }, Incident(id=incident_id, tenant_id="tenant-a", service="checkout-api", title="test"),
        context.alert, now,
    )
    assert result.accepted is False
    assert "does not match traces" in result.rejection_reasons[0]


def test_trace_gap_accepts_attributable_trace_and_redacts_secrets() -> None:
    incident_id = uuid4()
    context = context_for(incident_id)
    now = datetime.now(UTC)
    requirement = EvidenceRequirement(
        requirement_id=uuid4(), tenant_id="tenant-a", incident_id=incident_id,
        rca_version=1, category="traces", question="Which span failed?", reason="Test the causal path",
        priority="high", collection_mode="automatic", candidate_connectors=["jaeger"],
        created_at=now, updated_at=now,
    )
    result = validate_enrichment_observation(
        requirement, "jaeger", {"spans": [{
            "category": "traces", "trace_id": "trace-1", "span_id": "span-1",
            "service": "checkout-api", "tenant_id": "tenant-a", "timestamp": now.isoformat(),
            "source_uri": "jaeger://trace/trace-1", "token": "do-not-persist",
        }]}, Incident(id=incident_id, tenant_id="tenant-a", service="checkout-api", title="test"), context.alert, now,
    )
    assert result.accepted is True
    assert result.accepted_evidence[0]["token"] == "[REDACTED]"
    assert result.accepted_evidence[0]["category"] == "traces"


@pytest.mark.asyncio
async def test_missing_automatic_evidence_creates_idempotent_enrichment_jobs(
    sqlite_session_factory,
):
    incident_id = uuid4()
    requirements = await plan_missing_evidence(
        context_for(incident_id),
        {"tenant_id": "tenant-a", "incident_id": str(incident_id), "rca_version": 2,
         "missing_evidence": [{"category": "logs", "question": "Which errors preceded the alert?"}]},
    )
    result = await execute_enrichment_plan(requirements, authorized_connectors={"opensearch"})
    assert result.scheduled_requirement_ids == [requirements[0].requirement_id]

    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements(requirements)
        first = await repo.schedule_context_enrichment_job(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=requirements[0].requirement_id, connector_id="opensearch",
            query_payload={"service": "checkout-api", "environment": "prod"},
            observation_start=now - timedelta(minutes=20), observation_end=now + timedelta(seconds=1),
        )
        second = await repo.schedule_context_enrichment_job(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=requirements[0].requirement_id, connector_id="opensearch",
            query_payload={"service": "checkout-api", "environment": "prod"},
            observation_start=now - timedelta(minutes=10), observation_end=now,
        )
        assert first.job_id == second.job_id
        job_id = first.job_id
        await session.commit()

    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        claimed = await repo.claim_context_enrichment_jobs(worker_id="worker-a", limit=1)
        assert claimed[0]["job_id"] == str(job_id)
        assert claimed[0]["attempt_count"] == 1
        assert claimed[0]["lease_owner"] == "worker-a"
        with pytest.raises(RuntimeError, match="lease is not owned"):
            await repo.finish_context_enrichment_job(
                job_id=job_id, worker_id="worker-b", collected=True,
            )
        await repo.finish_context_enrichment_job(
            job_id=job_id, worker_id="worker-a", collected=True,
        )
        activity = await repo.list_context_enrichment_activity(
            tenant_id="tenant-a", incident_id=incident_id,
        )
        assert activity["jobs"][0]["status"] == "collected"
        assert activity["jobs"][0]["lease_owner"] is None


def test_requirement_identity_normalizes_question_case_and_whitespace() -> None:
    incident_id = uuid4()
    now = datetime.now(UTC)
    first = build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=3,
        missing_evidence=[{"category": "logs", "question": "Which errors preceded the alert?"}],
        now=now,
    )[0]
    second = build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=3,
        missing_evidence=[{"category": "logs", "question": "  WHICH   ERRORS preceded the ALERT? "}],
        now=now,
    )[0]

    assert first.requirement_id == second.requirement_id
    assert second.question == "WHICH ERRORS preceded the ALERT?"


@pytest.mark.asyncio
async def test_failed_human_evidence_jira_sync_observes_retry_cooldown(
    sqlite_session_factory,
):
    incident_id = uuid4()
    requirement = build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=1,
        missing_evidence=[{"category": "runbook", "question": "Which approved runbook applies?"}],
        now=datetime.now(UTC),
    )[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([requirement])
        request = await repo.create_human_evidence_request(
            tenant_id="tenant-a", incident_id=incident_id, requirement_id=requirement.requirement_id,
            expected_responder="platform-ops", assignment_source="service_ownership",
            due_at=datetime.now(UTC) + timedelta(hours=1), acceptable_format="A governed runbook URL.",
            evidence_already_checked=["vector-db"], hypothesis_impact="RCA requires an approved runbook.",
        )
        await session.commit()

        claimed = await repo.claim_human_evidence_jira_requests(limit=1)
        assert [row["request_id"] for row in claimed] == [str(request.request_id)]
        await repo.fail_human_evidence_jira_sync(request_id=request.request_id, error="upstream unavailable")
        await session.commit()

        assert await repo.claim_human_evidence_jira_requests(limit=1) == []
        request.updated_at = datetime.now(UTC) - timedelta(minutes=6)
        await session.commit()
        assert len(await repo.claim_human_evidence_jira_requests(limit=1)) == 1


@pytest.mark.asyncio
async def test_operations_state_selects_current_requirement_and_latest_job(
    sqlite_session_factory,
):
    incident_id = uuid4()
    now = datetime.now(UTC)
    old_requirement, current_requirement = build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=1,
        missing_evidence=[{"category": "logs", "question": "What failed previously?"}], now=now,
    )[0], build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=2,
        missing_evidence=[{"category": "metrics", "question": "What is failing now?"}], now=now,
    )[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="checkout-api", environment="prod",
            severity="critical", status="investigating", title="Checkout latency", payload={},
        ))
        # Simulate the normal asynchronous lag where evidence work has
        # advanced but the incident projection still says DETECTED.
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, tenant_id="tenant-a", service="checkout-api",
            environment="prod", severity="critical", status="investigating",
            lifecycle_state="DETECTED", first_seen_at=now, projection_payload={},
        ))
        await repo.upsert_context_evidence_requirements([old_requirement, current_requirement])
        first = await repo.schedule_context_enrichment_job(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=current_requirement.requirement_id, connector_id="prometheus-a",
            query_payload={"query": "up"}, observation_start=now - timedelta(minutes=5), observation_end=now,
        )
        second = await repo.schedule_context_enrichment_job(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=current_requirement.requirement_id, connector_id="prometheus-b",
            query_payload={"query": "rate(errors[5m])"},
            observation_start=now - timedelta(minutes=5), observation_end=now,
        )
        first.created_at = now - timedelta(seconds=1)
        second.created_at = now
        await session.commit()

        state = await repo.incident_operations_state(tenant_id="tenant-a", incident_id=incident_id)

    assert state is not None
    assert state["lifecycle_state"] == "COLLECTING"
    assert state["investigation"]["rca_version"] == 0
    assert state["approval"] == {
        "approval_id": None,
        "incident_id": str(incident_id),
        "recommendation_id": None,
        "plan_id": None,
        "plan_fingerprint": None,
        "status": "not_requested",
        "approver": None,
        "approver_role": None,
        "expires_at": None,
        "updated_at": None,
        "blocked_reasons": ["RCA_NOT_READY"],
    }
    assert [row["requirement_id"] for row in state["requirements"]] == [str(current_requirement.requirement_id)]
    assert state["requirements"][0]["latest_job"]["job_id"] == str(second.job_id)
    assert state["requirement_history"][0]["requirement_id"] == str(old_requirement.requirement_id)
    assert state["next_action"]["type"] == "AUTONOMOUS_COLLECTION"
    workspace = state["investigation_workspace"]
    assert workspace["schema_version"] == "kaiops.investigation-workspace.v1"
    assert workspace["binding"]["incident_id"] == str(incident_id)
    assert workspace["binding"]["analysis_request_id"] is None
    assert workspace["binding"]["context_snapshot_id"] is None
    assert workspace["binding"]["context_fingerprint"] is None
    assert workspace["rca"]["status"] == "not_started"
    assert workspace["resolution"]["status"] == "blocked"
    assert workspace["operator_review"]["required"] is True
    assert workspace["requirements"][0]["requirement_id"] == str(current_requirement.requirement_id)


@pytest.mark.asyncio
async def test_operations_state_is_tenant_scoped(sqlite_session_factory):
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="checkout-api", environment="prod",
            severity="critical", status="investigating", title="Checkout latency", payload={},
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, tenant_id="tenant-a", service="checkout-api",
            environment="prod", status="investigating", first_seen_at=datetime.now(UTC),
            projection_payload={},
        ))
        await session.commit()
        repository = ContextEnrichmentRepository(session)
        assert await repository.incident_operations_state(
            tenant_id="tenant-b", incident_id=incident_id,
        ) is None
        assert await repository.enabled_reconciliation_tenants() == ["tenant-a"]


@pytest.mark.asyncio
async def test_operations_state_selects_current_execution_and_validation_lineage(
    sqlite_session_factory,
):
    incident_id, alert_id = uuid4(), uuid4()
    recommendation_id, plan_id, approval_id, action_id = uuid4(), uuid4(), uuid4(), uuid4()
    snapshot_id, analysis_id = uuid4(), uuid4()
    plan_fingerprint = "sha256:" + "a" * 64
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="checkout-api", environment="prod",
            severity="critical", status="validating", title="Checkout latency", payload={},
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=alert_id, tenant_id="tenant-a",
            service="checkout-api", environment="prod", severity="critical",
            status="validating", lifecycle_state="VALIDATING", first_seen_at=now,
            projection_payload={},
        ))
        session.add(IncidentInvestigationBindingRecord(
            tenant_id="tenant-a", project_id="project-a", incident_id=incident_id,
            alert_id=alert_id, analysis_request_id=analysis_id, context_snapshot_id=snapshot_id,
            context_fingerprint="c" * 64, recommendation_id=recommendation_id,
            rca_version=2, resolution_plan_id=plan_id, plan_fingerprint=plan_fingerprint,
            status="grounded", created_at=now, expires_at=now + timedelta(hours=1),
        ))
        session.add(AuditLogRecord(
            id=recommendation_id, tenant_id="tenant-a", actor="resolution-agent",
            action="recommendation.generated", resource_type="incident",
            resource_id=str(incident_id), payload={"confidence": 0.9, "metadata": {
                "quality_gate": {"passed": True},
            }},
        ))
        session.add(ApprovalRecord(
            id=approval_id, tenant_id="tenant-a", incident_id=incident_id,
            recommendation_id=recommendation_id, plan_id=plan_id,
            plan_fingerprint=plan_fingerprint, decision="approved", approver="sre@example.com",
            approval_expires_at=now + timedelta(minutes=30), payload={},
        ))
        session.add(ActionRecord(
            id=action_id, tenant_id="tenant-a", incident_id=incident_id,
            recommendation_id=recommendation_id, resolution_plan_id=plan_id,
            plan_fingerprint=plan_fingerprint, approval_id=approval_id,
            action_type="rollback_deployment", target="checkout-api", status="succeeded", payload={},
        ))
        session.add(ActionRecord(
            id=uuid4(), tenant_id="tenant-a", incident_id=incident_id,
            recommendation_id=uuid4(), resolution_plan_id=uuid4(),
            plan_fingerprint="sha256:" + "b" * 64, approval_id=uuid4(),
            action_type="restart_service", target="stale-target", status="failed", payload={},
        ))
        session.add(RcaReportRecord(
            id=uuid4(), tenant_id="tenant-a", incident_id=incident_id,
            recommendation_id=recommendation_id, resolution_plan_id=plan_id,
            plan_fingerprint=plan_fingerprint, approval_id=approval_id,
            remediation_action_id=action_id, validation_checksum="sha256:" + "d" * 64,
            closure_kind="recovery", closure_status="closed", root_cause="Deployment regression",
            impact="Checkout unavailable", payload={"health_restored": True, "alerts_cleared": True},
        ))
        await session.commit()

        state = await ContextEnrichmentRepository(session).incident_operations_state(
            tenant_id="tenant-a", incident_id=incident_id,
        )

    assert state["execution"]["action_id"] == str(action_id)
    assert state["execution"]["status"] == "succeeded"
    assert state["execution"]["target"] == "checkout-api"
    assert state["validation"]["status"] == "closed"
    assert state["validation"]["health_restored"] is True
    assert state["validation"]["alerts_cleared"] is True


@pytest.mark.asyncio
async def test_incident_lifecycle_transition_is_atomic_idempotent_and_versioned(
    sqlite_session_factory,
):
    incident_id, alert_id = uuid4(), uuid4()
    now = datetime.now(UTC)
    requirement = build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=1,
        missing_evidence=[{"category": "metrics", "question": "What is failing?"}], now=now,
    )[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="checkout-api", environment="prod",
            severity="critical", status="investigating", title="Checkout latency", payload={},
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=alert_id, tenant_id="tenant-a",
            service="checkout-api", environment="prod", severity="critical",
            status="investigating", first_seen_at=now, projection_payload={},
        ))
        await repo.upsert_context_evidence_requirements([requirement])
        await session.commit()

        first = await repo.transition_incident_lifecycle(
            tenant_id="tenant-a", incident_id=incident_id,
            target_state="REQUIREMENTS_IDENTIFIED", expected_version=1,
            actor="context-agent", reason="RCA evidence gaps persisted",
            idempotency_key="requirements-v1",
        )
        await session.commit()
        repeated = await repo.transition_incident_lifecycle(
            tenant_id="tenant-a", incident_id=incident_id,
            target_state="REQUIREMENTS_IDENTIFIED", expected_version=1,
            actor="context-agent", reason="ignored on replay",
            idempotency_key="requirements-v1",
        )
        assert first["transition_id"] == repeated["transition_id"]
        assert repeated["idempotent"] is True

        with pytest.raises(RuntimeError, match="STALE_LIFECYCLE_VERSION"):
            await repo.transition_incident_lifecycle(
                tenant_id="tenant-a", incident_id=incident_id,
                target_state="COLLECTING", expected_version=1,
                actor="context-agent", reason="stale writer",
                idempotency_key="collecting-stale",
            )
        await session.rollback()

        projection = await session.get(IncidentProjectionRecord, incident_id)
        assert projection.lifecycle_state == "REQUIREMENTS_IDENTIFIED"
        assert projection.lifecycle_version == 2
        transitions = list((await session.execute(select(IncidentLifecycleTransitionRecord))).scalars())
        assert len(transitions) == 1
        assert await session.get(ResolutionOutboxRecord, f"incident-lifecycle:{first['transition_id']}") is not None


@pytest.mark.asyncio
async def test_incident_lifecycle_rejects_missing_prerequisite_and_failure_code(
    sqlite_session_factory,
):
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, tenant_id="tenant-a", service="checkout-api",
            environment="prod", status="investigating", first_seen_at=datetime.now(UTC),
            projection_payload={},
        ))
        await session.commit()
        with pytest.raises(ValueError, match="REQUIREMENTS_MISSING"):
            await repo.transition_incident_lifecycle(
                tenant_id="tenant-a", incident_id=incident_id,
                target_state="REQUIREMENTS_IDENTIFIED", expected_version=1,
                actor="context-agent", reason="no requirements", idempotency_key="missing",
            )
        await session.rollback()
        with pytest.raises(ValueError, match="failure_code"):
            await repo.transition_incident_lifecycle(
                tenant_id="tenant-a", incident_id=incident_id,
                target_state="COLLECTION_BLOCKED", expected_version=1,
                actor="context-agent", reason="connector exhausted", idempotency_key="blocked",
            )


@pytest.mark.asyncio
async def test_reconciliation_lease_prevents_overlap_and_records_run(sqlite_session_factory):
    async with sqlite_session_factory() as first_session:
        first = ContextEnrichmentRepository(first_session)
        assert await first.claim_reconciliation_lease(
            lease_key="active-incidents", owner="worker-a", lease_seconds=60,
        ) is True
        await first_session.commit()

    async with sqlite_session_factory() as second_session:
        second = ContextEnrichmentRepository(second_session)
        assert await second.claim_reconciliation_lease(
            lease_key="active-incidents", owner="worker-b", lease_seconds=60,
        ) is False
        await second_session.rollback()

    async with sqlite_session_factory() as first_session:
        first = ContextEnrichmentRepository(first_session)
        await first.release_reconciliation_lease(lease_key="active-incidents", owner="worker-a")
        await first_session.commit()

    async with sqlite_session_factory() as second_session:
        second = ContextEnrichmentRepository(second_session)
        assert await second.claim_reconciliation_lease(
            lease_key="active-incidents", owner="worker-b", lease_seconds=60,
        ) is True
        run = await second.start_reconciliation_run(owner="worker-b", tenant_id="tenant-a")
        await second.finish_reconciliation_run(
            run_id=run.run_id,
            summary={"incidents_scanned": 2, "jobs_scheduled": 1, "errors": []},
            status="completed",
        )
        await second_session.commit()
        persisted = await second_session.get(ContextReconciliationRunRecord, run.run_id)
        assert persisted.status == "completed"
        assert persisted.incidents_scanned == 2
        assert persisted.jobs_scheduled == 1
        assert persisted.duration_ms >= 0


@pytest.mark.asyncio
async def test_exhausted_context_job_is_dead_lettered(sqlite_session_factory):
    incident_id = uuid4()
    now = datetime.now(UTC)
    requirement = build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=1,
        missing_evidence=[{"category": "metrics", "question": "What failed?"}], now=now,
    )[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([requirement])
        # An RCA rerun may introduce a newer, unrelated requirement while this
        # collection call is in flight. It must not stale the metric result.
        newer_unrelated = build_evidence_requirements(
            tenant_id="tenant-a", incident_id=incident_id, rca_version=2,
            missing_evidence=[{"category": "topology", "question": "Which dependency is unhealthy?"}],
            now=now,
        )[0]
        await repo.upsert_context_evidence_requirements([newer_unrelated])
        job = await repo.schedule_context_enrichment_job(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=requirement.requirement_id, connector_id="prometheus",
            query_payload={}, observation_start=now - timedelta(minutes=5), observation_end=now,
        )
        await session.commit()
        await repo.claim_context_enrichment_jobs(worker_id="worker-a", limit=1)
        final_status = await repo.finish_context_enrichment_job(
            job_id=job.job_id, worker_id="worker-a", collected=False,
            error="connector unavailable", maximum_attempts=1,
        )
        assert final_status == "dead_letter"
        await session.commit()
        activity = await repo.list_context_enrichment_activity(
            tenant_id="tenant-a", incident_id=incident_id,
        )
        assert activity["jobs"][0]["status"] == "dead_letter"
        assert "connector unavailable" in activity["jobs"][0]["last_error"]


@pytest.mark.asyncio
async def test_scheduling_fallback_reopens_blocked_requirement(sqlite_session_factory):
    incident_id = uuid4()
    now = datetime.now(UTC)
    requirement = build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=1,
        missing_evidence=[{"category": "traces", "question": "Which span failed?"}], now=now,
    )[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([requirement])
        first = await repo.schedule_context_enrichment_job(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=requirement.requirement_id, connector_id="jaeger",
            query_payload={}, observation_start=now - timedelta(minutes=5), observation_end=now,
        )
        await repo.claim_context_enrichment_jobs(worker_id="worker-a", limit=1)
        await repo.finish_context_enrichment_job(
            job_id=first.job_id, worker_id="worker-a", collected=False,
            error="connector unavailable", maximum_attempts=1,
        )
        await repo.schedule_context_enrichment_job(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=requirement.requirement_id, connector_id="discovery-mcp",
            query_payload={}, observation_start=now - timedelta(minutes=5), observation_end=now,
        )
        requirement_row = await repo.context_evidence_requirement(
            tenant_id="tenant-a", requirement_id=requirement.requirement_id,
        )

        assert requirement_row["status"] == "scheduled"
        activity = await repo.list_context_enrichment_activity(
            tenant_id="tenant-a", incident_id=incident_id,
        )
        assert {job["connector_id"] for job in activity["jobs"]} == {"jaeger", "discovery-mcp"}


@pytest.mark.asyncio
async def test_atomic_enrichment_persists_exact_evidence_snapshot_and_outbox(
    sqlite_session_factory,
):
    incident_id = uuid4()
    requirement = EvidenceRequirement(
        requirement_id=uuid4(), tenant_id="tenant-a", incident_id=incident_id,
        rca_version=1, category="metrics", question="What was latency?",
        reason="Confirm the alert", priority="high", collection_mode="automatic",
        candidate_connectors=["prometheus"], created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
    )
    now = datetime.now(UTC)
    record = EvidenceRecord(
        evidence_id="EVD-" + "a" * 64, requirement_id=str(requirement.requirement_id),
        tenant_id="tenant-a", incident_id=str(incident_id), category="metrics",
        source_id="prometheus:9090", connector="prometheus",
        source_reference="prometheus://prometheus:9090/query?expr=up",
        service="checkout-api", observed_at=now, collected_at=now, freshness="fresh",
        content={"metric_name": "up", "labels": {"service": "checkout-api"},
                 "samples": [{"timestamp": now.isoformat(), "value": "0"}]},
        provenance={"query": "up"}, current_observation=True,
    )
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([requirement])
        job = await repo.schedule_context_enrichment_job(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=requirement.requirement_id, connector_id="prometheus",
            query_payload={"incident": {"id": str(incident_id), "tenant_id": "tenant-a",
                                          "service": "checkout-api", "title": "latency"}, "decision": {}},
            observation_start=now - timedelta(minutes=5), observation_end=now,
        )
        newer_requirement = build_evidence_requirements(
            tenant_id="tenant-a", incident_id=incident_id, rca_version=2,
            missing_evidence=[{"category": "metrics", "question": "What was latency?"}], now=now,
        )[0]
        await repo.upsert_context_evidence_requirements([newer_requirement])
        session.add(ContextSnapshotRecord(
            snapshot_id=uuid4(), tenant_id="tenant-a", incident_id=str(incident_id),
            alert_signature="signature", subject_fingerprint="s" * 64,
            context_fingerprint="c" * 64, snapshot_version=1, evidence_ids=["UNRELATED-PRIOR-LOG"],
            evidence_checksums={}, contract_version="kaiops.context.v2", quality_score=0.2,
            reusable=False, source_manifest={}, payload={"tenant_id": "tenant-a",
                "incident_id": str(incident_id), "metadata": {"context_evidence": {},
                    "context_sources": {"metrics": {"status": "skipped", "attempted": False,
                                                    "result_count": 0, "fresh_count": 0}}}},
            collected_at=now, expires_at=now + timedelta(hours=1),
        ))
        await session.commit()
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.claim_context_enrichment_jobs(worker_id="worker-a", limit=1)
        result = await repo.persist_enrichment_result_atomically(
            job_id=job.job_id, worker_id="worker-a", accepted_records=[record],
            rejected_records=[], source_response_metadata={"query": "up"},
        )
        await session.commit()
        assert result["evidence_ids"] == [record.evidence_id]
        assert await session.get(CanonicalEvidenceRecord, record.evidence_id) is not None
        assert await session.get(ResolutionOutboxRecord, result["outbox_event_id"]) is not None
        enriched_request_id = result["outbox_payload"]["decision"]["analysis_request_id"]
        assert UUID(enriched_request_id)
        assert result["outbox_payload"]["context"]["metadata"]["analysis_request_id"] == enriched_request_id
        snapshot = await session.get(ContextSnapshotRecord, UUID(result["snapshot_id"]))
        assert set(snapshot.evidence_ids) == {"UNRELATED-PRIOR-LOG", record.evidence_id}
        assert snapshot.payload["metadata"]["context_evidence"]["metrics"][0]["evidence_id"] == record.evidence_id
        source = snapshot.payload["metadata"]["context_sources"]["metrics"]
        assert source["status"] == "collected"
        assert source["attempted"] is True
        assert source["result_count"] == 1
        assert source["evidence_ids"] == [record.evidence_id]
        assert "fresh_count" not in source

        requirement_row = await repo.context_evidence_requirement(
            tenant_id="tenant-a", requirement_id=requirement.requirement_id,
        )
        assert requirement_row["status"] == "collected"
        assert requirement_row["evidence_ids"] == [record.evidence_id]
        newer_requirement_row = await repo.context_evidence_requirement(
            tenant_id="tenant-a", requirement_id=newer_requirement.requirement_id,
        )
        assert newer_requirement_row["status"] == "collected"
        assert newer_requirement_row["evidence_ids"] == [record.evidence_id]
        coverage = await repo.reconcile_requirement_coverage_from_ledger(
            tenant_id="tenant-a", incident_id=incident_id, apply=True,
        )
        assert coverage[str(requirement.requirement_id)] == [record.evidence_id]


@pytest.mark.asyncio
async def test_connector_unavailable_becomes_human_request_without_stopping_other_work(
    sqlite_session_factory,
):
    incident_id = uuid4()
    requirements = await plan_missing_evidence(
        context_for(incident_id),
        {"tenant_id": "tenant-a", "incident_id": str(incident_id), "rca_version": 1,
         "missing_evidence": ["logs", "ownership"]},
    )
    result = await execute_enrichment_plan(requirements, authorized_connectors={"opensearch"})
    assert len(result.scheduled_requirement_ids) == 1
    assert len(result.human_requirement_ids) == 1

    human_requirement = next(row for row in requirements if row.collection_mode == "human_required")
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements(requirements)
        request = await repo.create_human_evidence_request(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=human_requirement.requirement_id,
            expected_responder="checkout-service-owner", due_at=datetime.now(UTC) + timedelta(hours=1),
            acceptable_format="Account ID or governed support group",
            evidence_already_checked=["cmdb", "service-catalog"],
            hypothesis_impact="Determines the authorized approver",
            investigation_can_continue=True,
        )
        assert request.investigation_can_continue is True


@pytest.mark.asyncio
async def test_human_request_blocks_without_real_responder_and_rejects_placeholder(
    sqlite_session_factory,
):
    incident_id = uuid4()
    requirement = build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=1,
        missing_evidence=["ownership"], now=datetime.now(UTC),
    )[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([requirement])
        with pytest.raises(ValueError, match="placeholder"):
            await repo.create_human_evidence_request(
                tenant_id="tenant-a", incident_id=incident_id,
                requirement_id=requirement.requirement_id, expected_responder="incident-owner",
                due_at=datetime.now(UTC) + timedelta(hours=1), acceptable_format="source reference",
                evidence_already_checked=[], hypothesis_impact="ownership",
            )
        blocked = await repo.create_human_evidence_request(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=requirement.requirement_id, expected_responder=None,
            assignment_failure_reason="NO_AUTHORIZED_RESPONDER",
            due_at=datetime.now(UTC) + timedelta(hours=1), acceptable_format="source reference",
            evidence_already_checked=[], hypothesis_impact="ownership",
        )
        assert blocked.status == "assignment_blocked"
        assert blocked.expected_responder is None


@pytest.mark.asyncio
async def test_human_evidence_queue_lists_cross_incident_requests_with_context(
    sqlite_session_factory,
):
    """The queue view is what lets an operator work through the backlog
    without opening every incident individually - it must include enough
    incident/requirement context to be actionable, and must be filterable by
    responder so a fallback identity only sees its own assignments."""
    incident_id = uuid4()
    requirement = build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=1,
        missing_evidence=["ownership"], now=datetime.now(UTC),
    )[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="checkout-api", environment="prod",
            severity="critical", status="investigating", title="Checkout latency", payload={},
        ))
        await repo.upsert_context_evidence_requirements([requirement])
        await repo.create_human_evidence_request(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=requirement.requirement_id, expected_responder="platform-ops@kaims.local",
            due_at=datetime.now(UTC) + timedelta(hours=1), acceptable_format="source reference",
            evidence_already_checked=[], hypothesis_impact="ownership",
        )
        await session.commit()

        queue = await repo.list_human_evidence_request_queue(tenant_id="tenant-a")
        assert len(queue) == 1
        row = queue[0]
        assert row["incident_id"] == str(incident_id)
        assert row["incident_title"] == "Checkout latency"
        assert row["incident_service"] == "checkout-api"
        assert row["expected_responder"] == "platform-ops@kaims.local"
        assert row["category"] == "ownership"

        scoped = await repo.list_human_evidence_request_queue(
            tenant_id="tenant-a", responder="PLATFORM-OPS@kaims.local",
        )
        assert len(scoped) == 1

        other = await repo.list_human_evidence_request_queue(
            tenant_id="tenant-a", responder="someone-else@kaims.local",
        )
        assert other == []

        tenant_b = await repo.list_human_evidence_request_queue(tenant_id="tenant-b")
        assert tenant_b == []


@pytest.mark.asyncio
async def test_human_evidence_jira_binding_is_idempotent_and_reassignment_is_synchronized(
    sqlite_session_factory,
):
    incident_id = uuid4()
    requirement = build_evidence_requirements(
        tenant_id="tenant-a", incident_id=incident_id, rca_version=1,
        missing_evidence=["ownership"], now=datetime.now(UTC),
    )[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([requirement])
        request = await repo.create_human_evidence_request(
            tenant_id="tenant-a", incident_id=incident_id,
            requirement_id=requirement.requirement_id, expected_responder="account-a",
            assignment_source="service_ownership",
            due_at=datetime.now(UTC) + timedelta(hours=1), acceptable_format="source reference",
            evidence_already_checked=[], hypothesis_impact="ownership",
        )
        values = dict(
            tenant_id="tenant-a", incident_id=incident_id, request_id=request.request_id,
            requirement_id=requirement.requirement_id, jira_issue_key="KAN-77",
            jira_issue_url="https://example.atlassian.net/browse/KAN-77", jira_version="1",
            jira_assignee_id="account-a", sync_status="synchronized",
        )
        first = await repo.bind_human_evidence_jira(**values)
        second = await repo.bind_human_evidence_jira(**values)
        assert first == second
        synchronized = await repo.synchronize_human_evidence_jira_assignee(
            tenant_id="tenant-a", jira_issue_key="KAN-77", jira_assignee_id="account-b",
            jira_version="2", sync_status="synchronized",
        )
        assert synchronized["expected_responder"] == "account-b"
        row = await repo.context_evidence_requirement(
            tenant_id="tenant-a", requirement_id=requirement.requirement_id,
        )
        assert row["assigned_to"] == "account-b"


@pytest.mark.asyncio
async def test_human_response_is_tenant_scoped_and_recorded_as_assertion(sqlite_session_factory):
    incident_id = uuid4()
    requirement = EvidenceRequirement(
        requirement_id=uuid4(), tenant_id="tenant-a", incident_id=incident_id,
        rca_version=1, category="business_impact", question="Is checkout customer-facing?",
        reason="Impact classification requires business ownership", priority="high",
        collection_mode="human_required", created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
    )
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        now = datetime.now(UTC)
        snapshot_id, alert_id, analysis_id, recommendation_id = uuid4(), uuid4(), uuid4(), uuid4()
        session.add(ContextSnapshotRecord(
            snapshot_id=snapshot_id, tenant_id="tenant-a", incident_id=str(incident_id),
            source_incident_id=str(incident_id), alert_signature="alert-signature",
            subject_fingerprint="s" * 64, context_fingerprint="c" * 64,
            snapshot_stage="final", snapshot_version=1, evidence_ids=["metric-1"],
            evidence_checksums={"metric-1": "m" * 64}, contract_version="kaiops.context.v2",
            quality_score=0.5, reusable=False, source_manifest={}, payload={"metadata": {}},
            collected_at=now, expires_at=now + timedelta(hours=1),
        ))
        session.add(IncidentInvestigationBindingRecord(
            tenant_id="tenant-a", project_id="project-a", incident_id=incident_id,
            alert_id=alert_id, analysis_request_id=analysis_id, context_snapshot_id=snapshot_id,
            context_fingerprint="c" * 64, recommendation_id=recommendation_id,
            rca_version=1, status="grounded", created_at=now, expires_at=now + timedelta(hours=1),
        ))
        await repo.upsert_context_evidence_requirements([requirement])
        await repo.create_human_evidence_request(
            tenant_id="tenant-a", incident_id=incident_id, requirement_id=requirement.requirement_id,
            expected_responder="owner-a", due_at=datetime.now(UTC) + timedelta(hours=1),
            acceptable_format="yes/no with service catalog link", evidence_already_checked=["cmdb"],
            hypothesis_impact="Changes customer-impact classification",
        )
        with pytest.raises(LookupError):
            await repo.record_human_evidence_response(
                tenant_id="tenant-b", incident_id=incident_id, requirement_id=requirement.requirement_id,
                response={"response": "yes", "responder_id": "owner-a", "responded_at": datetime.now(UTC).isoformat(),
                          "source_reference": "service-catalog://checkout"},
            )
        with pytest.raises(PermissionError, match="not assigned"):
            await repo.record_human_evidence_response(
                tenant_id="tenant-a", incident_id=incident_id,
                requirement_id=requirement.requirement_id,
                response={
                    "response": "yes", "responder_id": "owner-b",
                    "responded_at": datetime.now(UTC).isoformat(),
                    "source_reference": "service-catalog://checkout",
                },
            )
        recorded = await repo.record_human_evidence_response(
            tenant_id="tenant-a", incident_id=incident_id, requirement_id=requirement.requirement_id,
            response={"response": "yes", "responder_id": "owner-a", "responded_at": datetime.now(UTC).isoformat(),
                      "source_reference": "service-catalog://checkout"},
        )
        assert recorded["evidence_id"].startswith("EVD-")
        assert recorded["context_snapshot_id"] is not None
        gaps = await repo.list_context_evidence_requirements(
            tenant_id="tenant-a", incident_id=incident_id,
        )
        assert gaps[0]["status"] == "collected"
        assert gaps[0]["evidence_ids"] == [recorded["evidence_id"]]
        latest = (await session.execute(
            select(ContextSnapshotRecord).where(
                ContextSnapshotRecord.tenant_id == "tenant-a",
                ContextSnapshotRecord.incident_id == str(incident_id),
            ).order_by(ContextSnapshotRecord.snapshot_version.desc())
        )).scalars().first()
        assert latest.snapshot_version == 2
        assert latest.parent_snapshot_id == snapshot_id
        canonical = await session.get(CanonicalEvidenceRecord, recorded["evidence_id"])
        assert canonical.category == "tickets"
        assert canonical.source_reference == "service-catalog://checkout"
        outbox = await session.get(
            ResolutionOutboxRecord, f"context-human-enriched:{incident_id}:{latest.snapshot_id}",
        )
        assert outbox is not None


@pytest.mark.asyncio
async def test_active_gap_reconciliation_is_idempotent(sqlite_session_factory) -> None:
    incident_id, alert_id, snapshot_id, recommendation_id = uuid4(), uuid4(), uuid4(), uuid4()
    analysis_id = uuid4()
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="checkout-api", environment="prod",
            severity="critical", status="investigating", title="checkout latency", payload={},
        ))
        session.add(ContextSnapshotRecord(
            snapshot_id=snapshot_id, tenant_id="tenant-a", incident_id=str(incident_id),
            alert_signature="signature", subject_fingerprint="s" * 64,
            context_fingerprint="c" * 64, contract_version="kaiops.context.v2",
            quality_score=0.4, reusable=False, source_manifest={}, evidence_ids=["LOG-attached", "METRIC-context-only"], payload={"metadata": {
                "context_evidence": {"logs": [{
                    "evidence_id": "LOG-attached", "category": "logs",
                    "connector": "opensearch", "citation": "opensearch://logs/attached",
                }], "metrics": [{
                    "evidence_id": "METRIC-context-only", "category": "metrics",
                    "connector": "prometheus", "citation": "prometheus://query/context-only",
                }]},
            }},
            collected_at=now, expires_at=now + timedelta(hours=1),
        ))
        session.add(ContextSnapshotRecord(
            snapshot_id=uuid4(), tenant_id="tenant-a", incident_id=str(incident_id),
            alert_signature="signature", subject_fingerprint="s" * 64,
            context_fingerprint="o" * 64, contract_version="kaiops.context.v2",
            snapshot_stage="investigation_complete", snapshot_version=2,
            quality_score=0.4, reusable=False, source_manifest={}, evidence_ids=[], payload={"metadata": {}},
            collected_at=now + timedelta(seconds=1), expires_at=now + timedelta(hours=1),
        ))
        session.add(IncidentInvestigationBindingRecord(
            tenant_id="tenant-a", project_id="project-a", incident_id=incident_id,
            alert_id=alert_id, analysis_request_id=analysis_id, context_snapshot_id=snapshot_id,
            context_fingerprint="c" * 64, recommendation_id=recommendation_id,
            evidence_ids=["LOG-attached", "METRIC-context-only"],
            rca_version=3, status="insufficient_evidence", created_at=now,
            expires_at=now + timedelta(hours=1),
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=alert_id, recommendation_id=recommendation_id,
            tenant_id="tenant-a", service="checkout-api", environment="prod",
            status="investigating", first_seen_at=now, projection_payload={},
        ))
        session.add(AuditLogRecord(
            id=recommendation_id, tenant_id="tenant-a", actor="resolution-agent",
            action="recommendation.generated", resource_type="incident",
            resource_id=str(incident_id), payload={"metadata": {
                "analysis_request_id": str(analysis_id), "project_id": "project-a",
                "alert_id": str(alert_id), "context_snapshot_id": str(snapshot_id),
                "context_fingerprint": "c" * 64, "evidence_ids": ["LOG-attached", "METRIC-context-only"],
                "rca_analysis": {
                    "evidence_used": ["LOG-attached"],
                    "missing_evidence": [{"category": "logs", "question": "Which errors occurred?"}],
                },
            }},
        ))
        await session.flush()
        verified = await IncidentRepository(session).get_bound_incident_investigation(
            tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            recommendation_id=recommendation_id,
        )
        assert verified["investigation_integrity"]["status"] == "verified"
        repo = ContextEnrichmentRepository(session)
        candidates = await repo.active_incident_gap_candidates(tenant_id="tenant-a")
        requirements = await plan_missing_evidence(
            context_for(incident_id), {
                "tenant_id": "tenant-a", "incident_id": str(incident_id), "rca_version": 3,
                "missing_evidence": candidates[0]["gaps"],
            },
        )
        first = await repo.upsert_context_evidence_requirements(requirements)
        second = await repo.upsert_context_evidence_requirements(requirements)
        assert len(candidates) == 1
        assert first[0].requirement_id == second[0].requirement_id
        state = await repo.incident_operations_state(tenant_id="tenant-a", incident_id=incident_id)
        attached = state["investigation_workspace"]["evidence"]
        assert len(attached) == 2
        attached_by_id = {row["evidence_id"]: row for row in attached}
        assert attached_by_id["LOG-attached"]["connector"] == "opensearch"
        assert attached_by_id["LOG-attached"]["citation"] == "opensearch://logs/attached"
        assert attached_by_id["LOG-attached"]["accepted_for_rca"] is True
        assert attached_by_id["METRIC-context-only"]["accepted_for_rca"] is False
        assert state["investigation_workspace"]["evidence_summary"]["rca_bound_records"] == 1
        assert state["context"]["snapshot_id"] == str(snapshot_id)


@pytest.mark.asyncio
async def test_structured_evidence_planes_count_as_traceable_citations(sqlite_session_factory) -> None:
    """`resolution_agent.investigation`'s structured evidence planes (traces,
    changes, database, resource, dependency) stamp their real URI under
    `source_uri` and their freshness flag under
    `current_operational_evidence` - a different shape from the flatter
    code/logs/topology/telemetry rows, which use `citation`/`uri` and
    `current_observation`. The workspace builder only ever checked the
    latter names, so every structured-plane row's citation silently fell
    back to "" (never traceable) and its freshness to False, regardless of
    the real, traceable value actually present on the row. Reproduced live
    against incident 417fc764acf342b1bdc8e815d18e8f1f: 11 RCA-bound records,
    almost all trace-sourced, and only 1 counted as a traceable citation -
    capping grounding coverage at 9% and leaving RCA_NOT_GROUNDED permanently
    set no matter how much real evidence had been collected.
    """
    incident_id, alert_id, snapshot_id, recommendation_id = uuid4(), uuid4(), uuid4(), uuid4()
    analysis_id = uuid4()
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="api-gateway", environment="prod",
            severity="critical", status="investigating", title="api-gateway latency", payload={},
        ))
        session.add(ContextSnapshotRecord(
            snapshot_id=snapshot_id, tenant_id="tenant-a", incident_id=str(incident_id),
            alert_signature="signature", subject_fingerprint="s" * 64,
            context_fingerprint="c" * 64, contract_version="kaiops.context.v2",
            quality_score=0.7, reusable=False, source_manifest={},
            evidence_ids=["TRACE-bound", "RESOURCE-bound"],
            payload={"metadata": {
                "context_evidence": {
                    "traces": [{
                        "evidence_id": "TRACE-bound", "category": "traces",
                        "connector": "jaeger", "source_uri": "jaeger://trace/abc123",
                        "current_operational_evidence": True,
                    }],
                    "resource": [{
                        "evidence_id": "RESOURCE-bound", "category": "resource",
                        "connector": "docker", "source_uri": "docker://kaims/api-gateway/stats",
                        "current_operational_evidence": True,
                    }],
                },
            }},
            collected_at=now, expires_at=now + timedelta(hours=1),
        ))
        session.add(IncidentInvestigationBindingRecord(
            tenant_id="tenant-a", project_id="project-a", incident_id=incident_id,
            alert_id=alert_id, analysis_request_id=analysis_id, context_snapshot_id=snapshot_id,
            context_fingerprint="c" * 64, recommendation_id=recommendation_id,
            evidence_ids=["TRACE-bound", "RESOURCE-bound"],
            rca_version=1, status="grounded", created_at=now,
            expires_at=now + timedelta(hours=1),
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=alert_id, recommendation_id=recommendation_id,
            tenant_id="tenant-a", service="api-gateway", environment="prod",
            status="investigating", first_seen_at=now, projection_payload={},
        ))
        session.add(AuditLogRecord(
            id=recommendation_id, tenant_id="tenant-a", actor="resolution-agent",
            action="recommendation.generated", resource_type="incident",
            resource_id=str(incident_id), payload={"metadata": {
                "analysis_request_id": str(analysis_id), "project_id": "project-a",
                "alert_id": str(alert_id), "context_snapshot_id": str(snapshot_id),
                "context_fingerprint": "c" * 64,
                "evidence_ids": ["TRACE-bound", "RESOURCE-bound"],
                "rca_analysis": {"evidence_used": ["TRACE-bound", "RESOURCE-bound"]},
            }},
        ))
        await session.flush()
        repo = ContextEnrichmentRepository(session)
        state = await repo.incident_operations_state(tenant_id="tenant-a", incident_id=incident_id)

    workspace = state["investigation_workspace"]
    attached_by_id = {row["evidence_id"]: row for row in workspace["evidence"]}
    assert attached_by_id["TRACE-bound"]["citation"] == "jaeger://trace/abc123"
    assert attached_by_id["TRACE-bound"]["current_observation"] is True
    assert attached_by_id["RESOURCE-bound"]["citation"] == "docker://kaims/api-gateway/stats"
    assert attached_by_id["RESOURCE-bound"]["current_observation"] is True
    assert workspace["evidence_summary"]["rca_bound_records"] == 2
    assert workspace["evidence_summary"]["traceable_citations"] == 2

    read_model = build_incident_command_workspace(
        incident_id=str(incident_id), incident={"incident_id": str(incident_id)}, operations=state,
    )
    grounding = next(score for score in read_model.evidence.scores if score.key == "grounding_coverage")
    assert grounding.percent == 100
    assert grounding.status == "available"


def test_hitl_routing_configuration_rejects_placeholder_identity():
    with pytest.raises(ValueError, match="explicit governed identities"):
        HitlRoutingConfiguration(
            default_approver_group="admin", l2_group="checkout-l2", l3_group="checkout-l3",
            service_owner="checkout-owner", timezone="Asia/Calcutta", business_hours={},
            severity_sla_minutes={"critical": 15}, jira_project_key="KAN", jira_issue_type="Bug",
            jira_transition_mapping={"approved": "31"}, fallback_assignment_group="platform-l2",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", [None, "tenant", "checksum", "assessment"])
async def test_closed_observed_recovery_is_read_without_execution_lineage(sqlite_session_factory, invalid):
    incident_id, assessment_id, report_id = uuid4(), uuid4(), uuid4()
    checksum = "sha256:" + "a" * 64
    async with sqlite_session_factory() as session:
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, tenant_id="tenant-a", service="external-endpoint",
            environment="prod", severity="critical", status="closed", lifecycle_state="CLOSED",
            projection_payload={"incident_lifecycle": {"assessment_id": str(assessment_id)}},
        ))
        session.add(AuditLogRecord(
            id=assessment_id, tenant_id="tenant-a", actor="operator", action="recovery.assessment.requested",
            resource_type="incident", resource_id=str(incident_id),
            payload={"status": "closed", "report_id": str(report_id), "validation_checksum": checksum},
        ))
        session.add(RcaReportRecord(
            id=report_id, tenant_id="other" if invalid == "tenant" else "tenant-a", incident_id=incident_id,
            closure_kind="observed_recovery", closure_status="closed", root_cause="Unconfirmed", impact="Endpoint unavailable",
            validation_checksum="different" if invalid == "checksum" else checksum,
            payload={"health_restored": True, "alerts_cleared": True, "metadata": {
                "assessment_id": str(uuid4()) if invalid == "assessment" else str(assessment_id),
                "independent_validation_observations": [{"validator_id": "availability", "passed": True}],
            }},
        ))
        await session.commit()
        state = await ContextEnrichmentRepository(session).incident_operations_state(tenant_id="tenant-a", incident_id=incident_id)
    assert state["lifecycle_state"] == "CLOSED"
    assert state["next_action"]["type"] == "REVIEW_CLOSURE"
    assert state["execution"]["action_id"] is None
    assert state["validation"]["report_id"] == (str(report_id) if invalid is None else None)
    if invalid is None:
        assert state["validation"]["health_restored"] is True
        assert state["validation"]["post_state_observations"][0]["passed"] is True


@pytest.mark.asyncio
async def test_external_probe_reconciliation_only_cancels_generic_trace_question(sqlite_session_factory):
    incident_id = uuid4()
    generic = "Collect fresh distributed traces for the affected service and incident window."
    specific = "Retrieve instrumented trace abc123 from the owned gateway."
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        requirements = build_evidence_requirements(
            tenant_id="tenant-a", incident_id=incident_id, rca_version=1,
            missing_evidence=[{"category": "traces", "question": generic}, {"category": "traces", "question": specific}],
            now=datetime.now(UTC),
        )
        await repo.upsert_context_evidence_requirements(requirements)
        changed = await repo.cancel_inapplicable_context_requirements(
            tenant_id="tenant-a", incident_id=incident_id, categories={"traces"},
            questions={generic}, reason="Superseded generic request",
        )
        rows = await repo.list_context_evidence_requirements(tenant_id="tenant-a", incident_id=incident_id)
        assert changed == 1
        assert next(row for row in rows if row["question"] == generic)["status"] == "cancelled"
        assert next(row for row in rows if row["question"] == specific)["status"] != "cancelled"
        assert await repo.cancel_inapplicable_context_requirements(
            tenant_id="tenant-a", incident_id=incident_id, categories={"traces"},
            questions={generic}, reason="Superseded generic request",
        ) == 0

@pytest.mark.asyncio
@pytest.mark.parametrize("category", ["database", "validation", "logs"])
async def test_automatic_technical_failure_does_not_require_human_facts(sqlite_session_factory, category):
    key = uuid4()
    req = build_evidence_requirements(tenant_id="tenant-a", incident_id=key, rca_version=1,
        missing_evidence=[category], now=datetime.now(UTC))[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([req])
        previous = await repo.create_human_evidence_request(tenant_id="tenant-a", incident_id=key,
            requirement_id=req.requirement_id, expected_responder="owner@example.com", due_at=datetime.now(UTC),
            acceptable_format="Verified observation", evidence_already_checked=[], hypothesis_impact="Test")
        result = await repo.create_human_evidence_request(tenant_id="tenant-a", incident_id=key,
            requirement_id=req.requirement_id, expected_responder="owner@example.com", due_at=datetime.now(UTC),
            acceptable_format="Verified observation", evidence_already_checked=[], hypothesis_impact="Test", automatic_fallback=True)
        assert result is None
        assert previous.status == "cancelled"
        current = await repo.context_evidence_requirement(tenant_id="tenant-a", requirement_id=req.requirement_id)
        assert current["status"] == "blocked"
        assert not current["evidence_ids"]
        from common.database import ContextEvidenceRequirementRecord
        stored = await session.get(ContextEvidenceRequirementRecord, req.requirement_id)
        version = stored.version
        await repo.create_human_evidence_request(tenant_id="tenant-a", incident_id=key,
            requirement_id=req.requirement_id, expected_responder=None, due_at=datetime.now(UTC),
            acceptable_format="Verified observation", evidence_already_checked=[], hypothesis_impact="Test", automatic_fallback=True)
        assert stored.version == version

@pytest.mark.asyncio
async def test_automatic_business_impact_can_still_request_a_person(sqlite_session_factory):
    key = uuid4()
    req = build_evidence_requirements(tenant_id="tenant-a", incident_id=key, rca_version=1,
        missing_evidence=["business_impact"], now=datetime.now(UTC))[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([req])
        result = await repo.create_human_evidence_request(tenant_id="tenant-a", incident_id=key,
            requirement_id=req.requirement_id, expected_responder="owner@example.com", due_at=datetime.now(UTC),
            acceptable_format="Verified observation", evidence_already_checked=[], hypothesis_impact="Test", automatic_fallback=True)
        assert result.status == "pending"

@pytest.mark.asyncio
async def test_workspace_activity_can_read_current_requirements_without_replaying_history(sqlite_session_factory):
    key = uuid4(); now = datetime.now(UTC)
    old = build_evidence_requirements(tenant_id="tenant-a", incident_id=key, rca_version=1, missing_evidence=["logs"], now=now)[0]
    current = build_evidence_requirements(tenant_id="tenant-a", incident_id=key, rca_version=2, missing_evidence=["logs"], now=now)[0]
    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        for req in [old, current]:
            await repo.upsert_context_evidence_requirements([req])
            await repo.schedule_context_enrichment_job(tenant_id="tenant-a", incident_id=key,
                requirement_id=req.requirement_id, connector_id="discovery-mcp", query_payload={},
                observation_start=now-timedelta(minutes=15), observation_end=now)
            await repo.create_human_evidence_request(tenant_id="tenant-a", incident_id=key,
                requirement_id=req.requirement_id, expected_responder="owner@example.com", due_at=now,
                acceptable_format="Observation", evidence_already_checked=[], hypothesis_impact="Test")
        all_activity = await repo.list_context_enrichment_activity(tenant_id="tenant-a", incident_id=key)
        active = await repo.list_context_enrichment_activity(tenant_id="tenant-a", incident_id=key,
            requirement_ids=[str(current.requirement_id)])
        assert len(all_activity["jobs"]) == len(all_activity["human_requests"]) == 2
        assert [item["requirement_id"] for item in active["jobs"]] == [str(current.requirement_id)]
        assert [item["requirement_id"] for item in active["human_requests"]] == [str(current.requirement_id)]
        assert await repo.list_context_enrichment_activity(tenant_id="tenant-a", incident_id=key, requirement_ids=[]) == {"jobs": [], "human_requests": []}


@pytest.mark.asyncio
async def test_missing_runbook_creates_pending_human_request_and_transitions_to_waiting_for_human(sqlite_session_factory):
    from common.database import IncidentRecord
    incident_id, alert_id = uuid4(), uuid4()
    now = datetime.now(UTC)
    req = build_evidence_requirements(
        tenant_id="tenant-a",
        incident_id=incident_id,
        rca_version=1,
        missing_evidence=[
            {
                "category": "runbook",
                "question": "Provide runbook and remediation steps for billing-api.",
                "reason": "No approved runbook was retrieved for billing-api.",
                "collection_mode": "human_required",
                "candidate_connectors": [],
            }
        ],
        now=now,
    )[0]
    assert req.collection_mode == "human_required"
    assert req.candidate_connectors == []

    async with sqlite_session_factory() as session:
        session.add(
            IncidentRecord(
                id=incident_id,
                tenant_id="tenant-a",
                title="billing-api unknown error",
                severity="high",
                status="investigating",
                service="billing-api",
                environment="prod",
                payload={"alert_ids": [str(alert_id)], "timeline": []},
            )
        )
        session.add(
            IncidentProjectionRecord(
                incident_id=incident_id,
                tenant_id="tenant-a",
                service="billing-api",
                environment="prod",
                severity="high",
                status="investigating",
                lifecycle_state="INVESTIGATING",
                projection_payload={"incident": {"id": str(incident_id), "status": "investigating"}},
            )
        )
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([req])
        assignment = await repo.resolve_human_evidence_responder(tenant_id="tenant-a", incident_id=incident_id)
        assert assignment is not None
        assert assignment["source"] == "tenant_fallback"
        human_req = await repo.create_human_evidence_request(
            tenant_id="tenant-a",
            incident_id=incident_id,
            requirement_id=req.requirement_id,
            expected_responder=assignment["identity"],
            assignment_source=assignment["source"],
            due_at=now + timedelta(hours=1),
            acceptable_format="Verified runbook observation",
            evidence_already_checked=[],
            hypothesis_impact=req.reason,
            automatic_fallback=True,
        )
        await session.commit()
        assert human_req is not None
        assert human_req.status == "pending"
        inc = await session.get(IncidentRecord, incident_id)
        proj = await session.get(IncidentProjectionRecord, incident_id)
        assert inc.status == "waiting_for_human"
        assert inc.payload["alert_ids"] == [str(alert_id)]
        assert proj.status == "waiting_for_human"


@pytest.mark.asyncio
async def test_human_input_without_existing_request_auto_creates_maps_categories_and_creates_governed_runbook_draft(
    sqlite_session_factory,
):
    from common.database import (
        CanonicalEvidenceRecord,
        IncidentRecord,
        KnowledgeRagDraftRecord,
        RunbookVersionRecord,
    )
    from common.repository import IncidentRepository
    from context_agent.connectors import VectorDBConnector

    incident_id, alert_id = uuid4(), uuid4()
    now = datetime.now(UTC)
    snapshot_id, analysis_id, recommendation_id = uuid4(), uuid4(), uuid4()
    reqs = build_evidence_requirements(
        tenant_id="tenant-a",
        incident_id=incident_id,
        rca_version=1,
        missing_evidence=[
            {
                "category": "runbook",
                "question": "Provide runbook and remediation steps for ledger-sync.",
                "collection_mode": "human_required",
                "candidate_connectors": [],
            },
            {
                "category": "metrics",
                "question": "Provide CPU saturation metric observation for ledger-sync.",
            },
        ],
        now=now,
    )
    runbook_req, metrics_req = reqs[0], reqs[1]

    async with sqlite_session_factory() as session:
        session.add(
            IncidentRecord(
                id=incident_id,
                tenant_id="tenant-a",
                title="ledger-sync stale cursor",
                severity="critical",
                status="waiting_for_human",
                service="ledger-sync",
                environment="prod",
                payload={"alert_ids": [str(alert_id)], "timeline": []},
            )
        )
        session.add(
            ContextSnapshotRecord(
                snapshot_id=snapshot_id,
                tenant_id="tenant-a",
                incident_id=str(incident_id),
                source_incident_id=str(incident_id),
                alert_signature="alert-signature",
                subject_fingerprint="s" * 64,
                context_fingerprint="c" * 64,
                snapshot_stage="final",
                snapshot_version=1,
                evidence_ids=["metric-1"],
                evidence_checksums={"metric-1": "m" * 64},
                contract_version="kaiops.context.v2",
                quality_score=0.5,
                reusable=False,
                source_manifest={},
                payload={"metadata": {}},
                collected_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        session.add(
            IncidentInvestigationBindingRecord(
                tenant_id="tenant-a",
                project_id="project-a",
                incident_id=incident_id,
                alert_id=alert_id,
                analysis_request_id=analysis_id,
                context_snapshot_id=snapshot_id,
                context_fingerprint="c" * 64,
                recommendation_id=recommendation_id,
                rca_version=1,
                status="grounded",
                created_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements(reqs)
        await session.commit()

        # Submit human response directly WITHOUT a pre-existing HumanEvidenceRequestRecord (verifies no 404)
        submission = {
            "response": "Cursor checkpoint table locked due to stale worker lease.",
            "responder_id": "sre-operator@example.com",
            "responded_at": (now + timedelta(minutes=2)).isoformat(),
            "observed_symptoms": "ledger-sync lag > 900s; stale lease on checkpoint row.",
            "root_cause": "Stale worker lease in ledger_checkpoints table blocking cursor advancement.",
            "business_impact": "Settlement ledger updates delayed by 15 minutes for enterprise tenants.",
            "remediation_steps": "1. Inspect stale leases\n2. Run `kubectl rollout restart deployment/ledger-sync -n prod`",
            "create_runbook_draft": True,
        }
        result = await repo.record_human_evidence_response(
            tenant_id="tenant-a",
            incident_id=incident_id,
            requirement_id=runbook_req.requirement_id,
            response=submission,
        )
        # Submit duplicate response to verify idempotency / retry safety
        duplicate = await repo.record_human_evidence_response(
            tenant_id="tenant-a",
            incident_id=incident_id,
            requirement_id=runbook_req.requirement_id,
            response=submission,
        )
        assert duplicate["evidence_id"] == result["evidence_id"]
        assert result["knowledge_draft_id"] is not None

        # Submit metrics category response to verify category mapping (metrics -> metrics, runbook -> knowledge)
        metrics_result = await repo.record_human_evidence_response(
            tenant_id="tenant-a",
            incident_id=incident_id,
            requirement_id=metrics_req.requirement_id,
            response={
                "response": "CPU utilization was 94% on ledger-sync pod-0.",
                "responder_id": "sre-operator@example.com",
                "responded_at": (now + timedelta(minutes=4)).isoformat(),
            },
        )
        await session.commit()

        runbook_ev = await session.get(CanonicalEvidenceRecord, result["evidence_id"])
        metrics_ev = await session.get(CanonicalEvidenceRecord, metrics_result["evidence_id"])
        assert runbook_ev.category == "knowledge"
        assert runbook_ev.service == "ledger-sync"
        assert metrics_ev.category == "metrics"

        inc = await session.get(IncidentRecord, incident_id)
        assert inc.status == "investigating"

        # Verify governed runbook draft is initially in 'draft' status (not auto-approved)
        draft = await session.get(KnowledgeRagDraftRecord, UUID(result["knowledge_draft_id"]))
        assert draft is not None
        assert draft.status == "draft"
        assert draft.document_kind == "runbook"

        assert repo._knowledge_draft_payload(draft)["draft_id"] == str(draft.draft_id)

        inc_repo = IncidentRepository(session)
        from common.database import GovernedRagDocumentRecord
        reviewed = await inc_repo.review_knowledge_rag_draft(
            tenant_id="tenant-a",
            draft_id=draft.draft_id,
            expected_row_version=draft.row_version,
            title=draft.title,
            content=draft.content,
            review_notes="Verified runbook steps for ledger-sync stale cursor.",
            reviewed_by="lead-sre@example.com",
        )
        assert reviewed is not None
        assert reviewed["status"] == "reviewed"
        approved = await inc_repo.approve_knowledge_rag_draft(
            tenant_id="tenant-a",
            draft_id=draft.draft_id,
            expected_row_version=reviewed["row_version"],
            approved_by="release-owner@example.com",
        )
        await session.commit()
        assert approved is not None
        approved_draft, approved_payload = approved
        assert approved_draft["status"] == "approved_pending_index"
        doc_row = await session.get(GovernedRagDocumentRecord, UUID(approved_payload["document_id"]))
        assert doc_row is not None

        # Verify RunbookVersionRecord is now approved
        rb_rows = (
            await session.execute(
                select(RunbookVersionRecord).where(
                    RunbookVersionRecord.tenant_id == "tenant-a",
                )
            )
        ).scalars().all()
        assert any(r.approval_status == "approved" for r in rb_rows)

        # Verify VectorDBConnector indexes the approved governed document and retrieves it for a similar alert
        connector = VectorDBConnector()
        indexed = await connector.index_governed_document(doc_row)
        assert indexed["indexed"] == 1
        hits = connector.search(
            "ledger-sync stale cursor checkpoint lease",
            tenant_id="tenant-a",
            service="ledger-sync",
            preferred_kind="runbook",
        )
        assert len(hits) >= 1
        assert "ledger-sync" in hits[0]["content"]
