from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import pytest
from common.models import Alert, AlertSeverity, ApprovalDecision, Recommendation
from common.orchestration.execution_plan import resolve_execution_plan
from common.orchestration.execution_plan_contract import ExecutionPlanV2
from common.repository import IncidentRepository
from test_bound_incident_investigation_repository import _seed_pair


def load_approval_module():
    path = Path("backend/src/approval-service/app.py")
    spec = importlib.util.spec_from_file_location("canonical_approval_app", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_resolution_module():
    path = Path("ai-workbench/src/resolution-agent/app.py")
    spec = importlib.util.spec_from_file_location("governed_resolution_agent_app", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def catalog_option() -> dict:
    return {
        "id": "restart-service", "source": "kaims-governed-catalog-v1",
        "service": "api-gateway", "risk": "high", "execution_eligible": False,
        "validation": ["health"], "rollback": ["rollback"],
    }


@pytest.mark.asyncio
async def test_incident_and_approval_use_exact_persisted_execution_plan(sqlite_session_factory):
    incident_id, alert_id, snapshot_id, recommendation_id = uuid4(), uuid4(), uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        await _seed_pair(
            session, tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            snapshot_id=snapshot_id, recommendation_id=recommendation_id,
            fingerprint="d" * 64, evidence_id="metric:up:api-gateway",
        )
        from datetime import UTC, datetime

        from common.database import IncidentProjectionRecord
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=alert_id, recommendation_id=recommendation_id,
            tenant_id="tenant-a", service="api-gateway", environment="prod", severity="critical",
            status="investigating", first_seen_at=datetime.now(UTC), projection_payload={},
        ))
        await session.commit()
        repo = IncidentRepository(session)
        from common.database import IncidentInvestigationBindingRecord
        binding = await session.get(IncidentInvestigationBindingRecord, recommendation_id)
        selection = await repo.persist_governed_resolution_selection(
            tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            analysis_request_id=binding.analysis_request_id, context_snapshot_id=snapshot_id,
            context_fingerprint="d" * 64, recommendation_id=recommendation_id, rca_version=1,
            option=catalog_option(), selected_by="operator-a",
        )
        raw_plan = resolve_execution_plan(
            alert=Alert(
                id=alert_id, tenant_id="tenant-a", source="prometheus", name="KaiOpsServiceDown",
                service="api-gateway", environment="prod", severity=AlertSeverity.CRITICAL,
                description="API endpoint is unreachable", metadata={"incident_id": str(incident_id)},
            ),
            workflow_name="operator-resolution-selection", requires_approval=True,
            risk_tier="high", execution_mode="human-approval",
            resolution_hints="restart service", evidence_basis=["metric:up:api-gateway"],
            incident_id=incident_id, root_cause="api gateway process unavailable", confidence=0.91,
        )
        raw_plan.update({
            "plan_id": uuid5(NAMESPACE_URL, f"execution-plan:{selection['selection_id']}"),
            "recommendation_id": recommendation_id, "recommendation_version": str(recommendation_id),
            "rca_version": 1, "evidence_snapshot_id": snapshot_id,
            "context_fingerprint": "d" * 64, "resolution_selection_id": selection["selection_id"],
            "policy_version": "resolution-policy.v1", "policy_decision": {"decision": "hitl"},
        })
        plan = ExecutionPlanV2.model_validate(raw_plan).finalized().model_dump(mode="json")
        persisted = await repo.persist_compiled_execution_plan(
            selection_id=selection["selection_id"], plan=plan, blocking_reasons=[],
        )
        await session.commit()
        retry = await repo.persist_compiled_execution_plan(
            selection_id=selection["selection_id"], plan=plan, blocking_reasons=[],
        )
        assert retry == persisted
        assert binding.resolution_plan_id == UUID(persisted["plan_id"])
        assert binding.plan_fingerprint == persisted["plan_fingerprint"]
        canonical = await repo.get_current_execution_plan_for_incident(
            tenant_id="tenant-a", incident_id=incident_id,
            recommendation_id=recommendation_id, rca_version=1,
        )
        projection = await session.get(IncidentProjectionRecord, incident_id)

    assert persisted and canonical
    assert projection.projection_payload["execution_plan"]["plan_id"] == canonical["plan_id"]
    assert projection.projection_payload["execution_plan"]["plan_fingerprint"] == canonical["plan_fingerprint"]

    from common.database import AuditLogRecord
    from common.event_publishers import build_event_envelope
    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        background_id = uuid4()
        session.add(AuditLogRecord(id=background_id, tenant_id="tenant-a", actor="resolution-agent",
            action="recommendation.generated", resource_type="incident", resource_id=str(incident_id),
            payload={"id": str(background_id), "incident_id": str(incident_id), "root_cause": "New observation"}))
        await session.commit()
        await repo.save_incident_event(build_event_envelope(
            event_type="incident.recommendation.generated",
            identity={"incident_id": str(incident_id), "alert_id": str(alert_id)},
            scope={"tenant_id": "tenant-a", "service": "api-gateway", "environment": "prod"},
            state={"status": "investigating"}, policy={}, transport={"provider": "test"},
            payload={"recommendation_id": str(background_id), "analysis_request_id": str(uuid4())},
        ))
        await session.commit()
        projection = await session.get(IncidentProjectionRecord, incident_id)
        assert projection.recommendation_id == recommendation_id
        assert (await repo.get_latest_recommendation_for_incident(incident_id, tenant_id="tenant-a"))["id"] == str(recommendation_id)
        assert await session.get(AuditLogRecord, background_id) is not None
        assert await repo.coalesce_superseded_background_rca(
            tenant_id="tenant-a", incident_id=incident_id, snapshot_id=snapshot_id,
            request_id=uuid5(NAMESPACE_URL, f"kaims:enriched-analysis:{snapshot_id}"),
        ) == f"governed-recovery:{recommendation_id}"

    approval_module = load_approval_module()
    approval_module.app.state.session_factory = sqlite_session_factory
    approval_module.settings.database_enabled = True
    approval_module.settings.service_internal_token = "test-internal-signing-key"
    metadata = {
        "rca_version": 1, "context_snapshot_id": str(snapshot_id), "context_fingerprint": "d" * 64,
        "resolution_selection": {**selection, "status": "compiled",
                                 "compiled_execution_plan_id": canonical["plan_id"]},
        "execution_plan": canonical, "runbook_status": "approved",
        "connection_profile": {"secret_ref": "vault://tenant-a/api-gateway"},
        "evidence_quality": {"evidence_coverage": 1.0, "citation_coverage": 1.0,
                             "evidence_fresh": True, "conflict_count": 0},
    }
    approval_module.PENDING_INCIDENTS[f"tenant-a:{incident_id}"] = {
        "tenant_id": "tenant-a", "incident_id": str(incident_id),
        "recommendation": {"id": str(recommendation_id), "incident_id": str(incident_id),
                           "tenant_id": "tenant-a", "metadata": metadata},
    }
    # Durable approval must ignore a stale in-memory view and hydrate the
    # selected immutable plan from the database.
    from common.database import AuditLogRecord, IncidentRecord
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(id=incident_id, tenant_id="tenant-a", service="api-gateway",
            environment="prod", severity="critical", status="awaiting_approval", title="API down", payload={}))
        audit = await session.get(AuditLogRecord, recommendation_id)
        audit.payload = {**audit.payload, "metadata": {**audit.payload["metadata"], **metadata}}
        await session.commit()
    approval_module.ApprovalRequest.model_rebuild(_types_namespace={"UUID": UUID})
    request = approval_module.ApprovalRequest(
        incident_id=incident_id, recommendation_id=recommendation_id, tenant_id="tenant-a",
        plan_id=canonical["plan_id"], plan_fingerprint=canonical["plan_fingerprint"],
        approver="operator-a", approver_role="hitl-reviewer", authorization_scope="execution",
    )
    approval = await approval_module._approval_from_request(request, ApprovalDecision.APPROVED)
    assert str(approval.plan_id) == canonical["plan_id"]
    assert approval.plan_fingerprint == canonical["plan_fingerprint"]
    assert approval.metadata["execution_plan"]["plan_id"] == projection.projection_payload["execution_plan"]["plan_id"]


def test_cached_rca_cannot_be_rebound_to_different_evidence():
    module = load_resolution_module()
    prior = {
        "tenant_id": "tenant-a", "metadata": {
            "context_subject_fingerprint": "a" * 64, "context_fingerprint": "b" * 64,
            "service": "api-gateway", "environment": "prod", "deployment_id": "dep-1",
            "change_id": "change-1", "evidence_ids": ["evidence-old"],
            "evidence_content_checksums": {"evidence-old": "sha256:old"},
            "contradicting_evidence_ids": [],
        },
    }
    snapshot = {
        "tenant_id": "tenant-a", "subject_fingerprint": "a" * 64,
        "context_fingerprint": "b" * 64, "evidence_ids": ["evidence-new"],
        "evidence_checksums": {"evidence-new": "sha256:new"},
        "payload": {"alert": {"service": "api-gateway", "environment": "prod"},
                    "metadata": {"deployment_id": "dep-1", "change_id": "change-1",
                                 "investigation_report": {"conclusion": {"contradicting_evidence_ids": []}}}},
        "expires_at": datetime.now(UTC) + timedelta(minutes=10),
    }
    decision = module.validate_rca_reuse(prior, snapshot)
    assert decision.reusable is False
    assert {"evidence_ids_mismatch", "evidence_checksums_mismatch"}.issubset(decision.reasons)


def test_rca_persistence_rejects_evidence_outside_final_snapshot():
    module = load_resolution_module()
    recommendation = Recommendation(
        tenant_id="tenant-a", incident_id=uuid4(), root_cause="candidate cause", confidence=0.7,
        impact="service impact", recommended_action="collect validation", severity=AlertSeverity.HIGH,
        rationale="candidate", metadata={"evidence_ids": ["forged-evidence"]},
    )
    with pytest.raises(module.HTTPException) as mismatch:
        module._validate_recommendation_snapshot_evidence(
            recommendation, SimpleNamespace(evidence_ids=["bound-evidence"]),
        )
    assert mismatch.value.detail["code"] == "evidence_snapshot_mismatch"


@pytest.mark.asyncio
async def test_refresh_context_to_latest_snapshot_picks_up_evidence_that_arrived_mid_investigation(
    sqlite_session_factory,
):
    """Investigation takes real wall-clock time; if fresh evidence lands while
    it's in flight, persistence correctly refuses to bind an RCA to the now-
    stale snapshot it started with. Retrying the exact same message can never
    succeed - it must re-fetch whatever the current snapshot actually is."""
    from common.database import ContextSnapshotRecord

    module = load_resolution_module()
    module.app.state.session_factory = sqlite_session_factory
    module.settings.database_enabled = True

    incident_id = uuid4()
    alert = Alert(
        id=uuid4(), tenant_id="tenant-a", source="prometheus", name="KaiOpsServiceDown",
        service="api-gateway", environment="prod", severity=AlertSeverity.CRITICAL,
        description="API endpoint is unreachable",
    )
    original_request_id = str(uuid4())
    stale_context = module.Context(tenant_id="tenant-a", incident_id=incident_id, alert=alert, metadata={"analysis_request_id": original_request_id, "analysis_mode": "fresh", "force_full_analysis": True})

    async with sqlite_session_factory() as session:
        session.add(ContextSnapshotRecord(
            snapshot_id=uuid4(), tenant_id="tenant-a", incident_id=str(incident_id),
            alert_signature="sig", subject_fingerprint="c" * 64, context_fingerprint="d" * 64,
            snapshot_stage="enriched", snapshot_version=2, evidence_ids=["evidence-new"],
            payload={
                "tenant_id": "tenant-a", "incident_id": str(incident_id),
                "alert": alert.model_dump(mode="json"),
                "metadata": {"analysis_request_id": str(uuid4()), "analysis_mode": "smart", "force_full_analysis": False, "evidence_ids": ["evidence-new"]},
            },
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        ))
        await session.commit()

        refreshed = await module._refresh_context_to_latest_snapshot(stale_context)

    assert refreshed is not None
    assert refreshed.incident_id == incident_id
    assert refreshed.tenant_id == "tenant-a"
    assert refreshed.metadata["analysis_request_id"] == original_request_id
    assert refreshed.metadata["analysis_mode"] == "fresh"
    assert refreshed.metadata["force_full_analysis"] is True
    assert "evidence-new" in refreshed.metadata["evidence_ids"]


@pytest.mark.asyncio
async def test_refresh_context_to_latest_snapshot_fails_closed_without_a_snapshot(sqlite_session_factory):
    module = load_resolution_module()
    module.app.state.session_factory = sqlite_session_factory
    module.settings.database_enabled = True
    alert = Alert(
        id=uuid4(), tenant_id="tenant-a", source="prometheus", name="KaiOpsServiceDown",
        service="api-gateway", environment="prod", severity=AlertSeverity.CRITICAL,
        description="API endpoint is unreachable",
    )
    context = module.Context(tenant_id="tenant-a", incident_id=uuid4(), alert=alert)

    refreshed = await module._refresh_context_to_latest_snapshot(context)

    assert refreshed is None


@pytest.mark.asyncio
async def test_completed_replay_reuses_saved_recommendation_and_bound_context(monkeypatch):
    from unittest.mock import AsyncMock
    module = load_resolution_module()
    module.settings.database_enabled = True
    iid, request_id, snapshot_id = uuid4(), uuid4(), uuid4()
    alert = Alert(id=uuid4(), tenant_id="tenant-a", source="prometheus", name="ServiceDown",
                  service="api-gateway", environment="prod", severity=AlertSeverity.CRITICAL, description="Unavailable")
    context = module.Context(tenant_id="tenant-a", incident_id=iid, alert=alert,
                             metadata={"analysis_request_id": str(request_id)})
    rid = module._deterministic_recommendation_id(context)
    recommendation = Recommendation(id=rid, tenant_id="tenant-a", incident_id=iid,
        root_cause="Unconfirmed", confidence=0.1, impact="Unknown", recommended_action="Collect evidence",
        severity=alert.severity, rationale="Unconfirmed", commands=[], risk="low", metadata={"evidence_ids": [], "evidence_set_digest": "sha256:" + __import__("hashlib").sha256(b"[]").hexdigest()})
    binding = SimpleNamespace(tenant_id="tenant-a", incident_id=iid, analysis_request_id=request_id,
                              context_snapshot_id=snapshot_id)
    audit = SimpleNamespace(tenant_id="tenant-a", payload=recommendation.model_dump(mode="json"))
    snapshot = SimpleNamespace(tenant_id="tenant-a", incident_id=str(iid), evidence_ids=[],
                               payload=context.model_dump(mode="json"))
    session = AsyncMock(); session.get.side_effect = [binding, audit, snapshot]
    manager = AsyncMock(); manager.__aenter__.return_value = session
    module.app.state.session_factory = lambda: manager
    replay = await module._completed_analysis_for_replay(context)
    assert replay[1].model_dump(mode="json") == recommendation.model_dump(mode="json")
    assert replay[0].metadata["analysis_request_id"] == str(request_id)
    session.merge.assert_not_called()
    session.commit.assert_not_called()


@pytest.mark.asyncio
async def test_expired_replay_requires_a_valid_replacement_snapshot(monkeypatch):
    from unittest.mock import AsyncMock
    module = load_resolution_module()
    original, refreshed = object(), object()
    validate = AsyncMock(side_effect=[module.HTTPException(409, "the bound context snapshot has expired"), {"snapshot_id":"fresh"}])
    refresh = AsyncMock(return_value=refreshed)
    monkeypatch.setattr(module, "_require_context_snapshot_binding", validate)
    monkeypatch.setattr(module, "_refresh_context_to_latest_snapshot", refresh)
    assert await module._initial_snapshot_for_replay(original) == (refreshed, {"snapshot_id":"fresh"})
    assert validate.call_args.args == (refreshed,)
    validate.side_effect = module.HTTPException(409, "the bound context snapshot fingerprint does not match")
    refresh.reset_mock()
    with pytest.raises(module.HTTPException):
        await module._initial_snapshot_for_replay(original)
    refresh.assert_not_called()
