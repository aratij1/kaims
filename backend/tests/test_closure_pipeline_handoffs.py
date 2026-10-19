from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from closure_service.validation import ClosureValidationAgent
from common.database import RcaReportRecord, ResolutionOutboxRecord
from common.models import Incident, IncidentStatus
from common.repository import IncidentRepository
from common.resolution_lifecycle import ResolutionState, create_lifecycle
from sqlalchemy import select
from test_closure_incident_payload import load_closure_app_module
from test_closure_validation_contract import _action, _plan


def observed_action(*, pending=True):
    plan = _plan()
    action = _action(plan=plan, completed_seconds_ago=30 if pending else 120)
    action.parameters["resolution_lifecycle"] = create_lifecycle(
        tenant_id=action.tenant_id,
        incident_id=action.incident_id,
        recommendation_id=uuid4(),
        plan=plan,
        state=ResolutionState.VALIDATING,
    )
    now = datetime.now(UTC)
    action.parameters["validation_observations"] = [
        {
            "validator_id": validator["validator_id"],
            "execution_id": str(action.id),
            "plan_fingerprint": plan["plan_fingerprint"],
            "connector_id": validator["connector_id"],
            "target_resource_id": validator["target_resource_id"],
            "observed_at": (now - timedelta(seconds=offset)).isoformat(),
            "passed": True,
            "result_checksum": f"sha256:{'b' * 64}",
        }
        for validator in plan["validators"]
        for offset in ((10, 0) if pending else (65, 0))
    ]
    return action


@pytest.mark.asyncio
async def test_pending_stability_has_its_own_report_and_event_identity():
    module = load_closure_app_module()
    action = observed_action()
    pending = await ClosureValidationAgent().validate(action)
    assert pending.closure_status == "pending_stability"
    assert pending.metadata["resolution_lifecycle"]["state"] == "pending_stability"
    pending_event = module._build_closure_event_payload(action=action, report=pending, source_payload={})
    assert pending_event["event_contract"]["event_id"].endswith(":pending_stability")

    action.parameters["validation_observations"][0]["passed"] = False
    failed = await ClosureValidationAgent().validate(action)
    failed_event = module._build_closure_event_payload(action=action, report=failed, source_payload={})
    assert failed.closure_status == "validation_failed"
    assert failed.id != pending.id
    assert failed_event["event_contract"]["event_id"] != pending_event["event_contract"]["event_id"]


@pytest.mark.asyncio
async def test_failed_plan_integrity_cannot_be_classified_as_pending_stability():
    action = observed_action()
    action.parameters["approved_plan_fingerprint"] = "sha256:" + "0" * 64
    report = await ClosureValidationAgent().validate(action)
    assert report.closure_status == "validation_failed"
    assert report.metadata["stability_window"]["status"] == "failed"
    assert report.metadata["resolution_lifecycle"]["state"] == "failed_retryable"


@pytest.mark.asyncio
@pytest.mark.parametrize("pending", [True, False])
@pytest.mark.parametrize("jira_raises", [True, False])
async def test_closure_persists_and_publishes_one_final_lifecycle(
    sqlite_session_factory,
    monkeypatch,
    pending,
    jira_raises,
):
    module = load_closure_app_module()
    monkeypatch.setattr(module.settings, "database_enabled", True)
    module.app.state.session_factory = sqlite_session_factory
    action = observed_action(pending=pending)
    incident = Incident(
        id=action.incident_id,
        tenant_id=action.tenant_id,
        service="payments-api",
        environment="test",
        severity="critical",
        status=IncidentStatus.VALIDATING,
        title="Payments unavailable",
        ticket_id="TEST-1",
        metadata={"resolution_lifecycle": action.parameters["resolution_lifecycle"]},
    )
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_incident(incident)
        await session.commit()

    async def fake_jira(*args):
        if jira_raises:
            raise RuntimeError("Jira unavailable")
        return {"status": "skipped", "transitioned": False}

    monkeypatch.setattr(module, "_sync_closure_to_jira", fake_jira)
    report = await ClosureValidationAgent().validate(action)
    event = module._build_closure_event_payload(action=action, report=report, source_payload={})
    result = await module._persist_closure_event(
        app=module.app,
        action=action,
        report=report,
        source_payload={},
        event_payload=event,
    )
    assert result["outbox_enqueued"] is True
    async with sqlite_session_factory() as session:
        stored = await IncidentRepository(session).get_incident(str(action.incident_id), tenant_id=action.tenant_id)
        outbox = (await session.execute(select(ResolutionOutboxRecord))).scalar_one()
        stored_report = await session.get(RcaReportRecord, report.id)
    lifecycle = stored["metadata"]["resolution_lifecycle"]
    assert stored["status"] == ("validating" if pending else "closed")
    assert lifecycle["state"] == ("pending_stability" if pending else "closed")
    assert event["resolution_lifecycle"] == lifecycle
    assert outbox.payload["resolution_lifecycle"] == lifecycle
    assert outbox.payload["report"]["metadata"]["resolution_lifecycle"] == lifecycle
    assert stored_report.payload["metadata"]["resolution_lifecycle"] == lifecycle
    assert outbox.payload["report"]["ticket_id"] == "TEST-1"


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_evidence", ["before_execution", "pre_state", "duplicate_sample", "naive_pre_state"])
async def test_replayed_or_misclassified_observations_cannot_prove_recovery(bad_evidence):
    action = observed_action(pending=False)
    observations = action.parameters["validation_observations"]
    if bad_evidence == "before_execution":
        for item in observations:
            item["observed_at"] = (action.completed_at - timedelta(seconds=10)).isoformat()
    elif bad_evidence == "pre_state":
        for item in observations:
            item["phase"] = "pre_state"
    elif bad_evidence == "duplicate_sample":
        observations[:] = [observations[0], dict(observations[0])]
    else:
        action.parameters["pre_state_validation_observations"] = [
            {**observations[0], "observed_at": datetime.now().isoformat()}
        ]
    report = await ClosureValidationAgent().validate(action)
    if bad_evidence == "naive_pre_state":
        assert report.metadata["pre_state_validation_observations"] == []
    else:
        assert report.health_restored is False
        assert report.closure_status == "validation_failed"


@pytest.mark.asyncio
@pytest.mark.parametrize("mismatch", ["plan", "attempt", "incident", "late_pending", "related"])
async def test_stale_closure_cannot_mutate_incident_or_create_report(
    sqlite_session_factory,
    monkeypatch,
    mismatch,
):
    module = load_closure_app_module()
    monkeypatch.setattr(module.settings, "database_enabled", True)
    module.app.state.session_factory = sqlite_session_factory
    action = observed_action(pending=mismatch == "late_pending")
    report = await ClosureValidationAgent().validate(action)
    current = dict(action.parameters["resolution_lifecycle"])
    if mismatch == "plan":
        current["recommendation_id"] = str(uuid4())
    elif mismatch == "attempt":
        current["execution"] = {"action_id": str(uuid4())}
    elif mismatch == "incident":
        report.incident_id = uuid4()
    elif mismatch == "related":
        action.parameters["resolution_propagated"] = True
    else:
        current.update(state="closed", state_version=10)
    incident = Incident(
        id=action.incident_id,
        tenant_id=action.tenant_id,
        service="payments-api",
        environment="test",
        severity="critical",
        status=IncidentStatus.CLOSED if mismatch == "late_pending" else IncidentStatus.VALIDATING,
        title="Current incident",
        metadata={"resolution_lifecycle": current},
    )
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_incident(incident)
        await session.commit()
    result = await module._persist_closure_event(
        app=module.app,
        action=action,
        report=report,
        source_payload={},
        sync_jira=False,
    )
    assert result["status"] == "stale_suppressed"
    assert result["outbox_enqueued"] is False
    async with sqlite_session_factory() as session:
        stored = await IncidentRepository(session).get_incident(str(action.incident_id), tenant_id=action.tenant_id)
        assert stored["metadata"]["resolution_lifecycle"] == current
        assert (await session.execute(select(ResolutionOutboxRecord))).scalars().all() == []
        assert (await session.execute(select(RcaReportRecord))).scalars().all() == []


@pytest.mark.asyncio
async def test_duplicate_delivery_records_learning_once(sqlite_session_factory, monkeypatch):
    from unittest.mock import AsyncMock

    module = load_closure_app_module()
    monkeypatch.setattr(module.settings, "database_enabled", True)
    module.app.state.session_factory = sqlite_session_factory
    action = observed_action(pending=False)
    incident = Incident(
        id=action.incident_id,
        tenant_id=action.tenant_id,
        service="payments-api",
        environment="test",
        severity="critical",
        status=IncidentStatus.VALIDATING,
        title="Payments incident",
        metadata={"resolution_lifecycle": action.parameters["resolution_lifecycle"]},
    )
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_incident(incident)
        await session.commit()
    learning = AsyncMock()
    monkeypatch.setattr(module, "_record_closure_learning", learning)
    for attempt in range(2):
        report = await module._validate_action(action)
        result = await module._persist_closure_event(
            app=module.app,
            action=action,
            report=report,
            source_payload={},
            sync_jira=False,
        )
        assert result["outbox_enqueued"] is (attempt == 0)
    learning.assert_awaited_once()
    async with sqlite_session_factory() as session:
        assert len((await session.execute(select(RcaReportRecord))).scalars().all()) == 1
        assert len((await session.execute(select(ResolutionOutboxRecord))).scalars().all()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("active", [True, False])
@pytest.mark.parametrize("publish_failure", [True, False])
async def test_manual_close_checks_lifecycle_before_jira(sqlite_session_factory, monkeypatch, active, publish_failure):
    from unittest.mock import AsyncMock

    from fastapi import HTTPException

    module = load_closure_app_module()
    monkeypatch.setattr(module.settings, "database_enabled", True)
    monkeypatch.setattr(module.settings, "service_internal_token", "test-token")
    module.app.state.session_factory = sqlite_session_factory
    action = observed_action()
    lifecycle = action.parameters["resolution_lifecycle"]
    lifecycle["state"] = "executing" if active else "failed_retryable"
    lifecycle["execution"] = {"action_id": str(action.id)}
    incident = Incident(
        id=action.incident_id,
        tenant_id=action.tenant_id,
        service="payments-api",
        environment="test",
        severity="critical",
        status=IncidentStatus.REMEDIATING if active else IncidentStatus.FAILED,
        title="Payments incident",
        metadata={"resolution_lifecycle": lifecycle},
    )
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_incident(incident)
        await session.commit()
    jira = AsyncMock(return_value={"commented": True})
    monkeypatch.setattr(module, "_sync_closure_to_jira", jira)
    monkeypatch.setattr(module, "_publish_closure_event", AsyncMock(side_effect=RuntimeError("broker unavailable") if publish_failure else None))
    request = module.ManualClosureRequest(
        comment="Reviewed incident and accepted administrative disposition",
        actor_id="operator-1",
        actor_role="Administrator",
        tenant_id=action.tenant_id,
        auth_jti="auth-1",
    )
    if active:
        with pytest.raises(HTTPException) as exc:
            await module.manual_close_incident(str(action.incident_id), request, "test-token")
        assert exc.value.status_code == 409
        jira.assert_not_awaited()
    else:
        result = await module.manual_close_incident(str(action.incident_id), request, "test-token")
        assert result["status"] == "closed"
        assert result["event_delivery"] == ("queued" if publish_failure else "published")
        async with sqlite_session_factory() as session:
            stored = await IncidentRepository(session).get_incident(str(action.incident_id), tenant_id=action.tenant_id)
            from common.repository import ContextEnrichmentRepository
            operations = await ContextEnrichmentRepository(session).incident_operations_state(
                tenant_id=action.tenant_id, incident_id=str(action.incident_id),
            )
            assert operations["validation"]["closure_kind"] == "manual"
            assert operations["validation"]["status"] == "closed"
            assert operations["validation"]["report_id"]
            assert operations["validation"]["health_restored"] is False
            assert operations["validation"]["alerts_cleared"] is False
            assert await IncidentRepository(session).committed_non_execution_closure_report(
                tenant_id="another-tenant", incident_id=action.incident_id,
            ) is None
            # Older administrative reports were incorrectly stored with the
            # validation_failed default. Their committed closure still binds them.
            legacy_report = await session.get(RcaReportRecord, UUID(operations["validation"]["report_id"]))
            legacy_report.closure_status = "validation_failed"
            await session.flush()
            assert (await IncidentRepository(session).committed_non_execution_closure_report(
                tenant_id=action.tenant_id, incident_id=action.incident_id,
            )).id == legacy_report.id
            legacy_operations = await ContextEnrichmentRepository(session).incident_operations_state(
                tenant_id=action.tenant_id, incident_id=str(action.incident_id),
            )
            assert legacy_operations["validation"]["status"] == "closed"
            assert legacy_operations["validation"]["health_restored"] is False
        assert stored["metadata"]["resolution_lifecycle"]["state"] == "closed"
        assert stored["metadata"]["resolution_lifecycle"]["validation"]["passed"] is False


@pytest.mark.asyncio
async def test_outbox_failure_rolls_back_report_and_incident(sqlite_session_factory, monkeypatch):
    from unittest.mock import AsyncMock

    module = load_closure_app_module()
    monkeypatch.setattr(module.settings, "database_enabled", True)
    module.app.state.session_factory = sqlite_session_factory
    action = observed_action(pending=False)
    incident = Incident(
        id=action.incident_id,
        tenant_id=action.tenant_id,
        service="payments-api",
        environment="test",
        severity="critical",
        status=IncidentStatus.VALIDATING,
        title="Payments incident",
        metadata={"resolution_lifecycle": action.parameters["resolution_lifecycle"]},
    )
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_incident(incident)
        await session.commit()
    monkeypatch.setattr(
        IncidentRepository, "enqueue_resolution_event", AsyncMock(side_effect=RuntimeError("storage failed"))
    )
    report = await module._validate_action(action)
    with pytest.raises(RuntimeError, match="storage failed"):
        await module._persist_closure_event(
            app=module.app,
            action=action,
            report=report,
            source_payload={},
            sync_jira=False,
        )
    async with sqlite_session_factory() as session:
        stored = await IncidentRepository(session).get_incident(str(action.incident_id), tenant_id=action.tenant_id)
        assert stored["status"] == "validating"
        assert (await session.execute(select(RcaReportRecord))).scalars().all() == []
