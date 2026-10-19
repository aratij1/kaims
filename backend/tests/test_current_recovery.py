from datetime import UTC, datetime, timedelta
import json
import httpx
import pytest
from sqlalchemy import select, func
from fastapi import HTTPException
from common.database import ActionRecord, AuditLogRecord, IncidentRecord, RcaReportRecord, ResolutionOutboxRecord
from common.recovery_status import project_observation, checksum, observation_id
from common.recovery_observers import RecoveryObserverRegistry
from closure_service.current_recovery import verify_current_recovery
from closure_service.recovery_assessments import collect_assessment
from closure_service.observations import PrometheusRecoveryObserver
from test_recovery_assessments import assessment_case
from test_recovery_observer_runtime import prometheus_response


def test_current_observation_rejects_stale_or_tampered_proof():
    now = datetime.now(UTC)
    result = {"status": "blocked", "checks": []}
    payload = {"result": result, "valid_until": (now + timedelta(seconds=120)).isoformat(), "validation_checksum": checksum(result)}
    assert project_observation(payload, now=now)["status"] == "blocked"
    assert project_observation(payload, now=now + timedelta(seconds=121))["status"] == "stale"
    payload["result"] = {"status": "verified"}
    assert project_observation(payload, now=now)["status"] == "invalid"
    payload["validation_checksum"] = checksum(payload["result"])
    assert project_observation(payload, now=now)["status"] == "invalid"


@pytest.mark.asyncio
@pytest.mark.parametrize("fault,expected", [(None,"verified"),("no_data","blocked"),("failed_check","blocked")])
async def test_current_checks_do_not_require_rca_or_close_linked_tickets(assessment_case, fault, expected):
    case = assessment_case
    case.registry["profiles"][0]["allow_automatic_observation"] = True
    registry = RecoveryObserverRegistry.model_validate(case.registry)
    async with case.factory() as session:
        incident = await session.get(IncidentRecord, case.incident.id)
        incident.ticket_id = "KAN-TEST-READONLY"
        await session.commit()
    async def collect(registered, profile, record, **kwargs):
        return await collect_assessment(registered, profile, record,
            observer=PrometheusRecoveryObserver(transport=httpx.MockTransport(lambda r:prometheus_response(r,fault=fault))), **kwargs)
    result = await verify_current_recovery(case.factory, registry, "tenant-a", case.incident.id, collector=collect)
    assert result["status"] == expected
    assert len(result["checks"]) == 6
    assert result["closes_incident"] is False
    async with case.factory() as session:
        incident = await session.get(IncidentRecord, case.incident.id)
        assert incident.status == "investigating"
        assert incident.ticket_id == "KAN-TEST-READONLY"
        for model in (ActionRecord, RcaReportRecord, ResolutionOutboxRecord):
            assert await session.scalar(select(func.count()).select_from(model)) == 0
        observation = await session.get(AuditLogRecord, observation_id("tenant-a", case.incident.id))
        assert observation.payload["validation_checksum"] == checksum(observation.payload["result"])


@pytest.mark.asyncio
async def test_observation_requires_explicit_scope_and_tenant(assessment_case):
    case = assessment_case
    registry = RecoveryObserverRegistry.model_validate(case.registry)
    with pytest.raises(HTTPException) as error:
        await verify_current_recovery(case.factory, registry, "tenant-a", case.incident.id)
    assert error.value.status_code == 409
    with pytest.raises(HTTPException) as error:
        await verify_current_recovery(case.factory, registry, "tenant-b", case.incident.id)
    assert error.value.status_code == 404


@pytest.mark.asyncio
async def test_observation_endpoint_does_not_accept_client_proof(assessment_case):
    case = assessment_case
    endpoint = f"/incidents/{case.incident.id}/recovery-observation"
    response = await case.client.post(endpoint,json={**case.identity,"health_restored":True})
    assert response.status_code == 422
