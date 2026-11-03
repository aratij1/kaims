from datetime import UTC, datetime, timedelta
import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select

from closure_service import recovery_assessments as assessments
from closure_service.observations import PrometheusRecoveryObserver
from common.database import ActionRecord, AlertRecord, AuditLogRecord, RcaReportRecord, ResolutionOutboxRecord, ValidationObservationRecord, IncidentProjectionRecord, IncidentLifecycleTransitionRecord
from common.models import Incident, IncidentStatus
from common.repository import IncidentRepository
from common.recovery_observers import RecoveryObserverRegistry
from test_closure_incident_payload import load_closure_app_module
from test_recovery_observer_runtime import registry_payload, prometheus_response


@pytest_asyncio.fixture
async def assessment_case(sqlite_session_factory, monkeypatch, tmp_path):
    module = load_closure_app_module()
    monkeypatch.setattr(module.settings, "database_enabled", True)
    monkeypatch.setattr(module.settings, "service_internal_token", "test-internal")
    module.app.state.session_factory = sqlite_session_factory
    registry = registry_payload()
    profile = registry["profiles"][0]
    profile["allow_operator_verified_closure"] = True
    for c in profile["checks"]:
        c["step_seconds"] = 30
        c["spec"].update(observation_window_seconds=300, minimum_sample_count=11)
    path = tmp_path / "observers.json"
    path.write_text(json.dumps(registry))
    monkeypatch.setattr(module.settings, "recovery_observer_registry_path", str(path))
    alert_id = uuid4()
    incident = Incident(tenant_id="tenant-a", service="payments-api", environment="test", severity="critical",
        title="PaymentsDown", alert_ids=[alert_id], status="investigating")
    async with sqlite_session_factory() as session:
        session.add(AlertRecord(id=alert_id, tenant_id="tenant-a", source="prometheus", name="PaymentsDown",
            service="payments-api", environment="test", severity="critical", payload={}))
        await IncidentRepository(session).save_incident(incident)
        await session.commit()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=module.app), base_url="http://test",
                                headers={"x-kaiops-internal-token": "test-internal"}) as client:
        yield SimpleNamespace(module=module, client=client, factory=sqlite_session_factory, incident=incident,
            registry=registry, path=path, base=f"/incidents/{incident.id}/recovery-assessments",
            identity={"actor_id": "operator", "actor_role": "ADMIN", "tenant_id": "tenant-a", "auth_jti": "test-jti"})


async def start(case):
    response = await case.client.post(case.base, json={**case.identity, "comment": "Repair completed outside the executor."})
    assert response.status_code == 200, response.text
    return response.json()["assessment_id"]


async def age(case, assessment_id, seconds=400):
    async with case.factory() as session:
        row = await session.get(AuditLogRecord, UUID(assessment_id))
        row.payload = {**row.payload, "requested_at": (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()}
        await session.commit()


def mock_observer(monkeypatch, fault=None):
    observer = PrometheusRecoveryObserver(transport=httpx.MockTransport(lambda request: prometheus_response(request, fault=fault)))
    monkeypatch.setattr(assessments, "PrometheusRecoveryObserver", lambda: observer)


@pytest.mark.asyncio
async def test_real_range_contract_closes_atomically_without_corrective_execution(assessment_case, monkeypatch):
    c = assessment_case
    mock_observer(monkeypatch)
    aid = await start(c)
    early = await c.client.post(f"{c.base}/{aid}/evaluate", json=c.identity)
    assert early.json()["status"] == "pending_stability"
    await age(c, aid)
    response = await c.client.post(f"{c.base}/{aid}/evaluate", json=c.identity)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "closed"
    async with c.factory() as session:
        incident = await IncidentRepository(session).get_incident(str(c.incident.id), tenant_id="tenant-a")
        report = (await session.execute(select(RcaReportRecord))).scalar_one()
        outbox = (await session.execute(select(ResolutionOutboxRecord).where(ResolutionOutboxRecord.event_id.like("closure:%")))).scalar_one()
        projection = await session.get(IncidentProjectionRecord, c.incident.id)
        assert projection.lifecycle_state == "CLOSED"
        transition = (await session.execute(select(IncidentLifecycleTransitionRecord))).scalar_one()
        assert transition.previous_state == "DETECTED"
        assert transition.new_state == "CLOSED"
        audit = await session.get(AuditLogRecord, UUID(aid))
        assert not (await session.execute(select(ActionRecord))).scalars().all()
        observations = (await session.execute(select(ValidationObservationRecord))).scalars().all()
        assert len(observations) == 66
        assert all(o.remediation_action_id is None for o in observations)
    async with c.factory() as session:
        rows = await IncidentRepository(session).list_incident_projections(tenant_id="tenant-a", include_enrichment=False)
    assert rows[0]["resolution_lifecycle"]["validation"]["closure_kind"] == "observed_recovery"
    assert "outside the KaiMS executor" in rows[0]["status_reason"]
    assert incident["status"] == "closed"
    validation = incident["metadata"]["resolution_lifecycle"]["validation"]
    assert validation["passed"] is True
    assert validation["administrative_disposition"] is False
    assert validation["operator_identity"]["actor_id"] == "operator"
    assert report.payload["health_restored"] is True
    assert report.payload["remediation_action_id"] is None
    assert report.payload["metadata"]["corrective_execution_performed"] is False
    assert outbox.payload["remediation_action"] is None
    assert outbox.payload["recovery_assessment_id"] == aid
    assert audit.payload["status"] == "closed"
    assert audit.payload["last_result"]["status"] == "verified"
    samples = response.json()["checks"][0]["samples"]
    assert len(samples) == 11
    assert all(s["assessment_id"] == aid and "execution_id" not in s for s in samples)
    retry = await c.client.post(f"{c.base}/{aid}/evaluate", json=c.identity)
    assert retry.json()["report_id"] == str(report.id)
    async with c.factory() as session:
        transitions = (await session.execute(select(IncidentLifecycleTransitionRecord))).scalars().all()
        assert len(transitions) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["no_data", "gap", "failed", "stale", "nan"])
async def test_unhealthy_or_incomplete_observations_never_close(assessment_case, monkeypatch, fault):
    c = assessment_case
    def response(request):
        original = prometheus_response(request).json()
        values = original["data"]["result"][0]["values"]
        if fault == "no_data": original["data"]["result"] = []
        elif fault == "gap": values.pop(0)
        elif fault == "failed": values[0][1] = "0"
        elif fault == "stale": values[0][0] -= 1
        elif fault == "nan": values[0][1] = "NaN"
        return httpx.Response(200, json=original)
    observer = PrometheusRecoveryObserver(transport=httpx.MockTransport(response))
    monkeypatch.setattr(assessments, "PrometheusRecoveryObserver", lambda: observer)
    aid = await start(c)
    await age(c, aid)
    result = await c.client.post(f"{c.base}/{aid}/evaluate", json=c.identity)
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "blocked"
    async with c.factory() as session:
        incident = await IncidentRepository(session).get_incident(str(c.incident.id), tenant_id="tenant-a")
        assert incident["status"] == "investigating"
        assert not (await session.execute(select(RcaReportRecord))).scalars().all()
        assert not (await session.execute(select(ResolutionOutboxRecord))).scalars().all()


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["profile", "incident", "active_action", "tenant", "expired"])
async def test_changed_scope_or_expired_assessment_blocks_closure(assessment_case, monkeypatch, change):
    c = assessment_case
    mock_observer(monkeypatch)
    aid = await start(c)
    await age(c, aid)
    identity = dict(c.identity)
    if change == "profile":
        c.registry["profiles"][0]["checks"][0]["spec"]["threshold"] = 2
        c.path.write_text(json.dumps(c.registry))
    if change == "tenant": identity["tenant_id"] = "tenant-b"
    async with c.factory() as session:
        if change == "incident":
            changed = c.incident.model_copy(update={"status": IncidentStatus.AWAITING_APPROVAL})
            await IncidentRepository(session).save_incident(changed)
        if change == "active_action":
            session.add(ActionRecord(id=uuid4(), tenant_id="tenant-a", incident_id=c.incident.id,
                action_type="restart", target="payments-api", status="approved", payload={}))
        if change == "expired":
            row = await session.get(AuditLogRecord, UUID(aid))
            row.payload = {**row.payload, "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}
        await session.commit()
    result = await c.client.post(f"{c.base}/{aid}/evaluate", json=identity)
    assert result.status_code in {200, 404, 409}, result.text
    assert result.status_code != 200 or result.json()["status"] in {"superseded", "expired"}
    async with c.factory() as session:
        assert not (await session.execute(select(RcaReportRecord))).scalars().all()


@pytest.mark.asyncio
async def test_explicit_registration_and_operator_authorization_required(assessment_case):
    c = assessment_case
    body = {**c.identity, "comment": "A completed external repair."}
    assert (await c.client.post(c.base, json=body, headers={"x-kaiops-internal-token": "wrong"})).status_code == 403
    assert (await c.client.post(c.base, json={**body, "actor_role": "VIEWER"})).status_code == 403
    assert (await c.client.post(c.base, json={**body, "samples": [{"passed": True}]})).status_code == 422
    del c.registry["profiles"][0]["allow_operator_verified_closure"]
    assert RecoveryObserverRegistry.model_validate(c.registry).profiles[0].allow_operator_verified_closure is False
    c.path.write_text(json.dumps(c.registry))
    assert (await c.client.post(c.base, json=body)).status_code == 409


@pytest.mark.asyncio
async def test_background_evaluator_resumes_persisted_assessment(assessment_case, monkeypatch):
    c = assessment_case
    mock_observer(monkeypatch)
    aid = await start(c)
    await age(c, aid)
    await c.module.app.state.reconcile_recovery_assessments()
    async with c.factory() as session:
        row = await session.get(AuditLogRecord, UUID(aid))
        assert row.payload["status"] == "closed"


@pytest.mark.asyncio
async def test_binding_is_rechecked_after_network_collection(assessment_case, monkeypatch):
    c = assessment_case
    mock_observer(monkeypatch)
    aid = await start(c)
    await age(c, aid)
    real_collect = assessments.collect_assessment
    async def changed_during_collection(*args, **kwargs):
        result = await real_collect(*args, **kwargs)
        async with c.factory() as session:
            await IncidentRepository(session).save_incident(c.incident.model_copy(update={"status": IncidentStatus.AWAITING_APPROVAL}))
            await session.commit()
        return result
    monkeypatch.setattr(assessments, "collect_assessment", changed_during_collection)
    response = await c.client.post(f"{c.base}/{aid}/evaluate", json=c.identity)
    assert response.status_code == 409
    async with c.factory() as session:
        assert not (await session.execute(select(RcaReportRecord))).scalars().all()
        assert (await session.get(AuditLogRecord, UUID(aid))).payload["status"] == "pending_stability"


@pytest.mark.asyncio
async def test_gateway_rejects_forged_identity_and_evidence():
    from api_gateway.control_routes import build_control_router
    from fastapi import FastAPI
    from unittest.mock import AsyncMock
    auth = SimpleNamespace(role="ADMIN", email="operator@example.test", username="operator", user_id="operator",
                           tenant_id="tenant-a", jwt_id="real-jti")
    proxy = AsyncMock(return_value={"status": "pending_stability"})
    app = FastAPI()
    app.include_router(build_control_router(settings=SimpleNamespace(closure_service_url="http://closure.test"),
        guarded_proxy=proxy, raw_proxy=AsyncMock(), trace_id_from_header=lambda x: "test-trace", analyzer=None,
        load_recent_events=AsyncMock(), build_audit_contract=lambda x: {}, load_audit_summary=AsyncMock(),
        auth_context_from_request=AsyncMock(return_value=auth)))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        path = f"/incidents/{uuid4()}/recovery-assessments"
        for field in ("tenant_id", "actor_id", "actor_role", "auth_jti", "samples", "requested_at", "profile"):
            response = await client.post(path, json={"comment": "Externally completed repair.", field: "forged"})
            assert response.status_code == 422
        proxy.assert_not_awaited()
        response = await client.post(path, json={"comment": "Externally completed repair."})
        assert response.status_code == 200
        body = proxy.call_args.kwargs["payload"]
        assert body["actor_id"] == "operator@example.test"
        assert body["auth_jti"] == "real-jti"
        auth.role = "VIEWER"
        assert (await client.post(path, json={"comment": "Externally completed repair."})).status_code == 403


@pytest.mark.asyncio
async def test_mixed_alerts_require_exact_registered_bundle_and_target_labels(assessment_case, monkeypatch):
    c = assessment_case
    mock_observer(monkeypatch)
    second = uuid4()
    c.incident.alert_ids.append(second)
    async with c.factory() as session:
        original = await session.get(AlertRecord, c.incident.alert_ids[0])
        original.payload = {"labels": {"instance": "payments:8080"}}
        session.add(AlertRecord(id=second, tenant_id="tenant-a", source="prometheus", name="PaymentsSlow",
            service="payments-api", environment="test", severity="critical", payload={"labels": {"instance": "payments:8080"}}))
        await IncidentRepository(session).save_incident(c.incident)
        await session.commit()
    body = {**c.identity, "comment": "Recovery verification of the restored demo."}
    assert (await c.client.post(c.base, json=body)).status_code == 409
    c.registry["profiles"][0].update(additional_alert_names=["PaymentsSlow"], required_alert_labels={"instance": "other:8080"})
    c.path.write_text(json.dumps(c.registry))
    assert (await c.client.post(c.base, json=body)).status_code == 409
    c.registry["profiles"][0]["required_alert_labels"] = {"instance": "payments:8080"}
    c.path.write_text(json.dumps(c.registry))
    aid = await start(c)
    await age(c, aid)
    response = await c.client.post(f"{c.base}/{aid}/evaluate", json=c.identity)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "closed"


@pytest.mark.asyncio
async def test_changed_target_label_invalidates_assessment(assessment_case, monkeypatch):
    c = assessment_case
    mock_observer(monkeypatch)
    c.registry["profiles"][0]["required_alert_labels"] = {"instance": "payments:8080"}
    c.path.write_text(json.dumps(c.registry))
    async with c.factory() as session:
        alert = await session.get(AlertRecord, c.incident.alert_ids[0])
        alert.payload = {"labels": {"instance": "payments:8080"}}
        await session.commit()
    aid = await start(c)
    await age(c, aid)
    async with c.factory() as session:
        alert = await session.get(AlertRecord, c.incident.alert_ids[0])
        alert.payload = {"labels": {"instance": "different:8080"}}
        await session.commit()
    assert (await c.client.post(f"{c.base}/{aid}/evaluate", json=c.identity)).status_code == 409


def test_ambiguous_bundle_or_extra_alert_is_not_eligible():
    from copy import deepcopy
    payload = registry_payload()
    profile = payload["profiles"][0]
    profile.update(allow_operator_verified_closure=True, additional_alert_names=["PaymentsSlow"])
    registry = RecoveryObserverRegistry.model_validate(payload)
    args = dict(tenant_id="tenant-a", environment="test", target="payments-api")
    alerts = [{"name": "PaymentsDown"}, {"name": "PaymentsSlow"}]
    assert registry.assessment_profile_for(**args, alerts=alerts) is not None
    assert registry.assessment_profile_for(**args, alerts=alerts + [{"name": "OtherFailure"}]) is None
    duplicate = deepcopy(profile)
    duplicate.update(alert_name="PaymentsSlow", additional_alert_names=["PaymentsDown"])
    payload["profiles"].append(duplicate)
    registry = RecoveryObserverRegistry.model_validate(payload)
    assert registry.assessment_profile_for(**args, alerts=alerts) is None


def test_incident_allowlist_limits_batch_closure_authority():
    payload = registry_payload()
    allowed = uuid4()
    payload["profiles"][0].update(allow_operator_verified_closure=True, operator_verified_incident_ids=[str(allowed)])
    registry = RecoveryObserverRegistry.model_validate(payload)
    args = dict(tenant_id="tenant-a", environment="test", target="payments-api", alerts=[{"name": "PaymentsDown"}])
    assert registry.assessment_profile_for(**args, incident_id=allowed) is not None
    assert registry.assessment_profile_for(**args, incident_id=uuid4()) is None
    assert registry.assessment_profile_for(**args) is None


@pytest.mark.asyncio
async def test_runtime_enforces_incident_allowlist(assessment_case):
    c = assessment_case
    profile = c.registry["profiles"][0]
    profile["operator_verified_incident_ids"] = [str(uuid4())]
    c.path.write_text(json.dumps(c.registry))
    body = {**c.identity, "comment": "User-authorized verification of the selected batch."}
    assert (await c.client.post(c.base, json=body)).status_code == 409
    profile["operator_verified_incident_ids"] = [str(c.incident.id)]
    c.path.write_text(json.dumps(c.registry))
    assert (await c.client.post(c.base, json=body)).status_code == 200


def test_same_primary_alert_requires_disjoint_explicit_incident_batches():
    from copy import deepcopy
    payload = registry_payload()
    first_id, second_id = uuid4(), uuid4()
    first = payload["profiles"][0]
    first.update(allow_operator_verified_closure=True, operator_verified_incident_ids=[str(first_id)])
    second = deepcopy(first)
    second.update(operator_verified_incident_ids=[str(second_id)], additional_alert_names=["PaymentsSlow"])
    payload["profiles"].append(second)
    registry = RecoveryObserverRegistry.model_validate(payload)
    args = dict(tenant_id="tenant-a", environment="test", target="payments-api")
    assert registry.assessment_profile_for(**args, incident_id=first_id, alerts=[{"name":"PaymentsDown"}]) is not None
    assert registry.assessment_profile_for(**args, incident_id=second_id, alerts=[{"name":"PaymentsDown"}]) is None
    assert registry.assessment_profile_for(**args, incident_id=second_id, alerts=[{"name":"PaymentsDown"},{"name":"PaymentsSlow"}]) is not None
    assert registry.profile_for(**args, alert_name="PaymentsDown") is None
    second["operator_verified_incident_ids"] = [str(first_id)]
    with pytest.raises(ValueError, match="duplicate recovery"):
        RecoveryObserverRegistry.model_validate(payload)
