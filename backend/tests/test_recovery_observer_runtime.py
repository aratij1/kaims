from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from unittest.mock import AsyncMock

import httpx
import pytest
from closure_service.observations import PrometheusRecoveryObserver, collect_recovery_observations
from closure_service.validation import ClosureValidationAgent
from common.orchestration.execution_plan_contract import canonical_plan_fingerprint
from common.recovery_observers import RecoveryObserverRegistry, load_recovery_observer_registry
from common.resolution_lifecycle import ResolutionState, create_lifecycle
from test_closure_incident_payload import load_closure_app_module
from test_closure_validation_contract import _action, _plan, _validators

KINDS = ["availability", "alert_clearance", "error_rate", "latency", "dependency_health", "critical_alerts"]


def registry_payload():
    specs = _validators(KINDS)
    checks = []
    for spec in specs:
        query = f'{spec["kind"]}{{tenant="tenant-a",target="payments-api"}}'
        spec["check_reference"] = "promql:sha256:" + sha256(query.encode()).hexdigest()
        checks.append({"spec": spec, "query": query, "step_seconds": 15})
    return {
        "schema_version": "kaims.recovery-observers.v1",
        "sources": [{"source_id": "fake-observer", "tenant_id": "tenant-a", "endpoint": "http://observer.test"}],
        "profiles": [
            {
                "tenant_id": "tenant-a",
                "environment": "test",
                "target_resource_id": "payments-api",
                "alert_name": "PaymentsDown",
                "checks": checks,
            }
        ],
    }


def bound_action(registry, *, seconds_ago=180, now=None):
    now = now or datetime.now(UTC)
    plan = _plan(validators=registry.profiles[0].specs())
    plan.update(environment="test", alert={"name": "PaymentsDown"})
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    action = _action(plan=plan)
    action.completed_at = now - timedelta(seconds=seconds_ago)
    action.parameters["resolution_lifecycle"] = create_lifecycle(
        tenant_id=action.tenant_id,
        incident_id=action.incident_id,
        recommendation_id="recommendation-v1",
        plan=plan,
        state=ResolutionState.VALIDATING,
    )
    return action


def prometheus_response(request, *, fault=None):
    params = request.url.params
    start, end, step = (int(params[key]) for key in ("start", "end", "step"))
    values = [[stamp, "1"] for stamp in range(start, end + 1, step)]
    body = {"status": "success", "data": {"resultType": "matrix", "result": [{"metric": {}, "values": values}]}}
    if fault == "no_data":
        body["data"]["result"] = []
    elif fault == "gap":
        values.pop(0)
    elif fault == "nan":
        values[-1][1] = "NaN"
    elif fault == "old_timestamp":
        values[-1][0] -= step
    elif fault == "multiple_series":
        body["data"]["result"].append({"metric": {"target": "other"}, "values": values})
    elif fault == "warning":
        body["warnings"] = ["partial result"]
    elif fault == "failed_check":
        values[-1][1] = "0"
    elif fault == "http_error":
        return httpx.Response(503)
    elif fault == "redirect":
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})
    return httpx.Response(200, json=body)


@pytest.mark.asyncio
async def test_independent_range_closes_without_executor_recovery_assertions():
    registry = RecoveryObserverRegistry.model_validate(registry_payload())
    action = bound_action(registry)
    action.parameters["validation_observations"] = [{"passed": True, "forged": True}]
    action.parameters["execution_result"] = {"recovery_validated": False}
    requests = []

    def handle(request):
        requests.append(request)
        return prometheus_response(request)

    enriched = await collect_recovery_observations(
        action,
        registry,
        observer=PrometheusRecoveryObserver(transport=httpx.MockTransport(handle)),
    )
    report = await ClosureValidationAgent().validate(enriched)
    assert report.health_restored is True
    assert report.closure_status == "closed"
    assert report.validation["executor_recovery_validated"] is False
    assert len(requests) == 6
    assert {request.url.params["query"] for request in requests} == {
        check.query for check in registry.profiles[0].checks
    }
    assert all(request.url.path == "/api/v1/query_range" for request in requests)
    samples = report.metadata["independent_validation_observations"]
    assert samples and all(sample["execution_id"] == str(action.id) for sample in samples)
    assert all(datetime.fromisoformat(sample["observed_at"]) > action.completed_at for sample in samples)
    assert all("forged" not in sample for sample in samples)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "no_data",
        "gap",
        "nan",
        "old_timestamp",
        "multiple_series",
        "warning",
        "http_error",
        "redirect",
    ],
)
async def test_incomplete_or_untrusted_response_stays_pending_then_fails(fault):
    registry = RecoveryObserverRegistry.model_validate(registry_payload())
    now = datetime.now(UTC)
    action = bound_action(registry, seconds_ago=100, now=now)
    observer = PrometheusRecoveryObserver(
        transport=httpx.MockTransport(lambda request: prometheus_response(request, fault=fault))
    )
    enriched = await collect_recovery_observations(action, registry, observer=observer, now=now)
    report = await ClosureValidationAgent().validate(enriched)
    assert report.health_restored is False
    assert report.closure_status == "pending_stability"
    assert report.metadata["closed_loop_validation"]["next_action"] == "OBSERVE"
    timed_out = await collect_recovery_observations(
        action,
        registry,
        observer=observer,
        now=now + timedelta(minutes=10),
    )
    report = await ClosureValidationAgent().validate(timed_out)
    assert report.health_restored is False
    assert report.closure_status == "validation_failed"


@pytest.mark.asyncio
async def test_actual_threshold_failure_never_waits_for_stability():
    registry = RecoveryObserverRegistry.model_validate(registry_payload())
    action = bound_action(registry)
    enriched = await collect_recovery_observations(
        action,
        registry,
        observer=PrometheusRecoveryObserver(
            transport=httpx.MockTransport(lambda request: prometheus_response(request, fault="failed_check"))
        ),
    )
    report = await ClosureValidationAgent().validate(enriched)
    assert report.health_restored is False
    assert report.closure_status == "validation_failed"


@pytest.mark.asyncio
async def test_fresh_execution_warms_up_before_minimum_samples():
    registry = RecoveryObserverRegistry.model_validate(registry_payload())
    action = bound_action(registry, seconds_ago=0)
    transport = httpx.MockTransport(lambda request: pytest.fail("no complete post-execution interval yet"))
    enriched = await collect_recovery_observations(
        action,
        registry,
        observer=PrometheusRecoveryObserver(transport=transport),
    )
    report = await ClosureValidationAgent().validate(enriched)
    assert report.closure_status == "pending_stability"
    assert report.health_restored is False
    assert report.validation["independent_checks_passed"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("mismatch", ["tenant", "target", "environment", "alert", "spec", "plan"])
async def test_registry_binding_rejects_swapped_inputs_without_network(mismatch):
    payload = registry_payload()
    registry = RecoveryObserverRegistry.model_validate(payload)
    action = bound_action(registry)
    if mismatch == "tenant":
        action.tenant_id = "tenant-b"
    elif mismatch == "target":
        action.target = "another-api"
    elif mismatch == "environment":
        action.parameters["execution_plan"]["environment"] = "other"
    elif mismatch == "alert":
        action.parameters["execution_plan"]["alert"]["name"] = "OtherAlert"
    elif mismatch == "spec":
        payload["profiles"][0]["checks"][0]["spec"]["threshold"] = 2
        registry = RecoveryObserverRegistry.model_validate(payload)
    else:
        action.parameters["approved_plan_fingerprint"] = "sha256:" + "0" * 64
    transport = httpx.MockTransport(lambda request: pytest.fail("unbound input reached network"))
    enriched = await collect_recovery_observations(
        action,
        registry,
        observer=PrometheusRecoveryObserver(transport=transport),
    )
    assert enriched.parameters["recovery_observation_collection"]["status"] == "failed"
    assert enriched.parameters["validation_observations"] == []


@pytest.mark.parametrize("invalid", ["query", "missing_kind", "source_tenant", "duplicate_profile", "operator"])
def test_registry_rejects_incomplete_or_unbound_configuration(invalid):
    payload = registry_payload()
    if invalid == "query":
        payload["profiles"][0]["checks"][0]["query"] = "vector(1)"
    elif invalid == "missing_kind":
        payload["profiles"][0]["checks"].pop()
    elif invalid == "source_tenant":
        payload["sources"][0]["tenant_id"] = "tenant-b"
    elif invalid == "duplicate_profile":
        payload["profiles"].append(payload["profiles"][0])
    else:
        payload["profiles"][0]["checks"][0]["spec"]["evaluation_operator"] = "contains"
    with pytest.raises(ValueError):
        RecoveryObserverRegistry.model_validate(payload)


@pytest.mark.asyncio
async def test_closure_runtime_reads_registry_and_collects_before_validation(tmp_path, monkeypatch):
    registry = RecoveryObserverRegistry.model_validate(registry_payload())
    path = tmp_path / "observers.json"
    path.write_text(registry.model_dump_json(), encoding="utf-8")
    module = load_closure_app_module()
    monkeypatch.setattr(module.settings, "recovery_observer_registry_path", str(path))
    observer = PrometheusRecoveryObserver(transport=httpx.MockTransport(prometheus_response))

    async def collect(action, configured_registry, **kwargs):
        return await collect_recovery_observations(action, configured_registry, observer=observer, **kwargs)

    monkeypatch.setattr(module, "collect_recovery_observations", collect)
    report = await module._validate_action(bound_action(registry))
    assert report.health_restored is True
    assert report.metadata["recovery_observation_collection"]["status"] == "complete"


@pytest.mark.asyncio
async def test_reconciliation_collects_without_signed_executor_proof(monkeypatch):
    registry = RecoveryObserverRegistry.model_validate(registry_payload())
    action = bound_action(registry)
    module = load_closure_app_module()
    monkeypatch.setattr(module.settings, "closure_reconciliation_mode", "apply")
    monkeypatch.setattr(module.settings, "recovery_observer_registry_path", "configured.json")
    monkeypatch.setattr(
        module,
        "_load_terminal_action_candidates",
        AsyncMock(
            return_value=[
                (action.model_dump(mode="json"), "validating", "test-restart"),
            ]
        ),
    )
    enriched = await collect_recovery_observations(
        action,
        registry,
        observer=PrometheusRecoveryObserver(transport=httpx.MockTransport(prometheus_response)),
    )
    report = await ClosureValidationAgent().validate(enriched)
    validate = AsyncMock(return_value=report)
    monkeypatch.setattr(module, "_validate_action", validate)
    monkeypatch.setattr(module, "_persist_closure_event", AsyncMock(return_value={"outbox_enqueued": True}))
    monkeypatch.setattr(module, "_publish_closure_event", AsyncMock())
    result = await module._reconcile_terminal_actions(module.app)
    validate.assert_awaited_once()
    assert result["replayed"] == 1
    assert result["decisions"]["revalidate"] == 1


def test_registry_loader_does_not_ignore_invalid_file(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_recovery_observer_registry(str(path))


@pytest.mark.parametrize("registered", [True, False])
def test_compilation_binds_registered_checks_or_blocks_execution(tmp_path, monkeypatch, registered):
    from common.orchestration.execution_plan import resolve_execution_plan
    from common.orchestration.execution_plan_contract import verify_plan_fingerprint
    from test_execution_plan_v2_contract import _alert

    alert = _alert()
    payload = registry_payload()
    profile = payload["profiles"][0]
    profile.update(target_resource_id=alert.service, environment=alert.environment, alert_name=alert.name)
    for check in profile["checks"]:
        check["spec"]["target_resource_id"] = alert.service
        check["query"] = check["query"].replace("payments-api", alert.service)
        check["spec"]["check_reference"] = "promql:sha256:" + sha256(check["query"].encode()).hexdigest()
    if not registered:
        payload["profiles"] = []
    registry = RecoveryObserverRegistry.model_validate(payload)
    path = tmp_path / "observers.json"
    path.write_text(registry.model_dump_json(), encoding="utf-8")
    monkeypatch.setenv("RECOVERY_OBSERVER_REGISTRY_PATH", str(path))
    plan = resolve_execution_plan(
        alert=alert,
        workflow_name="critical-auto-remediation",
        requires_approval=True,
        risk_tier="high",
        execution_mode="human-approval",
    )
    assert verify_plan_fingerprint(plan)
    if registered:
        assert plan["execution_ready"] is True
        assert plan["validators"] == registry.profiles[0].specs()
        assert set(plan["required_validation_kinds"]) == set(KINDS)
    else:
        assert plan["execution_ready"] is False
        assert plan["commands"] == []
        assert "independent recovery observation profile is not registered" in plan["readiness_blocks"]


@pytest.mark.asyncio
async def test_real_http_collection_persists_pending_then_recovery_after_restart(sqlite_session_factory, monkeypatch):
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from common.database import (
        ActionRecord,
        IncidentProjectionRecord,
        RcaReportRecord,
        ResolutionOutboxRecord,
        ValidationObservationRecord,
    )
    from common.models import Incident
    from common.repository import IncidentRepository
    from sqlalchemy import select

    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            request = httpx.Request("GET", "http://observer.test" + self.path)
            calls.append(request)
            response = prometheus_response(request)
            body = json.dumps(response.json()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = registry_payload()
        payload["sources"][0]["endpoint"] = f"http://127.0.0.1:{server.server_port}"
        registry = RecoveryObserverRegistry.model_validate(payload)
        later = datetime.now(UTC)
        earlier = later - timedelta(seconds=100)
        action = bound_action(registry, seconds_ago=0, now=earlier)
        module = load_closure_app_module()
        monkeypatch.setattr(module.settings, "database_enabled", True)
        module.app.state.session_factory = sqlite_session_factory
        monkeypatch.setattr(module, "_sync_closure_to_jira", AsyncMock(return_value={"status": "skipped"}))
        incident = Incident(
            id=action.incident_id,
            tenant_id=action.tenant_id,
            service=action.target,
            environment="test",
            severity="critical",
            title="Payments unavailable",
            status="validating",
            metadata={"resolution_lifecycle": action.parameters["resolution_lifecycle"]},
        )
        async with sqlite_session_factory() as session:
            repo = IncidentRepository(session)
            await repo.save_incident(incident)
            session.add(
                ActionRecord(
                    id=action.id,
                    incident_id=action.incident_id,
                    tenant_id=action.tenant_id,
                    action_type=action.action_type,
                    target=action.target,
                    status="succeeded",
                    payload=action.model_dump(mode="json"),
                )
            )
            session.add(
                IncidentProjectionRecord(
                    incident_id=action.incident_id,
                    tenant_id=action.tenant_id,
                    service=action.target,
                    environment="test",
                    severity="critical",
                    status="validating",
                )
            )
            await session.commit()

        first = await collect_recovery_observations(action, registry, now=earlier)
        pending = await ClosureValidationAgent().validate(first)
        assert pending.closure_status == "pending_stability"
        await module._persist_closure_event(
            app=module.app,
            action=action,
            report=pending,
            source_payload={},
            sync_jira=False,
        )
        # Restart: reconstruct the action from persisted work, with no
        # in-process samples or executor recovery assertions.
        rows = await module._load_terminal_action_candidates(module.app, limit=10)
        assert len(rows) == 1
        stored_payload = rows[0][0]
        restarted_action = type(action).model_validate(
            stored_payload if isinstance(stored_payload, dict) else json.loads(stored_payload)
        )
        second = await collect_recovery_observations(restarted_action, registry, now=later)
        recovered = await ClosureValidationAgent().validate(second)
        assert recovered.health_restored is True
        await module._persist_closure_event(
            app=module.app,
            action=restarted_action,
            report=recovered,
            source_payload={},
            sync_jira=False,
        )
        async with sqlite_session_factory() as session:
            repo = IncidentRepository(session)
            stored = await repo.get_incident(str(action.incident_id), tenant_id=action.tenant_id)
            assert stored["metadata"]["resolution_lifecycle"]["state"] == "closed"
            reports = (await session.execute(select(RcaReportRecord))).scalars().all()
            assert {report.closure_status for report in reports} == {"pending_stability", "closed"}
            observations = (
                await session.execute(select(ValidationObservationRecord))
            ).scalars().all()
            expected_checksums = {
                item["result_checksum"]
                for item in recovered.metadata["independent_validation_observations"]
            }
            assert {item.result_checksum for item in observations} == expected_checksums
            assert all(
                item.tenant_id == action.tenant_id
                and item.incident_id == action.incident_id
                and item.report_id == recovered.id
                and item.remediation_action_id == action.id
                and item.phase == "post_state"
                and item.passed
                for item in observations
            )
            events = (await session.execute(select(ResolutionOutboxRecord))).scalars().all()
            assert {event.payload["resolution_lifecycle"]["state"] for event in events} == {
                "pending_stability",
                "closed",
            }
        assert len(calls) == 6
        assert await module._load_terminal_action_candidates(module.app, limit=10) == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_decimal_measurement_text_survives_evidence_serialization():
    import json
    registry = RecoveryObserverRegistry.model_validate(registry_payload())
    check = next(c for c in registry.profiles[0].checks if c.spec.kind == "latency")
    check = check.model_copy(update={"spec": check.spec.model_copy(update={"evaluation_operator":"lte", "threshold":1.0})})
    decimal = "0.9874999999999999"
    def handle(request):
        body = prometheus_response(request).json()
        for sample in body["data"]["result"][0]["values"]:
            sample[1] = decimal
        return httpx.Response(200, json=body)
    now = datetime.now(UTC)
    samples = await PrometheusRecoveryObserver(transport=httpx.MockTransport(handle)).observe_window(
        registry.source_for(check.spec), check, now=now, not_before=now-timedelta(minutes=10),
        window_seconds=300, binding={"assessment_id":"precision-regression"})
    restored = json.loads(json.dumps(samples))
    assert restored and all(s["measured_value"] == decimal and s["passed"] for s in restored)
    assert all(s["expected_value"] == "1.0" for s in restored)
    assert [s["result_checksum"] for s in restored] == [s["result_checksum"] for s in samples]
