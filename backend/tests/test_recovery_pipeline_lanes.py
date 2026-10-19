import json
from datetime import UTC, datetime, timedelta

import pytest

from common.alert_processing_budget import ANALYSIS_TOPICS
from common.orchestration.compose_targets import compose_recovery_target
from common.orchestration.execution_plan import docker_compose_restart_plan
from common.topics import CONTEXT_EVENTS, INITIAL_CONTEXT_EVENTS, context_delivery_topic
from resolution_agent.investigation import IterativeInvestigator
from test_iterative_resolution_investigation import make_context


def test_first_investigations_have_an_independent_budgeted_queue():
    assert context_delivery_topic({"context_delivery_lane": "initial"}) == INITIAL_CONTEXT_EVENTS
    assert context_delivery_topic({}) == CONTEXT_EVENTS
    assert INITIAL_CONTEXT_EVENTS in ANALYSIS_TOPICS


def test_external_compose_target_is_pinned_and_exactly_scoped(monkeypatch):
    target = {"project": "telemetry", "service": "frontend-proxy", "container_id": "a" * 64,
              "health_url": "http://host.docker.internal:18080/"}
    monkeypatch.setenv("REMEDIATION_COMPOSE_TARGETS", json.dumps({"t/demo/frontend-proxy": target}))
    assert compose_recovery_target(tenant="t", environment="demo", service="frontend-proxy") == target
    assert compose_recovery_target(tenant="other", environment="demo", service="frontend-proxy") is None
    assert compose_recovery_target(tenant="t", environment="prod", service="frontend-proxy") is None
    target["container_id"] = ""
    monkeypatch.setenv("REMEDIATION_COMPOSE_TARGETS", json.dumps({"t/demo/frontend-proxy": target}))
    assert compose_recovery_target(tenant="t", environment="demo", service="frontend-proxy") is None
    plan = docker_compose_restart_plan(project="telemetry", service="frontend-proxy", container_id="a" * 64)
    assert "a" * 64 in plan["commands"][0]
    assert "/$container_id/start" in plan["commands"][0]
    from urllib.parse import parse_qs, urlsplit
    import re
    url = re.search(r"'([^']+/containers/json\?[^']+)'", plan["preflight"][0]).group(1)
    assert json.loads(parse_qs(urlsplit(url).query)["filters"][0])["status"] == ["exited", "dead"]


def stopped_evidence(context):
    stopped = (context.alert.starts_at - timedelta(seconds=30)).isoformat()
    return [{"evidence_id": "runtime", "source_type": "topology", "reliability_score": 1,
             "current_operational_evidence": True, "freshness_seconds": 1,
             "source_uri": "docker://telemetry/checkout", "incident_window_relation": "during",
             "observed_at": datetime.now(UTC).isoformat(), "snippet": "workload exited",
             "metadata": {"service": context.alert.service, "runtime_state": "exited",
                          "runtime_lifecycle": {"Running": False, "FinishedAt": stopped}}},
            {"evidence_id": "probe", "source_type": "metric", "reliability_score": 1,
             "current_operational_evidence": True, "freshness_seconds": 1,
             "source_uri": "prometheus://registered-probes?query=probe_success", "incident_window_relation": "during",
             "observed_at": datetime.now(UTC).isoformat(), "snippet": "HTTP probe failed",
             "metadata": {"metric": {"__name__": "probe_success", "service": context.alert.service},
                          "value": [context.alert.starts_at.timestamp(), "0"]}}]


def test_stopped_workload_needs_independent_failed_probe_after_exit():
    context = make_context()
    evidence = stopped_evidence(context)
    investigator = IterativeInvestigator()
    hypotheses = investigator._revise_hypotheses([], evidence, context=context)
    runtime = next(h for h in hypotheses if h.get("mechanism") == "runtime_stopped")
    assert set(runtime["supporting_evidence_ids"]) == {"runtime", "probe"}
    assert runtime["independent_source_count"] == 2
    assert runtime["status"] == "confirmed"
    assert investigator._required_sources(context, hypotheses) == {"topology", "telemetry"}
    for patch in ({"value": [context.alert.starts_at.timestamp(), "1"]},
                  {"value": [context.alert.starts_at.timestamp() - 60, "0"]},
                  {"metric": {"__name__": "probe_success", "service": "other"}}):
        invalid = {**evidence[1], "metadata": {**evidence[1]["metadata"], **patch}}
        assert not investigator._structured_mechanism_support(runtime, invalid)
    assert not investigator._structured_mechanism_support(runtime, {**evidence[0], "source_type": "dependency"})


def test_single_source_setting_cannot_certify_duplicate_runtime_observations():
    context = make_context()
    evidence = stopped_evidence(context)
    investigator = IterativeInvestigator()
    investigator.minimum_independent_sources = 1
    runtime_only = [evidence[0], {**evidence[0], "evidence_id": "runtime-again"}]
    revised = investigator._revise_hypotheses([], runtime_only, context=context)
    runtime = next(h for h in revised if h.get("mechanism") == "runtime_stopped")
    assert runtime["status"] != "confirmed"
    assert not investigator._confirmed_without_declared_gaps(revised, runtime_only, context)


def test_known_runtime_rule_synthesizes_only_its_verified_mechanism():
    from resolution_agent.runtime_recovery import stopped_workload_recommendation
    context = make_context()
    evidence = stopped_evidence(context)
    hypotheses = IterativeInvestigator()._revise_hypotheses([], evidence, context=context)
    runtime = next(h for h in hypotheses if h.get("mechanism") == "runtime_stopped")
    report = {"conclusive": True, "hypotheses": hypotheses, "evidence": evidence,
              "conclusion": {"hypothesis_id": runtime["hypothesis_id"],
                             "evidence_ids": runtime["supporting_evidence_ids"], "confidence": runtime["confidence"]}}
    recommendation = stopped_workload_recommendation(context, report)
    assert recommendation.metadata["rca_status"] == "grounded"
    assert recommendation.metadata["evidence_quality"]["independent_source_count"] == 2
    assert recommendation.metadata["evidence_quality"]["evidence_coverage"] == 1
    assert recommendation.metadata["quality_gate"]["trusted_for_auto_execution"] is False
    assert "workload stopped" in recommendation.root_cause
    assert "business losses are not established" in recommendation.impact
    assert recommendation.metadata["rca_analysis"]["missing_evidence"] == []
    assert recommendation.metadata["rca_analysis"]["follow_up_questions"]
    from resolution_agent.impact_claim import evaluated_impact_claim
    claim = evaluated_impact_claim(recommendation.metadata["impact_analysis"], recommendation.impact, evidence)
    assert claim["status"] == "OBSERVED"
    assert stopped_workload_recommendation(context, {**report, "conclusive": False}) is None
    assert stopped_workload_recommendation(context, {**report, "evidence": [evidence[0]]}) is None


def test_old_or_other_service_exit_cannot_create_a_causal_candidate():
    context = make_context()
    for service, finished in (("other", context.alert.starts_at),
                              (context.alert.service, context.alert.starts_at - timedelta(days=1))):
        rows = stopped_evidence(context)
        rows[0]["metadata"].update(service=service, runtime_lifecycle={"Running": False, "FinishedAt": finished.isoformat()})
        revised = IterativeInvestigator()._revise_hypotheses([], rows, context=context)
        assert not any(h.get("mechanism") == "runtime_stopped" for h in revised)


@pytest.mark.asyncio
@pytest.mark.parametrize("case,expected", [("stalled", True), ("fresh", False), ("analyzed", False), ("closed", False)])
async def test_duplicate_recovery_is_bounded_to_stalled_initial_work(case, expected):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from common.models import Incident
    from common.stalled_investigation import recover_stalled_investigation
    from uuid import uuid4
    context = make_context()
    now = datetime.now(UTC)
    context.alert.starts_at = now - timedelta(minutes=15)
    incident = Incident(tenant_id=context.tenant_id, service=context.alert.service,
        severity=context.alert.severity, title=context.alert.name,
        created_at=now - timedelta(minutes=10), status="closed" if case == "closed" else "investigating")
    session = SimpleNamespace(scalar=AsyncMock(side_effect=[
        uuid4() if case == "analyzed" else None,
        now + timedelta(minutes=5) if case == "fresh" else now - timedelta(minutes=1),
    ]))
    repo = SimpleNamespace(session=session, enqueue_resolution_event=AsyncMock(return_value=True))
    assert await recover_stalled_investigation(repo, context.alert, incident, now=now) is expected
    assert repo.enqueue_resolution_event.await_count == int(expected)
    if expected:
        first = repo.enqueue_resolution_event.await_args.kwargs
        await recover_stalled_investigation(SimpleNamespace(session=SimpleNamespace(scalar=AsyncMock(side_effect=[None, None])),
            enqueue_resolution_event=repo.enqueue_resolution_event), context.alert, incident, now=now)
        assert repo.enqueue_resolution_event.await_args.kwargs["event_id"] == first["event_id"]
        assert first["topic"] == "orchestration-events"


@pytest.mark.asyncio
async def test_expired_initial_snapshot_recollects_without_extending_old_ttl(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    import httpx
    from common.models import Incident
    from test_governed_resolution_handoff import load_resolution_module
    module = load_resolution_module()
    original = make_context()
    original.metadata.update(context_delivery_lane="initial", analysis_request_id="original-request",
                             context_snapshot_id="expired")
    fresh = original.model_copy(deep=True)
    fresh.metadata.update(context_snapshot_id="new-snapshot", analysis_request_id="collector-request")
    incident = Incident(id=original.incident_id, tenant_id=original.tenant_id, service=original.alert.service,
                        severity=original.alert.severity, title=original.alert.name)
    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    monkeypatch.setattr(module.app.state, "session_factory", Session, raising=False)
    monkeypatch.setattr(module, "IncidentRepository", lambda session: SimpleNamespace(
        get_incident=AsyncMock(return_value=incident.model_dump(mode="json"))))
    monkeypatch.setattr(module, "_refresh_context_to_latest_snapshot", AsyncMock(return_value=original))
    validate = AsyncMock(side_effect=[module.HTTPException(409, "the bound context snapshot has expired"),
        module.HTTPException(409, "the bound context snapshot has expired"), {"snapshot_id": "new-snapshot"}])
    monkeypatch.setattr(module, "_require_context_snapshot_binding", validate)
    calls = []
    def handle(request):
        calls.append(request)
        assert request.url.params["publish_events"] == "false"
        assert json.loads(request.content)["context_strategy"] == "realtime"
        return httpx.Response(200, json=fresh.model_dump(mode="json"))
    factory = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: factory(transport=httpx.MockTransport(handle), **kw))
    collected, binding = await module._initial_snapshot_for_replay(original)
    assert binding["snapshot_id"] == "new-snapshot" and len(calls) == 1
    assert collected.metadata["analysis_request_id"] == "original-request"
    assert original.metadata["context_snapshot_id"] == "expired"


@pytest.mark.asyncio
async def test_new_episode_reassesses_prior_rca_but_not_an_approval_or_execution():
    from common.stalled_investigation import recover_stalled_investigation
    from common.models import Incident
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from uuid import uuid4
    context = make_context(); now = datetime.now(UTC)
    incident = Incident(tenant_id=context.tenant_id, service=context.alert.service,
        severity=context.alert.severity, title=context.alert.name, status="rca_ready",
        created_at=now-timedelta(minutes=30))
    enqueue = AsyncMock(return_value=True)
    for state, expected in [("DETECTED", True), ("AWAITING_APPROVAL", False), ("EXECUTING", False)]:
        repo = SimpleNamespace(session=SimpleNamespace(scalar=AsyncMock(side_effect=[uuid4(), state, now+timedelta(minutes=5)])),
                               enqueue_resolution_event=enqueue)
        assert await recover_stalled_investigation(repo, context.alert, incident, now=now) is expected
    assert enqueue.await_count == 1

@pytest.mark.asyncio
async def test_local_default_tenant_approval_is_exact_and_oidc_still_rejects(sqlite_session_factory, monkeypatch):
    monkeypatch.setenv('ENVIRONMENT', 'local')
    monkeypatch.setenv('AUTH_MODE', 'local')
    monkeypatch.setenv('DEPLOYMENT_PROFILE', 'local')
    from common.config import get_settings
    from common.models import Approval, ApprovalDecision
    from common.repository import IncidentRepository
    from uuid import uuid4
    incident, recommendation, plan = uuid4(), uuid4(), uuid4()
    approval = Approval(tenant_id='default', incident_id=incident, recommendation_id=recommendation,
        plan_id=plan, plan_fingerprint='sha256:' + 'a' * 64, approver='local-admin',
        decision=ApprovalDecision.APPROVED, approval_expires_at=datetime.now(UTC) + timedelta(minutes=15),
        authorization_scope='execution')
    monkeypatch.setattr(get_settings(), 'auth_mode', 'local')
    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_approval(approval)
        await session.commit()
        arguments = dict(tenant_id='default', plan_id=plan, plan_fingerprint=approval.plan_fingerprint)
        assert await repo.has_accepted_approval_id(approval.id, incident, recommendation, **arguments)
        assert not await repo.has_accepted_approval_id(uuid4(), incident, recommendation, **arguments)
        assert not await repo.has_accepted_approval_id(approval.id, incident, uuid4(), **arguments)
        monkeypatch.setattr(get_settings(), 'auth_mode', 'oidc')
        assert not await repo.has_accepted_approval_id(approval.id, incident, recommendation, **arguments)
