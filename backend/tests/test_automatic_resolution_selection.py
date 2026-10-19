from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx
import pytest

from common.automatic_execution import automatic_execution_authorized
from resolution_agent.automatic_selection import certified_option
from test_selection_auto_execution_policy import load_approval_module, load_resolution_module


def option():
    return {"id": "certified", "source": "tenant-learned-resolution-catalog", "service_scope": ["checkout"],
            "self_heal_eligible": True, "risk": "low", "success_count": 2, "failure_count": 0,
            "steps": ["reviewed repair"], "validation": ["health"], "rollback": ["restore previous state"]}


@pytest.mark.parametrize("tenant,environment,service,expected", [
    ("tenant", "test", "checkout", True), ("other", "test", "checkout", False),
    ("tenant", "prod", "checkout", False), ("tenant", "test", "other", False),
    ("tenant", "test", "*", False),
])
def test_execution_requires_exact_operator_managed_scope(tenant, environment, service, expected):
    settings = SimpleNamespace(resolution_auto_execution_enabled=True, resolution_auto_execution_targets=["tenant/test/checkout"])
    assert automatic_execution_authorized(settings, tenant=tenant, environment=environment, service=service) is expected
    settings.resolution_auto_execution_enabled = False
    assert not automatic_execution_authorized(settings, tenant=tenant, environment=environment, service=service)


@pytest.mark.parametrize("patch", [{"self_heal_eligible": False}, {"risk": "high"}, {"success_count": 0},
                                   {"failure_count": 1}, {"rollback": []}, {"service_scope": ["other"]},
                                   {"source": "global-knowledge-repository"}])
def test_unproven_or_wrong_target_option_remains_human_gated(patch):
    assert certified_option([{**option(), **patch}], service="checkout") is None


def test_multiple_certified_choices_require_human_selection():
    assert certified_option([option()], service="checkout")["id"] == "certified"
    assert certified_option([option(), {**option(), "id": "another"}], service="checkout") is None


@pytest.mark.parametrize("patch", [{"service_scope": "checkout-other"}, {"success_count": True},
                                   {"success_count": "invalid"}, {"failure_count": None}])
def test_malformed_certification_cannot_select_a_remedy(patch):
    assert certified_option([{**option(), **patch}], service="checkout") is None


@pytest.mark.asyncio
async def test_assistant_prepares_bound_plan_without_enabling_auto_execution(monkeypatch):
    module = load_resolution_module()
    module.ResolutionCatalogRequest.model_rebuild(_types_namespace={"UUID": UUID})
    module.ResolutionSelectionRequest.model_rebuild(_types_namespace={"UUID": UUID})
    monkeypatch.setattr(module.settings, "service_internal_token", "internal-test")
    monkeypatch.setattr(module.settings, "resolution_auto_execution_enabled", False)
    monkeypatch.setattr(module.settings, "resolution_auto_execution_targets", [])
    monkeypatch.setattr(module, "_require_catalog_readiness", AsyncMock(return_value={
        "recommendation": {"confidence": .95, "metadata": {"service": "checkout", "environment": "test"}}}))
    monkeypatch.setattr(module, "resolution_catalog", AsyncMock(return_value={"rows": [option()]}))
    monkeypatch.setattr(module, "prepare_resolution_plan", lambda **kw: {**option(), "service": "checkout"})
    selected = AsyncMock(return_value={"automatic_approval": "not_requested", "compilation": {"status": "compiled"}})
    monkeypatch.setattr(module, "select_resolution", selected)
    request = module.ResolutionCatalogRequest(tenant_id="tenant", incident_id=uuid4(), alert_id=uuid4(),
        analysis_request_id=uuid4(), recommendation_id=uuid4(), rca_version=1, context_snapshot_id=uuid4(),
        context_fingerprint="a"*64, issue="checkout failure", service="checkout", environment="test")
    assert (await module.assist_resolution(request, "internal-test"))["status"] == "awaiting_approval"
    assert selected.await_args.args[0].actor == "kaims-resolution-assistant"
    readiness = module._require_catalog_readiness
    readiness.side_effect = module.HTTPException(status_code=409, detail="RCA evidence is not ready")
    with pytest.raises(module.HTTPException) as exc:
        await module.assist_resolution(request, "internal-test")
    assert exc.value.status_code == 409 and selected.await_count == 1
    readiness.side_effect = None
    selected.return_value = {"automatic_approval": "not_requested", "compilation": {"status": "blocked"}}
    assert (await module.assist_resolution(request, "internal-test"))["status"] == "human_required"
    monkeypatch.setattr(module, "resolution_catalog", AsyncMock(return_value={"rows": [option(), option()]}))
    assert (await module.assist_resolution(request, "internal-test"))["status"] == "human_required"
    assert selected.await_count == 2
    with pytest.raises(module.HTTPException) as exc:
        await module.assist_resolution(request, "wrong-token")
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_assisted_dispatch_runs_with_auto_disabled_and_skips_investigation(monkeypatch):
    module = load_approval_module()
    monkeypatch.setattr(module.settings, "resolution_auto_execution_enabled", False)
    calls = []
    def handle(request):
        calls.append(request)
        return httpx.Response(200, json={"status": "awaiting_approval"})
    factory = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: factory(transport=httpx.MockTransport(handle), **kwargs))
    metadata = {"service": "checkout", "environment": "test"}
    payload = {"recommendation": {"id": str(uuid4()), "incident_id": str(uuid4()),
                                  "tenant_id": "tenant", "metadata": metadata}}
    await module.request_automatic_selection(payload)
    assert len(calls) == 1 and calls[0].url.path == "/resolution-catalog/assist"
    for disposition in ("investigate", "watch_only"):
        metadata["resolution_control"] = {"disposition": disposition}
        await module.request_automatic_selection(payload)
    assert len(calls) == 1
    metadata["resolution_control"] = {"disposition": "execution_ready"}
    await module.request_automatic_selection(payload)
    assert len(calls) == 2  # A proposed plan still needs durable catalog compilation.
    metadata["resolution_selection"] = {"selection_id": str(uuid4())}
    await module.request_automatic_selection(payload)
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_configured_first_use_runbook_is_prepared_only_for_human_approval(monkeypatch):
    import json
    module = load_resolution_module()
    module.ResolutionCatalogRequest.model_rebuild(_types_namespace={"UUID": UUID})
    module.ResolutionSelectionRequest.model_rebuild(_types_namespace={"UUID": UUID})
    monkeypatch.setattr(module.settings, "service_internal_token", "internal-test")
    monkeypatch.setattr(module.settings, "resolution_auto_execution_enabled", True)
    monkeypatch.setattr(module.settings, "resolution_auto_execution_targets", ["tenant/test/checkout"])
    monkeypatch.setenv("REMEDIATION_COMPOSE_TARGETS", json.dumps({"tenant/test/checkout": {
        "project": "telemetry", "service": "checkout", "container_id": "a" * 64,
        "health_url": "http://fixture.test/health", "catalog_option_id": "reviewed-first-use"}}))
    monkeypatch.setattr(module, "_require_catalog_readiness", AsyncMock(return_value={"recommendation": {
        "confidence": .95, "metadata": {"service": "checkout", "environment": "test"}}}))
    monkeypatch.setattr(module, "resolution_catalog", AsyncMock(return_value={"rows": []}))
    first_use = {**option(), "id": "reviewed-first-use", "source": "kaims-governed-catalog-v1",
                 "service": "checkout", "risk": "medium", "self_heal_eligible": False, "success_count": 0}
    monkeypatch.setattr(module, "prepare_resolution_plan", lambda **kw: first_use)
    selected = AsyncMock(return_value={"automatic_approval": "not_requested", "compilation": {"status": "compiled"}})
    monkeypatch.setattr(module, "select_resolution", selected)
    request = module.ResolutionCatalogRequest(tenant_id="tenant", incident_id=uuid4(), alert_id=uuid4(),
        analysis_request_id=uuid4(), recommendation_id=uuid4(), rca_version=1, context_snapshot_id=uuid4(),
        context_fingerprint="a"*64, issue="checkout unavailable", service="checkout", environment="test")
    assert (await module.assist_resolution(request, "internal-test"))["status"] == "awaiting_approval"
    assert selected.await_args.args[0].actor == "kaims-resolution-assistant"
    assert (await module.automatically_select_resolution(request, "internal-test"))["status"] == "human_required"
    assert selected.await_count == 1


@pytest.mark.asyncio
async def test_automatic_selection_uses_persisted_readiness_and_server_catalog(monkeypatch):
    module = load_resolution_module()
    module.ResolutionCatalogRequest.model_rebuild(_types_namespace={"UUID": UUID})
    module.ResolutionSelectionRequest.model_rebuild(_types_namespace={"UUID": UUID})
    monkeypatch.setattr(module.settings, "resolution_auto_execution_enabled", True)
    monkeypatch.setattr(module.settings, "resolution_auto_execution_targets", ["tenant/test/checkout"])
    monkeypatch.setattr(module.settings, "service_internal_token", "internal-test")
    readiness = AsyncMock(return_value={"recommendation": {"confidence": .95,
                      "metadata": {"service": "checkout", "environment": "test"}}})
    monkeypatch.setattr(module, "_require_catalog_readiness", readiness)
    monkeypatch.setattr(module, "resolution_catalog", AsyncMock(return_value={"rows": [option()]}))
    monkeypatch.setattr(module, "prepare_resolution_plan", lambda **kw: {**option(), "service": "checkout"})
    selected = AsyncMock(return_value={"automatic_approval": "approved"})
    monkeypatch.setattr(module, "select_resolution", selected)
    request = module.ResolutionCatalogRequest(tenant_id="tenant", incident_id=uuid4(), alert_id=uuid4(),
        analysis_request_id=uuid4(), recommendation_id=uuid4(), rca_version=1, context_snapshot_id=uuid4(),
        context_fingerprint="a"*64, issue="checkout failure", service="checkout", environment="test")
    assert (await module.automatically_select_resolution(request, "internal-test"))["status"] == "selected"
    assert selected.await_args.args[0].actor == "kaims-auto-policy"
    assert selected.await_args.args[0].option_id == "certified"
    readiness.assert_awaited()
    monkeypatch.setattr(module.settings, "resolution_auto_execution_targets", [])
    assert (await module.automatically_select_resolution(request, "internal-test"))["status"] == "human_required"
    assert selected.await_count == 1
    with pytest.raises(module.HTTPException) as exc:
        await module.automatically_select_resolution(request, "wrong-token")
    assert exc.value.status_code == 403
    monkeypatch.setattr(module.settings, "resolution_auto_execution_targets", ["tenant/test/checkout"])
    selected.return_value = {"automatic_approval": "not_requested", "compilation": {"status": "blocked"}}
    assert (await module.automatically_select_resolution(request, "internal-test"))["status"] == "human_required"
    selected.return_value = {"automatic_approval": "deferred"}
    with pytest.raises(module.HTTPException) as exc:
        await module.automatically_select_resolution(request, "internal-test")
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_automatic_dispatch_propagates_transient_failure_for_broker_retry(monkeypatch):
    module = load_approval_module()
    monkeypatch.setattr(module.settings, "resolution_auto_execution_enabled", True)
    monkeypatch.setattr(module.settings, "resolution_auto_execution_targets", ["tenant/test/checkout"])
    factory = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: factory(
        transport=httpx.MockTransport(lambda request: httpx.Response(503)), **kwargs))
    payload = {"recommendation": {"id": str(uuid4()), "incident_id": str(uuid4()), "tenant_id": "tenant",
               "metadata": {"service": "checkout", "environment": "test"}}}
    with pytest.raises(httpx.HTTPStatusError):
        await module.request_automatic_selection(payload)
