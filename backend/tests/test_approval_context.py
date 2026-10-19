import importlib.util
import sys
from pathlib import Path

import pytest
from common.orchestration.execution_plan_contract import canonical_plan_fingerprint
from starlette.requests import Request


def _approval_plan(incident_id: str, recommendation_id: str = "22222222-2222-2222-2222-222222222222") -> dict:
    plan = {
        "tenant_id": "tenant-a",
        "incident_id": incident_id,
        "plan_id": "33333333-3333-3333-3333-333333333333",
        "recommendation_id": recommendation_id,
        "rca_version": 1,
        "evidence_snapshot_id": "55555555-5555-4555-8555-555555555555",
        "context_fingerprint": "a" * 64,
        "resolution_selection_id": "44444444-4444-4444-8444-444444444444",
        "policy_version": "resolution-policy.v1",
        "recommendation_version": recommendation_id,
        "execution_ready": True,
        "diagnostic_only": False,
        "plan_kind": "remediation",
        "target_resource_id": "k8s:/clusters/prod/namespaces/payments/deployments/api",
        "connector_id": "kubernetes-prod",
        "validators": [{"validator_id": "availability-1"}],
        "rollback_commands": ["governed:rollback-deployment"],
        "rollback_mode": "automatic",
        "policy_decision": {"decision": "allow"},
        "expiry": "2099-01-01T00:00:00+00:00",
    }
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    return plan


def _readiness_metadata(plan: dict) -> dict:
    return {
        "execution_plan": plan,
        "rca_version": plan["rca_version"],
        "context_snapshot_id": plan["evidence_snapshot_id"],
        "context_fingerprint": plan["context_fingerprint"],
        "resolution_selection": {"selection_id": plan["resolution_selection_id"]},
        "runbook_status": "approved",
        "connection_profile": {"credential_ref": "vault://tenant-a/prod-remediator"},
        "evidence_quality": {
            "evidence_coverage": 0.9,
            "citation_coverage": 0.8,
            "evidence_fresh": True,
            "conflict_count": 0,
        },
    }


def _set_pending_plan(module, incident_id: str, recommendation_id: str) -> dict:
    module.settings.service_internal_token = "internal-test-token"
    plan = _approval_plan(incident_id, recommendation_id)
    base_repository = module.IncidentRepository
    class CanonicalPlanRepository(base_repository):
        async def get_current_execution_plan_for_incident(self, **_kwargs):
            return plan
    module.IncidentRepository = CanonicalPlanRepository
    # These tests exercise approval mutation gates using an explicit context
    # double. Durable context hydration is covered by governed handoff tests.
    async def load_context(incident_id, *, tenant_id):
        value = module.PENDING_INCIDENTS.get(module._pending_key(tenant_id, str(incident_id)))
        if value is None:
            raise module.HTTPException(status_code=404, detail="No tenant-scoped incident")
        return value
    module._load_approval_context = load_context
    if not hasattr(module.app.state, "session_factory"):
        class _Session:
            async def __aenter__(self): return self
            async def __aexit__(self, *args): return False
        module.app.state.session_factory = lambda: _Session()
    module.PENDING_INCIDENTS[module._pending_key("tenant-a", incident_id)] = {
        "recommendation": {
            "id": recommendation_id,
            "incident_id": incident_id,
            "metadata": _readiness_metadata(plan),
        }
    }
    return plan


def load_approval_app_module():
    module_path = Path("backend/src/approval-service/app.py")
    spec = importlib.util.spec_from_file_location("approval_service_app", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_approval_mutations_require_internal_service_authentication() -> None:
    module = load_approval_app_module()
    module.settings.service_internal_token = "internal-test-token"
    called = False

    async def call_next(_request):
        nonlocal called
        called = True
        return module.JSONResponse({"ok": True})

    unauthenticated = Request({"type": "http", "method": "POST", "path": "/approve", "headers": []})
    denied = await module.require_internal_mutation_auth(unauthenticated, call_next)
    assert denied.status_code == 403
    assert called is False

    authenticated = Request({
        "type": "http",
        "method": "POST",
        "path": "/approve",
        "headers": [(b"x-kaiops-internal-token", b"internal-test-token")],
    })
    allowed = await module.require_internal_mutation_auth(authenticated, call_next)
    assert allowed.status_code == 200
    assert called is True


def test_approval_incident_context_resolves_nested_recommendation_id() -> None:
    module = load_approval_app_module()
    recommendation_id = "22222222-2222-2222-2222-222222222222"

    context = module._build_incident_context(
        {"incident_id": "11111111-1111-1111-1111-111111111111"},
        {
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "flow_id": "flow-1",
            "trace_id": "trace-1",
            "status": "pending",
            "payload": {
                "source_payload": {
                    "recommendation": {
                        "id": recommendation_id,
                    }
                }
            },
        },
    )

    assert context["recommendation_id"] == recommendation_id
    assert context["flow_id"] == "flow-1"


def test_approval_readiness_is_backend_signed_only_when_every_gate_passes() -> None:
    module = load_approval_app_module()
    module.settings.service_internal_token = "internal-test-token"
    plan = {
        "tenant_id": "tenant-a",
        "incident_id": "11111111-1111-1111-1111-111111111111",
        "plan_id": "33333333-3333-3333-3333-333333333333",
        "rca_version": "rca-v1",
        "evidence_snapshot_id": "snapshot-v1",
        "recommendation_version": "22222222-2222-2222-2222-222222222222",
        "execution_ready": True,
        "diagnostic_only": False,
        "plan_kind": "remediation",
        "target_resource_id": "k8s:/clusters/prod/namespaces/payments/deployments/api",
        "connector_id": "kubernetes-prod",
        "validators": [{"validator_id": "availability-1"}],
        "rollback_commands": ["governed:rollback-deployment"],
        "rollback_mode": "automatic",
        "policy_decision": {"decision": "allow"},
    }
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    context = module._build_incident_context({
        "tenant_id": "tenant-a",
        "incident_id": plan["incident_id"],
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "tenant_id": "tenant-a",
            "metadata": {
                "execution_plan": plan,
                "runbook_status": "approved",
                "connection_profile": {"credential_ref": "vault://tenant-a/prod-remediator"},
                "evidence_quality": {
                    "evidence_coverage": 0.9,
                    "citation_coverage": 0.8,
                    "evidence_fresh": True,
                    "conflict_count": 0,
                },
            },
        },
    }, None)

    receipt = context["approval_readiness"]
    assert receipt["state"] == "execution_eligible"
    assert receipt["missing"] == []
    assert receipt["signature"].startswith("hmac-sha256:")


def test_approval_readiness_fails_closed_without_signing_key() -> None:
    module = load_approval_app_module()
    module.settings.service_internal_token = ""
    receipt = module._build_incident_context({"incident_id": "incident-1"}, None)["approval_readiness"]
    assert receipt["state"] == "blocked"
    assert "readiness_signing_key" in receipt["missing"]
    assert receipt["signature"] == ""


@pytest.mark.parametrize("decision,eligible", [("hitl", True), ("investigate", False), ("block", False)])
def test_approval_readiness_understands_resolution_policy_disposition(decision: str, eligible: bool) -> None:
    module = load_approval_app_module()
    module.settings.service_internal_token = "internal-test-token"
    plan = _approval_plan("11111111-1111-1111-1111-111111111111")
    plan["policy_decision"] = {"decision": decision}
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    receipt = module._signed_approval_readiness({
        "tenant_id": "tenant-a",
        "incident_id": plan["incident_id"],
        "recommendation": {
            "id": plan["recommendation_version"],
            "tenant_id": "tenant-a",
            "metadata": _readiness_metadata(plan),
        },
    })
    assert (receipt["state"] == "execution_eligible") is eligible


def test_approval_readiness_rejects_raw_credentials() -> None:
    module = load_approval_app_module()
    module.settings.service_internal_token = "internal-test-token"
    plan = _approval_plan("11111111-1111-1111-1111-111111111111")
    metadata = _readiness_metadata(plan)
    metadata["connection_profile"] = {"credential_ref": "plain-text-password"}
    receipt = module._signed_approval_readiness({
        "tenant_id": "tenant-a",
        "incident_id": plan["incident_id"],
        "recommendation": {
            "id": plan["recommendation_version"],
            "tenant_id": "tenant-a",
            "metadata": metadata,
        },
    })

    assert receipt["state"] == "blocked"
    assert "current_credentials" in receipt["missing"]


def test_approval_readiness_finds_the_credential_a_real_compiled_plan_actually_carries() -> None:
    """`resolve_execution_plan` (common/orchestration/execution_plan.py) never
    writes a `connection_profile` key at all - the connector it resolved
    (with whatever `secret_ref`/`credential_ref` that connector carries) is
    nested at `plan["connection"]["connector"]`. Every real, catalog-
    compiled plan's credential reference therefore lived somewhere this
    check never looked, so `current_credentials` read false for every one
    of them regardless of whether a real, valid credential was actually
    resolved. Reproduced live: incident
    ac90a378-23c8-4efa-98d8-7968448219e8's compiled plan had a real,
    executable docker-socket-proxy restart command with
    `available_connector: true` (that check already reads the plan's real
    top-level `connector_id` field) while `current_credentials` was false
    for the exact same plan.
    """
    module = load_approval_app_module()
    module.settings.service_internal_token = "internal-test-token"
    plan = _approval_plan("11111111-1111-1111-1111-111111111111")
    plan["connection"] = {"connector": {"connector_id": "kubernetes-prod", "secret_ref": "vault://tenant-a/prod-remediator"}}
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    metadata = _readiness_metadata(plan)
    del metadata["connection_profile"]

    receipt = module._signed_approval_readiness({
        "tenant_id": "tenant-a",
        "incident_id": plan["incident_id"],
        "recommendation": {
            "id": plan["recommendation_version"],
            "tenant_id": "tenant-a",
            "metadata": metadata,
        },
    })

    assert receipt["checks"]["current_credentials"] is True
    assert "current_credentials" not in receipt["missing"]


def test_approval_request_rejects_placeholder_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_MODE", "oidc")
    monkeypatch.setenv("OIDC_ISSUER", "https://identity.example.test")
    monkeypatch.setenv("OIDC_AUDIENCE", "kaiops-tests")
    monkeypatch.setenv("OIDC_CLIENT_ID", "kaiops-tests")
    monkeypatch.setenv("EVENT_ENVELOPE_SIGNING_REQUIRED", "true")
    monkeypatch.setenv("EVENT_ENVELOPE_SIGNING_KEY", "test-signing-key-that-is-at-least-32-characters")
    monkeypatch.setenv("EVENT_ENVELOPE_SIGNING_ISSUER", "kaiops-tests")
    module = load_approval_app_module()

    with pytest.raises(ValueError, match="verified identity"):
        module.ApprovalRequest(
            incident_id="11111111-1111-1111-1111-111111111111",
            recommendation_id="22222222-2222-2222-2222-222222222222",
            tenant_id="default",
            approver="l2.engineer",
        )


@pytest.mark.asyncio
async def test_evidence_request_is_durable_non_execution_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_approval_app_module()
    stored = []

    async def store_stub(approval):
        stored.append(approval)

    monkeypatch.setattr(module, "_store_and_publish", store_stub)
    request = module.ApprovalRequest(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        tenant_id="tenant-a",
        approver="reviewer@example.com",
        comment="Collect application logs and recent deployment history.",
    )

    approval = await module.request_evidence(request)

    assert approval.decision.value == "evidence_requested"
    assert approval.authorization_scope == "execution"
    assert stored == [approval]


@pytest.mark.asyncio
async def test_evidence_request_requires_reason() -> None:
    module = load_approval_app_module()
    request = module.ApprovalRequest(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        tenant_id="tenant-a",
        approver="reviewer@example.com",
        comment="",
    )

    with pytest.raises(module.HTTPException) as exc:
        await module.request_evidence(request)
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_approval_submission_updates_ticket_projection_status(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_approval_app_module()
    calls: list[tuple[str, str]] = []

    class _FakeRepo:
        def __init__(self, session):
            self.session = session

        async def save_approval(self, approval):
            calls.append(("save_approval", str(approval.incident_id)))

        async def update_incident_approval_status(self, incident_id, *, status, approval=None):
            calls.append(("update_status", status))
            return True

        async def save_incident_event(self, payload):
            calls.append(("save_event", payload["state"]["status"]))

    class _FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def commit(self):
            calls.append(("commit", "ok"))

    class _FakeProducer:
        async def publish(self, *args, **kwargs):
            calls.append(("publish", "ok"))

    monkeypatch.setattr(module.settings, "database_enabled", True)
    monkeypatch.setattr(module, "IncidentRepository", _FakeRepo)
    module.app.state.session_factory = lambda: _FakeSession()
    module.app.state.producer = _FakeProducer()
    plan = _set_pending_plan(
        module,
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    )

    request = module.ApprovalRequest(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        tenant_id="tenant-a",
        plan_id=plan["plan_id"],
        plan_fingerprint=plan["plan_fingerprint"],
        approver="l2.engineer",
        comment="approved",
    )

    await module.approve(request)

    # Approval and execution are separate durable stages. The approval service
    # must not claim remediation has started before remediation-engine accepts it.
    assert ("update_status", "approved") in calls
    assert ("save_event", "approved") in calls


@pytest.mark.asyncio
async def test_approval_submission_resolves_missing_recommendation_id(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_approval_app_module()
    incident_id = "11111111-1111-1111-1111-111111111111"
    recommendation_id = "22222222-2222-2222-2222-222222222222"
    calls: list[tuple[str, str]] = []

    class _FakeRepo:
        def __init__(self, session):
            self.session = session

        async def get_latest_recommendation_for_incident(self, requested_incident_id, *, tenant_id=None):
            calls.append(("get_recommendation", str(requested_incident_id)))
            return {"id": recommendation_id, "incident_id": incident_id}

        async def get_pending_workflow(self, requested_incident_id):
            calls.append(("get_pending", str(requested_incident_id)))
            return None

        async def save_approval(self, approval):
            calls.append(("save_approval", str(approval.recommendation_id)))

        async def update_incident_approval_status(self, incident_id, *, status, approval=None):
            calls.append(("update_status", status))
            return True

        async def save_incident_event(self, payload):
            calls.append(("save_event", payload["state"]["status"]))

    class _FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def commit(self):
            calls.append(("commit", "ok"))

    class _FakeProducer:
        async def publish(self, *args, **kwargs):
            calls.append(("publish", "ok"))

    monkeypatch.setattr(module.settings, "database_enabled", True)
    monkeypatch.setattr(module, "IncidentRepository", _FakeRepo)
    module.app.state.session_factory = lambda: _FakeSession()
    module.app.state.producer = _FakeProducer()
    module.PENDING_INCIDENTS.clear()
    plan = _set_pending_plan(module, incident_id, recommendation_id)
    module.PENDING_INCIDENTS[module._pending_key("tenant-a", incident_id)]["recommendation"].pop("id")

    request = module.ApprovalRequest(
        incident_id=incident_id,
        tenant_id="tenant-a",
        plan_id=plan["plan_id"],
        plan_fingerprint=plan["plan_fingerprint"],
        approver="l2.engineer",
        comment="approved",
    )

    approval = await module.approve(request)

    assert str(approval.recommendation_id) == recommendation_id
    assert ("get_recommendation", incident_id) in calls
    assert ("save_approval", recommendation_id) in calls
    assert ("update_status", "approved") in calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tenant_id", "plan_id", "fingerprint", "status_code"),
    [
        ("tenant-b", "33333333-3333-3333-3333-333333333333", None, 404),
        ("tenant-a", "44444444-4444-4444-4444-444444444444", None, 409),
        ("tenant-a", "33333333-3333-3333-3333-333333333333", "sha256:" + "f" * 64, 409),
    ],
)
async def test_approval_rejects_cross_tenant_or_changed_plan(
    tenant_id: str,
    plan_id: str,
    fingerprint: str | None,
    status_code: int,
) -> None:
    module = load_approval_app_module()
    incident_id = "11111111-1111-1111-1111-111111111111"
    recommendation_id = "22222222-2222-2222-2222-222222222222"
    plan = _set_pending_plan(module, incident_id, recommendation_id)
    request = module.ApprovalRequest(
        incident_id=incident_id,
        recommendation_id=recommendation_id,
        tenant_id=tenant_id,
        plan_id=plan_id,
        plan_fingerprint=fingerprint or plan["plan_fingerprint"],
        approver="l2.engineer",
    )

    with pytest.raises(module.HTTPException) as exc_info:
        await module._approval_from_request(request, module.ApprovalDecision.APPROVED)

    assert exc_info.value.status_code == status_code


@pytest.mark.asyncio
async def test_approval_rejects_stale_recommendation_and_records_exact_governance_binding() -> None:
    module = load_approval_app_module()
    incident_id = "11111111-1111-1111-1111-111111111111"
    current_recommendation_id = "22222222-2222-2222-2222-222222222222"
    stale_recommendation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    plan = _set_pending_plan(module, incident_id, current_recommendation_id)
    stale_request = module.ApprovalRequest(
        incident_id=incident_id,
        recommendation_id=stale_recommendation_id,
        tenant_id="tenant-a",
        plan_id=plan["plan_id"],
        plan_fingerprint=plan["plan_fingerprint"],
        approver="l2.engineer",
    )

    with pytest.raises(module.HTTPException, match="stale") as exc_info:
        await module._approval_from_request(stale_request, module.ApprovalDecision.APPROVED)
    assert exc_info.value.status_code == 409

    current_request = stale_request.model_copy(update={"recommendation_id": current_recommendation_id})
    approval = await module._approval_from_request(current_request, module.ApprovalDecision.APPROVED)

    assert approval.metadata["rca_version"] == 1
    assert approval.metadata["evidence_snapshot_id"] == "55555555-5555-4555-8555-555555555555"
    assert approval.metadata["recommendation_version"] == current_recommendation_id
    assert approval.metadata["target_resource_id"] == plan["target_resource_id"]
    assert approval.metadata["connector_id"] == plan["connector_id"]
    assert approval.metadata["rollback_plan"] == plan["rollback_commands"]


@pytest.mark.asyncio
async def test_approval_rejects_legacy_recommendation_without_governed_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_approval_app_module()
    incident_id = "11111111-1111-1111-1111-111111111111"
    recommendation_id = "22222222-2222-2222-2222-222222222222"
    module.PENDING_INCIDENTS[module._pending_key("tenant-a", incident_id)] = {
        "recommendation": {"id": recommendation_id, "incident_id": incident_id, "metadata": {}},
    }
    monkeypatch.setattr(module.settings, "database_enabled", False)
    request = module.ApprovalRequest(
        incident_id=incident_id,
        recommendation_id=recommendation_id,
        tenant_id="tenant-a",
        approver="l2.engineer",
    )

    with pytest.raises(module.HTTPException, match="RCA version is unavailable") as exc_info:
        await module._approval_from_request(request, module.ApprovalDecision.APPROVED)

    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_local_development_can_approve_default_tenant_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_approval_app_module()
    module.settings.service_internal_token = "internal-test-token"
    incident_id = "11111111-1111-1111-1111-111111111111"
    recommendation_id = "22222222-2222-2222-2222-222222222222"
    plan = _set_pending_plan(module, incident_id, recommendation_id)
    plan["tenant_id"] = "default"
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    monkeypatch.setenv("ENVIRONMENT", "local")
    monkeypatch.setenv("AUTH_MODE", "local")
    monkeypatch.setenv("DEPLOYMENT_PROFILE", "local")
    monkeypatch.setattr(module.settings, "auth_mode", "local")
    module.PENDING_INCIDENTS[module._pending_key("default", incident_id)] = {
        "recommendation": {
            "id": recommendation_id,
            "incident_id": incident_id,
            "metadata": _readiness_metadata(plan),
        },
    }
    request = module.ApprovalRequest(
        incident_id=incident_id,
        recommendation_id=recommendation_id,
        tenant_id="default",
        plan_id=plan["plan_id"],
        plan_fingerprint=plan["plan_fingerprint"],
        approver="admin",
    )

    approval = await module._approval_from_request(request, module.ApprovalDecision.APPROVED)

    assert approval.tenant_id == "default"
    assert str(approval.plan_id) == plan["plan_id"]


@pytest.mark.asyncio
async def test_approval_rejects_valid_diagnostic_plan_until_readiness_controls_pass() -> None:
    module = load_approval_app_module()
    module.settings.service_internal_token = "internal-test-token"
    incident_id = "11111111-1111-1111-1111-111111111111"
    recommendation_id = "22222222-2222-2222-2222-222222222222"
    plan = _set_pending_plan(module, incident_id, recommendation_id)
    plan["execution_ready"] = False
    plan["diagnostic_only"] = True
    plan["plan_kind"] = "diagnostic"
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    module.PENDING_INCIDENTS[module._pending_key("tenant-a", incident_id)]["recommendation"]["metadata"] = (
        _readiness_metadata(plan)
    )
    request = module.ApprovalRequest(
        incident_id=incident_id,
        recommendation_id=recommendation_id,
        tenant_id="tenant-a",
        plan_id=plan["plan_id"],
        plan_fingerprint=plan["plan_fingerprint"],
        approver="l2.engineer",
    )

    with pytest.raises(module.HTTPException, match="not execution-eligible") as exc_info:
        await module._approval_from_request(request, module.ApprovalDecision.APPROVED)

    assert exc_info.value.status_code == 409
    assert "execution ready" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_approval_rejects_expired_plan() -> None:
    module = load_approval_app_module()
    incident_id = "11111111-1111-1111-1111-111111111111"
    recommendation_id = "22222222-2222-2222-2222-222222222222"
    plan = _set_pending_plan(module, incident_id, recommendation_id)
    plan["expiry"] = "2020-01-01T00:00:00+00:00"
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    request = module.ApprovalRequest(
        incident_id=incident_id,
        recommendation_id=recommendation_id,
        tenant_id="tenant-a",
        plan_id=plan["plan_id"],
        plan_fingerprint=plan["plan_fingerprint"],
        approver="l2.engineer",
    )

    with pytest.raises(module.HTTPException, match="expired"):
        await module._approval_from_request(request, module.ApprovalDecision.APPROVED)

@pytest.mark.asyncio
async def test_durable_context_does_not_sign_eligible_for_unpersisted_plan(monkeypatch):
    from uuid import UUID
    module = load_approval_app_module()
    module.settings.database_enabled = True
    module.settings.service_internal_token = 'internal-test-token'
    incident_id = '11111111-1111-1111-1111-111111111111'
    plan = _approval_plan(incident_id)
    recommendation = {'id': plan['recommendation_id'], 'tenant_id': 'tenant-a',
                      'incident_id': incident_id, 'metadata': _readiness_metadata(plan)}
    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    class Repository:
        async def get_incident(self, *args, **kwargs):
            return {'id': incident_id, 'tenant_id': 'tenant-a'}
        async def get_latest_recommendation_for_incident(self, *args, **kwargs):
            return recommendation
        async def get_current_execution_plan_for_incident(self, **kwargs): return None
        async def get_pending_workflow(self, *args): return None
    module.app.state.session_factory = Session
    monkeypatch.setattr(module, 'IncidentRepository', lambda session: Repository())
    context = await module._load_approval_context(UUID(incident_id), tenant_id='tenant-a')
    metadata = context['recommendation']['metadata']
    assert 'execution_plan' not in metadata
    assert metadata['model_proposed_execution_plan'] == plan
    receipt = module._signed_approval_readiness(context)
    assert receipt['state'] == 'blocked'
    assert 'valid_plan' in receipt['missing']
