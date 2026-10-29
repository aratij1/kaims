from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from common.repository import IncidentRepository


@pytest.fixture(scope="module")
def adapter_module():
    backend_root = Path(__file__).resolve().parents[1]
    module_name = "monitoring_adapter_route_dispatch_test"
    spec = importlib.util.spec_from_file_location(
        module_name,
        backend_root / "src" / "monitoring-adapter" / "app.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v1/alerts/jira", "/api/v1/tickets/jira"])
async def test_jira_webhook_aliases_enforce_secret_and_dispatch(adapter_module, monkeypatch, path):
    adapter_module.JIRA_WEBHOOK_SECRET = "test-webhook-secret"
    processed: list[dict] = []

    async def process(payload, trace_id):
        processed.append({"payload": payload, "trace_id": trace_id})

    monkeypatch.setattr(adapter_module, "_process_jira_webhook", process)
    transport = httpx.ASGITransport(app=adapter_module.app)
    payload = {"webhookEvent": "jira:issue_updated", "issue": {"key": "QUAL-1"}}

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        missing = await client.post(path, json=payload)
        invalid = await client.post(path, json=payload, headers={"X-Webhook-Token": "wrong"})
        valid = await client.post(
            path,
            json=payload,
            headers={"X-Webhook-Token": "test-webhook-secret", "X-Trace-Id": "jira-test-trace"},
        )

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert valid.status_code == 200
    assert valid.json() == {
        "received": True,
        "webhookEvent": "jira:issue_updated",
        "ticket_id": "QUAL-1",
    }
    assert processed == [{"payload": payload, "trace_id": "jira-test-trace"}]


@pytest.mark.asyncio
async def test_jira_webhook_fails_closed_when_secret_is_unconfigured(adapter_module, monkeypatch):
    adapter_module.JIRA_WEBHOOK_SECRET = ""
    transport = httpx.ASGITransport(app=adapter_module.app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/alerts/jira",
            json={"issue": {"key": "QUAL-2"}},
            headers={"X-Webhook-Token": "test-webhook-secret"},
        )

    assert response.status_code == 503


@pytest.mark.asyncio
async def test_generic_provider_webhook_still_uses_provider_ingestion(adapter_module, monkeypatch):
    calls: list[dict] = []

    async def ingest(**kwargs):
        calls.append(kwargs)
        return {"provider": kwargs["provider_hint"], "status": "accepted"}

    monkeypatch.setattr(adapter_module, "_ingest_provider_alert", ingest)
    transport = httpx.ASGITransport(app=adapter_module.app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/alerts/custom-provider", json={"alert": "payload"})

    assert response.status_code == 200
    assert response.json() == {"provider": "custom-provider", "status": "accepted"}
    assert calls[0]["provider_hint"] == "custom-provider"


@pytest.mark.asyncio
async def test_provider_webhook_validates_registered_token_hash(
    adapter_module,
    monkeypatch,
    sqlite_session_factory,
):
    integration_id = str(uuid4())
    tenant_id = "tenant-provider-webhook"
    webhook_token = "provider-webhook-token"
    adapter_module.settings.database_enabled = True
    adapter_module.app.state.session_factory = sqlite_session_factory

    async def publish_alert(_alert):
        return None

    async def publish_events(_normalized, trace_id=None):
        return None

    monkeypatch.setattr(adapter_module, "_publish_ingested_alert", publish_alert)
    monkeypatch.setattr(adapter_module, "_publish_lifecycle_events", publish_events)

    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        await repository.save_monitoring_integration(
            integration_id=integration_id,
            tenant_id=tenant_id,
            project_name="test-project",
            provider="prometheus",
            status="validated",
            active=True,
            auth_type="webhook_token",
            endpoint_url=None,
            webhook_path="/api/v1/alerts/prometheus",
            deployment_mode="existing_monitoring",
            config_payload={},
            validation_payload={"valid": True},
        )
        await repository.save_monitoring_webhook_endpoint(
            endpoint_id=str(uuid4()),
            integration_id=integration_id,
            provider="prometheus",
            webhook_path="/api/v1/alerts/prometheus",
            token_hash=adapter_module.hash_secrets({"token": webhook_token})["token"],
            hmac_enabled=False,
            m_tls_enabled=False,
            active=True,
            metadata_payload={},
        )
        await session.commit()

    payload = {
        "tenant_id": tenant_id,
        "labels": {
            "alertname": "HighCPU",
            "service": "cpu-worker",
            "severity": "critical",
        },
        "annotations": {"summary": "CPU utilization is high"},
    }
    rejected = await adapter_module._ingest_provider_alert(
        provider_hint="prometheus",
        payload=payload,
        x_trace_id=None,
        x_signature=None,
        x_webhook_token="wrong-token",
        integration_id_hint=integration_id,
    )
    accepted = await adapter_module._ingest_provider_alert(
        provider_hint="prometheus",
        payload=payload,
        x_trace_id=None,
        x_signature=None,
        x_webhook_token=webhook_token,
        integration_id_hint=integration_id,
    )

    assert rejected["status"] == "quarantined"
    assert rejected["auth_valid"] is False
    assert accepted["status"] == "accepted"
    assert accepted["auth_valid"] is True
    assert accepted["authenticity"] == "verified"
