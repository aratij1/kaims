from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from common.config import get_settings
from common.models import Alert, AlertSeverity, Incident
from common.repository import IncidentRepository
from context_agent.connectors import PrometheusConnector


@pytest.mark.asyncio
async def test_filesystem_enrichment_collects_measurements_instead_of_repeating_threshold(monkeypatch):
    captured = {}
    def handler(request):
        captured["request"] = request
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "matrix", "result": []}})
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))
    alert = Alert(tenant_id="tenant-a", source="prometheus", name="DiskSpaceLow", service="node-exporter",
        description="Disk capacity exceeded", severity=AlertSeverity.CRITICAL,
        labels={"job": "node-exporter", "instance": "host:9100", "mountpoint": "/mnt/host/d"},
        metadata={"context_requirement_category": "metrics", "context_requirement_question": "Confirm filesystem inode usage",
            "prometheus_expression": "disk_utilization > 90", "connector_resolution": {"status": "completed"},
            "resolved_context_connectors": [{"provider": "prometheus", "endpoint_identity": "http://prometheus:9090", "config": {}}]})
    incident = Incident(tenant_id="tenant-a", service=alert.service, severity=alert.severity, title=alert.name)
    await PrometheusConnector().fetch(alert, incident)
    query = captured["request"].url.params["query"]
    assert "node_filesystem_" in query and "files_free" in query
    assert 'mountpoint="/mnt/host/d"' in query
    assert "disk_utilization > 90" not in query


@pytest.mark.asyncio
async def test_connector_resolution_is_exact_and_tenant_scoped(sqlite_session_factory) -> None:
    integration_id = uuid4()
    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_monitoring_integration(
            integration_id=integration_id, tenant_id="tenant-a", project_name="checkout-project",
            provider="prometheus", status="active", active=True, auth_type="bearer",
            endpoint_url="https://prometheus.example", webhook_path="/hooks/prometheus",
            deployment_mode="existing_monitoring", config_payload={"observation_window_seconds": 600},
            validation_payload={},
        )
        await repo.save_monitoring_credential(
            credential_id=uuid4(), integration_id=integration_id, credential_type="bearer",
            secret_ref="env://PROMETHEUS_TEST_TOKEN", encrypted_payload={}, redacted_payload={},
        )
        await session.commit()
        exact = await repo.resolve_context_integrations(
            tenant_id="tenant-a", project_candidates=["checkout-project"],
        )
        wrong_tenant = await repo.resolve_context_integrations(
            tenant_id="tenant-b", project_candidates=["checkout-project"],
        )
        fuzzy = await repo.resolve_context_integrations(
            tenant_id="tenant-a", project_candidates=["checkout"],
        )
    assert len(exact) == 1
    assert exact[0]["secret_ref"] == "env://PROMETHEUS_TEST_TOKEN"
    assert "encrypted_payload" not in exact[0]
    assert wrong_tenant == []
    assert fuzzy == []


@pytest.mark.asyncio
async def test_prometheus_uses_original_range_query_and_preserves_scope(monkeypatch) -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "matrix", "result": []}})

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(transport=transport, **kwargs))
    alert = Alert(
        tenant_id="tenant-a", source="prometheus", name="CheckoutLatency", service="checkout-api",
        environment="prod", severity=AlertSeverity.HIGH, description="latency",
        labels={"cluster": "prod-1", "namespace": "checkout", "instance": "pod-1"},
        metadata={
            "project_id": "checkout-project",
            "prometheus_expression": "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))",
            "connector_resolution": {"status": "completed"},
            "resolved_context_connectors": [{
                "integration_id": str(uuid4()), "provider": "prometheus",
                "endpoint_identity": "https://prometheus.example", "config": {"observation_window_seconds": 600},
            }],
        },
    )
    incident = Incident(
        tenant_id="tenant-a",
        service=alert.service,
        environment=alert.environment,
        severity=alert.severity,
        title=alert.name,
    )
    result = await PrometheusConnector().fetch(alert, incident)
    request = captured["request"]
    assert result["_source_status"] == "empty"
    assert result["query"] == alert.metadata["prometheus_expression"]
    assert request.url.path == "/api/v1/query_range"
    assert "service_name" not in request.url.params["query"]
    assert result["preserved_labels"] == {"cluster": "prod-1", "namespace": "checkout", "instance": "pod-1"}


@pytest.mark.asyncio
async def test_local_prometheus_uses_alertmanager_generator_expression(monkeypatch) -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, json={
            "status": "success",
            "data": {"resultType": "matrix", "result": [
                {"metric": {"service": "api-gateway"}, "values": [[1, "4.2"]]},
            ]},
        })

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(transport=transport, **kwargs))
    monkeypatch.setenv("ENVIRONMENT", "local")
    monkeypatch.setenv("PROMETHEUS_URL", "http://prometheus:9090")
    get_settings.cache_clear()
    expression = "histogram_quantile(0.99, rate(kaiops_request_latency_seconds_bucket[5m])) > 3"
    alert = Alert(
        tenant_id="default", source="prometheus", name="KaiOpsHighLatencyP99", service="api-gateway",
        environment="prod", severity=AlertSeverity.CRITICAL, description="latency",
        annotations={
            "generatorURL": (
                "http://prometheus:9090/graph?g0.expr="
                f"{httpx.QueryParams({'g0.expr': expression})['g0.expr']}"
            ),
        },
    )
    incident = Incident(
        tenant_id="default", service=alert.service, environment=alert.environment,
        severity=alert.severity, title=alert.name,
    )

    result = await PrometheusConnector().fetch(alert, incident)

    assert result["_source_status"] == "completed"
    assert result["query"] == expression
    assert captured["request"].url.host == "prometheus"
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_prometheus_historical_rerun_queries_alert_observation_window(monkeypatch) -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "matrix", "result": []}})

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(transport=transport, **kwargs))
    alert_time = datetime(2026, 8, 20, 10, 0, tzinfo=UTC)
    alert = Alert(
        tenant_id="tenant-a", source="prometheus", name="CheckoutLatency", service="checkout-api",
        environment="prod", severity=AlertSeverity.HIGH, description="latency", created_at=alert_time,
        annotations={"startsAt": alert_time.isoformat()},
        metadata={
            "prometheus_expression": "up == 0",
            "connector_resolution": {"status": "completed"},
            "resolved_context_connectors": [{
                "integration_id": str(uuid4()), "provider": "prometheus",
                "endpoint_identity": "https://prometheus.example", "config": {"observation_window_seconds": 600},
            }],
        },
    )
    incident = Incident(
        tenant_id="tenant-a", service=alert.service, environment=alert.environment,
        severity=alert.severity, title=alert.name,
    )

    await PrometheusConnector().fetch(alert, incident)

    params = captured["request"].url.params
    assert float(params["start"]) == pytest.approx(alert_time.timestamp() - 300)
    assert float(params["end"]) == pytest.approx(alert_time.timestamp() + 300)


@pytest.mark.asyncio
async def test_probe_evidence_uses_named_series_for_exact_endpoint(monkeypatch):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={
        "status": "success", "data": {"resultType": "matrix", "result": []},
    }))
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(transport=transport, **kwargs))
    target = "https://httpbin.org/status/503"
    alert = Alert(
        tenant_id="tenant-a", source="prometheus", name="HighNetworkPacketLoss",
        service="httpbin-failure-lab", environment="public-internet", severity=AlertSeverity.HIGH,
        description="HTTP probe failed",
        labels={"job": "blackbox", "instance": target},
        metadata={
            "context_requirement_category": "metrics",
            "prometheus_expression": 'avg_over_time(probe_success{job="blackbox"}[5m]) < 0.95',
            "connector_resolution": {"status": "completed"},
            "resolved_context_connectors": [{"provider": "prometheus", "endpoint_identity": "http://prometheus:9090"}],
        },
    )
    incident = Incident(tenant_id=alert.tenant_id, service=alert.service, severity=alert.severity, title=alert.name)
    result = await PrometheusConnector().fetch(alert, incident)
    assert 'instance="https://httpbin.org/status/503"' in result["query"]
    assert "probe_http_status_code" in result["query"]
    assert "__name__" in result["query"]
    assert "avg_over_time" not in result["query"]
