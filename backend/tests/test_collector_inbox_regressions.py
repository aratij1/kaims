from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import uuid4
import importlib.util
from pathlib import Path

import httpx
import pytest
from sqlalchemy.exc import OperationalError
from common.context_enrichment_contract import EvidenceRequirement, normalize_connector_response
from common.models import Alert, AlertSeverity, Incident
from common.enrichment_scheduler import persist_collected_evidence, CollectionPersistenceBusy
from context_agent.connectors import PrometheusConnector

spec = importlib.util.spec_from_file_location("collector_discovery_regression", Path(__file__).parents[1] / "src/discovery-mcp/app.py")
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)
NOW = datetime(2026, 9, 13, 10, tzinfo=UTC)
START = "2026-09-12T10:00:00+00:00"
END = "2026-09-12T10:10:00+00:00"


def normalize(raw, category="metrics"):
    incident = Incident(tenant_id="t", service="api-gateway", title="latency")
    requirement = EvidenceRequirement(requirement_id=uuid4(), tenant_id="t", incident_id=incident.id,
        rca_version=1, category=category, question="Confirm failure", reason="Find cause", priority="high",
        collection_mode="automatic", candidate_connectors=["discovery-mcp"], created_at=NOW, updated_at=NOW)
    return normalize_connector_response(raw_response=raw, requirement=requirement, incident=incident,
        connector="discovery-mcp", collected_at=NOW)


def mock_http(monkeypatch, handler):
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))


@pytest.mark.asyncio
async def test_discovery_metrics_keep_window_samples_and_skip_trace_sources(monkeypatch):
    requests = []
    samples = [[datetime.fromisoformat(START).timestamp(), "3.5"], [datetime.fromisoformat(END).timestamp(), "4.1"]]
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"status": "success", "data": {"result": [{
            "metric": {"__name__": "latency", "service": "api-gateway"}, "values": samples}]}})
    mock_http(monkeypatch, handler)
    monkeypatch.setattr(discovery, "_project_for", lambda _: ("kaims", {"telemetry": {
        "prometheus_url": "http://prometheus:9090", "jaeger_url": "http://jaeger:16686"}}))
    response = await discovery._search_telemetry({"service": "api-gateway", "evidence_category": "metrics",
        "trace_id": "platform-correlation-id", "start_time": START, "end_time": END})
    assert len(requests) == 1
    assert requests[0].url.path == "/api/v1/query_range"
    assert float(requests[0].url.params["start"]) == samples[0][0]
    assert float(requests[0].url.params["end"]) == samples[1][0]
    assert not response["evidence_gap"]
    assert response["evidence"][0]["observed_at"] == END
    result = normalize(response)
    assert not result.rejected
    row = result.records[0]
    assert row.source_id == "http://prometheus:9090"
    assert row.observation_window_start == datetime.fromisoformat(START)
    assert row.observation_window_end == datetime.fromisoformat(END)
    assert [s["value"] for s in row.content["samples"]] == ["3.5", "4.1"]
    assert row.observed_at < NOW


@pytest.mark.asyncio
@pytest.mark.parametrize("start,end", [(END, START), ("invalid", END), (START, "")])
async def test_invalid_discovery_window_never_queries_now(monkeypatch, start, end):
    calls = []
    mock_http(monkeypatch, lambda request: calls.append(request))
    monkeypatch.setattr(discovery, "_project_for", lambda _: ("kaims", {"telemetry": {"prometheus_url": "http://prometheus:9090"}}))
    result = await discovery._search_telemetry({"service": "api-gateway", "evidence_category": "metrics", "start_time": start, "end_time": end})
    assert calls == []
    assert result["evidence"] == []
    assert result["sources"][0]["status"] == "unavailable"


@pytest.mark.asyncio
async def test_actual_deployment_identity_survives_admission(monkeypatch):
    mock_http(monkeypatch, lambda request: httpx.Response(200, json=[{
        "Id": "container-sha", "Created": datetime.fromisoformat(START).timestamp(), "Image": "kaims:version-1",
        "Labels": {"com.docker.compose.project": "kaims", "com.docker.compose.service": "api-gateway"}}]))
    rows = await discovery._container_deployment_events({"service": "api-gateway", "project": "kaims"})
    result = normalize({"evidence": rows}, "deployment")
    assert len(result.records) == 1
    assert result.records[0].content["deployment_id"] == "container-sha"
    assert result.records[0].observed_at == datetime.fromisoformat(START)


def test_file_keyword_match_is_not_admitted_as_deployment():
    result = normalize({"evidence": [{"source": "change", "path": "compose.yaml", "snippet": "api-gateway", "uri": "file://compose.yaml"}]}, "deployment")
    assert result.records == []
    assert result.rejected[0]["code"] == "EVIDENCE_REQUIRED_FIELD_MISSING"


@pytest.mark.parametrize("error", [False, True])
def test_resource_snapshot_requires_measurements_and_preserves_current_time(error):
    raw = {"source": "resource", "uri": "docker://kaims/api-gateway/stats", "service": "api-gateway",
           "observed_at": NOW.isoformat(), "cpu_percent": 14.0, "mem_percent": 45.0}
    if error:
        raw["provider_error"] = "stats unavailable"
    result = normalize({"evidence": [raw]})
    assert bool(result.records) is not error
    if not error:
        assert result.records[0].source_id == "docker"
        assert result.records[0].observed_at == NOW
        assert result.records[0].observation_window_start is None


@pytest.mark.asyncio
async def test_prometheus_connector_honors_job_window_over_alert_timestamp(monkeypatch):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"status": "success", "data": {"result": []}})
    mock_http(monkeypatch, handler)
    alert = Alert(tenant_id="t", source="prometheus", name="Latency", service="api-gateway", environment="prod",
        severity=AlertSeverity.HIGH, description="latency", created_at=NOW, metadata={
        "context_observation_start": START, "context_observation_end": END, "prometheus_expression": "up",
        "connector_resolution": {"status": "completed"}, "resolved_context_connectors": [{
            "provider": "prometheus", "endpoint_identity": "http://prometheus:9090", "config": {}}]})
    result = await PrometheusConnector().fetch(alert, Incident(tenant_id="t", service="api-gateway", title="latency"))
    assert result["observation_window_start"] == START
    assert float(calls[0].url.params["end"]) == datetime.fromisoformat(END).timestamp()


@pytest.mark.asyncio
@pytest.mark.parametrize("code,failures", [(1213, 1), (1205, 2), (1213, 3), (1045, 1)])
async def test_persistence_contention_retries_only_database_transactions(code, failures):
    attempts = []
    committed = []
    class Session:
        async def commit(self):
            committed.append(self)
    @asynccontextmanager
    async def factory():
        yield Session()
    async def operation(session):
        attempts.append(session)
        if len(attempts) <= failures:
            raise OperationalError("write", {}, Exception(code, "db error"))
        return "saved"
    if code == 1045:
        with pytest.raises(OperationalError):
            await persist_collected_evidence(factory, operation)
        assert len(attempts) == 1
    elif failures == 3:
        with pytest.raises(CollectionPersistenceBusy):
            await persist_collected_evidence(factory, operation)
        assert len(attempts) == 3
    else:
        assert await persist_collected_evidence(factory, operation) == "saved"
        assert len(attempts) == failures + 1
        assert len({id(item) for item in attempts}) == failures + 1
        assert len(committed) == 1


@pytest.mark.asyncio
async def test_metric_source_failure_is_explicit_and_not_an_empty_success(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("source DNS unavailable", request=request)
    mock_http(monkeypatch, handler)
    monkeypatch.setattr(discovery, "_project_for", lambda _: ("kaims", {"telemetry": {"prometheus_url": "http://prometheus:9090"}}))
    result = await discovery._search_telemetry({"service": "api-gateway", "evidence_category": "metrics", "start_time": START, "end_time": END})
    assert result["provider_status"] == "failed"
    assert result["evidence_gap"] == "PROMETHEUS_SOURCE_UNAVAILABLE"
    assert "DNS unavailable" in result["provider_error"]
    assert result["evidence"] == []


def test_rejection_metadata_is_json_serializable_for_incident_windows():
    import json
    result = normalize({"observation_window_start": START, "observation_window_end": END,
                        "evidence": [{"metric": {"__name__": "latency"}, "values": []}]})
    assert result.rejected
    assert json.loads(json.dumps(result.metadata))["observation_window_start"] == START


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["deployment", "topology", "resource"])
async def test_docker_target_is_scoped_before_container_limit(monkeypatch, tool):
    import json
    seen = []
    def handler(request):
        if request.url.path == "/containers/json":
            seen.append(request)
            # Simulate the target falling beyond an unfiltered Docker page.
            if json.loads(request.url.params.get("filters", "{}")) != {"name": ["node\\-exporter"]}:
                return httpx.Response(200, json=[])
            return httpx.Response(200, json=[{"Id": "node-container", "Created": NOW.timestamp(),
                "Names": ["/kaims-node-exporter-1"], "State": "running", "Labels": {
                "com.docker.compose.project": "kaims", "com.docker.compose.service": "node-exporter"}}])
        return httpx.Response(200, json={"memory_stats": {"usage": 100, "limit": 1000}})
    mock_http(monkeypatch, handler)
    args = {"service": "node-exporter"}
    if tool == "deployment":
        rows = await discovery._container_deployment_events(args)
    elif tool == "topology":
        rows = (await discovery._search_runtime_topology(args, health_only=False))["evidence"]
    else:
        rows = (await discovery._search_resource_saturation(args))["evidence"]
    assert len(rows) == 1
    assert len(seen) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("project,application,expected", [("", "unassigned", 1), ("unknown", "kaims", 1), ("customer-project", "unassigned", 0)])
async def test_deployment_ignores_placeholder_project_but_keeps_real_scope(monkeypatch, project, application, expected):
    mock_http(monkeypatch, lambda request: httpx.Response(200, json=[{
        "Id": "real-container", "Created": NOW.timestamp(), "Names": ["/kaims-node-exporter-1"],
        "Labels": {"com.docker.compose.project": "kaims", "com.docker.compose.service": "node-exporter"}}]))
    monkeypatch.setattr(discovery, "_project_for", lambda _: ("", {}))
    rows = await discovery._container_deployment_events({"service": "node-exporter", "project": project, "application": application})
    assert len(rows) == expected
    if rows:
        assert normalize({"evidence": rows}, "deployment").records[0].content["deployment_id"] == "real-container"
