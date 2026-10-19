from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "discovery-mcp" / "app.py"
SPEC = importlib.util.spec_from_file_location("discovery_mcp_app", MODULE_PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def test_trace_route_binding_rejects_health_checks_and_accepts_templates():
    trace = {"processes": {"p": {"serviceName": "api-gateway"}}, "spans": [
        {"processID": "p", "operationName": "GET /healthz", "tags": []},
    ]}
    assert not module._trace_matches_operation(trace, "api-gateway", "/onboarding/templates")
    trace["spans"][0]["operationName"] = "GET /alerts/{alert_id}/processed-result"
    assert module._trace_matches_operation(trace, "api-gateway", "/alerts/abc/processed-result?tenant=default")
    assert not module._trace_matches_operation(trace, "api-gateway", "/applications")


@pytest.mark.asyncio
async def test_target_scope_does_not_overwrite_filesystem_metric_selection(monkeypatch):
    captured = {}
    def handler(request):
        captured["query"] = request.url.params["query"]
        return module.httpx.Response(200, json={"status": "success", "data": {"result": []}})
    client = module.httpx.AsyncClient
    monkeypatch.setattr(module.httpx, "AsyncClient", lambda **kwargs: client(transport=module.httpx.MockTransport(handler), **kwargs))
    await module._search_telemetry({"service": "node-exporter", "evidence_category": "metrics", "question": "filesystem inode usage",
        "target_labels": {"job": "node-exporter", "instance": "node-exporter:9100", "mountpoint": "/mnt/host/d"}})
    assert "node_filesystem_" in captured["query"]
    assert 'mountpoint="/mnt/host/d"' in captured["query"]


@pytest.mark.asyncio
async def test_telemetry_filters_other_operations_before_limiting_results(monkeypatch):
    def handler(request):
        if "/api/v1/" in request.url.path:
            return module.httpx.Response(200, json={"status": "success", "data": {"result": [
                {"metric": {"__name__": "latency", "service": "api-gateway", "operation": "/applications"}, "value": [1792081780, "3"]},
                {"metric": {"__name__": "latency", "service": "api-gateway", "operation": "/onboarding/templates"}, "value": [1792081780, "1"]},
            ]}})
        return module.httpx.Response(200, json={"data": []})

    async_client = module.httpx.AsyncClient
    monkeypatch.setattr(module.httpx, "AsyncClient", lambda **kwargs: async_client(
        transport=module.httpx.MockTransport(handler), **kwargs))
    result = await module._search_telemetry({"service": "api-gateway", "operation": "/onboarding/templates",
                                             "evidence_category": "metrics", "limit": 1})
    rows = [row for row in result["evidence"] if "metric" in row]
    assert len(rows) == 1
    assert rows[0]["metric"]["operation"] == "/onboarding/templates"


def test_mcp_lists_read_only_discovery_tools() -> None:
    names = {row["name"] for row in module.TOOLS}
    assert names == {
        "logs.search",
        "tickets.search",
        "code.search",
        "mysql.search",
        "telemetry.search",
        "traces.search",
        "topology.search",
        "dependency-health.search",
        "resource-health.search",
        "changes.search",
        "runbooks.search",
        "external.search",
    }


def test_code_tool_returns_cited_redacted_evidence(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "service.py"
    source.write_text("payment-gateway failed password=super-secret\n", encoding="utf-8")
    monkeypatch.setenv("DISCOVERY_MCP_CODE_ROOTS", str(tmp_path))

    result = module._call_tool("code.search", {"terms": ["payment-gateway"], "limit": 4})

    assert result["result_count"] == 1
    row = result["evidence"][0]
    assert row["evidence_id"].startswith("CODE-")
    assert row["uri"].startswith("code://")
    assert "super-secret" not in row["snippet"]
    assert "[REDACTED]" in row["snippet"]


def test_ticket_tool_searches_jira_csv(tmp_path: Path, monkeypatch) -> None:
    ticket = tmp_path / "jira.csv"
    ticket.write_text("key,summary,service\nOPS-9,Pod crash loop,user-profile\n", encoding="utf-8")
    monkeypatch.setenv("DISCOVERY_MCP_TICKET_ROOTS", str(tmp_path))

    result = module._call_tool("tickets.search", {"terms": ["user-profile"], "limit": 4})

    assert result["result_count"] == 1
    assert result["evidence"][0]["evidence_id"].startswith("TICKET-")


def test_code_search_uses_service_path_as_relevance_signal(tmp_path: Path, monkeypatch) -> None:
    service_root = tmp_path / "otel-collector"
    service_root.mkdir()
    (service_root / "collector-config.yaml").write_text("receivers:\n  otlp:\n", encoding="utf-8")
    monkeypatch.setenv("DISCOVERY_MCP_CODE_ROOTS", str(tmp_path))

    result = module._call_tool("code.search", {"terms": ["otel-collector"], "limit": 4})

    assert result["result_count"] > 0
    assert "otel-collector" in result["evidence"][0]["uri"]


def test_code_search_prioritizes_kaiops_service_alias_directory(tmp_path: Path, monkeypatch) -> None:
    backend_root = tmp_path / "backend" / "src"
    service_root = backend_root / "context-agent"
    service_root.mkdir(parents=True)
    (service_root / "app.py").write_text("def collect_context():\n    return 'context'\n", encoding="utf-8")
    projects = tmp_path / "projects.json"
    projects.write_text(
        '{"projects":{"kaiops":{"aliases":["kaiops-platform"],"code_roots":["%s"]}}}'
        % backend_root.as_posix(),
        encoding="utf-8",
    )
    monkeypatch.setenv("DISCOVERY_MCP_PROJECTS_FILE", str(projects))

    roots = module._code_roots({"project": "kaiops-platform", "service": "kaiops-context-agent"})

    assert roots[0] == service_root


def test_code_search_for_an_onboarded_app_without_source_finds_nothing(monkeypatch) -> None:
    """A project resolves (an application registered through
    application-onboarding) but has no known source location in this
    container -- most onboarded applications live in their own separate
    repository. This must return no evidence, never silently fall back to
    searching KaiMS's own codebase and citing it as if it explained a
    different application's incident.
    """
    monkeypatch.setattr(module, "_project_catalog", lambda: {
        "checkout-api": {"name": "checkout-api", "aliases": ["checkout-api"], "code_roots": []},
    })

    roots = module._code_roots({"project": "checkout-api", "service": "checkout-api"})

    assert roots == []


def test_code_search_with_unknown_service_does_not_use_platform_default(monkeypatch) -> None:
    monkeypatch.setenv("DISCOVERY_MCP_CODE_ROOTS", "/workspace/backend/src")
    monkeypatch.setattr(module, "_project_catalog", lambda: {})
    assert module._code_roots({"service": "unregistered-service"}) == []
    assert module._code_roots({}) == [Path("/workspace/backend/src")]


def test_code_search_discards_volatile_alert_tokens() -> None:
    terms = module._code_search_terms(
        {
            "service": "monitoring-adapter",
            "terms": [
                "2026-07-28T13:09:12Z",
                "9a3726be-7e80-4521-8166-5f81f41ae4f1",
                "0123456789abcdef0123456789abcdef",
                "failed",
                "log_ingestion.py",
                "monitoring-adapter",
            ],
        }
    )

    assert terms == ["monitoring-adapter", "log_ingestion.py"]


def test_log_diagnosis_extracts_structured_signals() -> None:
    evidence = [
        module._evidence(
            "log",
            Path("runtime/service.log"),
            1,
            "dependency connection refused after request timeout",
            ["service"],
        )
    ]

    diagnosis = module._log_diagnosis(evidence, "api-gateway")

    assert diagnosis is not None
    assert diagnosis["signal_type"] == "log_diagnosis"
    assert {"connection_refused", "timeout"} <= set(diagnosis["diagnostic_signals"])
    assert diagnosis["supporting_evidence"] == [evidence[0]["evidence_id"]]


def test_docker_multiplexed_log_stream_is_decoded() -> None:
    line = b"2026-07-26T06:18:49Z Failed to export metrics: Deadline Exceeded\n"
    frame = bytes([2, 0, 0, 0]) + len(line).to_bytes(4, "big") + line

    assert module._decode_docker_log_stream(frame) == line.decode()


def test_onboarded_project_entry_uses_shared_platform_telemetry() -> None:
    """The registered metrics_endpoint is the application's own scrape target,
    not a queryable Prometheus server; discovery must point at the shared
    platform Prometheus/Jaeger that actually scrapes it instead.
    """
    project_id, entry = module._onboarded_project_entry({
        "name": "Checkout API",
        "environment": "prod",
        "metrics_endpoint": "http://fault-lab:8080/metrics",
    })

    assert project_id == "checkout-api"
    assert entry["aliases"] == ["checkout api"]
    assert entry["telemetry"]["prometheus_url"] == "http://prometheus:9090"
    assert entry["source"] == "application-onboarding"


def test_onboarded_project_entry_requires_a_name() -> None:
    assert module._onboarded_project_entry({"environment": "prod"}) is None


@pytest.mark.asyncio
async def test_onboarding_sync_populates_catalog_without_a_manual_edit(monkeypatch) -> None:
    """Reproduces the exact gap: an application registered through
    application-onboarding must become discoverable (topology, telemetry)
    without anyone hand-editing the curated discovery-projects.json file.
    """
    class Response:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, params=None):
            return Response({"rows": [{"name": "checkout-api", "environment": "prod"}]})

    monkeypatch.setattr(module.httpx, "AsyncClient", Client)
    monkeypatch.setattr(module.settings, "application_onboarding_url", "http://application-onboarding:8000")
    module._ONBOARDED_PROJECTS_CACHE.clear()

    try:
        await module._refresh_onboarded_projects()

        assert "checkout-api" in module._ONBOARDED_PROJECTS_CACHE
        # _project_catalog() merges this in on every lookup with no extra
        # wiring -- exercise the real function, not a stand-in.
        catalog = module._project_catalog()
        assert "checkout-api" in catalog
        assert catalog["checkout-api"]["telemetry"]["prometheus_url"] == "http://prometheus:9090"
    finally:
        module._ONBOARDED_PROJECTS_CACHE.clear()


def test_curated_catalog_entry_wins_over_onboarding_sync(monkeypatch) -> None:
    """A hand-authored catalog entry (richer code_roots, dedicated telemetry
    endpoints, correlation keys) must never be silently overwritten by the
    lightweight, auto-generated onboarding snapshot for the same project id.
    """
    catalog_path = Path(__file__).parents[1] / "config" / "discovery-projects.json"
    monkeypatch.setenv("DISCOVERY_MCP_PROJECTS_FILE", str(catalog_path))
    module._ONBOARDED_PROJECTS_CACHE.clear()
    module._ONBOARDED_PROJECTS_CACHE["kaiops"] = {
        "name": "kaiops",
        "telemetry": {"prometheus_url": "http://wrong:9999"},
    }
    try:
        catalog = module._project_catalog()
        assert catalog["kaiops"]["telemetry"]["prometheus_url"] == "http://prometheus:9090"
    finally:
        module._ONBOARDED_PROJECTS_CACHE.clear()


@pytest.mark.asyncio
async def test_ticket_search_keeps_local_history_when_jira_alone_fills_the_quota(monkeypatch) -> None:
    """jira_rows and local_rows are each already bounded to `limit`; the
    combined list was re-sliced to `limit` again, which silently dropped
    every local-history ticket whenever Jira alone returned enough rows."""
    limit = 3
    jira_rows = [{"evidence_id": f"JIRA-{i}", "source": "jira"} for i in range(limit)]
    local_rows = [{"evidence_id": f"LOCAL-{i}", "source": "local_history"} for i in range(limit)]

    async def fake_jira(arguments, terms, limit):
        return jira_rows

    def fake_local(terms, limit):
        return local_rows

    monkeypatch.setattr(module, "_search_jira_tickets", fake_jira)
    monkeypatch.setattr(module, "_search_tickets", fake_local)

    result = await module._call_ticket_tool({"limit": limit})

    assert result["result_count"] == len(jira_rows) + len(local_rows)
    sources_present = {row["source"] for row in result["evidence"]}
    assert sources_present == {"jira", "local_history"}


@pytest.mark.asyncio
async def test_log_search_keeps_file_rows_when_docker_alone_fills_the_quota(monkeypatch) -> None:
    """docker_rows and file_rows are each already bounded to `limit`; the
    merged list was re-sliced to `limit` again, which silently dropped every
    file-log row whenever Docker logs alone returned enough rows."""
    limit = 3
    docker_rows = [{"evidence_id": f"DOCKER-{i}", "uri": f"docker://{i}", "source": "log"} for i in range(limit)]
    file_rows = [{"evidence_id": f"FILE-{i}", "uri": f"file://{i}", "source": "log"} for i in range(limit)]

    def fake_files(roots, suffixes, terms, kind, limit):
        return file_rows

    async def fake_docker(arguments, terms, limit):
        return docker_rows

    monkeypatch.setattr(module, "_search_text_files", fake_files)
    monkeypatch.setattr(module, "_search_docker_logs", fake_docker)
    monkeypatch.setattr(module, "_log_diagnosis", lambda rows, service="": None)

    result = await module._call_logs_tool({"limit": limit})

    assert result["result_count"] == len(docker_rows) + len(file_rows)
    ids_present = {row["evidence_id"] for row in result["evidence"]}
    assert ids_present == {row["evidence_id"] for row in [*docker_rows, *file_rows]}


@pytest.mark.asyncio
async def test_dependency_health_search_labels_a_genuine_other_service_as_related_to(monkeypatch) -> None:
    """Real, live-reproduced gap: querying dependency-health.search for the
    alerting service's OWN container can never support or contradict a claim
    that ONE OF ITS DEPENDENCIES is unhealthy -- investigation.py's
    _structured_mechanism_support/_structured_mechanism_contradiction key off
    `target != related_to` to distinguish a genuine dependency check from a
    self-check, but `related_to` was always set to the exact same value as
    the queried `service`, so that distinction could never fire no matter
    which service was actually queried. Passing `related_to` explicitly
    (the incident's own alerting service) must land as a top-level row field,
    not just inside the JSON snippet text, since EvidenceCompiler.compile
    only promotes top-level row keys into `metadata`.
    """
    monkeypatch.setenv("DOCKER_LOG_DISCOVERY_HOST", "docker-socket-proxy:2375")

    def handler(request: object) -> "module.httpx.Response":  # type: ignore[name-defined]
        return module.httpx.Response(200, json=[{
            "Names": ["/kaims-model-router-1"],
            "State": "running",
            "Status": "Up 2 hours (healthy)",
            "Labels": {
                "com.docker.compose.project": "kaims",
                "com.docker.compose.service": "model-router",
            },
            "NetworkSettings": {"Networks": {"kaims_default": {}}},
        }])

    async_client = module.httpx.AsyncClient
    monkeypatch.setattr(module.httpx, "AsyncClient", lambda **kwargs: async_client(transport=module.httpx.MockTransport(handler), **kwargs))

    result = await module._search_runtime_topology(
        {"service": "model-router", "related_to": "api-gateway", "limit": 5}, health_only=True,
    )

    assert result["result_count"] == 1
    row = result["evidence"][0]
    assert row["service"] == "model-router"
    assert row["related_to"] == "api-gateway"
    assert row["service"] != row["related_to"]


@pytest.mark.asyncio
async def test_dependency_health_search_defaults_related_to_the_queried_service_for_a_self_check(monkeypatch) -> None:
    """Backward compatibility: a caller with no discovered dependency yet
    (today's only caller shape, before investigation.py learns to target a
    real dependency) must keep behaving exactly as before -- a self-check,
    target == related_to, never spuriously "contradicting" or "supporting"
    a dependency claim it never actually tested.
    """
    monkeypatch.setenv("DOCKER_LOG_DISCOVERY_HOST", "docker-socket-proxy:2375")

    def handler(request: object) -> "module.httpx.Response":  # type: ignore[name-defined]
        return module.httpx.Response(200, json=[{
            "Names": ["/kaims-api-gateway-1"],
            "State": "running",
            "Status": "Up 3 hours (healthy)",
            "Labels": {
                "com.docker.compose.project": "kaims",
                "com.docker.compose.service": "api-gateway",
            },
            "NetworkSettings": {"Networks": {"kaims_default": {}}},
        }])

    async_client = module.httpx.AsyncClient
    monkeypatch.setattr(module.httpx, "AsyncClient", lambda **kwargs: async_client(transport=module.httpx.MockTransport(handler), **kwargs))

    result = await module._search_runtime_topology({"service": "api-gateway", "limit": 5}, health_only=True)

    row = result["evidence"][0]
    assert row["service"] == row["related_to"] == "api-gateway"


def _docker_stats_payload(*, cpu_delta: int, system_delta: int, online_cpus: int = 4,
                           periods: int = 100, throttled_periods: int = 0,
                           mem_usage: int = 0, mem_limit: int = 0, mem_cache: int = 0) -> dict:
    return {
        "cpu_stats": {
            "cpu_usage": {"total_usage": cpu_delta, "percpu_usage": [0] * online_cpus},
            "system_cpu_usage": system_delta,
            "online_cpus": online_cpus,
            "throttling_data": {"periods": periods, "throttled_periods": throttled_periods, "throttled_time": 0},
        },
        "precpu_stats": {"cpu_usage": {"total_usage": 0}, "system_cpu_usage": 0},
        "memory_stats": {"usage": mem_usage, "limit": mem_limit, "stats": {"cache": mem_cache}},
    }


def test_container_resource_saturation_flags_cpu_throttling() -> None:
    """Real USE-method saturation signal: the kernel's own CFS bandwidth
    controller reports throttled periods directly -- this is exactly what
    cAdvisor/Prometheus compute as container_cpu_cfs_throttled_periods_total
    / container_cpu_cfs_periods_total, read straight from the source."""
    stats = _docker_stats_payload(
        cpu_delta=200_000_000, system_delta=1_000_000_000, online_cpus=4,
        periods=100, throttled_periods=40,
        mem_usage=100_000_000, mem_limit=1_000_000_000, mem_cache=10_000_000,
    )
    saturation = module._container_resource_saturation(stats)
    assert saturation["cpu_throttled_ratio"] == 0.4
    assert saturation["saturated"] is True


def test_container_resource_saturation_flags_memory_pressure() -> None:
    stats = _docker_stats_payload(
        cpu_delta=10_000_000, system_delta=1_000_000_000, online_cpus=4,
        periods=100, throttled_periods=0,
        mem_usage=950_000_000, mem_limit=1_000_000_000, mem_cache=10_000_000,
    )
    saturation = module._container_resource_saturation(stats)
    assert saturation["mem_percent"] >= 85
    assert saturation["saturated"] is True


def test_container_resource_saturation_reports_healthy_under_thresholds() -> None:
    stats = _docker_stats_payload(
        cpu_delta=10_000_000, system_delta=1_000_000_000, online_cpus=4,
        periods=100, throttled_periods=0,
        mem_usage=100_000_000, mem_limit=1_000_000_000, mem_cache=10_000_000,
    )
    saturation = module._container_resource_saturation(stats)
    assert saturation["saturated"] is False


def test_container_resource_saturation_handles_missing_limit_without_crashing() -> None:
    """A container with no memory limit configured (limit=0, or an
    unreadably huge cgroup default) must not divide by zero."""
    stats = _docker_stats_payload(cpu_delta=0, system_delta=0, mem_usage=100, mem_limit=0)
    saturation = module._container_resource_saturation(stats)
    assert saturation["mem_percent"] is None
    assert saturation["cpu_percent"] is None
    assert saturation["saturated"] is False


@pytest.mark.asyncio
async def test_resource_health_search_returns_saturation_evidence_for_a_running_container(monkeypatch) -> None:
    monkeypatch.setenv("DOCKER_LOG_DISCOVERY_HOST", "docker-socket-proxy:2375")

    def handler(request):
        if request.url.path == "/containers/json":
            return module.httpx.Response(200, json=[{
                "Id": "abc123",
                "Names": ["/kaims-checkout-1"],
                "State": "running",
                "Status": "Up 1 hour",
                "Labels": {"com.docker.compose.project": "kaims", "com.docker.compose.service": "checkout"},
            }])
        assert request.url.path == "/containers/abc123/stats"
        return module.httpx.Response(200, json=_docker_stats_payload(
            cpu_delta=350_000_000, system_delta=1_000_000_000, online_cpus=4,
            periods=100, throttled_periods=25,
            mem_usage=100_000_000, mem_limit=1_000_000_000, mem_cache=10_000_000,
        ))

    async_client = module.httpx.AsyncClient
    monkeypatch.setattr(module.httpx, "AsyncClient", lambda **kwargs: async_client(transport=module.httpx.MockTransport(handler), **kwargs))

    result = await module._search_resource_saturation({"service": "checkout", "limit": 5})

    assert result["result_count"] == 1
    row = result["evidence"][0]
    assert row["service"] == "checkout"
    assert row["saturated"] is True
    assert row["cpu_throttled_ratio"] == 0.25


@pytest.mark.asyncio
async def test_resource_health_search_skips_non_running_containers(monkeypatch) -> None:
    """A stopped container has no live cgroup stats to read -- its state is
    already covered by the dependency/topology plane, not this one."""
    monkeypatch.setenv("DOCKER_LOG_DISCOVERY_HOST", "docker-socket-proxy:2375")
    stats_calls = []

    def handler(request):
        if request.url.path == "/containers/json":
            return module.httpx.Response(200, json=[{
                "Id": "def456",
                "Names": ["/kaims-checkout-1"],
                "State": "exited",
                "Status": "Exited (1) 2 minutes ago",
                "Labels": {"com.docker.compose.project": "kaims", "com.docker.compose.service": "checkout"},
            }])
        stats_calls.append(request.url.path)
        return module.httpx.Response(200, json={})

    async_client = module.httpx.AsyncClient
    monkeypatch.setattr(module.httpx, "AsyncClient", lambda **kwargs: async_client(transport=module.httpx.MockTransport(handler), **kwargs))

    result = await module._search_resource_saturation({"service": "checkout", "limit": 5})

    assert result["result_count"] == 0
    assert stats_calls == []


@pytest.mark.asyncio
async def test_changes_search_never_lets_file_matches_crowd_out_deployment_events(monkeypatch) -> None:
    """`_container_deployment_events` (a container's real `Created` timestamp)
    is the one genuinely reliable "when was this actually (re)deployed"
    signal - `_search_changes`'s file-mtime matches are, per its own
    docstring, meaningless for correlation in a from-image deployment. But a
    monorepo this size almost always has `limit` keyword matches for any
    alert-derived term, so putting the file matches first in the combined
    list meant the reliable deployment event was silently truncated away in
    practice. Reproduced platform-wide: across 200 real investigations and
    2273 "change" evidence rows, zero were ever the "container_deployment"
    kind. Deployment events must survive the truncation.
    """
    file_matches = [{"evidence_id": f"CHANGE-file-{index}", "change_evidence_kind": "configuration_or_deployment_artifact"} for index in range(8)]
    deployment_event = {"evidence_id": "CHANGE-deploy-1", "change_evidence_kind": "container_deployment"}
    monkeypatch.setattr(module, "_search_changes", lambda arguments: {
        "tool": "changes.search", "query_terms": [], "result_count": len(file_matches), "evidence": file_matches,
    })

    async def fake_deployment_events(arguments):
        return [deployment_event]

    monkeypatch.setattr(module, "_container_deployment_events", fake_deployment_events)

    result = await module._search_changes_with_deployment_evidence({"service": "checkout", "limit": 8})

    assert result["result_count"] == 8
    assert result["evidence"][0]["evidence_id"] == "CHANGE-deploy-1"
    assert any(row["change_evidence_kind"] == "container_deployment" for row in result["evidence"])


def test_prefixed_service_code_search_uses_question_and_searches_late_handlers(tmp_path, monkeypatch):
    service = tmp_path / 'monitoring-adapter'
    service.mkdir()
    source = service / 'app.py'
    source.write_text('# padding\n'*5100 + 'raise HTTPException(status_code=503, detail="upstream unavailable")\n')
    monkeypatch.setattr(module, '_project_catalog', lambda: {'kaiops': {'platform':True, 'aliases':['kaims'], 'code_roots':[str(tmp_path)]}})
    result = module._call_tool('code.search', {'project':'kaims', 'service':'kaiops-monitoring-adapter',
        'terms':['kaiops-monitoring-adapter','kaiopsservicedown','prod','kan-2432'],
        'question':'Are there recent code changes or bugs that could explain HTTP 5xx errors?', 'limit':8})
    assert result['result_count'] == 1
    row = result['evidence'][0]
    assert row['path'] == str(source)
    assert row['line'] == 5101
    assert 'status_code=503' in row['snippet']
    assert 'monitoring-adapter' in result['query_terms']


def test_question_terms_do_not_expand_unknown_service_scope(tmp_path, monkeypatch):
    (tmp_path/'app.py').write_text('raise HTTPException(status_code=500)')
    monkeypatch.setenv('DISCOVERY_MCP_CODE_ROOTS',str(tmp_path))
    monkeypatch.setattr(module, '_project_catalog', lambda: {})
    result = module._call_tool('code.search', {'service':'external-unknown','question':'HTTP 5xx errors'})
    assert result['evidence'] == []


def test_text_search_retains_bounded_candidates_without_changing_ranking(tmp_path,monkeypatch):
    import tracemalloc
    root=tmp_path/'service';root.mkdir()
    source=root/'app.py'
    source.write_text('needle\n'*12000+'needle strongest\n',encoding='utf-8')
    monkeypatch.setenv('DISCOVERY_MCP_MAX_FILES','10')
    tracemalloc.start()
    result=module._search_text_files([root],{'.py'},['needle','strongest'],'code',8)
    _,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    assert len(result)==8
    assert result[0]['line']==12001
    # Input buffering is bounded by the file cap; candidate retention must not
    # grow one snippet dictionary per matching source line.
    assert peak < 5_000_000
