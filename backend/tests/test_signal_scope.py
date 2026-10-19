from types import SimpleNamespace
import pytest
from common.signal_scope import is_demo_signal
from common.analysis_admission import retirement_reason


def test_scoped_demo_enablement_does_not_admit_other_alerts(monkeypatch):
    import json
    from common.signal_scope import demo_analysis_enabled
    monkeypatch.delenv("DEMO_ALERT_INGESTION_ENABLED", raising=False)
    monkeypatch.setenv("DEMO_ALERT_INGESTION_TARGETS", json.dumps([
        "telemetry/demo/frontend-proxy/TelemetryApplicationUnavailable"]))
    row = {"name": "TelemetryApplicationUnavailable", "environment": "demo", "service": "frontend-proxy",
           "labels": {"project": "telemetry", "monitoring_scope": "demo"}}
    assert demo_analysis_enabled(row)
    alert = SimpleNamespace(**row, source="prometheus")
    assert retirement_reason(alert, "investigating") is None
    for field, value in (("service", "cart"), ("environment", "prod"), ("name", "TelemetryMonitoringUnavailable")):
        assert not demo_analysis_enabled({**row, field: value})
    assert not demo_analysis_enabled({**row, "labels": {"project": "other"}})
    for invalid in ('["*"]', '"telemetry/demo/frontend-proxy/TelemetryApplicationUnavailable"', 'invalid'):
        monkeypatch.setenv("DEMO_ALERT_INGESTION_TARGETS", invalid)
        assert not demo_analysis_enabled(row)


@pytest.mark.parametrize("row", [
    {"source":"robot-shop"}, {"labels":{"job":"robot-shop-mysql"}},
    {"name":"TelemetryCollectorUnavailable"}, {"labels":{"monitoring_scope":"demo"}},
    {"labels":{"instance":"http://ob-frontend:8080/_healthz"}},
])
def test_shipped_demo_targets_are_not_production(row):
    assert is_demo_signal(row)


@pytest.mark.parametrize("row", [{"name":"DiskSpaceLow","service":"node-exporter"},
    {"source":"telemetry","name":"CustomerOutage","labels":{"job":"payments"}},
    {"name":"HighLatency","service":"api-gateway"}])
def test_real_and_unknown_sources_are_not_silently_declared_demo(row):
    assert not is_demo_signal(row)


def test_demo_analysis_requires_explicit_enablement(monkeypatch):
    alert=SimpleNamespace(name="RobotShopServiceDown",labels={},source="robot-shop",service="rs-cart")
    monkeypatch.delenv("DEMO_ALERT_INGESTION_ENABLED",raising=False)
    assert retirement_reason(alert,"investigating") == "DEMO_ANALYSIS_RETIRED"
    monkeypatch.setenv("DEMO_ALERT_INGESTION_ENABLED","true")
    assert retirement_reason(alert,"investigating") is None


@pytest.mark.asyncio
async def test_missing_resource_metrics_do_not_generate_cpu_or_memory_alarms():
    from common.models import ApplicationRegistration
    from common.monitoring_onboarding import RuleGenerationAgent
    app = ApplicationRegistration(tenant_id="t",name="customer-api",owner_team="sre",
        owner_email="sre@example.com",environment="prod",namespace="payments",region="local",
        technology="python",metrics_endpoint="http://customer-api:8000/metrics")
    validation=SimpleNamespace(metric_families=[],metrics_endpoint=app.metrics_endpoint)
    rules=await RuleGenerationAgent().run(app,SimpleNamespace(),validation)
    assert [r.name for r in rules.alert_rules] == ["customer-api-target-down"]
    assert rules.governance["coverage_gaps"] == ["cpu","memory"]


@pytest.mark.asyncio
async def test_precomputed_millisecond_p95_is_not_treated_as_histogram():
    from common.models import ApplicationRegistration
    from common.monitoring_onboarding import RuleGenerationAgent
    app=ApplicationRegistration(tenant_id="t",name="api",owner_team="sre",owner_email="sre@example.com",
        environment="prod",namespace="payments",region="local",technology="python",metrics_endpoint="http://api:8000/metrics")
    rules=await RuleGenerationAgent().run(app,SimpleNamespace(),SimpleNamespace(
        metric_families=["request_latency_ms_p95"],metrics_endpoint=app.metrics_endpoint))
    latency=next(r for r in rules.alert_rules if r.name.endswith("latency-p95-high"))
    assert latency.expr == 'request_latency_ms_p95{job="api"} > 1000'
