from alert_intelligence import AlertIntelligenceAgent
from common.models import Alert, AlertSeverity
from common.repository_interfaces import InMemoryAlertHistoryRepository
import pytest
from datetime import timedelta


def make_alert(description: str = "payment latency above threshold") -> Alert:
    return Alert(
        source="prometheus",
        name="PaymentLatencyHigh",
        service="payments",
        severity=AlertSeverity.WARNING,
        description=description,
        labels={"deployment": "payments-api", "team": "payments-sre"},
    )


@pytest.mark.asyncio
async def test_durable_candidate_key_does_not_depend_on_alert_uuid_or_history():
    agent = AlertIntelligenceAgent()
    first = make_alert()
    first.labels["operation"] = "/checkout"
    second = make_alert("payment latency now 4.2 seconds")
    second.labels["operation"] = "/checkout"
    # Independent worker histories still converge on a single database key.
    _, one = await agent.process(first)
    _, two = await AlertIntelligenceAgent().process(second)
    assert first.correlation_id != second.correlation_id
    assert one.metadata["incident_candidate"]["correlation_key"] == two.metadata["incident_candidate"]["correlation_key"]


@pytest.mark.asyncio
async def test_different_endpoint_alerts_do_not_deduplicate_or_correlate():
    agent = AlertIntelligenceAgent()
    first = make_alert()
    first.labels["operation"] = "/checkout"
    first, _ = await agent.process(first)
    second = make_alert()
    second.labels["operation"] = "/onboarding/templates"
    second, _ = await agent.process(second)
    assert first.fingerprint != second.fingerprint
    assert second.deduplicated_count == 1
    assert first.correlation_id != second.correlation_id


@pytest.mark.asyncio
async def test_explicit_candidates_cannot_correlate_across_tenants():
    agent = AlertIntelligenceAgent()
    first = make_alert()
    first.tenant_id = "tenant-a"
    first, _ = await agent.process(first)
    second = make_alert()
    second.tenant_id = "tenant-b"
    second = await agent.deduplicate_alerts(second, candidates=[first])
    second = await agent.correlate_alerts(second, candidates=[first])
    assert second.deduplicated_count == 1
    assert first.correlation_id != second.correlation_id


@pytest.mark.asyncio
async def test_alert_intelligence_deduplicates_and_classifies() -> None:
    agent = AlertIntelligenceAgent()
    first, first_incident = await agent.process(make_alert())
    second, _ = await agent.process(make_alert())

    assert first.severity == AlertSeverity.CRITICAL
    assert second.deduplicated_count == 2
    assert first.metadata["deduplication"]["disposition"] == "new_incident"
    assert second.metadata["deduplication"]["disposition"] == "duplicate"
    assert second.correlation_id == first.correlation_id
    assert first_incident.owner_team == "payments-sre"


@pytest.mark.asyncio
async def test_same_alert_from_replaced_pod_is_an_exact_duplicate() -> None:
    agent = AlertIntelligenceAgent(deduplication_window_minutes=60)
    first = make_alert()
    first.labels["pod"] = "payments-api-7f44b7d6dd-abc12"
    first, _ = await agent.process(first)

    replacement = make_alert()
    replacement.labels["pod"] = "payments-api-7f44b7d6dd-xyz89"
    replacement, _ = await agent.process(replacement)

    assert replacement.fingerprint == first.fingerprint
    assert replacement.metadata["deduplication"]["disposition"] == "duplicate"
    assert replacement.metadata["deduplication"]["match_type"] == "exact"


@pytest.mark.asyncio
async def test_same_disk_alert_on_different_mount_is_not_a_duplicate() -> None:
    agent = AlertIntelligenceAgent(correlation_threshold=0.72)
    original = make_alert("Disk utilization is above 90% on mount /usr/lib/wsl/drivers")
    original.name = "DiskSpaceLow"
    original.labels.update({"mountpoint": "/usr/lib/wsl/drivers", "instance": "node-exporter:9100"})
    original.fingerprint = agent._fingerprint(original)
    incoming = make_alert("Disk utilization is above 90% on mount /run/desktop/mnt/host/c")
    incoming.name = "DiskSpaceLow"
    incoming.labels.update({"mountpoint": "/run/desktop/mnt/host/c", "instance": "node-exporter:9100"})

    enriched = await agent.deduplicate_alerts(incoming, [original])

    assert enriched.deduplicated_count == 1
    assert enriched.metadata["deduplication"]["disposition"] == "new_incident"
    assert agent._correlation_score(incoming, original)[0] == 0.0


@pytest.mark.asyncio
async def test_repeated_disk_alert_on_same_mount_is_a_duplicate() -> None:
    agent = AlertIntelligenceAgent(correlation_threshold=0.72)
    original = make_alert("Disk utilization is above 90% on mount /data")
    original.name = "DiskSpaceLow"
    original.labels["mountpoint"] = "/data"
    original.fingerprint = agent._fingerprint(original)
    repeated = make_alert("Disk utilization is above 91% on mount /data")
    repeated.name = "DiskSpaceLow"
    repeated.labels["mountpoint"] = "/data"

    enriched = await agent.deduplicate_alerts(repeated, [original])

    assert enriched.deduplicated_count == 2
    assert enriched.metadata["deduplication"]["disposition"] == "duplicate"


@pytest.mark.asyncio
async def test_alert_intelligence_uses_embedding_correlation() -> None:
    agent = AlertIntelligenceAgent(correlation_threshold=0.2)
    first, _ = await agent.process(make_alert("checkout payment latency high"))
    correlated, _ = await agent.process(make_alert("payment checkout latency degraded"))

    assert correlated.correlation_id == first.correlation_id


@pytest.mark.asyncio
async def test_alert_intelligence_uses_enterprise_correlation_evidence() -> None:
    agent = AlertIntelligenceAgent(correlation_threshold=0.72)
    first, _ = await agent.process(
        Alert(
            source="prometheus",
            name="PaymentLatencyHigh",
            service="payments-api",
            severity=AlertSeverity.HIGH,
            description="checkout p95 latency above threshold after deployment 2.5",
            labels={
                "team": "payments-sre",
                "deployment": "payments-api",
                "namespace": "checkout",
                "dependency": "ledger-api",
                "metric": "http_request_duration_seconds",
            },
        )
    )
    correlated, _ = await agent.process(
        Alert(
            source="prometheus",
            name="PaymentTimeoutRateHigh",
            service="checkout",
            severity=AlertSeverity.HIGH,
            description="payment timeout rate degraded for checkout path",
            labels={
                "team": "payments-sre",
                "deployment": "payments-api",
                "namespace": "checkout",
                "upstream": "payments-api",
                "dependency": "ledger-api",
                "metric": "http_request_duration_seconds",
            },
        )
    )

    assert correlated.correlation_id == first.correlation_id
    assert correlated.metadata["correlation"]["matched"] is True
    assert correlated.metadata["correlation"]["evidence"]["deployment_change"] > 0
    assert "ledger" in correlated.metadata["correlation"]["evidence"]["topology_overlap"]


@pytest.mark.asyncio
async def test_alert_intelligence_does_not_correlate_unrelated_services() -> None:
    agent = AlertIntelligenceAgent(correlation_threshold=0.72)
    first, _ = await agent.process(make_alert("payment latency above threshold"))
    unrelated, _ = await agent.process(
        Alert(
            source="prometheus",
            name="WarehouseDiskUsageHigh",
            service="warehouse-storage",
            severity=AlertSeverity.WARNING,
            description="warehouse disk usage crossed warning threshold",
            labels={"deployment": "warehouse-storage", "team": "data-platform", "metric": "disk_usage_percent"},
        )
    )

    assert unrelated.correlation_id != first.correlation_id
    assert unrelated.metadata["correlation"]["matched"] is False


@pytest.mark.asyncio
async def test_process_fetches_alert_history_once_per_alert() -> None:
    """Dedup and correlation previously issued two independent unfiltered
    history scans per incoming alert. process() must now share a single
    environment-scoped fetch between both steps."""

    class CountingRepository(InMemoryAlertHistoryRepository):
        def __init__(self) -> None:
            super().__init__()
            self.list_calls: list[str | None] = []

        async def list_recent_alerts(self, *, environment: str | None = None, tenant_id: str | None = None):
            self.list_calls.append(environment)
            return await super().list_recent_alerts(environment=environment, tenant_id=tenant_id)

    repository = CountingRepository()
    agent = AlertIntelligenceAgent(alert_history_repository=repository)

    await agent.process(make_alert())

    assert repository.list_calls == ["prod"]


def test_embedding_cache_is_bounded() -> None:
    """The embedding cache used to be an unbounded dict that grew for the
    life of the process. It must now evict the oldest entry once the cap is
    exceeded instead of leaking memory across a long-running soak."""
    agent = AlertIntelligenceAgent()
    agent._embedding_cache_max_size = 3

    agent._embed("alert-text-1")
    agent._embed("alert-text-2")
    agent._embed("alert-text-3")
    agent._embed("alert-text-4")

    assert len(agent._embedding_cache) == 3
    assert "alert-text-1" not in agent._embedding_cache
    assert "alert-text-4" in agent._embedding_cache


@pytest.mark.asyncio
async def test_alert_deduplication_can_be_disabled() -> None:
    repository = InMemoryAlertHistoryRepository()
    agent = AlertIntelligenceAgent(alert_history_repository=repository, deduplication_enabled=False)
    original = make_alert()
    await repository.record_alert(original)

    duplicate = make_alert()
    enriched = await agent.deduplicate_alerts(duplicate, [original])

    assert enriched.deduplicated_count == 1
    assert enriched.metadata["deduplication"]["enabled"] is False


@pytest.mark.asyncio
async def test_similar_alert_within_configured_hour_is_duplicate() -> None:
    repository = InMemoryAlertHistoryRepository()
    agent = AlertIntelligenceAgent(
        alert_history_repository=repository,
        deduplication_window_minutes=60,
        correlation_threshold=0.2,
    )
    original = make_alert("checkout payment latency high")
    original.fingerprint = agent._fingerprint(original)
    await repository.record_alert(original)
    similar = Alert(
        source="prometheus",
        name="CheckoutLatencyDegraded",
        service="payments",
        severity=AlertSeverity.WARNING,
        description="payment response latency degraded in checkout",
        labels={"deployment": "payments-api", "team": "payments-sre"},
        starts_at=original.starts_at + timedelta(minutes=59),
    )

    enriched = await agent.deduplicate_alerts(similar, [original])

    assert enriched.metadata["deduplication"]["disposition"] == "duplicate"
    assert enriched.metadata["deduplication"]["match_type"] == "similar"


@pytest.mark.asyncio
async def test_similar_alert_outside_configured_hour_is_new() -> None:
    agent = AlertIntelligenceAgent(deduplication_window_minutes=60, correlation_threshold=0.2)
    original = make_alert("checkout payment latency high")
    original.fingerprint = agent._fingerprint(original)
    original.starts_at = original.starts_at - timedelta(minutes=61)
    similar = Alert(
        source="prometheus",
        name="CheckoutLatencyDegraded",
        service="payments",
        severity=AlertSeverity.WARNING,
        description="payment response latency degraded in checkout",
        labels={"deployment": "payments-api", "team": "payments-sre"},
    )

    enriched = await agent.deduplicate_alerts(similar, [original])

    assert enriched.metadata["deduplication"]["disposition"] == "new_incident"


@pytest.mark.asyncio
async def test_active_e2e_runs_share_one_incident_family() -> None:
    agent = AlertIntelligenceAgent(deduplication_window_minutes=60)
    first = Alert(
        source="prometheus",
        name="KaiOps discovery unavailable 20260819085345",
        service="kaiops-discovery-mcp",
        environment="e2e-20260819085345",
        severity=AlertSeverity.CRITICAL,
        description="discovery endpoint is unreachable",
        ends_at=make_alert().starts_at + timedelta(minutes=10),
    )
    first, _ = await agent.process(first)
    second = Alert(
        source="prometheus",
        name="KaiOps discovery unavailable 20260819085721",
        service="kaiops-discovery-mcp",
        environment="e2e-20260819085721",
        severity=AlertSeverity.CRITICAL,
        description="discovery endpoint is unreachable",
        starts_at=first.starts_at + timedelta(minutes=4),
        ends_at=first.starts_at + timedelta(minutes=14),
    )

    second, _ = await agent.process(second)

    assert second.metadata["deduplication"]["disposition"] == "duplicate"
    assert second.metadata["deduplication"]["match_type"] == "exact"
    assert second.correlation_id == first.correlation_id


@pytest.mark.asyncio
async def test_environment_family_does_not_cross_production_and_staging() -> None:
    agent = AlertIntelligenceAgent(deduplication_window_minutes=60)
    production = make_alert()
    production.environment = "production"
    production, _ = await agent.process(production)
    staging = make_alert()
    staging.environment = "staging"

    staging, _ = await agent.process(staging)

    assert staging.metadata["deduplication"]["disposition"] == "new_incident"
    assert staging.correlation_id != production.correlation_id
