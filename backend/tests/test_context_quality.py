from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ai_workbench_common.models import Context
from common.models import Alert, AlertSeverity, Incident
from context_agent.context_quality import (
    CONTEXT_CONTRACT_VERSION,
    context_subject_fingerprint,
    govern_context,
    plan_connectors,
)


def make_context(*, stale: bool = False) -> Context:
    observed_at = datetime.now(UTC) - (timedelta(minutes=20) if stale else timedelta(seconds=5))
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="WorkerQueueLagHigh",
        service="worker",
        environment="prod",
        severity=AlertSeverity.WARNING,
        description="Queue lag is above threshold",
        labels={"application": "orders", "namespace": "production"},
        metadata={"tenant_id": "tenant-a"},
    )
    incident = Incident(tenant_id=alert.tenant_id, service="worker", environment="prod", severity=alert.severity, title=alert.name)
    return Context(
        tenant_id=alert.tenant_id,
        incident_id=incident.id,
        alert=alert,
        deployment="orders-worker-v42",
        dependency_services=["redis"],
        runbook="Restart only the affected worker and verify queue recovery.",
        metadata={
            "context_collected_at": observed_at.isoformat(),
            "context_evidence": {
                "logs": [
                    {
                        "source": "logs",
                        "uri": "opensearch://orders/worker-1",
                        "summary": "queue stalled password=supersecret",
                        "observed_at": observed_at.isoformat(),
                        "confidence": 0.9,
                    }
                ],
                "code": [
                    {
                        "source": "code",
                        "uri": "repository://orders/worker.py#L42",
                        "summary": "worker retry loop",
                        "observed_at": observed_at.isoformat(),
                        "confidence": 0.8,
                    }
                ],
            },
        },
    )


def test_govern_context_builds_redacted_provenance_and_strict_package() -> None:
    context = make_context()
    subject = context_subject_fingerprint(context.alert, "tenant-a")

    governed = govern_context(context, tenant_id="tenant-a", subject_fingerprint=subject)

    quality = governed.metadata["context_quality"]
    log = governed.metadata["context_evidence"]["logs"][0]
    package = governed.metadata["context_package"]
    assert governed.metadata["context_contract_version"] == CONTEXT_CONTRACT_VERSION
    assert governed.metadata["context_fingerprint"]
    assert quality["reusable"] is True
    assert quality["provenance_score"] == 1.0
    assert "supersecret" not in log["summary"]
    assert log["content_sha256"]
    assert log["provenance"]["primary_source"] == "opensearch://orders/worker-1"
    assert package["schema_version"] == "1.0"
    assert package["provenance"]["contract_version"] == CONTEXT_CONTRACT_VERSION


def test_stale_operational_evidence_is_not_reusable() -> None:
    context = make_context(stale=True)
    governed = govern_context(
        context,
        tenant_id="tenant-a",
        subject_fingerprint=context_subject_fingerprint(context.alert, "tenant-a"),
    )

    quality = governed.metadata["context_quality"]
    assert quality["reusable"] is False
    assert "logs" in quality["stale_sources"]
    assert governed.metadata["context_sources"]["logs"]["status"] == "stale"


def test_freshly_retrieved_incident_window_metric_is_historical_not_stale() -> None:
    context = make_context()
    context.alert.created_at = datetime.now(UTC) - timedelta(hours=2)
    context.alert.starts_at = context.alert.created_at
    context.runbook = None
    context.metadata["context_collected_at"] = datetime.now(UTC).isoformat()
    context.metadata["context_evidence"] = {
        "telemetry": [{
            "source": "telemetry",
            "uri": "prometheus://worker/queue-lag?window=incident",
            "summary": "queue lag was above threshold in the incident window",
            "observed_at": context.alert.starts_at.isoformat(),
            "retrieved_at": datetime.now(UTC).isoformat(),
            "confidence": 0.9,
        }],
    }

    governed = govern_context(context, tenant_id="tenant-a")
    quality = governed.metadata["context_quality"]
    metric = governed.metadata["context_evidence"]["telemetry"][0]

    assert metric["freshness_score"] == 0.0
    assert metric["incident_window_aligned"] is True
    assert quality["stale_sources"] == []
    assert quality["valid_for_seconds"] > 0
    assert governed.metadata["context_sources"]["telemetry"]["status"] == "historical"


def test_missing_provider_timestamp_is_explicit_and_cannot_claim_full_freshness() -> None:
    context = make_context()
    context.metadata["context_evidence"]["logs"][0].pop("observed_at")

    governed = govern_context(
        context,
        tenant_id="tenant-a",
        subject_fingerprint=context_subject_fingerprint(context.alert, "tenant-a"),
    )

    log = governed.metadata["context_evidence"]["logs"][0]
    source = governed.metadata["context_sources"]["logs"]
    assert log["observed_at_inferred"] is True
    assert log["timestamp_quality"] == "retrieval_fallback"
    assert log["freshness_score"] <= 0.5
    assert source["inferred_timestamp_count"] == 1


def test_partial_traceable_context_can_be_rca_ready_without_every_plane() -> None:
    context = make_context()
    context.runbook = None
    context.metadata["context_evidence"] = {
        "code": context.metadata["context_evidence"]["code"],
        "topology": [{
            "source": "topology",
            "uri": "cmdb://orders/worker",
            "summary": "worker depends on redis",
            "observed_at": datetime.now(UTC).isoformat(),
            "confidence": 0.9,
        }],
        "telemetry": [{
            "source": "telemetry",
            "uri": "prometheus://worker/queue-lag",
            "summary": "queue lag is above threshold",
            "observed_at": datetime.now(UTC).isoformat(),
            "confidence": 0.9,
        }],
    }

    governed = govern_context(context, tenant_id="tenant-a")
    quality = governed.metadata["context_quality"]

    assert quality["source_coverage_score"] == 0.375
    assert quality["coverage_score"] > quality["source_coverage_score"]
    assert quality["rca_readiness_score"] >= 0.70
    assert quality["rca_ready"] is True
    assert quality["impact_ready"] is True


def test_observed_high_severity_context_is_reusable_but_declares_causal_gap() -> None:
    context = make_context()
    context.alert.severity = AlertSeverity.HIGH
    context.runbook = None
    context.deployment = None
    context.dependency_services = []
    context.metadata["context_evidence"] = {
        "telemetry": [{
            "source": "telemetry",
            "uri": "prometheus://worker/queue-lag",
            "summary": "queue lag is above threshold",
            "observed_at": datetime.now(UTC).isoformat(),
            "confidence": 0.9,
        }],
        "topology": [{
            "source": "topology",
            "uri": "cmdb://orders/worker",
            "summary": "worker belongs to orders",
            "observed_at": datetime.now(UTC).isoformat(),
            "confidence": 0.9,
        }],
    }

    governed = govern_context(context, tenant_id="tenant-a")
    quality = governed.metadata["context_quality"]

    assert quality["reusable"] is True
    assert quality["impact_ready"] is True
    assert quality["rca_ready"] is False
    assert quality["missing_required"] == []
    assert quality["diagnostic_gaps"] == ["causal_or_action"]
    assert quality["execution_ready"] is False


def test_untraceable_connector_rows_are_diagnostic_only() -> None:
    context = make_context()
    context.metadata["context_evidence"] = {
        "logs": [{"source": "logs", "summary": "result without a source reference"}]
    }

    governed = govern_context(context, tenant_id="tenant-a")

    assert governed.metadata["context_evidence"]["logs"] == []
    source = governed.metadata["context_sources"]["logs"]
    assert source["status"] == "unavailable"
    assert source["result_count"] == 0
    assert source["untraceable_count"] == 1
    assert "traceable source reference" in source["error"]
    assert "context://" not in str(governed.metadata)


def test_governance_preserves_initial_collection_status() -> None:
    context = make_context()
    context.metadata["context_sources"] = {
        "logs": {"attempted": True, "status": "collected"},
        "database": {"attempted": False, "status": "skipped"},
    }

    first = govern_context(context, tenant_id="tenant-a")
    second = govern_context(first, tenant_id="tenant-a")

    assert second.metadata["context_sources"]["logs"]["collection_status"] == "collected"
    assert second.metadata["context_sources"]["database"]["collection_status"] == "skipped"


def test_subject_fingerprint_ignores_ephemeral_pod_but_not_namespace() -> None:
    alert = make_context().alert
    base = context_subject_fingerprint(alert, "tenant-a")
    another_pod = alert.model_copy(update={"labels": {**alert.labels, "pod": "orders-worker-abc"}})
    another_namespace = alert.model_copy(update={"labels": {**alert.labels, "namespace": "staging"}})

    assert context_subject_fingerprint(another_pod, "tenant-a") == base
    assert context_subject_fingerprint(another_namespace, "tenant-a") != base


def test_connector_plan_skips_unjustified_change_probes() -> None:
    alert = make_context().alert.model_copy(
        update={"description": "queue lag is above threshold", "labels": {"application": "orders"}}
    )
    available = [
        "servicenow", "prometheus", "kubernetes", "jenkins", "github",
        "cmdb", "discovery-mcp", "local-evidence", "vector-db",
    ]

    selected, reasons = plan_connectors(alert, available)

    assert set(selected) == {"prometheus", "cmdb", "discovery-mcp", "vector-db"}
    assert "baseline_signal_topology_discovery_knowledge" in reasons


def test_connector_plan_requests_bounded_local_evidence_for_latency() -> None:
    alert = make_context().alert.model_copy(update={
        "name": "CheckoutLatencyHigh",
        "description": "checkout p95 latency is above 2 seconds",
    })
    available = [
        "prometheus", "cmdb", "discovery-mcp", "vector-db", "local-evidence",
        "github", "jenkins", "servicenow", "kubernetes",
    ]

    selected, reasons = plan_connectors(alert, available)

    assert "local-evidence" in selected
    assert "bounded_local_evidence_requested" in reasons

def test_empty_topology_placeholders_are_not_evidence() -> None:
    context = make_context()
    context.deployment = None
    context.dependency_services = []
    context.cmdb = {'dependencies': []}
    context.kubernetes = {}
    governed = govern_context(context, tenant_id='tenant-a', subject_fingerprint=context_subject_fingerprint(context.alert, 'tenant-a'))
    assert not governed.metadata['context_evidence'].get('topology')
