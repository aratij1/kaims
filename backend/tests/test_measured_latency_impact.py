from datetime import UTC, datetime
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from common.models import Alert
from resolution_agent.impact_claim import measured_latency_impact


def inputs():
    alert = Alert(
        tenant_id="test",
        service="api",
        environment="prod",
        source="prometheus",
        name="HighLatency",
        description="Latency > 3s",
        labels={"operation": "/inbox"},
        annotations={
            "generatorURL": "http://prometheus/graph?" + urlencode({"g0.expr": "histogram_quantile(0.99, buckets) > 3"})
        },
    )
    rows = [
        {
            "evidence_id": str(uuid4()),
            "tenant_id": "test",
            "service": "api",
            "environment": "prod",
            "source_type": "trace",
            "source_uri": f"jaeger://trace/{index}",
            "observed_at": datetime.now(UTC).isoformat(),
            "incident_window_relation": "during",
            "current_operational_evidence": True,
            "metadata": {
                "slowest_spans": [
                    {"service": "api", "duration_ms": duration, "tags": {"span.kind": "server", "http.route": "/inbox"}}
                ]
            },
        }
        for index, duration in enumerate([14000, 4000])
    ]
    return alert, rows


def test_measured_technical_impact_does_not_require_a_confirmed_root_cause():
    alert, rows = inputs()
    claim = measured_latency_impact(alert, rows)
    assert claim["status"] == "OBSERVED"
    assert "2 recorded /inbox requests" in claim["statement"]
    assert "14.000s" in claim["statement"]
    assert set(claim["supporting_evidence_ids"]) == {r["evidence_id"] for r in rows}
    assert "underlying cause are not established" in claim["limitations"][0]


@pytest.mark.parametrize(
    "case",
    [
        "same_trace",
        "below_threshold",
        "wrong_tenant",
        "wrong_route",
        "after_window",
        "unverified",
        "wrong_environment",
        "nonfinite",
        "missing_rule",
    ],
)
def test_measured_latency_rejects_inadequate_or_mismatched_observations(case):
    alert, rows = inputs()
    row = rows[1]
    if case == "same_trace":
        row["source_uri"] = rows[0]["source_uri"]
    elif case == "below_threshold":
        row["metadata"]["slowest_spans"][0]["duration_ms"] = 100
    elif case == "wrong_tenant":
        row["tenant_id"] = "other"
    elif case == "wrong_route":
        row["metadata"]["slowest_spans"][0]["tags"]["http.route"] = "/other"
    elif case == "after_window":
        row["incident_window_relation"] = "after"
    elif case == "unverified":
        row["current_operational_evidence"] = False
    elif case == "wrong_environment":
        row["environment"] = "test"
    elif case == "nonfinite":
        row["metadata"]["slowest_spans"][0]["duration_ms"] = float("inf")
    elif case == "missing_rule":
        alert.annotations = {}
    assert measured_latency_impact(alert, rows) is None
