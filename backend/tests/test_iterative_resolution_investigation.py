from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from ai_workbench_common.models import Context
from common.models import Alert, AlertSeverity, Incident
from resolution_agent.investigation import IterativeInvestigator, ReadOnlyDiscoveryClient


class FakeDiscoveryClient:
    def __init__(self, results: dict[str, list[dict[str, Any]]]) -> None:
        self.results = results
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool_name, arguments))
        return {"tool": tool_name, "evidence": self.results.get(tool_name, [])}


def test_investigation_honors_configured_step_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RESOLUTION_INVESTIGATION_MAX_STEPS", "5")

    assert IterativeInvestigator(client=FakeDiscoveryClient({})).max_steps == 5


def test_evidence_budget_defaults_high_enough_for_a_full_category_pass() -> None:
    """Reproduced live: 142 of 300 recent investigations (47%) stopped after
    ~1.5 steps with evidence_count pinned at the old default of 40 - the
    alert's own pre-existing context (code/logs/traces) alone routinely
    filled that budget before the investigation's own targeted category
    queries (telemetry, data, topology, changes, dependency) ever ran more
    than once. The default must leave real headroom past a typical
    pre-existing-context size, not just past the floor."""
    assert IterativeInvestigator(client=FakeDiscoveryClient({})).max_evidence >= 150


def test_evidence_budget_is_configurable_and_clamped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RESOLUTION_INVESTIGATION_MAX_EVIDENCE", "60")
    assert IterativeInvestigator(client=FakeDiscoveryClient({})).max_evidence == 60

    monkeypatch.setenv("RESOLUTION_INVESTIGATION_MAX_EVIDENCE", "5")
    assert IterativeInvestigator(client=FakeDiscoveryClient({})).max_evidence == 8  # floor

    monkeypatch.setenv("RESOLUTION_INVESTIGATION_MAX_EVIDENCE", "10000")
    assert IterativeInvestigator(client=FakeDiscoveryClient({})).max_evidence == 300  # ceiling


def test_required_sources_never_demands_topology_dependency_or_runbooks_by_default() -> None:
    """A service with no registered topology, no tracked dependencies, and no
    approved runbook must not be investigated as though it were missing
    evidence it structurally can never have - "declared gaps addressed" must
    be closable on real evidence, not permanently blocked on planes that were
    never applicable. Reproduces the production pattern where every incident's
    investigation readiness showed the same "dependency, changes, runbooks"
    gaps regardless of the service."""
    required = IterativeInvestigator._required_sources(make_context())
    assert "topology" not in required
    assert "dependency" not in required
    assert "runbooks" not in required
    # Universal baseline observability stays required - most services can
    # produce at least logs and telemetry, and a real causal RCA nearly
    # always benefits from checking what changed recently.
    assert {"logs", "telemetry", "changes"}.issubset(required)


def test_required_sources_adds_dependency_and_topology_when_actually_relevant() -> None:
    context = make_context()
    with_dependencies = context.model_copy(update={"dependency_services": ["payments-api"]})
    required = IterativeInvestigator._required_sources(with_dependencies)
    assert {"dependency", "topology"}.issubset(required)


def test_required_sources_adds_dependency_and_topology_once_that_hypothesis_is_leading() -> None:
    """Real, live-reproduced gap: a "dependency" hypothesis is one of four
    generic starting candidates unconditionally generated for nearly every
    incident (see `mechanisms` in _revise_hypotheses), so requiring
    topology/dependency evidence just because that candidate *exists* would
    revert the earlier, deliberate narrowing this class already made (a
    service with no registered topology must not be treated as though it
    were missing evidence it never had). But once the investigation's OWN
    evidence has pushed that hypothesis to "leading" or "confirmed" status --
    real, earned momentum toward a dependency-based explanation -- the
    investigator must actually go check topology/dependency before it can
    conclude. Reproduced live on incident 417fc764acf342b1bdc8e815d18e8f1f:
    "An unhealthy upstream or downstream dependency is degrading api-gateway"
    reached "confirmed" from 10 trace records alone, having never queried
    topology.search or dependency-health.search at all -- so the RCA
    perpetually self-declared that exact evidence as missing despite being
    "conclusive", permanently blocking catalog selection.
    """
    context = make_context()
    candidate_only = [{"status": "candidate", "confidence": 0.0, "claim": "An unhealthy dependency is degrading checkout."}]
    assert "topology" not in IterativeInvestigator._required_sources(context, candidate_only)
    assert "dependency" not in IterativeInvestigator._required_sources(context, candidate_only)

    leading = [{"status": "leading", "confidence": 0.6, "claim": "An unhealthy downstream dependency is degrading checkout."}]
    required = IterativeInvestigator._required_sources(context, leading)
    assert {"dependency", "topology"}.issubset(required)

    confirmed = [{"status": "confirmed", "confidence": 0.8, "claim": "An unhealthy upstream dependency is degrading checkout."}]
    required = IterativeInvestigator._required_sources(context, confirmed)
    assert {"dependency", "topology"}.issubset(required)

    unrelated_leading = [{"status": "leading", "confidence": 0.6, "claim": "A recent code change affected checkout."}]
    required = IterativeInvestigator._required_sources(context, unrelated_leading)
    assert "topology" not in required
    assert "dependency" not in required


def test_required_sources_adds_data_and_resource_once_a_resource_hypothesis_is_leading() -> None:
    """Same pattern as the dependency gap, on the sibling mechanism: real,
    live-reproduced on incident 5504a8e5472a471b893ee5bd835ac1d3 --
    "Resource saturation or a data-path constraint is affecting api-gateway"
    reached "confirmed" from 10 trace records alone, having never queried
    mysql.search (the "data" plane) or resource-health.search (the "resource"
    plane, added to test real CPU/memory saturation) at all, so the RCA
    perpetually self-declared "Resource telemetry and data-store health
    metrics..." as missing despite being "conclusive". The claim conflates
    two distinct testable causes, so both planes must be required."""
    context = make_context()
    candidate_only = [{"status": "candidate", "confidence": 0.0, "claim": "Resource saturation or a data-path constraint is affecting checkout."}]
    required = IterativeInvestigator._required_sources(context, candidate_only)
    assert "data" not in required
    assert "resource" not in required

    leading = [{"status": "leading", "confidence": 0.6, "claim": "Resource saturation or a data-path constraint is affecting checkout."}]
    required = IterativeInvestigator._required_sources(context, leading)
    assert "data" in required
    assert "resource" in required

    confirmed = [{"status": "confirmed", "confidence": 0.8, "claim": "Resource saturation or a data-path constraint is affecting checkout."}]
    required = IterativeInvestigator._required_sources(context, confirmed)
    assert "data" in required
    assert "resource" in required

    unrelated_leading = [{"status": "leading", "confidence": 0.6, "claim": "A recent code change affected checkout."}]
    required = IterativeInvestigator._required_sources(context, unrelated_leading)
    assert "data" not in required
    assert "resource" not in required


def test_investigation_does_not_stop_on_confirmed_until_its_own_required_sources_are_covered() -> None:
    """`_required_sources` already grows to include "resource"/"data" once a
    resource-or-data hypothesis is leading (see the test above) - but the
    investigation loop's own early-stop-on-confirmed check used to fire the
    moment `_revise_hypotheses` marked the leading hypothesis "confirmed",
    completely independent of whether those specific required planes had
    ever actually been queried. `_revise_hypotheses`'s "confirmed" threshold
    is a numeric/independent-source-count check that can be satisfied by
    correlation evidence (e.g. trace spans) alone, well before
    `_select_tool` gets a turn at the plane that would actually test the
    claim directly. Reproduced live: a "resource_or_data" hypothesis
    reached `status="confirmed"` at 0.668 confidence and stopped the
    investigation after 2 steps, having queried neither
    resource-health.search nor mysql.search at all - so the same
    investigation simultaneously reported `conclusive: True` and (via the
    unrelated post-loop `missing_sources` computation) declared "resource"
    and "data" as missing evidence, which then blocks catalog readiness
    regardless of the conclusive flag.
    """
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    confirmed_resource_hypothesis = [{
        "status": "confirmed", "confidence": 0.668,
        "supporting_evidence_ids": ["DATA", "RESOURCE"],
        "claim": "Resource saturation or a data-path constraint is affecting checkout.",
    }]

    # make_context()'s alert text ("timeout", "deployment") pulls in "traces"
    # and "code" as required baseline sources too - cover the investigator's
    # actual full required-sources set, not just the universal minimum.
    # "database" is the raw evidence-source string that _source() aliases to
    # the "data" plane (there is no literal "data" alias).
    baseline = [
        {"source": source} for source in IterativeInvestigator._required_sources(context)
    ]

    # Neither "resource" nor "data" queried yet - must not stop despite "confirmed".
    assert investigator._confirmed_without_declared_gaps(
        confirmed_resource_hypothesis, baseline, context,
    ) is False

    # Only "data" covered - "resource" still outstanding.
    assert investigator._confirmed_without_declared_gaps(
        confirmed_resource_hypothesis, [*baseline, {"source": "database"}], context,
    ) is False

    # Every required plane (baseline plus this claim's own resource+data) covered.
    assert investigator._confirmed_without_declared_gaps(
        confirmed_resource_hypothesis,
        [*baseline, {"source": "database"}, {"source": "resource"}],
        context,
    ) is True

    # A hypothesis that isn't actually "confirmed" yet must never stop the loop early.
    candidate_only = [{
        "status": "candidate", "confidence": 0.2,
        "claim": "Resource saturation or a data-path constraint is affecting checkout.",
    }]
    assert investigator._confirmed_without_declared_gaps(candidate_only, [], context) is False


def test_select_tool_pursues_resource_health_for_a_leading_resource_hypothesis() -> None:
    context = make_context()
    context.alert.name = "CheckoutLatencyHigh"
    context.alert.description = "checkout p99 latency is above threshold"
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    leading_resource = [
        {"status": "leading", "confidence": 0.6, "claim": "Resource saturation or a data-path constraint is affecting checkout."},
    ]

    selection = investigator._select_tool(
        context=context, evidence=[], hypotheses=leading_resource,
        tool_counts={"logs.search": 1, "telemetry.search": 1, "traces.search": 1, "code.search": 1, "topology.search": 1, "dependency-health.search": 1},
    )

    assert selection is not None
    tool_name, arguments = selection
    assert tool_name in {"resource-health.search", "mysql.search"}
    # Unlike dependency-health.search, a resource check genuinely tests the
    # alerting service's own container -- no discovered-dependency targeting
    # or related_to override applies.
    assert arguments["service"] == "checkout"


def test_saturated_container_supports_a_resource_hypothesis() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    hypothesis = {"claim": "Resource saturation or a data-path constraint is affecting checkout."}
    resource_row = {
        "source_type": "resource",
        "service": "checkout",
        "metadata": {"service": "checkout", "saturated": True, "cpu_percent": 97.0, "cpu_throttled_ratio": 0.4},
    }

    assert investigator._structured_mechanism_support(hypothesis, resource_row) is True


def test_healthy_container_does_not_disprove_a_data_path_constraint() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    hypothesis = {"claim": "Resource saturation or a data-path constraint is affecting checkout."}
    resource_row = {
        "source_type": "resource",
        "service": "checkout",
        "metadata": {"service": "checkout", "saturated": False, "cpu_percent": 12.0, "cpu_throttled_ratio": 0.0},
    }

    assert investigator._structured_mechanism_contradiction(hypothesis, resource_row) is False
    assert investigator._structured_mechanism_contradiction(
        {"claim": "Resource saturation is affecting checkout."}, resource_row,
    ) is True


def test_later_resource_health_is_not_support_for_a_historical_cause() -> None:
    """Later cgroup state cannot corroborate a historical resource bottleneck."""
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    checked_now = context.alert.starts_at + timedelta(hours=2)
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "RESOURCE-SATURATED",
        "source": "resource",
        "uri": "docker://checkout/stats",
        "observed_at": checked_now.isoformat(),
        "service": "checkout",
        "saturated": True,
        "cpu_percent": 96.5,
        "cpu_throttled_ratio": 0.35,
        "summary": "checkout container is CPU throttled",
    }])
    hypotheses = [{
        "hypothesis_id": "resource-hyp",
        "claim": "Resource saturation or a data-path constraint is affecting checkout.",
        "source": "mechanism_candidate",
        "status": "candidate",
        "confidence": 0.0,
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "affected_resource_ids": [], "causal_sequence": [], "confidence_components": {},
        "falsification_check": {}, "next_evidence_requests": [],
    }]

    revised = investigator._revise_hypotheses(hypotheses, evidence, context=context)
    resource_hyp = next(row for row in revised if row["hypothesis_id"] == "resource-hyp")

    assert "RESOURCE-SATURATED" not in resource_hyp["supporting_evidence_ids"]


def test_select_tool_pursues_topology_before_a_leading_dependency_hypothesis_can_go_unchecked() -> None:
    context = make_context()
    context.alert.name = "CheckoutLatencyHigh"
    context.alert.description = "checkout p99 latency is above threshold"
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    leading_dependency = [
        {"status": "leading", "confidence": 0.6, "claim": "An unhealthy upstream dependency is degrading checkout."},
    ]

    selection = investigator._select_tool(
        context=context, evidence=[], hypotheses=leading_dependency,
        tool_counts={"logs.search": 1, "telemetry.search": 1, "traces.search": 1, "code.search": 1},
    )

    assert selection is not None
    tool_name, _ = selection
    assert tool_name in {"topology.search", "dependency-health.search"}


def make_context(*, hypotheses: list[dict[str, Any]] | None = None) -> Context:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="CheckoutPoolTimeout",
        service="checkout",
        severity=AlertSeverity.HIGH,
        description="checkout connection pool timeout after deployment",
    )
    incident = Incident(
        tenant_id="tenant-a", service="checkout", severity=AlertSeverity.HIGH, title=alert.name,
    )
    return Context(
        tenant_id=alert.tenant_id,
        incident_id=incident.id,
        alert=alert,
        metadata={
            "discovery_report": {"report": {"hypotheses": hypotheses or []}},
            "context_evidence": {},
        },
    )


@pytest.mark.asyncio
async def test_investigation_queries_missing_sources_and_returns_inconclusive() -> None:
    client = FakeDiscoveryClient({})
    investigator = IterativeInvestigator(client=client)
    investigator.max_steps = 2

    report = await investigator.investigate(make_context())

    assert report["status"] == "budget_exhausted"
    assert report["conclusive"] is False
    assert report["steps_used"] == 2
    assert len(client.calls) == 2
    assert all(name in ReadOnlyDiscoveryClient.ALLOWED_TOOLS for name, _ in client.calls)
    assert report["next_evidence"]
    assert report["outcome"] == "INSUFFICIENT_EVIDENCE"
    assert report["rca_result"]["root_cause"] is None
    assert report["investigation_plan"]["questions_to_answer"]
    assert report["investigation_plan"]["recommended_tool_calls"]
    assert report["correlation_id"]
    assert all("start_time" in arguments and "end_time" in arguments for _, arguments in client.calls)


@pytest.mark.asyncio
async def test_full_accumulated_context_leaves_capacity_for_targeted_diagnostics() -> None:
    context = make_context()
    context.metadata["context_evidence"] = {"code": [
        {"evidence_id": f"CODE-{index}", "source": "code", "snippet": "instrumentation only"}
        for index in range(200)
    ]}
    client = FakeDiscoveryClient({"logs.search": [
        {"evidence_id": "LOG-targeted", "source": "logs", "snippet": "read-only diagnostic result"}
    ]})
    investigator = IterativeInvestigator(client=client)
    investigator.max_steps = 4
    report = await investigator.investigate(context)

    assert report["steps_used"] == 4
    assert all(arguments["limit"] > 0 for _, arguments in client.calls)
    assert report["stop_reason"] != "evidence_budget_exhausted"
    assert report["evidence_count"] <= investigator.max_evidence
    assert any(row["evidence_id"] == "LOG-targeted" for row in report["evidence"])
    assert report["conclusive"] is False


def test_failed_outbound_connection_does_not_require_a_downstream_server_span() -> None:
    row = {"source_type": "trace", "metadata": {"slowest_spans": [{
        "tags": {"span.kind": "client"}, "exception_types": ["httpx.ConnectTimeout"],
        "duration_ms": 5002,
    }]}}
    claim = {"claim": "Outbound dependency connection timeouts are delaying checkout requests."}
    assert IterativeInvestigator._structured_mechanism_support(claim, row)
    row["metadata"]["slowest_spans"][0]["exception_types"] = ["httpx.ReadTimeout"]
    assert not IterativeInvestigator._structured_mechanism_support(claim, row)


def test_generic_change_candidate_does_not_override_latency_evidence_priority() -> None:
    context = make_context(hypotheses=[{"cause": "A recent configuration change affected checkout"}])
    context.alert.name = "CheckoutLatencyHigh"
    context.alert.description = "checkout p99 latency is above threshold"
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))

    selection = investigator._select_tool(
        context=context,
        evidence=[],
        hypotheses=investigator._initial_hypotheses(context),
        tool_counts={},
    )

    assert selection is not None
    tool_name, arguments = selection
    assert tool_name == "logs.search"
    assert datetime.fromisoformat(arguments["start_time"]).tzinfo == UTC
    assert datetime.fromisoformat(arguments["end_time"]) > datetime.fromisoformat(arguments["start_time"])


def test_unresolved_latency_investigation_queries_code_before_bulk_inventory() -> None:
    context = make_context()
    context.alert.name = "CheckoutLatencyHigh"
    context.alert.description = "checkout p95 latency is above 2 seconds"
    context.metadata["context_quality"] = {"diagnostic_gaps": ["causal_or_action"]}
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "LOG-IRRELEVANT",
        "source": "log",
        "uri": "log://archive/replayed-alert.json",
        "summary": "historical replayed alert",
        "observed_at": (context.alert.starts_at - timedelta(days=5)).isoformat(),
    }, {
        "evidence_id": "METRIC-LATENCY",
        "source": "telemetry",
        "uri": "prometheus://checkout/latency",
        "summary": "checkout p95 latency is above 2 seconds",
        "observed_at": context.alert.starts_at.isoformat(),
    }])

    selection = investigator._select_tool(
        context=context,
        evidence=evidence,
        hypotheses=investigator._revise_hypotheses([], evidence, context=context),
        tool_counts={"logs.search": 1, "traces.search": 1},
    )

    assert selection is not None
    assert selection[0] == "code.search"


def test_non_operational_log_cannot_seed_hypothesis_and_source_is_accounted() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "LOG-REPLAY",
        "source": "log",
        "uri": "log://archive/replayed-alert.json",
        "summary": "unrelated historical latency alert",
        "observed_at": (context.alert.starts_at - timedelta(days=5)).isoformat(),
    }, {
        "evidence_id": "METRIC-CURRENT",
        "source": "telemetry",
        "uri": "prometheus://checkout/pool-timeout",
        "summary": "checkout connection pool timeout is active",
        "observed_at": context.alert.starts_at.isoformat(),
    }, {
        "evidence_id": "CODE-REVIEWED",
        "source": "code",
        "uri": "repository://checkout/handler.py#L10",
        "summary": "request handler delegates to the pool",
        "observed_at": context.alert.starts_at.isoformat(),
        "current_operational_evidence": False,
    }])

    hypotheses = investigator._revise_hypotheses([], evidence, context=context)
    assessments = investigator._source_assessments(evidence, hypotheses)

    assert "METRIC-CURRENT" in hypotheses[0]["supporting_evidence_ids"]
    assert "LOG-REPLAY" not in hypotheses[0]["claim"]
    assert assessments["logs"]["disposition"] == "reviewed_no_incident_aligned_evidence"
    assert assessments["code"]["disposition"] == "reviewed_no_causal_match"


def test_root_trace_latency_is_not_mistaken_for_a_causal_mechanism() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    hypothesis = {"claim": "An unhealthy downstream dependency is degrading checkout."}
    trace = {
        "source_type": "trace",
        "metadata": {
            "slowest_spans": [{"service": "checkout", "operation": "GET", "duration_ms": 3200}],
            "dependency_edges": [],
        },
    }

    assert investigator._structured_mechanism_support(hypothesis, trace) is False


def test_healthy_dependency_does_not_contradict_an_observed_latency_signal() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "METRIC-LATENCY",
        "source": "telemetry",
        "uri": "prometheus://checkout/latency",
        "observed_at": context.alert.starts_at.isoformat(),
        "summary": "checkout latency is above 2 seconds",
    }, {
        "evidence_id": "DEPENDENCY-HEALTHY",
        "source": "dependency",
        "uri": "docker://payments",
        "observed_at": context.alert.starts_at.isoformat(),
        "service": "payments",
        "related_to": "checkout",
        "healthy": True,
        "summary": "checkout dependency payments is healthy",
    }])
    hypotheses = [{
        "hypothesis_id": "observation",
        "claim": "Observed signal requiring causal confirmation: checkout latency is above 2 seconds",
        "source": "derived_observation",
        "confidence": 0.3,
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "affected_resource_ids": [], "causal_sequence": [], "confidence_components": {},
        "falsification_check": {}, "next_evidence_requests": [],
    }]

    revised = investigator._revise_hypotheses(hypotheses, evidence, context=context)
    observed = next(row for row in revised if row["hypothesis_id"] == "observation")

    assert observed["supporting_evidence_ids"] == ["METRIC-LATENCY"]
    assert observed["contradicting_evidence_ids"] == []


def test_slow_cross_service_trace_supports_dependency_candidate() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    hypothesis = {"claim": "An unhealthy downstream dependency is degrading checkout."}
    trace = {
        "source_type": "trace",
        "metadata": {
            "slowest_spans": [{"service": "payments", "operation": "POST /charge", "duration_ms": 910}],
            "dependency_edges": [{"upstream": "checkout", "downstream": "payments"}],
        },
    }

    assert investigator._structured_mechanism_support(hypothesis, trace) is True


def test_incident_window_evidence_remains_temporally_aligned_after_wall_clock_age() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    row = {
        "incident_window_relation": "during",
        "freshness_seconds": 86400,
        "metadata": {"current_operational_evidence": True},
    }

    assert investigator._incident_window_aligned(row) is True


def test_compiled_trace_evidence_is_idempotent_and_keeps_causal_metadata() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    raw = [{
        "evidence_id": "TRACE-BOUND",
        "source": "trace",
        "uri": "jaeger://trace/bound",
        "observed_at": context.alert.starts_at.isoformat(),
        "slowest_spans": [{"service": "payments", "operation": "POST /charge", "duration_ms": 910}],
        "dependency_edges": [{"upstream": "checkout", "downstream": "payments"}],
    }]

    first = investigator._compile_evidence(context, raw)
    second = investigator._compile_evidence(context, first)

    assert second == first
    assert second[0]["metadata"]["dependency_edges"][0]["downstream"] == "payments"
    assert "metadata" not in second[0]["metadata"]


def test_structured_trace_binding_includes_traceable_citation() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "TRACE-CITED",
        "source": "trace",
        "uri": "jaeger://trace/cited",
        "observed_at": context.alert.starts_at.isoformat(),
        "slowest_spans": [{"service": "payments", "operation": "POST /charge", "duration_ms": 910}],
        "dependency_edges": [{"upstream": "checkout", "downstream": "payments"}],
    }])
    hypotheses = [{
        "hypothesis_id": "dependency",
        "claim": "An unhealthy downstream dependency is degrading checkout.",
        "source": "mechanism_candidate",
        "confidence": 0.0,
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "affected_resource_ids": [],
        "causal_sequence": [],
        "confidence_components": {},
        "falsification_check": {},
        "next_evidence_requests": [],
    }]

    revised = investigator._revise_hypotheses(hypotheses, evidence, context=context)
    bound = next(row for row in revised if row["hypothesis_id"] == "dependency")

    assert bound["supporting_evidence_ids"] == ["TRACE-CITED"]
    assert bound["evidence_bindings"][0]["source_uri"] == "jaeger://trace/cited"
    assert bound["independent_sources"] == ["traces"]


def test_structured_metric_evidence_is_summarized_without_raw_json() -> None:
    summary = IterativeInvestigator._human_evidence_summary({
        "source_status": "completed",
        "query": "sum(rate(http_requests_total[5m]))",
        "series": [{"metric": {"service": "checkout"}, "values": [[1, "2"]]}],
        "provenance": {"source": "onboarded-prometheus"},
    })

    assert summary == "Prometheus returned 1 time series for query: sum(rate(http_requests_total[5m]))"
    assert "source_status" not in summary


def test_confirmed_hypothesis_outranks_a_higher_confidence_unconfirmable_symptom() -> None:
    """Reproduced live on a real incident: a symptom-only derived_observation
    (0.71 confidence) and a genuinely confirmed dependency mechanism (0.66
    confidence, causally eligible, properly corroborated) existed side by
    side. Sorting by raw confidence alone put the unconfirmable symptom in
    hypotheses[0] - the position every caller treats as "the conclusion" -
    so the investigation kept reporting "inconclusive: symptom summary, not
    a causal mechanism" despite already holding a real, corroborated answer
    one slot down."""
    confirmed_mechanism = {"status": "confirmed", "confidence": 0.66}
    higher_confidence_symptom = {"status": "leading", "confidence": 0.71}

    ranked = sorted(
        [higher_confidence_symptom, confirmed_mechanism],
        key=IterativeInvestigator._hypothesis_rank,
        reverse=True,
    )

    assert ranked[0] is confirmed_mechanism


def test_hypothesis_rank_breaks_ties_by_confidence_within_the_same_status() -> None:
    lower = {"status": "candidate", "confidence": 0.2}
    higher = {"status": "candidate", "confidence": 0.4}

    assert sorted([lower, higher], key=IterativeInvestigator._hypothesis_rank, reverse=True) == [higher, lower]


def test_missing_optional_sources_do_not_cap_independently_corroborated_mechanism() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "DEPENDENCY-DOWN",
        "source": "dependency",
        "uri": "docker://payments",
        "observed_at": context.alert.starts_at.isoformat(),
        "service": "payments",
        "related_to": "checkout",
        "runtime_state": "exited",
        "healthy": False,
        "summary": "payments dependency exited during the checkout incident",
    }, {
        "evidence_id": "TRACE-PAYMENTS",
        "source": "trace",
        "uri": "jaeger://trace/payments",
        "observed_at": context.alert.starts_at.isoformat(),
        "slowest_spans": [{"service": "payments", "operation": "POST /charge", "duration_ms": 1200}],
        "dependency_edges": [{"upstream": "checkout", "downstream": "payments"}],
        "summary": "checkout trace stalls at payments",
    }])
    hypotheses = investigator._revise_hypotheses([], evidence, context=context)
    dependency = next(row for row in hypotheses if "dependency" in row["claim"].lower())

    assert dependency["independent_sources"] == ["dependency", "traces"]
    assert "required_sources_unavailable" not in dependency["confidence_breakdown"]["ceiling_reasons"]
    assert dependency["status"] == "confirmed"


def test_minimum_independent_sources_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RESOLUTION_INVESTIGATION_MIN_SOURCES", "1")

    assert IterativeInvestigator(client=FakeDiscoveryClient({})).minimum_independent_sources == 1


def test_minimum_independent_sources_defaults_to_two_and_never_drops_below_one(monkeypatch: pytest.MonkeyPatch) -> None:
    assert IterativeInvestigator(client=FakeDiscoveryClient({})).minimum_independent_sources == 2

    monkeypatch.setenv("RESOLUTION_INVESTIGATION_MIN_SOURCES", "0")
    # An uncorroborated hypothesis must never auto-confirm on confidence alone -
    # the floor of 1 is a safety property, not just a default.
    assert IterativeInvestigator(client=FakeDiscoveryClient({})).minimum_independent_sources == 1


def test_single_source_hypothesis_stays_leading_until_corroboration_bar_is_lowered() -> None:
    """A well-corroborated single-source hypothesis (e.g. a service with no
    tracing, only one usable evidence plane) reaches confirm-eligible confidence
    but must not auto-confirm on the conservative default of 2 sources - only once
    an operator has explicitly relaxed the bar to 1 for this deployment."""
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "TRACE-PAYMENTS",
        "source": "trace",
        "uri": "jaeger://trace/payments",
        "observed_at": context.alert.starts_at.isoformat(),
        "slowest_spans": [{"service": "payments", "operation": "POST /charge", "duration_ms": 1200}],
        "dependency_edges": [{"upstream": "checkout", "downstream": "payments"}],
        "summary": "checkout trace stalls at payments",
    }])

    hypotheses = investigator._revise_hypotheses([], evidence, context=context)
    dependency = next(row for row in hypotheses if "dependency" in row["claim"].lower())
    assert dependency["independent_sources"] == ["traces"]
    assert dependency["confidence"] >= investigator.conclusive_threshold
    assert dependency["status"] != "confirmed"

    investigator.minimum_independent_sources = 1
    hypotheses = investigator._revise_hypotheses([], evidence, context=context)
    dependency = next(row for row in hypotheses if "dependency" in row["claim"].lower())
    assert dependency["status"] == "confirmed"


def test_fallback_diagnostic_prefers_a_recent_change_over_a_generic_code_snippet() -> None:
    """Reproduces the exact production noise this ranking exists to fix: a
    real incident whose fallback (no LLM configured) surfaced an arbitrary
    import line as its leading claim while a deployment shortly before the
    incident window sat in the same evidence set, unconsidered. Discovery
    order previously decided which one won; causal relevance must now.
    """
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "CODE-NOISE", "source": "code",
        "uri": "repository://api-gateway/safety.py#L1",
        "observed_at": context.alert.starts_at.isoformat(),
        "summary": "from api_gateway.safety import SafetyAnalyzer",
    }, {
        "evidence_id": "DEPLOY-1", "source": "deployment",
        "uri": "jenkins://checkout-api/build/482",
        "observed_at": (context.alert.starts_at - timedelta(minutes=6)).isoformat(),
        "summary": "checkout-api deployed build 482 six minutes before the alert",
    }])

    hypotheses = investigator._revise_hypotheses([], evidence, context=context)
    observation = next(row for row in hypotheses if row.get("source") == "derived_observation")

    assert "build 482" in observation["claim"]
    assert "SafetyAnalyzer" not in observation["claim"]
    assert observation["claim"].startswith("Candidate causal change identified")


def test_fallback_diagnostic_skips_an_unrendered_alert_rule_template() -> None:
    """Reproduces a live production incident: a "changes" evidence row was a
    diff touching an alerting-rule config file, and its raw `description:`
    field - a Prometheus annotation template like 'Service {{ $labels.job }}
    is not reachable' - was surfaced verbatim as the leading "candidate causal
    change" with the placeholder never substituted and zero real evidence
    behind it. Template markup is never an observation and must never win."""
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "CHANGE-ALERTRULE", "source": "changes",
        "uri": "git://observability/alert.rules.yml",
        "observed_at": (context.alert.starts_at - timedelta(minutes=4)).isoformat(),
        "incident_window_relation": "before",
        "summary": 'description: "Service {{ $labels.job }} is not reachable by Prometheus for more than 1 minute."',
    }, {
        "evidence_id": "DEPLOY-1", "source": "deployment",
        "uri": "jenkins://checkout-api/build/482",
        "observed_at": (context.alert.starts_at - timedelta(minutes=6)).isoformat(),
        "summary": "checkout-api deployed build 482 six minutes before the alert",
    }])

    hypotheses = investigator._revise_hypotheses([], evidence, context=context)
    observation = next(row for row in hypotheses if row.get("source") == "derived_observation")

    assert "build 482" in observation["claim"]
    assert "$labels.job" not in observation["claim"]
    assert observation["supporting_evidence_ids"] == ["DEPLOY-1"]


def test_leading_diagnostic_candidate_returns_none_when_only_template_text_is_available() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "CHANGE-ALERTRULE", "source": "changes",
        "uri": "git://observability/alert.rules.yml",
        "observed_at": (context.alert.starts_at - timedelta(minutes=4)).isoformat(),
        "incident_window_relation": "before",
        "summary": 'description: "Service {{ $labels.job }} is not reachable by Prometheus for more than 1 minute."',
    }])

    assert investigator._leading_diagnostic_candidate(evidence) is None


def test_fallback_diagnostic_still_uses_an_operational_signal_with_no_change_present() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "CODE-NOISE", "source": "code",
        "uri": "repository://api-gateway/safety.py#L1",
        "observed_at": context.alert.starts_at.isoformat(),
        "summary": "from api_gateway.safety import SafetyAnalyzer",
    }, {
        "evidence_id": "METRIC-1", "source": "telemetry",
        "uri": "prometheus://checkout/latency",
        "observed_at": context.alert.starts_at.isoformat(),
        "summary": "checkout p99 latency is above threshold",
    }])

    hypotheses = investigator._revise_hypotheses([], evidence, context=context)
    observation = next(row for row in hypotheses if row.get("source") == "derived_observation")

    assert "p99 latency" in observation["claim"]
    assert observation["claim"].startswith("Observed signal requiring causal confirmation")


def test_derived_observation_cannot_be_promoted_to_root_cause() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "METRIC-1", "source": "telemetry",
        "uri": "prometheus://checkout/latency", "observed_at": context.alert.starts_at.isoformat(),
        "summary": "checkout latency timeout after deployment",
    }, {
        "evidence_id": "LOG-1", "source": "log",
        "uri": "logs://checkout/timeout", "observed_at": context.alert.starts_at.isoformat(),
        "summary": "checkout latency timeout after deployment",
    }])
    hypotheses = investigator._revise_hypotheses([], evidence, context=context)
    observation = next(row for row in hypotheses if row.get("source") == "derived_observation")

    assert observation["independent_source_count"] == 2
    assert observation["status"] != "confirmed"


def test_all_four_mechanism_candidates_are_considered_alongside_a_symptom_seed() -> None:
    """Real, live-reproduced gap: the candidate set is documented as holding
    "3-5 candidates" (see the comment in _revise_hypotheses), but the loop
    broke as soon as the count reached 3 -- with the common case of one
    pre-existing derived_observation seed hypothesis (built from whatever
    evidence is already attached to the alert), that silently capped every
    investigation at just the first 2 of the 4 mechanism candidates
    (recent_change and dependency), never even considering resource_or_data
    or traffic regardless of which one actually fit the evidence. Reproduced
    live: 0 of ~60 freshly re-investigated incidents across this session ever
    carried a resource_or_data or traffic hypothesis at all."""
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "METRIC-1", "source": "telemetry",
        "uri": "prometheus://checkout/latency", "observed_at": context.alert.starts_at.isoformat(),
        "summary": "checkout latency timeout after deployment",
    }])

    hypotheses = investigator._revise_hypotheses([], evidence, context=context)
    claims = {str(h.get("claim") or "").lower() for h in hypotheses}

    assert len(hypotheses) == 5, "1 derived_observation seed + all 4 mechanism candidates"
    assert any("resource saturation" in claim for claim in claims)
    assert any("traffic or workload shift" in claim for claim in claims)
    assert any("recent code or configuration change" in claim for claim in claims)
    assert any("unhealthy upstream or downstream dependency" in claim for claim in claims)


def test_truncated_structured_metric_evidence_preserves_query_observation() -> None:
    summary = IterativeInvestigator._human_evidence_summary(
        '{"query": "histogram_quantile(0.95, rate(latency_bucket[5m])) > 2", "series": [{"metric":'
    )

    assert summary == (
        "Prometheus observed matching time series for query: "
        "histogram_quantile(0.95, rate(latency_bucket[5m])) > 2"
    )


def test_pre_alert_trace_inside_query_envelope_counts_as_operational_evidence() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    observed_at = context.alert.starts_at - timedelta(minutes=3)

    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "TRACE-PRE-ALERT",
        "source": "trace",
        "uri": "jaeger://trace/pre-alert",
        "observed_at": observed_at.isoformat(),
        "slowest_spans": [{"service": "payments", "operation": "POST /charge", "duration_ms": 910}],
        "dependency_edges": [{"upstream": "checkout", "downstream": "payments"}],
    }])

    assert evidence[0]["incident_window_relation"] == "during"
    assert evidence[0]["current_operational_evidence"] is True


def test_current_dependency_snapshot_is_after_historical_incident_window() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "DEPENDENCY-NOW",
        "source": "dependency",
        "uri": "docker://kaiops/payments",
        "observed_at": (context.alert.starts_at + timedelta(hours=2)).isoformat(),
        "service": "payments",
        "related_to": "checkout",
        "runtime_state": "running",
        "healthy": True,
    }])

    assert evidence[0]["incident_window_relation"] == "after"
    assert evidence[0]["current_operational_evidence"] is False


def test_unhealthy_dependency_in_incident_window_is_typed_support() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    hypothesis = {"claim": "An unhealthy downstream dependency is degrading checkout."}
    dependency = {
        "source_type": "dependency",
        "service": "payments",
        "metadata": {
            "service": "payments", "related_to": "checkout",
            "runtime_state": "exited", "healthy": False,
        },
    }

    assert investigator._structured_mechanism_support(hypothesis, dependency) is True


def test_later_dependency_failure_is_not_support_for_a_historical_cause() -> None:
    """A query-time snapshot cannot establish the cause two hours earlier."""
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    checked_now = context.alert.starts_at + timedelta(hours=2)
    evidence = investigator._compile_evidence(context, [{
        "evidence_id": "DEPENDENCY-UNHEALTHY",
        "source": "dependency",
        "uri": "docker://payments",
        "observed_at": checked_now.isoformat(),
        "service": "payments",
        "related_to": "checkout",
        "healthy": False,
        "runtime_state": "exited",
        "summary": "checkout dependency payments is unhealthy",
    }])
    hypotheses = [{
        "hypothesis_id": "dependency-hyp",
        "claim": "An unhealthy downstream dependency is degrading checkout.",
        "source": "mechanism_candidate",
        "status": "candidate",
        "confidence": 0.0,
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "affected_resource_ids": [], "causal_sequence": [], "confidence_components": {},
        "falsification_check": {}, "next_evidence_requests": [],
    }]

    revised = investigator._revise_hypotheses(hypotheses, evidence, context=context)
    dependency_hyp = next(row for row in revised if row["hypothesis_id"] == "dependency-hyp")

    assert "DEPENDENCY-UNHEALTHY" not in dependency_hyp["supporting_evidence_ids"]


def test_later_healthy_dependency_does_not_contradict_historical_trace() -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    context = make_context()
    checked_now = context.alert.starts_at + timedelta(hours=2)
    evidence = investigator._compile_evidence(context, [
        {
            "evidence_id": "TRACE-CROSS",
            "source": "trace",
            "uri": "jaeger://trace/1",
            "observed_at": context.alert.starts_at.isoformat(),
            "summary": "checkout to payments trace",
            "slowest_spans": [{"service": "payments", "operation": "POST /charge", "duration_ms": 910}],
            "dependency_edges": [{"upstream": "checkout", "downstream": "payments"}],
        },
        {
            "evidence_id": "DEPENDENCY-HEALTHY-NOW",
            "source": "dependency",
            "uri": "docker://payments",
            "observed_at": checked_now.isoformat(),
            "service": "payments",
            "related_to": "checkout",
            "healthy": True,
            "runtime_state": "running",
            "summary": "checkout dependency payments is healthy",
        },
    ])
    hypotheses = [{
        "hypothesis_id": "dependency-hyp",
        "claim": "An unhealthy downstream dependency is degrading checkout.",
        "source": "mechanism_candidate",
        "status": "candidate",
        "confidence": 0.0,
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "affected_resource_ids": [], "causal_sequence": [], "confidence_components": {},
        "falsification_check": {}, "next_evidence_requests": [],
    }]

    revised = investigator._revise_hypotheses(hypotheses, evidence, context=context)
    dependency_hyp = next(row for row in revised if row["hypothesis_id"] == "dependency-hyp")

    assert "DEPENDENCY-HEALTHY-NOW" not in dependency_hyp["contradicting_evidence_ids"]


@pytest.mark.asyncio
async def test_keyword_overlap_alone_cannot_confirm_a_hypothesis() -> None:
    hypothesis = {"cause": "checkout connection pool exhaustion", "confidence": 0.6}
    client = FakeDiscoveryClient({
        "code.search": [{
            "evidence_id": "CODE-POOL",
            "source": "code",
            "snippet": "checkout connection pool exhaustion occurs when pool size is two",
        }],
        "logs.search": [{
            "evidence_id": "LOG-POOL",
            "source": "log",
            "snippet": "checkout connection pool exhaustion timeout",
        }],
    })
    investigator = IterativeInvestigator(client=client)
    investigator.max_steps = 4

    report = await investigator.investigate(make_context(hypotheses=[hypothesis]))

    assert report["status"] == "budget_exhausted"
    assert report["conclusive"] is False
    assert report["steps_used"] == 4
    assert report["conclusion"]["confidence"] < investigator.conclusive_threshold
    tested = next(row for row in report["hypotheses"] if row["claim"] == hypothesis["cause"])
    collected_ids = {row["evidence_id"] for row in report["evidence"]}
    assert {"CODE-POOL", "LOG-POOL"} <= collected_ids, (client.calls, report["steps"])
    assert tested["status"] != "confirmed"
    assert report["rca_result"]["outcome"] == "INSUFFICIENT_EVIDENCE"
    assert report["rca_result"]["root_cause"] is None
    assert len(report["typed_hypotheses"]) >= 3


@pytest.mark.asyncio
async def test_alert_label_never_becomes_confirmed_root_cause_without_corroboration() -> None:
    context = make_context(hypotheses=[{
        "cause": "checkout connection pool timeout after deployment",
        "confidence": 0.99,
    }])
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    investigator.max_steps = 1

    report = await investigator.investigate(context)

    assert report["conclusive"] is False
    assert report["rca_result"]["root_cause"] is None
    assert report["rca_result"]["outcome"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.asyncio
async def test_conflicting_operational_evidence_is_surfaced_and_blocks_root_cause() -> None:
    hypothesis = {"cause": "checkout connection pool exhaustion", "confidence": 0.8}
    context = make_context(hypotheses=[hypothesis])
    client = FakeDiscoveryClient({
        "changes.search": [{
            "evidence_id": "LOG-CONTRADICTION",
            "source": "log",
            "snippet": "checkout connection pool healthy and normal",
            "timestamp": context.alert.starts_at.isoformat(),
        }],
    })
    investigator = IterativeInvestigator(client=client)
    investigator.max_steps = 1

    report = await investigator.investigate(context)

    assert report["rca_result"]["outcome"] == "CONFLICTING_EVIDENCE"
    assert report["rca_result"]["root_cause"] is None
    assert "LOG-CONTRADICTION" in report["rca_result"]["contradicting_evidence_ids"]
    assert "unresolved_contradicting_evidence" in report["evidence_graph"]["data_gaps"]


@pytest.mark.asyncio
async def test_discovery_client_rejects_mutating_or_unknown_tools() -> None:
    client = ReadOnlyDiscoveryClient()

    with pytest.raises(ValueError, match="not read-only"):
        await client.call("kubectl.restart", {"service": "checkout"})


@pytest.mark.asyncio
async def test_investigation_emits_durable_events_in_order() -> None:
    events: list[tuple[str, dict[str, Any]]] = []
    client = FakeDiscoveryClient({})
    investigator = IterativeInvestigator(client=client)
    investigator.max_steps = 1

    async def persist(event: str, payload: dict[str, Any]) -> None:
        events.append((event, payload))

    report = await investigator.investigate(make_context(), persist=persist)

    assert [event for event, _ in events] == ["started", "step", "completed"]
    assert events[0][1]["investigation_id"] == report["investigation_id"]
    assert events[0][1]["investigation_plan"]["schema_version"] == "kaims.investigation-plan.v1"
    assert events[1][1]["sequence_no"] == 1
    assert events[-1][1]["status"] == "budget_exhausted"


def _trace_row_with_dependency_edge(*, upstream: str, downstream: str) -> dict[str, Any]:
    return {
        "evidence_id": "TRACE-edge-1",
        "source_type": "trace",
        "metadata": {"dependency_edges": [{"upstream": upstream, "downstream": downstream}]},
    }


def test_discovered_dependency_service_finds_the_other_side_of_a_real_edge() -> None:
    evidence = [_trace_row_with_dependency_edge(upstream="api-gateway", downstream="model-router")]
    assert IterativeInvestigator._discovered_dependency_service("api-gateway", evidence) == "model-router"
    # Symmetric: the alerting service can be on either side of the edge.
    evidence = [_trace_row_with_dependency_edge(upstream="model-router", downstream="api-gateway")]
    assert IterativeInvestigator._discovered_dependency_service("api-gateway", evidence) == "model-router"


def test_discovered_dependency_service_is_empty_with_no_cross_service_edges() -> None:
    """Real, live-reproduced case: a single-hop trace with every span inside
    the alerting service itself carries no dependency_edges at all -- this
    must not fabricate a dependency that was never actually observed."""
    single_service_trace = {"evidence_id": "TRACE-1", "source_type": "trace", "metadata": {"dependency_edges": []}}
    assert IterativeInvestigator._discovered_dependency_service("api-gateway", [single_service_trace]) == ""
    assert IterativeInvestigator._discovered_dependency_service("api-gateway", []) == ""


def test_discovered_dependency_service_ignores_edges_not_touching_the_alerting_service() -> None:
    evidence = [_trace_row_with_dependency_edge(upstream="checkout", downstream="payments")]
    assert IterativeInvestigator._discovered_dependency_service("api-gateway", evidence) == ""


def test_select_tool_targets_the_discovered_dependency_not_a_self_check() -> None:
    """Real, live-reproduced gap: dependency-health.search was always called
    with service=<the alerting service itself>, so it could only ever answer
    "is api-gateway healthy?" -- never "is the dependency it is blamed on
    healthy?". Once a real cross-service trace edge names model-router,
    the tool call must target model-router and record api-gateway as the
    incident it relates back to, so investigation.py's own
    _structured_mechanism_support/_structured_mechanism_contradiction
    (which require target != related_to) can ever fire."""
    context = make_context()
    context.alert.name = "ApiGatewayLatencyHigh"
    context.alert.description = "api-gateway p99 latency is above threshold"
    context.alert.service = "api-gateway"
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    leading_dependency = [
        {"status": "leading", "confidence": 0.6, "claim": "An unhealthy downstream dependency is degrading api-gateway."},
    ]
    evidence = [_trace_row_with_dependency_edge(upstream="api-gateway", downstream="model-router")]

    selection = investigator._select_tool(
        context=context, evidence=evidence, hypotheses=leading_dependency,
        tool_counts={"logs.search": 1, "telemetry.search": 1, "traces.search": 1, "topology.search": 1},
    )

    assert selection is not None
    tool_name, arguments = selection
    assert tool_name == "dependency-health.search"
    assert arguments["service"] == "model-router"
    assert arguments["related_to"] == "api-gateway"


def test_select_tool_falls_back_to_a_self_check_with_no_discovered_dependency() -> None:
    """Backward compatible default: with no cross-service trace edge
    discovered yet, dependency-health.search keeps querying the alerting
    service itself exactly as before -- no related_to argument is fabricated."""
    context = make_context()
    context.alert.name = "ApiGatewayLatencyHigh"
    context.alert.description = "api-gateway p99 latency is above threshold"
    context.alert.service = "api-gateway"
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    leading_dependency = [
        {"status": "leading", "confidence": 0.6, "claim": "An unhealthy downstream dependency is degrading api-gateway."},
    ]

    selection = investigator._select_tool(
        context=context, evidence=[], hypotheses=leading_dependency,
        tool_counts={"logs.search": 1, "telemetry.search": 1, "traces.search": 1, "topology.search": 1},
    )

    assert selection is not None
    tool_name, arguments = selection
    assert tool_name == "dependency-health.search"
    assert arguments["service"] == "api-gateway"
    assert "related_to" not in arguments


@pytest.mark.asyncio
@pytest.mark.parametrize("supporting", [["E1"], ["E1", "E1"], ["E1", "E2"]])
async def test_confirmed_hypothesis_respects_claim_grounding_before_stopping(
    monkeypatch: pytest.MonkeyPatch, supporting: list[str],
) -> None:
    investigator = IterativeInvestigator(client=FakeDiscoveryClient({}))
    investigator.minimum_independent_sources = 1
    investigator.max_steps = 1
    hypothesis = {
        "hypothesis_id": "single-source-candidate",
        "claim": "A dependency failure caused the timeout",
        "status": "confirmed", "confidence": 0.9,
        "supporting_evidence_ids": supporting,
        "contradicting_evidence_ids": [],
        "falsification_check": {"objective": "Check independent dependency health"},
    }
    monkeypatch.setattr(investigator, "_revise_hypotheses", lambda *a, **kw: [hypothesis])
    monkeypatch.setattr(investigator, "_required_sources", lambda *a, **kw: set())
    monkeypatch.setattr(investigator, "_select_tool", lambda **kw: None)

    report = await investigator.investigate(make_context())

    corroborated = len(set(supporting)) >= 2
    assert report["conclusive"] is corroborated
    assert report["rca_result"]["outcome"] == (
        "EVIDENCE_SUPPORTED" if corroborated else "INSUFFICIENT_EVIDENCE"
    )
    causal = next(c for c in report["rca_result"]["claims"] if c["kind"] == "CAUSAL")
    assert causal["status"] == ("GROUNDED" if corroborated else "HYPOTHESIS")
    if not corroborated:
        assert report["rca_result"]["root_cause"] is None
        assert "causal_corroboration" in report["rca_result"]["missing_evidence"]


@pytest.mark.parametrize("leading", [
    {"claim": "Candidate causal change identified: container is up", "source": "derived_observation"},
    {"claim": "Observed signal requiring causal confirmation: HTTP 503"},
])
def test_observations_cannot_become_typed_causal_claims(leading):
    from resolution_agent.contracts import ClaimKind, ResolutionOutcome

    claims = IterativeInvestigator._build_claims(
        leading=leading, outcome=ResolutionOutcome.INSUFFICIENT_EVIDENCE,
        context=make_context(), evidence=[],
    )
    assert not any(claim.kind == ClaimKind.CAUSAL for claim in claims)


def test_genuine_causal_hypothesis_remains_explicitly_unconfirmed():
    from resolution_agent.contracts import ClaimKind, ClaimStatus, ResolutionOutcome

    claims = IterativeInvestigator._build_claims(
        leading={"claim": "Pool limit reduction exhausted checkout connections", "source": "discovery"},
        outcome=ResolutionOutcome.INSUFFICIENT_EVIDENCE,
        context=make_context(), evidence=[],
    )
    causal = next(claim for claim in claims if claim.kind == ClaimKind.CAUSAL)
    assert causal.status == ClaimStatus.HYPOTHESIS


def test_latency_alert_and_unrelated_log_do_not_prove_impact():
    from resolution_agent.contracts import ClaimKind, ClaimStatus, ResolutionOutcome

    context = make_context()
    context.alert.name = "HighLatency"
    claims = IterativeInvestigator._build_claims(
        leading=None, outcome=ResolutionOutcome.INSUFFICIENT_EVIDENCE,
        context=context, evidence=[{"source": "logs", "evidence_id": "unrelated-log", "snippet": "container started"}],
    )
    impact = next(claim for claim in claims if claim.kind == ClaimKind.IMPACT)
    assert impact.status == ClaimStatus.NOT_ESTABLISHED
    assert impact.supporting_evidence_ids == []

def test_supported_mechanism_gets_investigation_priority_over_unconfirmable_symptom():
    symptom = {'source': 'derived_observation', 'status': 'leading', 'confidence': .95,
               'supporting_evidence_ids': ['healthy-container']}
    mechanism = {'source': 'mechanism_candidate', 'status': 'leading', 'confidence': .55,
                 'supporting_evidence_ids': ['slow-trace']}
    unsupported = {'source': 'mechanism_candidate', 'status': 'candidate', 'confidence': .9}
    assert sorted([symptom, mechanism, unsupported], key=IterativeInvestigator._hypothesis_rank,
                  reverse=True)[0] == mechanism
    assert mechanism['status'] != 'confirmed'

def test_running_dependency_is_not_a_performance_counterexample():
    hypothesis = {'claim': 'An unhealthy downstream dependency is degrading checkout.'}
    row = {'source_type': 'dependency', 'metadata': {'service': 'payments', 'related_to': 'checkout',
           'healthy': True, 'runtime_state': 'running'}}
    assert IterativeInvestigator._structured_mechanism_contradiction(hypothesis, row) is False
    row['metadata']['health_scope'] = 'performance'
    assert IterativeInvestigator._structured_mechanism_contradiction(hypothesis, row) is True
