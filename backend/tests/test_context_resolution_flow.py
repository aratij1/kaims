import json
import pytest
from datetime import UTC, datetime
from uuid import uuid4
from ai_workbench_common.models import Context
from ai_workbench_common.memory_store import InMemoryStore
from common.models import Alert, AlertSeverity, Incident, Recommendation
from context_agent import ContextIntelligenceAgent
from context_agent.connectors import DiscoveryMCPConnector, VectorDBConnector
from model_router import ModelRouter
from model_router.router import ModelProvider, ModelResponse, build_usage
from resolution_agent import ResolutionIntelligenceAgent


@pytest.mark.asyncio
async def test_infrastructure_manifest_uses_claim_specific_source_policy():
    alert = Alert(tenant_id="tenant-a", source="prometheus", name="DiskSpaceLow", service="node-exporter", description="Disk utilization exceeds 90%", severity=AlertSeverity.CRITICAL)
    context = Context(tenant_id="tenant-a", incident_id=uuid4(), alert=alert)
    agent = ResolutionIntelligenceAgent(model_router=static_router())
    state = await agent.plan_investigation({"context": context, "gathered_context": {"alert": {"service": "node-exporter"}}})
    missing = state["investigation_report"]["missing_sources"]
    assert "telemetry" in missing
    # A disk symptom alone does not establish that a deployment/change plane
    # exists or is required to diagnose the issue.
    assert "changes" not in missing
    assert "code" not in missing
    assert "history" not in missing


@pytest.mark.asyncio
async def test_resolution_runtime_accepts_explicit_zero_confidence_abstention() -> None:
    recommendation = Recommendation(
        root_cause="Insufficient evidence", confidence=0, impact="Unknown",
        recommended_action="Collect evidence", severity=AlertSeverity.WARNING,
        tenant_id="tenant-a", incident_id=uuid4(),
        rationale="No linked evidence supports a hypothesis.",
        metadata={"rca_status": "insufficient_evidence", "evidence_ids": []},
    )
    assert await ResolutionIntelligenceAgent().validate(recommendation) is True


class StaticProvider(ModelProvider):
    async def generate(self, prompt: str, payload: dict) -> ModelResponse:
        self._ensure_available()
        self.breaker.record_success()
        import json

        # Build cited evidence list from payload
        evidence_ids = []
        summary = "incident"
        deployment = "payments-api"

        if isinstance(payload, dict):
            summary = payload.get("summary", payload.get("service", "incident"))
            alert_info = payload.get("alert", {})
            if isinstance(alert_info, dict):
                labels = alert_info.get("labels", {})
                if isinstance(labels, dict) and labels.get("deployment"):
                    deployment = str(labels["deployment"])

            disc_evidence = payload.get("discovery_evidence", [])
            if isinstance(disc_evidence, list):
                for item in disc_evidence:
                    if isinstance(item, dict) and item.get("evidence_id"):
                        evidence_ids.append(str(item["evidence_id"]))

            # Fallback/default if none found
            if not evidence_ids and payload.get("alert", {}).get("labels", {}).get("source_event_id"):
                source_id = payload["alert"]["labels"]["source_event_id"]
                evidence_ids.append(f"alert:{source_id}")

        content_obj = {
            "root_cause": f"The alert reports degradation after deployment {deployment}; confirm the rollout diff and timing before treating it as causal.",
            "confidence_score": 0.85,
            "evidence_used": evidence_ids,
            "alternative_causes": [],
            "grounding_notes": "Grounding based on Deployment context.",
            "impact_summary": f"Service impact for {summary}",
            "customer_impact": "Payment latency",
            "remediation_target": "payments",
            "recommended_action": "Rollback deployment",
            "commands": ["kubectl rollout undo deployment/payments-service -n prod"],
            "validation_queries": [],
            "rollback_plan": ""
        }

        return ModelResponse(
            content=json.dumps(content_obj),
            usage=build_usage(
                provider=self.name,
                model=f"{self.name}-model",
                input_tokens=100,
                output_tokens=50,
                input_cost_per_million=1.0,
                output_cost_per_million=2.0,
            ),
        )


class FallbackGateway:
    async def generate(self, request) -> dict:
        content = {
            "title": "Identify the most likely root cause using only",
            "summary": "Generic fallback RCA draft",
            "content": "Generic fallback content that should not be used as trusted RCA.",
            "commands": [],
            "scripts": [],
            "queries": [],
            "metadata": {
                "fallback": True,
                "fallback_reason": "gemini unavailable; gpt-4o unavailable; gpt-5 unavailable",
            },
        }
        return {
            "model": "heuristic-fallback",
            "content": json.dumps(content),
            "usage": {
                "provider": "heuristic-fallback",
                "model": "heuristic-fallback",
                "task": request.task,
                "estimated": True,
                "fallback": True,
            },
        }


def test_discovery_promotes_application_errors_into_report_findings() -> None:
    rows = [
        {
            "evidence_id": "LOG-timeout",
            "source": "log",
            "service": "recommendation",
            "container": "telemetry-recommendation",
            "uri": "docker://telemetry-recommendation#L1",
            "snippet": "2026-07-26T06:18:49Z Failed to export metrics: Deadline Exceeded",
            "diagnostic_signals": ["timeout", "error"],
        },
        {
            "evidence_id": "LOG-summary",
            "source": "log",
            "signal_type": "log_diagnosis",
            "snippet": "Structured log diagnosis",
            "diagnostic_signals": ["timeout"],
        },
    ]

    findings = DiscoveryMCPConnector._detected_errors(rows)

    assert len(findings) == 1
    assert findings[0]["service"] == "recommendation"
    assert findings[0]["evidence_id"] == "LOG-timeout"
    assert findings[0]["signals"] == ["timeout", "error"]


def test_detected_errors_exclude_unrelated_global_log_signals() -> None:
    alert = Alert(
        source="email",
        name="Payment API unavailable",
        service="payment",
        severity=AlertSeverity.CRITICAL,
        description="Payment requests are failing.",
        labels={"application": "robot-shop"},
    )
    incident = Incident(service="payment", severity=AlertSeverity.CRITICAL, title="payment unavailable")
    rows = [
        {
            "evidence_id": "LOG-rabbitmq",
            "source": "log",
            "service": "rabbitmq",
            "container": "kaiops-rabbitmq",
            "snippet": "Queue depth critical; threshold exceeded.",
            "diagnostic_signals": ["resource_exhaustion", "error"],
            "matched_terms": ["critical"],
        },
        {
            "evidence_id": "LOG-payment",
            "source": "log",
            "service": "payment",
            "container": "robot-shop-payment",
            "snippet": "Payment provider connection refused.",
            "diagnostic_signals": ["connection_refused", "error"],
            "matched_terms": ["payment"],
        },
    ]

    findings = DiscoveryMCPConnector._detected_errors(rows, alert, incident)

    assert [row["evidence_id"] for row in findings] == ["LOG-payment"]


def test_discovery_routes_metric_alerts_without_unrelated_database_or_ticket_queries() -> None:
    alert = Alert(
        source="prometheus",
        name="CheckoutLatencyHigh",
        service="checkout",
        severity=AlertSeverity.HIGH,
        description="p95 latency is above the service objective",
    )

    selected, reasons = DiscoveryMCPConnector._plan_discovery_tools(alert)

    assert selected == ["telemetry.search"]
    assert reasons == ["metric_or_trace_signal"]


def test_discovery_routes_trace_requirement_to_targeted_trace_query() -> None:
    alert = Alert(
        source="prometheus",
        name="CheckoutLatencyHigh",
        service="checkout",
        severity=AlertSeverity.HIGH,
        description="p95 latency is above the service objective",
        metadata={"context_requirement_category": "traces"},
    )

    selected, reasons = DiscoveryMCPConnector._plan_discovery_tools(alert)

    assert selected == ["traces.search"]
    assert reasons == ["evidence_requirement"]


@pytest.mark.parametrize(
    ("category", "expected_tool"),
    [
        ("topology", "topology.search"),
        ("change", "changes.search"),
        ("deployment", "changes.search"),
        ("runbook", "runbooks.search"),
    ],
)
def test_discovery_routes_operational_requirements_to_dedicated_mcp_tools(
    category: str, expected_tool: str,
) -> None:
    alert = Alert(
        source="prometheus",
        name="CheckoutLatencyHigh",
        service="checkout",
        severity=AlertSeverity.HIGH,
        description="p95 latency is above the service objective",
        metadata={"context_requirement_category": category},
    )

    selected, reasons = DiscoveryMCPConnector._plan_discovery_tools(alert)

    assert selected == [expected_tool]
    assert reasons == ["evidence_requirement"]


def test_discovery_expands_route_for_change_database_and_recurring_signals() -> None:
    alert = Alert(
        source="logs",
        name="MySQL regression after deployment",
        service="orders-mysql",
        severity=AlertSeverity.CRITICAL,
        description="Repeated query timeout after release build 42",
        deduplicated_count=3,
    )

    selected, reasons = DiscoveryMCPConnector._plan_discovery_tools(alert)

    assert selected == [
        "logs.search", "tickets.search", "code.search", "mysql.search",
    ]
    assert set(reasons) >= {
        "log_signal", "failure_diagnostics", "change_correlation",
        "database_diagnostics", "incident_history",
    }


def test_code_review_keeps_only_evidence_linked_unified_diff_patches() -> None:
    evidence = [
        {
            "evidence_id": "CODE-settings",
            "source": "code",
            "uri": "code://app/settings.py#L30",
            "snippet": "29: value = config.get('token')\n30: return value.strip()",
        },
        {"evidence_id": "LOG-error", "source": "log", "uri": "log://app.log#L1", "snippet": "token missing"},
    ]
    report = {
        "code_review": {
            "summary": "One source-grounded issue.",
            "findings": [
                {
                    "title": "Missing null guard",
                    "severity": "high",
                    "explanation": "strip() can be called when token is absent.",
                    "evidence_id": "CODE-settings",
                    "patch": "--- a/app/settings.py\n+++ b/app/settings.py\n@@ -29,2 +29,2 @@\n-value = config.get('token')\n+value = config.get('token') or ''",
                },
                {
                    "title": "Log-only guess",
                    "evidence_id": "LOG-error",
                    "patch": "--- a/unknown.py\n+++ b/unknown.py\n@@ -1 +1 @@\n-bad\n+good",
                },
            ],
        }
    }

    review = DiscoveryMCPConnector._validated_code_review(report, evidence)

    assert review["status"] == "completed"
    assert review["reviewed_evidence_ids"] == ["CODE-settings"]
    assert review["reviewed_sources"] == [
        {
            "evidence_id": "CODE-settings",
            "source_uri": "code://app/settings.py#L30",
            "snippet": "29: value = config.get('token')\n30: return value.strip()",
        }
    ]
    assert len(review["findings"]) == 1
    assert review["findings"][0]["source_uri"] == "code://app/settings.py#L30"
    assert review["findings"][0]["patch"].startswith("--- a/app/settings.py")
    assert review["proposed_changes"][0]["ready_to_apply"] is True
    assert review["proposed_changes"][0]["source_uri"] == "code://app/settings.py#L30"


def test_code_review_does_not_claim_findings_without_code_evidence() -> None:
    review = DiscoveryMCPConnector._validated_code_review(
        {"code_review": {"summary": "Invented", "findings": [{"evidence_id": "LOG-1"}]}},
        [{"evidence_id": "LOG-1", "source": "log", "snippet": "error"}],
    )

    assert review["status"] == "not_performed"
    assert review["findings"] == []
    assert review["proposed_changes"] == []
    assert review["insufficient_context"] is True


def static_router() -> ModelRouter:
    return ModelRouter(
        providers={
            "gpt-5": StaticProvider("gpt-5"),
            "gpt-4o": StaticProvider("gpt-4o"),
            "claude": StaticProvider("claude"),
            "local-llama": StaticProvider("local-llama"),
        }
    )


def test_resolution_agent_extracts_values_from_fenced_json_with_introductory_text() -> None:
    content = """Given the evidence, here is the result:
```json
{"root_cause":"Collector endpoint is unreachable","confidence_score":0.72}
```"""

    parsed = ResolutionIntelligenceAgent._extract_model_text(
        content,
        keys=("root_cause", "summary"),
        fallback_text="fallback",
    )

    assert parsed == "Collector endpoint is unreachable"


def test_resolution_agent_rejects_malformed_structured_output_as_display_text() -> None:
    malformed = '{"observed_impact":{"mysql":{"row count high", "connection refused"}}}'

    parsed = ResolutionIntelligenceAgent._extract_model_text(
        malformed,
        keys=("impact_summary", "service_impact", "severity_rationale"),
        fallback_text="Impact is not established from validated evidence.",
    )

    assert parsed == "Impact is not established from validated evidence."


def test_vector_db_connector_loads_rag_documents(governed_rag_root) -> None:
    connector = VectorDBConnector(rag_root=governed_rag_root)
    connector.reload()

    assert connector.documents
    assert any(doc["kind"] == "runbook" for doc in connector.documents)
    assert any(doc["kind"] == "incident" for doc in connector.documents)
    assert any(doc["kind"] == "dependency" for doc in connector.documents)


@pytest.mark.asyncio
async def test_vector_db_connector_reports_empty_approved_corpus(tmp_path) -> None:
    connector = VectorDBConnector(rag_root=tmp_path)
    alert = Alert(
        tenant_id="tenant-a", name="HighLatency", service="api-gateway",
        severity="critical", source="prometheus", description="Latency exceeded the SLO.",
        starts_at=datetime.now(UTC),
    )
    incident = Incident(tenant_id="tenant-a", service="api-gateway", title="High latency")

    result = await connector.fetch(alert, incident)

    assert result["matches"] == []
    assert result["document_count"] == 0
    assert result["evidence_gap"] == "NO_MATCHING_APPROVED_EVIDENCE"


def test_context_rag_gate_rejects_weak_untagged_history() -> None:
    connector = VectorDBConnector()

    assert connector.context_match_relevant(
        {"services": [], "match_confidence": 0.22, "_metadata_match_score": 0.09},
        "checkout",
    ) is False
    assert connector.context_match_relevant(
        {"services": ["checkout"], "match_confidence": 0.12, "_metadata_match_score": 0.0},
        "checkout",
    ) is True
    assert connector.context_match_relevant(
        {"services": ["payments"], "match_confidence": 0.95, "_metadata_match_score": 0.9},
        "checkout",
    ) is False


@pytest.mark.asyncio
async def test_resolution_does_not_treat_rag_history_as_current_observation() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="CheckoutLatencyHigh",
        service="checkout",
        severity=AlertSeverity.HIGH,
        description="checkout latency is elevated",
    )
    incident = Incident(service="checkout", severity=AlertSeverity.HIGH, title=alert.name)
    context = Context(
        tenant_id=alert.tenant_id,
        incident_id=incident.id,
        alert=alert,
        metadata={
            "context_evidence": {
                "rag": [{
                    "evidence_id": "RAG-HISTORY",
                    "source": "rag",
                    "uri": "rag://history/payments",
                    "snippet": "Deployment 2.5 caused an older payments incident.",
                    "epistemic_role": "historical_knowledge",
                }]
            }
        },
    )

    state = await ResolutionIntelligenceAgent(model_router=static_router()).collect_context({"context": context})

    assert all(row.get("evidence_id") != "RAG-HISTORY" for row in state["gathered_context"]["discovery_evidence"])
    assert state["gathered_context"]["knowledge_evidence_count"] == 1


@pytest.mark.asyncio
async def test_resolution_ingests_current_enrichment_evidence_categories() -> None:
    alert = Alert(
        tenant_id="tenant-a", source="prometheus", name="kaiops-platform-target-down",
        service="kaiops-platform", severity=AlertSeverity.CRITICAL,
        description="Prometheus reports the target as down.",
    )
    incident = Incident(service="kaiops-platform", severity=AlertSeverity.CRITICAL, title=alert.name)
    context = Context(
        tenant_id=alert.tenant_id, incident_id=incident.id, alert=alert,
        metadata={"context_evidence": {
            "metrics": [{
                "evidence_id": "METRIC-DOWN-1", "category": "metrics",
                "connector": "prometheus", "service": "kaiops-platform",
                "source_reference": "prometheus://query?expr=up",
                "content": {"metric_name": "up", "value": 0},
            }],
            "topology": [{
                "evidence_id": "TOPOLOGY-1", "category": "topology",
                "connector": "discovery-mcp", "service": "kaiops-platform",
                "source_reference": "catalog://services/kaiops-platform",
                "content": {"deployment": "api-gateway", "environment": "prod"},
            }],
        }},
    )

    state = await ResolutionIntelligenceAgent(model_router=static_router()).collect_context({"context": context})
    evidence = {row["evidence_id"]: row for row in state["gathered_context"]["discovery_evidence"]}

    assert "METRIC-DOWN-1" in evidence
    assert "TOPOLOGY-1" in evidence
    assert evidence["METRIC-DOWN-1"]["source"] == "metrics"
    assert evidence["METRIC-DOWN-1"]["connector"] == "prometheus"
    assert evidence["METRIC-DOWN-1"]["uri"] == "prometheus://query?expr=up"
    assert '"value": 0' in evidence["METRIC-DOWN-1"]["snippet"]
    assert evidence["METRIC-DOWN-1"]["metadata"]["value"] == 0
    assert evidence["METRIC-DOWN-1"]["metadata"]["metric_name"] == "up"


@pytest.mark.asyncio
async def test_resolution_builds_application_crawl_and_historical_hypotheses() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="CheckoutTimeouts",
        service="checkout",
        severity=AlertSeverity.HIGH,
        description="checkout requests time out after release",
    )
    incident = Incident(service="checkout", severity=AlertSeverity.HIGH, title=alert.name)
    context = Context(
        tenant_id=alert.tenant_id,
        incident_id=incident.id,
        alert=alert,
        related_incidents=[{
            "id": "INC-OLD",
            "title": "Earlier checkout timeout",
            "root_cause": "Connection pool exhaustion after a configuration change",
            "resolution": "Restore the prior pool limit",
            "outcome": "succeeded",
            "similarity": 0.82,
        }],
        recent_changes=[{"id": "CHG-9", "message": "checkout release deployed"}],
        metadata={
            "context_evidence": {
                "logs": [{"evidence_id": "LOG-1", "source": "log", "service": "checkout", "snippet": "pool timeout"}],
                "code": [{"evidence_id": "CODE-1", "source": "code", "service": "checkout", "snippet": "pool_size = 2"}],
                "telemetry": [{"evidence_id": "METRIC-1", "source": "prometheus", "service": "checkout", "snippet": "timeouts=42"}],
                "rag": [{"evidence_id": "RAG-1", "source": "rag", "service": "checkout", "snippet": "reviewed pool runbook"}],
            },
            "discovery_report": {
                "report": {
                    "hypotheses": [{"cause": "Connection pool exhaustion", "confidence": 0.78, "evidence_ids": ["LOG-1"]}],
                    "code_review": {"findings": [{"title": "Small pool", "explanation": "Configured pool size is two", "evidence_id": "CODE-1"}]},
                }
            },
        },
    )
    agent = ResolutionIntelligenceAgent(model_router=static_router())

    state = await agent.collect_context({"context": context})
    state = await agent.plan_investigation(state)
    state = await agent.rank_hypotheses(state)

    report = state["investigation_report"]
    assert report["coverage"]["logs"] == 1
    assert report["coverage"]["code"] == 1
    assert report["coverage"]["telemetry"] >= 1
    assert report["coverage"]["history"] >= 2
    assert report["application_evidence_available"] is True
    assert report["historical_evidence_available"] is True
    assert any(item["source"] == "historical_incident" for item in state["hypothesis_analysis"]["ranked"])


@pytest.mark.asyncio
async def test_context_agent_returns_requested_shape(governed_rag_root) -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PaymentLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="payment latency after deployment",
        labels={"deployment": "payments-api"},
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")

    connectors = ContextIntelligenceAgent().connectors
    connectors[-1] = VectorDBConnector(rag_root=governed_rag_root)
    agent = ContextIntelligenceAgent(connectors=connectors)
    context = await agent.collect(alert, incident)

    assert context.deployment == "payments-api"
    assert context.runbook
    assert context.cmdb.get("dependencies", []) == []
    assert all(str(change.get("id")) != "CHG-1024" for change in context.recent_changes)
    assert context.metadata["rag_documents"] >= 1
    assert any(match["kind"] == "runbook" for match in context.metadata["rag_matches"])
    assert context.metadata["rag_index"]["vector_store"]["provider"] == "local-hybrid-vector-index"
    assert context.metadata["rag_index"]["embedding_model"]["model"] == "hashing-token-counter-v1"
    graph = context.metadata["context_graph"]
    assert graph["enabled"] is True
    assert graph["stages"] == ["validate_event", "collect_connector_evidence", "assemble_context"]
    assert graph["connector_count"] == 9
    assert graph["available_connector_count"] == 9
    assert graph["collection_plan"]["mode"] == "adaptive"
    assert all(
        connector["status"] not in {"failed", "timed_out"}
        for connector in graph["connectors"].values()
    )
    assert graph["degraded"] is False


@pytest.mark.asyncio
async def test_context_agent_persists_multi_source_evidence_manifest() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="TelemetryCollectorUnavailable",
        service="otel-collector",
        severity=AlertSeverity.CRITICAL,
        description="Prometheus cannot scrape collector metrics endpoint",
        labels={"project_name": "Telemetry", "application": "Telemetry"},
    )
    incident = Incident(service="otel-collector", severity=AlertSeverity.CRITICAL, title="collector unavailable")

    context = await ContextIntelligenceAgent().collect(alert, incident)

    assert set(context.metadata["context_sources"]) >= {"logs", "tickets", "code", "telemetry", "database", "rag"}
    assert all(context.metadata["context_sources"][source]["attempted"] is True for source in ("logs", "telemetry", "rag"))
    assert all(context.metadata["context_sources"][source]["attempted"] is False for source in ("tickets", "code", "database"))
    assert all(context.metadata["context_sources"][source]["status"] == "skipped" for source in ("tickets", "code", "database"))
    assert context.metadata["context_sources"]["rag"]["result_count"] == len(context.metadata["rag_matches"])
    assert set(context.metadata["context_evidence"]) >= {"logs", "tickets", "code", "rag"}
    assert all(
        row.get("epistemic_role") == "historical_knowledge" and row.get("current_observation") is False
        for row in context.metadata["context_evidence"]["rag"]
    )


@pytest.mark.asyncio
async def test_resolution_agent_generates_recommendation(governed_rag_root) -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PaymentLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="payment latency after deployment",
        labels={"deployment": "payments-api"},
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    connectors = ContextIntelligenceAgent().connectors
    connectors[-1] = VectorDBConnector(rag_root=governed_rag_root)
    agent = ContextIntelligenceAgent(connectors=connectors)
    context = await agent.collect(alert, incident)

    recommendation = await ResolutionIntelligenceAgent(model_router=static_router()).resolve(context)

    assert "deployment payments-api" in recommendation.root_cause
    assert "confirm the rollout diff" in recommendation.root_cause
    assert 0.5 <= recommendation.confidence < 0.9
    assert "evidence" in recommendation.rationale.lower()
    assert "No direct customer or service impact is established" in recommendation.impact
    assert recommendation.metadata["impact_analysis"]["observed_impact"] == ""
    assert recommendation.recommended_action == "Rollback deployment"


@pytest.mark.asyncio
async def test_rca_status_is_not_grounded_on_citation_alone_without_a_conclusive_investigation() -> None:
    """Regression for finding #13: `rca_status` used to be set to "grounded"
    purely because the model cited at least one evidence id
    (`bool(accepted_evidence_ids)`), with zero connection to the real
    IterativeInvestigator verdict. That let incidents whose own root-cause
    text said "Investigation inconclusive: the leading hypothesis reached 3%
    confidence..." still persist `binding.status = "grounded"` - misleading
    every reader of that field (the Triage queue, the lifecycle stepper,
    get_processed_result_by_alert_id's `grounded` boolean) even though the
    real execution gate (_investigation_readiness_blocks) was never fooled.
    This incident has real cited evidence (StaticProvider always cites the
    real discovery evidence ids) but no conclusive iterative investigation
    at all - `rca_status` must now say "insufficient_evidence", not
    "grounded"."""
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PaymentLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="payment latency after deployment",
        labels={"deployment": "payments-api"},
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)

    recommendation = await ResolutionIntelligenceAgent(model_router=static_router()).resolve(context)

    assert recommendation.metadata["evidence_ids"]  # real evidence was cited
    assert recommendation.metadata["rca_status"] == "insufficient_evidence"


@pytest.mark.asyncio
async def test_rca_status_is_grounded_only_once_the_real_investigation_is_genuinely_conclusive() -> None:
    """Positive counterpart: once the same incident's iterative investigation
    has genuinely reached conclusive/confirmed status, `rca_status` correctly
    reports "grounded" - the fix does not simply make every incident say
    "insufficient_evidence" forever, it makes the label track the real
    verdict in both directions."""
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PaymentLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="payment latency after deployment",
        labels={"deployment": "payments-api"},
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)
    context.metadata["iterative_investigation"] = {
        "conclusive": True,
        "status": "conclusive",
        "conclusion": {"confidence": 0.71, "evidence_ids": []},
    }

    recommendation = await ResolutionIntelligenceAgent(model_router=static_router()).resolve(context)

    assert recommendation.metadata["evidence_ids"]
    assert recommendation.metadata["rca_status"] == "grounded"


@pytest.mark.asyncio
async def test_resolution_agent_blocks_high_confidence_when_discovery_is_degraded() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PaymentLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="payment latency after deployment",
        labels={"deployment": "payments-api"},
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)
    context.metadata["context_quality"] = {
        "quality_score": 0.92,
        "discovery_degraded": True,
        "execution_ready": False,
    }

    recommendation = await ResolutionIntelligenceAgent(model_router=static_router()).resolve(context)

    rca = recommendation.metadata["rca_analysis"]
    plan = recommendation.metadata["execution_plan"]
    assert rca["confidence_score"] <= 0.49
    assert rca["context_degraded"] is True
    assert "discovery_evidence" in rca["missing_evidence"]
    assert plan["execution_ready"] is False
    assert any("Discovery evidence is degraded" in reason for reason in plan["readiness_blocks"])


@pytest.mark.asyncio
async def test_resolution_agent_propagates_readiness_and_blocks_mutation_when_rca_is_not_ready() -> None:
    alert = Alert(
        tenant_id="tenant-a", source="prometheus", name="PaymentLatencyHigh",
        service="payments", severity=AlertSeverity.CRITICAL,
        description="payment latency after deployment", labels={"deployment": "payments-api"},
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)
    context.metadata["context_quality"].update({
        "source_coverage_score": 0.375,
        "rca_readiness_score": 0.46,
        "rca_ready": False,
        "impact_readiness_score": 0.41,
        "impact_ready": False,
    })

    recommendation = await ResolutionIntelligenceAgent(model_router=static_router()).resolve(context)

    rca = recommendation.metadata["rca_analysis"]
    impact = recommendation.metadata["impact_analysis"]
    plan = recommendation.metadata["execution_plan"]
    assert rca["context_readiness"] == {"score": 0.46, "ready": False, "source_coverage": 0.375}
    assert impact["context_readiness"] == {"score": 0.41, "ready": False}
    assert impact["confidence_score"] <= 0.49
    assert recommendation.impact.startswith("No direct customer or service impact is established")
    assert impact["observed_impact"] == ""
    assert plan["execution_ready"] is False
    assert any("46% RCA-ready" in reason for reason in plan["readiness_blocks"])


@pytest.mark.asyncio
async def test_resolution_agent_uses_severity_heuristic_risk_when_model_omits_risk_level() -> None:
    """Default (deterministic fast-path) behavior must be unchanged: the fix step never
    returns a risk_level, so recommendation.risk keeps falling back to the severity-only
    heuristic exactly as before this change."""
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PaymentLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="payment latency after deployment",
        labels={"deployment": "payments-api"},
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)

    recommendation = await ResolutionIntelligenceAgent(model_router=static_router()).resolve(context)

    assert recommendation.risk == "high"


@pytest.mark.asyncio
async def test_resolution_agent_prefers_model_risk_level_over_severity_heuristic() -> None:
    class RiskAwareGateway:
        async def generate(self, request) -> dict:
            if request.task == "fix":
                content = {
                    "recommended_action": "Restart the affected pod",
                    "risk_level": "low",
                    "validation_queries": ["kubectl rollout status deployment/checkout -n prod"],
                    "rollback_plan": "kubectl rollout undo deployment/checkout -n prod",
                    "confidence_score": 0.8,
                }
            else:
                content = {"root_cause": "Pod crash loop", "confidence_score": 0.8, "evidence_used": []}
            return {
                "model": "test-model",
                "content": json.dumps(content),
                "usage": {"provider": "test", "model": "test-model", "task": request.task},
            }

    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PodCrashLoop",
        service="checkout",
        # CRITICAL severity would normally force risk="high" via the old heuristic --
        # proves the model's risk_level ("low") genuinely overrides it, not just falls
        # back to matching the same value by coincidence.
        severity=AlertSeverity.CRITICAL,
        description="pod crashloop",
    )
    incident = Incident(service="checkout", severity=AlertSeverity.CRITICAL, title="pod crash")
    context = await ContextIntelligenceAgent().collect(alert, incident)

    agent = ResolutionIntelligenceAgent(model_gateway=RiskAwareGateway())
    agent.deep_analysis_enabled = True
    recommendation = await agent.resolve(context)

    assert recommendation.risk == "low"
    assert 0.0 < recommendation.confidence < 0.5
    assert recommendation.metadata["rca_status"] == "insufficient_evidence"
    assert recommendation.metadata["execution_plan"]["execution_ready"] is False
    assert await agent.validate(recommendation) is True


@pytest.mark.asyncio
async def test_resolution_agent_ignores_unrecognized_model_risk_level() -> None:
    class BadRiskGateway:
        async def generate(self, request) -> dict:
            if request.task == "fix":
                content = {"recommended_action": "Restart the affected pod", "risk_level": "not-a-real-risk-tier"}
            else:
                content = {"root_cause": "Pod crash loop", "confidence_score": 0.8, "evidence_used": []}
            return {
                "model": "test-model",
                "content": json.dumps(content),
                "usage": {"provider": "test", "model": "test-model", "task": request.task},
            }

    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus", name="PodCrashLoop", service="checkout",
        severity=AlertSeverity.CRITICAL, description="pod crashloop",
    )
    incident = Incident(service="checkout", severity=AlertSeverity.CRITICAL, title="pod crash")
    context = await ContextIntelligenceAgent().collect(alert, incident)

    agent = ResolutionIntelligenceAgent(model_gateway=BadRiskGateway())
    agent.deep_analysis_enabled = True
    recommendation = await agent.resolve(context)

    assert recommendation.risk == "high"


@pytest.mark.asyncio
async def test_resolution_agent_adds_validation_and_rollback_without_changing_commands() -> None:
    """Default (deterministic) fast path: validation_queries/rollback_plan must now be
    populated, while `commands` -- which remediation-engine reads directly to execute --
    must be byte-for-byte identical to before this change. Calls the heuristic directly
    (rather than through the full resolve() pipeline) so the test isn't at the mercy of
    what a mocked model echoes back as root_cause text."""
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PodCrashLoop",
        service="checkout",
        severity=AlertSeverity.HIGH,
        description="pod crashloop detected",
    )
    incident = Incident(service="checkout", severity=AlertSeverity.HIGH, title="checkout pod crash loop")
    context = await ContextIntelligenceAgent().collect(alert, incident)

    agent = ResolutionIntelligenceAgent(model_router=static_router())
    action, commands, target, validation_queries, rollback_plan = agent._infer_action_and_commands(
        context, root_cause="pod crashloop detected", model_action=""
    )

    assert action == "Restart pod"
    assert commands == ["kubectl rollout restart deployment/checkout -n prod"]
    assert validation_queries == [
        "kubectl rollout status deployment/checkout -n prod --timeout=180s",
        "kubectl get pods -n prod | findstr checkout",
    ]
    assert "kubectl rollout undo deployment/checkout -n prod" in rollback_plan


@pytest.mark.asyncio
async def test_resolution_agent_clamps_all_model_fallback_confidence() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="KaiOpsServiceDown",
        service="kaiops-platform",
        severity=AlertSeverity.CRITICAL,
        description="KaiOps platform service is not reachable by Prometheus for more than 1 minute.",
    )
    incident = Incident(service="kaiops-platform", severity=AlertSeverity.CRITICAL, title="kaiops service down")
    context = await ContextIntelligenceAgent().collect(alert, incident)

    recommendation = await ResolutionIntelligenceAgent(model_gateway=FallbackGateway()).resolve(context)

    assert recommendation.confidence <= 0.49
    assert not recommendation.root_cause.startswith("{")
    assert recommendation.metadata["fallback_used"] is True
    assert recommendation.metadata["quality_gate"]["requires_human_review"] is True
    assert recommendation.metadata["quality_gate"]["trusted_for_auto_execution"] is False


@pytest.mark.asyncio
async def test_resolution_agent_grounds_mysql_exporter_privilege_rca_in_raw_alert() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="logs",
        name="[WARNING] mysql-exporter: Error from scraper",
        service="mysql-exporter",
        severity=AlertSeverity.HIGH,
        description=(
            'level=ERROR msg="Error from scraper" scraper=slave_status target=mysql:3306 '
            'err="Error 1227 (42000): Access denied; you need (at least one of) the SUPER, '
            'REPLICATION CLIENT privilege(s) for this operation"'
        ),
        labels={
            "source_event_id": "mysql-exporter-log-1",
            "log_source_path": "opensearch://otel-*/mysql-exporter-log-1",
        },
    )
    incident = Incident(service="mysql-exporter", severity=AlertSeverity.HIGH, title="exporter scrape failure")
    context = Context(
        tenant_id=alert.tenant_id,
        incident_id=incident.id,
        alert=alert,
        metadata={
            "discovery_report": {
                "report": {
                    "external_knowledge_eligible": True,
                    "external_knowledge_used": True,
                    "external_tools_used": ["external.search"],
                },
                "evidence": [],
            }
        },
    )

    recommendation = await ResolutionIntelligenceAgent(model_gateway=FallbackGateway()).resolve(context)

    assert "lacks the REPLICATION CLIENT privilege" in recommendation.root_cause
    assert "loss of replication-health visibility" in recommendation.impact
    assert recommendation.recommended_action.startswith("Verify the exporter account")
    assert "alert:mysql-exporter-log-1" in recommendation.metadata["rca_analysis"]["evidence_used"]
    assert "opensearch://otel-*/mysql-exporter-log-1" in recommendation.metadata["citations"]
    assert recommendation.metadata["external_knowledge_used"] is True
    assert recommendation.metadata["external_tools_used"] == ["external.search"]


@pytest.mark.asyncio
async def test_resolution_agent_runtime_persists_reflection_memory() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PaymentLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="payment latency after deployment",
        labels={"deployment": "payments-api"},
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)
    memory = InMemoryStore()

    recommendation = await ResolutionIntelligenceAgent(model_router=static_router(), memory_store=memory).resolve_with_runtime(context)

    assert recommendation.metadata.get("runtime", {}).get("status") == "succeeded"
    assert recommendation.metadata.get("runtime", {}).get("reflection", {}).get("agent") == "resolution-agent"
    entries = await memory.recent("incident-memory", limit=5)
    assert entries
    assert entries[-1]["incident_id"] == str(context.incident_id)
