from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from time import monotonic
from typing import Any, Awaitable, Callable
from uuid import uuid4

import httpx

from ai_workbench_common.models import Context
from common.change_intelligence import ChangeCorrelationContext, ChangeEvent, rank_correlated_changes
from common.evidence_graph import build_incident_evidence_graph
from resolution_agent.contracts import (
    ClaimKind,
    ClaimStatus,
    EvidenceBoundClaim,
    Hypothesis as HypothesisContract,
    HypothesisStatus,
    InvestigationPlan,
    InvestigationToolCall,
    RCAResult,
    ResolutionOutcome,
)
from resolution_agent.evidence import EvidenceCompiler, EvidenceRecord, source_metadata
from resolution_agent.confidence import ConfidenceInputs, score_confidence
from resolution_agent.metrics import (
    EVIDENCE_COUNT,
    HYPOTHESIS_COUNT,
    INCONCLUSIVE_TOTAL,
    INVESTIGATION_DURATION,
    RESOLUTION_CONFIDENCE,
)


class InvestigationStatus(StrEnum):
    RUNNING = "running"
    CONCLUSIVE = "conclusive"
    INCONCLUSIVE = "inconclusive"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TOOL_FAILURE = "tool_failure"


PersistEvent = Callable[[str, dict[str, Any]], Awaitable[None]]


class ReadOnlyDiscoveryClient:
    ALLOWED_TOOLS = frozenset({
        "logs.search", "code.search", "telemetry.search", "traces.search", "topology.search",
        "dependency-health.search", "resource-health.search", "changes.search", "runbooks.search",
        "tickets.search", "mysql.search",
    })

    def __init__(self) -> None:
        self.url = os.getenv("DISCOVERY_MCP_URL", "http://discovery-mcp:8000/mcp")
        self.timeout_seconds = max(2.0, min(float(os.getenv("RESOLUTION_INVESTIGATION_TOOL_TIMEOUT_SECONDS", "15")), 45.0))

    async def call(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool_name not in self.ALLOWED_TOOLS:
            raise ValueError(f"investigation tool is not read-only or allow-listed: {tool_name}")
        request = {
            "jsonrpc": "2.0",
            "id": str(uuid4()),
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        async with httpx.AsyncClient(timeout=self.timeout_seconds, trust_env=False) as client:
            response = await client.post(self.url, json=request)
            response.raise_for_status()
            payload = response.json()
        if isinstance(payload.get("error"), dict):
            raise RuntimeError(str(payload["error"].get("message") or "discovery tool failed"))
        result = payload.get("result")
        if not isinstance(result, dict):
            return {}
        # KaiMS Discovery MCP returns the tool payload directly. Also accept the
        # standard MCP content envelope so a compliant remote server does not
        # silently produce zero evidence.
        if isinstance(result.get("evidence"), list):
            return result
        content = result.get("content")
        if isinstance(content, list):
            for item in content:
                if not isinstance(item, dict) or item.get("type") != "text":
                    continue
                try:
                    decoded = json.loads(str(item.get("text") or ""))
                except (TypeError, ValueError):
                    continue
                if isinstance(decoded, dict):
                    return decoded
        return result


class IterativeInvestigator:
    SOURCE_TOOL = {
        "logs": "logs.search",
        "code": "code.search",
        "telemetry": "telemetry.search",
        "traces": "traces.search",
        "topology": "topology.search",
        "dependency": "dependency-health.search",
        "resource": "resource-health.search",
        "changes": "changes.search",
        "runbooks": "runbooks.search",
        "history": "tickets.search",
        "data": "mysql.search",
    }
    SOURCE_ALIASES = {
        "log": "logs", "logs": "logs", "opensearch": "logs", "elasticsearch": "logs",
        "code": "code", "source": "code", "github": "code", "gitlab": "code",
        "prometheus": "telemetry", "metric": "telemetry", "metrics": "telemetry", "telemetry": "telemetry",
        "trace": "traces", "traces": "traces", "jaeger": "traces",
        "topology": "topology", "dependency": "dependency", "dependencies": "dependency",
        "resource": "resource",
        "change": "changes", "changes": "changes", "deployment": "changes",
        "runbook": "runbooks", "runbooks": "runbooks",
        "ticket": "history", "tickets": "history", "incident": "history", "rag": "history",
        "mysql": "data", "database": "data",
    }

    @staticmethod
    def _human_evidence_summary(value: Any) -> str:
        """Render structured evidence as a concise observation, never raw JSON."""
        parsed = value
        if isinstance(value, str):
            text = value.strip()
            if text.startswith(("{", "[")):
                try:
                    parsed = json.loads(text)
                except (TypeError, ValueError):
                    # Canonical evidence deliberately bounds large connector
                    # payloads.  Preserve the useful observation when a JSON
                    # metric response was truncated after its query/series.
                    query_match = re.search(r'\\?"query\\?"\s*:\s*\\?"([^"\\]*(?:\\.[^"\\]*)*)', text)
                    if query_match and "series" in text:
                        query = query_match.group(1).replace('\\"', '"').replace('\\\\', '\\')
                        return f"Prometheus observed matching time series for query: {query[:320]}"
                    return text[:500]
            else:
                return text[:500]
        if isinstance(parsed, list):
            return IterativeInvestigator._human_evidence_summary(parsed[0]) if parsed else "Evidence source returned no records."
        if not isinstance(parsed, dict):
            return str(parsed or "").strip()[:500]
        for key in ("summary", "message", "description", "observation", "finding"):
            candidate = parsed.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()[:500]
        query = str(parsed.get("query") or "").strip()
        series = parsed.get("series")
        if query and isinstance(series, list):
            return f"Prometheus returned {len(series)} time series for query: {query[:320]}"
        provenance = parsed.get("provenance") if isinstance(parsed.get("provenance"), dict) else {}
        source = str(provenance.get("source") or parsed.get("source") or "Connector").strip()
        status = str(parsed.get("source_status") or parsed.get("status") or "recorded").replace("_", " ")
        return f"{source} evidence was {status}; inspect the cited evidence record for structured details."

    def __init__(self, client: ReadOnlyDiscoveryClient | None = None) -> None:
        self.client = client or ReadOnlyDiscoveryClient()
        self.evidence_compiler = EvidenceCompiler()
        self.max_steps = max(1, min(int(os.getenv("RESOLUTION_INVESTIGATION_MAX_STEPS", "8")), 12))
        # Reproduced live: 47% of recent investigations (142 of the last 300)
        # stopped after an average of 1.5 steps with evidence_count pinned at
        # the old default of 40 - the alert's own pre-existing context
        # (code/logs/traces) alone routinely fills most of that budget before
        # the investigation's own targeted category queries (telemetry, data,
        # topology, changes, dependency, history, runbooks) ever run more
        # than once, permanently starving 6+ required evidence categories on
        # nearly half of all investigations. Raised the default and the
        # ceiling so a full pass over every required category actually fits.
        self.max_evidence = max(8, min(int(os.getenv("RESOLUTION_INVESTIGATION_MAX_EVIDENCE", "150")), 300))
        self.max_tool_calls = max(1, min(int(os.getenv("RESOLUTION_INVESTIGATION_MAX_TOOL_CALLS", "12")), 100))
        self.max_duration_seconds = max(5, min(int(os.getenv("RESOLUTION_INVESTIGATION_MAX_DURATION_SECONDS", "120")), 3600))
        self.max_cost_usd = max(0.0, min(float(os.getenv("RESOLUTION_INVESTIGATION_MAX_COST_USD", "0.25")), 1000.0))
        self.conclusive_threshold = max(0.6, min(float(os.getenv("RESOLUTION_INVESTIGATION_CONCLUSIVE_THRESHOLD", "0.65")), 0.98))
        # How many independently-sourced evidence records must corroborate a
        # hypothesis before it can be marked "confirmed" (a single source
        # meeting the confidence bar can still be a coincidence). Defaulted to
        # 2 for the same reason the confidence bar exists - operator judgment
        # decided this can be relaxed to 1 where evidence is thin but the
        # confidence bar is still met; never below 1, since an uncorroborated
        # hypothesis with zero sources should never be "confirmed" outright.
        self.minimum_independent_sources = max(1, min(int(os.getenv("RESOLUTION_INVESTIGATION_MIN_SOURCES", "2")), 5))

    def plan(self, context: Context, *, investigation_id: str) -> InvestigationPlan:
        required = sorted(self._required_sources(context))
        service = context.alert.service
        questions = [
            f"What changed immediately before {service} became unhealthy?",
            f"Which direct evidence proves or disproves failure inside {service}?",
            f"Is a dependency, data store, or infrastructure resource causing the symptom in {service}?",
            "Which resources and dependent services are inside the blast radius?",
            "Is there an independently corroborated causal chain rather than a temporal coincidence?",
        ]
        text = " ".join((context.alert.name, context.alert.description)).lower()
        if any(token in text for token in ("deploy", "release", "exception", "traceback")):
            questions.insert(0, "Did the failure begin after a deployment, and is only the new version affected?")
        if any(token in text for token in ("database", "mysql", "query", "pool", "replica")):
            questions.insert(0, "Do database saturation or data-path diagnostics align with the application failure window?")
        calls = [
            InvestigationToolCall(
                tool_name=self.SOURCE_TOOL[source],
                objective=f"Collect {source} evidence that can support or falsify a hypothesis.",
                source_type=source,
                arguments={"service": service},
            )
            for source in required
        ]
        return InvestigationPlan(
            investigation_id=investigation_id,
            incident_id=context.incident_id,
            correlation_id=str(context.trace_id or context.incident_id),
            objectives=[
                "Identify a falsifiable causal explanation grounded in incident-window evidence.",
                "Disprove plausible competing hypotheses before recommending remediation.",
                "Return an explicit non-conclusive outcome when proof is insufficient.",
            ],
            questions_to_answer=questions,
            required_evidence=required,
            recommended_tool_calls=calls,
            investigation_priority=required,
            stop_conditions=[
                f"confidence >= {self.conclusive_threshold:.2f} with "
                f"{self.minimum_independent_sources} independent evidence source"
                f"{'s' if self.minimum_independent_sources != 1 else ''}",
                "required evidence remains unavailable",
                "contradictory evidence cannot be resolved",
                "tool-call, duration, cost, or step budget is exhausted",
                "policy prevents further read access",
            ],
            max_steps=self.max_steps,
            max_tool_calls=self.max_tool_calls,
            max_duration_seconds=self.max_duration_seconds,
            max_cost_usd=self.max_cost_usd,
            minimum_confidence=self.conclusive_threshold,
        )

    def _compile_evidence(self, context: Context, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        compiled: list[dict[str, Any]] = []
        raw_rows: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            # Investigation loops merge immutable compiled records with newly
            # retrieved rows. Recompiling an EvidenceRecord nests metadata and
            # loses structured diagnostics/citation identity on every step.
            try:
                if {
                    "evidence_id", "source_type", "source_uri", "observed_at",
                    "collected_at", "content_hash", "lineage_id", "metadata",
                } <= row.keys():
                    record = EvidenceRecord.model_validate(row)
                    compiled.append(record.model_copy(
                        update={"metadata": source_metadata(record.metadata)},
                    ).model_dump(mode="json"))
                    continue
            except ValueError:
                pass
            raw_rows.append(row)
        alert_started_at = context.alert.starts_at or context.alert.created_at
        if alert_started_at.tzinfo is None:
            alert_started_at = alert_started_at.replace(tzinfo=UTC)
        # Match the read-only investigation query envelope. Causal activity
        # immediately preceding a threshold crossing is part of the incident
        # observation window, not stale or unrelated evidence.
        observation_window_start = alert_started_at - timedelta(minutes=5)
        compiled.extend(
            record.model_dump(mode="json")
            for record in self.evidence_compiler.compile(
                raw_rows,
                tenant_id=context.tenant_id,
                incident_id=context.incident_id,
                service=context.alert.service,
                environment=context.alert.environment,
                incident_started_at=observation_window_start,
                incident_ended_at=alert_started_at + timedelta(minutes=15),
            )
        )
        unique: dict[str, dict[str, Any]] = {}
        for row in compiled:
            unique[str(row.get("evidence_id") or row.get("source_uri"))] = row
        return list(unique.values())

    @staticmethod
    def _tokens(value: Any) -> set[str]:
        ignored = {"after", "before", "service", "error", "failed", "failure", "issue", "alert", "prod", "production"}
        return {
            token for token in re.findall(r"[a-z0-9_.-]{3,}", str(value or "").lower())
            if token not in ignored
        }

    @classmethod
    def _source(cls, row: dict[str, Any]) -> str:
        return cls.SOURCE_ALIASES.get(
            str(row.get("source") or row.get("source_type") or "").strip().lower(), "alert"
        )

    @staticmethod
    def _current_operational(row: dict[str, Any]) -> bool:
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        return bool(row.get("current_operational_evidence", metadata.get("current_operational_evidence", True)))

    @classmethod
    def _operational_for_support(cls, row: dict[str, Any]) -> bool:
        """Historical causality needs incident-window observations.

        Pre-window changes may seed timing hypotheses, but a later runtime
        health/resource snapshot cannot prove or disprove an earlier cause.
        Current health remains available separately for recovery validation.
        """
        return cls._current_operational(row) or (
            cls._source(row) == "changes" and row.get("incident_window_relation") == "before"
        )

    @staticmethod
    def _incident_window_aligned(row: dict[str, Any]) -> bool:
        return (
            row.get("incident_window_relation") == "during"
            and IterativeInvestigator._current_operational(row)
        )

    @staticmethod
    def _is_unrendered_template(text: str) -> bool:
        """True for text that is still template markup, not an observation.

        Reproduced live: a "changes" evidence row surfaced a diff touching an
        alerting-rule config file, and its `description:` field - a Prometheus
        annotation template like 'Service {{ $labels.job }} is not reachable'
        - was picked up verbatim as a "candidate causal change" and shown to an
        operator as the root cause, with the placeholder never substituted and
        zero actual evidence behind it. `{{ ... }}` (Go/Jinja template
        delimiters) is a cheap, reliable signal that text is unrendered
        configuration source, not a description of anything that was observed.
        """
        return "{{" in text and "}}" in text

    @classmethod
    def _leading_diagnostic_candidate(cls, evidence: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Pick the fallback diagnostic claim by causal relevance, not by
        which evidence tool happened to return it first.

        A change or deployment shortly before the incident window is the
        strongest heuristic causal signal available without a model --
        "what changed right before this started" -- so it ranks ahead of a
        merely-concurrent operational signal, which in turn ranks ahead of a
        static code reference with no timing signal at all (previously the
        only kind of evidence this fallback could land on, since discovery
        order has no relationship to relevance). Scoped to exactly the
        sources this fallback has always drawn from (logs/code/telemetry/data)
        plus "changes": widening it further to "dependency" evidence collides
        with the separate mechanism-hypothesis text that already reasons
        about dependencies explicitly (see test_missing_optional_sources_do_
        not_cap_independently_corroborated_mechanism), which is a distinct,
        already-covered code path.

        `_current_operational` excludes anything timestamped before the
        incident window by design (it means "describes the symptom as it is
        happening now"), which is correct for logs/telemetry but would also
        exclude exactly the change precursor this ranking exists to surface --
        a deploy is definitionally timestamped before the incident it causes.
        "changes" evidence is allowed through on a "before" relation as an
        explicit, narrow exception; every other source still requires the
        normal operational-currency gate.
        """
        def inventory_only(row):
            if cls._source(row) != "changes":
                return False
            try:
                item = json.loads(str(row.get("snippet") or row.get("summary") or ""))
            except (ValueError, TypeError):
                return False
            return (isinstance(item, dict) and "status" in item and "created_at" in item
                    and set(item).issubset({"project", "service", "created_at", "status"}))

        source_rank = {"changes": 0, "logs": 1, "telemetry": 1, "data": 2, "code": 3}
        candidates = [
            row for row in evidence
            if cls._source(row) in source_rank
            and str(row.get("snippet") or row.get("summary") or "").strip()
            and not cls._is_unrendered_template(str(row.get("snippet") or row.get("summary") or ""))
            and cls._operational_for_support(row)
            and not inventory_only(row)
        ]
        if not candidates:
            return None

        def priority(row: dict[str, Any]) -> tuple[int, int]:
            source = cls._source(row)
            relation = row.get("incident_window_relation")
            timing_rank = 0 if relation == "during" or (source == "changes" and relation == "before") else 1
            return (source_rank[source], timing_rank)

        return min(candidates, key=priority)

    @classmethod
    def _structured_mechanism_support(cls, hypothesis: dict[str, Any], row: dict[str, Any]) -> bool:
        """Admit structured diagnostics as support without treating symptom words as causation."""
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        if hypothesis.get("mechanism") == "runtime_stopped":
            target = hypothesis.get("target_service")
            if row.get("source_type") == "topology":
                runtime = metadata.get("runtime_lifecycle") or {}
                return (metadata.get("service") == target
                        and metadata.get("runtime_state") in {"exited", "dead"}
                        and runtime.get("Running") is False
                        and runtime.get("FinishedAt") == hypothesis.get("stopped_at"))
            if cls._source(row) == "telemetry":
                metric = metadata.get("metric") or {}
                samples = metadata.get("values") or ([metadata["value"]] if metadata.get("value") else [])
                try:
                    stopped = datetime.fromisoformat(hypothesis["stopped_at"].replace("Z", "+00:00"))
                    return (metric.get("__name__") == "probe_success" and metric.get("service") == target
                            and bool(samples) and float(samples[-1][1]) == 0
                            and float(samples[-1][0]) >= stopped.timestamp())
                except (ValueError, TypeError, KeyError, IndexError):
                    return False
            return False
        claim = str(hypothesis.get("claim") or "").lower()
        if row.get("source_type") == "dependency" and (
            "dependency" in claim or "upstream" in claim or "downstream" in claim
        ):
            target = str(metadata.get("service") or row.get("service") or "").lower()
            related_to = str(metadata.get("related_to") or "").lower()
            return (
                metadata.get("healthy") is False
                and bool(target) and bool(related_to)
                and target != related_to
                and str(metadata.get("runtime_state") or "").lower() != "running"
            )
        if row.get("source_type") == "resource" and any(
            token in claim for token in ("resource saturation", "data-path", "data path")
        ):
            # A direct cgroup read (resource-health.search) genuinely tests
            # this claim's own alerting service, unlike "dependency" -- no
            # related_to/self-check distinction is needed here.
            return metadata.get("saturated") is True
        if row.get("source_type") != "trace":
            return False
        spans = metadata.get("slowest_spans") if isinstance(metadata.get("slowest_spans"), list) else []
        edges = metadata.get("dependency_edges") if isinstance(metadata.get("dependency_edges"), list) else []
        if "dependency" in claim or "upstream" in claim or "downstream" in claim:
            if "connection timeout" in claim:
                return any(
                    isinstance(span, dict)
                    and (span.get("tags") or {}).get("span.kind") == "client"
                    and any(str(kind).rsplit(".", 1)[-1] == "ConnectTimeout"
                            for kind in span.get("exception_types", []))
                    for span in spans
                )
            downstream = {
                str(edge.get("downstream") or "").lower()
                for edge in edges if isinstance(edge, dict)
                and edge.get("upstream") and edge.get("downstream")
                and edge["upstream"] != edge["downstream"]
            }
            return any(
                float(span.get("duration_ms") or 0) >= 500
                and str(span.get("service") or "").lower() in downstream
                for span in spans if isinstance(span, dict)
            )
        if any(token in claim for token in ("resource", "data-path", "database", "mysql", "query")):
            return any(
                isinstance(span, dict)
                and float(span.get("duration_ms") or 0) >= 250
                and isinstance(span.get("tags"), dict)
                and bool(span["tags"].get("db.system") or span["tags"].get("db.operation"))
                for span in spans
            )
        return False

    @staticmethod
    def _structured_mechanism_contradiction(hypothesis: dict[str, Any], row: dict[str, Any]) -> bool:
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        if hypothesis.get("mechanism") == "runtime_stopped" and row.get("source_type") == "topology":
            return (metadata.get("service") == hypothesis.get("target_service")
                    and metadata.get("runtime_state") == "running")
        claim = str(hypothesis.get("claim") or "").lower()
        if row.get("source_type") == "resource" and any(
            token in claim for token in ("resource saturation", "data-path", "data path")
        ):
            # Normal CPU/memory does not rule out a database/data-path wait.
            return (metadata.get("saturated") is False
                    and not any(token in claim for token in ("data-path", "data path", "database", "query")))
        if row.get("source_type") != "dependency" or not any(
            token in claim for token in ("dependency", "upstream", "downstream")
        ):
            return False
        target = str(metadata.get("service") or row.get("service") or "").lower()
        related_to = str(metadata.get("related_to") or "").lower()
        # Container availability is not evidence of dependency performance.
        return (metadata.get("healthy") is True and metadata.get("health_scope") == "performance"
                and bool(target) and bool(related_to) and target != related_to)

    @staticmethod
    def _initial_evidence(context: Context) -> list[dict[str, Any]]:
        metadata = context.metadata if isinstance(context.metadata, dict) else {}
        buckets = metadata.get("context_evidence") if isinstance(metadata.get("context_evidence"), dict) else {}
        discovery = metadata.get("discovery_report") if isinstance(metadata.get("discovery_report"), dict) else {}
        rows: list[dict[str, Any]] = []
        for category, values in buckets.items():
            if isinstance(values, list):
                rows.extend({"category": category, **item} for item in values if isinstance(item, dict))
        if isinstance(discovery.get("evidence"), list):
            rows.extend(item for item in discovery["evidence"] if isinstance(item, dict))
        unique: dict[str, dict[str, Any]] = {}
        for index, row in enumerate(rows):
            key = str(row.get("evidence_id") or row.get("uri") or f"existing:{index}")
            unique[key] = row
        return list(unique.values())

    @staticmethod
    def _initial_hypotheses(context: Context) -> list[dict[str, Any]]:
        metadata = context.metadata if isinstance(context.metadata, dict) else {}
        discovery = metadata.get("discovery_report") if isinstance(metadata.get("discovery_report"), dict) else {}
        report = discovery.get("report") if isinstance(discovery.get("report"), dict) else {}
        candidates = report.get("hypotheses") if isinstance(report.get("hypotheses"), list) else []
        hypotheses: list[dict[str, Any]] = []
        for item in candidates:
            if not isinstance(item, dict):
                continue
            claim = str(item.get("claim") or item.get("cause") or item.get("summary") or "").strip()
            if not claim:
                continue
            hypotheses.append({
                "hypothesis_id": str(uuid4()),
                "claim": claim[:1000],
                "status": "viable",
                "confidence": max(0.05, min(float(item.get("confidence") or 0.35), 0.75)),
                "supporting_evidence_ids": list(item.get("evidence_ids") or item.get("evidence_used") or []),
                "contradicting_evidence_ids": [],
                "affected_resource_ids": list(item.get("affected_resource_ids") or []),
                "causal_sequence": list(item.get("causal_sequence") or []),
                "confidence_components": dict(item.get("confidence_components") or {}),
                "falsification_check": item.get("falsification_check") or item.get("falsification_query") or item.get("next_check") or {},
                "next_evidence_requests": list(item.get("next_evidence_requests") or []),
                "source": "context",
            })
        return hypotheses[:8]

    @staticmethod
    def _claim_id(kind: ClaimKind, statement: str) -> str:
        digest = hashlib.sha256(f"{kind.value}:{statement.strip().casefold()}".encode()).hexdigest()[:20]
        return f"claim-{kind.value.lower()}-{digest}"

    @classmethod
    def _build_claims(
        cls, *, leading: dict[str, Any] | None, outcome: ResolutionOutcome,
        context: Context, evidence: list[dict[str, Any]],
    ) -> list[EvidenceBoundClaim]:
        claims: list[EvidenceBoundClaim] = []
        # A fallback diagnostic observation is not a causal mechanism. Keep it
        # in investigation evidence/hypotheses, but never promote it into the
        # typed causal authority consumed by operator views and execution gates.
        if leading and leading.get("source") != "derived_observation" and not str(
            leading.get("claim") or ""
        ).startswith("Observed signal requiring causal confirmation:"):
            statement = str(leading.get("claim") or "").strip()
            supporting = list(dict.fromkeys(leading.get("supporting_evidence_ids") or []))
            contradicting = list(dict.fromkeys(leading.get("contradicting_evidence_ids") or []))
            falsification = str(
                (leading.get("falsification_check") or {}).get("objective")
                or "Collect independent evidence capable of disproving this causal mechanism."
            )
            if statement:
                claim_status = (
                    ClaimStatus.GROUNDED if outcome == ResolutionOutcome.EVIDENCE_SUPPORTED
                    else ClaimStatus.REFUTED if str(leading.get("status") or "").lower() == "falsified"
                    else ClaimStatus.HYPOTHESIS
                )
                claims.append(EvidenceBoundClaim(
                    claim_id=cls._claim_id(ClaimKind.CAUSAL, statement),
                    kind=ClaimKind.CAUSAL,
                    status=claim_status,
                    statement=statement,
                    supporting_evidence_ids=supporting,
                    contradicting_evidence_ids=contradicting,
                    falsification_test=falsification,
                    limitations=[] if claim_status == ClaimStatus.GROUNDED else [
                        "This causal claim is not established and cannot authorize remediation."
                    ],
                ))
        # An alert name and an arbitrary telemetry row cannot establish impact.
        # Direct, incident-bound impact evidence must be evaluated separately.
        impact_statement = "Customer or business impact has not been established by accepted evidence."
        impact_status = ClaimStatus.NOT_ESTABLISHED
        impact_support = []
        impact_limitations = ["An alert signal is not proof of customer or business impact."]
        claims.append(EvidenceBoundClaim(
            claim_id=cls._claim_id(ClaimKind.IMPACT, impact_statement),
            kind=ClaimKind.IMPACT,
            status=impact_status,
            statement=impact_statement,
            supporting_evidence_ids=impact_support,
            falsification_test=(
                "Collect direct SLO, availability, transaction, support-ticket, or customer-impact evidence "
                "for the incident window."
            ),
            limitations=impact_limitations,
        ))
        return claims

    def _coverage(self, evidence: list[dict[str, Any]]) -> dict[str, int]:
        coverage = {source: 0 for source in self.SOURCE_TOOL}
        for row in evidence:
            source = self._source(row)
            if source in coverage:
                coverage[source] += 1
        return coverage

    @staticmethod
    def _change_events(context: Context, evidence: list[dict[str, Any]]) -> list[ChangeEvent]:
        source_map = {
            "github": "git_commit", "gitlab": "git_commit", "git": "git_commit",
            "deployment": "deployment", "jenkins": "jenkins", "argocd": "argocd",
            "terraform": "terraform", "servicenow": "servicenow_change",
            "feature_flag": "feature_flag", "database": "database", "config": "configuration",
        }
        events: list[ChangeEvent] = []
        for row in evidence:
            if row.get("source_type") != "change":
                continue
            metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            raw_source = str(metadata.get("change_source") or row.get("source_system") or "deployment").lower()
            source = next((value for key, value in source_map.items() if key in raw_source), "deployment")
            occurred_at = row.get("observed_at")
            if isinstance(occurred_at, str):
                try:
                    occurred_at = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
                except ValueError:
                    continue
            if not isinstance(occurred_at, datetime) or occurred_at.tzinfo is None:
                continue
            target = str(row.get("target_resource_id") or "").strip()
            topology_ids = metadata.get("topology_resource_ids")
            topology_ids = topology_ids if isinstance(topology_ids, list) else []
            try:
                events.append(ChangeEvent(
                    change_id=str(metadata.get("change_id") or row.get("evidence_id") or ""),
                    tenant_id=context.tenant_id,
                    source=source,
                    source_event_id=str(metadata.get("source_event_id") or row.get("evidence_id") or ""),
                    occurred_at=occurred_at,
                    service=str(row.get("service") or context.alert.service),
                    environment=str(row.get("environment") or context.alert.environment),
                    resource_ids=[target] if target else [],
                    topology_resource_ids=[str(item) for item in topology_ids],
                    change_reference=str(row.get("source_uri") or metadata.get("uri") or row.get("evidence_id") or ""),
                    actor_reference=str(metadata.get("actor_reference") or "") or None,
                    version=str(metadata.get("version") or metadata.get("deployment") or "") or None,
                    evidence_ids=[str(row.get("evidence_id"))] if row.get("evidence_id") else [],
                    metadata={"source_system": row.get("source_system")},
                ))
            except ValueError:
                continue
        return events

    # Maps tokens found in a hypothesis's own claim text to the evidence
    # planes that would actually test it. Used by
    # `_leading_hypothesis_signaled_sources` below.
    _MECHANISM_CLAIM_SOURCES: tuple[tuple[tuple[str, ...], frozenset[str]], ...] = (
        (("code or configuration change",), frozenset({"changes"})),
        (("dependency", "upstream", "downstream", "dependent"), frozenset({"dependency", "topology"})),
        # The mechanism candidate's own claim conflates two distinct testable
        # causes ("resource saturation OR a data-path constraint"): a real
        # CPU/memory ceiling on the service's own container (the "resource"
        # plane, added below) versus a downstream data-store/query problem
        # (the "data" plane, mysql.search). Require both, so whichever one
        # actually applies gets a chance to support or contradict the claim.
        (("resource saturation", "data-path", "data path"), frozenset({"data", "resource"})),
    )

    @classmethod
    def _leading_hypothesis_signaled_sources(cls, hypotheses: list[dict[str, Any]] | None) -> set[str]:
        """Evidence planes that a hypothesis the investigation has
        organically gravitated toward (status "leading" or "confirmed", i.e.
        confidence already >= 0.55) actually needs to be tested against --
        not merely because its mechanism is one of the four generic starting
        candidates unconditionally generated for nearly every incident (see
        `mechanisms` above). Gating on real, earned status keeps this from
        reverting the earlier `_required_sources` narrowing (a service with
        no registered topology or tracked dependencies must not be
        investigated as if it were missing evidence it never had), while
        still catching the real failure mode: a mechanism hypothesis that
        climbed to "confirmed" purely from trace/log correlation, without the
        investigator ever having queried the evidence plane that would
        actually test IT specifically.

        Live-reproduced twice on the same pattern:
        - incident 417fc764acf342b1bdc8e815d18e8f1f: "An unhealthy upstream
          or downstream dependency is degrading api-gateway" confirmed via
          10 trace records alone, having never queried topology or
          dependency-health evidence at all.
        - incident 5504a8e5472a471b893ee5bd835ac1d3: "Resource saturation or
          a data-path constraint is affecting api-gateway" confirmed via 10
          trace records alone, having never queried mysql.search (the "data"
          plane) at all.
        Both perpetually self-declared their own exact missing evidence
        category as a gap, despite being "conclusive" -- permanently
        blocking catalog selection.
        """
        signaled: set[str] = set()
        if not hypotheses:
            return signaled
        for hypothesis in hypotheses:
            if str(hypothesis.get("status") or "") not in {"leading", "confirmed"}:
                continue
            claim = str(hypothesis.get("claim") or "").lower()
            for tokens, sources in cls._MECHANISM_CLAIM_SOURCES:
                if any(token in claim for token in tokens):
                    signaled |= sources
        return signaled

    @staticmethod
    def _required_sources(context: Context, hypotheses: list[dict[str, Any]] | None = None) -> set[str]:
        if hypotheses and hypotheses[0].get("mechanism") == "runtime_stopped" and hypotheses[0].get("status") == "confirmed":
            return {"topology", "telemetry"}
        text = " ".join((context.alert.name, context.alert.description, context.alert.service)).lower()
        source = str(context.alert.source or "").lower()
        environment = str(context.alert.environment or "").lower()
        external_probe = (
            "blackbox" in source
            or "synthetic" in source
            or "public-internet" in environment
            or "public internet" in environment
        )
        # Only logs and telemetry - basic observability nearly every real
        # service can produce - are unconditionally required. Every other
        # plane used to be required for every incident regardless of whether
        # it could plausibly exist: a service with no registered topology, no
        # tracked dependencies, or no approved runbook yet was investigated as
        # if it were missing evidence it never had, permanently blocking
        # "declared gaps addressed" on gaps that were never closable. Each
        # other plane is now required only when there is an actual signal it
        # is relevant - the investigation still queries broadly (see `plan`
        # and `_select_tool`), this only changes what counts as a real,
        # closable gap versus evidence that simply does not apply here.
        required = {"logs", "telemetry"}
        if any(token in text for token in ("deploy", "release", "config", "change")):
            required.add("changes")
        if any(token in text for token in ("latency", "timeout", "availability", "down", "error", "5xx")):
            required.add("traces")
        quality = context.metadata.get("context_quality") if isinstance(context.metadata, dict) else {}
        diagnostic_gaps = quality.get("diagnostic_gaps") if isinstance(quality, dict) else []
        # When signal/topology collection still has no causal explanation,
        # inspect implementation evidence instead of exhausting the budget on
        # additional broad inventory sources.
        if "causal_or_action" in (diagnostic_gaps if isinstance(diagnostic_gaps, list) else []):
            required.add("code")
        if any(token in text for token in ("deploy", "release", "config", "traceback", "exception")):
            required.add("code")
        signaled_sources = IterativeInvestigator._leading_hypothesis_signaled_sources(hypotheses)
        if any(token in text for token in ("database", "mysql", "query", "replica", "table", "data")) or (
            "data" in signaled_sources
        ):
            required.add("data")
        if any(token in text for token in ("recurring", "repeat", "known issue", "regression")):
            required.add("history")
        if not external_probe and (
            context.dependency_services or context.cmdb or context.kubernetes
            or any(token in text for token in ("dependency", "upstream", "downstream", "dependent"))
            or {"dependency", "topology"} & signaled_sources
        ):
            required.add("dependency")
            required.add("topology")
        if "resource" in signaled_sources:
            # Unlike "data" (also signaled by literal alert-text keywords
            # like "database"/"mysql"), there is no comparable alert-text
            # token for "the container is CPU/memory saturated" -- a
            # generic latency/error alert gives no textual hint either way,
            # so this plane is only ever required once the investigation's
            # own evidence has already made "resource saturation" the
            # leading explanation.
            required.add("resource")
        return required

    def _select_tool(
        self,
        *,
        context: Context,
        evidence: list[dict[str, Any]],
        hypotheses: list[dict[str, Any]],
        tool_counts: dict[str, int],
    ) -> tuple[str, dict[str, Any]] | None:
        coverage = self._coverage(evidence)
        alert_text = " ".join([
            context.alert.name, context.alert.description, context.alert.service,
        ]).lower()
        priority = [
            "logs", "telemetry", "traces", "code", "topology", "dependency", "resource", "changes",
            "runbooks", "history", "data",
        ]
        # Evidence-plane priority must be selected from observed alert facts.
        # Generic candidate hypotheses (for example "a configuration change")
        # must not redirect every latency investigation to change search first.
        if any(token in alert_text for token in ("deploy", "release", "config", "stack", "traceback")):
            priority = ["changes", "code", "logs", "telemetry", "traces", "topology", "dependency", "resource", "runbooks", "history", "data"]
        elif any(token in alert_text for token in ("database", "mysql", "query", "replica", "table")):
            priority = ["data", "logs", "telemetry", "topology", "dependency", "resource", "changes", "runbooks", "code", "history", "traces"]
        elif any(token in alert_text for token in ("recurring", "repeat", "known issue")):
            priority = ["history", "logs", "telemetry", "topology", "dependency", "resource", "changes", "runbooks", "code", "data", "traces"]
        from common.diagnostic_runbooks import diagnostic_tools
        guidance = diagnostic_tools(context.metadata.get("diagnostic_runbook"), tenant_id=context.tenant_id,
                                    service=context.alert.service, environment=context.alert.environment)
        planned = [source for tool in guidance for source, registered in self.SOURCE_TOOL.items() if registered == tool]
        priority = list(dict.fromkeys([*planned, *priority]))
        required = self._required_sources(context, hypotheses)
        priority = [source for source in priority if source in required]
        # An unavailable/empty source must not consume the entire investigation
        # budget. Query every required evidence plane once before issuing a
        # bounded refinement query to any one tool.
        source = next(
            (
                name
                for name in priority
                if coverage.get(name, 0) == 0
                and tool_counts.get(self.SOURCE_TOOL[name], 0) == 0
            ),
            None,
        )
        if source is None:
            # A second query to the same plane is allowed when it refines or
            # falsifies the leading hypothesis. Bound it to two calls per tool.
            source = min(
                (name for name in priority if tool_counts.get(self.SOURCE_TOOL[name], 0) < 2),
                key=lambda name: tool_counts.get(self.SOURCE_TOOL[name], 0),
                default=None,
            )
        if source is None:
            return None
        tool = self.SOURCE_TOOL[source]
        terms: list[str] = []
        for value in (
            context.alert.service, context.alert.name, context.alert.description,
            *(item.get("claim") for item in hypotheses[:2]),
        ):
            terms.extend(sorted(self._tokens(value)))
        terms = list(dict.fromkeys(terms))[:18]
        arguments: dict[str, Any] = {
            "terms": terms,
            "limit": min(10, self.max_evidence - len(evidence)),
            "service": context.alert.service,
            "tenant_id": context.tenant_id,
            "alert_name": context.alert.name,
            "environment": context.alert.environment,
            "target_labels": {key: context.alert.labels[key] for key in (
                "job", "instance", "namespace", "cluster", "operation", "http_route", "route", "device", "mountpoint"
            ) if context.alert.labels.get(key)},
            "application": context.alert.labels.get("application") or context.alert.service,
            "project": context.alert.labels.get("project") or context.alert.metadata.get("project"),
            "trace_id": context.alert.trace_id,
            "operation": context.alert.labels.get("operation"),
        }
        if tool in {"dependency-health.search", "topology.search"}:
            # Querying the alerting service's OWN container ("is api-gateway
            # healthy?") can never support or contradict a claim that ONE OF
            # ITS DEPENDENCIES is unhealthy -- self != related_to in the
            # scoring below (_structured_mechanism_support /
            # _structured_mechanism_contradiction) requires actually probing
            # a different, discovered service. Trace evidence already carries
            # real caller/callee edges (see `dependency_edges` in
            # _trace_evidence_summary); once one names a service other than
            # the alerting service, target that dependency directly and
            # record which incident it relates back to.
            dependent_service = self._discovered_dependency_service(context.alert.service, evidence)
            if dependent_service and not any(h.get("mechanism") == "runtime_stopped" for h in hypotheses[:1]):
                arguments["service"] = dependent_service
                arguments["related_to"] = context.alert.service
        alert_started_at = context.alert.starts_at or context.alert.created_at
        if alert_started_at.tzinfo is None:
            alert_started_at = alert_started_at.replace(tzinfo=UTC)
        else:
            alert_started_at = alert_started_at.astimezone(UTC)
        arguments["start_time"] = (alert_started_at - timedelta(minutes=5)).isoformat()
        arguments["end_time"] = (alert_started_at + timedelta(minutes=15)).isoformat()
        return tool, {key: value for key, value in arguments.items() if value not in (None, "", [])}

    @staticmethod
    def _discovered_dependency_service(service: str, evidence: list[dict[str, Any]]) -> str:
        """The first real, OTHER service the alerting service actually calls
        or is called by, per trace-derived caller/callee edges -- empty when
        no cross-service span has been observed yet (most traces in a
        single-hop request are entirely self-contained, so this legitimately
        stays empty for services with no discovered dependency, matching
        today's self-check behavior rather than fabricating one)."""
        service_lower = str(service or "").strip().lower()
        if not service_lower:
            return ""
        for row in evidence:
            if row.get("source_type") != "trace":
                continue
            metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            edges = metadata.get("dependency_edges") if isinstance(metadata.get("dependency_edges"), list) else []
            for edge in edges:
                if not isinstance(edge, dict):
                    continue
                upstream = str(edge.get("upstream") or "").strip()
                downstream = str(edge.get("downstream") or "").strip()
                if upstream.lower() == service_lower and downstream:
                    return downstream
                if downstream.lower() == service_lower and upstream:
                    return upstream
        return ""

    @staticmethod
    def _hypothesis_rank(hypothesis: dict[str, Any]) -> tuple[bool, bool, float]:
        """Confirmation status outranks raw confidence: a "confirmed" hypothesis
        is always a more trustworthy answer than one that structurally can
        never be confirmed (a symptom-only derived_observation), regardless
        of which one happens to score higher. Used to sort hypotheses so
        every caller's `hypotheses[0]` reflects the actual best conclusion."""
        explanatory = (hypothesis.get("source") != "derived_observation"
                       and hypothesis.get("status") != "falsified"
                       and bool(hypothesis.get("supporting_evidence_ids")))
        return (hypothesis.get("status") == "confirmed", explanatory,
                float(hypothesis.get("confidence") or 0))

    def _revise_hypotheses(
        self,
        hypotheses: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        *,
        context: Context,
    ) -> list[dict[str, Any]]:
        if not hypotheses:
            diagnostic = self._leading_diagnostic_candidate(evidence)
            if diagnostic:
                snippet = self._human_evidence_summary(diagnostic.get("snippet") or diagnostic.get("summary"))
                is_causal_precursor = (
                    self._source(diagnostic) == "changes"
                    and diagnostic.get("incident_window_relation") == "before"
                )
                claim_prefix = (
                    "Candidate causal change identified" if is_causal_precursor
                    else "Observed signal requiring causal confirmation"
                )
                hypotheses = [{
                    "hypothesis_id": str(uuid4()),
                    "claim": f"{claim_prefix}: {snippet}",
                    "status": "viable",
                    # A timing-correlated change precursor is a stronger
                    # heuristic signal than a merely-concurrent observation,
                    # but both stay far below the 0.65 conclusiveness and
                    # 0.70 auto-execution thresholds -- this only changes
                    # what an operator sees first, never what the platform
                    # is willing to act on.
                    "confidence": 0.4 if is_causal_precursor else 0.3,
                    "supporting_evidence_ids": [str(diagnostic.get("evidence_id"))] if diagnostic.get("evidence_id") else [],
                    "contradicting_evidence_ids": [],
                    "affected_resource_ids": [], "causal_sequence": [], "confidence_components": {},
                    "falsification_check": {"objective": "Find an independent source that confirms the causal mechanism."},
                    "next_evidence_requests": [],
                    "source": "derived_observation",
                }]
        # Keep a falsifiable 3-5 candidate set.  These are investigation
        # branches, not asserted causes: their deliberately low initial score
        # cannot authorize a plan without independent supporting evidence.
        mechanisms = [
            ("recent_change", f"A recent code or configuration change affected {context.alert.service}.", "Query deployment and code history around the alert onset."),
            ("dependency", f"An unhealthy upstream or downstream dependency is degrading {context.alert.service}.", "Query topology and dependency health for temporal correlation."),
            ("resource_or_data", f"Resource saturation or a data-path constraint is affecting {context.alert.service}.", "Query resource telemetry and data-store health over the incident window."),
            ("traffic", f"A traffic or workload shift exceeded the operating envelope of {context.alert.service}.", "Compare request volume, latency, errors, and capacity before and after onset."),
        ]
        for row in evidence:
            metadata = row.get("metadata") or {}
            lifecycle = metadata.get("runtime_lifecycle") or {}
            if (row.get("source_type") != "topology" or metadata.get("service") != context.alert.service
                    or metadata.get("runtime_state") not in {"exited", "dead"}
                    or lifecycle.get("Running") is not False):
                continue
            try:
                stopped = datetime.fromisoformat(str(lifecycle["FinishedAt"]).replace("Z", "+00:00"))
                onset = context.alert.starts_at
                if onset.tzinfo is None:
                    onset = onset.replace(tzinfo=UTC)
                if not onset - timedelta(minutes=15) <= stopped <= onset + timedelta(minutes=5):
                    continue
            except (KeyError, ValueError, TypeError):
                continue
            if not any(h.get("mechanism") == "runtime_stopped" for h in hypotheses):
                hypotheses.insert(0, {
                    "hypothesis_id": hypothesis_digest(f"{context.incident_id}:runtime_stopped")[:24],
                    "claim": f"The {context.alert.service} workload stopped, causing its HTTP endpoint to be unavailable.",
                    "mechanism": "runtime_stopped", "target_service": context.alert.service,
                    "stopped_at": lifecycle["FinishedAt"], "source": "mechanism_candidate",
                    "status": "candidate", "confidence": 0.0,
                    "supporting_evidence_ids": [], "contradicting_evidence_ids": [],
                    "affected_resource_ids": [], "causal_sequence": [], "confidence_components": {},
                    "falsification_check": {"objective": "Verify failed HTTP probes after the recorded process exit and check whether the workload has recovered. Why the process exited remains unproven."},
                    "next_evidence_requests": [],
                })
            break
        existing_claims = {str(item.get("claim") or "").strip().lower() for item in hypotheses}
        for mechanism, claim, objective in mechanisms:
            # The set is meant to hold 3-5 candidates (see comment above), but
            # this previously broke as soon as the count reached 3 -- with the
            # common case of one pre-existing derived_observation seed
            # hypothesis, that silently capped every investigation at just 2
            # of the 4 mechanism candidates (recent_change and dependency,
            # the first two in the list), never even considering
            # resource_or_data or traffic regardless of which one actually
            # fit the evidence. Reproduced live: 0 of ~60 freshly
            # re-investigated incidents ever carried a resource_or_data or
            # traffic hypothesis. Break at the actual upper bound instead.
            if len(hypotheses) >= 5:
                break
            if claim.lower() in existing_claims:
                continue
            hypotheses.append({
                "hypothesis_id": hypothesis_digest(f"{context.incident_id}:{mechanism}")[:24],
                "claim": claim,
                "status": "candidate",
                "confidence": 0.0,
                "supporting_evidence_ids": [],
                "contradicting_evidence_ids": [],
                "affected_resource_ids": [], "causal_sequence": [], "confidence_components": {},
                "falsification_check": {"objective": objective}, "next_evidence_requests": [],
                "source": "mechanism_candidate",
            })
            existing_claims.add(claim.lower())
        hypotheses = hypotheses[:5]
        # A failed connection can have no downstream server span at all.
        # Name the observed boundary mechanism instead of requiring a slow
        # remote server span or pretending the remote process itself failed.
        timeout_claim = f"Outbound dependency connection timeouts are delaying {context.alert.service} requests."
        if any(row.get("source_type") == "trace" and self._current_operational(row) and self._structured_mechanism_support(
            {"claim": timeout_claim}, row
        ) for row in evidence):
            for hypothesis in hypotheses:
                if (hypothesis.get("source") == "mechanism_candidate"
                        and "unhealthy upstream or downstream dependency" in str(hypothesis.get("claim"))):
                    hypothesis["claim"] = timeout_claim
        coverage = self._coverage(evidence)
        required_sources = self._required_sources(context, hypotheses)
        change_events = self._change_events(context, evidence)
        for hypothesis in hypotheses:
            claim_tokens = self._tokens(hypothesis.get("claim"))
            support: list[str] = []
            sources: set[str] = set()
            contradiction: list[str] = []
            for row in evidence:
                evidence_id = str(row.get("evidence_id") or "")
                text = " ".join(str(row.get(key) or "") for key in ("snippet", "summary", "content", "title"))
                overlap = claim_tokens.intersection(self._tokens(text))
                structured_support = self._structured_mechanism_support(hypothesis, row)
                lexical_support = (
                    hypothesis.get("source") != "mechanism_candidate"
                    and (len(overlap) >= 2 or (claim_tokens and len(overlap) / len(claim_tokens) >= 0.35))
                )
                # Not just `_current_operational`: a "changes" row timestamped
                # before the incident window is exactly the kind of evidence a
                # fallback claim gets built from (see _leading_diagnostic_candidate),
                # and it must remain eligible to support - or contradict - a
                # hypothesis on every later revision pass, not just at selection time.
                current_operational = self._operational_for_support(row)
                if (structured_support or lexical_support) and current_operational:
                    if evidence_id:
                        support.append(evidence_id)
                    sources.add(self._source(row))
                structured_contradiction = self._structured_mechanism_contradiction(hypothesis, row)
                # Word-boundary match, not plain substring: "unhealthy" (the
                # evidence text a dependency hypothesis is actually looking
                # for) contains "healthy" as a literal substring, so a naive
                # `"healthy" in text` search reads exactly the evidence that
                # should SUPPORT "dependency is unhealthy" as if it said the
                # opposite. Reproduced live: an unhealthy-dependency evidence
                # row (metadata.healthy=False) simultaneously satisfied
                # _structured_mechanism_support (True) and this check (also
                # True, via "un-HEALTHY"), and the two are irreconcilable by
                # design -- supporting_evidence_ids explicitly drops anything
                # that also lands in contradicting_evidence_ids -- so the
                # evidence ended up counted as neither, silently discarded.
                generic_health_contradiction = (
                    hypothesis.get("source") != "derived_observation"
                    and row.get("source_type") not in {"topology", "dependency", "resource"}
                    and bool(re.search(r"\b(healthy|normal|no errors|recovered)\b", text.lower()))
                    and bool(overlap)
                )
                if evidence_id and current_operational and (
                    structured_contradiction
                    or generic_health_contradiction
                ):
                    contradiction.append(evidence_id)
            supporting_rows = [row for row in evidence if str(row.get("evidence_id") or "") in set(support)]
            fresh_support = [
                row for row in supporting_rows
                if (int(row.get("freshness_seconds") or 0) <= 900 or self._incident_window_aligned(row))
                and self._current_operational(row)
            ]
            temporal_alignment = len(fresh_support) / max(1, len(supporting_rows))
            topology_support = 1.0 if any(row.get("source_type") in {"topology", "dependency"} for row in supporting_rows) else (
                0.5 if len({str(row.get("service") or "") for row in supporting_rows if row.get("service")}) > 1 else 0.0
            )
            affected_resources = [str(item) for item in hypothesis.get("affected_resource_ids") or []]
            alert_resource = str(context.alert.labels.get("resource_id") or "").strip()
            if alert_resource and alert_resource not in affected_resources:
                affected_resources.append(alert_resource)
            correlated_changes = rank_correlated_changes(
                change_events,
                ChangeCorrelationContext(
                    tenant_id=context.tenant_id,
                    incident_started_at=context.alert.starts_at,
                    service=context.alert.service,
                    environment=context.alert.environment,
                    affected_resource_ids=affected_resources,
                    topology_resource_ids=[str(item) for item in context.metadata.get("topology_resource_ids", [])],
                ),
            ) if change_events else []
            change_correlation = max(
                (item.change_correlation_score for item in correlated_changes), default=0.0
            )
            for item in correlated_changes:
                if item.change_correlation_score >= 0.55:
                    support.extend(evidence_id for evidence_id in item.evidence_ids if evidence_id)
                    sources.add("changes")
            supporting_rows = [row for row in evidence if str(row.get("evidence_id") or "") in set(support)]
            fresh_support = [
                row for row in supporting_rows
                if (int(row.get("freshness_seconds") or 0) <= 900 or self._incident_window_aligned(row))
                and self._current_operational(row)
            ]
            temporal_alignment = len(fresh_support) / max(1, len(supporting_rows))
            topology_support = 1.0 if any(
                row.get("source_type") in {"topology", "dependency"} for row in supporting_rows
            ) else topology_support
            historical_similarities = [
                float(row.get("metadata", {}).get("similarity"))
                for row in evidence
                if row.get("source_type") == "ticket"
                and row.get("metadata", {}).get("reviewed") is True
                and row.get("metadata", {}).get("similarity") is not None
            ]
            tested_rows = [
                row for row in supporting_rows
                if row.get("metadata", {}).get("test_passed") is not None
            ]
            successful_test_ratio = (
                sum(1 for row in tested_rows if row.get("metadata", {}).get("test_passed") is True)
                / len(tested_rows)
                if tested_rows else 0.0
            )
            evidence_quality = (
                sum(float(row.get("reliability_score") or 0.0) for row in supporting_rows)
                / len(supporting_rows)
                if supporting_rows else 0.0
            )
            consistency = len(support) / max(1, len(support) + len(contradiction))
            causal_observations = [(0.35, temporal_alignment)] if supporting_rows else []
            if any(row.get("source_type") in {"topology", "dependency"} for row in evidence):
                causal_observations.append((0.25, topology_support))
            if tested_rows:
                causal_observations.append((0.20, successful_test_ratio))
            if change_events:
                causal_observations.append((0.20, change_correlation))
            causal_weight = sum(weight for weight, _ in causal_observations)
            causal_strength = (
                sum(weight * value for weight, value in causal_observations) / causal_weight
                if causal_weight else 0.0
            )
            completeness = sum(1 for source in required_sources if coverage.get(source, 0)) / max(1, len(required_sources))
            available_components = {
                "evidence_quality", "evidence_consistency", "causal_strength",
                "independent_source_corroboration",
            }
            if supporting_rows:
                available_components.add("temporal_alignment")
            if any(row.get("source_type") in {"topology", "dependency"} for row in evidence):
                available_components.add("topology_alignment")
            if historical_similarities:
                available_components.add("historical_similarity")
            if tested_rows:
                available_components.add("successful_test_ratio")
            scored = score_confidence(ConfidenceInputs(
                evidence_quality=evidence_quality,
                evidence_consistency=consistency,
                causal_strength=causal_strength,
                independent_source_corroboration=min(len(sources) / 3, 1.0),
                temporal_alignment=temporal_alignment,
                topology_alignment=topology_support,
                historical_similarity=(
                    sum(historical_similarities) / len(historical_similarities)
                    if historical_similarities else 0.0
                ),
                successful_test_ratio=successful_test_ratio,
                contradiction_penalty=min(len(set(contradiction)) * 0.1, 0.35),
                freshness_penalty=0.15 if supporting_rows and not fresh_support else 0.0,
                missing_data_penalty=(1.0 - completeness) * 0.2,
                # Missing optional planes are represented by the proportional
                # missing-data penalty and explicit gaps. They must not impose
                # a global ceiling once two independent sources corroborate the
                # same mechanism. Fewer than two sources remains non-conclusive.
                sources_unavailable=len(sources) < 2,
                stale_evidence=bool(supporting_rows and not fresh_support),
                model_fallback=bool(context.metadata.get("model_fallback")),
                degraded_context=bool(context.metadata.get("degraded_context")),
                unresolved_contradictions=bool(contradiction),
                ambiguous_target=not bool(str(context.alert.service or "").strip()),
                available_components=frozenset(available_components),
            ))
            contradiction_ids = list(dict.fromkeys(contradiction))[:20]
            hypothesis["supporting_evidence_ids"] = [
                evidence_id for evidence_id in dict.fromkeys(support)
                if evidence_id not in set(contradiction_ids)
            ][:20]
            supporting_id_set = set(hypothesis["supporting_evidence_ids"])
            hypothesis["evidence_bindings"] = [
                {
                    "evidence_id": str(row.get("evidence_id")),
                    "source_type": str(row.get("source_type") or "unknown"),
                    "source_uri": str(row.get("source_uri") or ""),
                    "query_reference": str(row.get("query_reference") or ""),
                    "observed_at": row.get("observed_at"),
                    "citation_provenance": str(row.get("citation_provenance") or row.get("source_uri") or ""),
                }
                for row in evidence
                if str(row.get("evidence_id") or "") in supporting_id_set
            ][:20]
            hypothesis["contradicting_evidence_ids"] = contradiction_ids
            hypothesis["independent_sources"] = sorted(sources)
            hypothesis["temporal_alignment"] = round(temporal_alignment, 4)
            hypothesis["topology_support"] = round(topology_support, 4)
            hypothesis["change_correlation"] = round(change_correlation, 4)
            hypothesis["correlated_changes"] = [item.model_dump(mode="json") for item in correlated_changes[:5]]
            hypothesis["independent_source_count"] = len(sources)
            hypothesis["confidence"] = scored.score
            hypothesis["confidence_breakdown"] = {
                "raw_score": scored.raw_score,
                "ceiling": scored.ceiling,
                "components": scored.components,
                "penalties": scored.penalties,
                "ceiling_reasons": list(scored.ceiling_reasons),
            }
            hypothesis["confidence_components"] = scored.components
            # A derived observation is a symptom summary, never a causal
            # mechanism. It remains useful context but cannot become a root
            # cause merely through repeated/lexically similar evidence.
            causally_eligible = hypothesis.get("source") != "derived_observation"
            hypothesis["status"] = (
                "confirmed" if causally_eligible
                and hypothesis["confidence"] >= self.conclusive_threshold
                and len(sources) >= (max(2, self.minimum_independent_sources)
                                     if hypothesis.get("mechanism") == "runtime_stopped"
                                     else self.minimum_independent_sources)
                else "falsified" if hypothesis["confidence"] <= 0.15 and bool(contradiction)
                else "leading" if hypothesis["confidence"] >= 0.55
                else "candidate"
            )
        # Reproduced live: a symptom-only "derived_observation" can never
        # reach "confirmed" status by design (see the comment above), but
        # ranking purely by raw confidence let one outrank an actual
        # confirmed causal mechanism sitting right next to it whenever the
        # unconfirmable symptom's own confidence happened to be a little
        # higher (0.71 vs 0.66 in the case this was found on) - every caller
        # treats hypotheses[0] as "the conclusion", so the genuinely
        # confirmed mechanism was silently shadowed and the investigation
        # kept reporting "inconclusive: symptom summary, not a causal
        # mechanism" despite already having a real, corroborated answer.
        # A confirmed hypothesis - whatever its raw score - is always a more
        # trustworthy answer than one that structurally cannot ever be
        # confirmed, so confirmation status is the primary sort key and
        # confidence only breaks ties within the same status.
        return sorted(
            hypotheses,
            key=self._hypothesis_rank,
            reverse=True,
        )

    def _source_assessments(
        self, evidence: list[dict[str, Any]], hypotheses: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        supporting_ids = {
            str(evidence_id)
            for hypothesis in hypotheses
            for evidence_id in hypothesis.get("supporting_evidence_ids", [])
        }
        assessments: dict[str, dict[str, Any]] = {}
        for source in self.SOURCE_TOOL:
            rows = [row for row in evidence if self._source(row) == source]
            eligible = [row for row in rows if self._current_operational(row)]
            used = [row for row in eligible if str(row.get("evidence_id") or "") in supporting_ids]
            if not rows:
                disposition = "not_available"
            elif not eligible and source in {"logs", "telemetry", "traces", "data", "dependency", "changes"}:
                disposition = "reviewed_no_incident_aligned_evidence"
            elif used:
                disposition = "used_as_hypothesis_support"
            else:
                disposition = "reviewed_no_causal_match"
            assessments[source] = {
                "retrieved_count": len(rows),
                "incident_eligible_count": len(eligible),
                "supporting_count": len(used),
                "disposition": disposition,
            }
        return assessments

    def _confirmed_without_declared_gaps(
        self, hypotheses: list[dict[str, Any]], evidence: list[dict[str, Any]], context: Context,
    ) -> bool:
        """True only once the leading "confirmed" hypothesis has actually been
        tested against every evidence plane its own claim requires.

        The early-stop-on-confirmed checks below used to fire the moment
        `_revise_hypotheses` marked the leading hypothesis "confirmed" -
        which already requires independent-source corroboration, but not
        that the *specific* planes `_required_sources` demands for this
        hypothesis's own claim (e.g. "resource" and "data" for a
        resource-or-data claim, added by the fix documented on
        `_MECHANISM_CLAIM_SOURCES`) were ever queried. A hypothesis could
        stop-and-declare `conclusive: True` via correlation alone while the
        post-loop `missing_sources` computation - using the exact same
        `_required_sources` set - simultaneously reported those same planes
        as unaddressed, which then blocks catalog readiness ("declared
        evidence gaps remain") regardless. Reproduced live: a
        "resource_or_data" hypothesis reached `status="confirmed"` at 0.668
        confidence and stopped the investigation in 2 steps, having queried
        neither `resource-health.search` nor `mysql.search` at all -
        `conclusive: True` and "declared evidence gaps remain" were both
        true for the same investigation at once. Continuing to spend
        remaining step/tool budget on those specific planes - rather than
        declaring victory prematurely - is exactly what `_required_sources`
        was already designed to demand.
        """
        leading = hypotheses[0] if hypotheses else None
        if not leading or leading.get("status") != "confirmed":
            return False
        if leading.get("mechanism") == "runtime_stopped" and not {"topology", "telemetry"}.issubset(
            set(leading.get("independent_sources") or [])
        ):
            return False
        # Configurable source diversity does not replace the claim contract's
        # requirement for two distinct supporting items and no contradictions.
        supporting = {
            str(item).strip() for item in leading.get("supporting_evidence_ids") or []
            if str(item or "").strip()
        }
        if len(supporting) < 2 or leading.get("contradicting_evidence_ids"):
            return False
        coverage = self._coverage(evidence)
        required_sources = self._required_sources(context, hypotheses)
        return not any(coverage.get(source, 0) == 0 for source in required_sources)

    async def investigate(self, context: Context, *, persist: PersistEvent | None = None) -> dict[str, Any]:
        investigation_started = monotonic()
        investigation_id = str(uuid4())
        investigation_plan = self.plan(context, investigation_id=investigation_id)
        initial = self._compile_evidence(context, self._initial_evidence(context))
        # Accumulated snapshots must not consume the capacity needed to test
        # their hypotheses. Keep a balanced seed, preferring incident-aligned
        # observations, and reserve half the bounded working set for tool results.
        seed_limit = self.max_evidence - min(self.max_evidence // 2, self.max_tool_calls * 10)
        buckets: dict[str, list[dict[str, Any]]] = {}
        for row in sorted(initial, key=lambda row: not self._operational_for_support(row)):
            buckets.setdefault(self._source(row), []).append(row)
        evidence: list[dict[str, Any]] = []
        while buckets and len(evidence) < seed_limit:
            for source in list(buckets):
                evidence.append(buckets[source].pop(0))
                if not buckets[source]:
                    del buckets[source]
                if len(evidence) >= seed_limit:
                    break
        hypotheses = self._revise_hypotheses(self._initial_hypotheses(context), evidence, context=context)
        started_at = datetime.now(UTC).isoformat()
        tool_counts: dict[str, int] = {}
        diagnostic_decisions: list[dict[str, Any]] = []
        ai_diagnostics = os.getenv("RESOLUTION_DIAGNOSIS_PLANNER_ENABLED", "false").lower() in {"1", "true", "yes"}
        steps: list[dict[str, Any]] = []
        if persist:
            await persist("started", {
                "investigation_id": investigation_id,
                "incident_id": str(context.incident_id),
                "alert_id": str(context.alert.id),
                "tenant_id": str(context.alert.tenant_id or "default"),
                "status": InvestigationStatus.RUNNING.value,
                "step_budget": self.max_steps,
                "evidence_count": len(evidence),
                "correlation_id": investigation_plan.correlation_id,
                "investigation_plan": investigation_plan.model_dump(mode="json"),
            })

        status = InvestigationStatus.RUNNING
        stop_reason = ""
        for sequence in range(1, self.max_steps + 1):
            if monotonic() - investigation_started >= self.max_duration_seconds:
                status, stop_reason = InvestigationStatus.BUDGET_EXHAUSTED, "duration_budget_exhausted"
                break
            if sum(tool_counts.values()) >= self.max_tool_calls:
                status, stop_reason = InvestigationStatus.BUDGET_EXHAUSTED, "tool_call_budget_exhausted"
                break
            if len(evidence) >= self.max_evidence:
                status, stop_reason = InvestigationStatus.BUDGET_EXHAUSTED, "evidence_budget_exhausted"
                break
            leading = hypotheses[0] if hypotheses else None
            # Apply both source coverage and claim-grounding requirements at
            # every stopping point, including the final post-loop check.
            if self._confirmed_without_declared_gaps(hypotheses, evidence, context):
                status, stop_reason = InvestigationStatus.CONCLUSIVE, "corroborated_leading_hypothesis"
                break
            selection = self._select_tool(
                context=context, evidence=evidence, hypotheses=hypotheses, tool_counts=tool_counts,
            )
            if ai_diagnostics and len(diagnostic_decisions) < 2 and self.max_cost_usd > 0:
                from resolution_agent.diagnostic_planner import diagnostic_choices, choose_diagnostic
                choices = diagnostic_choices(self, context, evidence, hypotheses, tool_counts)
                selected, diagnostic = await choose_diagnostic(context, evidence, hypotheses, choices)
                diagnostic_decisions.append({"step": sequence, **diagnostic})
                if selected is not None:
                    selection = selected["tool"], selected["arguments"]
            if selection is None:
                status, stop_reason = InvestigationStatus.INCONCLUSIVE, "no_additional_read_only_tool"
                break
            tool_name, arguments = selection
            tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
            step_id = str(uuid4())
            step_started = datetime.now(UTC).isoformat()
            try:
                result = await self.client.call(tool_name, arguments)
                rows = result.get("evidence") if isinstance(result.get("evidence"), list) else []
                combined = self._compile_evidence(
                    context,
                    [*evidence, *(row for row in rows if isinstance(row, dict))],
                )[: self.max_evidence]
                existing = {str(row.get("evidence_id") or "") for row in evidence}
                new_rows = [row for row in combined if str(row.get("evidence_id") or "") not in existing]
                evidence = combined
                hypotheses = self._revise_hypotheses(hypotheses, evidence, context=context)
                step = {
                    "step_id": step_id,
                    "sequence_no": sequence,
                    "tool_name": tool_name,
                    "query": arguments,
                    "status": "completed",
                    "result_count": len(new_rows),
                    "evidence_ids": [str(row.get("evidence_id")) for row in new_rows if row.get("evidence_id")],
                    "hypothesis_updates": hypotheses,
                    "started_at": step_started,
                    "completed_at": datetime.now(UTC).isoformat(),
                }
            except Exception as exc:
                step = {
                    "step_id": step_id,
                    "sequence_no": sequence,
                    "tool_name": tool_name,
                    "query": arguments,
                    "status": "failed",
                    "result_count": 0,
                    "evidence_ids": [],
                    "hypothesis_updates": hypotheses,
                    "error": str(exc)[:1000],
                    "started_at": step_started,
                    "completed_at": datetime.now(UTC).isoformat(),
                }
            steps.append(step)
            if persist:
                await persist("step", {"investigation_id": investigation_id, **step})
            leading = hypotheses[0] if hypotheses else None
            # Apply both source coverage and claim-grounding requirements at
            # every stopping point, including the final post-loop check.
            if self._confirmed_without_declared_gaps(hypotheses, evidence, context):
                status, stop_reason = InvestigationStatus.CONCLUSIVE, "corroborated_leading_hypothesis"
                break
            if len(evidence) >= self.max_evidence:
                status, stop_reason = InvestigationStatus.BUDGET_EXHAUSTED, "evidence_budget_exhausted"
                break

        if status == InvestigationStatus.RUNNING:
            if self._confirmed_without_declared_gaps(hypotheses, evidence, context):
                status, stop_reason = InvestigationStatus.CONCLUSIVE, "corroborated_leading_hypothesis"
            else:
                status, stop_reason = InvestigationStatus.BUDGET_EXHAUSTED, "step_budget_exhausted"
        coverage = self._coverage(evidence)
        required_sources = self._required_sources(context, hypotheses)
        missing = [source for source in required_sources if coverage.get(source, 0) == 0]
        leading = hypotheses[0] if hypotheses else None
        grounding_gaps = []
        if leading and len({
            str(item).strip() for item in leading.get("supporting_evidence_ids") or []
            if str(item or "").strip()
        }) < 2:
            grounding_gaps.append("causal_corroboration")
        contradictory = list(leading.get("contradicting_evidence_ids") or []) if leading else []
        failed_steps = [step for step in steps if step.get("status") == "failed"]
        if status == InvestigationStatus.CONCLUSIVE:
            outcome = ResolutionOutcome.EVIDENCE_SUPPORTED
        elif contradictory:
            outcome = ResolutionOutcome.CONFLICTING_EVIDENCE
        elif failed_steps and len(failed_steps) == len(steps):
            outcome = ResolutionOutcome.CONNECTOR_FAILURE
        elif missing or grounding_gaps or status == InvestigationStatus.BUDGET_EXHAUSTED:
            outcome = ResolutionOutcome.INSUFFICIENT_EVIDENCE
        else:
            outcome = ResolutionOutcome.UNKNOWN
        confidence_breakdown = leading.get("confidence_breakdown") if leading else {}
        confidence_breakdown = confidence_breakdown if isinstance(confidence_breakdown, dict) else {}
        typed_hypotheses = []
        status_map = {
            "confirmed": HypothesisStatus.SUPPORTED,
            "falsified": HypothesisStatus.REJECTED,
            "leading": HypothesisStatus.TESTING,
            "candidate": HypothesisStatus.PROPOSED,
            "viable": HypothesisStatus.PROPOSED,
        }
        for hypothesis in hypotheses:
            claim = str(hypothesis.get("claim") or "").strip()
            typed_hypotheses.append(HypothesisContract(
                hypothesis_id=str(hypothesis.get("hypothesis_id") or uuid4()),
                incident_id=context.incident_id,
                correlation_id=investigation_plan.correlation_id,
                title=claim[:160] or "Unresolved causal hypothesis",
                description=claim or "No causal claim was available.",
                suspected_component=str(context.alert.service or "unknown"),
                suspected_change=None,
                probability=float(hypothesis.get("confidence") or 0.0),
                status=status_map.get(str(hypothesis.get("status") or ""), HypothesisStatus.INCONCLUSIVE),
                supporting_evidence_ids=list(hypothesis.get("supporting_evidence_ids") or []),
                contradicting_evidence_ids=list(hypothesis.get("contradicting_evidence_ids") or []),
                required_tests=[str((hypothesis.get("falsification_check") or {}).get("objective") or "Collect independent causal evidence.")],
                reasoning_summary=str(hypothesis.get("reasoning_summary") or "Probability is computed from evidence factors, not model self-assessment."),
                confidence_factors=dict(confidence_breakdown.get("components") or {}),
                confidence_penalties=dict(confidence_breakdown.get("penalties") or {}),
                affected_resource_ids=list(hypothesis.get("affected_resource_ids") or []),
                causal_path=[str(item) for item in hypothesis.get("causal_sequence") or []],
                recommended_next_diagnostic=str(
                    (hypothesis.get("falsification_check") or {}).get("objective")
                    or "Collect independent causal evidence."
                ),
            ).model_dump(mode="json"))
        rca_result = RCAResult(
            incident_id=context.incident_id,
            correlation_id=investigation_plan.correlation_id,
            outcome=outcome,
            root_cause=str(leading.get("claim")) if outcome == ResolutionOutcome.EVIDENCE_SUPPORTED and leading else None,
            leading_hypothesis_id=str(leading.get("hypothesis_id")) if outcome == ResolutionOutcome.EVIDENCE_SUPPORTED and leading else None,
            confidence=float(leading.get("confidence") or 0.0) if leading else 0.0,
            supporting_evidence_ids=list(leading.get("supporting_evidence_ids") or []) if leading else [],
            contradicting_evidence_ids=contradictory,
            factors=dict(confidence_breakdown.get("components") or {}),
            penalties=dict(confidence_breakdown.get("penalties") or {}),
            missing_evidence=[*missing, *grounding_gaps],
            claims=self._build_claims(leading=leading, outcome=outcome, context=context, evidence=evidence),
        )
        graph_gaps = [*missing, *grounding_gaps]
        if contradictory:
            graph_gaps.append("unresolved_contradicting_evidence")
        if not hypotheses:
            graph_gaps.append("no_falsifiable_hypothesis")
        evidence_graph = build_incident_evidence_graph(
            tenant_id=context.tenant_id,
            incident_id=context.incident_id,
            evidence=evidence,
            hypotheses=hypotheses,
            conclusive_primary_id=(
                str(leading.get("hypothesis_id"))
                if outcome == ResolutionOutcome.EVIDENCE_SUPPORTED and leading
                else None
            ),
            data_gaps=graph_gaps,
        )
        report = {
            "schema_version": "kaims.iterative-investigation.v1",
            "investigation_id": investigation_id,
            "correlation_id": investigation_plan.correlation_id,
            "incident_id": str(context.incident_id),
            "alert_id": str(context.alert.id),
            "status": status.value,
            "stop_reason": stop_reason,
            "conclusive": status == InvestigationStatus.CONCLUSIVE,
            "started_at": started_at,
            "completed_at": datetime.now(UTC).isoformat(),
            "step_budget": self.max_steps,
            "steps_used": len(steps),
            "evidence_budget": self.max_evidence,
            "evidence_count": len(evidence),
            "source_coverage": coverage,
            "source_assessments": self._source_assessments(evidence, hypotheses),
            "diagnostic_decisions": diagnostic_decisions,
            "missing_sources": missing,
            "investigation_plan": investigation_plan.model_dump(mode="json"),
            "steps": steps,
            "hypotheses": hypotheses,
            "typed_hypotheses": typed_hypotheses,
            "outcome": outcome.value,
            "rca_result": rca_result.model_dump(mode="json"),
            "evidence_graph": evidence_graph.model_dump(mode="json"),
            "change_intelligence": {
                "correlations": list(leading.get("correlated_changes") or []) if leading else [],
                "change_correlation_score": float(leading.get("change_correlation") or 0.0) if leading else 0.0,
                "causal_proof": False,
            },
            "conclusion": {
                "hypothesis_id": leading.get("hypothesis_id") if leading else None,
                "claim": leading.get("claim") if leading else None,
                "confidence": leading.get("confidence") if leading else 0.0,
                "evidence_ids": leading.get("supporting_evidence_ids", []) if leading else [],
                # Lets a caller explain *why* an inconclusive result is inconclusive
                # (thin confidence vs. uncorroborated vs. no hypothesis at all)
                # instead of one generic message regardless of the actual cause.
                "independent_source_count": leading.get("independent_source_count", 0) if leading else 0,
                "causally_eligible": bool(leading and leading.get("source") != "derived_observation"),
                "conclusive_threshold": self.conclusive_threshold,
                "minimum_independent_sources": (max(2, self.minimum_independent_sources)
                    if leading and leading.get("mechanism") == "runtime_stopped" else self.minimum_independent_sources),
            },
            "next_evidence": [
                {"source": source, "tool": self.SOURCE_TOOL[source], "reason": "required evidence plane is missing"}
                for source in missing[:3]
            ],
            "evidence": evidence,
        }
        if persist:
            await persist("completed", report)
        INVESTIGATION_DURATION.observe(monotonic() - investigation_started)
        EVIDENCE_COUNT.set(len(evidence))
        HYPOTHESIS_COUNT.set(len(hypotheses))
        RESOLUTION_CONFIDENCE.set(float((report.get("conclusion") or {}).get("confidence") or 0.0))
        if not report["conclusive"]:
            INCONCLUSIVE_TOTAL.inc()
        return report


def hypothesis_digest(claim: str) -> str:
    return hashlib.sha256(str(claim or "").strip().lower().encode()).hexdigest()
