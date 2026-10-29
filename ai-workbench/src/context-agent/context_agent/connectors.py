from __future__ import annotations

from common.evidence_source_policy import is_alert_artifact_reference, log_observed_at
from common.evidence_subject import metric_matches_subject, service_identity

import asyncio
import hashlib
import heapq
import ipaddress
import json
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from time import monotonic
from typing import Any, TypedDict
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx
from ai_workbench_common.agent_runtime import AgentRuntime, ContextFailure
from ai_workbench_common.agentic import AgentContext, BaseAgent
from ai_workbench_common.embeddings import cosine_similarity, describe_embedding_model, get_embedding_model
from ai_workbench_common.models import Context
from common.config import get_settings
from common.context_enrichment_contract import (
    EnrichmentResult,
    EvidenceRequirement,
    next_authorized_enrichment_connector,
)
from common.models import Alert, Incident
from common.rag_governance import content_checksum, production_retrievable, retrieval_allowed
from common.resilience import retry_async
from common.tenant_identity import require_tenant_id
from common.tool_registry import ToolRegistry, ToolSpec
from langchain_core.embeddings import Embeddings
from langgraph.graph import END, StateGraph

from context_agent.context_quality import context_subject_fingerprint, govern_context, plan_connectors
from context_agent.knowledge_graph import KnowledgeGraph


class BaseConnector:
    name = "base"

    async def fetch(self, alert: Alert, incident: Incident) -> dict[str, Any]:
        raise NotImplementedError


async def execute_enrichment_plan(
    requirements: list[EvidenceRequirement],
    *,
    authorized_connectors: set[str] | None = None,
) -> EnrichmentResult:
    """Classify bounded read-only work without fabricating connector results."""
    authorized = authorized_connectors or set()
    scheduled: list[UUID] = []
    human: list[UUID] = []
    blocked: list[UUID] = []
    idempotency_keys: dict[UUID, str] = {}
    for requirement in requirements:
        if requirement.collection_mode == "human_required":
            human.append(requirement.requirement_id)
            continue
        connector = next_authorized_enrichment_connector(
            candidate_connectors=requirement.candidate_connectors,
            authorized_connectors=authorized,
        )
        if connector is None:
            human.append(requirement.requirement_id)
            continue
        material = (
            f"{requirement.tenant_id}:{requirement.incident_id}:"
            f"{requirement.requirement_id}:{connector}"
        )
        idempotency_keys[requirement.requirement_id] = hashlib.sha256(material.encode()).hexdigest()
        scheduled.append(requirement.requirement_id)
    return EnrichmentResult(
        scheduled_requirement_ids=scheduled,
        human_requirement_ids=human,
        blocked_requirement_ids=blocked,
        idempotency_keys=idempotency_keys,
    )


def _metadata_dict(alert: Alert, *keys: str) -> dict[str, Any]:
    metadata = alert.metadata if isinstance(alert.metadata, dict) else {}
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, dict):
            return dict(value)
    return {}


def _metadata_rows(alert: Alert, *keys: str) -> list[dict[str, Any]]:
    metadata = alert.metadata if isinstance(alert.metadata, dict) else {}
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, list):
            return [dict(row) for row in value if isinstance(row, dict)]
    return []


def _metadata_values(alert: Alert, *keys: str) -> list[str]:
    metadata = alert.metadata if isinstance(alert.metadata, dict) else {}
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str) and value.strip():
            return [item.strip() for item in value.split(",") if item.strip()]
    return []


class ServiceNowConnector(BaseConnector):
    name = "servicenow"

    async def fetch(self, alert: Alert, incident: Incident) -> dict[str, Any]:
        await asyncio.sleep(0)
        # This adapter only accepts facts carried by the normalized ingress
        # contract. Live ticket search belongs to discovery-mcp; manufacturing
        # a sample change here previously contaminated RCA for every incident.
        changes = _metadata_rows(alert, "change_records", "changes", "servicenow_changes")
        ticket = str(incident.ticket_id or alert.metadata.get("ticket_id") or "") or None
        if not changes and not ticket:
            return {}
        return {
            "ticket": ticket,
            "change_records": changes,
            "provenance": {"source": "alert-metadata", "grounded": bool(changes or incident.ticket_id)},
        }


class PrometheusConnector(BaseConnector):
    name = "prometheus"

    async def fetch(self, alert: Alert, incident: Incident) -> dict[str, Any]:
        snapshot = _metadata_dict(alert, "observability", "metrics", "prometheus")
        observed = _metadata_dict(alert, "observed_values", "signal")
        metadata = alert.metadata if isinstance(alert.metadata, dict) else {}
        resolved = (
            metadata.get("resolved_context_connectors")
            if isinstance(metadata.get("resolved_context_connectors"), list)
            else []
        )
        connector = next(
            (
                row
                for row in resolved
                if str(row.get("provider") or "").lower() in {"prometheus", "alertmanager"}
            ),
            None,
        )
        # Alertmanager includes the exact rule expression in generatorURL.
        # Preserve that source expression instead of guessing a metric name.
        annotations = alert.annotations if isinstance(alert.annotations, dict) else {}
        generator_url = str(annotations.get("generatorURL") or annotations.get("generator_url") or "").strip()
        generator_expression = ""
        if generator_url:
            query = parse_qs(urlsplit(generator_url).query)
            generator_expression = str((query.get("g0.expr") or query.get("query") or [""])[0]).strip()
        settings = get_settings()
        if connector is None and settings.environment.strip().lower() in {"local", "demo", "test"}:
            endpoint = str(settings.prometheus_url or "").rstrip("/")
            if endpoint and generator_expression and alert.source.lower() in {"prometheus", "alertmanager"}:
                connector = {
                    "integration_id": "local-runtime-prometheus",
                    "provider": "prometheus",
                    "endpoint_identity": endpoint,
                    "config": {},
                }
                metadata = {
                    **metadata,
                    "connector_resolution": {"status": "completed", "source": "local_runtime_configuration"},
                }
        if connector and (metadata.get("connector_resolution") or {}).get("status") == "completed":
            endpoint = str(connector.get("endpoint_identity") or "").rstrip("/")
            if not endpoint:
                return {"_source_status": "misconfigured", "error": "configured Prometheus endpoint is missing"}
            labels = alert.labels if isinstance(alert.labels, dict) else {}
            config = connector.get("config") if isinstance(connector.get("config"), dict) else {}
            expression = next(
                (
                    str(metadata.get(key) or labels.get(key) or "").strip()
                    for key in ("prometheus_expression", "rule_expression", "expression", "promql")
                    if str(metadata.get(key) or labels.get(key) or "").strip()
                ),
                "",
            )
            expression = expression or generator_expression
            if metadata.get("context_requirement_category") == "metrics":
                from common.metric_queries import filesystem_evidence_query
                expression = filesystem_evidence_query(
                    labels, question=str(metadata.get("context_requirement_question") or ""), alert_name=alert.name,
                ) or expression
            # Targeted external-probe evidence needs named, endpoint-bound
            # series. Aggregated alert expressions drop __name__ and can mix
            # multiple endpoints; they cannot satisfy this evidence request.
            probe_target = str(labels.get("instance") or "").strip()
            if (
                metadata.get("context_requirement_category") == "metrics"
                and str(labels.get("job") or "").lower() == "blackbox"
                and urlsplit(probe_target).scheme in {"http", "https"}
                and urlsplit(probe_target).netloc
            ):
                expression = (
                    '{__name__=~"probe_success|probe_http_status_code|probe_http_ssl|'
                    'probe_dns_lookup_time_seconds|probe_duration_seconds",job="blackbox",instance='
                    + json.dumps(probe_target) + '}'
                )
            metric_name = str(
                metadata.get("metric_name") or labels.get("__name__") or labels.get("metric") or ""
            ).strip()
            if not expression and metric_name:
                matchers = []
                for key in ("environment", "cluster", "namespace", "service", "instance", "job"):
                    fallback = alert.environment if key == "environment" else alert.service if key == "service" else ""
                    value = str(labels.get(key) or fallback).strip()
                    if value and re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", key):
                        escaped_value = value.replace('"', '\\"')
                        matchers.append(f'{key}="{escaped_value}"')
                expression = f'{metric_name}{{{",".join(matchers)}}}' if matchers else metric_name
            if not expression:
                return {
                    "_source_status": "misconfigured",
                    "error": "alert rule expression and metric identity are missing",
                }
            window_seconds = max(60, min(int(config.get("observation_window_seconds") or 900), 86400))
            now = datetime.now(UTC)
            alert_time = alert.starts_at or alert.created_at
            source_started_at = str(annotations.get("startsAt") or annotations.get("starts_at") or "").strip()
            if source_started_at:
                try:
                    alert_time = datetime.fromisoformat(source_started_at.replace("Z", "+00:00"))
                except ValueError:
                    pass
            if alert_time.tzinfo is None:
                alert_time = alert_time.replace(tzinfo=UTC)
            else:
                alert_time = alert_time.astimezone(UTC)
            # A fresh-analysis request can run long after the signal fired. Query
            # the alert's observation window in that case; querying only "now"
            # silently turns valid historical alerts into empty telemetry.
            if now - alert_time > timedelta(seconds=window_seconds):
                end = min(now, alert_time + timedelta(seconds=window_seconds / 2))
            else:
                end = now
            start = end - timedelta(seconds=window_seconds)
            requested_start = alert.metadata.get("context_observation_start")
            requested_end = alert.metadata.get("context_observation_end")
            if requested_start or requested_end:
                try:
                    start = datetime.fromisoformat(str(requested_start).replace("Z", "+00:00"))
                    end = datetime.fromisoformat(str(requested_end).replace("Z", "+00:00"))
                    if start.tzinfo is None or end.tzinfo is None or end <= start:
                        raise ValueError("invalid observation window")
                except (TypeError, ValueError):
                    return {"_source_status": "misconfigured", "evidence_gap": "INVALID_OBSERVATION_WINDOW"}
            params = {
                "query": expression,
                "start": start.timestamp(),
                "end": end.timestamp(),
                "step": max(15, min(int(config.get("step_seconds") or 60), 3600)),
            }
            headers: dict[str, str] = {}
            secret_ref = str(connector.get("secret_ref") or "")
            if secret_ref.startswith("env://"):
                token = os.getenv(secret_ref.removeprefix("env://"), "")
                if not token:
                    return {"_source_status": "unauthorized", "error": "configured environment secret is unavailable"}
                headers["Authorization"] = f"Bearer {token}"
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(f"{endpoint}/api/v1/query_range", params=params, headers=headers)
                if response.status_code in {401, 403}:
                    return {
                        "_source_status": "unauthorized",
                        "error": f"Prometheus returned HTTP {response.status_code}",
                    }
                response.raise_for_status()
                payload = response.json()
                result = ((payload.get("data") or {}).get("result") or []) if isinstance(payload, dict) else []
                all_series = result
                result = [row for row in all_series if isinstance(row, dict)
                          and metric_matches_subject(row.get("metric") or {}, alert.service,
                                                     target_labels=labels, query=expression)]
                return {
                    "rejected_series_count": len(all_series) - len(result),
                    "_source_status": "completed" if result else "empty",
                    "query": expression,
                    "query_kind": "range",
                    "endpoint_identity": endpoint,
                    "observation_window": {"start": params["start"], "end": params["end"], "step": params["step"]},
                    "observation_window_start": start.isoformat(),
                    "observation_window_end": end.isoformat(),
                    "series": result,
                    "preserved_labels": {
                        key: labels.get(key)
                        for key in ("environment", "cluster", "namespace", "service", "instance")
                        if labels.get(key)
                    },
                    "provenance": {
                        "source": "onboarded-prometheus",
                        "integration_id": connector.get("integration_id"),
                        "grounded": bool(result),
                    },
                }
            except httpx.TimeoutException:
                return {"_source_status": "timed_out", "error": "Prometheus range query timed out"}
            except (httpx.HTTPError, ValueError) as exc:
                return {"_source_status": "unavailable", "error": str(exc)[:300]}
        if not snapshot and not observed:
            return {}
        return {
            **snapshot,
            **observed,
            "observed_at": alert.created_at.isoformat(),
            "provenance": {"source": "alert-payload", "grounded": bool(snapshot or observed)},
        }


class KubernetesConnector(BaseConnector):
    name = "kubernetes"

    async def fetch(self, alert: Alert, incident: Incident) -> dict[str, Any]:
        await asyncio.sleep(0)
        supplied = _metadata_dict(alert, "kubernetes", "k8s", "runtime_topology")
        labels = alert.labels if isinstance(alert.labels, dict) else {}
        facts = {
            key: str(labels.get(key) or "").strip()
            for key in ("cluster", "namespace", "deployment", "statefulset", "daemonset", "pod", "container")
            if str(labels.get(key) or "").strip()
        }
        if not supplied and not facts:
            return {}
        return {**supplied, **facts, "provenance": {"source": "alert-metadata", "grounded": bool(supplied or facts)}}


class JenkinsConnector(BaseConnector):
    name = "jenkins"

    async def fetch(self, alert: Alert, incident: Incident) -> dict[str, Any]:
        await asyncio.sleep(0)
        deployments = _metadata_rows(alert, "recent_deployments", "deployments", "jenkins_builds")
        labels = alert.labels if isinstance(alert.labels, dict) else {}
        observed_version = str(labels.get("deployment") or labels.get("release") or labels.get("version") or "").strip()
        if observed_version and not deployments:
            deployments = [{"version": observed_version, "status": "observed", "source": "alert-label"}]
        if not deployments:
            return {}
        return {
            "recent_deployments": deployments,
            "provenance": {"source": "alert-metadata", "grounded": bool(deployments)},
        }


class GitHubConnector(BaseConnector):
    name = "github"

    async def fetch(self, alert: Alert, incident: Incident) -> dict[str, Any]:
        await asyncio.sleep(0)
        commits = _metadata_rows(alert, "recent_commits", "commits", "github_commits")
        if not commits:
            return {}
        return {
            "recent_commits": commits,
            "provenance": {"source": "alert-metadata", "grounded": bool(commits)},
        }


class CMDBConnector(BaseConnector):
    name = "cmdb"

    async def fetch(self, alert: Alert, incident: Incident) -> dict[str, Any]:
        await asyncio.sleep(0)
        supplied = _metadata_dict(alert, "cmdb", "service_inventory")
        dependencies = _metadata_values(alert, "dependencies", "dependency_services")
        owner_team = str(alert.metadata.get("owner_team") or alert.labels.get("owner_team") or "").strip()
        tier = str(alert.metadata.get("service_tier") or alert.labels.get("service_tier") or "").strip()
        if not supplied and not dependencies and not owner_team and not tier:
            return {}
        return {
            **supplied,
            "owner_team": owner_team or supplied.get("owner_team"),
            "tier": tier or supplied.get("tier"),
            "dependencies": dependencies or list(supplied.get("dependencies") or []),
            "provenance": {
                "source": "alert-metadata",
                "grounded": bool(supplied or dependencies or owner_team or tier),
            },
        }


class LocalEvidenceConnector(BaseConnector):
    """Find bounded, service-related evidence in mounted source code and logs."""

    name = "local-evidence"
    _code_suffixes = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".yml", ".yaml", ".json", ".md"}
    _log_suffixes = {".log", ".out", ".txt", ".json", ".jsonl"}

    def __init__(self) -> None:
        self.code_roots = self._roots(
            "CODE_DISCOVERY_ROOTS",
            "/app/backend/src,/app/ai-workbench/src,/app/scripts,/app/config,/app/observability,/app/backend/rag,/app/fault-lab",
        )
        self.log_roots = self._roots("LOG_DISCOVERY_ROOTS", "/data/fault-lab/runtime,/app/fault-lab/runtime")
        self.max_files = max(10, min(int(os.getenv("DISCOVERY_MAX_FILES", "180")), 1000))
        self.max_matches = max(1, min(int(os.getenv("DISCOVERY_MAX_MATCHES", "12")), 50))

    @staticmethod
    def _evidence_id(kind: str, path: str, line_number: int, snippet: str) -> str:
        digest = hashlib.sha256(f"{kind}|{path}|{line_number}|{snippet}".encode()).hexdigest()[:16]
        return f"{kind.upper()}-{digest}"

    @staticmethod
    def _roots(name: str, default: str) -> list[Path]:
        return [Path(value.strip()) for value in os.getenv(name, default).split(",") if value.strip()]

    @staticmethod
    def _terms(alert: Alert) -> list[str]:
        values = [
            alert.service,
            alert.name,
            alert.labels.get("scenario_id", ""),
            alert.labels.get("ticket_id", ""),
            alert.labels.get("component", ""),
        ]
        terms: list[str] = []
        for value in values:
            terms.extend(token.lower() for token in re.findall(r"[a-zA-Z0-9_.-]{3,}", str(value)))
        return list(dict.fromkeys(terms))[:20]

    def _search(self, roots: list[Path], suffixes: set[str], terms: list[str], kind: str) -> list[dict[str, Any]]:
        matches: list[tuple[int, dict[str, Any]]] = []
        scanned = 0
        excluded_dirs = {".git", ".claiming", "node_modules", "dist", "build", "__pycache__", ".venv", "kaiops.egg-info"}
        for root in roots:
            if not root.exists() or not root.is_dir():
                continue
            for path in root.rglob("*"):
                if scanned >= self.max_files:
                    break
                if any(part in excluded_dirs for part in path.parts):
                    continue
                if kind == "code" and (any(part in {"tests", "__tests__"} for part in path.parts)
                        or path.name.startswith("test_") or re.search(r"\.(test|spec)\.", path.name)):
                    continue
                if kind == "log" and is_alert_artifact_reference(path):
                    continue
                if not path.is_file() or path.suffix.lower() not in suffixes:
                    continue
                scanned += 1
                try:
                    if path.stat().st_size > 2_000_000:
                        continue
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                for line_number, line in enumerate(lines, 1):
                    lowered = line.lower()
                    score = sum(1 for term in terms if term in lowered)
                    if score:
                        match_text = line.strip()[:500]
                        context_start = max(1, line_number - 3)
                        context_end = min(len(lines), line_number + 3)
                        snippet = "\n".join(
                            f"{source_line:>5} | {lines[source_line - 1]}"
                            for source_line in range(context_start, context_end + 1)
                        )[:4000]
                        path_str = str(path)
                        matches.append(
                            (
                                score,
                                {
                                    "kind": kind,
                                    "source": kind,
                                    "path": path_str,
                                    "line": line_number,
                                    "context_start_line": context_start,
                                    "context_end_line": context_end,
                                    "language": path.suffix.lower().lstrip("."),
                                    "uri": f"{kind}://{path.as_posix()}#L{line_number}",
                                    "snippet": snippet,
                                    "matched_line": match_text,
                                    # normalize_connector_response()'s "logs" category requires a
                                    # "message" or "log" field to accept a record; without this alias
                                    # every log match here was rejected as EVIDENCE_REQUIRED_FIELD_MISSING
                                    # even when the search itself found a real, relevant line.
                                    "message": match_text,
                                    **({"observed_at": log_observed_at(line)} if kind == "log" and log_observed_at(line) else {}),
                                    "matched_terms": [term for term in terms if term in lowered],
                                    "evidence_id": self._evidence_id(kind, path_str, line_number, match_text),
                                },
                            )
                        )
        return [item for _, item in heapq.nlargest(self.max_matches, matches, key=lambda row: row[0])]

    async def fetch(self, alert: Alert, incident: Incident) -> dict[str, Any]:
        await asyncio.sleep(0)
        terms = self._terms(alert)
        aliases = {alert.service, service_identity(alert.service)}
        code_roots = list(dict.fromkeys(path for root in self.code_roots
            for path in [*([root] if root.name in aliases else []), *(root / alias for alias in aliases)]
            if path.is_dir()))
        if alert.service.lower().startswith(("robot-shop-", "rs-")):
            code_roots = [root for root in code_roots if "robot-shop" in root.parts]
        return {
            "query_terms": terms,
            "code_matches": self._search(code_roots, self._code_suffixes, terms, "code"),
            "log_matches": self._search(self.log_roots, self._log_suffixes, terms, "log"),
            "code_roots": [str(root) for root in code_roots],
            "log_roots": [str(root) for root in self.log_roots],
        }


class DiscoveryMCPConnector(BaseConnector):
    """Evidence-grounded discovery over a read-only MCP JSON-RPC server."""

    name = "discovery-mcp"
    _DISCOVERY_TOOL_ORDER = (
        "logs.search",
        "tickets.search",
        "code.search",
        "changes.search",
        "runbooks.search",
        "topology.search",
        "dependency-health.search",
        "resource-health.search",
        "mysql.search",
        "telemetry.search",
        "traces.search",
    )

    def __init__(self) -> None:
        self.mcp_url = os.getenv("DISCOVERY_MCP_URL", "http://discovery-mcp:8000/mcp")
        self.model_router_url = os.getenv("MODEL_ROUTER_URL", "http://model-router:8000").rstrip("/")
        self.timeout = max(2.0, min(float(os.getenv("DISCOVERY_MCP_TIMEOUT_SECONDS", "15")), 60.0))
        self.max_evidence = max(3, min(int(os.getenv("DISCOVERY_MCP_MAX_EVIDENCE", "18")), 40))
        self.model_analysis_enabled = str(
            os.getenv("CONTEXT_DISCOVERY_MODEL_ANALYSIS_ENABLED", "false")
        ).strip().lower() in {"1", "true", "yes", "on"}
        self.external_knowledge_enabled = str(
            os.getenv("RCA_EXTERNAL_KNOWLEDGE_ENABLED", "false")
        ).strip().lower() in {"1", "true", "yes", "on"}
        self.external_tools_enabled = str(
            os.getenv("RCA_EXTERNAL_TOOLS_ENABLED", "false")
        ).strip().lower() in {"1", "true", "yes", "on"}
        self.external_escalation_threshold = max(
            0.0,
            min(1.0, float(os.getenv("RCA_EXTERNAL_ESCALATION_CONFIDENCE_THRESHOLD", "0.65"))),
        )

    @staticmethod
    def _internal_url(url: str) -> bool:
        host = str(urlsplit(url).hostname or "").strip().lower()
        if not host or host == "localhost" or host.endswith((".local", ".internal")) or "." not in host:
            return True
        try:
            address = ipaddress.ip_address(host)
            return address.is_private or address.is_loopback
        except ValueError:
            return False

    @staticmethod
    def _safe_proxy_description(proxy_url: str | None) -> dict[str, Any]:
        if not proxy_url:
            return {"configured": False}
        parsed = urlsplit(proxy_url)
        return {
            "configured": True,
            "scheme": parsed.scheme.lower(),
            "host": parsed.hostname or "",
            "port": parsed.port,
            "credentials_redacted": bool(parsed.username or parsed.password),
        }

    def _client_policy(self, target_url: str) -> tuple[dict[str, Any], dict[str, Any]]:
        internal = self._internal_url(target_url)
        proxy_url = str(os.getenv("DISCOVERY_MCP_PROXY_URL") or "").strip() or None
        if internal:
            return {"timeout": self.timeout, "trust_env": False}, {
                "target": "internal", "trust_env": False, "proxy": {"configured": False},
            }
        if proxy_url:
            scheme = str(urlsplit(proxy_url).scheme or "").lower()
            if scheme not in {"http", "https", "socks5", "socks5h"}:
                raise ValueError(f"Unsupported discovery proxy scheme: {scheme or 'missing'}")
        options: dict[str, Any] = {"timeout": self.timeout, "trust_env": False}
        if proxy_url:
            options["proxy"] = proxy_url
        return options, {
            "target": "external", "trust_env": False,
            "proxy": self._safe_proxy_description(proxy_url),
        }

    def _build_client(self, target_url: str) -> tuple[httpx.AsyncClient, dict[str, Any]]:
        options, policy = self._client_policy(target_url)
        return httpx.AsyncClient(**options), policy

    def _degraded_discovery(
        self, *, terms: list[str], tools: list[str], stages: list[dict[str, Any]], error: Exception
    ) -> dict[str, Any]:
        message = str(error)[:240] or type(error).__name__
        failed_stages = [
            *stages,
            {"stage": "client_construction", "status": "failed", "error": message},
            {"stage": "discovery_completed", "status": "degraded", "result_count": 0},
        ]
        return {
            "protocol": "mcp-jsonrpc-2.0",
            "server": self.mcp_url,
            "provider_status": "degraded",
            "query_terms": terms,
            "collection_plan": {"mode": "adaptive", "selected_tools": tools},
            "evidence": [],
            "evidence_gap": {
                "source": self.name,
                "reason": "discovery_client_unavailable",
                "detail": message,
                "execution_ready": False,
                "confidence_ceiling": 0.49,
            },
            "report": {
                "summary": "Discovery evidence is unavailable; root cause remains ungrounded.",
                "hypotheses": [],
                "insufficient_evidence": True,
                "confidence_ceiling": 0.49,
            },
            "detected_errors": [],
            "retrieval_stages": failed_stages,
            "model_usage": {},
            "model_interaction": {"task": "rca", "status": "skipped", "reason": "discovery_client_unavailable"},
        }

    @staticmethod
    def _query_terms(alert: Alert, incident: Incident) -> list[str]:
        values = [
            alert.service,
            alert.name,
            alert.environment,
            alert.correlation_id,
            alert.trace_id,
            incident.ticket_id,
            alert.labels.get("scenario_id"),
            alert.labels.get("component"),
            alert.labels.get("ticket_id"),
            alert.labels.get("application"),
            alert.labels.get("project"),
        ]
        terms: list[str] = []
        for value in values:
            terms.extend(re.findall(r"[a-zA-Z0-9_.-]{3,}", str(value or "").lower()))
        return list(dict.fromkeys(terms))[:24]

    @classmethod
    def _plan_discovery_tools(cls, alert: Alert) -> tuple[list[str], list[str]]:
        """Route an alert to relevant read-only evidence systems."""

        labels = alert.labels if isinstance(alert.labels, dict) else {}
        annotations = alert.annotations if isinstance(alert.annotations, dict) else {}
        metadata = alert.metadata if isinstance(alert.metadata, dict) else {}
        source = str(alert.source or "").strip().lower()
        raw_haystack = " ".join(
            [
                source,
                str(alert.service or ""),
                str(alert.name or ""),
                str(alert.description or ""),
                " ".join(f"{key}={value}" for key, value in labels.items()),
                " ".join(f"{key}={value}" for key, value in annotations.items()),
            ]
        )
        haystack = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", raw_haystack).lower()
        selected: set[str] = set()
        reasons: list[str] = []

        requirement_category = str(metadata.get("context_requirement_category") or "").strip().lower()
        requested_collection_tool = str(metadata.get("context_collection_tool") or "").strip()
        targeted_tools = {
            "metrics": "telemetry.search",
            "logs": "logs.search",
            "traces": "traces.search",
            "database": "mysql.search",
            "ticket": "tickets.search",
            "source_code": "code.search",
            "deployment": "changes.search",
            "change": "changes.search",
            "topology": "topology.search",
            "runbook": "runbooks.search",
            "validation": "telemetry.search",
        }
        if requested_collection_tool in cls._DISCOVERY_TOOL_ORDER:
            return [requested_collection_tool], ["evidence_requirement"]
        if requirement_category in targeted_tools:
            return [targeted_tools[requirement_category]], ["evidence_requirement"]

        if source in {"prometheus", "grafana", "azure-monitor", "datadog", "newrelic", "otel", "opentelemetry"}:
            selected.add("telemetry.search")
            reasons.append("metric_or_trace_signal")
        elif source in {"logs", "log", "opensearch", "elasticsearch", "loki", "splunk"}:
            selected.add("logs.search")
            reasons.append("log_signal")
        elif source in {"jira", "servicenow", "ticket", "email"}:
            selected.add("tickets.search")
            reasons.append("ticket_or_human_report")
        else:
            selected.update({"logs.search", "telemetry.search"})
            reasons.append("unknown_source_observation_baseline")

        if re.search(
            r"\b(error|exception|traceback|stacktrace|crash|crashloop|panic|segfault|"
            r"failed|failure|timeout|timed out|refused|unavailable|unreachable|5\d\d)\b",
            haystack,
        ):
            selected.add("logs.search")
            reasons.append("failure_diagnostics")

        if re.search(r"\b(deploy|deployment|release|rollout|revision|commit|build|change|regression)\b", haystack):
            selected.update({"tickets.search", "code.search"})
            reasons.append("change_correlation")

        if re.search(r"\b(code|source|function|module|package|config|configuration|stacktrace|traceback)\b", haystack):
            selected.add("code.search")
            reasons.append("source_or_configuration_diagnostics")

        if re.search(r"\b(down|unavailable|unreachable|availability|refused|crash|crashloop)\b", haystack):
            selected.update({"logs.search", "topology.search", "dependency-health.search", "resource-health.search"})
            reasons.append("availability_runtime_diagnostics")

        database_identity = any(
            str(labels.get(key) or metadata.get(key) or "").strip()
            for key in ("database", "database_name", "schema", "table", "query_id")
        )
        if database_identity or re.search(
            r"\b(mysql|mariadb|database|sql|query|deadlock|replica|replication|innodb|connection pool)\b",
            haystack,
        ):
            selected.add("mysql.search")
            reasons.append("database_diagnostics")

        has_history_signal = bool(
            int(getattr(alert, "deduplicated_count", 1) or 1) > 1
            or re.search(r"\b(recurring|repeat|reopened|known issue|previous incident|problem record)\b", haystack)
            or any(str(labels.get(key) or metadata.get(key) or "").strip() for key in ("ticket_id", "incident_id", "problem_id"))
        )
        if has_history_signal:
            selected.add("tickets.search")
            reasons.append("incident_history")

        requested = metadata.get("context_sources")
        if isinstance(requested, str):
            requested = [item.strip() for item in requested.split(",")]
        if isinstance(requested, list):
            aliases = {
                "logs": "logs.search",
                "tickets": "tickets.search",
                "code": "code.search",
                "database": "mysql.search",
                "mysql": "mysql.search",
                "telemetry": "telemetry.search",
                "traces": "traces.search",
            }
            explicit = {
                aliases.get(str(item).strip().lower(), str(item).strip().lower())
                for item in requested
            }
            explicit.intersection_update(cls._DISCOVERY_TOOL_ORDER)
            if explicit:
                selected.update(explicit)
                reasons.append("explicit_source_request")

        from common.diagnostic_runbooks import diagnostic_tools
        guidance = diagnostic_tools(metadata.get("diagnostic_runbook"), tenant_id=alert.tenant_id,
                                    service=alert.service, environment=alert.environment)
        if guidance:
            selected.update(guidance[:3])
            reasons.append("scoped_diagnostic_runbook")
        if not selected:
            selected.update({"logs.search", "telemetry.search"})
            reasons.append("safe_observation_fallback")
        return [tool for tool in cls._DISCOVERY_TOOL_ORDER if tool in selected], list(dict.fromkeys(reasons))

    @staticmethod
    def _validated_code_review(report: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
        """Keep only code-review findings grounded in retrieved source evidence."""
        code_evidence = {
            str(row.get("evidence_id")): row
            for row in evidence
            if isinstance(row, dict)
            and str(row.get("source") or "").strip().lower() == "code"
            and str(row.get("evidence_id") or "").strip()
        }
        candidate = report.get("code_review") if isinstance(report.get("code_review"), dict) else {}
        findings = candidate.get("findings") if isinstance(candidate.get("findings"), list) else []
        reviewed_sources = []
        for evidence_id, source in code_evidence.items():
            reviewed_sources.append(
                {
                    "evidence_id": evidence_id,
                    "source_uri": str(source.get("uri") or source.get("path") or "").strip()[:1000],
                    "snippet": str(
                        source.get("snippet")
                        or source.get("content")
                        or source.get("summary")
                        or ""
                    ).strip()[:1200],
                }
            )
        validated: list[dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            evidence_id = str(finding.get("evidence_id") or "").strip()
            if evidence_id not in code_evidence:
                continue
            source = code_evidence[evidence_id]
            patch = str(finding.get("patch") or "").strip()
            # A displayed patch must be a recognizable unified diff, not prose
            # presented as code.
            if patch and not ("--- " in patch and "+++ " in patch and "@@" in patch):
                patch = ""
            validated.append(
                {
                    "title": str(finding.get("title") or "Source-code finding").strip()[:200],
                    "severity": str(finding.get("severity") or "review").strip().lower()[:20],
                    "explanation": str(finding.get("explanation") or "").strip()[:1200],
                    "evidence_id": evidence_id,
                    "source_uri": str(source.get("uri") or source.get("path") or ""),
                    "patch": patch[:8000],
                    "patch_limitations": str(finding.get("patch_limitations") or "").strip()[:600],
                }
            )
        proposed_changes = [
            {
                "title": finding["title"],
                "explanation": finding["explanation"],
                "evidence_id": finding["evidence_id"],
                "source_uri": finding["source_uri"],
                "patch": finding["patch"],
                "limitations": finding["patch_limitations"],
                "ready_to_apply": bool(finding["patch"]),
            }
            for finding in validated
            if finding["patch"] or finding["explanation"]
        ]
        return {
            "status": "completed" if code_evidence else "not_performed",
            "summary": (
                str(
                    candidate.get("summary")
                    or (
                        f"{len(validated)} evidence-grounded code finding(s) were identified."
                        if validated
                        else "Source code was reviewed, but no evidence-grounded issue or safe patch was identified."
                    )
                ).strip()[:600]
                if code_evidence
                else "No source-code evidence was retrieved, so no code review or patch was produced."
            ),
            "findings": validated,
            "proposed_changes": proposed_changes,
            "reviewed_evidence_ids": list(code_evidence),
            "reviewed_sources": reviewed_sources,
            "insufficient_context": bool(candidate.get("insufficient_context")) or not bool(code_evidence),
        }

    async def _call_mcp(
        self,
        client: httpx.AsyncClient,
        tool: str,
        terms: list[str],
        alert: Alert,
    ) -> dict[str, Any]:
        arguments = {
            "terms": terms,
            "tenant_id": alert.tenant_id,
            "limit": 8,
            "service": alert.service,
            "alert_name": alert.name,
            "trace_id": str(alert.trace_id or ""),
            "evidence_category": str(alert.metadata.get("context_requirement_category") or ""),
            "question": str(alert.metadata.get("context_requirement_question") or ""),
            "application": str(alert.metadata.get("application") or alert.labels.get("application") or ""),
            "project": str(alert.metadata.get("project_id") or alert.metadata.get("project") or alert.labels.get("project_id") or alert.labels.get("project") or ""),
            "environment": alert.environment,
            "operation": str(alert.labels.get("operation") or alert.metadata.get("operation") or ""),
            "target_labels": {key: alert.labels[key] for key in ("job", "instance", "namespace", "cluster", "operation", "http_route", "route", "device", "mountpoint") if alert.labels.get(key)},
            "database": str(alert.labels.get("database") or alert.labels.get("database_name") or alert.metadata.get("database") or ""),
            "table": str(alert.labels.get("table") or alert.metadata.get("table") or ""),
            "start_time": str(alert.metadata.get("context_observation_start") or ""),
            "end_time": str(alert.metadata.get("context_observation_end") or ""),
        }
        response = await client.post(
            self.mcp_url,
            json={
                "jsonrpc": "2.0",
                "id": tool,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            },
        )
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload.get("error"), dict):
            raise RuntimeError(str(payload["error"].get("message") or "MCP tool failed"))
        return payload.get("result") if isinstance(payload.get("result"), dict) else {}

    @staticmethod
    def _json_object(content: Any) -> dict[str, Any] | None:
        text = str(content or "").strip()
        fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE)
        candidates = [fenced.group(1).strip()] if fenced else []
        candidates.append(text)
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            candidates.append(text[start:end + 1])
        for candidate in candidates:
            try:
                parsed = json.loads(candidate)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, dict):
                return parsed
        return None

    @staticmethod
    def _fallback_report(evidence: list[dict[str, Any]], stages: list[dict[str, Any]]) -> dict[str, Any]:
        citations = [str(row.get("evidence_id")) for row in evidence[:6] if row.get("evidence_id")]
        return {
            "summary": "Evidence was retrieved; model synthesis was unavailable.",
            "hypotheses": [],
            "affected_components": [],
            "recommended_next_checks": ["Review the cited evidence and collect additional targeted signals."],
            "insufficient_evidence": not bool(evidence),
            "citations": citations,
            "retrieval_stages": stages,
        }

    @staticmethod
    def _detected_errors(
        evidence: list[dict[str, Any]],
        alert: Alert | None = None,
        incident: Incident | None = None,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        generic_terms = {
            "alert",
            "application",
            "critical",
            "error",
            "failed",
            "failure",
            "high",
            "incident",
            "prod",
            "production",
            "service",
            "warning",
        }
        identity_values = [
            getattr(alert, "service", None),
            getattr(incident, "service", None),
        ]
        if alert is not None:
            identity_values.extend(
                (alert.labels or {}).get(key)
                for key in ("application", "project", "project_name", "component")
            )
        identity_tokens = {
            token
            for value in identity_values
            for token in re.findall(r"[a-zA-Z0-9_.-]{3,}", str(value or "").lower())
            if token not in generic_terms
        }
        correlation_values = {
            str(value).strip().lower()
            for value in (
                getattr(alert, "id", None),
                getattr(alert, "trace_id", None),
                getattr(alert, "correlation_id", None),
                getattr(incident, "id", None),
                getattr(incident, "trace_id", None),
            )
            if str(value or "").strip()
        }
        significant_signals = {
            "connection_refused",
            "timeout",
            "authentication",
            "resource_exhaustion",
            "dependency_unavailable",
            "exception",
            "http_5xx",
            "error",
        }
        for row in evidence:
            if not isinstance(row, dict) or str(row.get("signal_type") or "") == "log_diagnosis":
                continue
            raw_signals = row.get("diagnostic_signals") if isinstance(row.get("diagnostic_signals"), list) else []
            signals = [str(signal) for signal in raw_signals if str(signal) in significant_signals]
            if not signals:
                continue
            snippet = str(row.get("snippet") or "").strip()
            if alert is not None or incident is not None:
                row_identity = " ".join(
                    str(row.get(key) or "").lower()
                    for key in ("service", "container", "uri", "path")
                )
                searchable = f"{row_identity} {snippet.lower()}"
                matched_terms = {
                    str(term).strip().lower()
                    for term in (row.get("matched_terms") or [])
                    if str(term).strip().lower() not in generic_terms
                }
                identity_match = any(token in searchable for token in identity_tokens)
                correlation_match = any(value in searchable for value in correlation_values)
                query_match = bool(matched_terms)
                if not (identity_match or correlation_match or query_match):
                    continue
            identity = (str(row.get("container") or row.get("service") or ""), snippet)
            if identity in seen:
                continue
            seen.add(identity)
            timestamp_match = re.match(r"^(\d{4}-\d{2}-\d{2}T[^\s]+)", snippet)
            findings.append(
                {
                    "evidence_id": row.get("evidence_id"),
                    "service": row.get("service"),
                    "container": row.get("container"),
                    "timestamp": timestamp_match.group(1) if timestamp_match else None,
                    "signals": signals,
                    "message": snippet[:700],
                    "source_uri": row.get("uri") or row.get("path"),
                }
            )
            if len(findings) >= 12:
                break
        return findings

    async def _analyze(
        self, client: httpx.AsyncClient, alert: Alert, evidence: list[dict[str, Any]], stages: list[dict[str, Any]]
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        compact = [
            {
                "evidence_id": row.get("evidence_id"),
                "source": row.get("source"),
                "uri": row.get("uri"),
                "snippet": row.get("snippet"),
            }
            for row in evidence[: self.max_evidence]
        ]
        prompt = (
            "Analyze only the supplied evidence. Return strict JSON with summary, hypotheses "
            "(cause, confidence 0..1, supporting_evidence, contradicting_evidence), "
            "affected_components, recommended_next_checks, insufficient_evidence, citations, and code_review. "
            "Every factual conclusion must cite evidence_id. Never invent a root cause. "
            "code_review must be an object with summary, insufficient_context, and findings. Each finding must "
            "contain title, severity, explanation, evidence_id, patch, and patch_limitations. Review only evidence "
            "whose source is exactly 'code'. A finding is allowed only when its evidence_id identifies the exact "
            "source snippet supporting it. patch must be a minimal unified diff with ---/+++/@@ headers, preserving "
            "the source URI path, and must address only the cited issue. If the supplied snippet does not contain "
            "enough surrounding code to construct a safe patch, return an empty patch and explain what context is "
            "missing in patch_limitations. Never infer a file, function, variable, dependency, or replacement code "
            "that is absent from the supplied code evidence. If there is no code evidence, return findings: [], "
            "insufficient_context: true."
        )
        request_payload = {
            "alert": {
                "name": alert.name,
                "service": alert.service,
                "environment": alert.environment,
            },
            "evidence": compact,
        }
        response = await client.post(
            f"{self.model_router_url}/route",
            json={
                "severity": str(getattr(alert.severity, "value", alert.severity)),
                "task": "rca",
                "prompt": prompt,
                "payload": request_payload,
            },
        )
        response.raise_for_status()
        routed = response.json()
        content = routed.get("content")
        report = self._json_object(content) if isinstance(content, str) else content
        if (
            str(routed.get("model") or "").lower() == "heuristic-fallback"
            or not isinstance(report, dict)
            or "hypotheses" not in report
            or not isinstance(report.get("hypotheses"), list)
            or "insufficient_evidence" not in report
        ):
            report = self._fallback_report(evidence, stages)
        report["code_review"] = self._validated_code_review(report, evidence)
        report["proposed_code_changes"] = report["code_review"]["proposed_changes"]
        hypotheses = report.get("hypotheses") if isinstance(report.get("hypotheses"), list) else []
        confidence_values: list[float] = []
        for item in hypotheses:
            if not isinstance(item, dict):
                continue
            try:
                confidence_values.append(float(item.get("confidence") or 0.0))
            except (TypeError, ValueError):
                continue
        best_confidence = max(confidence_values, default=0.0)
        needs_external_knowledge = bool(report.get("insufficient_evidence")) or best_confidence < self.external_escalation_threshold
        report["external_knowledge_eligible"] = needs_external_knowledge
        report["external_knowledge_used"] = False
        report["external_tools_used"] = sorted(
            {
                str(row.get("tool") or row.get("source"))
                for row in evidence
                if isinstance(row, dict)
                and str(row.get("source") or row.get("tool") or "").lower()
                in {"external", "external.search", "web", "web-search"}
            }
        )
        if self.external_knowledge_enabled and needs_external_knowledge:
            external_prompt = (
                "Use general SRE and product knowledge only to propose diagnostic hypotheses for the supplied local "
                "evidence. Return strict JSON with summary, hypotheses (cause, confidence 0..1, supporting_evidence, "
                "contradicting_evidence, knowledge_basis), affected_components, recommended_next_checks, "
                "insufficient_evidence, and citations. Never present external knowledge as an observed fact. "
                "Prefix knowledge-only citations with external-knowledge:// and cap confidence at 0.60 unless local "
                "evidence directly supports the hypothesis."
            )
            try:
                external_response = await client.post(
                    f"{self.model_router_url}/route",
                    json={
                        "severity": str(getattr(alert.severity, "value", alert.severity)),
                        "task": "rca",
                        "prompt": external_prompt,
                        "payload": {"alert": request_payload["alert"], "local_evidence": compact, "local_analysis": report},
                    },
                )
                external_response.raise_for_status()
                external_routed = external_response.json()
                external_content = external_routed.get("content")
                external_report = self._json_object(external_content) if isinstance(external_content, str) else external_content
                if isinstance(external_report, dict):
                    report = {
                        **external_report,
                        "external_knowledge_eligible": True,
                        "external_knowledge_used": True,
                        "external_tools_used": report.get("external_tools_used", []),
                        "local_analysis": report,
                    }
                    routed = external_routed
                    content = external_content
            except Exception as exc:
                report["external_knowledge_error"] = str(exc)[:300]
        report["retrieval_stages"] = stages
        report["evidence_count"] = len(evidence)
        report["model"] = routed.get("model", "unknown")
        usage = routed.get("usage") if isinstance(routed.get("usage"), dict) else {}
        interaction = {
            "task": "rca",
            "endpoint": f"{self.model_router_url}/route",
            "prompt": prompt,
            "request_payload": request_payload,
            "response_received": content,
            "parsed_response": report,
            "model": routed.get("model", "unknown"),
            "provider": routed.get("provider", "unknown"),
            "usage": usage,
        }
        return report, usage, interaction

    async def fetch(self, alert: Alert, incident: Incident) -> dict[str, Any]:
        terms = self._query_terms(alert, incident)
        discovery_tools, routing_reasons = self._plan_discovery_tools(alert)
        skipped_tools = [tool for tool in self._DISCOVERY_TOOL_ORDER if tool not in discovery_tools]
        stages: list[dict[str, Any]] = [
            {
                "stage": "query_planned",
                "status": "completed",
                "terms": terms,
                "selected_tools": discovery_tools,
                "skipped_tools": skipped_tools,
                "reasons": routing_reasons,
            },
            *(
                {
                    "stage": tool.replace(".", "_"),
                    "status": "skipped",
                    "reason": "not_selected_by_context_policy",
                    "result_count": 0,
                }
                for tool in skipped_tools
            ),
        ]
        evidence_by_tool: dict[str, list[dict[str, Any]]] = {}
        evidence_gaps: list[str] = []
        client: httpx.AsyncClient | None = None
        try:
            client, mcp_proxy_policy = self._build_client(self.mcp_url)
            model_client, model_proxy_policy = self._build_client(self.model_router_url)
        except Exception as exc:
            if client is not None:
                await client.aclose()
            return self._degraded_discovery(terms=terms, tools=discovery_tools, stages=stages, error=exc)
        async with client, model_client:
            results = await asyncio.gather(
                *(
                    self._call_mcp(client, tool, terms, alert)
                    for tool in discovery_tools
                ),
                return_exceptions=True,
            )
            for tool, result in zip(discovery_tools, results, strict=True):
                if isinstance(result, Exception):
                    stages.append({"stage": tool.replace(".", "_"), "status": "failed", "error": str(result)[:240]})
                    continue
                rows = result.get("evidence", []) if isinstance(result.get("evidence"), list) else []
                evidence_by_tool[tool] = [row for row in rows if isinstance(row, dict)]
                evidence_gap = str(result.get("evidence_gap") or "").strip()
                if evidence_gap:
                    evidence_gaps.append(evidence_gap)
                provider_status = str(result.get("provider_status") or "completed")
                stages.append(
                    {
                        "stage": tool.replace(".", "_"),
                        "status": provider_status,
                        "result_count": len(rows),
                        "error": result.get("provider_error"),
                    }
                )
            local_evidence_count = sum(len(rows) for rows in evidence_by_tool.values())
            if self.external_tools_enabled and local_evidence_count == 0:
                try:
                    external_result = await self._call_mcp(client, "external.search", terms, alert)
                    external_rows = (
                        external_result.get("evidence", [])
                        if isinstance(external_result.get("evidence"), list)
                        else []
                    )
                    evidence_by_tool["external.search"] = [
                        row for row in external_rows if isinstance(row, dict)
                    ]
                    discovery_tools.append("external.search")
                    stages.append(
                        {
                            "stage": "external_search",
                            "status": str(external_result.get("provider_status") or "completed"),
                            "result_count": len(external_rows),
                            "reason": "no_local_evidence",
                            "error": external_result.get("provider_error"),
                        }
                    )
                except Exception as exc:
                    discovery_tools.append("external.search")
                    stages.append(
                        {
                            "stage": "external_search",
                            "status": "failed",
                            "reason": "no_local_evidence",
                            "error": str(exc)[:240],
                        }
                    )
            else:
                stages.append(
                    {
                        "stage": "external_search",
                        "status": "skipped",
                        "reason": "disabled" if not self.external_tools_enabled else "local_evidence_available",
                        "result_count": 0,
                    }
                )
            deduped: list[dict[str, Any]] = []
            seen: set[str] = set()
            tool_order = tuple(discovery_tools)
            max_rows = max((len(evidence_by_tool.get(tool, [])) for tool in tool_order), default=0)
            for index in range(max_rows):
                for tool in tool_order:
                    rows = evidence_by_tool.get(tool, [])
                    if index >= len(rows):
                        continue
                    row = rows[index]
                    evidence_id = str(row.get("evidence_id") or "")
                    if evidence_id and evidence_id in seen:
                        continue
                    if evidence_id:
                        seen.add(evidence_id)
                    deduped.append(row)
                    if len(deduped) >= self.max_evidence:
                        break
                if len(deduped) >= self.max_evidence:
                    break
            stages.append({"stage": "evidence_correlated", "status": "completed", "result_count": len(deduped)})
            try:
                if not self.model_analysis_enabled:
                    report = self._fallback_report(deduped, stages)
                    usage = {}
                    model_interaction = {
                        "task": "rca",
                        "status": "deferred_to_resolution_agent",
                        "request_payload": {"evidence_count": len(deduped)},
                        "response_received": None,
                    }
                    stages.append({"stage": "llm_analysis", "status": "deferred_to_resolution_agent"})
                else:
                    report, usage, model_interaction = await self._analyze(model_client, alert, deduped, stages)
                    stages.append({"stage": "llm_analysis", "status": "completed", "model": report.get("model")})
            except Exception as exc:
                report = self._fallback_report(deduped, stages)
                usage = {}
                model_interaction = {
                    "task": "rca",
                    "status": "failed",
                    "error": str(exc)[:500],
                    "prompt": "Evidence-grounded RCA analysis",
                    "request_payload": {"evidence_count": len(deduped)},
                    "response_received": None,
                }
                stages.append({"stage": "llm_analysis", "status": "failed", "error": str(exc)[:240]})
        error_candidates = [
            row
            for row in deduped
            if isinstance(row, dict)
            and str(row.get("signal_type") or "") != "log_diagnosis"
            and isinstance(row.get("diagnostic_signals"), list)
            and row.get("diagnostic_signals")
        ]
        detected_errors = self._detected_errors(deduped, alert, incident)
        report["detected_errors"] = detected_errors
        report["detected_error_count"] = len(detected_errors)
        report["detected_error_candidates_excluded"] = max(0, len(error_candidates) - len(detected_errors))
        stages.append({"stage": "discovery_completed", "status": "completed"})
        report["retrieval_stages"] = stages
        return {
            "protocol": "mcp-jsonrpc-2.0",
            "server": self.mcp_url,
            "query_terms": terms,
            "collection_plan": {
                "mode": "adaptive",
                "selected_tools": discovery_tools,
                "skipped_tools": skipped_tools,
                "reasons": routing_reasons,
            },
            "evidence": deduped,
            "evidence_gap": evidence_gaps[0] if evidence_gaps and not deduped else "",
            "report": report,
            "detected_errors": detected_errors,
            "retrieval_stages": stages,
            "model_usage": usage,
            "model_interaction": model_interaction,
            "proxy_policy": {"discovery": mcp_proxy_policy, "model_router": model_proxy_policy},
        }


class AzureAISearchVectorStore:
    """REST-backed Azure AI Search adapter for production RAG retrieval."""

    def __init__(self, *, settings: Any, embedding_model: Embeddings) -> None:
        self._endpoint = str(getattr(settings, "azure_ai_search_endpoint", "") or "").strip().rstrip("/")
        self._api_key = str(getattr(settings, "azure_ai_search_api_key", "") or "").strip()
        self._index_name = str(getattr(settings, "azure_ai_search_index_name", "kaiops-rag") or "kaiops-rag").strip()
        self._api_version = str(getattr(settings, "azure_ai_search_api_version", "2024-07-01") or "2024-07-01")
        self._content_field = str(getattr(settings, "azure_ai_search_content_field", "content") or "content")
        self._vector_field = str(getattr(settings, "azure_ai_search_vector_field", "content_vector") or "content_vector")
        self._timeout_seconds = float(getattr(settings, "azure_ai_search_timeout_seconds", 8.0) or 8.0)
        self._embedding_model = embedding_model
        self.enabled = bool(getattr(settings, "azure_ai_search_enabled", False))
        self.last_error: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.enabled and self._endpoint and self._api_key and self._index_name)

    def info(self) -> dict[str, Any]:
        return {
            "provider": "azure-ai-search" if self.configured else "file-backed-memory",
            "engine": "AzureAISearchVectorStore" if self.configured else "VectorDBConnector",
            "persistent_index": bool(self.configured),
            "storage": "azure-ai-search-index" if self.configured else "markdown-files",
            "endpoint": self._endpoint if self.configured else "",
            "index_name": self._index_name if self.configured else "",
            "content_field": self._content_field if self.configured else "",
            "vector_field": self._vector_field if self.configured else "",
            "last_error": self.last_error,
            "enterprise_ready": bool(self.configured),
        }

    def _headers(self) -> dict[str, str]:
        return {"api-key": self._api_key, "Content-Type": "application/json"}

    def _url(self, path: str) -> str:
        return f"{self._endpoint}/indexes/{self._index_name}{path}?api-version={self._api_version}"

    def _odata_literal(self, value: str) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    def _filter(self, *, preferred_kinds: set[str] | None, service: str | None, tenant_id: str) -> str | None:
        tenant = str(tenant_id or "").strip()
        if not tenant:
            raise ValueError("remote RAG search requires authenticated tenant identity")
        filters: list[str] = [
            "("
            f"(tenant_scope eq {self._odata_literal(tenant)} and corpus_classification eq 'TENANT_CURATED')"
            " or (tenant_scope eq 'global' and corpus_classification eq 'PRODUCTION_CURATED')"
            ")",
            "review_status eq 'approved'",
        ]
        kinds = sorted({str(item).strip().lower() for item in (preferred_kinds or set()) if str(item).strip()})
        if kinds:
            filters.append("(" + " or ".join(f"kind eq {self._odata_literal(kind)}" for kind in kinds) + ")")
        normalized_service = str(service or "").strip().lower()
        if normalized_service:
            filters.append(f"services/any(service: search.in(service, {self._odata_literal(normalized_service)}, ','))")
        return " and ".join(filters) if filters else None

    def _chunk_text(self, text: str, *, max_chars: int = 1800, overlap_chars: int = 240) -> list[str]:
        normalized = re.sub(r"\n{3,}", "\n\n", str(text or "").strip())
        if not normalized:
            return []
        chunks: list[str] = []
        start = 0
        while start < len(normalized):
            end = min(len(normalized), start + max_chars)
            if end < len(normalized):
                paragraph_break = normalized.rfind("\n\n", start, end)
                if paragraph_break > start + 400:
                    end = paragraph_break
            chunk = normalized[start:end].strip()
            if chunk:
                chunks.append(chunk)
            if end >= len(normalized):
                break
            start = max(0, end - overlap_chars)
        return chunks

    def search(
        self,
        *,
        query: str,
        query_vector: list[float],
        limit: int,
        preferred_kinds: set[str] | None = None,
        service: str | None = None,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        if not self.configured:
            return []
        payload: dict[str, Any] = {
            "search": query or "*",
            "top": max(1, min(limit, 50)),
            "select": (
                "id,document_id,chunk_id,kind,title,content,services,deployment,dependencies,change_id,"
                "alert_id,incident_id,tenant_scope,source_system,source_ref,review_status,content_version,"
                "corpus_classification,owner,version,freshness_score,embedding_model,path"
            ),
            "vectorQueries": [
                {
                    "kind": "vector",
                    "vector": query_vector,
                    "fields": self._vector_field,
                    "k": max(1, min(limit * 3, 50)),
                }
            ],
        }
        filter_expression = self._filter(preferred_kinds=preferred_kinds, service=service, tenant_id=tenant_id)
        if filter_expression:
            payload["filter"] = filter_expression
        try:
            with httpx.Client(timeout=self._timeout_seconds) as client:
                response = client.post(self._url("/docs/search"), headers=self._headers(), json=payload)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            self.last_error = str(exc)
            return []
        rows = data.get("value") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            return []
        results: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            doc = dict(row)
            score = float(doc.pop("@search.score", 0.0) or 0.0)
            doc["_similarity"] = score
            doc["_semantic_score"] = score
            doc["_metadata_match_score"] = 0.0
            doc["match_confidence"] = score
            doc["_vector_store"] = "azure-ai-search"
            services = doc.get("services", [])
            if isinstance(services, str):
                doc["services"] = [item.strip() for item in services.split(",") if item.strip()]
            if retrieval_allowed(doc, tenant_id):
                results.append(doc)
        return results

    def upsert_documents(self, documents: list[dict[str, Any]]) -> dict[str, Any]:
        if not self.configured:
            return {"attempted": False, "indexed": 0, "reason": "azure ai search is not configured"}
        rows = []
        for doc in documents:
            content = str(doc.get("content") or "").strip()
            if not content:
                continue
            doc_id = re.sub(r"[^a-zA-Z0-9_-]", "-", str(doc.get("path") or doc.get("title") or "document"))[:512]
            chunks = self._chunk_text(content)
            services = doc.get("services", [])
            if isinstance(services, str):
                services = [item.strip() for item in services.split(",") if item.strip()]
            elif not isinstance(services, list):
                services = []
            for index, chunk in enumerate(chunks or [content]):
                chunk_id = f"chunk-{index + 1}"
                rows.append(
                    {
                        "@search.action": "mergeOrUpload",
                        "id": f"{doc_id}-{chunk_id}"[:512],
                        "document_id": str(doc.get("path") or doc_id),
                        "chunk_id": chunk_id,
                        "kind": str(doc.get("kind") or "document").strip().lower(),
                        "title": str(doc.get("title") or doc_id),
                        self._content_field: chunk,
                        self._vector_field: self._embedding_model.embed(chunk),
                        "services": [str(item).strip().lower() for item in services if str(item).strip()],
                        "deployment": str(doc.get("deployment") or ""),
                        "dependencies": doc.get("dependencies", []) if isinstance(doc.get("dependencies"), list) else [],
                        "change_id": str(doc.get("change_id") or ""),
                        "alert_id": str(doc.get("alert_id") or ""),
                        "incident_id": str(doc.get("incident_id") or ""),
                        "tenant_scope": str(doc.get("tenant_scope") or ""),
                        "source_system": str(doc.get("source_system") or ""),
                        "source_ref": str(doc.get("source_ref") or ""),
                        "review_status": str(doc.get("review_status") or ""),
                        "content_version": str(doc.get("content_version") or ""),
                        "corpus_classification": str(doc.get("corpus_classification") or ""),
                        "owner": str(doc.get("owner") or doc.get("resolved_by") or "unassigned"),
                        "version": str(doc.get("version") or "v1"),
                        "freshness_score": float(doc.get("freshness_score") or 0.75),
                        "embedding_model": str(describe_embedding_model(self._embedding_model).get("model") or ""),
                        "path": str(doc.get("path") or ""),
                    }
                )
        if not rows:
            return {"attempted": True, "indexed": 0, "reason": "no documents with content"}
        try:
            with httpx.Client(timeout=self._timeout_seconds) as client:
                response = client.post(self._url("/docs/index"), headers=self._headers(), json={"value": rows})
            response.raise_for_status()
        except Exception as exc:
            self.last_error = str(exc)
            return {"attempted": True, "indexed": 0, "error": str(exc)}
        self.last_error = ""
        return {"attempted": True, "indexed": len(rows), "index_name": self._index_name}

    def delete_document(self, document_id: str) -> dict[str, Any]:
        """Remove every remote chunk for one quarantined or superseded document."""
        if not self.configured:
            return {"attempted": False, "deleted": 0, "reason": "azure ai search is not configured"}
        identity = str(document_id or "").strip()
        if not identity:
            raise ValueError("document_id is required for remote RAG deletion")
        search_payload = {
            "search": "*",
            "top": 1000,
            "select": "id,document_id",
            "filter": f"document_id eq {self._odata_literal(identity)}",
        }
        try:
            with httpx.Client(timeout=self._timeout_seconds) as client:
                response = client.post(
                    self._url("/docs/search"), headers=self._headers(), json=search_payload
                )
                response.raise_for_status()
                rows = response.json().get("value", [])
                deletions = [
                    {"@search.action": "delete", "id": str(row.get("id"))}
                    for row in rows
                    if isinstance(row, dict) and str(row.get("id") or "").strip()
                ]
                if deletions:
                    deleted = client.post(
                        self._url("/docs/index"),
                        headers=self._headers(),
                        json={"value": deletions},
                    )
                    deleted.raise_for_status()
        except Exception as exc:
            self.last_error = str(exc)
            return {"attempted": True, "deleted": 0, "error": str(exc)}
        self.last_error = ""
        return {"attempted": True, "deleted": len(deletions), "document_id": identity}


@dataclass
class VectorDBConnector(BaseConnector):
    name: str = "vector-db"
    embedding_model: Embeddings = field(default_factory=lambda: get_embedding_model(get_settings()))
    rag_root: Path | None = None
    documents: list[dict[str, Any]] = field(default_factory=list)
    _document_cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    _remote_store: AzureAISearchVectorStore | None = field(default=None, init=False)
    _load_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _knowledge_graph: KnowledgeGraph | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        # Loading performs remote embedding calls. Keep construction/startup
        # side-effect free so message-bus consumers become available first.
        pass

    async def fetch(self, alert: Alert, incident: Incident) -> dict[str, Any]:
        await asyncio.sleep(0)
        if not self.documents:
            with self._load_lock:
                if not self.documents:
                    self.documents = self.load_documents()
        if self._knowledge_graph is None:
            self._knowledge_graph = KnowledgeGraph.from_documents(self.documents)
        query = " ".join(
            [
                str(alert.service or ""),
                str(alert.name or ""),
                str(alert.description or ""),
                " ".join(f"{key}={value}" for key, value in alert.labels.items()),
                " ".join(f"{key}={value}" for key, value in alert.annotations.items()),
            ]
        )
        tenant_id = str(getattr(alert, "tenant_id", "") or getattr(incident, "tenant_id", "")).strip()
        if not tenant_id:
            return {
                "matches": [],
                "document_count": len(self.documents),
                "evidence_gap": "authenticated tenant identity is missing",
            }
        ranked = self.search(
            query,
            limit=8,
            preferred_kinds={"runbook", "incident", "deployment", "dependency", "change", "remediation"},
            service=str(alert.service or "").strip(),
            tenant_id=tenant_id,
        )
        return {
            "matches": ranked,
            "document_count": len(self.documents),
            "evidence_gap": "" if ranked else "NO_MATCHING_APPROVED_EVIDENCE",
            "knowledge_graph": self._knowledge_graph.context(str(alert.service or "").strip()),
        }

    def load_documents(self) -> list[dict[str, Any]]:
        governed_cache = {
            key: dict(val)
            for key, val in self._document_cache.items()
            if str(key).startswith("governed://")
        }
        root = self.rag_root or self._discover_rag_root()
        if root is None or not root.exists():
            self._document_cache.clear()
            self._document_cache.update(governed_cache)
            return list(governed_cache.values())
        self._document_cache.clear()
        self._document_cache.update(governed_cache)
        documents = [
            self._parse_metadata_document(path)
            for path in sorted(root.rglob("*.md"))
            if path.name != "flows.md"
        ]
        derived_documents: list[dict[str, Any]] = []
        for doc in documents:
            if str(doc.get("kind", "")).strip().lower() != "incident":
                continue
            dependencies = doc.get("dependencies", [])
            if isinstance(dependencies, str):
                dependencies = [item.strip() for item in dependencies.split(",") if item.strip()]
            if isinstance(dependencies, list) and dependencies:
                filtered_dependencies = [str(item).strip() for item in dependencies if str(item).strip().lower() != "not explicitly documented."]
                if filtered_dependencies:
                    dependency_doc = {
                        **doc,
                        "kind": "dependency",
                        "title": f"{doc.get('title', 'Incident')} dependency context",
                        "content": "Dependency context derived from incident metadata.",
                        "dependencies": filtered_dependencies,
                        "_synthetic": True,
                    }
                    dependency_doc["_metadata_embedding"] = self.embedding_model.embed(self._metadata_text(dependency_doc))
                    dependency_doc["_embedding"] = self.embedding_model.embed(self._document_text(dependency_doc))
                    derived_documents.append(dependency_doc)

            deployment = str(doc.get("deployment") or "").strip()
            if deployment and deployment.lower() != "not explicitly documented.":
                deployment_doc = {
                    **doc,
                    "kind": "deployment",
                    "title": f"{doc.get('title', 'Incident')} deployment context",
                    "content": "Deployment context derived from incident metadata.",
                    "deployment": deployment,
                    "_synthetic": True,
                }
                deployment_doc["_metadata_embedding"] = self.embedding_model.embed(self._metadata_text(deployment_doc))
                deployment_doc["_embedding"] = self.embedding_model.embed(self._document_text(deployment_doc))
                derived_documents.append(deployment_doc)

            change_id = str(doc.get("change_id") or "").strip()
            if change_id:
                change_doc = {
                    **doc,
                    "kind": "change",
                    "title": f"{doc.get('title', 'Incident')} change context",
                    "content": "Change context derived from incident metadata.",
                    "change_id": change_id,
                    "_synthetic": True,
                }
                change_doc["_metadata_embedding"] = self.embedding_model.embed(self._metadata_text(change_doc))
                change_doc["_embedding"] = self.embedding_model.embed(self._document_text(change_doc))
                derived_documents.append(change_doc)

        return documents + derived_documents + list(governed_cache.values())

    def reload(self) -> int:
        self.documents = self.load_documents()
        self._knowledge_graph = KnowledgeGraph.from_documents(self.documents)
        self.sync_remote_index()
        return len(self.documents)

    def embedding_info(self) -> dict[str, Any]:
        return describe_embedding_model(self.embedding_model)

    def vector_store_info(self) -> dict[str, Any]:
        remote = self.remote_store()
        if remote.configured:
            return remote.info()
        return {
            "provider": "local-hybrid-vector-index",
            "engine": self.__class__.__name__,
            "persistent_index": False,
            "storage": "markdown-files-with-in-memory-vector-rerank",
            "root_path": str(self.root_path()),
            "remote_configured": False,
            "enterprise_ready": False,
            "recommended_enterprise_store": "azure-ai-search",
            "remote_last_error": remote.last_error,
        }

    def remote_store(self) -> AzureAISearchVectorStore:
        if self._remote_store is None:
            self._remote_store = AzureAISearchVectorStore(settings=get_settings(), embedding_model=self.embedding_model)
        return self._remote_store

    def sync_remote_index(self) -> dict[str, Any]:
        remote = self.remote_store()
        if not remote.configured:
            return {"attempted": False, "indexed": 0, "reason": "azure ai search is not configured"}
        full_docs = [
            dict(doc) if doc.get("_synthetic") else self._load_full_document(str(doc.get("path", "")))
            for doc in self.documents
            if not doc.get("_synthetic")
        ]
        return remote.upsert_documents([doc for doc in full_docs if doc and production_retrievable(doc)])

    async def index_governed_document(self, document: Any) -> dict[str, Any]:
        """Project one authoritative DB document into the configured vector index."""
        remote = self.remote_store()
        doc_meta = dict(getattr(document, "document_metadata", None) or {})
        raw_services = doc_meta.get("services") or doc_meta.get("service") or []
        if isinstance(raw_services, str):
            services = [item.strip() for item in raw_services.split(",") if item.strip()]
        elif isinstance(raw_services, list):
            services = [str(item).strip() for item in raw_services if str(item).strip()]
        else:
            services = []
        path = f"governed://{document.tenant_id}/{document.document_id}/v{document.document_version}"
        now_iso = datetime.now(UTC).isoformat()
        created_iso = (
            document.created_at.isoformat()
            if getattr(document, "created_at", None)
            else str(doc_meta.get("created_at") or now_iso)
        )
        approved_iso = (
            document.approved_at.isoformat()
            if getattr(document, "approved_at", None)
            else str(doc_meta.get("approved_at") or now_iso)
        )
        metadata: dict[str, Any] = {
            **doc_meta,
            "path": path,
            "document_id": str(document.document_id),
            "tenant_scope": document.tenant_id,
            "kind": document.document_kind,
            "title": document.title,
            "content": document.content,
            "services": services,
            "owner_team": str(doc_meta.get("owner_team") or getattr(document, "approved_by", None) or "platform-ops"),
            "content_version": str(document.document_version),
            "corpus_classification": document.corpus_classification,
            "review_status": document.review_status,
            "evidence_ids": list(document.evidence_ids or []),
            "source_uris": list(document.source_uris or []),
            "recommendation_id": str(document.recommendation_id) if getattr(document, "recommendation_id", None) else "",
            "rca_version": int(document.rca_version or 1) if getattr(document, "rca_version", None) is not None else 1,
            "created_at": created_iso,
            "updated_at": approved_iso,
            "approved_by": document.approved_by,
            "approved_at": approved_iso,
            "content_checksum": document.content_checksum,
            "incident_id": str(document.incident_id) if getattr(document, "incident_id", None) else str(doc_meta.get("incident_id") or ""),
            "alert_id": str(document.alert_id) if getattr(document, "alert_id", None) else str(doc_meta.get("alert_id") or ""),
            "source_system": "kaims-governed-rag",
            "source_ref": str(getattr(document, "source_ref", None) or f"governed-rag://{document.document_id}"),
        }
        local_entry = {
            **metadata,
            "_metadata_embedding": self.embedding_model.embed(self._metadata_text(metadata)),
            "_embedding": self.embedding_model.embed(self._document_text(metadata)),
        }
        with self._load_lock:
            if not self.documents:
                self.documents = self.load_documents()
            self._document_cache[path] = dict(local_entry)
            self.documents = [
                item for item in self.documents
                if str(item.get("document_id") or "") != str(document.document_id)
                and str(item.get("path") or "") != path
            ]
            self.documents.append(dict(local_entry))
        if remote.configured:
            result = await asyncio.to_thread(remote.upsert_documents, [metadata])
            if result.get("error") or int(result.get("indexed") or 0) < 1:
                raise RuntimeError(str(result.get("error") or result.get("reason") or "index did not accept document"))
        else:
            result = {"attempted": True, "indexed": 1, "provider": "local-hybrid-vector-index"}
        return {**result, "document_id": str(document.document_id),
                "content_checksum": document.content_checksum, "metadata": metadata}

    async def verify_index_receipt(self, receipt: dict[str, Any], *, expected_checksum: str) -> None:
        if str(receipt.get("content_checksum") or "") != expected_checksum:
            raise RuntimeError("indexed checksum verification failed")
        if int(receipt.get("indexed") or 0) < 1:
            raise RuntimeError("index receipt confirms no indexed chunks")

    def index_info(self) -> dict[str, Any]:
        if not self.documents:
            self.documents = self.load_documents()
        docs = [doc for doc in self.documents if not doc.get("_synthetic")]
        active_docs = [doc for doc in docs if production_retrievable(doc)]
        pending_docs = [
            doc for doc in docs
            if str(doc.get("review_status") or "").strip().lower() in {"draft", "pending_review"}
        ]
        quarantined_docs = [doc for doc in docs if doc not in active_docs and doc not in pending_docs]
        synthetic_docs = [doc for doc in self.documents if doc.get("_synthetic")]
        by_kind: dict[str, int] = {}
        embedded_metadata = 0
        for doc in docs:
            kind = str(doc.get("kind") or "unknown").strip().lower() or "unknown"
            by_kind[kind] = by_kind.get(kind, 0) + 1
            if isinstance(doc.get("_metadata_embedding"), list):
                embedded_metadata += 1
        return {
            "contract_version": "kaiops.rag-index.v1",
            "status": "ready" if active_docs else "degraded_empty_corpus",
            "execution_ready": bool(active_docs),
            "degraded": not active_docs,
            "degraded_reason": "no approved retrievable RAG documents" if not active_docs else "",
            "vector_store": self.vector_store_info(),
            "embedding_model": self.embedding_info(),
            "remote_index_enabled": self.remote_store().configured,
            "enterprise_index_enabled": self.remote_store().configured,
            "document_count": len(active_docs),
            "inventory_count": len(docs),
            "approved_retrievable_count": len(active_docs),
            "pending_review_count": len(pending_docs),
            "quarantined_count": len(quarantined_docs),
            "synthetic_document_count": len(synthetic_docs),
            "metadata_embedding_count": embedded_metadata,
            "full_document_cache_count": len(self._document_cache),
            "kinds": by_kind,
            "quality_gates": {
                "semantic_embeddings": self.embedding_info().get("provider") in {"openai", "azure-openai"},
                "persistent_vector_store": self.remote_store().configured,
                "service_scoped_retrieval": True,
                "metadata_prefilter": True,
                "full_document_rerank": True,
                "metadata_confidence_scoring": True,
            },
            "index_strategy": {
                "chunking": "chunk-level-for-remote-document-level-for-local",
                "metadata_shortlist": True,
                "full_document_rerank": True,
                "service_filter": True,
                "score_components": ["semantic_score", "metadata_match_score", "match_confidence"],
                "preferred_kinds": ["runbook", "incident", "deployment", "dependency", "change", "remediation"],
            },
        }

    def search(
        self,
        query: str,
        limit: int = 8,
        *,
        preferred_kind: str | None = None,
        preferred_kinds: set[str] | None = None,
        service: str | None = None,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        normalized_tenant = str(tenant_id or "").strip()
        if not normalized_tenant:
            raise ValueError("RAG search requires authenticated tenant identity")
        if not self.documents:
            with self._load_lock:
                if not self.documents:
                    self.documents = self.load_documents()
        query_vector = self.embedding_model.embed(query)
        kind_filter = (
            {preferred_kind.strip().lower()}
            if preferred_kind and preferred_kind.strip()
            else ({str(item).strip().lower() for item in preferred_kinds if str(item).strip()} if preferred_kinds else None)
        )
        remote_matches = self.remote_store().search(
            query=query,
            query_vector=query_vector,
            limit=limit,
            preferred_kinds=kind_filter,
            service=service,
            tenant_id=normalized_tenant,
        )
        if remote_matches:
            return remote_matches
        return self._rank_documents(
            query=query,
            query_vector=query_vector,
            limit=limit,
            preferred_kinds=kind_filter,
            service=service,
            tenant_id=normalized_tenant,
        )

    @staticmethod
    def _tenant_allowed(doc: dict[str, Any], tenant_id: str) -> bool:
        return retrieval_allowed(doc, tenant_id)

    def root_path(self) -> Path:
        root = self.rag_root or self._discover_rag_root()
        if root is None:
            root = Path.cwd() / "backend" / "rag"
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _discover_rag_root(self) -> Path | None:
        candidates = [Path.cwd(), *Path.cwd().parents, Path("/app")]
        for candidate in candidates:
            for rag_root in (candidate / "backend" / "rag", candidate / "rag"):
                if rag_root.exists():
                    return rag_root
        return None

    def _parse_metadata_document(self, path: Path) -> dict[str, Any]:
        metadata = self._read_metadata(path)
        metadata["_metadata_embedding"] = self.embedding_model.embed(self._metadata_text(metadata))
        return metadata

    def _resolve_document_path(self, path: str) -> Path | None:
        if not path:
            return None
        file_path = Path(path)
        if file_path.exists():
            return file_path

        root = self.root_path()
        raw = str(path).replace("\\", "/")
        for marker in ("/rag/", "rag/"):
            if marker not in raw:
                continue
            relative = raw.split(marker, 1)[1]
            candidate = root / relative
            if candidate.exists():
                return candidate
        candidate = root / file_path.name
        if candidate.exists():
            return candidate
        matches = list(root.rglob(file_path.name))
        return matches[0] if matches else None

    def _load_full_document(self, path: str) -> dict[str, Any]:
        cached = self._document_cache.get(path)
        if cached is not None:
            return dict(cached)

        if not path:
            return {}

        file_path = self._resolve_document_path(path)
        if file_path is None:
            return {}
        raw = file_path.read_text(encoding="utf-8")
        metadata: dict[str, Any] = {"path": path, "kind": file_path.parent.name.rstrip("s")}
        body_lines: list[str] = []
        in_metadata = True
        for line in raw.splitlines():
            stripped = line.strip()
            # Some generated docs have stray blank lines (or bare \r line
            # endings that splitlines() treats as blanks) within the header
            # block; skip them instead of ending metadata mode early.
            if in_metadata and not stripped:
                continue
            if in_metadata and stripped.startswith("#"):
                in_metadata = False
                body_lines.append(line)
                continue
            if in_metadata and ":" in line:
                key, value = line.split(":", 1)
                metadata[key.strip()] = self._parse_metadata_value(value.strip())
            else:
                in_metadata = False
                body_lines.append(line)

        title = str(metadata.get("title") or metadata.get("alert_name") or file_path.stem.replace("-", " "))
        content = "\n".join(body_lines).strip()
        services = metadata.get("services") or metadata.get("service", [])
        if isinstance(services, str):
            services = [item.strip() for item in services.split(",") if item.strip()]
        elif not isinstance(services, list):
            services = []
        self._apply_corpus_governance_defaults(metadata, file_path.stem)
        document = {**metadata, "title": title, "content": content, "services": services}
        document["_embedding"] = self.embedding_model.embed(self._document_text(document))
        self._document_cache[path] = document
        return dict(document)

    @staticmethod
    def _apply_corpus_governance_defaults(metadata: dict[str, Any], default_ref: str) -> None:
        if "tenant_scope" not in metadata:
            metadata["tenant_scope"] = "global"
        if "review_status" not in metadata:
            metadata["review_status"] = "approved"
        if "corpus_classification" not in metadata:
            metadata["corpus_classification"] = "PRODUCTION_CURATED"
        if "content_version" not in metadata:
            metadata["content_version"] = 1
        if "owner_team" not in metadata:
            metadata["owner_team"] = "platform-ops"
        if "source_system" not in metadata:
            metadata["source_system"] = "internal"
        if "source_ref" not in metadata:
            metadata["source_ref"] = str(metadata.get("alert_id") or default_ref)
        if "created_at" not in metadata:
            metadata["created_at"] = "2026-01-01T00:00:00Z"
        if "updated_at" not in metadata:
            metadata["updated_at"] = "2026-01-01T00:00:00Z"
        if "content_checksum" not in metadata:
            metadata["content_checksum"] = content_checksum(str(default_ref))

    def _read_metadata(self, path: Path) -> dict[str, Any]:
        metadata: dict[str, Any] = {"path": str(path), "kind": path.parent.name.rstrip("s")}
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    stripped = line.strip()
                    if not stripped:
                        # Some generated docs have stray blank lines (or bare
                        # \r line endings that read() splits into blanks)
                        # within the header block; skip rather than stop.
                        continue
                    if stripped.startswith("#"):
                        break
                    if ":" in line:
                        key, value = line.split(":", 1)
                        metadata[key.strip()] = self._parse_metadata_value(value.strip())
        except OSError:
            return metadata

        title = str(metadata.get("title") or metadata.get("alert_name") or path.stem.replace("-", " "))
        services = metadata.get("services") or metadata.get("service", [])
        if isinstance(services, str):
            services = [item.strip() for item in services.split(",") if item.strip()]
        elif not isinstance(services, list):
            services = []
        metadata["title"] = title
        metadata["services"] = services
        self._apply_corpus_governance_defaults(metadata, path.stem)
        return metadata

    def _parse_metadata_value(self, value: str) -> Any:
        if "," in value:
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    def _document_text(self, doc: dict[str, Any]) -> str:
        services = doc.get("services", [])
        dependencies = doc.get("dependencies", [])
        if isinstance(services, list):
            services = " ".join(services)
        if isinstance(dependencies, list):
            dependencies = " ".join(dependencies)
        return " ".join(
            [
                str(doc.get("kind", "")),
                str(doc.get("title", "")),
                str(services),
                str(dependencies),
                str(doc.get("deployment", "")),
                str(doc.get("content", "")),
            ]
        )

    def _metadata_text(self, doc: dict[str, Any]) -> str:
        services = doc.get("services", [])
        dependencies = doc.get("dependencies", [])
        if isinstance(services, list):
            services = " ".join(services)
        if isinstance(dependencies, list):
            dependencies = " ".join(dependencies)
        return " ".join(
            [
                str(doc.get("kind", "")),
                str(doc.get("title", "")),
                str(services),
                str(dependencies),
                str(doc.get("deployment", "")),
                str(doc.get("change_id", "")),
            ]
        )

    def _service_matches(self, doc: dict[str, Any], service: str | None) -> bool:
        normalized_service = str(service or "").strip().lower()
        if not normalized_service:
            return True
        doc_services = doc.get("services", [])
        if isinstance(doc_services, str):
            doc_services = [doc_services]
        if not isinstance(doc_services, list) or not doc_services:
            return True
        normalized_doc_services = {str(item).strip().lower() for item in doc_services if str(item).strip()}
        return normalized_service in normalized_doc_services or any(
            normalized_service in item or item in normalized_service for item in normalized_doc_services
        )

    def _kind_matches(self, doc: dict[str, Any], preferred_kinds: set[str] | None) -> bool:
        if not preferred_kinds:
            return True
        return str(doc.get("kind", "")).strip().lower() in preferred_kinds

    def context_match_relevant(self, doc: dict[str, Any], service: str) -> bool:
        """Apply a stricter gate than exploratory RAG search.

        Context may contain service-scoped reviewed knowledge with a modest
        semantic score. Untagged corpus documents need materially stronger
        semantic and metadata evidence before they can enter an incident
        package; otherwise generic demo/history documents become false facts.
        """

        services = doc.get("services", [])
        if isinstance(services, str):
            services = [services]
        services = [str(item).strip() for item in services if str(item).strip()] if isinstance(services, list) else []
        confidence = float(doc.get("match_confidence", doc.get("_similarity", 0.0)) or 0.0)
        metadata_score = float(doc.get("_metadata_match_score", 0.0) or 0.0)
        if services:
            return self._service_matches(doc, service) and confidence >= 0.08
        return confidence >= 0.30 and metadata_score >= 0.10

    def has_service_tagged_match(self, alert: Alert, min_similarity: float = 0.1) -> bool:
        """True only if some doc explicitly declares this alert's service.

        Unlike _rank_documents (used for general context enrichment, which
        deliberately falls back to the whole corpus so it can still surface
        loosely-related info), this is the strict signal behind
        "document_available": with hundreds of similar-domain ops documents,
        a bare similarity score can't reliably tell "genuinely relevant" from
        "coincidentally shares vocabulary" apart. Requiring an explicit
        services tag first narrows the candidate pool enough that similarity
        becomes a meaningful sanity check rather than the only signal.
        """
        service = str(alert.service or "").strip().lower()
        if not service:
            return False
        candidates = []
        for doc in self.documents:
            doc_services = doc.get("services", [])
            if isinstance(doc_services, str):
                doc_services = [doc_services]
            if not isinstance(doc_services, list) or not doc_services:
                continue
            normalized = {str(item).strip().lower() for item in doc_services if str(item).strip()}
            if service in normalized or any(service in item or item in service for item in normalized):
                candidates.append(doc)
        if not candidates:
            return False
        hydrated = [dict(doc) if doc.get("_synthetic") else self._load_full_document(str(doc.get("path", ""))) for doc in candidates]
        query_vector = self.embedding_model.embed(f"{alert.service} {alert.name} {alert.description}")
        best_score = max(
            cosine_similarity(query_vector, doc.get("_embedding") or self.embedding_model.embed(self._document_text(doc)))
            for doc in hydrated
        )
        return best_score >= min_similarity

    @staticmethod
    def _tokenize(text: Any) -> set[str]:
        return {
            token
            for token in re.findall(r"[a-z0-9][a-z0-9_.:-]{2,}", str(text or "").lower())
            if token not in {"the", "and", "for", "with", "from", "this", "that", "alert", "service"}
        }

    def _doc_match_text(self, doc: dict[str, Any]) -> str:
        services = doc.get("services", [])
        dependencies = doc.get("dependencies", [])
        if isinstance(services, list):
            services = " ".join(str(item) for item in services)
        if isinstance(dependencies, list):
            dependencies = " ".join(str(item) for item in dependencies)
        return " ".join(
            [
                str(doc.get("kind", "")),
                str(doc.get("title", "")),
                str(doc.get("alert_type", "")),
                str(doc.get("alert_id", "")),
                str(doc.get("incident_id", "")),
                str(doc.get("source_ref", "")),
                str(doc.get("source_system", "")),
                str(services),
                str(dependencies),
                str(doc.get("deployment", "")),
                str(doc.get("content", "")),
            ]
        ).lower()

    def _metadata_exact_score(
        self,
        *,
        query: str,
        doc: dict[str, Any],
        service: str | None,
        preferred_kinds: set[str] | None,
    ) -> float:
        query_text = str(query or "").lower()
        doc_text = self._doc_match_text(doc)
        query_tokens = self._tokenize(query_text)
        doc_tokens = self._tokenize(doc_text)

        score = 0.0
        service_token = str(service or "").strip().lower()
        if service_token and service_token in doc_tokens:
            score += 0.22

        doc_kind = str(doc.get("kind") or "").strip().lower()
        if preferred_kinds and doc_kind in preferred_kinds:
            score += 0.08

        alert_tokens = {token for token in query_tokens if "alert" in token or token.endswith("high") or token.endswith("down")}
        if alert_tokens and any(token in doc_text for token in alert_tokens):
            score += 0.18

        metric_tokens = {token for token in query_tokens if "_" in token or token.startswith(("mysql", "kaiops", "http", "queue"))}
        if metric_tokens:
            matched = len([token for token in metric_tokens if token in doc_text])
            score += min(0.18, 0.06 * matched)

        connector_tokens = {"database", "table", "environment", "project", "fingerprint", "source_ref"}
        keyed_tokens = {
            piece.split("=", 1)[1].strip().lower()
            for piece in query_text.split()
            if "=" in piece and piece.split("=", 1)[0].strip().lower() in connector_tokens
        }
        if keyed_tokens:
            matched = len([token for token in keyed_tokens if token and token in doc_text])
            score += min(0.16, 0.05 * matched)

        if "kaiops_alert_health_triage.sh" in query_text and "kaiops_alert_health_triage.sh" in doc_text:
            score += 0.08

        overlap = len(query_tokens & doc_tokens) / max(1, len(query_tokens))
        score += min(0.10, overlap)
        return min(score, 1.0)

    def _metadata_rank_score(self, *, query: str, query_vector: list[float], doc: dict[str, Any], service: str | None, preferred_kinds: set[str] | None) -> float:
        embedding = doc.get("_metadata_embedding")
        if not isinstance(embedding, list):
            embedding = self.embedding_model.embed(self._metadata_text(doc))
            doc["_metadata_embedding"] = embedding
        semantic_score = cosine_similarity(query_vector, embedding)
        exact_score = self._metadata_exact_score(
            query=query,
            doc=doc,
            service=service,
            preferred_kinds=preferred_kinds,
        )
        return (0.55 * semantic_score) + (0.45 * exact_score)

    def _rank_documents(
        self,
        *,
        query: str,
        query_vector: list[float],
        limit: int,
        preferred_kinds: set[str] | None = None,
        service: str | None = None,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 20))
        candidates = [
            doc
            for doc in self.documents
            if self._tenant_allowed(doc, tenant_id)
            and self._kind_matches(doc, preferred_kinds)
            and self._service_matches(doc, service)
        ]
        if not candidates and preferred_kinds:
            candidates = [
                doc
                for doc in self.documents
                if self._tenant_allowed(doc, tenant_id) and self._service_matches(doc, service)
            ]

        shortlist_size = min(max(limit * 4, 12), len(candidates))
        shortlisted = heapq.nlargest(
            shortlist_size,
            candidates,
            key=lambda doc: self._metadata_rank_score(
                query=query,
                query_vector=query_vector,
                doc=doc,
                service=service,
                preferred_kinds=preferred_kinds,
            ),
        )
        hydrated = [dict(doc) if doc.get("_synthetic") else self._load_full_document(str(doc.get("path", ""))) for doc in shortlisted]
        scored = []
        for doc in hydrated:
            semantic_score = cosine_similarity(
                query_vector,
                doc.get("_embedding") or self.embedding_model.embed(self._document_text(doc)),
            )
            metadata_score = self._metadata_exact_score(
                query=query,
                doc=doc,
                service=service,
                preferred_kinds=preferred_kinds,
            )
            match_confidence = max(semantic_score, (0.65 * metadata_score) + (0.35 * max(semantic_score, 0.0)))
            scored.append((match_confidence, semantic_score, metadata_score, doc))
        top = heapq.nlargest(limit, scored, key=lambda item: item[0])
        results = []
        for score, semantic_score, metadata_score, doc in top:
            doc = dict(doc)
            doc["_similarity"] = score
            doc["_semantic_score"] = semantic_score
            doc["_metadata_match_score"] = metadata_score
            doc["match_confidence"] = score
            results.append(doc)
        return results


class ContextGraphState(TypedDict, total=False):
    alert: Alert
    incident: Incident
    connector_results: dict[str, dict[str, Any]]
    context: Context
    graph_stages: list[str]
    connector_health: dict[str, dict[str, Any]]
    collection_latency_ms: float
    selected_connectors: list[str]
    collection_plan: dict[str, Any]


@dataclass
class ContextIntelligenceAgent(BaseAgent):
    connectors: list[BaseConnector] = field(
        default_factory=lambda: [
            ServiceNowConnector(),
            PrometheusConnector(),
            KubernetesConnector(),
            JenkinsConnector(),
            GitHubConnector(),
            CMDBConnector(),
            DiscoveryMCPConnector(),
            LocalEvidenceConnector(),
            VectorDBConnector(),
        ]
    )
    name: str = "context-agent"
    runtime: AgentRuntime = field(default_factory=AgentRuntime)
    tool_registry: ToolRegistry = field(default_factory=ToolRegistry)
    graph: Any = field(init=False)

    def __post_init__(self) -> None:
        if not self.tool_registry.tools:
            for connector in self.connectors:
                tool_name = f"connector.{connector.name}"

                async def _handler(payload: dict[str, Any], _connector: BaseConnector = connector) -> dict[str, Any]:
                    alert_payload = payload.get("alert")
                    incident_payload = payload.get("incident")
                    if not isinstance(alert_payload, dict) or not isinstance(incident_payload, dict):
                        raise ValueError("connector payload must include alert and incident objects")
                    alert = Alert.model_validate(alert_payload)
                    incident = Incident.model_validate(incident_payload)
                    if _connector.name in {"vector-db", "local-evidence"}:
                        # These connectors perform CPU/file work and synchronous embedding HTTP.
                        # Keep them off the consumer event loop so Kafka heartbeats remain timely.
                        return await asyncio.to_thread(
                            lambda: asyncio.run(_connector.fetch(alert, incident))
                        )
                    return await _connector.fetch(alert, incident)

                self.tool_registry.register(
                    ToolSpec(
                        name=tool_name,
                        handler=_handler,
                        timeout_seconds=(
                            300.0
                            if connector.name == "vector-db"
                            else 45.0
                            if connector.name == "discovery-mcp"
                            else 30.0
                            if connector.name == "local-evidence"
                            else 10.0
                        ),
                        permissions={"context-agent"},
                    )
                )
        self.graph = self._build_graph()

    def _build_graph(self):
        workflow = StateGraph(ContextGraphState)
        workflow.add_node("validate_event", self.validate_event)
        workflow.add_node("collect_connector_evidence", self.collect_connector_evidence)
        workflow.add_node("assemble_context", self.assemble_context)
        workflow.set_entry_point("validate_event")
        workflow.add_edge("validate_event", "collect_connector_evidence")
        workflow.add_edge("collect_connector_evidence", "assemble_context")
        workflow.add_edge("assemble_context", END)
        return workflow.compile()

    async def _run_connector(self, connector: BaseConnector, alert: Alert, incident: Incident) -> dict[str, Any]:
        return await self.tool_registry.execute(
            f"connector.{connector.name}",
            {
                "alert": alert.model_dump(mode="json"),
                "incident": incident.model_dump(mode="json"),
            },
            role="context-agent",
        )

    async def can_execute(self, context: AgentContext) -> bool:
        return context.alert is not None and context.incident is not None

    async def validate_event(self, state: ContextGraphState) -> ContextGraphState:
        if not isinstance(state.get("alert"), Alert) or not isinstance(state.get("incident"), Incident):
            raise ContextFailure("context graph requires alert and incident")
        available = [connector.name for connector in self.connectors]
        selected, reasons = plan_connectors(state["alert"], available)
        state["selected_connectors"] = selected
        state["collection_plan"] = {
            "mode": "adaptive",
            "selected": selected,
            "skipped": [name for name in available if name not in selected],
            "reasons": reasons,
        }
        state["graph_stages"] = [*state.get("graph_stages", []), "validate_event"]
        return state

    async def collect_connector_evidence(self, state: ContextGraphState) -> ContextGraphState:
        alert = state["alert"]
        incident = state["incident"]
        budget_seconds = max(5.0, min(float(os.getenv("CONTEXT_COLLECTION_BUDGET_SECONDS", "60")), 180.0))
        started = monotonic()

        async def collect_one(connector: BaseConnector) -> tuple[dict[str, Any], dict[str, Any]]:
            connector_started = monotonic()
            # Expensive discovery/vector operations already have internal retries and
            # long tool deadlines. Retrying them here amplifies incident latency.
            attempts = 1 if connector.name in {"vector-db", "discovery-mcp", "local-evidence"} else 2
            try:
                result = await retry_async(
                    lambda: self._run_connector(connector, alert, incident),
                    attempts=attempts,
                    base_delay=0.15,
                )
                explicit_status = str(result.get("_source_status") or "").strip().lower()
                return result, {
                    "status": explicit_status or "completed",
                    "latency_ms": round((monotonic() - connector_started) * 1000, 2),
                    "attempts": attempts,
                }
            except Exception as exc:  # A connector failure must not erase healthy evidence.
                failure_status = (
                    "timed_out" if isinstance(exc, TimeoutError | asyncio.TimeoutError)
                    else "unauthorized" if isinstance(exc, PermissionError)
                    else "misconfigured" if isinstance(exc, KeyError | ValueError)
                    else "unavailable"
                )
                return {}, {
                    "status": failure_status,
                    "latency_ms": round((monotonic() - connector_started) * 1000, 2),
                    "attempts": attempts,
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:300],
                }

        selected_names = set(state.get("selected_connectors") or [connector.name for connector in self.connectors])
        selected_connectors = [connector for connector in self.connectors if connector.name in selected_names]
        tasks = {
            connector.name: asyncio.create_task(collect_one(connector), name=f"context:{connector.name}")
            for connector in selected_connectors
        }
        done, pending = await asyncio.wait(tasks.values(), timeout=budget_seconds)
        results: dict[str, dict[str, Any]] = {}
        health: dict[str, dict[str, Any]] = {}
        task_names = {task: name for name, task in tasks.items()}
        for task in done:
            name = task_names[task]
            result, status = task.result()
            results[name] = result
            has_material_result = bool(
                result
                and any(
                    value not in (None, "", [], {}, False)
                    for key, value in result.items()
                    if key not in {"provenance", "_source_status", "error"}
                )
            )
            health[name] = (
                status
                if status.get("status") != "completed"
                else {**status, "status": "completed" if has_material_result else "empty"}
            )
        for task in pending:
            name = task_names[task]
            task.cancel()
            results[name] = {}
            health[name] = {
                "status": "timed_out",
                "latency_ms": round(budget_seconds * 1000, 2),
                "attempts": 1,
                "error": f"context collection exceeded the {budget_seconds:g}s budget",
            }
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        for connector in self.connectors:
            if connector.name not in selected_names:
                health[connector.name] = {
                    "status": "skipped",
                    "latency_ms": 0.0,
                    "attempts": 0,
                    "reason": "not required by adaptive collection plan",
                }
        state["connector_results"] = results
        state["connector_health"] = health
        state["collection_latency_ms"] = round((monotonic() - started) * 1000, 2)
        state["graph_stages"] = [*state.get("graph_stages", []), "collect_connector_evidence"]
        return state

    async def assemble_context(self, state: ContextGraphState) -> ContextGraphState:
        alert = state["alert"]
        incident = state["incident"]
        connector_defaults = {
            "vector-db": {"matches": [], "document_count": 0, "knowledge_graph": {}},
            "jenkins": {"recent_deployments": []},
            "cmdb": {"dependencies": []},
            "servicenow": {"change_records": []},
            "github": {"recent_commits": []},
            "kubernetes": {},
            "prometheus": {},
            "local-evidence": {},
            "discovery-mcp": {},
        }
        by_name = {
            name: {
                **defaults,
                **(
                    state["connector_results"].get(name, {})
                    if isinstance(state["connector_results"].get(name), dict)
                    else {}
                ),
            }
            for name, defaults in connector_defaults.items()
        }
        by_name.update({
            name: result
            for name, result in state["connector_results"].items()
            if name not in by_name and isinstance(result, dict)
        })
        raw_vector_matches = by_name["vector-db"]["matches"]
        vector_connector = next((c for c in self.connectors if isinstance(c, VectorDBConnector)), None)
        vector_matches = [
            doc for doc in raw_vector_matches
            if isinstance(doc, dict)
            and vector_connector is not None
            and vector_connector.context_match_relevant(doc, str(alert.service or ""))
        ]
        def explicitly_matches_service(doc: dict[str, Any]) -> bool:
            if not vector_connector:
                return False
            services = doc.get("services", [])
            if isinstance(services, str):
                services = [services]
            return bool(services) and vector_connector._service_matches(doc, alert.service)

        service_tagged_match = any(explicitly_matches_service(doc) for doc in vector_matches)

        runbook = next(
            (doc["content"] for doc in vector_matches if doc["kind"] == "runbook" and explicitly_matches_service(doc)),
            "",
        )
        related = [doc for doc in vector_matches if doc["kind"] == "incident" and explicitly_matches_service(doc)]
        deployment_doc = next((doc for doc in vector_matches if doc["kind"] == "deployment" and explicitly_matches_service(doc)), {})
        dependency_docs = [doc for doc in vector_matches if doc["kind"] == "dependency" and explicitly_matches_service(doc)]
        change_docs = [doc for doc in vector_matches if doc["kind"] == "change" and explicitly_matches_service(doc)]
        recent_deployments = by_name["jenkins"].get("recent_deployments") or [{}]
        deployment = (
            recent_deployments[0].get("version")
            or alert.labels.get("deployment")
            or deployment_doc.get("deployment")
        )
        dependencies = list(by_name["cmdb"].get("dependencies", []))
        knowledge_graph = (
            by_name["vector-db"].get("knowledge_graph", {})
            if isinstance(by_name["vector-db"].get("knowledge_graph"), dict)
            else {}
        )
        for dependency in knowledge_graph.get("dependencies", []):
            if dependency not in dependencies:
                dependencies.append(dependency)
        for doc in dependency_docs:
            for dependency in doc.get("dependencies", []):
                if dependency not in dependencies:
                    dependencies.append(dependency)
        recent_changes = (
            by_name["servicenow"].get("change_records", [])
            + by_name["github"].get("recent_commits", [])
            + [
                {
                    "id": doc.get("change_id", doc.get("title")),
                    "source": "rag",
                    "title": doc.get("title"),
                    "deployment": doc.get("deployment"),
                }
                for doc in change_docs
            ]
        )
        local_evidence = by_name.get("local-evidence", {}) if isinstance(by_name.get("local-evidence"), dict) else {}
        discovery_report = by_name.get("discovery-mcp", {}) if isinstance(by_name.get("discovery-mcp"), dict) else {}
        discovery_report = self._merge_discovery_results(alert, discovery_report, local_evidence)
        discovery_rows = discovery_report.get("evidence") if isinstance(discovery_report.get("evidence"), list) else []
        retrieval_stages = discovery_report.get("retrieval_stages") if isinstance(discovery_report.get("retrieval_stages"), list) else []
        source_aliases = {
            "log": "logs",
            "logs": "logs",
            "opensearch": "logs",
            "ticket": "tickets",
            "tickets": "tickets",
            "jira": "tickets",
            "email": "tickets",
            "code": "code",
            "source": "code",
            "telemetry": "telemetry",
            "trace": "telemetry",
            "metric": "telemetry",
            "mysql": "database",
            "database": "database",
        }
        evidence_buckets: dict[str, list[dict[str, Any]]] = {
            "logs": [],
            "tickets": [],
            "code": [],
            "telemetry": [],
            "database": [],
            "rag": [],
            "other": [],
        }
        for row in discovery_rows:
            if not isinstance(row, dict):
                continue
            source = str(row.get("source") or row.get("kind") or "other").strip().lower()
            bucket = source_aliases.get(source, "other")
            if bucket in {"tickets", "code"}:
                searchable = " ".join(str(value) for value in row.values()).lower()
                service = str(alert.service or "").strip().lower()
                alert_name = str(alert.name or "").strip().lower()
                service_aliases = {service, service.removeprefix("kaiops-")} - {""}
                if service_aliases and not any(alias in searchable for alias in service_aliases) and (not alert_name or alert_name not in searchable):
                    continue
            evidence_buckets[bucket].append(row)
        evidence_buckets["rag"] = [
            {
                "source": "rag",
                "kind": doc.get("kind"),
                "title": doc.get("title"),
                "path": doc.get("path"),
                "snippet": str(doc.get("content") or doc.get("summary") or "")[:500],
                "epistemic_role": "historical_knowledge",
                "current_observation": False,
                "similarity": float(doc.get("_similarity", 0.0) or 0.0),
                "match_confidence": float(doc.get("match_confidence", doc.get("_similarity", 0.0)) or 0.0),
            }
            for doc in vector_matches
        ]
        stage_by_name = {
            str(stage.get("stage") or "").strip().lower(): stage
            for stage in retrieval_stages
            if isinstance(stage, dict)
        }
        source_stage_names = {
            "logs": ("logs_search", "local_log_search"),
            "tickets": ("tickets_search",),
            "code": ("code_search", "local_code_search"),
            "telemetry": ("telemetry_search",),
            "database": ("mysql_search",),
        }
        context_source_manifest: dict[str, dict[str, Any]] = {}
        for source_name, rows in evidence_buckets.items():
            attempted_stages = [
                stage_by_name[stage_name]
                for stage_name in source_stage_names.get(source_name, ())
                if stage_name in stage_by_name
            ]
            source_attempted = source_name == "rag" or any(
                str(stage.get("status") or "").lower() != "skipped"
                for stage in attempted_stages
            )
            context_source_manifest[source_name] = {
                "attempted": source_attempted,
                "status": (
                    "collected"
                    if rows
                    else "failed"
                    if any(str(stage.get("status") or "").lower() == "failed" for stage in attempted_stages)
                    else "skipped"
                    if attempted_stages and not source_attempted
                    else "no_matches"
                ),
                "result_count": len(rows),
                "evidence_ids": [
                    str(row.get("evidence_id"))
                    for row in rows
                    if str(row.get("evidence_id") or "").strip()
                ],
            }
        prometheus_health = state.get("connector_health", {}).get("prometheus", {})
        if isinstance(prometheus_health, dict) and prometheus_health:
            context_source_manifest["telemetry"] = {
                **context_source_manifest.get("telemetry", {}),
                "attempted": prometheus_health.get("status") != "skipped",
                "status": str(prometheus_health.get("status") or "unavailable"),
                "connector": "prometheus",
                "endpoint_identity": by_name["prometheus"].get("endpoint_identity"),
                "query": by_name["prometheus"].get("query"),
                "result_count": len(by_name["prometheus"].get("series") or []),
                "error": prometheus_health.get("error") or by_name["prometheus"].get("error"),
            }
        context = Context(
            tenant_id=alert.tenant_id,
            incident_id=incident.id,
            alert=alert,
            deployment=deployment,
            related_incidents=related,
            runbook=runbook,
            dependency_services=dependencies,
            recent_changes=recent_changes,
            cmdb=by_name["cmdb"],
            kubernetes=by_name["kubernetes"],
            observability=by_name["prometheus"],
            metadata={
                "rag_documents": by_name["vector-db"]["document_count"],
                "rag_matches": [
                    {
                        "kind": doc.get("kind"),
                        "title": doc.get("title"),
                        "path": doc.get("path"),
                        "similarity": float(doc.get("_similarity", 0.0) or 0.0),
                        "semantic_score": float(doc.get("_semantic_score", doc.get("_similarity", 0.0)) or 0.0),
                        "metadata_match_score": float(doc.get("_metadata_match_score", 0.0) or 0.0),
                        "match_confidence": float(doc.get("match_confidence", doc.get("_similarity", 0.0)) or 0.0),
                    }
                    for doc in vector_matches
                ],
                "rag_top_similarity": max((doc.get("_similarity", 0.0) for doc in vector_matches), default=0.0),
                "rag_top_semantic_score": max((doc.get("_semantic_score", 0.0) for doc in vector_matches), default=0.0),
                "rag_top_metadata_match_score": max((doc.get("_metadata_match_score", 0.0) for doc in vector_matches), default=0.0),
                "rag_top_match_confidence": max((doc.get("match_confidence", doc.get("_similarity", 0.0)) for doc in vector_matches), default=0.0),
                "rag_service_tagged_match": service_tagged_match,
                "rag_rejected_match_count": max(0, len(raw_vector_matches) - len(vector_matches)),
                "rag_index": vector_connector.index_info() if vector_connector else {},
                "discovery_evidence": local_evidence,
                "discovery_report": discovery_report,
                "context_sources": context_source_manifest,
                "context_evidence": evidence_buckets,
                "context_graph": {
                    "enabled": True,
                    "stages": [*state.get("graph_stages", []), "assemble_context"],
                    "connector_count": len(state.get("selected_connectors") or self.connectors),
                    "available_connector_count": len(self.connectors),
                    "collection_plan": state.get("collection_plan", {}),
                    "collection_latency_ms": state.get("collection_latency_ms", 0.0),
                    "connectors": state.get("connector_health", {}),
                    "collected_count": sum(
                        1 for item in state.get("connector_health", {}).values()
                        if item.get("status") == "completed"
                    ),
                    "degraded": any(
                        item.get("status") in {"unavailable", "unauthorized", "misconfigured", "timed_out"}
                        for item in state.get("connector_health", {}).values()
                    ),
                },
                "knowledge_graph": knowledge_graph,
            },
        )
        tenant_id = require_tenant_id(alert.tenant_id, source="context collection alert identity")
        context = govern_context(
            context,
            tenant_id=tenant_id,
            subject_fingerprint=context_subject_fingerprint(alert, tenant_id),
            threshold=float(os.getenv("CONTEXT_MIN_QUALITY_SCORE", "0.70")),
            max_evidence_per_source=int(os.getenv("CONTEXT_MAX_EVIDENCE_PER_SOURCE", "20")),
        )
        state["context"] = context
        state["graph_stages"] = [*state.get("graph_stages", []), "assemble_context"]
        return state

    async def collect(self, alert: Alert, incident: Incident) -> Context:
        state = await self.graph.ainvoke({"alert": alert, "incident": incident, "graph_stages": []})
        context = state.get("context")
        if not isinstance(context, Context):
            raise ContextFailure("context graph produced non-context output")
        return context

    def _merge_discovery_results(
        self,
        alert: Alert,
        mcp_result: dict[str, Any],
        local_result: dict[str, Any],
    ) -> dict[str, Any]:
        report_payload = dict(mcp_result) if isinstance(mcp_result, dict) else {}
        existing_evidence = report_payload.get("evidence") if isinstance(report_payload.get("evidence"), list) else []
        retrieval_stages = report_payload.get("retrieval_stages") if isinstance(report_payload.get("retrieval_stages"), list) else []
        code_matches = local_result.get("code_matches") if isinstance(local_result.get("code_matches"), list) else []
        log_matches = local_result.get("log_matches") if isinstance(local_result.get("log_matches"), list) else []
        local_evidence = [row for row in [*code_matches, *log_matches] if isinstance(row, dict)]

        merged_by_id: dict[str, dict[str, Any]] = {}
        for row in [*existing_evidence, *local_evidence]:
            evidence_id = str(row.get("evidence_id") or "").strip()
            if evidence_id:
                merged_by_id[evidence_id] = row

        if code_matches:
            retrieval_stages.append({"stage": "local_code_search", "status": "completed", "result_count": len(code_matches)})
        if log_matches:
            retrieval_stages.append({"stage": "local_log_search", "status": "completed", "result_count": len(log_matches)})

        report = report_payload.get("report") if isinstance(report_payload.get("report"), dict) else {}
        if not report:
            report = {}
        if local_evidence and not str(report.get("summary") or "").strip():
            report["summary"] = (
                f"Local discovery matched {len(code_matches)} code snippets and {len(log_matches)} log snippets "
                f"for alert {alert.name} on service {alert.service}."
            )
        report.setdefault("hypotheses", [])
        report.setdefault("affected_components", sorted({str(alert.service or "").strip() or "unknown"}))
        report.setdefault(
            "recommended_next_checks",
            [
                "Inspect the cited code and log evidence for the matched service before executing remediation.",
                "Correlate the matched code paths with the latest deployment and incident timeline.",
            ],
        )
        report["insufficient_evidence"] = bool(report.get("insufficient_evidence", False)) and not bool(local_evidence)
        report["code_review"] = DiscoveryMCPConnector._validated_code_review(report, list(merged_by_id.values()))
        report["proposed_code_changes"] = report["code_review"]["proposed_changes"]
        report_payload["protocol"] = str(report_payload.get("protocol") or ("local-evidence" if local_evidence else "mcp-jsonrpc-2.0"))
        report_payload["query_terms"] = report_payload.get("query_terms") or local_result.get("query_terms") or []
        report_payload["report"] = report
        report_payload["evidence"] = list(merged_by_id.values())
        report_payload["retrieval_stages"] = retrieval_stages
        report_payload["model_usage"] = report_payload.get("model_usage") if isinstance(report_payload.get("model_usage"), dict) else {}
        return report_payload

    async def execute(self, context: AgentContext) -> Context:
        if context.alert is None or context.incident is None:
            raise ContextFailure("AgentContext must include alert and incident")
        result = await self.collect(context.alert, context.incident)
        context.set_result(self.name, result.model_dump(mode="json"))
        return result

    async def validate(self, result: Any) -> bool:
        return isinstance(result, Context)

    async def collect_with_runtime(self, alert: Alert, incident: Incident) -> Context:
        runtime_context = AgentContext(alert=alert, incident=incident)
        runtime_result = await self.runtime.run(self, runtime_context)
        if not isinstance(runtime_result.result, Context):
            raise ContextFailure("context runtime produced non-context output")
        return runtime_result.result
