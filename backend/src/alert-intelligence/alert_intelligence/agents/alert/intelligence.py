from __future__ import annotations

import hashlib
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from ai_workbench_common.agentic import AgentContext, BaseAgent
from common.config import get_settings
from ai_workbench_common.embeddings import HashingEmbeddingModel, cosine_similarity
from common.models import Alert, AlertSeverity, Incident, IncidentStatus, utc_now
from common.incident_policy import IncidentSeverityPolicy
from common.incident_identity import environment_family, is_ephemeral_environment, same_environment_family
from common.repository_interfaces import AlertHistoryRepository, InMemoryAlertHistoryRepository
from alert_intelligence.discovery import build_incident_candidate

_CORRELATION_WEIGHTS = {
    "text_similarity": 0.30,
    "service": 0.15,
    "environment": 0.08,
    "topology": 0.15,
    "deployment_change": 0.12,
    "metric_signal": 0.10,
    "temporal": 0.07,
    "alert_family": 0.03,
}

_DEPENDENCY_KEYS = (
    "dependency",
    "dependencies",
    "upstream",
    "downstream",
    "database",
    "db",
    "queue",
    "topic",
)
_TOPOLOGY_KEYS = ("cluster", "namespace", "node", "host", "pod", "app", "application", "job", "instance")
_DEPLOYMENT_KEYS = ("deployment", "release", "revision", "version", "change_id", "change", "build")
_METRIC_KEYS = ("metric", "metric_name", "__name__", "prometheus_rule", "rule", "alertname")
_STABLE_RESOURCE_KEYS = (
    "mountpoint", "filesystem", "volume", "persistentvolumeclaim", "disk",
    "resource_id", "resource", "database", "queue", "topic",
    "operation", "http_route", "route", "method", "http_method",
)


@dataclass
class AlertIntelligenceAgent(BaseAgent):
    embedding_model: HashingEmbeddingModel = field(default_factory=HashingEmbeddingModel)
    correlation_threshold: float | None = None
    retention_minutes: int | None = None
    deduplication_enabled: bool | None = None
    deduplication_window_minutes: int | None = None
    alert_history_repository: AlertHistoryRepository = field(default_factory=InMemoryAlertHistoryRepository)
    name: str = "alert-intelligence-agent"
    # Bounded FIFO cache: an unbounded dict here grows for the life of the
    # process (one entry per distinct alert text seen), which is a slow
    # memory leak across a multi-day soak at 10k alerts/day.
    _embedding_cache: OrderedDict[str, list[float]] = field(default_factory=OrderedDict)
    _embedding_cache_max_size: int = 5000

    def __post_init__(self) -> None:
        settings = get_settings()
        if self.correlation_threshold is None:
            self.correlation_threshold = float(getattr(settings, "alert_correlation_threshold", 0.72))
        if self.retention_minutes is None:
            self.retention_minutes = int(getattr(settings, "alert_retention_minutes", 60))
        if self.deduplication_enabled is None:
            self.deduplication_enabled = bool(getattr(settings, "alert_deduplication_enabled", True))
        if self.deduplication_window_minutes is None:
            self.deduplication_window_minutes = int(
                getattr(settings, "alert_deduplication_window_minutes", self.retention_minutes or 60)
            )
        self.deduplication_window_minutes = max(1, min(int(self.deduplication_window_minutes), 1440))
        self.retention_minutes = max(int(self.retention_minutes or 0), self.deduplication_window_minutes)

    async def deduplicate_alerts(self, alert: Alert, candidates: Sequence[Alert] | None = None) -> Alert:
        fingerprint = self._fingerprint(alert)
        alert.fingerprint = fingerprint
        alert.metadata["deduplication"] = {
            "enabled": bool(self.deduplication_enabled),
            "window_minutes": int(self.deduplication_window_minutes or 60),
            "fingerprint": fingerprint,
            "similarity_threshold": float(self.correlation_threshold or 0.72),
        }
        if not self.deduplication_enabled:
            alert.deduplicated_count = 1
            alert.metadata["deduplication"].update({"matched": False, "disposition": "new_incident"})
            return alert
        cutoff = utc_now() - timedelta(minutes=int(self.deduplication_window_minutes or 60))
        if candidates is None:
            candidates = await self.alert_history_repository.list_recent_alerts(
                environment=alert.environment, tenant_id=alert.tenant_id
            )
        matches: list[Alert] = []
        match_details: list[dict[str, Any]] = []
        for item in candidates:
            if (
                item.tenant_id != alert.tenant_id
                or item.starts_at < cutoff
                or (item.ends_at is not None and item.ends_at <= utc_now())
                or not same_environment_family(alert.environment, item.environment)
            ):
                continue
            if self._resource_conflicts(alert, item):
                continue
            exact = item.fingerprint == fingerprint
            similarity, evidence = self._correlation_score(alert, item)
            if not exact and similarity < float(self.correlation_threshold or 0.72):
                continue
            matches.append(item)
            match_details.append(
                {
                    "alert_id": str(item.id),
                    "match_type": "exact" if exact else "similar",
                    "similarity_score": round(similarity, 4),
                    "evidence": evidence,
                }
            )
        alert.deduplicated_count = len(matches) + 1
        alert.metadata["deduplication"].update(
            {
                "matched": bool(matches),
                "matched_alert_ids": [str(item.id) for item in matches[:20]],
                "matches": match_details[:20],
                "match_type": match_details[0]["match_type"] if match_details else None,
                "similarity_score": match_details[0]["similarity_score"] if match_details else 0.0,
                "disposition": "duplicate" if matches else "new_incident",
            }
        )
        return alert

    async def correlate_alerts(self, alert: Alert, candidates: Sequence[Alert] | None = None) -> Alert:
        if candidates is None:
            candidates = await self.alert_history_repository.list_recent_alerts(
                environment=alert.environment, tenant_id=alert.tenant_id
            )
        best_match: Alert | None = None
        best_score = 0.0
        best_evidence: dict[str, Any] = {}
        for candidate in candidates:
            if candidate.tenant_id != alert.tenant_id or not same_environment_family(alert.environment, candidate.environment):
                continue
            candidate_score, evidence = self._correlation_score(alert, candidate)
            if candidate_score > best_score:
                best_match = candidate
                best_score = candidate_score
                best_evidence = evidence

        if best_match and best_score >= float(self.correlation_threshold or 0.72):
            alert.correlation_id = best_match.correlation_id or str(best_match.id)
        else:
            alert.correlation_id = str(alert.id)
        alert.metadata["correlation"] = {
            "algorithm": "weighted-enterprise-correlation-v1",
            "score": round(best_score, 4),
            "threshold": float(self.correlation_threshold or 0.72),
            "matched": bool(best_match and best_score >= float(self.correlation_threshold or 0.72)),
            "matched_alert_id": str(best_match.id) if best_match else None,
            "matched_correlation_id": str(best_match.correlation_id or best_match.id) if best_match else None,
            "evidence": best_evidence,
            "weights": dict(_CORRELATION_WEIGHTS),
        }
        return alert

    def classify_severity(self, alert: Alert) -> Alert:
        text = f"{alert.name} {alert.description}".lower()
        critical_terms = ("outage", "unavailable", "data loss", "security")
        high_terms = ("latency", "error", "saturation", "throttling", "degraded")
        threshold_breach_terms = ("above threshold", "threshold exceeded", "breach")
        has_high_signal = any(term in text for term in high_terms)
        has_threshold_breach = any(term in text for term in threshold_breach_terms)
        if (
            alert.severity == AlertSeverity.CRITICAL
            or any(term in text for term in critical_terms)
            or (has_high_signal and has_threshold_breach)
        ):
            alert.severity = AlertSeverity.CRITICAL
        elif alert.severity == AlertSeverity.HIGH or has_high_signal:
            alert.severity = AlertSeverity.HIGH
        elif "warn" in text:
            alert.severity = AlertSeverity.WARNING
        else:
            alert.severity = AlertSeverity.INFO if alert.severity == AlertSeverity.INFO else alert.severity
        return alert

    async def enrich_alert(self, alert: Alert) -> tuple[Alert, Incident]:
        alert.metadata.update(
            {
                "owner_team": alert.labels.get("team", "platform-ops"),
                "runbook_hint": alert.annotations.get("runbook", f"runbooks/{alert.service}.md"),
                "source_category": self._source_category(alert.source),
            }
        )
        await self.alert_history_repository.record_alert(alert)
        incident = Incident(
            tenant_id=alert.tenant_id,
            alert_ids=[alert.id],
            service=alert.service,
            environment=alert.environment,
            severity=alert.severity,
            status=IncidentStatus.INVESTIGATING,
            title=f"{alert.service}: {alert.name}",
            summary=alert.description,
            owner_team=alert.metadata["owner_team"],
        )
        return alert, incident

    async def process(self, alert: Alert, llm_discovery: dict[str, Any] | None = None) -> tuple[Alert, Incident]:
        # Dedup and correlation both need a recent-alert candidate pool; fetch
        # it once (environment-scoped) instead of two independent unfiltered
        # history scans per incoming alert.
        # Run-scoped test environments (for example e2e-<timestamp>) belong
        # to one operational environment. Fetch the tenant pool for those
        # environments, then apply the family boundary in both algorithms.
        candidate_environment = alert.environment
        if is_ephemeral_environment(alert.environment):
            candidate_environment = None
        candidates = await self.alert_history_repository.list_recent_alerts(
            environment=candidate_environment, tenant_id=alert.tenant_id
        )
        alert = await self.deduplicate_alerts(alert, candidates)
        alert = await self.correlate_alerts(alert, candidates)
        alert = self.classify_severity(alert)
        alert, incident = await self.enrich_alert(alert)
        candidate = build_incident_candidate(alert, incident, llm_discovery)
        criticality = str(alert.labels.get("service_criticality") or alert.labels.get("criticality") or "medium")
        policy = IncidentSeverityPolicy().evaluate(candidate, service_criticality=criticality)
        candidate.final_severity = policy.final_severity
        alert.severity = policy.final_severity
        incident.severity = policy.final_severity
        incident.title = candidate.title
        incident.summary = candidate.description
        incident.ticket_id = candidate.jira_key
        incident.metadata.update(
            {
                "incident_candidate": candidate.model_dump(mode="json"),
                "severity_policy": policy.model_dump(mode="json"),
                "managed_by_kaiops": True,
                "kaiops_incident_id": str(incident.id),
                "event_origin": "kaiops",
            }
        )
        return alert, incident

    async def can_execute(self, context: AgentContext) -> bool:
        return context.alert is not None

    async def execute(self, context: AgentContext) -> dict[str, Any]:
        if context.alert is None:
            raise ValueError("AgentContext.alert is required")
        alert, incident = await self.process(context.alert)
        context.alert = alert
        context.incident = incident
        context.set_result(self.name, {"alert": alert.model_dump(mode="json"), "incident": incident.model_dump(mode="json")})
        return {"alert": alert, "incident": incident}

    async def validate(self, result: Any) -> bool:
        return isinstance(result, dict) and "alert" in result and "incident" in result

    def _fingerprint(self, alert: Alert) -> str:
        alert_identity = (
            self._alert_family(alert.name)
            if is_ephemeral_environment(alert.environment)
            else self._norm(alert.name)
        )
        stable = "|".join(
            [
                self._norm(alert.source),
                alert_identity,
                self._norm(alert.service),
                environment_family(alert.environment),
                self._resource_identity(alert),
            ]
        )
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

    def _resource_identity(self, alert: Alert) -> str:
        """Return stable affected-resource identity without ephemeral pod IDs."""
        values: list[str] = []
        for source in (alert.labels, alert.annotations, alert.metadata):
            for key in _STABLE_RESOURCE_KEYS:
                value = str(source.get(key) or "").strip()
                if value:
                    values.append(f"{key}={self._norm(value)}")
        return "|".join(sorted(set(values)))

    def _resource_conflicts(self, alert: Alert, candidate: Alert) -> bool:
        left = self._resource_identity(alert)
        right = self._resource_identity(candidate)
        return bool(left and right and left != right)

    def _correlation_text(self, alert: Alert) -> str:
        labels = " ".join(f"{key}:{value}" for key, value in sorted(alert.labels.items()))
        return f"{alert.service} {alert.environment} {alert.name} {alert.description} {labels}"

    def _correlation_score(self, alert: Alert, candidate: Alert) -> tuple[float, dict[str, Any]]:
        if self._resource_conflicts(alert, candidate):
            return 0.0, {
                "resource_identity_conflict": True,
                "alert_resource": self._resource_identity(alert),
                "candidate_resource": self._resource_identity(candidate),
            }
        text_score = cosine_similarity(
            self._embed(self._correlation_text(alert)),
            self._embed(self._correlation_text(candidate)),
        )
        service_score = self._service_score(alert, candidate)
        environment_score = 1.0 if same_environment_family(alert.environment, candidate.environment) else 0.0
        topology_score, topology_evidence = self._token_overlap_score(alert, candidate, _TOPOLOGY_KEYS + _DEPENDENCY_KEYS)
        deployment_score, deployment_evidence = self._token_overlap_score(alert, candidate, _DEPLOYMENT_KEYS)
        metric_score, metric_evidence = self._token_overlap_score(alert, candidate, _METRIC_KEYS)
        temporal_score = self._temporal_score(alert, candidate)
        alert_family_score = 1.0 if self._alert_family(alert.name) == self._alert_family(candidate.name) else 0.0

        score = (
            _CORRELATION_WEIGHTS["text_similarity"] * text_score
            + _CORRELATION_WEIGHTS["service"] * service_score
            + _CORRELATION_WEIGHTS["environment"] * environment_score
            + _CORRELATION_WEIGHTS["topology"] * topology_score
            + _CORRELATION_WEIGHTS["deployment_change"] * deployment_score
            + _CORRELATION_WEIGHTS["metric_signal"] * metric_score
            + _CORRELATION_WEIGHTS["temporal"] * temporal_score
            + _CORRELATION_WEIGHTS["alert_family"] * alert_family_score
        )
        corroboration_bonus = self._corroboration_bonus(
            service_score=service_score,
            topology_score=topology_score,
            deployment_score=deployment_score,
            metric_score=metric_score,
            temporal_score=temporal_score,
        )
        score += corroboration_bonus
        evidence = {
            "text_similarity": round(text_score, 4),
            "service": round(service_score, 4),
            "environment": round(environment_score, 4),
            "topology": round(topology_score, 4),
            "topology_overlap": topology_evidence,
            "deployment_change": round(deployment_score, 4),
            "deployment_change_overlap": deployment_evidence,
            "metric_signal": round(metric_score, 4),
            "metric_signal_overlap": metric_evidence,
            "temporal": round(temporal_score, 4),
            "alert_family": round(alert_family_score, 4),
            "corroboration_bonus": round(corroboration_bonus, 4),
        }
        return min(1.0, max(0.0, score)), evidence

    def _service_score(self, alert: Alert, candidate: Alert) -> float:
        alert_service = self._norm(alert.service)
        candidate_service = self._norm(candidate.service)
        if alert_service and alert_service == candidate_service:
            return 1.0
        left = self._tokens_for(alert, ("service", "app", "application") + _DEPENDENCY_KEYS)
        right = self._tokens_for(candidate, ("service", "app", "application") + _DEPENDENCY_KEYS)
        if alert_service and alert_service in right:
            return 0.85
        if candidate_service and candidate_service in left:
            return 0.85
        return self._jaccard(left, right)

    def _token_overlap_score(
        self,
        alert: Alert,
        candidate: Alert,
        keys: tuple[str, ...],
    ) -> tuple[float, list[str]]:
        left = self._tokens_for(alert, keys)
        right = self._tokens_for(candidate, keys)
        overlap = sorted(left.intersection(right))
        return self._jaccard(left, right), overlap[:12]

    def _tokens_for(self, alert: Alert, keys: tuple[str, ...]) -> set[str]:
        values: list[str] = [alert.service, alert.environment]
        for source in (alert.labels, alert.annotations, alert.metadata):
            for key, value in source.items():
                key_norm = self._norm(key)
                if key_norm in keys or key_norm.replace("-", "_") in keys:
                    values.append(str(value))
        return {
            token
            for value in values
            for token in self._split_tokens(value)
            if token and token not in {"prod", "production", "default", "unknown", "none", "na"}
        }

    def _temporal_score(self, alert: Alert, candidate: Alert) -> float:
        seconds = abs((alert.starts_at - candidate.starts_at).total_seconds())
        window = max(60.0, float(self.retention_minutes or 30) * 60.0)
        return max(0.0, 1.0 - min(seconds, window) / window)

    def _jaccard(self, left: set[str], right: set[str]) -> float:
        if not left or not right:
            return 0.0
        return len(left.intersection(right)) / len(left.union(right))

    def _corroboration_bonus(
        self,
        *,
        service_score: float,
        topology_score: float,
        deployment_score: float,
        metric_score: float,
        temporal_score: float,
    ) -> float:
        independent_hits = sum(
            [
                service_score >= 0.5,
                topology_score >= 0.5,
                deployment_score >= 0.5,
                metric_score >= 0.5,
                temporal_score >= 0.7,
            ]
        )
        if independent_hits >= 4 and topology_score >= 0.5:
            return 0.05
        if independent_hits >= 3 and topology_score >= 0.75 and deployment_score >= 0.5:
            return 0.03
        return 0.0

    def _split_tokens(self, value: Any) -> list[str]:
        raw = str(value or "").strip().lower().replace("/", " ").replace(",", " ").replace("|", " ")
        return [token for token in raw.replace("_", "-").split() for token in token.split("-") if len(token) >= 2]

    def _alert_family(self, value: str) -> str:
        text = self._norm(value)
        for token in ("latency", "timeout", "unavailable", "down", "error", "saturation", "lag", "throughput", "quality"):
            if token in text:
                return token
        return text

    def _norm(self, value: Any) -> str:
        return str(value or "").strip().lower().replace("_", "-")

    def _embed(self, text: str) -> list[float]:
        cached = self._embedding_cache.get(text)
        if cached is not None:
            return cached
        cached = self.embedding_model.embed(text)
        self._embedding_cache[text] = cached
        if len(self._embedding_cache) > self._embedding_cache_max_size:
            self._embedding_cache.popitem(last=False)
        return cached

    def _source_category(self, source: str) -> str:
        if source in {"prometheus", "grafana", "datadog", "splunk", "azure monitor"}:
            return "monitoring"
        return "custom"
