from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from ai_workbench_common.models import Context
from common.context_enrichment_contract import EvidenceRequirement, discovery_evidence_requirements as build_evidence_requirements
from common.incident_contracts import ContextPackage
from common.models import EvidenceReference

CONTEXT_CONTRACT_VERSION = "kaiops.context.v2"

# Operational observations expire quickly; reviewed knowledge and source code
# can remain useful for longer.  A single global TTL cannot represent both.
SOURCE_POLICIES: dict[str, dict[str, Any]] = {
    "logs": {"ttl_seconds": 300, "weight": 1.3, "group": "signal"},
    "telemetry": {"ttl_seconds": 300, "weight": 1.5, "group": "signal"},
    "database": {"ttl_seconds": 300, "weight": 1.2, "group": "signal"},
    "deployments": {"ttl_seconds": 900, "weight": 1.1, "group": "causal"},
    "changes": {"ttl_seconds": 900, "weight": 1.1, "group": "causal"},
    "tickets": {"ttl_seconds": 1800, "weight": 0.9, "group": "causal"},
    "topology": {"ttl_seconds": 1800, "weight": 1.0, "group": "topology"},
    "code": {"ttl_seconds": 21600, "weight": 0.9, "group": "causal"},
    "rag": {"ttl_seconds": 86400, "weight": 0.8, "group": "action"},
    "other": {"ttl_seconds": 900, "weight": 0.5, "group": "supplemental"},
}

EVIDENCE_PLANES = ("rag", "code", "logs", "other", "tickets", "database", "topology", "telemetry")

_SOURCE_ALIASES = {
    "log": "logs",
    "logs": "logs",
    "opensearch": "logs",
    "metric": "telemetry",
    "metrics": "telemetry",
    "prometheus": "telemetry",
    "trace": "telemetry",
    "telemetry": "telemetry",
    "mysql": "database",
    "database": "database",
    "ticket": "tickets",
    "tickets": "tickets",
    "jira": "tickets",
    "servicenow": "tickets",
    "code": "code",
    "source": "code",
    "github": "code",
    "rag": "rag",
    "runbook": "rag",
    "knowledge": "rag",
    "deployment": "deployments",
    "jenkins": "deployments",
    "change": "changes",
    "cmdb": "topology",
    "kubernetes": "topology",
    "dependency": "topology",
}

_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)((?:password|passwd|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(AccountKey=)[^;\s]+"),
)


def utc_now() -> datetime:
    return datetime.now(UTC)


async def plan_missing_evidence(
    context: Context,
    investigation: Any,
) -> list[EvidenceRequirement]:
    """Turn declared gaps into deterministic, version-bound collection work."""
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    investigation_payload = (
        investigation.model_dump(mode="json")
        if hasattr(investigation, "model_dump")
        else dict(investigation or {})
    )
    tenant_id = str(
        investigation_payload.get("tenant_id") or metadata.get("tenant_id") or ""
    ).strip()
    incident_raw = str(
        investigation_payload.get("incident_id") or metadata.get("incident_id") or ""
    ).strip()
    if not tenant_id or not incident_raw:
        raise ValueError("tenant_id and incident_id are required to plan evidence")
    raw_gaps = investigation_payload.get("missing_evidence") or metadata.get("missing_evidence") or []
    return build_evidence_requirements(
        tenant_id=tenant_id, incident_id=incident_raw,
        rca_version=max(1, int(investigation_payload.get("rca_version") or 1)),
        missing_evidence=raw_gaps, now=utc_now(),
    )


def canonical_source(value: Any) -> str:
    token = str(value or "other").strip().lower()
    return _SOURCE_ALIASES.get(token, token if token in SOURCE_POLICIES else "other")


def _bounded_text(value: Any, limit: int = 8000) -> str:
    text = str(value or "")[:limit]
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(r"\1***", text)
    return text


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).strip().lower() in {
                "password", "passwd", "secret", "token", "access_token",
                "refresh_token", "api_key", "authorization", "connection_string",
            }:
                result[key] = "***"
            else:
                result[key] = _redact(item)
        return result
    if isinstance(value, list):
        return [_redact(item) for item in value[:100]]
    if isinstance(value, str):
        return _bounded_text(value)
    return value


def _as_utc(value: Any, fallback: datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value or "").strip()
        if not raw:
            return fallback
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return fallback
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _clamp(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    if number > 1.0:
        number /= 100.0
    return max(0.0, min(number, 1.0))


def context_subject_fingerprint(alert: Any, tenant_id: str = "default") -> str:
    labels = alert.labels if isinstance(getattr(alert, "labels", None), dict) else {}
    metadata = alert.metadata if isinstance(getattr(alert, "metadata", None), dict) else {}
    material = {
        "tenant_id": tenant_id or "default",
        "service": str(getattr(alert, "service", "unknown") or "unknown").strip().lower(),
        "environment": str(getattr(alert, "environment", "prod") or "prod").strip().lower(),
        "target": {
            key: str(labels.get(key) or metadata.get(key) or "").strip().lower()
            for key in (
                "application", "project", "cluster", "namespace", "deployment",
                "release", "version", "region", "resource_id", "subscription_id",
            )
            if str(labels.get(key) or metadata.get(key) or "").strip()
        },
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def plan_connectors(alert: Any, available: list[str]) -> tuple[list[str], list[str]]:
    """Select the smallest useful connector set for this alert.

    Small custom connector sets are test/plugin compositions and are preserved
    verbatim. The production set uses four baseline sources and expands only
    when alert semantics justify deployment, Kubernetes, or local-code probes.
    """

    names = list(dict.fromkeys(str(name) for name in available if str(name)))
    if len(names) <= 3:
        return names, ["custom_connector_set"]

    selected = {name for name in ("prometheus", "cmdb", "discovery-mcp", "vector-db") if name in names}
    reasons = ["baseline_signal_topology_discovery_knowledge"]
    labels = getattr(alert, "labels", {}) if isinstance(getattr(alert, "labels", None), dict) else {}
    metadata = getattr(alert, "metadata", {}) if isinstance(getattr(alert, "metadata", None), dict) else {}
    raw_haystack = " ".join(
        [
            str(getattr(alert, "source", "")),
            str(getattr(alert, "name", "")),
            str(getattr(alert, "description", "")),
            " ".join(f"{key}={value}" for key, value in labels.items()),
        ]
    )
    haystack = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", raw_haystack).lower()
    has_change_signal = bool(
        re.search(r"\b(deploy|deployment|release|rollout|revision|version|change|commit|build)\b", haystack)
        or any(str(labels.get(key) or metadata.get(key) or "").strip() for key in ("deployment", "release", "version", "change_id", "build"))
    )
    has_kubernetes_signal = bool(
        re.search(r"\b(kubernetes|k8s|pod|container|namespace|deployment|statefulset|daemonset)\b", haystack)
        or any(str(labels.get(key) or metadata.get(key) or "").strip() for key in ("cluster", "namespace", "pod", "container"))
    )
    has_local_evidence_signal = has_change_signal or bool(
        re.search(
            r"\b(exception|stack|traceback|error|failed|failure|crash|source|code|log|latency|timeout|5xx|availability|down)\b",
            haystack,
        )
    )
    if has_change_signal:
        selected.update(name for name in ("jenkins", "github", "servicenow") if name in names)
        reasons.append("change_correlation_requested")
    if has_kubernetes_signal:
        selected.update(name for name in ("kubernetes",) if name in names)
        reasons.append("runtime_topology_requested")
    if has_local_evidence_signal:
        selected.update(name for name in ("local-evidence",) if name in names)
        reasons.append("bounded_local_evidence_requested")
    if not selected:
        return names, ["fallback_all_connectors"]
    return [name for name in names if name in selected], reasons


def _relevance(row: dict[str, Any], context: Context) -> float:
    service = str(context.alert.service or "").strip().lower()
    alert_tokens = {
        token for token in re.findall(r"[a-z0-9_.-]{3,}", f"{context.alert.name} {context.alert.description}".lower())
    }
    text = " ".join(str(value) for value in row.values()).lower()
    matched = sum(1 for token in alert_tokens if token in text)
    service_match = bool(service and (service in text or service.removeprefix("kaiops-") in text))
    supplied = row.get("relevance_score", row.get("match_confidence", row.get("similarity")))
    lexical = min(1.0, (0.55 if service_match else 0.0) + min(0.45, matched * 0.09))
    return max(_clamp(supplied), lexical, 0.25 if row.get("uri") else 0.1)


def _traceable_citation(row: dict[str, Any]) -> str:
    provenance = row.get("provenance") if isinstance(row.get("provenance"), dict) else {}
    value = _bounded_text(
        row.get("citation") or row.get("source_uri") or row.get("uri")
        or row.get("url") or row.get("path") or row.get("source_ref")
        or provenance.get("primary_source") or "",
        1000,
    ).strip()
    if not value or value.lower().startswith(("context://", "unknown://", "unavailable://")):
        return ""
    return value


def _normalise_row(
    row: dict[str, Any],
    *,
    context: Context,
    bucket: str,
    collected_at: datetime,
    now: datetime,
    reused: bool,
) -> dict[str, Any]:
    public = _redact(dict(row))
    source = canonical_source(public.get("source") or public.get("kind") or bucket)
    policy = SOURCE_POLICIES[source]
    observed_value = (
        public.get("observed_at")
        or public.get("timestamp")
        or public.get("updated_at")
        or public.get("created_at")
        or public.get("collected_at")
    )
    observed_at_inferred = bool(public.get("observed_at_inferred")) or not bool(observed_value)
    observed_at = _as_utc(observed_value, collected_at)
    retrieved_at = _as_utc(public.get("retrieved_at"), collected_at)
    age_seconds = max(0.0, (now - observed_at).total_seconds())
    alert_started_at = _as_utc(context.alert.starts_at or context.alert.created_at, collected_at)
    incident_window_aligned = abs((observed_at - alert_started_at).total_seconds()) <= 20 * 60
    ttl_seconds = int(policy["ttl_seconds"])
    freshness_score = max(0.0, min(1.0, 1.0 - (age_seconds / max(1, ttl_seconds))))
    if observed_at_inferred and source in {"logs", "telemetry", "database", "deployments", "changes", "tickets"}:
        freshness_score = min(freshness_score, 0.5)
    uri = _traceable_citation(public)
    summary = _bounded_text(
        public.get("summary") or public.get("snippet") or public.get("matched_line") or public.get("content") or "",
        4000,
    )
    digest_material = json.dumps(
        {"source": source, "uri": uri, "summary": summary, "observed_at": observed_at.isoformat()},
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    content_sha256 = hashlib.sha256(digest_material.encode("utf-8")).hexdigest()
    evidence_id = str(public.get("evidence_id") or public.get("id") or "").strip() or f"CTX-{content_sha256[:20]}"
    public.update(
        {
            "evidence_id": evidence_id,
            "source": source,
            "category": str(public.get("category") or bucket),
            "source_id": str(public.get("source_id") or source),
            "connector": str(public.get("connector") or public.get("provider") or source),
            "tenant_id": str(public.get("tenant_id") or context.tenant_id or "default"),
            "project_id": str(
                public.get("project_id") or context.alert.metadata.get("project_id")
                or context.alert.labels.get("project_id") or "default"
            ),
            "service": str(public.get("service") or context.alert.service or "unknown"),
            "resource_id": public.get("resource_id") or public.get("resource"),
            "uri": uri,
            "citation": uri,
            "traceable": bool(uri),
            "summary": summary or f"{source} evidence collected for {context.alert.service}",
            "observed_at": observed_at.isoformat(),
            "observed_at_inferred": observed_at_inferred,
            "timestamp_quality": "retrieval_fallback" if observed_at_inferred else "source_timestamp",
            "timestamp": observed_at.isoformat(),
            "collected_at": collected_at.isoformat(),
            "retrieved_at": retrieved_at.isoformat(),
            "observation_window": public.get("observation_window"),
            "age_seconds": round(age_seconds, 3),
            "incident_window_aligned": incident_window_aligned,
            "ttl_seconds": ttl_seconds,
            "freshness_score": round(freshness_score, 4),
            "freshness": "Fresh" if freshness_score > 0 else "Stale",
            "cached": bool(reused or public.get("cached")),
            "confidence": _clamp(public.get("confidence", public.get("match_confidence", 0.65)), 0.65),
            "relevance_score": round(_relevance(public, context), 4),
            "content_sha256": content_sha256,
            "redaction_applied": True,
            "epistemic_role": public.get("epistemic_role") or "current_observation",
            "current_observation": public.get("current_observation") is not False,
            "provenance": {
                "entity": evidence_id,
                "activity": "kaiops-context-collection",
                "agent": source,
                "generated_at": retrieved_at.isoformat(),
                "primary_source": uri or None,
                "content_sha256": content_sha256,
            },
        }
    )
    return public


def _context_material(context: Context, buckets: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {
        "service": str(context.alert.service or "unknown").lower(),
        "environment": str(context.alert.environment or "prod").lower(),
        "deployment": context.deployment,
        "dependencies": sorted(str(item) for item in context.dependency_services),
        "changes": context.recent_changes,
        "cmdb": context.cmdb,
        "kubernetes": context.kubernetes,
        "observability": context.observability,
        "runbook_sha256": hashlib.sha256(str(context.runbook or "").encode("utf-8")).hexdigest(),
        "evidence": sorted(
            str(row.get("content_sha256") or "")
            for rows in buckets.values()
            for row in rows
            if row.get("content_sha256")
        ),
    }


def _has_context_fact(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_has_context_fact(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_has_context_fact(item) for item in value)
    return value is not None and value != ""


def assess_context(context: Context, *, now: datetime | None = None, threshold: float = 0.70) -> dict[str, Any]:
    now = now or utc_now()
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    buckets = metadata.get("context_evidence") if isinstance(metadata.get("context_evidence"), dict) else {}
    discovery = metadata.get("discovery_report") if isinstance(metadata.get("discovery_report"), dict) else {}
    discovery_degraded = bool(
        discovery.get("evidence_gap")
        or str(discovery.get("provider_status") or "").lower() in {"failed", "degraded", "unavailable"}
    )
    all_rows = [row for rows in buckets.values() if isinstance(rows, list) for row in rows if isinstance(row, dict)]
    present = {
        "identity": bool(str(context.alert.service or "").strip() and str(context.alert.service).lower() != "unknown"),
        "signal": bool(context.observability or buckets.get("logs") or buckets.get("telemetry") or buckets.get("database")),
        "topology": _has_context_fact([context.cmdb, context.kubernetes, context.dependency_services, context.deployment]),
        "causal": bool(context.recent_changes or buckets.get("changes") or buckets.get("deployments") or buckets.get("tickets") or buckets.get("code")),
        "action": bool(context.runbook or buckets.get("rag")),
    }
    weights = {"identity": 0.15, "signal": 0.35, "topology": 0.15, "causal": 0.20, "action": 0.15}
    coverage = sum(weights[name] for name, available in present.items() if available)
    severity = str(getattr(context.alert.severity, "value", context.alert.severity) or "warning").lower()
    # A context snapshot is usable when it identifies the subject and carries
    # a real signal.  Causal/action evidence determines RCA and execution
    # readiness; it must not make otherwise valid observations look unusable.
    required = ["identity", "signal"]
    missing_required = [name for name in required if not present.get(name)]
    diagnostic_gaps: list[str] = []
    if severity in {"critical", "high"} and not (present["causal"] or present["action"]):
        diagnostic_gaps.append("causal_or_action")
    if discovery_degraded and "discovery_evidence" not in missing_required:
        missing_required.append("discovery_evidence")
    missing = [name for name, available in present.items() if not available]

    if all_rows:
        source_weight = sum(float(SOURCE_POLICIES[canonical_source(row.get("source"))]["weight"]) for row in all_rows)
        freshness = sum(
            _clamp(row.get("freshness_score")) * float(SOURCE_POLICIES[canonical_source(row.get("source"))]["weight"])
            for row in all_rows
        ) / max(source_weight, 0.01)
        provenance = sum(
            (
                0.65 if row.get("observed_at_inferred") else 1.0
            )
            if row.get("uri") and row.get("observed_at") and row.get("content_sha256")
            else 0.0
            for row in all_rows
        ) / len(all_rows)
        relevance = sum(_clamp(row.get("relevance_score")) for row in all_rows) / len(all_rows)
    else:
        collected_at = _as_utc(metadata.get("context_collected_at"), now)
        age = max(0.0, (now - collected_at).total_seconds())
        freshness = max(0.0, 1.0 - age / SOURCE_POLICIES["other"]["ttl_seconds"])
        provenance = 0.35 if any(present.values()) else 0.0
        relevance = 0.5 if present["identity"] else 0.0

    stale_sources = sorted(
        {
            canonical_source(row.get("source"))
            for row in all_rows
            if _clamp(row.get("freshness_score")) <= 0.0
            and not bool(row.get("incident_window_aligned"))
        }
    )
    conflicts = metadata.get("context_conflicts") if isinstance(metadata.get("context_conflicts"), list) else []
    represented_planes = {
        canonical_source(source)
        for source, rows in buckets.items()
        if isinstance(rows, list) and any(isinstance(row, dict) for row in rows)
    }
    source_coverage = len(represented_planes.intersection(EVIDENCE_PLANES)) / len(EVIDENCE_PLANES)
    direct_signal_planes = represented_planes.intersection({"logs", "telemetry", "database"})
    causal_planes = represented_planes.intersection({"code", "tickets", "deployments", "changes"})
    inferred_timestamp_ratio = (
        sum(1 for row in all_rows if row.get("observed_at_inferred")) / len(all_rows)
        if all_rows else 0.0
    )
    # Score what was actually observable. Missing optional planes remain
    # explicit gaps, but are not treated as measured zero-quality evidence.
    observed_quality = (freshness + provenance + relevance) / 3
    signal_strength = min(1.0, 0.75 + (0.25 * max(0, len(direct_signal_planes) - 1))) if direct_signal_planes else 0.0
    causal_strength = min(1.0, 0.75 + (0.25 * max(0, len(causal_planes) - 1))) if causal_planes else 0.0
    rca_readiness = (
        (observed_quality * 0.40)
        + (signal_strength * 0.30)
        + (causal_strength * 0.20)
        + (0.10 if "topology" in represented_planes else 0.0)
        - (inferred_timestamp_ratio * 0.15)
    )
    if not direct_signal_planes:
        rca_readiness = min(rca_readiness, 0.35)
    rca_readiness = _clamp(rca_readiness)
    impact_readiness = _clamp(
        (observed_quality * 0.45)
        + (signal_strength * 0.40)
        + (0.15 if "topology" in represented_planes else 0.0)
        - (inferred_timestamp_ratio * 0.10)
    )
    if not direct_signal_planes:
        impact_readiness = min(impact_readiness, 0.20)
    confidence = (coverage * 0.45) + (freshness * 0.25) + (provenance * 0.20) + (relevance * 0.10)
    confidence = max(0.0, min(confidence, 1.0))
    if discovery_degraded:
        confidence = min(confidence, 0.49)
    reusable = bool(confidence >= threshold and not missing_required and not stale_sources and not conflicts)
    valid_for = min(
        (
            max(0, int(row.get("ttl_seconds") or 0) - int(
                max(0.0, (now - _as_utc(row.get("retrieved_at"), now)).total_seconds())
                if row.get("incident_window_aligned")
                else float(row.get("age_seconds") or 0)
            ))
            for row in all_rows
        ),
        default=max(0, int(SOURCE_POLICIES["other"]["ttl_seconds"])),
    )
    return {
        "contract_version": CONTEXT_CONTRACT_VERSION,
        "quality_score": round(confidence, 4),
        "coverage_score": round(coverage, 4),
        "source_coverage_score": round(source_coverage, 4),
        "freshness_score": round(freshness, 4),
        "provenance_score": round(provenance, 4),
        "relevance_score": round(relevance, 4),
        "threshold": round(max(0.0, min(threshold, 1.0)), 4),
        "reusable": reusable,
        "rca_readiness_score": round(rca_readiness, 4),
        "rca_ready": bool(
            rca_readiness >= 0.70
            and bool(direct_signal_planes)
            and bool(causal_planes)
            and not conflicts
        ),
        "impact_readiness_score": round(impact_readiness, 4),
        "impact_ready": bool(impact_readiness >= 0.65 and bool(direct_signal_planes)),
        "represented_evidence_planes": sorted(represented_planes.intersection(EVIDENCE_PLANES)),
        "evidence_plane_count": len(EVIDENCE_PLANES),
        "execution_ready": bool(
            reusable
            and rca_readiness >= 0.70
            and bool(direct_signal_planes)
            and bool(causal_planes)
            and not discovery_degraded
            and not conflicts
        ),
        "discovery_degraded": discovery_degraded,
        "present": present,
        "missing_context": missing,
        "missing_required": missing_required,
        "diagnostic_gaps": diagnostic_gaps,
        "stale_sources": stale_sources,
        "conflicts": conflicts,
        "evidence_count": len(all_rows),
        "valid_for_seconds": valid_for,
        "assessed_at": now.isoformat(),
    }


def govern_context(
    context: Context,
    *,
    tenant_id: str = "default",
    subject_fingerprint: str | None = None,
    now: datetime | None = None,
    threshold: float = 0.70,
    max_evidence_per_source: int = 20,
) -> Context:
    now = now or utc_now()
    result = context.model_copy(deep=True)
    metadata = result.metadata if isinstance(result.metadata, dict) else {}
    collected_at = _as_utc(metadata.get("context_collected_at"), now)
    reused = bool(metadata.get("context_reused"))
    raw_buckets = metadata.get("context_evidence") if isinstance(metadata.get("context_evidence"), dict) else {}
    discovery = metadata.get("discovery_report") if isinstance(metadata.get("discovery_report"), dict) else {}
    discovery_rows = discovery.get("evidence") if isinstance(discovery.get("evidence"), list) else []

    combined: dict[str, list[dict[str, Any]]] = {
        source: [dict(row) for row in rows if isinstance(row, dict)]
        for source, rows in raw_buckets.items()
        if isinstance(rows, list)
    }
    for row in discovery_rows:
        if isinstance(row, dict):
            combined.setdefault(canonical_source(row.get("source") or row.get("kind")), []).append(dict(row))

    # Promote structured connector outputs into the same evidence ledger. This
    # prevents topology/metric facts from bypassing provenance and freshness
    # checks merely because they are first-class Context fields.
    alert_uri = f"alert://{result.alert.id}"
    if result.observability:
        telemetry_uri = alert_uri
        query = str(result.observability.get("query") or "").strip()
        window = result.observability.get("observation_window")
        endpoint = str(result.observability.get("endpoint_identity") or "").rstrip("/")
        if query and endpoint and isinstance(window, dict):
            query_params = {
                "query": query,
                "start": window.get("start"),
                "end": window.get("end"),
                "step": window.get("step"),
            }
            telemetry_uri = f"{endpoint}/api/v1/query_range?{urlencode(query_params)}"
        combined.setdefault("telemetry", []).append(
            {
                "source": "telemetry",
                "uri": telemetry_uri,
                "summary": json.dumps(result.observability, sort_keys=True, default=str),
                "observed_at": result.alert.created_at.isoformat(),
                "confidence": 0.9,
            }
        )
    topology = {
        "cmdb": result.cmdb,
        "kubernetes": result.kubernetes,
        "dependencies": result.dependency_services,
        "deployment": result.deployment,
    }
    if _has_context_fact(topology):
        combined.setdefault("topology", []).append(
            {
                "source": "topology",
                "uri": alert_uri,
                "summary": json.dumps(topology, sort_keys=True, default=str),
                "observed_at": collected_at.isoformat(),
                "confidence": 0.8,
            }
        )
    for change in result.recent_changes[:50]:
        if isinstance(change, dict):
            combined.setdefault("changes", []).append(
                {
                    **change,
                    "source": "changes",
                    "uri": change.get("uri") or change.get("url") or alert_uri,
                    "summary": change.get("summary") or change.get("title") or json.dumps(change, default=str),
                }
            )
    if result.runbook:
        combined.setdefault("rag", []).append(
            {
                "source": "rag",
                "uri": f"rag://{result.alert.service}/runbook",
                "summary": result.runbook,
                "observed_at": collected_at.isoformat(),
                "confidence": 0.75,
                "epistemic_role": "historical_knowledge",
                "current_observation": False,
            }
        )

    normalised: dict[str, list[dict[str, Any]]] = {}
    untraceable_counts: dict[str, int] = {}
    seen: set[str] = set()
    limit = max(1, min(int(max_evidence_per_source), 100))
    for raw_source, rows in combined.items():
        bucket = canonical_source(raw_source)
        ranked: list[dict[str, Any]] = []
        for row in rows:
            item = _normalise_row(
                row,
                context=result,
                bucket=bucket,
                collected_at=collected_at,
                now=now,
                reused=reused,
            )
            if not item.get("traceable"):
                untraceable_counts[bucket] = untraceable_counts.get(bucket, 0) + 1
                continue
            identity = str(item["evidence_id"])
            if identity in seen:
                continue
            seen.add(identity)
            ranked.append(item)
        # Several raw source names share a canonical plane (e.g. dependency
        # and CMDB are topology). Preserve them instead of overwriting facts.
        ranked.extend(normalised.get(bucket, []))
        ranked.sort(
            key=lambda item: (
                _clamp(item.get("freshness_score")),
                _clamp(item.get("relevance_score")),
                _clamp(item.get("confidence")),
            ),
            reverse=True,
        )
        normalised[bucket] = ranked[:limit]

    discovery = dict(discovery)
    discovery["evidence"] = [row for rows in normalised.values() for row in rows if row.get("source") != "rag"]
    existing_manifest = metadata.get("context_sources") if isinstance(metadata.get("context_sources"), dict) else {}
    source_manifest: dict[str, dict[str, Any]] = {}
    for source, details in existing_manifest.items():
        entry = dict(details) if isinstance(details, dict) else {"status": str(details)}
        entry.setdefault("collection_status", entry.get("status", "unknown"))
        entry.setdefault("inferred_timestamp_count", 0)
        source_manifest[str(source)] = entry
    for source in set(normalised) | set(untraceable_counts):
        rows = normalised.get(source, [])
        prior = source_manifest.get(source, {})
        stale = bool(rows) and all(
            _clamp(row.get("freshness_score")) <= 0.0 and not row.get("incident_window_aligned")
            for row in rows
        )
        historical = bool(rows) and all(
            _clamp(row.get("freshness_score")) <= 0.0 and row.get("incident_window_aligned")
            for row in rows
        )
        untraceable = untraceable_counts.get(source, 0)
        status = (
            "stale" if stale
            else "historical" if historical
            else "fresh" if rows
            else "unavailable" if untraceable
            else str(prior.get("status") or "no_data")
        )
        source_manifest[source] = {
            **prior,
            "attempted": bool(prior.get("attempted", True)),
            "collection_status": prior.get("collection_status", prior.get("status", "collected")),
            "status": status,
            "result_count": len(rows),
            "untraceable_count": untraceable,
            "error": prior.get("error") or (
                "Connector returned records without a traceable source reference." if untraceable else None
            ),
            "required_configuration": prior.get("required_configuration") or (
                "Configure the connector to return a durable source URI or citation." if untraceable else None
            ),
            "last_attempt_at": prior.get("last_attempt_at") or collected_at.isoformat(),
            "fresh_count": sum(1 for row in rows if _clamp(row.get("freshness_score")) > 0.0),
            "incident_aligned_count": sum(1 for row in rows if row.get("incident_window_aligned")),
            "inferred_timestamp_count": sum(1 for row in rows if row.get("observed_at_inferred")),
            "oldest_observed_at": min((str(row.get("observed_at")) for row in rows), default=None),
            "newest_observed_at": max((str(row.get("observed_at")) for row in rows), default=None),
            "ttl_seconds": int(SOURCE_POLICIES[source]["ttl_seconds"]),
            "evidence_ids": [str(row.get("evidence_id")) for row in rows],
        }
    metadata = {
        **metadata,
        "context_contract_version": CONTEXT_CONTRACT_VERSION,
        "context_collected_at": collected_at.isoformat(),
        "context_evidence": normalised,
        "context_sources": source_manifest,
        "discovery_report": discovery,
        "context_subject_fingerprint": subject_fingerprint
        or str(metadata.get("context_subject_fingerprint") or ""),
        "redaction_applied": True,
    }
    result.metadata = metadata
    material = _context_material(result, normalised)
    context_fingerprint = hashlib.sha256(
        json.dumps(material, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    result.metadata["context_fingerprint"] = context_fingerprint
    quality = assess_context(result, now=now, threshold=threshold)
    result.metadata["context_quality"] = quality
    result.metadata["context_complete"] = not quality["missing_required"]
    result.metadata["context_missing_sections"] = quality["missing_context"]
    result.metadata["context_reusable"] = quality["reusable"]
    result.metadata["context_package"] = build_context_package(result, quality).model_dump(mode="json")
    return result


def _reference(row: dict[str, Any]) -> EvidenceReference:
    return EvidenceReference(
        evidence_id=str(row.get("evidence_id") or "unknown"),
        source=str(row.get("source") or "unknown"),
        uri=str(row.get("uri") or row.get("citation") or ""),
        summary=str(row.get("summary") or "Evidence collected")[:4000],
        observed_at=_as_utc(row.get("observed_at"), utc_now()),
        confidence=_clamp(row.get("confidence"), 0.5),
        attributes={
            "freshness_score": _clamp(row.get("freshness_score")),
            "relevance_score": _clamp(row.get("relevance_score")),
            "content_sha256": str(row.get("content_sha256") or ""),
            "cached": bool(row.get("cached")),
            "observed_at_inferred": bool(row.get("observed_at_inferred")),
            "timestamp_quality": str(row.get("timestamp_quality") or "unknown"),
            "epistemic_role": str(row.get("epistemic_role") or "observation"),
            "current_observation": bool(row.get("current_observation", True)),
            "redaction_applied": bool(row.get("redaction_applied", True)),
        },
    )


def build_context_package(context: Context, quality: dict[str, Any] | None = None) -> ContextPackage:
    quality = quality or assess_context(context)
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    buckets = metadata.get("context_evidence") if isinstance(metadata.get("context_evidence"), dict) else {}
    refs = {name: [_reference(row) for row in rows if isinstance(row, dict)] for name, rows in buckets.items() if isinstance(rows, list)}
    return ContextPackage(
        incident_id=str(context.incident_id),
        affected_services=list(dict.fromkeys([str(context.alert.service), *map(str, context.dependency_services)])),
        related_incidents=context.related_incidents,
        relevant_logs=refs.get("logs", []),
        metric_anomalies=[*refs.get("telemetry", []), *refs.get("database", [])],
        recent_changes=[*refs.get("changes", []), *refs.get("tickets", [])],
        deployments=refs.get("deployments", []),
        dependencies=refs.get("topology", []),
        runbooks=refs.get("rag", []),
        knowledge_documents=refs.get("rag", []),
        source_code_evidence=refs.get("code", []),
        evidence_source=sorted(refs),
        evidence_timestamp=_as_utc(metadata.get("context_collected_at"), utc_now()),
        relevance_score=_clamp(quality.get("relevance_score")),
        confidence=_clamp(quality.get("quality_score")),
        missing_context=[str(item) for item in quality.get("missing_context", [])],
        provenance={
            "contract_version": CONTEXT_CONTRACT_VERSION,
            "context_fingerprint": metadata.get("context_fingerprint"),
            "subject_fingerprint": metadata.get("context_subject_fingerprint"),
            "source_manifest": metadata.get("context_sources", {}),
            "redaction_applied": True,
        },
    )
