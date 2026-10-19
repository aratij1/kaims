"""Bind the impact stage output to evidence without treating alert names as proof."""
from __future__ import annotations

import hashlib
import math
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from resolution_agent.contracts import ClaimKind, ClaimStatus, EvidenceBoundClaim


def measured_latency_impact(alert, evidence: list[dict[str, Any]]) -> dict[str, Any] | None:
    """A narrow measured service effect, independent of causal/model certainty."""
    from resolution_agent.evidence import source_metadata

    annotations = alert.annotations or {}
    expression = str(annotations.get("expression") or "")
    generator = annotations.get("generatorURL") or annotations.get("generator_url")
    if generator:
        expression = str(parse_qs(urlsplit(str(generator)).query).get("g0.expr", [expression])[0])
    threshold = re.search(r">\s*(\d+(?:\.\d+)?)\s*$", expression)
    operation = str((alert.labels or {}).get("operation") or "").split("?", 1)[0]
    if "histogram_quantile(" not in expression or not threshold or not operation.startswith("/"):
        return None
    boundary_ms = float(threshold.group(1)) * 1000
    if boundary_ms <= 0:
        return None
    matching = {}
    for row in evidence:
        uri = str(row.get("source_uri") or "")
        if (row.get("source_type") != "trace" or not uri.startswith("jaeger://trace/")
                or row.get("tenant_id") != alert.tenant_id or row.get("service") != alert.service
                or row.get("environment") != alert.environment
                or row.get("incident_window_relation") != "during"
                or row.get("current_operational_evidence") is not True
                or row.get("contradiction_status") == "contradicting"):
            continue
        metadata = source_metadata(row.get("metadata"))
        for span in metadata.get("slowest_spans") or []:
            if not isinstance(span, dict) or span.get("service") != alert.service:
                continue
            tags = span.get("tags") or {}
            route = str(tags.get("http.route") or tags.get("http.target") or "").split("?", 1)[0]
            try:
                duration = float(span.get("duration_ms") or 0)
            except (TypeError, ValueError):
                continue
            if (tags.get("span.kind") == "server" and route == operation
                    and math.isfinite(duration) and duration > boundary_ms):
                matching[uri] = (str(row["evidence_id"]), duration)
    if len(matching) < 2:
        return None
    ids = list(dict.fromkeys(item[0] for item in matching.values()))
    if len(ids) < 2:
        return None
    peak = max(item[1] for item in matching.values())
    statement = (f"At least {len(matching)} recorded {operation} requests in {alert.service} exceeded "
                 f"the {boundary_ms / 1000:g}s alert threshold; the slowest took {peak / 1000:.3f}s.")
    return EvidenceBoundClaim(
        claim_id="claim-impact-" + hashlib.sha256(statement.encode()).hexdigest()[:20],
        kind=ClaimKind.IMPACT, status=ClaimStatus.OBSERVED, source="measured-request-latency",
        statement=statement, supporting_evidence_ids=ids,
        limitations=[
            "Observed technical request latency only. Customer counts, business losses "
            "and the underlying cause are not established."
        ],
    ).model_dump(mode="json")


def evaluated_impact_claim(analysis: dict[str, Any], statement: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    statement = str(statement or analysis.get("impact_summary") or "").strip()
    if not statement:
        statement = "Customer or business impact has not been established by accepted evidence."
    citations = {str(value) for value in analysis.get("evidence_used", []) if isinstance(value, str)}
    supporting = [row for row in evidence if str(row.get("evidence_id")) in citations
                  and (row.get("source_type") in {"metric", "log", "trace", "dependency", "resource"}
                       or (analysis.get("analysis_engine") == "verified-runtime-recovery.v1"
                           and row.get("source_type") == "topology"
                           and (row.get("metadata", {}).get("runtime_lifecycle") or {}).get("Running") is False))
                  and row.get("incident_window_relation") == "during"
                  and row.get("current_operational_evidence") is True
                  and row.get("source_uri") and "://unknown/" not in str(row.get("source_uri"))
                  and row.get("contradiction_status") != "contradicting"]
    try:
        confidence = float(analysis.get("confidence_score") or 0)
    except (TypeError, ValueError):
        confidence = 0
    observation = analysis.get("observed_impact")
    observation = observation.strip() if isinstance(observation, str) else ""
    # A separate summary may describe downstream risk alongside a directly
    # observed service effect. Judge the observed claim on its own statement.
    uncertain = any(term in observation.lower() for term in (
        "not established", "no direct", "may ", "could ", "potential", "risk", "unknown", "unconfirmed",
    ))
    observed = bool(observation and not uncertain and confidence >= .55
                    and (analysis.get("context_readiness") or {}).get("ready") is True
                    and not analysis.get("external_knowledge_used")
                    and len({row["evidence_id"] for row in supporting}) >= 2
                    and len({row["source_type"] for row in supporting}) >= 2)
    status = ClaimStatus.OBSERVED if observed else ClaimStatus.NOT_ESTABLISHED
    if observed:
        statement = observation
    return EvidenceBoundClaim(
        claim_id="claim-impact-" + hashlib.sha256(statement.encode()).hexdigest()[:20],
        kind=ClaimKind.IMPACT, status=status, statement=statement,
        supporting_evidence_ids=list(dict.fromkeys(row["evidence_id"] for row in supporting)),
        falsification_test=(
            "Validate the assessed impact with incident-window availability, transaction or SLO observations."
        ),
        limitations=[] if observed else [
            "The recorded assessment has not established impact with corroborated incident-window evidence."
        ],
    ).model_dump(mode="json")
