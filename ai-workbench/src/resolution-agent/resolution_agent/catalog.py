from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from time import monotonic
from typing import Any

# 20 failure families x 10 targets x 5 safe strategies = 1,000 options.
FAMILIES = (
    (
        "availability",
        "down unavailable health crash restart",
        "Inspect health checks, restarts, events, and dependencies",
        "Restore only the unhealthy component",
        "Health checks and transactions remain stable",
    ),
    (
        "latency",
        "latency slow timeout response p95 p99",
        "Compare latency, load, saturation, traces, and baselines",
        "Remove the verified latency bottleneck",
        "Latency returns within SLO",
    ),
    (
        "error-rate",
        "error exception 5xx failure fault",
        "Identify new error signatures, endpoints, versions, and dependencies",
        "Contain the confirmed error-producing component",
        "Error rate and critical transactions recover",
    ),
    (
        "cpu-saturation",
        "cpu throttle load saturation",
        "Inspect CPU throttling, hot processes, traffic, and limits",
        "Relieve the confirmed CPU constraint",
        "CPU and throttling remain below threshold",
    ),
    (
        "memory-pressure",
        "memory oom heap leak eviction",
        "Inspect working set, OOM events, heap growth, and limits",
        "Contain memory pressure without discarding required state",
        "Memory stabilizes without new OOM events",
    ),
    (
        "disk-capacity",
        "disk filesystem volume storage inode space",
        "Inspect utilization, growth, retention, and volume health",
        "Recover approved storage headroom",
        "Capacity remains healthy without data loss",
    ),
    (
        "network-connectivity",
        "network dns connection packet tls certificate",
        "Test DNS, routes, policy, TLS, loss, and connectivity",
        "Restore the verified network path",
        "Representative connectivity checks succeed",
    ),
    (
        "database-contention",
        "database mysql postgres sql lock connection pool",
        "Inspect locks, slow queries, connections, and replication",
        "Relieve confirmed database contention",
        "Query latency, locks, and errors recover",
    ),
    (
        "cache-failure",
        "cache redis memcached stale eviction hit",
        "Inspect cache health, hit rate, memory, eviction, and origin load",
        "Recover cache while protecting the origin",
        "Hit rate and origin load stabilize",
    ),
    (
        "queue-backlog",
        "queue backlog consumer lag kafka rabbitmq dlq",
        "Inspect rates, lag, poison messages, partitions, and dependencies",
        "Drain the backlog without overwhelming dependencies",
        "Lag falls and processing remains healthy",
    ),
    (
        "deployment-regression",
        "deployment release rollout version regression",
        "Correlate onset with deployments, flags, and version telemetry",
        "Restore the last verified healthy release",
        "Service SLIs and journeys recover",
    ),
    (
        "configuration-drift",
        "configuration config drift policy setting",
        "Diff runtime configuration against approved desired state",
        "Reconcile only the verified drift",
        "Configuration and health checks converge",
    ),
    (
        "certificate-expiry",
        "certificate cert expiry x509 handshake",
        "Validate expiry, chain, hostname, trust, and rotation",
        "Rotate through the approved secret path",
        "TLS and expiry monitoring pass",
    ),
    (
        "authentication",
        "authentication authorization login 401 403 token identity",
        "Inspect identity provider, tokens, permissions, clocks, and policies",
        "Restore least-privilege access",
        "Authorized access succeeds and denials remain enforced",
    ),
    (
        "dependency-outage",
        "dependency upstream downstream third party api",
        "Verify dependency health, ownership, breakers, quotas, and propagation",
        "Isolate or recover the confirmed dependency",
        "Dependency and caller health stabilize",
    ),
    (
        "rate-limiting",
        "rate limit 429 quota throttle",
        "Inspect quotas, caller volume, retries, and protection",
        "Reduce demand or adjust an approved quota",
        "429 and retry pressure return to baseline",
    ),
    (
        "data-quality",
        "data quality schema null duplicate integrity drift",
        "Identify affected data, lineage, changes, and last valid checkpoint",
        "Quarantine bad data and restore a verified checkpoint",
        "Quality and reconciliation checks pass",
    ),
    (
        "job-failure",
        "job batch etl pipeline scheduler cron",
        "Inspect failed stage, inputs, checkpoint, dependencies, and retries",
        "Resume the bounded failed stage from a safe checkpoint",
        "Job and output reconciliation complete",
    ),
    (
        "security-event",
        "security vulnerability malware intrusion secret compromise",
        "Preserve evidence and validate scope with security response",
        "Contain using the approved security playbook",
        "Threat indicators clear and integrity is verified",
    ),
    (
        "observability-gap",
        "telemetry metric log trace monitor missing",
        "Validate instrumentation, collectors, sampling, identity, and ingestion",
        "Restore the telemetry path without changing service behavior",
        "Expected telemetry arrives with correct timestamps",
    ),
)

TARGETS = (
    ("kubernetes", "Kubernetes", "workload, namespace, and cluster"),
    ("linux", "Linux", "host, service, and process"),
    ("windows", "Windows", "host, service, and event channel"),
    ("aws", "AWS", "account, region, and resource"),
    ("azure", "Azure", "subscription, group, and resource"),
    ("gcp", "Google Cloud", "project, region, and resource"),
    ("database", "Database", "cluster, instance, and query"),
    ("network", "Network", "device, route, and policy"),
    ("saas", "SaaS/API", "tenant, endpoint, and quota"),
    ("data-platform", "Data platform", "pipeline, dataset, and checkpoint"),
)

STRATEGIES = (
    ("diagnose", "Collect targeted diagnostics", "low", "Collect and correlate evidence before changing production"),
    ("contain", "Contain blast radius", "medium", "Apply a reversible isolation or traffic-protection control"),
    ("recover", "Recover service", "medium", "Execute the approved recovery procedure against the confirmed target"),
    ("rollback", "Roll back verified change", "high", "Restore the last known-good version or configuration"),
    (
        "scale",
        "Adjust bounded capacity",
        "medium",
        "Adjust capacity within approved quotas while watching dependencies",
    ),
)


def _build_catalog() -> tuple[dict[str, Any], ...]:
    rows = []
    for family, terms, diagnostic, action, validation in FAMILIES:
        for platform, platform_label, target in TARGETS:
            for strategy, strategy_label, risk, strategy_action in STRATEGIES:
                rows.append(
                    {
                        "id": f"{family}-{platform}-{strategy}",
                        "title": f"{strategy_label}: {family.replace('-', ' ')} on {platform_label}",
                        "family": family,
                        "platform": platform,
                        "strategy": strategy,
                        "patterns": [*terms.split(), platform, platform_label.lower()],
                        "risk": risk,
                        "applicability": f"Use when evidence confirms {family.replace('-', ' ')} on {platform_label}.",
                        "prerequisites": [
                            f"Confirm the exact {target}",
                            "Capture incident-window evidence and identify the owner",
                            "Verify policy, approval, and rollback requirements",
                        ],
                        "diagnostics": [
                            diagnostic,
                            f"Compare the affected {platform_label} target with a healthy peer and recent changes",
                        ],
                        "steps": [
                            strategy_action,
                            action,
                            "Change only the confirmed target and observe a bounded safety window",
                        ],
                        "validation": [validation, "Confirm alerts clear and no dependent SLO regresses"],
                        "rollback": ["Restore the last known-good state and confirm the original safety baseline"],
                        "source": "kaims-governed-catalog-v1",
                        "execution_eligible": False,
                        "requires_evidence": True,
                        "requires_operator_review": True,
                    }
                )
    assert len(rows) == 1000
    return tuple(rows)


RESOLUTION_CATALOG = _build_catalog()
_BY_ID = {row["id"]: row for row in RESOLUTION_CATALOG}
# Runtime fallback candidates are never globally addressable.  Their key is
# scoped by the authenticated tenant so possession of an option ID cannot be
# used to probe or select another tenant's retrieved knowledge.
_KNOWLEDGE: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
_KNOWLEDGE_TTL_SECONDS = 300.0
_KNOWLEDGE_MAX_ENTRIES = 256
_LEARNED: dict[tuple[str, str], dict[str, Any]] = {}


def _tokens(value: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", value.lower()) if len(t) > 1}


_OPTION_TOKENS = tuple(frozenset(_tokens(" ".join(row["patterns"]))) for row in RESOLUTION_CATALOG)


def _build_inverted_index() -> dict[str, tuple[int, ...]]:
    mutable: dict[str, list[int]] = {}
    for index, tokens in enumerate(_OPTION_TOKENS):
        for token in tokens:
            mutable.setdefault(token, []).append(index)
    return {token: tuple(indexes) for token, indexes in mutable.items()}


_INVERTED_INDEX = _build_inverted_index()


@lru_cache(maxsize=2048)
def _ranked_matches(
    issue: str, service: str, recommended_action: str, limit: int
) -> tuple[tuple[int, float, tuple[str, ...]], ...]:
    corpus = f"{issue} {service} {recommended_action}".lower()
    tokens = _tokens(corpus)
    candidate_indexes = {index for token in tokens for index in _INVERTED_INDEX.get(token, ())}
    ranked: list[tuple[int, float, tuple[str, ...]]] = []
    for index in candidate_indexes:
        option = RESOLUTION_CATALOG[index]
        exact = [p for p in option["patterns"] if p in corpus]
        overlap = tokens & _OPTION_TOKENS[index]
        score = min(
            0.99,
            len(exact) * 0.22 + len(overlap) * 0.055 + (0.2 if option["family"].replace("-", " ") in corpus else 0),
        )
        if score:
            ranked.append((index, round(score, 3), tuple(sorted(set(exact) | overlap))))
    risk_order = {"low": 0, "medium": 1, "high": 2}
    ranked.sort(
        key=lambda match: (
            -match[1],
            risk_order.get(RESOLUTION_CATALOG[match[0]]["risk"], 9),
            RESOLUTION_CATALOG[match[0]]["id"],
        )
    )
    return tuple(ranked[:limit])


def relevant_resolutions(
    *, issue: str, service: str, recommended_action: str = "", limit: int = 6
) -> list[dict[str, Any]]:
    bounded_limit = max(1, min(limit, 20))
    return [
        {**RESOLUTION_CATALOG[index], "match_reasons": list(reasons), "relevance": score}
        for index, score, reasons in _ranked_matches(issue, service, recommended_action, bounded_limit)
    ]


def register_global_knowledge(*, tenant_id: str, matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    now = monotonic()
    for key, (registered_at, _) in list(_KNOWLEDGE.items()):
        if now - registered_at >= _KNOWLEDGE_TTL_SECONDS:
            _KNOWLEDGE.pop(key, None)
    rows = []
    for index, match in enumerate(matches[:6]):
        path = str(match.get("path") or "")
        identity = path or str(match.get("title") or index)
        option_id = f"global-knowledge-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:10]}-{index}"
        row = {
            "id": option_id,
            "title": str(match.get("title") or "Global knowledge candidate"),
            "family": "knowledge-fallback",
            "platform": "unverified",
            "strategy": "diagnose",
            "risk": "high",
            "applicability": (
                "Global knowledge matched because no governed local option cleared "
                "the relevance threshold."
            ),
            "prerequisites": [
                "Review the complete source",
                "Validate against live local evidence",
                "Convert it to an approved local runbook before execution",
            ],
            "diagnostics": [str(match.get("preview") or "Review the referenced knowledge")],
            "steps": ["Do not execute directly; submit for operator validation"],
            "validation": ["A locally evidenced and approved plan is produced"],
            "rollback": ["No production mutation is allowed from unverified knowledge"],
            "source": "global-knowledge-repository",
            "source_path": path,
            "execution_eligible": False,
            "requires_evidence": True,
            "requires_operator_review": True,
            "match_reasons": ["global knowledge fallback"],
            "relevance": min(0.6, max(0.0, float(match.get("score") or 0))),
        }
        while len(_KNOWLEDGE) >= _KNOWLEDGE_MAX_ENTRIES:
            oldest_key = min(_KNOWLEDGE, key=lambda key: _KNOWLEDGE[key][0])
            _KNOWLEDGE.pop(oldest_key, None)
        _KNOWLEDGE[(tenant_id, option_id)] = (now, row)
        rows.append(row)
    return rows


def register_learned_runbooks(
    *, tenant_id: str, runbooks: list[dict[str, Any]], issue: str, service: str,
) -> list[dict[str, Any]]:
    """Expose approved, outcome-backed runbooks as tenant-local catalog options.

    Discovery and model output can create drafts, but cannot enter this path.
    Automatic eligibility requires an approved immutable version, a verified
    prior success, no failures, low risk, and complete recovery controls.
    """
    query_tokens = _tokens(f"{issue} {service}")
    registered: list[dict[str, Any]] = []
    for record in runbooks:
        content = record.get("content") if isinstance(record.get("content"), dict) else {}
        remediation = [str(value) for value in content.get("remediation_steps", []) if str(value).strip()]
        validation = [str(value) for value in content.get("validation_steps", []) if str(value).strip()]
        rollback = [str(value) for value in content.get("rollback_steps", []) if str(value).strip()]
        scopes = [str(value).lower() for value in content.get("service_scope", []) if str(value).strip()]
        risk = str(record.get("risk_level") or content.get("risk_level") or "high").lower()
        successes = int(record.get("success_count") or 0)
        failures = int(record.get("failure_count") or 0)
        approved = str(record.get("approval_status") or "").lower() == "approved"
        complete = bool(remediation and validation and rollback)
        self_heal = bool(approved and successes >= 1 and failures == 0 and risk == "low" and complete)
        corpus = " ".join([str(content.get("name") or ""), *scopes, *content.get("diagnostic_steps", []), *remediation])
        overlap = query_tokens & _tokens(corpus)
        exact_service = service.lower() in scopes
        relevance = min(0.99, (0.65 if exact_service else 0.0) + min(0.3, len(overlap) * 0.06))
        if not exact_service and relevance < 0.35:
            continue
        option_id = f"learned-{record['runbook_id']}-v{record['version']}"
        option = {
            "id": option_id,
            "title": str(content.get("name") or f"Learned recovery for {service}"),
            "family": "learned-recovery",
            "platform": str(content.get("platform") or "discovered"),
            "strategy": "recover",
            "patterns": sorted(overlap),
            "risk": risk,
            "applicability": "Matched from a previously reviewed and validated recovery for this service.",
            "prerequisites": list(content.get("prerequisites") or []),
            "diagnostics": list(content.get("diagnostic_steps") or []),
            "steps": remediation,
            "validation": validation,
            "rollback": rollback,
            "source": "tenant-learned-resolution-catalog",
            "service_scope": scopes,
            "runbook_id": str(record["runbook_id"]),
            "runbook_version": int(record["version"]),
            "success_count": successes,
            "failure_count": failures,
            "execution_eligible": self_heal,
            "self_heal_eligible": self_heal,
            "requires_evidence": True,
            "requires_operator_review": not self_heal,
            "match_reasons": ["exact service scope", "reviewed successful recovery", *sorted(overlap)][:8],
            "relevance": round(relevance, 3),
        }
        _LEARNED[(tenant_id, option_id)] = option
        registered.append(option)
    return sorted(registered, key=lambda row: (-float(row["relevance"]), not row["self_heal_eligible"]))


def prepare_resolution_plan(*, tenant_id: str, option_id: str, issue: str, service: str) -> dict[str, Any]:
    option = _BY_ID.get(option_id)
    if option is None:
        option = _LEARNED.get((tenant_id, option_id))
    cached = _KNOWLEDGE.get((tenant_id, option_id))
    if cached is not None:
        registered_at, candidate = cached
        if monotonic() - registered_at >= _KNOWLEDGE_TTL_SECONDS:
            _KNOWLEDGE.pop((tenant_id, option_id), None)
        elif option is None:
            option = candidate
    if option is None:
        raise ValueError(f"Unknown resolution option: {option_id}")
    external = option.get("source") == "global-knowledge-repository"
    learned = option.get("source") == "tenant-learned-resolution-catalog"
    return {
        **option,
        "issue": issue,
        "service": service,
        "plan": [
            *({"phase": "diagnose", "instruction": x} for x in option["diagnostics"]),
            *({"phase": "remediate", "instruction": x} for x in option["steps"]),
            *({"phase": "validate", "instruction": x} for x in option["validation"]),
        ],
        "agent_status": "self_heal_candidate" if learned and option.get("self_heal_eligible") else "knowledge_candidate_requires_validation" if external else "prepared_for_operator_review",
        "execution_eligible": bool(learned and option.get("self_heal_eligible")),
    }
