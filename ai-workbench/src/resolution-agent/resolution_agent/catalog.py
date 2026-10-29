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
        "down unavailable health crash restart stopped exit",
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
                        "patterns": [*terms.split(), *family.split("-"), platform, platform_label.lower()],
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
    expanded = re.sub(r"([a-z])([A-Z])", r"\1 \2", str(value or ""))
    return {t for t in re.findall(r"[a-z0-9]+", expanded.lower()) if len(t) > 1}


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
    platform_order = {
        "linux": 0,
        "kubernetes": 1,
        "database": 2,
        "network": 3,
        "aws": 4,
        "azure": 5,
        "gcp": 6,
        "data-platform": 7,
        "saas": 8,
        "windows": 9,
    }
    strategy_order = {
        "recover": 0,
        "scale": 1,
        "diagnose": 2,
        "contain": 3,
        "rollback": 4,
    }
    ranked.sort(
        key=lambda match: (
            -match[1],
            platform_order.get(RESOLUTION_CATALOG[match[0]]["platform"], 9),
            strategy_order.get(RESOLUTION_CATALOG[match[0]]["strategy"], 9),
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


def _extract_markdown_runbook_fields(markdown: str, service: str = "") -> dict[str, Any]:
    raw_text = str(markdown or "").strip()
    if not raw_text:
        return {}

    frontmatter: dict[str, str] = {}
    fm_match = re.match(r"\A---\s*\r?\n([\s\S]*?)\r?\n---\s*(?:\r?\n|$)", raw_text)
    if fm_match:
        for fm_line in fm_match.group(1).splitlines():
            if ":" in fm_line:
                key, value = fm_line.split(":", 1)
                frontmatter[key.strip().lower()] = value.strip().strip("'\"`")

    def _section_text(heading_pattern: str) -> str:
        match = re.search(
            rf"^##\s+(?:{heading_pattern})\s*$([\s\S]*?)(?=^##\s+|\Z)",
            raw_text,
            flags=re.IGNORECASE | re.MULTILINE,
        )
        return match.group(1).strip() if match else ""

    def _clean_items(section: str) -> list[str]:
        if not section:
            return []
        fenced = re.findall(r"```(?:[a-zA-Z0-9_-]+)?\s*\n([\s\S]*?)```", section)
        if fenced:
            items: list[str] = []
            for block in fenced:
                for line in block.splitlines():
                    cleaned = line.strip()
                    if cleaned and not cleaned.startswith("#"):
                        items.append(cleaned)
            if items:
                return items
        items = []
        for raw_line in section.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("```"):
                continue
            line = re.sub(r"^(?:[-*+]|\d+[.)])\s*", "", line).strip()
            if line.startswith("`") and line.endswith("`") and len(line) > 2:
                line = line[1:-1].strip()
            if line:
                items.append(line)
        return items

    title_match = re.search(r"^#\s+(.+)$", raw_text, flags=re.MULTILINE)
    service_match = re.search(
        r"^\s*-\s*\*{0,2}Service\*{0,2}:\s*(.+)$",
        raw_text,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    alert_match = re.search(
        r"^\s*-\s*\*{0,2}Alert\*{0,2}:\s*(.+)$",
        raw_text,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    parsed_service = (
        (service_match.group(1).strip().strip("`'\"* ") if service_match else "")
        or frontmatter.get("service", "")
        or str(service or "").strip()
    )
    parsed_alert = (
        (alert_match.group(1).strip().strip("`'\"* ") if alert_match else "")
        or frontmatter.get("alert_name", "")
        or frontmatter.get("alert", "")
    )
    title = title_match.group(1).strip() if title_match else ""
    if not parsed_alert and ":" in title:
        parsed_alert = title.split(":", 1)[1].strip()

    symptoms_section = _section_text(r"(?:Observed\s+)?Symptoms\s*&\s*Root\s*Cause|Root\s*Cause")
    root_cause_guidance = " ".join(
        line.strip()
        for line in symptoms_section.splitlines()
        if line.strip() and not line.strip().startswith("```")
    ).strip()

    return {
        "name": title,
        "alert_name": parsed_alert,
        "service_scope": [parsed_service.lower()] if parsed_service else [],
        "prerequisites": _clean_items(_section_text(r"Preconditions|Prerequisites")),
        "diagnostic_steps": _clean_items(_section_text(r"Diagnostic\s*Steps|Diagnostics")),
        "remediation_steps": _clean_items(_section_text(r"Remediation\s*Steps|Remediation|Resolution\s*Steps")),
        "validation_steps": _clean_items(_section_text(r"Validation(?:\s*Steps)?|Verification(?:\s*Steps)?")),
        "rollback_steps": _clean_items(_section_text(r"Rollback\s*Plan|Rollback(?:\s*Steps)?")),
        "root_cause_guidance": root_cause_guidance,
    }


def register_learned_runbooks(
    *,
    tenant_id: str,
    runbooks: list[dict[str, Any]],
    issue: str,
    service: str,
    alert_name: str = "",
) -> list[dict[str, Any]]:
    """Expose approved, outcome-backed runbooks as tenant-local catalog options.

    Discovery and model output can create drafts, but cannot enter this path.
    Automatic eligibility requires an approved immutable version, a verified
    prior success, no failures, low risk, and complete recovery controls.
    """
    from resolution_agent.runbooks import contains_unresolved_placeholders

    query_tokens = _tokens(f"{issue} {service} {alert_name}")
    registered: list[dict[str, Any]] = []
    normalized_tenant = str(tenant_id or "").strip()
    normalized_service = str(service or "").strip().lower()
    normalized_requested_alert = str(alert_name or "").strip().lower()
    def _as_step_list(raw_val: Any) -> list[str]:
        if isinstance(raw_val, list):
            return [str(v).strip() for v in raw_val if str(v).strip()]
        if isinstance(raw_val, str) and raw_val.strip():
            items: list[str] = []
            for raw_line in raw_val.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("```"):
                    continue
                line = re.sub(r"^(?:[-*+]|\d+[.)])\s*", "", line).strip()
                if line.startswith("`") and line.endswith("`") and len(line) > 2:
                    line = line[1:-1].strip()
                if line:
                    items.append(line)
            return items
        return []

    for record in runbooks:
        if not isinstance(record, dict):
            continue
        runbook_id = str(record.get("runbook_id") or "").strip()
        try:
            version = int(record.get("version") or 0)
        except (TypeError, ValueError):
            version = 0
        if not runbook_id or version < 1:
            continue
        record_tenant = str(record.get("tenant_id") or "").strip()
        if record_tenant and normalized_tenant and record_tenant != normalized_tenant:
            continue
        content = record.get("content") if isinstance(record.get("content"), dict) else record
        approval_status = str(
            record.get("approval_status")
            or content.get("approval_status")
            or content.get("review_status")
            or ""
        ).strip().lower()
        lifecycle_status = str(
            record.get("status")
            or content.get("status")
            or ""
        ).strip().lower()
        index_status = str(
            record.get("index_status")
            or content.get("index_status")
            or ""
        ).strip().lower()
        stale = bool(record.get("stale") or content.get("stale"))
        approved = (
            approval_status == "approved"
            and not stale
            and lifecycle_status not in {"draft", "pending_review", "rejected", "stale", "deprecated", "disabled"}
            and index_status not in {"pending", "unindexed", "failed"}
        )
        if not approved:
            continue
        markdown_text = str(content.get("markdown") or record.get("markdown") or "").strip()
        extracted = _extract_markdown_runbook_fields(
            markdown_text,
            service=str(record.get("service") or content.get("service") or ""),
        ) if markdown_text else {}
        remediation = (
            _as_step_list(content.get("remediation_steps") or record.get("remediation_steps") or record.get("steps"))
            or _as_step_list(extracted.get("remediation_steps"))
        )
        validation = (
            _as_step_list(content.get("validation_steps") or record.get("validation_steps") or content.get("verification_steps"))
            or _as_step_list(extracted.get("validation_steps"))
        )
        rollback = (
            _as_step_list(content.get("rollback_steps") or record.get("rollback_steps") or content.get("rollback_plan"))
            or _as_step_list(extracted.get("rollback_steps"))
        )
        diagnostics = (
            _as_step_list(content.get("diagnostic_steps") or record.get("diagnostic_steps"))
            or _as_step_list(extracted.get("diagnostic_steps"))
        )
        prerequisites = (
            _as_step_list(content.get("prerequisites") or record.get("prerequisites"))
            or _as_step_list(extracted.get("prerequisites"))
        )
        scopes = [
            str(value).strip().lower()
            for value in (
                _as_step_list(content.get("service_scope") or record.get("service_scope"))
                or _as_step_list(extracted.get("service_scope"))
            )
            if str(value).strip()
        ]
        record_service = str(record.get("service") or content.get("service") or "").strip().lower()
        if record_service and record_service not in scopes:
            scopes.append(record_service)
        exact_service = bool(normalized_service and normalized_service in scopes)
        if not exact_service:
            continue
        if not remediation or contains_unresolved_placeholders([*remediation, *validation, *rollback]):
            continue
        risk = str(record.get("risk_level") or content.get("risk_level") or "high").lower()
        successes = int(record.get("success_count") or 0)
        failures = int(record.get("failure_count") or 0)
        complete = bool(remediation and validation and rollback)
        self_heal = bool(approved and successes >= 1 and failures == 0 and risk == "low" and complete)
        record_alert_name = str(
            record.get("alert_name")
            or content.get("alert_name")
            or extracted.get("alert_name")
            or ""
        ).strip()
        title = str(
            record.get("title")
            or content.get("name")
            or content.get("title")
            or extracted.get("name")
            or f"Learned recovery for {service}"
        )
        corpus = " ".join([title, record_alert_name, *scopes, *diagnostics, *remediation])
        overlap = query_tokens & _tokens(corpus)
        alert_match = bool(
            record_alert_name
            and (
                record_alert_name.lower() in issue.lower()
                or (
                    normalized_requested_alert
                    and (
                        record_alert_name.lower() == normalized_requested_alert
                        or normalized_requested_alert in record_alert_name.lower()
                        or record_alert_name.lower() in normalized_requested_alert
                    )
                )
            )
        )
        if record_alert_name and record_alert_name.lower() not in {"unknown", "general"} and not alert_match and not overlap:
            continue
        relevance = min(
            0.99,
            (0.65 if exact_service else 0.0) + (0.15 if alert_match else 0.0) + min(0.3, len(overlap) * 0.06),
        )
        if not exact_service and relevance < 0.35:
            continue
        slug_seed = re.sub(r"[^a-z0-9]+", "-", normalized_service or "service").strip("-")
        runbook_slug = str(
            record.get("slug")
            or content.get("slug")
            or f"learned-{slug_seed}-{runbook_id[:8]}"
        )
        option_id = f"learned-{runbook_id}-v{version}"
        option = {
            "id": option_id,
            "title": title,
            "family": "learned-recovery",
            "platform": str(content.get("platform") or "discovered"),
            "strategy": "recover",
            "patterns": sorted(overlap),
            "risk": risk,
            "applicability": "Matched from a previously reviewed and validated recovery for this service.",
            "prerequisites": prerequisites,
            "diagnostics": diagnostics,
            "steps": remediation,
            "validation": validation,
            "rollback": rollback,
            "source": "tenant-learned-resolution-catalog",
            "service": record_service or (scopes[0] if scopes else normalized_service),
            "service_scope": scopes,
            "runbook_id": runbook_id,
            "runbook_slug": runbook_slug,
            "runbook_version": version,
            "alert_name": record_alert_name,
            "root_cause_guidance": str(
                content.get("root_cause_guidance") or extracted.get("root_cause_guidance") or ""
            ),
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
