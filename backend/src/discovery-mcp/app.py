from __future__ import annotations

from common.evidence_source_policy import is_alert_artifact_reference, log_observed_at

import aiomysql
import asyncio
import csv
import hashlib
import json
import logging
import os
import re
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

import httpx
from common.evidence_subject import service_matches, metric_matches_subject
from common.config import get_settings
from common.service import create_app
from fastapi import FastAPI
from pydantic import BaseModel, Field

logger = logging.getLogger("kaiops.discovery_mcp")

settings = get_settings()
settings.service_name = "discovery-mcp"
_background_tasks: list[asyncio.Task] = []
async def _startup(app: FastAPI) -> None:
    # Keeps the onboarding-derived project catalog warm from process start
    # instead of leaving the first several minutes of investigations without
    # dependency/telemetry evidence for any newly onboarded application.
    _background_tasks.append(asyncio.create_task(_onboarding_sync_loop()))


async def _shutdown(app: FastAPI) -> None:
    for task in _background_tasks:
        task.cancel()


app = create_app(title="KaiOps Discovery MCP", settings=settings, startup=_startup, shutdown=_shutdown)

CODE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".cs",
    ".rs", ".php", ".kt", ".kts", ".ex", ".exs", ".cpp", ".cc", ".h",
    ".proto", ".yml", ".yaml", ".json", ".toml", ".xml", ".md",
}
LOG_SUFFIXES = {".log", ".out", ".txt", ".json", ".jsonl"}
TICKET_SUFFIXES = {".csv", ".eml", ".md", ".txt"}
SECRET_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|authorization|token)\s*[:=]\s*([^\s,;]+)"
)
LOG_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("connection_refused", re.compile(r"(?i)\b(connection refused|econnrefused)\b")),
    ("timeout", re.compile(r"(?i)\b(timed? out|timeout|deadline exceeded)\b")),
    ("authentication", re.compile(r"(?i)\b(unauthorized|forbidden|authentication failed|invalid credential)\b")),
    ("resource_exhaustion", re.compile(r"(?i)\b(out of memory|oomkilled|resource exhausted|no space left)\b")),
    ("dependency_unavailable", re.compile(r"(?i)\b(unavailable|connection reset|no route to host|name resolution)\b")),
    ("exception", re.compile(r"(?i)\b(exception|traceback|panic|fatal)\b")),
    ("http_5xx", re.compile(r"\b5\d\d\b")),
    ("error", re.compile(r"(?i)\b(error|failed|failure|critical)\b")),
)


class MCPRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


def _roots(name: str, default: str) -> list[Path]:
    return [Path(item.strip()) for item in os.getenv(name, default).split(",") if item.strip()]


# Applications registered through application-onboarding are otherwise
# invisible to discovery: the curated catalog file below is hand-authored and
# nothing keeps it in sync with the onboarding registry, so a newly onboarded
# application gets zero dependency/telemetry/topology evidence forever. This
# cache is refreshed periodically from the onboarding service (see
# _onboarding_sync_loop) and merged into the catalog on every lookup, so a
# freshly onboarded application becomes discoverable without a manual catalog
# edit or a code deploy. Curated file entries always win on key collision --
# this only fills a gap, it never overrides deliberate configuration.
_ONBOARDED_PROJECTS_CACHE: dict[str, dict[str, Any]] = {}


def _onboarded_project_entry(row: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    name = str(row.get("name") or "").strip()
    if not name:
        return None
    project_id = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-") or name.lower()
    # The registered metrics_endpoint is the application's own /metrics
    # scrape target, not a queryable Prometheus server -- discovery tools
    # need the shared platform Prometheus/Jaeger that actually scrapes it,
    # scoped down by service label at query time.
    return project_id, {
        "name": name,
        "display_name": name,
        "environment": str(row.get("environment") or "").strip() or "prod",
        "aliases": [name.lower()],
        "code_roots": [],
        "telemetry": {
            "prometheus_url": os.getenv("DISCOVERY_MCP_ONBOARDED_PROMETHEUS_URL", "http://prometheus:9090"),
            "jaeger_url": os.getenv("DISCOVERY_MCP_ONBOARDED_JAEGER_URL", "http://jaeger:16686"),
        },
        "ticket_sources": {"jira_url": "", "landing_pad": "/data/landing/documents"},
        "correlation_keys": ["service", "trace_id", "incident_id", "alert_fingerprint", "environment"],
        "source": "application-onboarding",
    }


async def _refresh_onboarded_projects() -> None:
    base_url = str(getattr(settings, "application_onboarding_url", "") or "").rstrip("/")
    if not base_url:
        return
    try:
        async with httpx.AsyncClient(base_url=base_url, timeout=httpx.Timeout(8.0), trust_env=False) as client:
            response = await client.get("/applications")
            response.raise_for_status()
            rows = response.json().get("rows", [])
    except Exception as exc:
        logger.warning("onboarding catalog sync failed; keeping previous snapshot: %s", str(exc)[:240])
        return
    catalog: dict[str, dict[str, Any]] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        entry = _onboarded_project_entry(row)
        if entry:
            catalog[entry[0]] = entry[1]
    _ONBOARDED_PROJECTS_CACHE.clear()
    _ONBOARDED_PROJECTS_CACHE.update(catalog)


async def _onboarding_sync_loop() -> None:
    interval = max(15.0, float(os.getenv("DISCOVERY_MCP_ONBOARDING_SYNC_INTERVAL_SECONDS", "60")))
    while True:
        await _refresh_onboarded_projects()
        await asyncio.sleep(interval)


def _project_catalog() -> dict[str, dict[str, Any]]:
    path = Path(os.getenv("DISCOVERY_MCP_PROJECTS_FILE", "/workspace/backend/config/discovery-projects.json"))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        payload = {}
    curated = payload.get("projects") if isinstance(payload, dict) else {}
    curated = curated if isinstance(curated, dict) else {}
    # Operator-owned aliases and bindings must win over a dynamically
    # onboarded alias of the same application. Dict override precedence alone
    # is insufficient: _project_for searches entries in insertion order.
    return {**curated, **{key: value for key, value in _ONBOARDED_PROJECTS_CACHE.items() if key not in curated}}


def _project_for(arguments: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    catalog = _project_catalog()
    hints = [
        arguments.get("project"),
        arguments.get("application"),
        *(_terms(arguments)),
    ]
    normalized_hints = {str(value or "").strip().lower() for value in hints if str(value or "").strip()}
    for project_id, project in catalog.items():
        aliases = {
            str(project_id).lower(),
            str(project.get("name") or "").lower(),
            str(project.get("display_name") or "").lower(),
            *(str(alias).lower() for alias in project.get("aliases", []) if alias),
        }
        if normalized_hints & aliases or any(alias and alias in " ".join(normalized_hints) for alias in aliases):
            return str(project_id), project
    service = re.sub(r"[^a-zA-Z0-9_-]", "", str(arguments.get("service") or "").strip())
    if service:
        matches = [
            (str(project_id), project)
            for project_id, project in catalog.items()
            if str(project.get("service_catalog_root") or "").strip()
            and (Path(str(project["service_catalog_root"])) / service).is_dir()
        ]
        if len(matches) == 1:
            return matches[0]
    return "", {}


def _code_roots_legacy(arguments: dict[str, Any]) -> list[Path]:
    project_id, project = _project_for(arguments)
    configured = project.get("code_roots") if isinstance(project.get("code_roots"), list) else []
    if not configured and project_id:
        # A real project resolved (typically an application registered
        # through application-onboarding) but has no known source location
        # in this container -- most onboarded applications live in their own
        # separate repository, not this one. Falling through to the platform
        # default here would search KaiMS's own codebase and cite it as
        # evidence for a different application's incident: confidently wrong,
        # not just missing. No project match at all (project_id == "") is the
        # only case the platform-wide default is actually correct for --
        # investigating KaiMS itself.
        return []
    if configured:
        roots = [Path(str(root)) for root in configured if str(root).strip()]
        service = re.sub(r"[^a-zA-Z0-9_-]", "", str(arguments.get("service") or "").strip())
        service = {
            "log-ingestion": "monitoring-adapter",
            "email-inbox": "monitoring-adapter",
            "common.rabbitmq": "common",
        }.get(service.lower(), service)
        service_aliases = [service]
        if service.lower().startswith("kaiops-"):
            service_aliases.append(service[7:])
        catalog_root = str(project.get("service_catalog_root") or "").strip()
        if service and catalog_root:
            service_root = Path(catalog_root) / service
            if service_root.is_dir():
                roots.insert(0, service_root)
        for root in list(roots):
            for alias in service_aliases:
                candidate = root / alias
                if candidate.is_dir():
                    roots.insert(0, candidate)
        return list(dict.fromkeys(roots))
    return _roots(
        "DISCOVERY_MCP_CODE_ROOTS",
        "/workspace/backend/src,/workspace/ai-workbench/src,/workspace/frontend/react/src,/workspace/scripts,/workspace/config,/workspace/observability,/workspace/fault-lab,/workspace/docs",
    )


def _code_roots(arguments: dict[str, Any]) -> list[Path]:
    roots = _code_roots_legacy(arguments)
    service = str(arguments.get("service") or "").strip()
    if not service:
        return roots
    from common.evidence_subject import service_identity
    aliases = {service, service_identity(service)}
    project_id, project = _project_for(arguments)
    if service.lower().startswith(("robot-shop-", "rs-")) and (not project_id or project_id in {"kaiops", "kaims"} or project.get("platform") is True):
        return []
    candidates = []
    catalog_root = str(project.get("service_catalog_root") or "").strip()
    if catalog_root:
        candidates.extend(Path(catalog_root) / alias for alias in aliases)
    for root in roots:
        if root.name in aliases:
            candidates.append(root)
        candidates.extend(root / alias for alias in aliases)
    # Fault lab is a platform workload whose source is outside backend/src.
    if service_identity(service) == "fault-lab":
        candidates.extend(Path(root).parent.parent / "fault-lab" for root in roots
                          if root.as_posix().endswith("backend/src"))
    scoped = list(dict.fromkeys(path for path in candidates if path.is_dir()))
    if scoped:
        return scoped
    # Explicit external project roots remain valid project context. An unknown
    # service must never silently search the platform repository or its tests.
    if project_id and project.get("platform") is not True and project_id not in {"kaiops", "kaims"}:
        return roots
    return []


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "discovery-mcp"}


def _redact(text: str) -> str:
    return SECRET_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)


def _terms(arguments: dict[str, Any]) -> list[str]:
    values = arguments.get("terms", [])
    if not isinstance(values, list):
        values = [values]
    tokens: list[str] = []
    for value in values:
        tokens.extend(re.findall(r"[a-zA-Z0-9_.-]{3,}", str(value).lower()))
    return list(dict.fromkeys(tokens))[:24]


def _code_search_terms(arguments: dict[str, Any]) -> list[str]:
    """Keep code retrieval focused on stable service and component tokens."""

    generic_terms = {
        str(arguments.get("project") or "").strip().lower(),
        str(arguments.get("application") or "").strip().lower(),
        str(arguments.get("environment") or "").strip().lower(),
        "prod", "production", "stage", "staging", "test", "dev", "warning",
        "failed", "failure", "error", "request", "list", "from", "with",
        "into", "unable", "resource", "service", "message",
    }
    service = str(arguments.get("service") or "").strip().lower()
    from common.evidence_subject import service_identity
    # The alert identity commonly has a deployment prefix which source files
    # do not contain. Keep the original identity, but search its code alias too.
    question = str(arguments.get("question") or "")
    diagnostic_terms: list[str] = []
    if re.search(r"\b(?:5xx|50[0-9]|http|server error)\b", question, re.I):
        diagnostic_terms.extend(["httpexception", "status_code", "exception"])
    if re.search(r"\b(?:timeout|timed out|connection|connectivity)\b", question, re.I):
        diagnostic_terms.extend(["timeout", "connect"])
    diagnostic_terms.extend(re.findall(r"[\w/-]+\.(?:py|go|js|ts|java)\b", question.lower()))
    candidates = [service, service_identity(service), *diagnostic_terms, *_terms(arguments)]
    selected: list[str] = []
    for term in candidates:
        token = str(term or "").strip().lower()
        if not token or token in generic_terms or token.isdigit():
            continue
        if re.fullmatch(r"[0-9a-f]{16,}", token) or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f-]{27,}", token
        ):
            continue
        if re.match(r"^\d{4}-\d{2}-\d{2}", token):
            continue
        if len(token) < 4 or token in selected:
            continue
        selected.append(token)
        if len(selected) >= 8:
            break
    return selected


def _evidence(kind: str, path: Path, line: int, snippet: str, matched: list[str]) -> dict[str, Any]:
    safe_snippet = _redact(re.sub(r"\s+", " ", snippet).strip())[:700]
    digest = hashlib.sha256(f"{kind}|{path}|{line}|{safe_snippet}".encode()).hexdigest()[:16]
    evidence = {
        "evidence_id": f"{kind.upper()}-{digest}",
        "source": kind,
        "uri": f"{kind}://{path.as_posix()}#L{line}",
        "path": str(path),
        "line": line,
        "snippet": safe_snippet,
        "matched_terms": matched,
        "sha256": hashlib.sha256(safe_snippet.encode()).hexdigest(),
    }
    if kind == "log":
        observed = log_observed_at(snippet)
        if observed:
            evidence["observed_at"] = observed
        evidence["diagnostic_signals"] = [
            signal for signal, pattern in LOG_SIGNAL_PATTERNS if pattern.search(safe_snippet)
        ]
    return evidence


def _log_diagnosis(evidence: list[dict[str, Any]], service: str = "") -> dict[str, Any] | None:
    counts: dict[str, int] = {}
    supporting_ids: list[str] = []
    for row in evidence:
        if str(row.get("source") or "").lower() not in {"log", "opensearch"}:
            continue
        signals = row.get("diagnostic_signals") if isinstance(row.get("diagnostic_signals"), list) else []
        for signal in signals:
            token = str(signal)
            counts[token] = counts.get(token, 0) + 1
        if signals and row.get("evidence_id"):
            supporting_ids.append(str(row["evidence_id"]))
    if not counts:
        return None
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    target = service or "selected service"
    summary = ", ".join(f"{name.replace('_', ' ')} ({count})" for name, count in ranked[:5])
    item = _evidence(
        "log",
        Path(f"diagnosis/{target}"),
        1,
        f"Structured log diagnosis for {target}: {summary}. Correlate these signals before assigning root cause.",
        [name for name, _ in ranked[:5]],
    )
    item.update(
        {
            "signal_type": "log_diagnosis",
            "derived_observation": True,
            "current_observation": False,
            "diagnostic_signals": [name for name, _ in ranked],
            "signal_counts": dict(ranked),
            "supporting_evidence": supporting_ids[:12],
            "service": target,
        }
    )
    return item


def _decode_docker_log_stream(payload: bytes) -> str:
    """Decode Docker's multiplexed stdout/stderr stream, with plain-text fallback."""
    chunks: list[bytes] = []
    offset = 0
    while offset + 8 <= len(payload):
        frame_size = int.from_bytes(payload[offset + 4 : offset + 8], "big")
        frame_end = offset + 8 + frame_size
        if payload[offset] not in {0, 1, 2} or frame_end > len(payload):
            break
        chunks.append(payload[offset + 8 : frame_end])
        offset = frame_end
    if chunks:
        # Keep whatever frames parsed cleanly even if a trailing frame was cut short (e.g.
        # by a streaming read boundary) instead of discarding good data for one bad frame.
        return b"".join(chunks).decode("utf-8", errors="replace")
    return payload.decode("utf-8", errors="replace")


async def _search_docker_logs(arguments: dict[str, Any], terms: list[str], limit: int) -> list[dict[str, Any]]:
    if str(os.getenv("DOCKER_LOG_DISCOVERY_ENABLED", "true")).strip().lower() not in {"1", "true", "yes", "on"}:
        return []
    # Talk to a scoped docker-socket-proxy (read-only GET on /containers*) rather than mounting
    # /var/run/docker.sock into this container directly. A raw socket mount is root-on-host even
    # when the bind mount itself is ":ro" -- that flag only stops the container from replacing
    # the socket *file*, it does not restrict which Docker API calls (create/exec/mount) are
    # reachable through it. The proxy (see docker-compose.yml) only allows GET on containers.
    docker_host = str(os.getenv("DOCKER_LOG_DISCOVERY_HOST", "docker-socket-proxy:2375")).strip()
    if not docker_host:
        return []
    service = str(arguments.get("service") or "").strip().lower()
    project = _runtime_project_scope(arguments)
    max_containers = max(1, min(int(os.getenv("DOCKER_LOG_DISCOVERY_MAX_CONTAINERS", "40")), 100))
    tail = max(20, min(int(os.getenv("DOCKER_LOG_DISCOVERY_TAIL", "250")), 2000))
    timeout = httpx.Timeout(max(2.0, min(float(os.getenv("DOCKER_LOG_DISCOVERY_TIMEOUT_SECONDS", "10")), 30.0)))
    evidence: list[dict[str, Any]] = []
    log_params = {"stdout": "true", "stderr": "true", "timestamps": "true", "tail": str(tail)}
    for argument_name, docker_name in (("start_time", "since"), ("end_time", "until")):
        raw_time = str(arguments.get(argument_name) or "").strip()
        if not raw_time:
            continue
        try:
            parsed_time = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            log_params[docker_name] = str(int(parsed_time.timestamp()))
        except ValueError:
            continue
    try:
        async with httpx.AsyncClient(base_url=f"http://{docker_host}", timeout=timeout) as client:
            project_id, project_entry = _project_for(arguments)
            response = await client.get("/containers/json", params=_docker_container_list_params(
                service, platform_wide=_is_platform_wide_target(service, project_id, project_entry), limit=max_containers,
            ))
            response.raise_for_status()
            containers = response.json()
            for container in containers[:max_containers]:
                if not isinstance(container, dict):
                    continue
                names = [str(name).lstrip("/") for name in container.get("Names", []) if name]
                labels = container.get("Labels") if isinstance(container.get("Labels"), dict) else {}
                compose_service = str(labels.get("com.docker.compose.service") or "")
                identity = " ".join([*names, compose_service, str(container.get("Image") or "")]).lower()
                # A filter that wasn't provided must not count as "matched" -- otherwise, e.g.
                # a service-only query (project == "") would trivially satisfy `not project`
                # and every container would pass regardless of whether service_ok is true.
                has_project_filter = bool(project)
                has_service_filter = bool(service)
                project_ok = has_project_filter and (
                    (project.startswith("telemetry") and "telemetry-" in identity)
                    or (project.startswith("kaiops") and "kaiops" in identity)
                    or project in identity
                )
                service_ok = has_service_filter and service_matches(compose_service, service)
                if has_service_filter and not service_ok:
                    continue
                if not has_service_filter and has_project_filter and not project_ok:
                    continue
                container_id = str(container.get("Id") or "")
                if not container_id:
                    continue
                logs = await client.get(
                    f"/containers/{container_id}/logs",
                    params=log_params,
                )
                logs.raise_for_status()
                container_name = names[0] if names else container_id[:12]
                for line_number, line in enumerate(_decode_docker_log_stream(logs.content).splitlines(), 1):
                    lowered = line.lower()
                    matched = [term for term in terms if term in lowered or term in identity]
                    signals = [signal for signal, pattern in LOG_SIGNAL_PATTERNS if pattern.search(line)]
                    if not matched and not signals:
                        continue
                    item = _evidence("log", Path(f"docker/{container_name}"), line_number, line, matched)
                    item.update(
                        {
                            "uri": f"docker://{container_name}#L{line_number}",
                            "container": container_name,
                            "container_id": container_id[:12],
                            "service": compose_service or service or container_name,
                            "diagnostic_signals": signals,
                            "log_channel": "docker",
                        }
                    )
                    evidence.append(item)
    except Exception as exc:
        logger.warning(
            "docker_log_discovery_unavailable",
            extra={"error": str(exc)[:240], "docker_host": docker_host},
        )
        return []
    evidence.sort(key=lambda row: (not bool(row.get("diagnostic_signals")), str(row.get("container") or "")))
    return evidence[:limit]


def _search_text_files(
    roots: list[Path], suffixes: set[str], terms: list[str], kind: str, limit: int
) -> list[dict[str, Any]]:
    ranked: list[tuple[int, int, dict[str, Any]]] = []
    max_files = max(10, min(int(os.getenv("DISCOVERY_MCP_MAX_FILES", "60")), 400))
    excluded_dirs = {".git", ".claiming", "node_modules", "dist", "build", "__pycache__", "ingested_alerts", ".venv", "kaiops.egg-info"}
    if kind == "code":
        excluded_dirs.update({".github", ".devcontainer", "tests", "__tests__"})
    for root_index, root in enumerate(roots):
        if not root.is_dir():
            continue
        scanned = 0
        # A project-specific service root is intentionally searched more deeply.
        # The broader repository fallback keeps the normal global crawl bound.
        root_budget = 400 if root_index == 0 and len(roots) > 1 else max_files
        for current, directories, files in os.walk(root):
            directories[:] = [name for name in directories if name not in excluded_dirs]
            for filename in files:
                if scanned >= root_budget:
                    break
                path = Path(current) / filename
                if kind == "code" and (filename.startswith("test_") or re.search(r"\.(test|spec)\.", filename)):
                    continue
                if kind == "log" and is_alert_artifact_reference(path):
                    continue
                if kind == "log" and "disk-attribution" in path.parts:
                    continue  # Structured host records require exact target/time binding.
                if path.suffix.lower() not in suffixes:
                    continue
                scanned += 1
                try:
                    if path.stat().st_size > 750_000:
                        continue
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if kind != "code":
                        lines = lines[:5000]
                except OSError:
                    continue
                try:
                    # Match only the path *inside* the configured project root.
                    # Absolute roots such as ".../external/telemetry/..." otherwise
                    # make the generic project term "telemetry" match every file.
                    path_lowered = path.relative_to(root).as_posix().lower()
                except ValueError:
                    path_lowered = path.name.lower()
                path_matches = [term for term in terms if term in path_lowered]
                for line_no, line in enumerate(lines, 1):
                    lowered = line.lower()
                    matched = list(dict.fromkeys([*path_matches, *(term for term in terms if term in lowered)]))
                    if matched:
                        snippet = line
                        if kind == "code":
                            start = max(0, line_no - 4)
                            end = min(len(lines), line_no + 3)
                            snippet = "\n".join(
                                f"{context_line_no + 1}: {lines[context_line_no]}"
                                for context_line_no in range(start, end)
                            )
                        ranked.append((len(matched), -root_index, _evidence(kind, path, line_no, snippet, matched)))
                        # Retain only the best candidates while scanning. Broad
                        # terms can match thousands of lines in one source file.
                        if len(ranked) >= 2 * limit:
                            ranked.sort(key=lambda row: (-row[0], -row[1], row[2]["uri"]))
                            del ranked[limit:]
            if scanned >= root_budget:
                break
        if root_index == 0 and len(ranked) >= limit:
            break
    ranked.sort(key=lambda row: (-row[0], -row[1], row[2]["uri"]))
    return [row[2] for row in ranked[:limit]]


def _ticket_text(path: Path) -> list[tuple[int, str]]:
    try:
        if path.suffix.lower() == ".eml":
            message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
            chunks = [f"Subject: {message.get('Subject', '')}"]
            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    chunks.append(str(part.get_content()))
            return list(enumerate("\n".join(chunks).splitlines(), 1))
        if path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                return [
                    (index, json.dumps(row, ensure_ascii=False, default=str))
                    for index, row in enumerate(csv.DictReader(handle), 1)
                ]
        return list(enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1))
    except (OSError, ValueError):
        return []


def _search_tickets(terms: list[str], limit: int) -> list[dict[str, Any]]:
    ranked: list[tuple[int, dict[str, Any]]] = []
    scanned = 0
    max_files = max(10, min(int(os.getenv("DISCOVERY_MCP_MAX_TICKET_FILES", "80")), 400))
    for root in _roots("DISCOVERY_MCP_TICKET_ROOTS", "/workspace/backend/rag,/data/tickets,/data/landing/documents"):
        if not root.is_dir():
            continue
        for current, directories, files in os.walk(root):
            directories[:] = [name for name in directories if name not in {".claiming", "node_modules", ".git"}]
            for filename in files:
                if scanned >= max_files:
                    break
                path = Path(current) / filename
                if path.suffix.lower() not in TICKET_SUFFIXES:
                    continue
                scanned += 1
                for line_no, text in _ticket_text(path):
                    lowered = text.lower()
                    matched = [term for term in terms if term in lowered]
                    if matched:
                        ranked.append((len(matched), _evidence("ticket", path, line_no, text, matched)))
            if scanned >= max_files:
                break
    ranked.sort(key=lambda row: (-row[0], row[1]["uri"]))
    return [row[1] for row in ranked[:limit]]


def _adf_to_text(node: Any, *, max_chars: int = 400) -> str:
    """Flattens Jira API v3's Atlassian Document Format (a nested JSON tree,
    not plain text) into a plain string. /rest/api/3/search returns
    `description` in this shape; naively str()-ing it produces an
    unreadable Python dict repr instead of the actual ticket narrative."""
    parts: list[str] = []

    def walk(value: Any) -> None:
        if len(" ".join(parts)) >= max_chars:
            return
        if isinstance(value, dict):
            text = value.get("text")
            if isinstance(text, str) and text.strip():
                parts.append(text.strip())
            content = value.get("content")
            if isinstance(content, list):
                for child in content:
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    if isinstance(node, str):
        return node.strip()[:max_chars]
    walk(node)
    return " ".join(parts).strip()[:max_chars]


async def _search_jira_tickets(arguments: dict[str, Any], terms: list[str], limit: int) -> list[dict[str, Any]]:
    _, project = _project_for(arguments)
    ticket_sources = project.get("ticket_sources") if isinstance(project.get("ticket_sources"), dict) else {}
    jira_url = str(os.getenv("JIRA_URL") or ticket_sources.get("jira_url") or "").strip().rstrip("/")
    user_email = str(os.getenv("JIRA_USER_EMAIL") or "").strip()
    api_token = str(os.getenv("JIRA_API_TOKEN") or "").strip()
    project_key = str(os.getenv("JIRA_PROJECT_KEY") or ticket_sources.get("jira_project_key") or "").strip()
    if not jira_url or not user_email or not api_token or not terms:
        return []

    # Previously joined all terms into one `text ~ "a b c"` clause, which Jira
    # treats as a phrase requiring co-occurrence — realistic multi-word alerts
    # almost always matched zero tickets. OR-ing individual term clauses lets
    # any one matching word surface a ticket, matching how `matched_terms`
    # below already treats term matching (any, not all).
    safe_terms = [term.replace('"', '\\"') for term in terms[:8] if term.strip()]
    text_clause = " OR ".join(f'text ~ "{term}"' for term in safe_terms)
    clauses = [f"({text_clause})"] if len(safe_terms) > 1 else [f'text ~ "{safe_terms[0]}"']
    if project_key:
        safe_project = re.sub(r"[^A-Za-z0-9_-]", "", project_key)
        if safe_project:
            clauses.insert(0, f'project = "{safe_project}"')
    jql = " AND ".join(clauses) + " ORDER BY updated DESC"
    timeout = httpx.Timeout(max(2.0, min(float(os.getenv("JIRA_TIMEOUT_SECONDS", "8")), 30.0)))
    async with httpx.AsyncClient(timeout=timeout, auth=(user_email, api_token)) as client:
        # Atlassian removed GET/POST /rest/api/3/search (returns 410 Gone as
        # of the "Enhanced JQL" migration, CHANGE-2046) — confirmed live
        # while testing this change. /rest/api/3/search/jql is the
        # replacement, same params for a non-paginated call like this one.
        response = await client.get(
            f"{jira_url}/rest/api/3/search/jql",
            params={
                "jql": jql,
                "maxResults": limit,
                "fields": "summary,description,status,priority,issuetype,created,updated,labels,components",
            },
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        issues = response.json().get("issues", [])

    evidence: list[dict[str, Any]] = []
    for index, issue in enumerate(issues[:limit], 1):
        if not isinstance(issue, dict):
            continue
        fields = issue.get("fields") if isinstance(issue.get("fields"), dict) else {}
        key = str(issue.get("key") or "").strip()
        summary = str(fields.get("summary") or "").strip()
        status = fields.get("status") if isinstance(fields.get("status"), dict) else {}
        priority = fields.get("priority") if isinstance(fields.get("priority"), dict) else {}
        # These four were already being fetched from the Jira API (see the
        # "fields" param above) but discarded before reaching the RCA
        # evidence snippet — description in particular is often the single
        # highest-value field for root-cause grounding.
        issuetype = fields.get("issuetype") if isinstance(fields.get("issuetype"), dict) else {}
        description_text = _adf_to_text(fields.get("description"))
        labels = [str(label) for label in fields.get("labels", []) if isinstance(fields.get("labels"), list) and str(label).strip()]
        components = [
            str(component.get("name") or "").strip()
            for component in (fields.get("components") or [])
            if isinstance(component, dict) and str(component.get("name") or "").strip()
        ]
        snippet = (
            f"{key} {summary}; type={issuetype.get('name', 'unknown')}; "
            f"status={status.get('name', 'unknown')}; priority={priority.get('name', 'unknown')}; "
            f"updated={fields.get('updated', '')}"
            + (f"; labels={','.join(labels)}" if labels else "")
            + (f"; components={','.join(components)}" if components else "")
            + (f"; description={description_text}" if description_text else "")
        )
        matched = [term for term in terms if term in snippet.lower()] or terms[:1]
        item = _evidence("ticket", Path(f"jira/{key or index}"), 1, snippet, matched)
        item.update(
            {
                "uri": f"{jira_url}/browse/{key}" if key else jira_url,
                "ticket_id": key,
                "ticket_system": "jira",
                "title": summary,
                "status": status.get("name"),
                "priority": priority.get("name"),
                "issue_type": issuetype.get("name"),
                "labels": labels,
                "components": components,
                "description": description_text,
            }
        )
        evidence.append(item)
    return evidence


def _mysql_connection_settings() -> dict[str, Any]:
    return {
        "host": os.getenv("DB_HOST", "mysql"),
        "port": int(os.getenv("DB_PORT", "3306")),
        "user": os.getenv("DB_USER", "kaiops"),
        "password": os.getenv("DB_PASSWORD", "kaiops"),
        "db": os.getenv("DB_DATABASE", "kaiops"),
    }


async def _search_mysql(terms: list[str], limit: int) -> list[dict[str, Any]]:
    if not terms:
        return []
    settings = _mysql_connection_settings()
    max_rows = max(20, min(int(os.getenv("DISCOVERY_MCP_MYSQL_MAX_ROWS", "120")), 500))
    configured_tables = [
        token.strip()
        for token in os.getenv(
            "DISCOVERY_MCP_MYSQL_TABLES",
            "alerts,incident_projections,incidents,closed_incidents,onboarding_state",
        ).split(",")
        if token.strip()
    ]
    ranked: list[tuple[int, dict[str, Any]]] = []
    pool = await aiomysql.create_pool(
        host=settings["host"],
        port=settings["port"],
        user=settings["user"],
        password=settings["password"],
        db=settings["db"],
        minsize=1,
        maxsize=2,
        autocommit=True,
        connect_timeout=4,
    )
    try:
        async with pool.acquire() as connection:
            async with connection.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute("SHOW TABLES")
                rows = await cursor.fetchall()
                available = {str(next(iter(row.values()), "")).strip().lower() for row in rows if isinstance(row, dict)}
                table_names = [table for table in configured_tables if table.lower() in available]
                for table in table_names:
                    try:
                        await cursor.execute(f"SELECT * FROM `{table}` ORDER BY 1 DESC LIMIT %s", (max_rows,))
                        table_rows = await cursor.fetchall()
                    except Exception:
                        continue
                    for table_row in table_rows:
                        if not isinstance(table_row, dict):
                            continue
                        normalized = {
                            str(key): value
                            for key, value in table_row.items()
                            if str(key).strip().lower()
                            not in {"password", "passwd", "secret", "token", "api_key", "authorization"}
                        }
                        serialized = json.dumps(normalized, ensure_ascii=False, default=str)
                        lowered = serialized.lower()
                        matched = [term for term in terms if term in lowered]
                        if not matched:
                            continue
                        row_id = ""
                        for key in ("id", "alert_id", "incident_id", "flow_id", "ticket_id"):
                            if key in normalized and str(normalized.get(key) or "").strip():
                                row_id = str(normalized.get(key)).strip()
                                break
                        snippet = f"table={table} {serialized[:620]}"
                        uri_path = Path(f"{settings['db']}/{table}")
                        evidence = _evidence("mysql", uri_path, 1, snippet, matched)
                        evidence["uri"] = f"mysql://{settings['db']}/{table}#row={row_id or evidence['evidence_id']}"
                        evidence["table"] = table
                        if row_id:
                            evidence["row_id"] = row_id
                        ranked.append((len(matched), evidence))
    finally:
        pool.close()
        await pool.wait_closed()

    ranked.sort(key=lambda row: (-row[0], row[1]["uri"]))
    return [row[1] for row in ranked[:limit]]


async def _call_mysql_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    terms = _terms(arguments)
    limit = max(1, min(int(arguments.get("limit", 8)), 20))
    database = str(arguments.get("database") or arguments.get("database_name") or "").strip()
    table = str(arguments.get("table") or "").strip()
    configured_database = str(_mysql_connection_settings()["db"])
    if not database or not table or database != configured_database:
        return {"tool": "mysql.search", "query_terms": terms, "result_count": 0, "evidence": [],
                "evidence_gap": "APPLICATION_DATABASE_SCOPE_NOT_CONFIGURED",
                "source_scope": "kaiops_control_plane",
                "reason": "The default connection reads KaiMS records, not the affected application's database. An explicit matching database and table are required."}
    rows = [row for row in await _search_mysql(terms, limit) if row.get("table") == table]
    for row in rows:
        row.update({"source_scope": "kaiops_control_plane", "epistemic_role": "historical_record", "current_observation": False})
    return {"tool": "mysql.search", "query_terms": terms, "result_count": len(rows), "evidence": rows}


def _jaeger_operation(value: str) -> str:
    operation = str(value or "").strip()
    if not operation:
        return ""
    path = operation.split("?", 1)[0]
    path = re.sub(
        r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "/{alert_id}",
        path,
    )
    return path if " " in path else f"GET {path}"


def _trace_matches_operation(trace: dict[str, Any], service: str, requested_operation: str) -> bool:
    """A broad Jaeger retry must still match the requested route locally."""
    if not requested_operation:
        return True

    def path(value: object) -> str:
        text = str(value or "").split("?", 1)[0].strip()
        return next((part for part in text.split() if part.startswith("/")), "")

    expected = path(requested_operation)
    processes = trace.get("processes") or {}
    for span in trace.get("spans", []):
        process = processes.get(span.get("processID"), {})
        if process.get("serviceName") and not service_matches(process["serviceName"], service):
            continue
        tags = {tag.get("key"): tag.get("value") for tag in span.get("tags", [])}
        for value in (tags.get("http.route"), tags.get("http.target"), tags.get("url.path"), span.get("operationName")):
            observed = path(value)
            if not observed:
                continue
            pattern = re.escape(observed)
            pattern = re.sub(r"\\\{[^{}]+\\\}", "[^/]+", pattern)
            if expected and re.fullmatch(pattern, expected):
                return True
    return False


def _trace_evidence_summary(trace: dict[str, Any], requested_operation: str = "") -> dict[str, Any]:
    spans = [span for span in trace.get("spans", []) if isinstance(span, dict)]
    processes = trace.get("processes") if isinstance(trace.get("processes"), dict) else {}
    services = sorted({
        str(process.get("serviceName"))
        for process in processes.values()
        if isinstance(process, dict) and process.get("serviceName")
    })
    operations = sorted({str(span.get("operationName")) for span in spans if span.get("operationName")})
    status_codes: list[int] = []
    error_spans = 0
    span_rows: list[dict[str, Any]] = []
    span_index = {str(span.get("spanID") or ""): span for span in spans}
    dependency_edges: set[tuple[str, str]] = set()
    safe_tag_names = {
        "db.system", "db.operation", "server.address", "net.peer.name",
        "http.route", "http.target", "http.status_code", "http.response.status_code", "span.kind",
        "exception.type", "error.type",
    }
    for span in spans:
        tags = {
            str(tag.get("key")): tag.get("value")
            for tag in span.get("tags", [])
            if isinstance(tag, dict) and tag.get("key")
        }
        # Jaeger stores OTLP exception events in span logs. Preserve types,
        # never messages/stack traces (which may contain request secrets).
        exception_types = sorted({
            str(field.get("value"))[:160]
            for event in span.get("logs", []) if isinstance(event, dict)
            for field in event.get("fields", []) if isinstance(field, dict)
            and field.get("key") == "exception.type" and field.get("value")
        })[:8]
        status = tags.get("http.status_code", tags.get("http.response.status_code"))
        try:
            if status is not None:
                status_codes.append(int(status))
        except (TypeError, ValueError):
            pass
        # A log event is not itself an error, and the previous span's status
        # must never contaminate this span's outcome.
        try:
            http_error = status is not None and int(status) >= 500
        except (TypeError, ValueError):
            http_error = False
        if tags.get("error") is True or http_error or exception_types:
            error_spans += 1
        process = processes.get(span.get("processID"), {})
        service_name = str(process.get("serviceName") or "unknown") if isinstance(process, dict) else "unknown"
        span_rows.append({
            "span_id": str(span.get("spanID") or ""),
            "parent_span_ids": [str(ref["spanID"]) for ref in span.get("references", [])
                                if isinstance(ref, dict) and ref.get("refType") == "CHILD_OF"
                                and ref.get("spanID") and ref.get("traceID", trace.get("traceID")) == trace.get("traceID")],
            "start_time_us": int(span.get("startTime") or 0),
            "service": service_name,
            "operation": str(span.get("operationName") or "unknown"),
            "duration_ms": round(int(span.get("duration") or 0) / 1000, 3),
            "exception_types": exception_types,
            "tags": {key: tags[key] for key in safe_tag_names if tags.get(key) not in (None, "")},
        })
        for reference in span.get("references", []):
            if not isinstance(reference, dict) or reference.get("refType") != "CHILD_OF":
                continue
            if reference.get("traceID", trace.get("traceID")) != trace.get("traceID"):
                continue
            parent = span_index.get(str(reference.get("spanID") or ""))
            if not parent:
                continue
            parent_process = processes.get(parent.get("processID"), {})
            parent_service = (
                str(parent_process.get("serviceName") or "unknown")
                if isinstance(parent_process, dict)
                else "unknown"
            )
            if parent_service != service_name and "unknown" not in {parent_service, service_name}:
                dependency_edges.add((parent_service, service_name))
    duration_us = max((int(span.get("duration") or 0) for span in spans), default=0)
    signals: list[str] = []
    if error_spans:
        signals.append("http_5xx" if any(code >= 500 for code in status_codes) else "error")
    if duration_us >= 3_000_000:
        signals.append("high_latency")
    return {
        "trace_id": str(trace.get("traceID") or ""),
        "services": services,
        "span_count": len(spans),
        "operations": operations[:20],
        "requested_operation": requested_operation or None,
        "duration_ms": round(duration_us / 1000, 3),
        "http_status_codes": sorted(set(status_codes)),
        "error_span_count": error_spans,
        "diagnostic_signals": signals,
        "slowest_spans": sorted(span_rows, key=lambda row: -row["duration_ms"])[:10],
        "dependency_edges": [
            {"upstream": upstream, "downstream": downstream}
            for upstream, downstream in sorted(dependency_edges)
        ],
    }


def _is_platform_wide_target(identity: str, project_id: str, project: dict[str, Any]) -> bool:
    """True only for the umbrella platform catalog entry itself, never a
    normal onboarded application.

    A request scoped to the platform's own id/name/aliases (e.g. an incident
    targeting "kaiops-platform" itself, with no single failing service) asks
    for platform-wide evidence, not evidence about a container or metric
    series literally named that -- no such single-service signal exists.
    A single-service onboarded application legitimately has "service ==
    project's own name" as its NORMAL case (its project entry is named after
    itself), so that overlap alone must never imply "platform-wide" -- only
    the catalog entry explicitly marked `"platform": true` (the curated
    "kaiops" entry in discovery-projects.json) qualifies.
    """
    if not identity or not bool(project.get("platform")):
        return False
    aliases = {
        value
        for value in (
            str(project_id).lower(),
            str(project.get("name") or "").lower(),
            str(project.get("display_name") or "").lower(),
            *(str(alias).lower() for alias in project.get("aliases", []) if alias),
        )
        if value
    }
    return identity.lower() in aliases


async def _search_telemetry(arguments: dict[str, Any]) -> dict[str, Any]:
    project_id, project = _project_for(arguments)
    telemetry = project.get("telemetry") if isinstance(project.get("telemetry"), dict) else {}
    if not telemetry:
        # Unlike code search (`_code_roots`), which must never guess a
        # source repository for an unmatched service - citing the wrong
        # application's code would be confidently wrong, not just missing -
        # this deployment has exactly one shared Prometheus/Jaeger backend
        # that every service in it scrapes into or exports to, whether or
        # not that service has been formally onboarded as its own project.
        # Falling through to an empty telemetry dict here made
        # traces.search/telemetry.search return zero evidence for every
        # non-onboarded service unconditionally - indistinguishable from
        # "this service genuinely has no telemetry" even when Jaeger/
        # Prometheus held real, current data for it. Reproduced live: an
        # active fault-lab fault emitting real OTLP spans for "payments-api"
        # was fully visible via Jaeger's own query API, but
        # `traces.search({"service": "payments-api"})` still returned
        # `result_count: 0` because "payments-api" matches no curated or
        # onboarded project, only the platform's own "api-gateway" (which
        # happens to also resolve via `_code_roots`' service-directory
        # match) ever got real evidence. Only the two curated entries that
        # deliberately point elsewhere (a project matched but with its own,
        # different telemetry - e.g. the "telemetry" demo project's external
        # Jaeger) are unaffected, since those still return a real `project`.
        telemetry = {
            "prometheus_url": os.getenv("DISCOVERY_MCP_ONBOARDED_PROMETHEUS_URL", "http://prometheus:9090"),
            "jaeger_url": os.getenv("DISCOVERY_MCP_ONBOARDED_JAEGER_URL", "http://jaeger:16686"),
        }
    terms = _terms(arguments)
    service = str(arguments.get("service") or next(iter(terms), "")).strip()
    # A platform-wide target has no single service_name series to match
    # against; querying for one deterministically returns zero results even
    # though the platform's own metrics are being scraped and are healthy.
    metric_service = "" if _is_platform_wide_target(service, project_id, project) else service
    trace_id = str(arguments.get("trace_id") or "").strip()
    requested_operation = str(arguments.get("operation") or "").strip()
    limit = max(1, min(int(arguments.get("limit", 8)), 20))
    evidence: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    start_time = str(arguments.get("start_time") or "").strip()
    end_time = str(arguments.get("end_time") or "").strip()
    timeout = httpx.Timeout(max(2.0, min(float(os.getenv("DISCOVERY_MCP_TELEMETRY_TIMEOUT_SECONDS", "6")), 20.0)))

    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        prometheus_url = str(telemetry.get("prometheus_url") or "").rstrip("/")
        probe_sources = telemetry.get("probe_job_sources") or {}
        bound_job = (arguments.get("target_labels") or {}).get("job")
        probe_source = probe_sources.get(bound_job) if isinstance(probe_sources, dict) else None
        if probe_source:
            prometheus_url = str(probe_source).rstrip("/")
        if prometheus_url and arguments.get("evidence_category") in (None, "", "metrics"):
            if metric_service:
                # OTel-instrumented services label series "service_name";
                # this platform's own Prometheus-native metrics (fault-lab,
                # most kaiops_* series) label them "service". Querying only
                # the OTel convention silently returned zero evidence for
                # every non-OTel service, which is most of them.
                literal = metric_service.replace("\\", "\\\\").replace('"', '\\"')
                query = f'{{service="{literal}"}} or {{service_name="{literal}"}} or {{job="{literal}"}}'
            else:
                query = "up"
            target_labels = dict(arguments.get("target_labels") or {})
            for key in ("operation", "environment"):
                if arguments.get(key):
                    target_labels.setdefault(key, arguments[key])
            target_selectors = {key: str(target_labels[key]) for key in ("job", "instance", "namespace", "cluster", "operation", "http_route", "route", "device", "mountpoint")
                                if target_labels.get(key)}
            if target_selectors and (target_selectors.get("job") or target_selectors.get("instance")):
                query = "{" + ",".join(key + "=" + json.dumps(value) for key, value in target_selectors.items()) + "}"
                if probe_source:
                    # Independent probes are owned by a different registered
                    # monitoring source than the application's OTLP metrics.
                    query = query.replace("{", '{__name__=~"probe_success|probe_http_status_code|probe_duration_seconds|up",', 1)
            if arguments.get("evidence_category") == "metrics":
                from common.metric_queries import filesystem_evidence_query
                query = filesystem_evidence_query(
                    target_labels, question=str(arguments.get("question") or ""),
                ) or query
            # Scrape targets and independently probed HTTP targets use different
            # jobs/instances. Preserve both, scoped by the operator's registry.
            runtime_probe_job = str(telemetry.get("runtime_probe_job") or "")
            runtime_probe_labels = {
                "__name__": "probe_success", "job": runtime_probe_job,
                "service": metric_service, "tenant_id": str(arguments.get("tenant_id") or "default"),
            }
            if runtime_probe_job and metric_service:
                selector = ",".join(k + "=" + json.dumps(v) for k, v in runtime_probe_labels.items())
                query = f"({query}) or {{{selector}}}"
            from common.metric_queries import registered_signal_metric
            signal_binding = registered_signal_metric(telemetry, arguments)
            if signal_binding:
                query = signal_binding[0]
            try:
                params = {"query": query}
                query_path = "query"
                if start_time or end_time:
                    # Invalid historical windows must not silently query the present.
                    start = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                    end = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
                    if start.tzinfo is None or end.tzinfo is None or end <= start:
                        raise ValueError("INVALID_OBSERVATION_WINDOW")
                    # Prometheus can evaluate future range steps using its
                    # lookback cache. Those timestamps are not observations
                    # from the future and cannot support a current RCA.
                    end = min(end, datetime.now(UTC))
                    if end <= start:
                        raise ValueError("INVALID_OBSERVATION_WINDOW")
                    params.update({"start": start.timestamp(), "end": end.timestamp(),
                                   "step": max(15, int((end - start).total_seconds() / 240))})
                    query_path = "query_range"
                response = await client.get(f"{prometheus_url}/api/v1/{query_path}", params=params)
                response.raise_for_status()
                payload = response.json()
                if payload.get("status") == "error":
                    raise ValueError(str(payload.get("error") or "PROMETHEUS_QUERY_FAILED"))
                results = payload.get("data", {}).get("result", [])
                metric_results = [row for row in results if isinstance(row, dict)
                                  and (row.get("metric") or {}).get("__name__") not in {"ALERTS", "ALERTS_FOR_STATE"}
                                  and (all((row.get("metric") or {}).get(k) == v
                                           for k, v in signal_binding[1].items()) if signal_binding else
                                       all((row.get("metric") or {}).get(k) == v
                                           for k, v in runtime_probe_labels.items())
                                       if runtime_probe_job and (row.get("metric") or {}).get("job") == runtime_probe_job
                                       else not metric_service or metric_matches_subject(
                                      row.get("metric") or {}, metric_service,
                                      target_labels=target_labels, query=query))]
                def metric_priority(row):
                    samples = row.get("values") or ([row["value"]] if row.get("value") else [])
                    activity = 0.0
                    if signal_binding:
                        try:
                            values = [float(sample[1]) for sample in samples]
                            activity = sum(max(0.0, right - left) for left, right in zip(values, values[1:]))
                        except (TypeError, ValueError, IndexError):
                            pass
                    return (0 if (row.get("metric") or {}).get("__name__") == "probe_success" else 1, -activity)
                # Zero-valued series must not crowd out the failing consumer
                # when a registered counter has more series than the quota.
                metric_results.sort(key=metric_priority)
                for index, row in enumerate(metric_results[:limit], 1):
                    snippet = json.dumps(row, ensure_ascii=False, default=str)[:700]
                    item = _evidence("metric", Path(f"{project_id or 'telemetry'}/prometheus"), index, snippet, terms)
                    item["uri"] = f"prometheus://{project_id or 'telemetry'}?query={query}"
                    # Preserve samples for evidence admission; snippets are display text only.
                    item.update({key: row[key] for key in ("metric", "value", "values") if key in row})
                    item.update({"query": query, "endpoint": prometheus_url, "service": service,
                                 "observation_window_start": start_time or None,
                                 "observation_window_end": end_time or None})
                    samples = row.get("values") or ([row["value"]] if row.get("value") else [])
                    try:
                        item["observed_at"] = datetime.fromtimestamp(max(float(sample[0]) for sample in samples), tz=UTC).isoformat()
                    except (TypeError, ValueError, IndexError, OverflowError, OSError):
                        pass  # Missing source timestamps remain unknown to the evidence compiler.
                    evidence.append(item)
                sources.append({"source": "prometheus", "status": "completed", "result_count": len(metric_results),
                                "returned_series_count": len(results), "rejected_series_count": len(results) - len(metric_results)})
            except Exception as exc:
                sources.append({"source": "prometheus", "status": "unavailable", "error": str(exc)[:240]})

        jaeger_url = str(telemetry.get("jaeger_url") or "").rstrip("/")
        if jaeger_url and arguments.get("evidence_category") in (None, "", "traces"):
            try:
                trace_not_found = False
                bound_trace_fallback = False
                operation_filter_fallback = False
                if trace_id:
                    response = await client.get(f"{jaeger_url}/api/traces/{trace_id}")
                    if response.status_code == 404:
                        # Alert correlation IDs are not always Jaeger trace
                        # IDs. Fall back to the same bounded service,
                        # operation, and incident-window query used when no
                        # trace ID is supplied.
                        trace_params = {"service": service, "limit": str(limit), "lookback": "1h"}
                        jaeger_operation = _jaeger_operation(requested_operation)
                        if jaeger_operation:
                            trace_params["operation"] = jaeger_operation
                        if start_time and end_time:
                            try:
                                trace_params.update({
                                    "start": str(int(datetime.fromisoformat(
                                        start_time.replace("Z", "+00:00")
                                    ).timestamp() * 1_000_000)),
                                    "end": str(int(datetime.fromisoformat(
                                        end_time.replace("Z", "+00:00")
                                    ).timestamp() * 1_000_000)),
                                })
                                trace_params.pop("lookback", None)
                            except ValueError:
                                pass
                        fallback = await client.get(f"{jaeger_url}/api/traces", params=trace_params)
                        fallback.raise_for_status()
                        traces = fallback.json().get("data", [])
                        if not traces and trace_params.get("operation"):
                            # Route labels vary between instrumentation layers
                            # (for example, a receive span may be recorded while
                            # the requested HTTP route is absent). Keep the
                            # service and incident window fixed, but retry
                            # without the lossy operation-name filter.
                            broad_params = dict(trace_params)
                            broad_params.pop("operation", None)
                            broad = await client.get(f"{jaeger_url}/api/traces", params=broad_params)
                            broad.raise_for_status()
                            traces = broad.json().get("data", [])
                            operation_filter_fallback = bool(traces)
                        bound_trace_fallback = bool(traces)
                        trace_not_found = not bool(traces)
                    else:
                        response.raise_for_status()
                        traces = response.json().get("data", [])
                else:
                    trace_params = {"service": service, "limit": str(limit), "lookback": "1h"}
                    jaeger_operation = _jaeger_operation(requested_operation)
                    if jaeger_operation:
                        trace_params["operation"] = jaeger_operation
                    if start_time and end_time:
                        try:
                            trace_params.update({
                                "start": str(int(
                                    datetime.fromisoformat(start_time.replace("Z", "+00:00")).timestamp() * 1_000_000
                                )),
                                "end": str(int(
                                    datetime.fromisoformat(end_time.replace("Z", "+00:00")).timestamp() * 1_000_000
                                )),
                            })
                            trace_params.pop("lookback", None)
                        except ValueError:
                            pass
                    response = await client.get(
                        f"{jaeger_url}/api/traces",
                        params=trace_params,
                    )
                    response.raise_for_status()
                    traces = response.json().get("data", [])
                    if not traces and trace_params.get("operation"):
                        broad_params = dict(trace_params)
                        broad_params.pop("operation", None)
                        broad = await client.get(f"{jaeger_url}/api/traces", params=broad_params)
                        broad.raise_for_status()
                        traces = broad.json().get("data", [])
                        operation_filter_fallback = bool(traces)
                returned_trace_count = len(traces)
                traces = [trace for trace in traces if _trace_matches_operation(trace, service, requested_operation)]
                trace_not_found = not bool(traces)
                for index, trace in enumerate(traces[:limit], 1):
                    discovered_trace_id = str(trace.get("traceID") or trace_id or "")
                    summary = _trace_evidence_summary(trace, requested_operation)
                    snippet = json.dumps(summary, ensure_ascii=False)
                    item = _evidence("trace", Path(f"{project_id or 'telemetry'}/jaeger"), index, snippet, terms)
                    item["uri"] = f"jaeger://trace/{discovered_trace_id or index}"
                    item["diagnostic_signals"] = summary["diagnostic_signals"]
                    item["trace_id"] = discovered_trace_id
                    item["duration_ms"] = summary["duration_ms"]
                    item["operations"] = summary["operations"]
                    item["http_status_codes"] = summary["http_status_codes"]
                    item["slowest_spans"] = summary["slowest_spans"]
                    item["dependency_edges"] = summary["dependency_edges"]
                    start_times = [
                        int(span.get("startTime") or 0)
                        for span in trace.get("spans", [])
                        if isinstance(span, dict)
                    ]
                    if start_times and min(start_times) > 0:
                        item["observed_at"] = datetime.fromtimestamp(min(start_times) / 1_000_000, tz=UTC).isoformat()
                    evidence.append(item)
                sources.append({
                    "source": "jaeger",
                    "status": "not_found" if trace_not_found else "completed",
                    "result_count": len(traces),
                    "rejected_trace_count": returned_trace_count - len(traces),
                    "bound_trace_fallback": bound_trace_fallback,
                    "operation_filter_fallback": operation_filter_fallback,
                    **({"reason": "TRACE_OPERATION_MISMATCH" if returned_trace_count else "TRACE_NOT_FOUND_OR_EXPIRED"} if trace_not_found else {}),
                })
            except Exception as exc:
                sources.append({"source": "jaeger", "status": "unavailable", "error": str(exc)[:240]})

        opensearch_url = str(telemetry.get("opensearch_url") or "").rstrip("/")
        opensearch_index = str(telemetry.get("opensearch_index") or "otel-*").strip()
        if opensearch_url and arguments.get("evidence_category") in (None, "", "logs"):
            must: list[dict[str, Any]] = []
            if service:
                must.append(
                    {
                        "query_string": {
                            "query": f'"{service}"',
                            "fields": ["service.name", "resource.attributes.service.name", "body", "message"],
                        }
                    }
                )
            if trace_id:
                must.append(
                    {
                        "query_string": {
                            "query": f'"{trace_id}"',
                            "fields": ["trace_id", "traceId", "trace.id"],
                        }
                    }
                )
            body = {
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
                "query": {"bool": {"must": must or [{"match_all": {}}]}},
            }
            if start_time and end_time:
                body["query"]["bool"].setdefault("filter", []).append(
                    {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}
                )
            try:
                response = await client.post(f"{opensearch_url}/{opensearch_index}/_search", json=body)
                response.raise_for_status()
                hits = response.json().get("hits", {}).get("hits", [])
                for index, hit in enumerate(hits[:limit], 1):
                    source = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
                    snippet = json.dumps(source, ensure_ascii=False, default=str)[:700]
                    item = _evidence("log", Path(f"{project_id or 'telemetry'}/opensearch"), index, snippet, terms)
                    item["uri"] = f"opensearch://{opensearch_index}/{hit.get('_id', index)}"
                    evidence.append(item)
                sources.append({"source": "opensearch", "status": "completed", "result_count": len(hits)})
            except Exception as exc:
                sources.append({"source": "opensearch", "status": "unavailable", "error": str(exc)[:240]})

    diagnosis = _log_diagnosis(evidence, service)
    if diagnosis:
        evidence.insert(0, diagnosis)
    trace_not_found = any(
        source.get("source") == "jaeger" and source.get("status") == "not_found"
        for source in sources
    )
    failed_sources = [source for source in sources if source.get("status") == "unavailable"]
    provider_failed = not evidence and bool(failed_sources)
    metric_request = arguments.get("evidence_category") == "metrics"
    evidence_gap = (
        "PROMETHEUS_SOURCE_UNAVAILABLE" if metric_request and provider_failed
        else "METRIC_SERIES_NOT_FOUND_IN_WINDOW" if metric_request and not evidence and start_time
        else "TRACE_NOT_FOUND_OR_EXPIRED" if trace_id and trace_not_found else ""
    )
    return {
        "tool": "telemetry.search",
        "provider_status": "failed" if provider_failed else "completed",
        "provider_error": "; ".join(str(source.get("error") or "") for source in failed_sources)[:500] or None,
        "project": project_id,
        "query_terms": terms,
        "service": service,
        "trace_id": trace_id,
        "result_count": len(evidence),
        # Each source above already bounds itself to `limit` before appending
        # (results[:limit], traces[:limit], hits[:limit]), so evidence here is
        # naturally capped at roughly limit * source_count. Re-slicing the
        # merged list to `limit` here silently dropped every source queried
        # after whichever ran first filled the quota on its own - in practice
        # Prometheus (queried first, and almost always returning >= limit
        # series for an actively-scraped service) crowded out every trace and
        # log result, so traces.search and logs.search returned zero evidence
        # even when Jaeger/OpenSearch genuinely had matches.
        "evidence": evidence,
        "sources": sources,
        "evidence_gap": evidence_gap,
        "correlation_keys": project.get("correlation_keys", []),
    }


async def _search_traces(arguments: dict[str, Any]) -> dict[str, Any]:
    result = await _search_telemetry({**arguments, "evidence_category": "traces"})
    evidence = [row for row in result.get("evidence", []) if str(row.get("source") or "").lower() == "trace"]
    return {**result, "tool": "traces.search", "result_count": len(evidence), "evidence": evidence}


def _search_changes(arguments: dict[str, Any]) -> dict[str, Any]:
    terms = _code_search_terms(arguments)
    limit = max(1, min(int(arguments.get("limit", 8)), 20))
    rows = _search_text_files(
        _code_roots(arguments),
        {".yml", ".yaml", ".json", ".toml", ".xml", ".tf", ".py"},
        terms,
        "change",
        limit,
    )
    for row in rows:
        try:
            modified_at = Path(str(row.get("path") or "")).stat().st_mtime
            row["observed_at"] = datetime.fromtimestamp(modified_at, tz=UTC).isoformat()
        except OSError:
            pass
        row["change_evidence_kind"] = "configuration_or_deployment_artifact"
    return {"tool": "changes.search", "query_terms": terms, "result_count": len(rows), "evidence": rows}


def _runtime_project_scope(arguments: dict[str, Any]) -> str:
    # Ingestion uses placeholders when application attribution is missing.
    # They are not Docker project names and must not suppress an explicitly
    # targeted service. Preserve real project constraints.
    for key in ("project", "application"):
        value = str(arguments.get(key) or "").strip().lower()
        if value not in {"", "unassigned", "unknown", "none", "null", "n/a"}:
            return value
    return ""


def _docker_container_list_params(service: str, *, platform_wide: bool = False, limit: int = 100) -> dict[str, str]:
    params = {"all": "true", "limit": str(limit)}
    if service and not platform_wide:
        # Apply service scope before Docker's limit. Older containers otherwise
        # disappear when more recently created unrelated containers fill the page.
        from common.evidence_subject import service_identity
        params["filters"] = json.dumps({"name": list(dict.fromkeys([re.escape(service), re.escape(service_identity(service))]))})
    return params


async def _container_deployment_events(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Real deployment-timing evidence for the "recent_change" hypothesis.

    `_search_changes` above can only report a config/code file's filesystem
    mtime as its "observed_at" -- but this deployment has no git repository
    (checked out fresh, or built into an image), so every file's mtime
    clusters around whenever the image was last built/checked out,
    regardless of that file's real edit history. That is not a stale
    signal, it is a *meaningless* one for change-incident correlation: the
    resolution_agent.change_intelligence time_score correctly, deliberately
    scores it near zero (delta from the incident far outside
    correlation_window_seconds), so a "recent_change" hypothesis could never
    reach real confidence in this environment through that path alone.

    A container's own `Created` timestamp is a genuine, verifiable "when was
    this service actually last (re)deployed" event -- read straight from
    the same minimal-privilege docker-socket-proxy already used for
    topology/dependency/resource checks, no new infrastructure required.
    """
    docker_host = str(os.getenv("DOCKER_LOG_DISCOVERY_HOST", "docker-socket-proxy:2375")).strip()
    if not docker_host:
        return []
    service = str(arguments.get("service") or "").strip().lower()
    project = _runtime_project_scope(arguments)
    project_id, project_entry = _project_for(arguments)
    platform_wide = _is_platform_wide_target(project, project_id, project_entry)
    service_platform_wide = _is_platform_wide_target(service, project_id, project_entry)
    events: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(
            base_url=f"http://{docker_host}", timeout=httpx.Timeout(8.0), trust_env=False
        ) as client:
            response = await client.get("/containers/json", params=_docker_container_list_params(service, platform_wide=service_platform_wide))
            response.raise_for_status()
            containers = response.json()
        for container in containers:
            if not isinstance(container, dict):
                continue
            labels = container.get("Labels") if isinstance(container.get("Labels"), dict) else {}
            compose_project = str(labels.get("com.docker.compose.project") or "").lower()
            compose_service = str(labels.get("com.docker.compose.service") or "").lower()
            identity = " ".join(
                [compose_project, compose_service, *(str(item).lower() for item in container.get("Names", []))]
            )
            if project and not platform_wide and project not in identity:
                continue
            if service and not service_platform_wide and not service_matches(compose_service, service):
                continue
            created_epoch = container.get("Created")
            if not isinstance(created_epoch, (int, float)) or created_epoch <= 0:
                continue
            created_at = datetime.fromtimestamp(created_epoch, tz=UTC)
            snippet = json.dumps(
                {
                    "project": compose_project, "service": compose_service,
                    "created_at": created_at.isoformat(), "status": container.get("Status"),
                },
                ensure_ascii=False,
            )
            row = _evidence(
                "change", Path(f"docker/{compose_project or 'runtime'}/{compose_service or 'container'}"),
                1, snippet, [service] if service else [],
            )
            row.update({
                "uri": f"docker://{compose_project or 'runtime'}/{compose_service or 'container'}/created",
                "service": compose_service or service,
                "observed_at": created_at.isoformat(),
                "source_system": "deployment",
                "change_evidence_kind": "container_deployment",
                "deployment_id": str(container.get("Id") or ""),
                "image": container.get("Image"),
                "image_id": container.get("ImageID"),
                "observation_scope": "container_creation",
            })
            events.append(row)
    except Exception:
        return []
    return events


async def _search_changes_with_deployment_evidence(arguments: dict[str, Any]) -> dict[str, Any]:
    result = _search_changes(arguments)
    deployment_events = await _container_deployment_events(arguments)
    limit = max(1, min(int(arguments.get("limit", 8)), 20))
    # `_container_deployment_events` is the one genuinely reliable "when was
    # this service actually (re)deployed" signal `_search_changes` cannot
    # provide on its own (see its docstring) - but a monorepo the size of
    # this platform's almost always has `limit` (default 8) keyword matches
    # for any alert-derived term, so putting the weaker file-search results
    # first meant they always filled the slice and `deployment_events` was
    # silently truncated away in practice. Reproduced platform-wide: across
    # the 200 most recent investigations and 2273 total "change" evidence
    # rows, zero were ever the "container_deployment" kind. Deployment
    # events go first so the reliable signal is never starved out by the
    # weaker one.
    combined = [*deployment_events, *result.get("evidence", [])][:limit]
    return {**result, "result_count": len(combined), "evidence": combined}


def _search_runbooks(arguments: dict[str, Any]) -> dict[str, Any]:
    terms = list(dict.fromkeys([str(arguments.get("service") or "").lower(), *_terms(arguments)]))
    terms = [term for term in terms if term]
    limit = max(1, min(int(arguments.get("limit", 8)), 20))
    path = Path(
        os.getenv("DISCOVERY_MCP_PLAYBOOKS_FILE", "/workspace/backend/rag/execution/playbooks.json")
    )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        payload = {}
    rows: list[dict[str, Any]] = []
    for index, playbook in enumerate(payload.get("playbooks", []) if isinstance(payload, dict) else [], 1):
        if not isinstance(playbook, dict):
            continue
        searchable = json.dumps(playbook, sort_keys=True, ensure_ascii=False, default=str).lower()
        matched = [term for term in terms if term in searchable]
        if terms and not matched:
            continue
        summary = json.dumps(
            {
                "id": playbook.get("id"),
                "name": playbook.get("name"),
                "status": playbook.get("status"),
                "risk_class": playbook.get("risk_class"),
                "match": playbook.get("match"),
            },
            ensure_ascii=False,
            default=str,
        )
        row = _evidence("runbook", path, index, summary, matched)
        row.update(
            {
                "observed_at": playbook.get("approved_at"),
                "status": str(playbook.get("status") or "unregistered").lower(),
                "runbook_id": str(playbook.get("governance_id") or ""),
                "runbook_slug": str(playbook.get("id") or ""),
                "version": playbook.get("version"),
                "checksum_sha256": playbook.get("checksum_sha256"),
            }
        )
        rows.append(row)
    return {"tool": "runbooks.search", "query_terms": terms, "result_count": len(rows[:limit]), "evidence": rows[:limit]}


async def _search_runtime_topology(arguments: dict[str, Any], *, health_only: bool) -> dict[str, Any]:
    tool_name = "dependency-health.search" if health_only else "topology.search"
    limit = max(1, min(int(arguments.get("limit", 8)), 20))
    docker_host = str(os.getenv("DOCKER_LOG_DISCOVERY_HOST", "docker-socket-proxy:2375")).strip()
    if not docker_host:
        return {"tool": tool_name, "result_count": 0, "evidence": [], "provider_status": "unavailable"}
    service = str(arguments.get("service") or "").strip().lower()
    # `related_to` names the incident's own alerting service when `service`
    # names a genuinely different, discovered dependency of it -- distinct
    # from a self-check (the common case, where a caller has no specific
    # dependency to name yet and just asks "is my own service healthy?").
    # Defaulting it to `service` preserves that self-check shape (target ==
    # related_to, matching every existing caller). investigation.py's
    # dependency-hypothesis scoring keys off `target != related_to` to tell
    # "I confirmed MY OWN health" apart from "I confirmed THE DEPENDENCY's
    # health" -- without a real related_to, that distinction could never
    # fire no matter which service was actually queried.
    related_to = str(arguments.get("related_to") or arguments.get("service") or "").strip().lower()
    project = _runtime_project_scope(arguments)
    project_id, project_entry = _project_for(arguments)
    # Requesting the platform project's own identity means "show the whole
    # runtime topology", since no single container is named after the
    # umbrella project itself. This is independent of the actual Compose
    # project name on disk (it need not be "kaiops" at all -- see
    # _is_platform_wide_target), which is exactly why a literal "kaiops"
    # substring check previously matched nothing in a checkout named e.g.
    # "kaims". A normal single-service onboarded app whose project entry
    # happens to be named after itself is explicitly excluded.
    platform_wide = _is_platform_wide_target(project, project_id, project_entry)
    # A platform-wide incident's context-agent call passes the same identity
    # as both project and service (there is no more specific service to
    # name), so the service-level filter needs the identical exemption --
    # otherwise "show the whole topology" (project exempted) immediately
    # filters that same result back down to nothing (service not exempted),
    # a real live-verified regression: a platform-wide incident's dependency
    # evidence read 0 despite the project-level fix above.
    service_platform_wide = _is_platform_wide_target(service, project_id, project_entry)
    evidence: list[dict[str, Any]] = []
    observed_at = datetime.now(UTC).isoformat()
    try:
        async with httpx.AsyncClient(
            base_url=f"http://{docker_host}", timeout=httpx.Timeout(8.0), trust_env=False
        ) as client:
            response = await client.get("/containers/json", params=_docker_container_list_params(service, platform_wide=service_platform_wide))
            response.raise_for_status()
            containers = response.json()
        for index, container in enumerate(containers, 1):
            if not isinstance(container, dict):
                continue
            labels = container.get("Labels") if isinstance(container.get("Labels"), dict) else {}
            compose_project = str(labels.get("com.docker.compose.project") or "").lower()
            compose_service = str(labels.get("com.docker.compose.service") or "").lower()
            identity = " ".join(
                [compose_project, compose_service, *(str(item).lower() for item in container.get("Names", []))]
            )
            # project and service narrow independently and both apply when
            # both are supplied (e.g. project="kaiops", service="api-gateway"
            # must return only api-gateway, not the platform's own topology
            # with the service argument silently dropped).
            if project and not platform_wide and project not in identity:
                continue
            if service and not service_platform_wide and not service_matches(compose_service, service):
                continue
            state = str(container.get("State") or "unknown").lower()
            status = str(container.get("Status") or "unknown")
            lifecycle: dict[str, Any] = {}
            if state in {"exited", "dead"} and container.get("Id"):
                try:
                    async with httpx.AsyncClient(base_url=f"http://{docker_host}", timeout=5, trust_env=False) as inspector:
                        detail = await inspector.get(f"/containers/{container['Id']}/json")
                        detail.raise_for_status()
                        runtime = detail.json().get("State") or {}
                        lifecycle = {key: runtime.get(key) for key in (
                            "Running", "Restarting", "OOMKilled", "ExitCode", "StartedAt", "FinishedAt",
                        )}
                except Exception as error:
                    lifecycle = {"collection_error": type(error).__name__}
            networks = sorted((container.get("NetworkSettings") or {}).get("Networks", {}).keys())
            kind = "dependency" if health_only else "topology"
            subject_service = service if service and not service_platform_wide else compose_service
            snippet = json.dumps(
                {
                    "project": compose_project,
                    "service": subject_service, "runtime_service": compose_service,
                    "state": state,
                    "status": status,
                    "networks": networks,
                    "related_to": related_to,
                },
                ensure_ascii=False,
            )
            row = _evidence(kind, Path(f"docker/{compose_project or 'runtime'}/{compose_service or index}"), 1, snippet, [service] if service else [])
            row.update(
                {
                    "uri": f"docker://{compose_project or 'runtime'}/{compose_service or index}",
                    "service": subject_service, "runtime_service": compose_service,
                    # A top-level field, not just embedded in the snippet text --
                    # investigation.py's dependency-hypothesis scoring reads
                    # metadata.related_to directly (metadata is populated by
                    # passing every row field through, see EvidenceCompiler.compile).
                    "related_to": related_to,
                    "runtime_state": state,
                    "runtime_status": status,
                    "runtime_lifecycle": lifecycle,
                    "healthy": state == "running" and "unhealthy" not in status.lower(),
                    "observed_at": observed_at,
                    "observation_scope": "current_snapshot",
                    "requested_window": {
                        "start": str(arguments.get("start_time") or "") or None,
                        "end": str(arguments.get("end_time") or "") or None,
                    },
                }
            )
            evidence.append(row)
            if len(evidence) >= limit:
                break
    except Exception as exc:
        return {
            "tool": tool_name,
            "result_count": 0,
            "evidence": [],
            "provider_status": "failed",
            "provider_error": str(exc)[:240],
        }
    return {"tool": tool_name, "result_count": len(evidence), "evidence": evidence, "provider_status": "completed"}


# USE-method (Utilization/Saturation/Errors, Brendan Gregg) thresholds for a
# single container read from its own cgroup accounting via Docker's stats
# API -- the same read-only, minimal-privilege docker-socket-proxy already
# used for topology/dependency-health (CONTAINERS=1 permits GET .../stats,
# confirmed live). No new infrastructure: cAdvisor in this deployment only
# scrapes the "online boutique" demo project, but every container's own
# kernel-level CPU/memory accounting is already reachable through the proxy
# every other discovery tool uses.
_RESOURCE_CPU_SATURATED_PERCENT = float(os.getenv("DISCOVERY_MCP_RESOURCE_CPU_SATURATED_PERCENT", "90"))
_RESOURCE_CPU_THROTTLED_RATIO = float(os.getenv("DISCOVERY_MCP_RESOURCE_CPU_THROTTLED_RATIO", "0.1"))
_RESOURCE_MEMORY_SATURATED_PERCENT = float(os.getenv("DISCOVERY_MCP_RESOURCE_MEMORY_SATURATED_PERCENT", "85"))


def _container_resource_saturation(stats: dict[str, Any]) -> dict[str, Any]:
    """Derive USE-method saturation signals from one Docker `/stats` payload.

    - Utilization: cpu_percent (standard `docker stats` formula: usage delta
      over the two samples Docker's stats endpoint always returns, even for
      a single `stream=false` read, scaled by online CPU count) and
      mem_percent (working-set-style usage, preferring cgroup v2's
      `inactive_file` and falling back to cgroup v1's `cache` as the
      reclaimable component to subtract -- mirrors cAdvisor's
      container_memory_working_set_bytes, not raw RSS+cache).
    - Saturation: cpu_throttled_ratio, directly from the kernel's own CFS
      bandwidth controller (`throttling_data`) -- this is exactly
      cAdvisor/Prometheus's container_cpu_cfs_throttled_periods_total /
      container_cpu_cfs_periods_total ratio, read straight from the source
      Docker already collects it from instead of via a separate scraper.
    - Errors: not observed here (an OOM kill is a container-restart event,
      not a stats-endpoint field) -- left to the "dependency" plane's
      runtime_state/runtime_status, which already surfaces "exited"/"restarting".
    """
    cpu_stats = stats.get("cpu_stats") if isinstance(stats.get("cpu_stats"), dict) else {}
    precpu_stats = stats.get("precpu_stats") if isinstance(stats.get("precpu_stats"), dict) else {}
    cpu_usage = cpu_stats.get("cpu_usage") if isinstance(cpu_stats.get("cpu_usage"), dict) else {}
    precpu_usage = precpu_stats.get("cpu_usage") if isinstance(precpu_stats.get("cpu_usage"), dict) else {}
    cpu_delta = float(cpu_usage.get("total_usage") or 0) - float(precpu_usage.get("total_usage") or 0)
    system_delta = float(cpu_stats.get("system_cpu_usage") or 0) - float(precpu_stats.get("system_cpu_usage") or 0)
    online_cpus = int(cpu_stats.get("online_cpus") or len(cpu_usage.get("percpu_usage") or []) or 1)
    cpu_percent = round((cpu_delta / system_delta) * online_cpus * 100, 2) if system_delta > 0 else None

    throttling = cpu_stats.get("throttling_data") if isinstance(cpu_stats.get("throttling_data"), dict) else {}
    periods = int(throttling.get("periods") or 0)
    throttled_periods = int(throttling.get("throttled_periods") or 0)
    cpu_throttled_ratio = round(throttled_periods / periods, 4) if periods > 0 else 0.0

    memory_stats = stats.get("memory_stats") if isinstance(stats.get("memory_stats"), dict) else {}
    mem_usage_raw = float(memory_stats.get("usage") or 0)
    mem_limit = float(memory_stats.get("limit") or 0)
    mem_detail = memory_stats.get("stats") if isinstance(memory_stats.get("stats"), dict) else {}
    reclaimable = float(mem_detail.get("inactive_file", mem_detail.get("cache", 0)) or 0)
    mem_working_set = max(0.0, mem_usage_raw - reclaimable)
    mem_percent = round((mem_working_set / mem_limit) * 100, 2) if mem_limit > 0 else None

    saturated = bool(
        (cpu_percent is not None and cpu_percent >= _RESOURCE_CPU_SATURATED_PERCENT)
        or cpu_throttled_ratio >= _RESOURCE_CPU_THROTTLED_RATIO
        or (mem_percent is not None and mem_percent >= _RESOURCE_MEMORY_SATURATED_PERCENT)
    )
    return {
        "cpu_percent": cpu_percent,
        "cpu_throttled_ratio": cpu_throttled_ratio,
        "mem_percent": mem_percent,
        "mem_working_set_bytes": int(mem_working_set),
        "mem_limit_bytes": int(mem_limit) if mem_limit > 0 else None,
        "saturated": saturated,
    }


async def _search_resource_saturation(arguments: dict[str, Any]) -> dict[str, Any]:
    tool_name = "resource-health.search"
    limit = max(1, min(int(arguments.get("limit", 8)), 20))
    docker_host = str(os.getenv("DOCKER_LOG_DISCOVERY_HOST", "docker-socket-proxy:2375")).strip()
    if not docker_host:
        return {"tool": tool_name, "result_count": 0, "evidence": [], "provider_status": "unavailable"}
    service = str(arguments.get("service") or "").strip().lower()
    project = _runtime_project_scope(arguments)
    project_id, project_entry = _project_for(arguments)
    platform_wide = _is_platform_wide_target(project, project_id, project_entry)
    service_platform_wide = _is_platform_wide_target(service, project_id, project_entry)
    evidence: list[dict[str, Any]] = []
    observed_at = datetime.now(UTC).isoformat()
    try:
        async with httpx.AsyncClient(
            base_url=f"http://{docker_host}", timeout=httpx.Timeout(8.0), trust_env=False
        ) as client:
            response = await client.get("/containers/json", params=_docker_container_list_params(service, platform_wide=service_platform_wide))
            response.raise_for_status()
            containers = response.json()
            matched: list[dict[str, Any]] = []
            for container in containers:
                if not isinstance(container, dict):
                    continue
                labels = container.get("Labels") if isinstance(container.get("Labels"), dict) else {}
                compose_project = str(labels.get("com.docker.compose.project") or "").lower()
                compose_service = str(labels.get("com.docker.compose.service") or "").lower()
                identity = " ".join(
                    [compose_project, compose_service, *(str(item).lower() for item in container.get("Names", []))]
                )
                if project and not platform_wide and project not in identity:
                    continue
                if service and not service_platform_wide and not service_matches(compose_service, service):
                    continue
                if str(container.get("State") or "").lower() != "running":
                    # A stopped container has no live cgroup stats to read;
                    # its runtime_state is already covered by the
                    # "dependency"/"topology" plane.
                    continue
                matched.append(container)
            for index, container in enumerate(matched[:limit], 1):
                container_id = str(container.get("Id") or "")
                labels = container.get("Labels") if isinstance(container.get("Labels"), dict) else {}
                compose_project = str(labels.get("com.docker.compose.project") or "").lower()
                compose_service = str(labels.get("com.docker.compose.service") or "").lower()
                try:
                    stats_response = await client.get(f"/containers/{container_id}/stats", params={"stream": "false"})
                    stats_response.raise_for_status()
                    saturation = _container_resource_saturation(stats_response.json())
                except Exception as exc:
                    saturation = {"provider_error": str(exc)[:240]}
                snippet = json.dumps(
                    {"project": compose_project, "service": compose_service, **saturation},
                    ensure_ascii=False,
                )
                row = _evidence(
                    "resource", Path(f"docker/{compose_project or 'runtime'}/{compose_service or index}"),
                    1, snippet, [service] if service else [],
                )
                row.update({
                    "uri": f"docker://{compose_project or 'runtime'}/{compose_service or index}/stats",
                    "service": compose_service or service,
                    "observed_at": observed_at,
                    "observation_scope": "current_snapshot",
                    **saturation,
                })
                evidence.append(row)
    except Exception as exc:
        return {
            "tool": tool_name,
            "result_count": 0,
            "evidence": [],
            "provider_status": "failed",
            "provider_error": str(exc)[:240],
        }
    return {"tool": tool_name, "result_count": len(evidence), "evidence": evidence, "provider_status": "completed"}


TOOLS = [
    {
        "name": "logs.search",
        "description": "Read-only bounded search of runtime and archived logs.",
        "inputSchema": {"type": "object", "properties": {"terms": {"type": "array"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "tickets.search",
        "description": "Read-only search of Jira CSV, email tickets, and incident documents.",
        "inputSchema": {"type": "object", "properties": {"terms": {"type": "array"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "code.search",
        "description": "Read-only bounded search of source, configuration, and deployment files.",
        "inputSchema": {"type": "object", "properties": {"terms": {"type": "array"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "mysql.search",
        "description": "Read-only bounded evidence search over KaiOps MySQL tables.",
        "inputSchema": {"type": "object", "properties": {"terms": {"type": "array"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "telemetry.search",
        "description": "Correlated read-only search of project Prometheus metrics, Jaeger traces, and OpenSearch logs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string"},
                "application": {"type": "string"},
                "service": {"type": "string"},
                "trace_id": {"type": "string"},
                "terms": {"type": "array"},
                "limit": {"type": "integer"}
            }
        },
    },
    {
        "name": "traces.search",
        "description": "Read-only correlated trace search through the onboarded telemetry project.",
        "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}, "service": {"type": "string"}, "trace_id": {"type": "string"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "topology.search",
        "description": "Read-only runtime topology discovery through the scoped Docker API proxy.",
        "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}, "service": {"type": "string"}, "related_to": {"type": "string"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "dependency-health.search",
        "description": "Read-only dependency runtime health discovery through the scoped Docker API proxy. Pass `service` as the specific dependency being checked and `related_to` as the incident's own alerting service to distinguish a dependency check from a self-check.",
        "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}, "service": {"type": "string"}, "related_to": {"type": "string"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "resource-health.search",
        "description": "Read-only USE-method (utilization/saturation) container resource check through the scoped Docker API proxy: CPU percent, CPU CFS throttling ratio, and working-set memory percent read directly from the container's own cgroup accounting.",
        "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}, "service": {"type": "string"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "changes.search",
        "description": "Read-only bounded search of deployment and configuration change artifacts.",
        "inputSchema": {"type": "object", "properties": {"terms": {"type": "array"}, "service": {"type": "string"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "runbooks.search",
        "description": "Read-only lookup of immutable governed runbook catalog entries.",
        "inputSchema": {"type": "object", "properties": {"terms": {"type": "array"}, "service": {"type": "string"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "external.search",
        "description": "Read-only search through the explicitly configured external knowledge provider.",
        "inputSchema": {
            "type": "object",
            "properties": {"terms": {"type": "array"}, "limit": {"type": "integer"}},
        },
    },
]


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    terms = _terms(arguments)
    limit = max(1, min(int(arguments.get("limit", 8)), 20))
    if name == "code.search":
        terms = _code_search_terms(arguments)
        rows = _search_text_files(
            _code_roots(arguments),
            CODE_SUFFIXES - {".md"},
            terms,
            "code",
            limit,
        )
    elif name == "tickets.search":
        rows = _search_tickets(terms, limit)
    elif name == "changes.search":
        return _search_changes(arguments)
    elif name == "runbooks.search":
        return _search_runbooks(arguments)
    else:
        raise ValueError(f"unknown MCP tool: {name}")
    return {"tool": name, "query_terms": terms, "result_count": len(rows), "evidence": rows}


async def _call_ticket_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    terms = _terms(arguments)
    limit = max(1, min(int(arguments.get("limit", 8)), 20))
    jira_rows = await _search_jira_tickets(arguments, terms, limit)
    local_rows = await asyncio.to_thread(_search_tickets, terms, limit)
    # Each source above already bounds itself to `limit`; re-slicing the
    # concatenation to `limit` here silently dropped every local-history row
    # whenever Jira alone returned `limit` or more tickets (the common case).
    rows = jira_rows + local_rows
    return {
        "tool": "tickets.search",
        "query_terms": terms,
        "result_count": len(rows),
        "evidence": rows,
        "sources": {
            "jira": len(jira_rows),
            "local_history": len(local_rows),
        },
    }


async def _call_logs_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    terms = _terms(arguments)
    limit = max(1, min(int(arguments.get("limit", 8)), 20))
    from common.disk_attribution import search_disk_observations
    file_rows, docker_rows, disk_result = await asyncio.gather(
        asyncio.to_thread(
            _search_text_files,
            _roots("DISCOVERY_MCP_LOG_ROOTS", "/data/fault-lab/runtime"),
            LOG_SUFFIXES,
            terms,
            "log",
            limit,
        ),
        _search_docker_logs(arguments, terms, limit),
        asyncio.to_thread(search_disk_observations,
            Path(os.getenv("DISCOVERY_MCP_DISK_OBSERVATIONS_ROOT", "/workspace/backend/host-evidence/disk-attribution")),
            arguments, limit),
    )
    merged: dict[str, dict[str, Any]] = {}
    # Host filesystem questions must see actual writer/allocation observations
    # before exporter startup logs consume the evidence quota.
    for row in [*disk_result["evidence"], *docker_rows, *file_rows]:
        merged[str(row.get("evidence_id") or row.get("uri"))] = row
    rows = list(merged.values())
    diagnosis = _log_diagnosis(rows, str(arguments.get("service") or ""))
    if diagnosis:
        rows.insert(0, diagnosis)
    # docker_rows and file_rows are each already bounded to `limit` before
    # merging; re-slicing the merged list to `limit` here silently dropped
    # every file-log row whenever docker logs alone filled the quota.
    return {
        "tool": "logs.search",
        "query_terms": terms,
        "result_count": len(rows),
        "evidence": rows,
        "sources": {"docker": len(docker_rows), "files": len(file_rows),
                    "host_disk": len(disk_result["evidence"])},
        "host_disk_status": disk_result["provider_status"],
        "host_disk_coverage": disk_result.get("coverage", [])[:3],
    }


async def _call_external_search_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Query an explicitly configured read-only external search provider.

    The provider must accept ``{"query": str, "limit": int}`` and return either
    ``{"results": [...]}`` or ``{"items": [...]}``. Keeping this behind a
    configured endpoint avoids silently treating a second LLM call as external
    evidence.
    """
    terms = _terms(arguments)
    limit = max(1, min(int(arguments.get("limit", 8)), 10))
    endpoint = str(os.getenv("EXTERNAL_KNOWLEDGE_SEARCH_URL", "")).strip()
    if not endpoint:
        return {
            "tool": "external.search",
            "query_terms": terms,
            "result_count": 0,
            "evidence": [],
            "provider_status": "unavailable",
            "provider_error": "EXTERNAL_KNOWLEDGE_SEARCH_URL is not configured",
        }
    headers = {"Accept": "application/json"}
    token = str(os.getenv("EXTERNAL_KNOWLEDGE_SEARCH_TOKEN", "")).strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    timeout = max(2.0, min(float(os.getenv("EXTERNAL_KNOWLEDGE_SEARCH_TIMEOUT_SECONDS", "12")), 30.0))
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            response = await client.post(endpoint, json={"query": " ".join(terms), "limit": limit})
            response.raise_for_status()
            payload = response.json()
        rows = payload.get("results") if isinstance(payload, dict) else []
        if not isinstance(rows, list) and isinstance(payload, dict):
            rows = payload.get("items")
        rows = rows if isinstance(rows, list) else []
        evidence: list[dict[str, Any]] = []
        for index, row in enumerate(rows[:limit], 1):
            if not isinstance(row, dict):
                continue
            uri = str(row.get("url") or row.get("uri") or "").strip()
            snippet = _redact(str(row.get("snippet") or row.get("description") or row.get("title") or ""))[:700]
            if not uri or not snippet:
                continue
            digest = hashlib.sha256(f"{uri}|{snippet}".encode()).hexdigest()[:16]
            evidence.append(
                {
                    "evidence_id": f"EXTERNAL-{digest}",
                    "source": "external.search",
                    "uri": uri,
                    "title": str(row.get("title") or "")[:200],
                    "snippet": snippet,
                    "matched_terms": terms,
                    "confidence": min(0.6, float(row.get("confidence") or 0.5)),
                    "knowledge_only": True,
                }
            )
        return {
            "tool": "external.search",
            "query_terms": terms,
            "result_count": len(evidence),
            "evidence": evidence,
            "provider_status": "completed",
        }
    except Exception as exc:
        return {
            "tool": "external.search",
            "query_terms": terms,
            "result_count": 0,
            "evidence": [],
            "provider_status": "failed",
            "provider_error": str(exc)[:240],
        }


@app.post("/mcp")
async def mcp(request: MCPRequest) -> dict[str, Any]:
    try:
        if request.method == "initialize":
            result = {
                "protocolVersion": "2025-03-26",
                "serverInfo": {"name": "kaiops-discovery-mcp", "version": "1.0.0"},
                "capabilities": {"tools": {"listChanged": False}},
            }
        elif request.method == "tools/list":
            result = {"tools": TOOLS}
        elif request.method == "tools/call":
            name = str(request.params.get("name") or "")
            arguments = request.params.get("arguments")
            safe_arguments = arguments if isinstance(arguments, dict) else {}
            if name == "mysql.search":
                result = await _call_mysql_tool(safe_arguments)
            elif name == "telemetry.search":
                result = await _search_telemetry(safe_arguments)
            elif name == "traces.search":
                result = await _search_traces(safe_arguments)
            elif name == "topology.search":
                result = await _search_runtime_topology(safe_arguments, health_only=False)
            elif name == "dependency-health.search":
                result = await _search_runtime_topology(safe_arguments, health_only=True)
            elif name == "resource-health.search":
                result = await _search_resource_saturation(safe_arguments)
            elif name == "changes.search":
                result = await _search_changes_with_deployment_evidence(safe_arguments)
            elif name == "tickets.search":
                result = await _call_ticket_tool(safe_arguments)
            elif name == "logs.search":
                result = await _call_logs_tool(safe_arguments)
            elif name == "external.search":
                result = await _call_external_search_tool(safe_arguments)
            else:
                result = await asyncio.to_thread(_call_tool, name, safe_arguments)
        else:
            raise ValueError(f"unsupported MCP method: {request.method}")
        return {"jsonrpc": "2.0", "id": request.id, "result": result}
    except Exception as exc:
        return {"jsonrpc": "2.0", "id": request.id, "error": {"code": -32602, "message": str(exc)}}
