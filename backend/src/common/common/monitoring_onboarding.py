from __future__ import annotations

import asyncio
import json
import os
import re
from collections import Counter, deque
from pathlib import Path
from time import perf_counter
from typing import Any, TypedDict
from urllib.parse import urlparse
from uuid import UUID, uuid4

import httpx
from langgraph.graph import END, StateGraph

from common.logging import get_logger
from common.models import (
    ApplicationDiscoveryResult,
    ApplicationRegistration,
    GrafanaDashboardResult,
    MetricsValidationResult,
    MonitoringValidationResult,
    PrometheusRuleSpec,
    RecordingRuleSpec,
    RulesGeneratedResult,
    ScrapeConfigSpec,
)

logger = get_logger(__name__)


def application_from_row(row: dict[str, Any]) -> ApplicationRegistration:
    payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
    return ApplicationRegistration.model_validate(
        {
            "id": row.get("id") or payload.get("id"),
            "created_at": row.get("created_at") or payload.get("created_at"),
            "trace_id": payload.get("trace_id"),
            "metadata": payload.get("metadata") or {},
            "tenant_id": row.get("tenant_id") or payload.get("tenant_id"),
            "name": row.get("name") or payload.get("name"),
            "owner_team": row.get("owner_team") or payload.get("owner_team"),
            "owner_email": row.get("owner_email") or payload.get("owner_email"),
            "environment": row.get("environment") or payload.get("environment"),
            "namespace": row.get("namespace") or payload.get("namespace"),
            "region": row.get("region") or payload.get("region"),
            "technology": row.get("technology") or payload.get("technology"),
            "monitoring_platform": row.get("monitoring_platform") or payload.get("monitoring_platform"),
            "metrics_endpoint": row.get("metrics_endpoint") or payload.get("metrics_endpoint"),
            "labels": payload.get("labels") or {},
            "status": row.get("status") or payload.get("status"),
        }
    )


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", str(value or "").strip().lower()).strip("-") or "application"


def _metric_prefix(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", str(value or "").strip().lower()).strip("_") or "application"
    if cleaned[0].isdigit():
        return f"app_{cleaned}"
    return cleaned


def onboarding_root() -> Path:
    candidates = [
        Path("/app/rag/changes"),
        Path(__file__).resolve().parents[5] / "backend" / "rag" / "changes",
        Path(__file__).resolve().parents[5] / "rag" / "changes",
    ]
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except Exception:
            continue
    fallback = Path("/tmp/kaiops/changes")
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def _build_metrics_candidates(endpoint: str) -> list[str]:
    raw = str(endpoint or "").strip().rstrip("/")
    if not raw:
        return []
    parsed = urlparse(raw)
    if parsed.path.endswith("/metrics") or parsed.path.endswith("/actuator/prometheus"):
        return [raw]
    return [f"{raw}/metrics", f"{raw}/actuator/prometheus", raw]


# --- Codebase / log discovery -------------------------------------------------
#
# The discovery agent inspects the monitored application's source tree and its
# runtime logs to build real context (services, technology, metrics endpoint,
# active incident scenarios) instead of echoing the registration payload. The
# scan roots are configurable; by default they point at the vendored fault-lab
# app that produces the KaiOps incident symptoms.

DISCOVERY_CODEBASE_ROOT_ENV = "DISCOVERY_CODEBASE_ROOT"
DISCOVERY_LOG_PATH_ENV = "DISCOVERY_LOG_PATH"
_DEFAULT_CODEBASE_ROOT = "/app/fault-lab"

# Bounds so a scan can never run away on a large or hostile tree.
_SCAN_MAX_FILES = 600
_SCAN_MAX_FILE_BYTES = 300_000
_SCAN_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".mypy_cache", ".pytest_cache", "runtime", "dist", "build"}
_SCAN_CODE_SUFFIXES = {".py", ".js", ".ts", ".go", ".java", ".rb", ".yml", ".yaml", ".toml", ".txt", ".md", ""}
_LOG_MAX_LINES = 4000
_LOG_RECENT_ERRORS = 20


def _discovery_codebase_root() -> Path | None:
    raw = str(os.getenv(DISCOVERY_CODEBASE_ROOT_ENV, _DEFAULT_CODEBASE_ROOT) or "").strip()
    if not raw:
        return None
    root = Path(raw)
    return root if root.exists() else None


def _discovery_log_path(root: Path | None) -> Path | None:
    raw = str(os.getenv(DISCOVERY_LOG_PATH_ENV, "") or "").strip()
    if raw:
        candidate = Path(raw)
        return candidate if candidate.is_file() else None
    if root is not None:
        candidate = root / "runtime" / "application.log"
        if candidate.is_file():
            return candidate
    return None


def _scan_bundled_ticket_csv(path: Path) -> dict[str, Any]:
    """Extract service / component / scenario inventory from a bundled ticket CSV."""
    import csv as _csv

    services: Counter[str] = Counter()
    components: Counter[str] = Counter()
    scenarios: set[str] = set()
    try:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = _csv.DictReader(stream)
            for index, row in enumerate(reader):
                if index >= 5000:
                    break
                service = str(row.get("Service") or "").strip()
                component = str(row.get("Component/s") or "").strip()
                labels = str(row.get("Labels") or "")
                if service:
                    services[service] += 1
                if component:
                    components[component] += 1
                for token in labels.split(","):
                    token = token.strip()
                    if token.startswith("kaiops-scenario-"):
                        scenarios.add(token)
    except Exception:
        return {}
    return {
        "services": [name for name, _ in services.most_common()],
        "components": [name for name, _ in components.most_common()],
        "scenarios": sorted(scenarios),
    }


def scan_codebase(root: Path | None) -> dict[str, Any]:
    """Inspect an application's source tree to discover monitoring context.

    Returns services, components, detected languages/technology, the metrics
    endpoint (path + port) and entrypoints. Bounded by file count and size so it
    is safe to run against arbitrary trees. Never raises.
    """
    result: dict[str, Any] = {
        "root": str(root) if root else "",
        "services": [],
        "components": [],
        "scenarios": [],
        "languages": [],
        "technology": "",
        "metrics_path": "",
        "metrics_port": "",
        "entrypoints": [],
        "files_scanned": 0,
    }
    if root is None or not root.exists():
        return result

    languages: set[str] = set()
    frameworks: set[str] = set()
    entrypoints: list[str] = []
    metrics_path = ""
    metrics_port = ""
    files_scanned = 0
    ext_language = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".go": "go",
        ".java": "java",
        ".rb": "ruby",
    }

    try:
        for path in sorted(root.rglob("*")):
            if files_scanned >= _SCAN_MAX_FILES:
                break
            if not path.is_file():
                continue
            if any(part in _SCAN_SKIP_DIRS for part in path.relative_to(root).parts):
                continue
            suffix = path.suffix.lower()

            # Ticket CSVs describe the monitored service inventory directly.
            if suffix == ".csv":
                bundled = _scan_bundled_ticket_csv(path)
                if bundled:
                    result["services"] = bundled.get("services", [])[:50]
                    result["components"] = bundled.get("components", [])[:50]
                    result["scenarios"] = bundled.get("scenarios", [])
                continue

            if suffix not in _SCAN_CODE_SUFFIXES:
                continue
            try:
                if path.stat().st_size > _SCAN_MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            files_scanned += 1

            if suffix in ext_language:
                languages.add(ext_language[suffix])
            lowered = text.lower()
            if "fastapi" in lowered or "uvicorn" in lowered:
                frameworks.add("python-fastapi")
            if "from http.server" in lowered or "basehttprequesthandler" in lowered:
                frameworks.add("python-http-server")
            if "flask" in lowered:
                frameworks.add("python-flask")
            if "spring" in lowered or "org.springframework" in lowered:
                frameworks.add("java-spring")
            if path.name in {"package.json"}:
                frameworks.add("node")
            if path.name in {"go.mod"}:
                frameworks.add("go-service")

            if not metrics_path:
                match = re.search(r'["\']((?:/[\w.-]*)*/metrics)["\']', text) or re.search(r"(/metrics)\b", text)
                if match:
                    metrics_path = match.group(1)
            if not metrics_port:
                port_match = (
                    re.search(r"EXPOSE\s+(\d{2,5})", text)
                    or re.search(r"port[\"'\s:=]+(\d{2,5})", text, re.IGNORECASE)
                    or re.search(r"--port[=\s]+(\d{2,5})", text)
                )
                if port_match:
                    metrics_port = port_match.group(1)

            if path.name in {"fault_lab.py", "app.py", "main.py", "main.go", "server.py", "index.js"}:
                entrypoints.append(str(path.relative_to(root)))
    except Exception:
        logger.exception("codebase scan failed for %s", root)

    technology = ""
    for candidate in ("python-fastapi", "java-spring", "python-http-server", "python-flask", "go-service", "node"):
        if candidate in frameworks:
            technology = candidate
            break
    if not technology and languages:
        technology = f"{sorted(languages)[0]}-service"

    result.update(
        {
            "languages": sorted(languages),
            "frameworks": sorted(frameworks),
            "technology": technology,
            "metrics_path": metrics_path,
            "metrics_port": metrics_port,
            "entrypoints": entrypoints[:10],
            "files_scanned": files_scanned,
        }
    )
    return result


def scan_logs(log_path: Path | None) -> dict[str, Any]:
    """Parse JSON-line application logs to discover active runtime context.

    Extracts active services/components, incident scenarios, alert names, log
    level counts and recent error signatures from the tail of the log. Bounded
    by line count. Never raises.
    """
    result: dict[str, Any] = {
        "log_path": str(log_path) if log_path else "",
        "services": [],
        "components": [],
        "active_scenarios": [],
        "alert_names": [],
        "levels": {},
        "error_count": 0,
        "recent_errors": [],
        "lines_parsed": 0,
    }
    if log_path is None or not log_path.is_file():
        return result

    services: Counter[str] = Counter()
    components: Counter[str] = Counter()
    scenarios: Counter[str] = Counter()
    alert_names: Counter[str] = Counter()
    levels: Counter[str] = Counter()
    recent_errors: deque[dict[str, str]] = deque(maxlen=_LOG_RECENT_ERRORS)
    lines_parsed = 0

    try:
        with log_path.open(encoding="utf-8", errors="ignore") as stream:
            tail = deque(stream, maxlen=_LOG_MAX_LINES)
        for line in tail:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except Exception:
                continue
            if not isinstance(record, dict):
                continue
            lines_parsed += 1
            level = str(record.get("level") or "").strip().upper()
            if level:
                levels[level] += 1
            if record.get("service"):
                services[str(record["service"])] += 1
            if record.get("component"):
                components[str(record["component"])] += 1
            if record.get("scenario_id"):
                scenarios[str(record["scenario_id"])] += 1
            if record.get("alert_name"):
                alert_names[str(record["alert_name"])] += 1
            if level in {"ERROR", "CRITICAL", "FATAL"}:
                recent_errors.append(
                    {
                        "service": str(record.get("service") or ""),
                        "scenario_id": str(record.get("scenario_id") or ""),
                        "message": str(record.get("message") or "")[:300],
                    }
                )
    except Exception:
        logger.exception("log scan failed for %s", log_path)

    result.update(
        {
            "services": [name for name, _ in services.most_common(50)],
            "components": [name for name, _ in components.most_common(50)],
            "active_scenarios": [name for name, _ in scenarios.most_common()],
            "alert_names": [name for name, _ in alert_names.most_common(50)],
            "levels": dict(levels),
            "error_count": int(levels.get("ERROR", 0) + levels.get("CRITICAL", 0) + levels.get("FATAL", 0)),
            "recent_errors": list(recent_errors),
            "lines_parsed": lines_parsed,
        }
    )
    return result


class _DiscoveryState(TypedDict, total=False):
    application: dict[str, Any]
    resources: list[dict[str, Any]]
    labels: dict[str, str]
    metrics_endpoint: str
    technology: str
    resource_kind: str
    code_scan: dict[str, Any]
    log_scan: dict[str, Any]


class DiscoveryAgent:
    def __init__(self) -> None:
        graph = StateGraph(_DiscoveryState)
        graph.add_node("inventory", self._inventory)
        graph.add_node("metrics", self._metrics)
        graph.add_node("classify", self._classify)
        graph.set_entry_point("inventory")
        graph.add_edge("inventory", "metrics")
        graph.add_edge("metrics", "classify")
        graph.add_edge("classify", END)
        self._graph = graph.compile()

    def _inventory(self, state: _DiscoveryState) -> _DiscoveryState:
        application = state.get("application", {})
        labels = dict(application.get("labels") or {})

        # Look into the application's codebase and runtime logs for real context.
        root = _discovery_codebase_root()
        code_scan = scan_codebase(root)
        log_scan = scan_logs(_discovery_log_path(root))

        resources = [
            {
                "kind": labels.get("workload_kind", "Deployment"),
                "name": application.get("name"),
                "namespace": application.get("namespace"),
                "environment": application.get("environment"),
            },
            {
                "kind": "Service",
                "name": f"{application.get('name')}-svc",
                "namespace": application.get("namespace"),
            },
        ]

        # Merge services discovered from code + logs (logs describe what is
        # actually running now; code describes the full inventory).
        discovered_services: list[str] = []
        for name in list(log_scan.get("services") or []) + list(code_scan.get("services") or []):
            if name and name not in discovered_services:
                discovered_services.append(name)
        for name in discovered_services:
            resources.append({"kind": "DiscoveredService", "name": name, "source": "codebase+logs"})

        return {"resources": resources, "labels": labels, "code_scan": code_scan, "log_scan": log_scan}

    def _metrics(self, state: _DiscoveryState) -> _DiscoveryState:
        application = state.get("application", {})
        endpoint = str(application.get("metrics_endpoint") or "").strip()
        if endpoint:
            return {"metrics_endpoint": endpoint}

        code_scan = state.get("code_scan") or {}
        log_scan = state.get("log_scan") or {}
        labels = application.get("labels", {}) if isinstance(application.get("labels"), dict) else {}
        # Prefer a metrics endpoint discovered from the codebase; fall back to the
        # registration labels and finally the previous default.
        host = (
            (log_scan.get("services") or [None])[0]
            or (code_scan.get("services") or [None])[0]
            or application.get("name")
        )
        port = str(code_scan.get("metrics_port") or labels.get("metrics_port") or "8000").strip() or "8000"
        path = str(code_scan.get("metrics_path") or "").strip()
        base = f"http://{host}:{port}"
        return {"metrics_endpoint": f"{base}{path}" if path else base}

    def _classify(self, state: _DiscoveryState) -> _DiscoveryState:
        application = state.get("application", {})
        technology = str(application.get("technology") or "").strip().lower()
        discovered_technology = str((state.get("code_scan") or {}).get("technology") or "").strip().lower()
        resource_kind = str((state.get("labels") or {}).get("workload_kind") or "Deployment")
        return {
            "technology": technology or discovered_technology or "python-fastapi",
            "resource_kind": resource_kind.lower(),
        }

    async def run(self, application: ApplicationRegistration) -> ApplicationDiscoveryResult:
        state = await self._graph.ainvoke({"application": application.model_dump(mode="json")})
        code_scan = state.get("code_scan") or {}
        log_scan = state.get("log_scan") or {}

        # Surface discovered context as string labels for downstream onboarding/RAG.
        def _join(values: Any, limit: int = 25) -> str:
            items = [str(item) for item in (values or []) if str(item).strip()]
            return ", ".join(items[:limit])

        discovery_labels: dict[str, str] = {}
        discovered_services = _join(log_scan.get("services") or code_scan.get("services"))
        if discovered_services:
            discovery_labels["discovered_services"] = discovered_services
        if code_scan.get("scenarios") or log_scan.get("active_scenarios"):
            discovery_labels["active_scenarios"] = _join(
                log_scan.get("active_scenarios") or code_scan.get("scenarios"), limit=50
            )
        if log_scan.get("alert_names"):
            discovery_labels["discovered_alert_names"] = _join(log_scan.get("alert_names"))
        if code_scan.get("languages"):
            discovery_labels["discovered_languages"] = _join(code_scan.get("languages"))
        if int(log_scan.get("error_count") or 0):
            discovery_labels["log_error_count"] = str(int(log_scan.get("error_count")))
        if code_scan.get("files_scanned"):
            discovery_labels["codebase_files_scanned"] = str(int(code_scan.get("files_scanned")))
        if code_scan.get("root"):
            discovery_labels["codebase_root"] = str(code_scan.get("root"))

        return ApplicationDiscoveryResult(
            application_id=application.id,
            tenant_id=application.tenant_id,
            name=application.name,
            environment=application.environment,
            namespace=application.namespace,
            technology=str(state.get("technology") or application.technology),
            resource_kind=str(state.get("resource_kind") or "deployment"),
            discovered_resources=list(state.get("resources") or []),
            metrics_endpoint=str(state.get("metrics_endpoint") or application.metrics_endpoint),
            labels={**application.labels, **dict(state.get("labels") or {}), **discovery_labels},
        )


class _ValidationState(TypedDict, total=False):
    discovery: dict[str, Any]
    metrics_available: bool
    exporter: str
    technology: str
    metric_families: list[str]
    sample_metrics: list[str]


class ValidationAgent:
    def __init__(self) -> None:
        graph = StateGraph(_ValidationState)
        graph.add_node("probe", self._probe)
        graph.add_node("infer", self._infer)
        graph.set_entry_point("probe")
        graph.add_edge("probe", "infer")
        graph.add_edge("infer", END)
        self._graph = graph.compile()

    async def _probe(self, state: _ValidationState) -> _ValidationState:
        discovery = state.get("discovery", {})
        candidates = _build_metrics_candidates(str(discovery.get("metrics_endpoint") or ""))
        metric_families: list[str] = []
        sample_metrics: list[str] = []
        metrics_available = False
        async with httpx.AsyncClient(timeout=5.0) as client:
            for candidate in candidates:
                try:
                    response = await client.get(candidate)
                except Exception:
                    continue
                if response.status_code >= 400:
                    continue
                body = response.text
                lines = [line.strip() for line in body.splitlines() if line.strip() and not line.startswith("#")]
                if lines:
                    metrics_available = True
                    sample_metrics = lines[:12]
                    metric_families = sorted({line.split("{", 1)[0].split(" ", 1)[0] for line in lines[:120]})
                    break
        return {
            "metrics_available": metrics_available,
            "metric_families": metric_families,
            "sample_metrics": sample_metrics,
        }

    def _infer(self, state: _ValidationState) -> _ValidationState:
        families = [str(item) for item in state.get("metric_families") or []]
        exporter = "custom"
        technology = "unknown"
        if any(name.startswith("jvm_") for name in families):
            technology = "java-spring"
            exporter = "micrometer"
        elif any(name.startswith("http_server_requests") for name in families):
            technology = "spring-boot"
            exporter = "actuator"
        elif any(name.startswith("process_") or name.startswith("python_") for name in families):
            technology = "python-fastapi"
            exporter = "prometheus-client"
        elif any(name.startswith("go_") for name in families):
            technology = "go-service"
            exporter = "promhttp"
        elif any(name.startswith("rabbitmq_") for name in families):
            technology = "rabbitmq"
            exporter = "rabbitmq-exporter"
        elif any(name.startswith("mysql_") for name in families):
            technology = "mysql"
            exporter = "mysqld-exporter"
        return {"technology": technology, "exporter": exporter}

    async def run(self, discovery: ApplicationDiscoveryResult) -> MetricsValidationResult:
        state = await self._graph.ainvoke({"discovery": discovery.model_dump(mode="json")})
        return MetricsValidationResult(
            application_id=discovery.application_id,
            tenant_id=discovery.tenant_id,
            metrics_endpoint=discovery.metrics_endpoint,
            metrics_available=bool(state.get("metrics_available", False)),
            technology=str(state.get("technology") or discovery.technology),
            exporter=str(state.get("exporter") or "custom"),
            labels=discovery.labels,
            metric_families=list(state.get("metric_families") or []),
            sample_metrics=list(state.get("sample_metrics") or []),
        )


def _pick_metric(families: list[str], candidates: list[str], fallback: str) -> str:
    for candidate in candidates:
        if candidate in families:
            return candidate
    return fallback


class RuleGenerationAgent:
    async def run(
        self,
        application: ApplicationRegistration,
        discovery: ApplicationDiscoveryResult,
        validation: MetricsValidationResult,
    ) -> RulesGeneratedResult:
        families = validation.metric_families
        slug = _slug(application.name)
        parsed_endpoint = urlparse(validation.metrics_endpoint)
        target = parsed_endpoint.netloc or parsed_endpoint.path
        metrics_path = parsed_endpoint.path or "/metrics"
        scrape_config = ScrapeConfigSpec(
            job_name=slug,
            targets=[target],
            metrics_path=metrics_path,
            scheme=parsed_endpoint.scheme or "http",
            labels={
                "application": application.name,
                "tenant": application.tenant_id,
                "environment": application.environment,
                "namespace": application.namespace,
            },
        )

        cpu_metric = _pick_metric(families, ["process_cpu_seconds_total", "container_cpu_usage_seconds_total"], "up")
        mem_metric = _pick_metric(families, ["process_resident_memory_bytes", "container_memory_working_set_bytes"], "up")
        latency_metric = _pick_metric(families, ["http_server_requests_seconds_bucket", "request_latency_ms_p95"], "")
        five_xx_metric = _pick_metric(families, ["http_requests_total", "http_server_requests_seconds_count"], "")
        restart_metric = _pick_metric(families, ["kube_pod_container_status_restarts_total"], "")

        alert_rules = [
            PrometheusRuleSpec(
                name=f"{slug}-target-down",
                expr=f'(up{{job="{slug}"}} == 0) or absent(up{{job="{slug}"}})',
                duration="2m",
                severity="critical",
                labels={"team": application.owner_team, "namespace": application.namespace},
                annotations={"summary": f"{application.name} target is down", "description": "Prometheus cannot scrape the application target."},
            ),
            PrometheusRuleSpec(
                name=f"{slug}-cpu-high",
                expr=(f'rate({cpu_metric}{{job="{slug}"}}[5m]) > 0.85' if cpu_metric != "up" else f'(up{{job="{slug}"}} == 0) or absent(up{{job="{slug}"}})'),
                duration="5m",
                severity="warning",
                labels={"team": application.owner_team},
                annotations={"summary": f"{application.name} CPU usage high", "description": "Sustained CPU saturation detected."},
            ),
            PrometheusRuleSpec(
                name=f"{slug}-memory-high",
                expr=(f'{mem_metric}{{job="{slug}"}} > 5e+08' if mem_metric != "up" else f'(up{{job="{slug}"}} == 0) or absent(up{{job="{slug}"}})'),
                duration="10m",
                severity="warning",
                labels={"team": application.owner_team},
                annotations={"summary": f"{application.name} memory usage high", "description": "Sustained memory growth detected."},
            ),
        ]
        # Missing resource metrics are a coverage gap, never a resource alarm.
        alert_rules = [rule for rule in alert_rules
                       if not (rule.name.endswith("-cpu-high") and cpu_metric == "up")
                       and not (rule.name.endswith("-memory-high") and mem_metric == "up")]
        if latency_metric:
            alert_rules.append(
                PrometheusRuleSpec(
                    name=f"{slug}-latency-p95-high",
                    expr=(f'{latency_metric}{{job="{slug}"}} > 1000' if latency_metric == "request_latency_ms_p95"
                          else f'histogram_quantile(0.95, sum(rate({latency_metric}{{job="{slug}"}}[5m])) by (le)) > 1'),
                    duration="5m",
                    severity="critical",
                    labels={"team": application.owner_team},
                    annotations={"summary": f"{application.name} latency elevated", "description": "95th percentile latency exceeded threshold."},
                )
            )
        if five_xx_metric:
            alert_rules.append(
                PrometheusRuleSpec(
                    name=f"{slug}-http-5xx-rate",
                    expr=f'sum(rate({five_xx_metric}{{job="{slug}",status=~"5.."}}[5m])) > 0.05',
                    duration="5m",
                    severity="critical",
                    labels={"team": application.owner_team},
                    annotations={"summary": f"{application.name} HTTP 5xx rate high", "description": "Server error rate exceeded threshold."},
                )
            )
        if restart_metric:
            alert_rules.append(
                PrometheusRuleSpec(
                    name=f"{slug}-pod-restarts",
                    expr=f'increase({restart_metric}[10m]) > 0',
                    duration="0m",
                    severity="warning",
                    labels={"team": application.owner_team},
                    annotations={"summary": f"{application.name} pod restarted", "description": "Container or pod restart detected."},
                )
            )

        metric_prefix = _metric_prefix(application.name)
        recording_rules = [
            RecordingRuleSpec(name=f"{metric_prefix}:availability:ratio", expr=f'avg_over_time(up{{job="{slug}"}}[5m])', labels={"application": application.name}),
            RecordingRuleSpec(name=f"{metric_prefix}:request_rate:sum", expr=f'sum(rate(http_requests_total{{job="{slug}"}}[5m]))', labels={"application": application.name}),
            RecordingRuleSpec(name=f"{metric_prefix}:error_rate:sum", expr=f'sum(rate(http_requests_total{{job="{slug}",status=~"5.."}}[5m]))', labels={"application": application.name}),
        ]

        governance_issues: list[str] = []
        if not application.owner_team:
            governance_issues.append("team ownership missing")
        if not application.namespace:
            governance_issues.append("namespace missing")
        if len({rule.name for rule in alert_rules}) != len(alert_rules):
            governance_issues.append("duplicate alert rule names detected")
        governance = {
            "coverage_gaps": [name for name, metric in (("cpu", cpu_metric), ("memory", mem_metric)) if metric == "up"],
            "decision": "approved" if not governance_issues else "requires_approval",
            "issues": governance_issues,
            "naming_convention_ok": all(rule.name.startswith(slug) for rule in alert_rules),
            "duplicate_jobs": False,
            "security_labels": bool(application.labels.get("security") or application.labels.get("compliance")),
        }

        return RulesGeneratedResult(
            application_id=application.id,
            tenant_id=application.tenant_id,
            scrape_config=scrape_config,
            alert_rules=alert_rules,
            recording_rules=recording_rules,
            governance=governance,
        )


def render_prometheus_rule_groups(group_name: str, alert_rules: list[PrometheusRuleSpec], recording_rules: list[RecordingRuleSpec]) -> tuple[str, str]:
    def _indent(lines: list[str], depth: int = 0) -> str:
        prefix = "  " * depth
        return "\n".join(f"{prefix}{line}" for line in lines)

    alert_lines = ["groups:", f"- name: {group_name}-alerts", "  rules:"]
    for rule in alert_rules:
        alert_lines.extend([
            f"  - alert: {rule.name}",
            f"    expr: {rule.expr}",
            f"    for: {rule.duration}",
            "    labels:",
            _indent([f"{key}: {value}" for key, value in {**rule.labels, 'severity': rule.severity}.items()], 3),
            "    annotations:",
            _indent([f"{key}: {json.dumps(value)}" for key, value in rule.annotations.items()], 3),
        ])

    recording_lines = ["groups:", f"- name: {group_name}-recording", "  rules:"]
    for rule in recording_rules:
        recording_lines.extend([
            f"  - record: {rule.name}",
            f"    expr: {rule.expr}",
            "    labels:",
            _indent([f"{key}: {value}" for key, value in rule.labels.items()], 3),
        ])
    return "\n".join(alert_lines) + "\n", "\n".join(recording_lines) + "\n"


def write_prometheus_artifacts(application: ApplicationRegistration, rules: RulesGeneratedResult) -> tuple[dict[str, str], dict[str, str]]:
    root = onboarding_root()
    rules_dir = root / "prometheus_rules"
    targets_dir = root / "prometheus_targets"
    rules_dir.mkdir(parents=True, exist_ok=True)
    targets_dir.mkdir(parents=True, exist_ok=True)
    slug = _slug(application.name)
    alert_yaml, recording_yaml = render_prometheus_rule_groups(slug, rules.alert_rules, rules.recording_rules)
    target_payload = [
        {
            "targets": rules.scrape_config.targets,
            "labels": {
                "job": rules.scrape_config.job_name,
                "application": application.name,
                "tenant": application.tenant_id,
                "environment": application.environment,
                "namespace": application.namespace,
                "__metrics_path__": rules.scrape_config.metrics_path,
                "__scheme__": rules.scrape_config.scheme,
            },
        }
    ]
    alert_file = rules_dir / f"{slug}-alerts.yml"
    recording_file = rules_dir / f"{slug}-recording.yml"
    target_file = targets_dir / f"{slug}.json"
    alert_file.write_text(alert_yaml, encoding="utf-8")
    recording_file.write_text(recording_yaml, encoding="utf-8")
    target_file.write_text(json.dumps(target_payload, indent=2), encoding="utf-8")
    return (
        {
            "alert_rules": str(alert_file),
            "recording_rules": str(recording_file),
            "scrape_config": str(target_file),
        },
        {
            "alert_rules": alert_yaml,
            "recording_rules": recording_yaml,
            "scrape_config": json.dumps(target_payload, indent=2),
        },
    )


async def reload_prometheus(prometheus_url: str) -> dict[str, Any]:
    normalized = str(prometheus_url or "").strip().rstrip("/")
    response_payload: dict[str, Any] = {"reload_ok": False, "status_code": None, "message": "prometheus url not configured"}
    if not normalized:
        return response_payload
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post(f"{normalized}/-/reload")
            response_payload.update({"reload_ok": response.status_code < 400, "status_code": response.status_code, "message": f"reload returned HTTP {response.status_code}"})
        except Exception as exc:
            response_payload.update({"message": f"reload request failed: {exc}"})
    return response_payload


async def validate_prometheus_application(prometheus_url: str, application: ApplicationRegistration) -> MonitoringValidationResult:
    normalized = str(prometheus_url or "").strip().rstrip("/")
    slug = _slug(application.name)
    target_up = False
    alerts_loaded = False
    recording_rules_loaded = False
    service_discovery_ok = False
    details: dict[str, Any] = {"attempts": 0}
    async with httpx.AsyncClient(timeout=10.0) as client:
        if normalized:
            for attempt in range(1, 7):
                details["attempts"] = attempt
                try:
                    targets_response = await client.get(f"{normalized}/api/v1/targets")
                    targets_payload = targets_response.json() if targets_response.headers.get("content-type", "").startswith("application/json") else {}
                    active_targets = ((targets_payload.get("data") or {}).get("activeTargets") or []) if isinstance(targets_payload, dict) else []
                    for target in active_targets:
                        labels = target.get("labels") or {}
                        if str(labels.get("job") or "") == slug:
                            service_discovery_ok = True
                            target_up = str(target.get("health") or "").lower() == "up"
                            break
                    details["targets_checked"] = len(active_targets)
                except Exception as exc:
                    details["targets_error"] = str(exc)
                try:
                    rules_response = await client.get(f"{normalized}/api/v1/rules")
                    rules_payload = rules_response.json() if rules_response.headers.get("content-type", "").startswith("application/json") else {}
                    groups = ((rules_payload.get("data") or {}).get("groups") or []) if isinstance(rules_payload, dict) else []
                    for group in groups:
                        name = str(group.get("name") or "")
                        if name == f"{slug}-alerts":
                            alerts_loaded = True
                        if name == f"{slug}-recording":
                            recording_rules_loaded = True
                    details["rule_groups_checked"] = len(groups)
                except Exception as exc:
                    details["rules_error"] = str(exc)

                if service_discovery_ok and target_up and alerts_loaded and recording_rules_loaded:
                    break
                if attempt < 6:
                    await asyncio.sleep(1)
    return MonitoringValidationResult(
        application_id=application.id,
        tenant_id=application.tenant_id,
        target_up=target_up,
        metrics_available=target_up,
        alerts_loaded=alerts_loaded,
        recording_rules_loaded=recording_rules_loaded,
        service_discovery_ok=service_discovery_ok,
        details=details,
    )


def build_dashboard(application: ApplicationRegistration, validation: MonitoringValidationResult) -> GrafanaDashboardResult:
    slug = _slug(application.name)
    dashboard_uid = f"{slug}-{str(uuid4())[:8]}"
    panels = [
        {"title": "CPU", "type": "timeseries", "expr": f'rate(process_cpu_seconds_total{{job="{slug}"}}[5m])'},
        {"title": "Memory", "type": "timeseries", "expr": f'process_resident_memory_bytes{{job="{slug}"}}'},
        {"title": "Availability", "type": "stat", "expr": f'avg_over_time(up{{job="{slug}"}}[5m])'},
        {"title": "Error Rate", "type": "timeseries", "expr": f'sum(rate(http_requests_total{{job="{slug}",status=~"5.."}}[5m]))'},
        {"title": "Latency", "type": "timeseries", "expr": f'histogram_quantile(0.95, sum(rate(http_server_requests_seconds_bucket{{job="{slug}"}}[5m])) by (le))'},
        {"title": "Restarts", "type": "timeseries", "expr": f'increase(kube_pod_container_status_restarts_total{{namespace="{application.namespace}"}}[10m])'},
    ]
    dashboard = {
        "uid": dashboard_uid,
        "title": f"KaiOps - {application.name}",
        "tags": [application.environment, application.namespace, application.technology],
        "templating": {"list": []},
        "panels": panels,
        "annotations": {"list": []},
        "metadata": validation.model_dump(mode="json"),
    }
    return GrafanaDashboardResult(
        application_id=application.id,
        tenant_id=application.tenant_id,
        dashboard_uid=dashboard_uid,
        title=f"KaiOps - {application.name}",
        url=f"/grafana/d/{dashboard_uid}",
        dashboard=dashboard,
    )
