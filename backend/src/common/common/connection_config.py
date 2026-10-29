from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from common.config import Settings

logger = logging.getLogger(__name__)

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")
_DEFAULT_CONFIG_PATH = Path("backend/config/kaiops-connections.json")


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "pyproject.toml").exists() and (parent / "backend").exists():
            return parent
    return current.parents[4]


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            default = match.group(2) if match.group(2) is not None else ""
            return os.getenv(name, default)

        return _ENV_PATTERN.sub(replace, value)
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _expand_env(item) for key, item in value.items()}
    return value


def _read_json(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(parsed, dict):
            return parsed
        logger.warning("Connection config at %s is not a JSON object; using defaults", path)
    except Exception as exc:
        logger.warning("Failed to read connection config from %s: %s", path, exc)
    return {}


def _default_connection_config() -> dict[str, Any]:
    return {
        "version": "kaiops-connections-v1",
        "environment": "local",
        "cloud_provider": "local",
        "deployment_profile": "onprem",
        "connection_architecture": {
            "mode": "externalized-shared-state",
            "principles": [],
        },
        "platform": {},
        "external_applications": {
            "default_connector": "generic-api",
            "connectors": {
                "generic-api": {
                    "connector_id": "generic-api",
                    "system": "generic",
                    "type": "api",
                    "endpoint": "https://api.internal",
                    "auth_method": "service-account-token",
                    "secret_ref": "vault://kaiops/local/default-token",
                    "timeout_seconds": 10,
                    "retry": {"max_attempts": 2, "backoff_seconds": 2},
                    "health_check": {"method": "GET", "path": "/health"},
                    "allowed_operations": [
                        "read_status",
                        "read_metrics",
                        "api_execution",
                        "script_execution",
                        "restart_service",
                        "scale_service",
                        "rollback_deployment",
                        "verify_slo",
                        "verify_service_health",
                        "verify_onboarding_flow",
                    ],
                }
            },
        },
    }


def _normalize_connector(key: str, connector: dict[str, Any]) -> dict[str, Any]:
    connector_id = str(connector.get("connector_id") or key).strip() or key
    system = str(connector.get("system") or key).strip() or key
    connector_type = str(connector.get("type") or "api").strip().lower() or "api"
    allowed_operations = connector.get("allowed_operations")
    if not isinstance(allowed_operations, list):
        allowed_operations = ["read_status"]
    cleaned_operations = [str(item).strip() for item in allowed_operations if str(item).strip()]
    if not cleaned_operations:
        cleaned_operations = ["read_status"]

    retry = connector.get("retry") if isinstance(connector.get("retry"), dict) else {}
    health_check = connector.get("health_check") if isinstance(connector.get("health_check"), dict) else {}

    normalized = {
        **connector,
        "connector_id": connector_id,
        "system": system,
        "type": connector_type,
        "auth_method": str(connector.get("auth_method") or "service-account-token").strip(),
        "secret_ref": str(connector.get("secret_ref") or "").strip(),
        "timeout_seconds": int(connector.get("timeout_seconds") or 10),
        "retry": {
            "max_attempts": int(retry.get("max_attempts") or 2),
            "backoff_seconds": float(retry.get("backoff_seconds") or 2),
        },
        "health_check": health_check,
        "allowed_operations": cleaned_operations,
    }
    if connector_type == "api" and not str(normalized.get("endpoint") or "").strip():
        normalized["endpoint"] = "https://api.internal"
    return normalized


def normalize_connection_config(raw: dict[str, Any]) -> dict[str, Any]:
    config = _default_connection_config()
    expanded = _expand_env(raw)
    if not isinstance(expanded, dict):
        return config

    for key in ("version", "environment", "cloud_provider", "deployment_profile"):
        if str(expanded.get(key) or "").strip():
            config[key] = str(expanded[key]).strip()

    if isinstance(expanded.get("connection_architecture"), dict):
        config["connection_architecture"] = {
            **config["connection_architecture"],
            **expanded["connection_architecture"],
        }

    if isinstance(expanded.get("platform"), dict):
        config["platform"] = expanded["platform"]

    external = expanded.get("external_applications")
    if isinstance(external, dict):
        default_connector = str(external.get("default_connector") or "generic-api").strip() or "generic-api"
        raw_connectors = external.get("connectors") if isinstance(external.get("connectors"), dict) else {}
        connectors = {
            str(key).strip().lower(): _normalize_connector(str(key).strip().lower(), value)
            for key, value in raw_connectors.items()
            if str(key).strip() and isinstance(value, dict)
        }
        if default_connector not in connectors and "generic-api" in connectors:
            default_connector = "generic-api"
        if connectors:
            config["external_applications"] = {
                "default_connector": default_connector,
                "connectors": connectors,
            }

    return config


def load_connection_config(settings: Settings | None = None) -> dict[str, Any]:
    resolved_settings = settings or Settings()
    configured_path = str(getattr(resolved_settings, "connection_config_path", "") or "").strip()
    config_path = Path(configured_path) if configured_path else _repo_root() / _DEFAULT_CONFIG_PATH
    if not config_path.is_absolute():
        config_path = _repo_root() / config_path
    return normalize_connection_config(_read_json(config_path))


def connector_catalog_from_connection_config(config: dict[str, Any]) -> dict[str, Any]:
    external = config.get("external_applications") if isinstance(config.get("external_applications"), dict) else {}
    connectors = external.get("connectors") if isinstance(external.get("connectors"), dict) else {}
    default_connector = str(external.get("default_connector") or "generic-api").strip() or "generic-api"
    return {
        "version": str(config.get("version") or "kaiops-connections-v1"),
        "default_connector": default_connector,
        "connectors": connectors,
    }
