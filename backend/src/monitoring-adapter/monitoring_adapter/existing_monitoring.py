from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
from uuid import uuid4


SUPPORTED_MONITORING_PROVIDERS = [
    "prometheus",
    "grafana",
    "datadog",
    "new_relic",
    "dynatrace",
    "azure_monitor",
    "splunk",
    "nagios",
    "zabbix",
    "elastic",
    "jira",
    "raygun",
    "uptime_robot",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_provider_name(value: str) -> str:
    token = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "prometheus_alertmanager": "prometheus",
        "grafana_alerting": "grafana",
        "azure": "azure_monitor",
        "azuremonitor": "azure_monitor",
        "newrelic": "new_relic",
        "uptimerobot": "uptime_robot",
        "elastic_observability": "elastic",
    }
    normalized = aliases.get(token, token)
    if normalized not in SUPPORTED_MONITORING_PROVIDERS:
        raise ValueError(f"unsupported provider: {value}")
    return normalized


def build_webhook_path(provider: str) -> str:
    return f"/api/v1/alerts/{normalize_provider_name(provider)}"


def _extract_string(source: dict[str, Any], keys: list[str], default: str = "") -> str:
    for key in keys:
        value = source.get(key)
        if value is None:
            continue
        token = str(value).strip()
        if token:
            return token
    return default


def _extract_dict(source: dict[str, Any], key: str) -> dict[str, Any]:
    value = source.get(key)
    if isinstance(value, dict):
        return value
    return {}


class IMonitoringProvider(Protocol):
    provider: str

    def connect(self, config: dict[str, Any], credentials: dict[str, Any]) -> dict[str, Any]: ...

    def validate(self, config: dict[str, Any], credentials: dict[str, Any]) -> dict[str, Any]: ...

    def register_webhook(self, config: dict[str, Any], webhook_url: str) -> dict[str, Any]: ...

    def discover_alerts(self, config: dict[str, Any], credentials: dict[str, Any]) -> dict[str, Any]: ...

    def normalize_alert(self, payload: dict[str, Any], mapping: dict[str, Any] | None = None) -> dict[str, Any]: ...

    def disconnect(self, config: dict[str, Any]) -> dict[str, Any]: ...


@dataclass
class BaseMonitoringProvider:
    provider: str

    def connect(self, config: dict[str, Any], credentials: dict[str, Any]) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "connected": True,
            "message": "connection profile accepted",
            "timestamp": utc_now_iso(),
            "endpoint": str(config.get("server_url") or config.get("endpoint_url") or ""),
        }

    def validate(self, config: dict[str, Any], credentials: dict[str, Any]) -> dict[str, Any]:
        endpoint = str(config.get("server_url") or config.get("endpoint_url") or "").strip()
        auth_present = bool(credentials)
        return {
            "provider": self.provider,
            "authentication": auth_present,
            "api": bool(endpoint),
            "permissions": auth_present,
            "alertmanager": bool(config.get("alertmanager_url") or endpoint),
            "connectivity": bool(endpoint) or self.provider in {"datadog", "new_relic"},
            "valid": auth_present or bool(endpoint),
            "timestamp": utc_now_iso(),
        }

    def register_webhook(self, config: dict[str, Any], webhook_url: str) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "registered": True,
            "webhook_url": webhook_url,
            "instructions": [
                f"Configure {self.provider} notification destination to POST {webhook_url}",
                "Enable JSON payload delivery",
                "Set retry policy to at least 3 attempts",
            ],
            "timestamp": utc_now_iso(),
        }

    def discover_alerts(self, config: dict[str, Any], credentials: dict[str, Any]) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "alert_policies": ["default-policy"],
            "notification_channels": ["webhook"],
            "alert_rules": ["high_cpu", "service_down"],
            "receivers": ["kaiops-webhook"],
            "labels": ["severity", "environment", "service", "team"],
            "severity_levels": ["critical", "high", "warning", "info"],
            "environments": ["prod", "staging", "dev"],
            "teams": ["platform-ops", "sre"],
            "timestamp": utc_now_iso(),
        }

    def normalize_alert(self, payload: dict[str, Any], mapping: dict[str, Any] | None = None) -> dict[str, Any]:
        labels = _extract_dict(payload, "labels")
        annotations = _extract_dict(payload, "annotations")
        alert_name = _extract_string(payload, ["alertname", "name", "title"], default="provider-alert")
        resource = _extract_string(payload, ["instance", "resource", "host", "entity"], default="unknown")
        severity = _extract_string(payload, ["severity", "priority", "level"], default="warning").lower()
        application = _extract_string(payload, ["application", "service", "app", "project"], default="unknown-app")
        environment = _extract_string(payload, ["environment", "env"], default="prod")
        if isinstance(mapping, dict):
            application = str(mapping.get("application") or application)
            environment = str(mapping.get("environment") or environment)
        return {
            "provider": self.provider,
            "application": application,
            "environment": environment,
            "severity": severity,
            "alertName": alert_name,
            "resource": resource,
            "labels": labels,
            "annotations": annotations,
            "timestamp": _extract_string(payload, ["timestamp", "startsAt", "created_at"], default=utc_now_iso()),
            "rawPayload": payload,
        }

    def disconnect(self, config: dict[str, Any]) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "disconnected": True,
            "timestamp": utc_now_iso(),
        }


@dataclass
class PrometheusProvider(BaseMonitoringProvider):
    provider: str = "prometheus"

    def normalize_alert(self, payload: dict[str, Any], mapping: dict[str, Any] | None = None) -> dict[str, Any]:
        labels = _extract_dict(payload, "labels")
        annotations = _extract_dict(payload, "annotations")
        alert_name = _extract_string(labels, ["alertname", "name"], default="prometheus-alert")
        return {
            "provider": self.provider,
            "application": _extract_string(labels, ["application", "service", "job"], default="unknown-app"),
            "environment": _extract_string(labels, ["environment", "env"], default="prod"),
            "severity": _extract_string(labels, ["severity"], default="warning").lower(),
            "alertName": alert_name,
            "resource": _extract_string(labels, ["instance", "pod", "host"], default="unknown"),
            "labels": labels,
            "annotations": annotations,
            "timestamp": _extract_string(payload, ["startsAt", "timestamp"], default=utc_now_iso()),
            "rawPayload": payload,
        }


@dataclass
class DatadogProvider(BaseMonitoringProvider):
    provider: str = "datadog"

    def normalize_alert(self, payload: dict[str, Any], mapping: dict[str, Any] | None = None) -> dict[str, Any]:
        tags = payload.get("tags") if isinstance(payload.get("tags"), list) else []
        label_map: dict[str, Any] = {}
        for item in tags:
            token = str(item or "").strip()
            if not token:
                continue
            if ":" in token:
                key, value = token.split(":", 1)
                label_map[key.strip()] = value.strip()
        return {
            "provider": self.provider,
            "application": str(payload.get("app") or label_map.get("service") or "unknown-app"),
            "environment": str(payload.get("env") or label_map.get("env") or "prod"),
            "severity": str(payload.get("severity") or payload.get("priority") or "warning").lower(),
            "alertName": str(payload.get("title") or payload.get("alert_type") or "datadog-alert"),
            "resource": str(payload.get("resource") or payload.get("host") or "unknown"),
            "labels": label_map,
            "annotations": {
                "text": str(payload.get("text") or ""),
                "url": str(payload.get("alert_transition_url") or ""),
            },
            "timestamp": str(payload.get("date_happened") or utc_now_iso()),
            "rawPayload": payload,
        }


@dataclass
class NewRelicProvider(BaseMonitoringProvider):
    provider: str = "new_relic"

    def normalize_alert(self, payload: dict[str, Any], mapping: dict[str, Any] | None = None) -> dict[str, Any]:
        labels = _extract_dict(payload, "labels")
        return {
            "provider": self.provider,
            "application": _extract_string(payload, ["application_name", "policy_name"], default="unknown-app"),
            "environment": _extract_string(payload, ["environment", "env"], default="prod"),
            "severity": _extract_string(payload, ["priority", "severity"], default="warning").lower(),
            "alertName": _extract_string(payload, ["condition_name", "title"], default="newrelic-alert"),
            "resource": _extract_string(payload, ["target_name", "entity_name"], default="unknown"),
            "labels": labels,
            "annotations": {
                "description": _extract_string(payload, ["details", "description"]),
            },
            "timestamp": _extract_string(payload, ["timestamp", "opened_at"], default=utc_now_iso()),
            "rawPayload": payload,
        }


@dataclass
class UptimeRobotProvider(BaseMonitoringProvider):
    provider: str = "uptime_robot"

    def normalize_alert(self, payload: dict[str, Any], mapping: dict[str, Any] | None = None) -> dict[str, Any]:
        status = _extract_string(payload, ["alertTypeFriendlyName", "status", "alertType"], default="unknown")
        monitor = _extract_string(payload, ["monitorFriendlyName", "monitor", "name"], default="unknown-monitor")
        alert_type = str(payload.get("alertType") or "").strip()
        return {
            "provider": self.provider,
            "application": _extract_string(payload, ["application", "project"], default="UptimeRobot"),
            "environment": _extract_string(payload, ["environment", "env"], default="unknown"),
            "severity": "critical" if alert_type == "1" or status.lower() == "down" else "info",
            "alertName": f"{monitor} {status}".strip(),
            "resource": _extract_string(payload, ["monitorURL", "url", "monitorID"], default=monitor),
            "labels": {
                "monitor_id": str(payload.get("monitorID") or ""),
                "monitor_type": str(payload.get("monitorType") or ""),
                "monitor_group": str(payload.get("monitorGroup") or ""),
                "http_status_code": str(payload.get("httpStatusCode") or ""),
                "vendor_event_status": status,
            },
            "annotations": {
                "summary": str(payload.get("alertDetails") or f"UptimeRobot reported {status} for {monitor}"),
                "dashboard_url": str(payload.get("dashboardUrl") or ""),
                "monitor_url": str(payload.get("monitorURL") or ""),
                "incident_start_time": str(payload.get("incidentStartTime") or ""),
                "incident_end_time": str(payload.get("incidentEndTime") or ""),
            },
            "timestamp": _extract_string(payload, ["alertDateTime", "incidentStartTime", "timestamp"], default=utc_now_iso()),
            "rawPayload": payload,
        }


@dataclass
class RaygunProvider(BaseMonitoringProvider):
    provider: str = "raygun"

    def normalize_alert(self, payload: dict[str, Any], mapping: dict[str, Any] | None = None) -> dict[str, Any]:
        error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
        application = payload.get("application") if isinstance(payload.get("application"), dict) else {}
        instance = error.get("instance") if isinstance(error.get("instance"), dict) else {}
        tags = instance.get("tags") if isinstance(instance.get("tags"), list) else []
        environment = next((str(tag).split(":", 1)[1] for tag in tags if str(tag).lower().startswith("env:") and ":" in str(tag)), "unknown")
        event_type = _extract_string(payload, ["eventType", "event"], default="RaygunEvent")
        message = _extract_string(error, ["message", "description"], default=event_type)
        return {
            "provider": self.provider,
            "application": _extract_string(application, ["name"], default="Raygun"),
            "environment": environment,
            "severity": "high" if str(payload.get("event") or "").lower() == "error_notification" else "info",
            "alertName": message,
            "resource": _extract_string(error, ["url"], default=_extract_string(application, ["url"], default="unknown")),
            "labels": {"event_type": event_type, "vendor_event": str(payload.get("event") or ""), "tags": tags},
            "annotations": {
                "summary": message,
                "error_url": str(error.get("url") or ""),
                "application_url": str(application.get("url") or ""),
                "users_affected": str(error.get("usersAffected") or ""),
                "total_occurrences": str(error.get("totalOccurrences") or ""),
            },
            "timestamp": _extract_string(error, ["lastOccurredOn", "firstOccurredOn", "activityDate"], default=utc_now_iso()),
            "rawPayload": payload,
        }


def provider_registry() -> dict[str, IMonitoringProvider]:
    generic = {
        "grafana": BaseMonitoringProvider("grafana"),
        "dynatrace": BaseMonitoringProvider("dynatrace"),
        "azure_monitor": BaseMonitoringProvider("azure_monitor"),
        "splunk": BaseMonitoringProvider("splunk"),
        "nagios": BaseMonitoringProvider("nagios"),
        "zabbix": BaseMonitoringProvider("zabbix"),
        "elastic": BaseMonitoringProvider("elastic"),
        "jira": BaseMonitoringProvider("jira"),
    }
    return {
        "prometheus": PrometheusProvider(),
        "datadog": DatadogProvider(),
        "new_relic": NewRelicProvider(),
        "uptime_robot": UptimeRobotProvider(),
        "raygun": RaygunProvider(),
        **generic,
    }


def get_provider_adapter(provider: str) -> IMonitoringProvider:
    normalized = normalize_provider_name(provider)
    registry = provider_registry()
    return registry[normalized]


def mask_secrets(payload: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in (payload or {}).items():
        token = str(value or "")
        if not token:
            redacted[key] = ""
            continue
        redacted[key] = f"***{token[-4:]}"
    return redacted


def hash_secrets(payload: dict[str, Any]) -> dict[str, Any]:
    hashed: dict[str, Any] = {}
    for key, value in (payload or {}).items():
        token = str(value or "")
        hashed[key] = hashlib.sha256(token.encode("utf-8")).hexdigest() if token else ""
    return hashed


def verify_webhook_token(token: str | None, token_hash: str | None) -> bool:
    if not token or not token_hash:
        return False
    candidate_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate_hash, str(token_hash))


def verify_hmac_signature(secret: str, body: str, signature: str | None) -> bool:
    if not secret:
        return True
    if not signature:
        return False
    digest = hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    candidate = str(signature or "").strip().lower().replace("sha256=", "")
    return hmac.compare_digest(digest, candidate)


def default_field_mappings() -> list[dict[str, Any]]:
    return [
        {"provider_field": "alertname", "kaiops_field": "alertName", "required": True},
        {"provider_field": "instance", "kaiops_field": "resource", "required": False},
        {"provider_field": "severity", "kaiops_field": "severity", "required": True},
        {"provider_field": "labels", "kaiops_field": "labels", "required": False},
        {"provider_field": "annotations", "kaiops_field": "annotations", "required": False},
        {"provider_field": "status", "kaiops_field": "metadata.status", "required": False},
        {"provider_field": "service", "kaiops_field": "application", "required": False},
        {"provider_field": "environment", "kaiops_field": "environment", "required": False},
    ]


def apply_field_mapping(normalized: dict[str, Any], mappings: list[dict[str, Any]]) -> dict[str, Any]:
    if not mappings:
        return normalized
    payload = dict(normalized)
    labels = dict(payload.get("labels") or {})
    metadata = dict(payload.get("metadata") or {})
    raw = payload.get("rawPayload") if isinstance(payload.get("rawPayload"), dict) else {}
    for mapping in mappings:
        provider_field = str(mapping.get("provider_field") or "").strip()
        kaiops_field = str(mapping.get("kaiops_field") or "").strip()
        if not provider_field or not kaiops_field:
            continue
        value = raw.get(provider_field)
        if value is None and provider_field in labels:
            value = labels.get(provider_field)
        if value is None:
            continue
        if kaiops_field.startswith("metadata."):
            metadata[kaiops_field.split(".", 1)[1]] = value
        elif kaiops_field.startswith("labels."):
            labels[kaiops_field.split(".", 1)[1]] = value
        else:
            payload[kaiops_field] = value
    payload["labels"] = labels
    if metadata:
        payload["metadata"] = metadata
    return payload


def generate_integration_id() -> str:
    return str(uuid4())
