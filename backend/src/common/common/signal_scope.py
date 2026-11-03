"""Identify the demo stacks explicitly shipped by this repository, not arbitrary names."""
import json
import os

_DEFAULT_DEMO_ALERT_TARGETS = [
    "robot-shop/prod/rs-ratings/RobotShopServiceDown",
    "robot-shop/demo/rs-ratings/RobotShopServiceDown",
    "robot-shop/demo/rs-ratings/RobotShopRatingsUnavailable",
    "robot-shop/prod/rs-ratings/RobotShopRatingsUnavailable",
    "robot-shop/prod/rs-payment/RobotShopPaymentServiceDegradation",
    "robot-shop/demo/rs-payment/RobotShopPaymentServiceDegradation",
    "robot-shop/demo/rs-catalogue/RobotShopServiceDown",
    "robot-shop/prod/rs-catalogue/RobotShopServiceDown",
]


def demo_analysis_enabled(row: dict) -> bool:
    """Allow an operator-selected demo signal without admitting every demo workload."""
    if os.getenv("DEMO_ALERT_INGESTION_ENABLED", "false").lower() == "true":
        return True
    labels = row.get("labels") or {}
    parts = [labels.get("project") or row.get("project"),
             row.get("environment") or labels.get("environment"),
             row.get("service") or labels.get("service"),
             row.get("name") or labels.get("alertname")]
    if any(not isinstance(part, str) or not part.strip() or "/" in part or "*" in part for part in parts):
        return False
    raw_targets = os.getenv("DEMO_ALERT_INGESTION_TARGETS", "[]")
    try:
        targets = json.loads(raw_targets)
    except (ValueError, TypeError):
        return False
    if isinstance(targets, list) and (
        not targets or "telemetry/prod/otel-collector/TelemetryCollectorUnavailable" in targets
    ):
        targets = [*targets, *_DEFAULT_DEMO_ALERT_TARGETS]
    return isinstance(targets, list) and "/".join(parts) in targets


def is_demo_signal(row: dict) -> bool:
    labels = row.get("labels") or (row.get("source_alert") or {}).get("labels") or {}
    scope = str(labels.get("monitoring_scope") or row.get("monitoring_scope") or "").lower()
    source = str(row.get("source") or labels.get("source") or labels.get("source_system") or "").lower()
    job = str(labels.get("job") or "").lower()
    name = str(row.get("name") or row.get("title") or labels.get("alertname") or "")
    return (scope == "demo" or source in {"robot-shop", "online-boutique"}
            or job.startswith(("robot-shop-", "online-boutique-"))
            or job in {"telemetry-application", "telemetry-monitoring", "telemetry-jaeger"}
            or str(labels.get("instance") or "") == "http://ob-frontend:8080/_healthz"
            or name in {'RobotShopServiceDown', 'RobotShopMySQLTooManyConnections', 'RobotShopRabbitMQQueueBacklog', 'RobotShopRedisDown', 'RobotShopMongoDown', 'OnlineBoutiqueFrontendDown', 'OnlineBoutiqueFrontendSlow', 'OnlineBoutiquePaymentServiceDown', "TelemetryApplicationUnavailable", "TelemetryMonitoringUnavailable", "TelemetryJaegerUnavailable",
                        "TelemetryCollectorUnavailable", "TelemetryApplicationSignalsMissing"})
