/** Explicit test markers and the dedicated fault targets configured locally. */
export function isSyntheticSignal(row: Record<string, any>): boolean {
  const labels = row.labels || row.source_alert?.labels || row.context?.alert?.labels || {};
  const mode = String(labels.event_mode || labels.test_mode || row.event_mode || "").toLowerCase();
  const marker = String(labels.synthetic ?? row.synthetic ?? "").toLowerCase();
  const service = String(row.service || labels.service || labels.job || "").toLowerCase();
  const name = String(row.title || row.name || labels.alertname || "");
  return ["synthetic", "test", "validation", "simulation"].includes(mode)
    || ["true", "1", "yes"].includes(marker)
    || String(labels.event_authenticity || row.event_authenticity || "").toLowerCase() === "synthetic"
    || /^ServiceDown-E2E-\d{14}$/.test(name)
    || ["kaiops-fault-lab", "kaiops-fault-lab-service", "httpbin-failure-lab"].includes(service);
}

/** Demo outages are observed signals, but do not belong in production counts. */
export function isDemoSignal(row: Record<string, any>): boolean {
  const labels = row.labels || row.source_alert?.labels || row.context?.alert?.labels || {};
  const source = String(row.source || labels.source || labels.source_system || "").toLowerCase();
  const job = String(labels.job || "").toLowerCase();
  const name = String(row.name || row.title || labels.alertname || "");
  return String(labels.monitoring_scope || row.monitoring_scope || "").toLowerCase() === "demo"
    || ["robot-shop", "online-boutique"].includes(source)
    || /^(robot-shop-|online-boutique-)/.test(job)
    || ["telemetry-application", "telemetry-monitoring", "telemetry-jaeger"].includes(job)
    || labels.instance === "http://ob-frontend:8080/_healthz"
    || ["RobotShopServiceDown", "RobotShopMySQLTooManyConnections", "RobotShopRabbitMQQueueBacklog", "RobotShopRedisDown", "RobotShopMongoDown", "OnlineBoutiqueFrontendDown", "OnlineBoutiqueFrontendSlow", "OnlineBoutiquePaymentServiceDown", "TelemetryApplicationUnavailable", "TelemetryMonitoringUnavailable", "TelemetryJaegerUnavailable", "TelemetryCollectorUnavailable", "TelemetryApplicationSignalsMissing"].includes(name);
}

export const isNonProductionSignal = (row: Record<string, any>): boolean => isSyntheticSignal(row) || isDemoSignal(row);
