import { describe, expect, it } from "vitest";
import { capLatestAlertsPerSource, dedupeAndConsolidateAlertRows, ensureMinimumAlertsBySource, filterAlertsForMonitor, filterRowsForMonitor, shouldRetainAlertSelection, resolveCanonicalAlertForRow } from "./appHelpers.jsx";
import { uniqueMonitorApplications } from "./app/legacyShellHelpers.js";
import { availableApplication } from "./domain/applicationSelection";
import { hasPendingDecision } from "./domain/pendingDecision";
import { belongsToInboxView } from "./routes/incidents/IncidentsRoute";

describe("alert stream and inbox identity", () => {
  it("does not merge different Alertmanager fingerprints sharing name, service, and time", () => {
    const rows = dedupeAndConsolidateAlertRows([{
      id: "mount-a", name: "DiskSpaceLow", service: "node-exporter", severity: "critical",
      created_at: "2026-09-02T02:36:24Z", labels: { alert_fingerprint: "fingerprint-a", mountpoint: "/usr/lib/wsl/drivers" },
    }, {
      id: "mount-b", name: "DiskSpaceLow", service: "node-exporter", severity: "critical",
      created_at: "2026-09-02T02:36:24Z", labels: { alert_fingerprint: "fingerprint-b", mountpoint: "/run/desktop/mnt/host/c" },
    }]);

    expect(rows).toHaveLength(2);
  });

  it("keeps canonical identity and incident linkage when a newer landing occurrence wins", () => {
    const alertId = "bbe1b2c1-2542-488c-81d3-f57b38a25296";
    const incidentId = "2a3b34d2-b5e1-453f-924a-04ebe115a518";
    const rows = dedupeAndConsolidateAlertRows([{
      id: alertId, alert_id: alertId, incident_id: incidentId, ticket_id: "KAN-1246",
      name: "RobotShopServiceDown", service: "robot-shop-redis", created_at: "2026-08-12T09:54:59.000Z",
      labels: { alert_fingerprint: "8478690570ded4e4", alertname: "RobotShopServiceDown", service: "robot-shop-redis" },
      _stream_kind: "alerts_api",
    }, {
      id: "20260812T095500Z_robotshop.json", alert_id: "20260812T095500Z_robotshop.json",
      name: "RobotShopServiceDown", service: "robot-shop-redis", received_at: "2026-08-12T09:55:00.000Z",
      labels: { alert_fingerprint: "8478690570ded4e4", alertname: "RobotShopServiceDown", service: "robot-shop-redis" },
      _stream_kind: "landing_pad",
    }], { preferLatestState: true });

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ id: alertId, alert_id: alertId, incident_id: incidentId, ticket_id: "KAN-1246" });
    expect(rows[0].received_at).toBe("2026-08-12T09:55:00.000Z");

    const reverseOrder = dedupeAndConsolidateAlertRows([{
      id: "20260812T095500Z_robotshop.json", alert_id: "20260812T095500Z_robotshop.json",
      name: "RobotShopServiceDown", service: "robot-shop-redis", received_at: "2026-08-12T09:55:00.000Z",
      labels: { alert_fingerprint: "8478690570ded4e4", alertname: "RobotShopServiceDown", service: "robot-shop-redis" },
      _stream_kind: "landing_pad",
    }, {
      id: alertId, alert_id: alertId, incident_id: incidentId, ticket_id: "KAN-1246",
      name: "RobotShopServiceDown", service: "robot-shop-redis", created_at: "2026-08-12T09:54:59.000Z",
      labels: { alert_fingerprint: "8478690570ded4e4", alertname: "RobotShopServiceDown", service: "robot-shop-redis" },
      _stream_kind: "alerts_api",
    }], { preferLatestState: true });
    expect(reverseOrder[0]).toMatchObject({ id: alertId, alert_id: alertId, incident_id: incidentId, ticket_id: "KAN-1246" });
    expect(reverseOrder[0].received_at).toBe("2026-08-12T09:55:00.000Z");
  });

  it("keeps persisted E2E incidents out of production scope while retaining them in test scope", () => {
    const production = { title: "PolicyEngineUnavailable", service: "kaiops-orchestrator", environment: "prod" };
    const testRun = { title: "ServiceDown-E2E-20260826050115", service: "kaiops-discovery-mcp", environment: "review-20260826050115" };
    expect(filterRowsForMonitor([production, testRun], "real-usecases")).toEqual([production]);
    expect(filterRowsForMonitor([production, testRun], "test-usecases")).toEqual([testRun]);
  });

  it("retains built-in KaiMS and Telemetry workspaces even when applications API returns only payment-gateway", () => {
    const options = uniqueMonitorApplications(["payment-gateway"]);
    expect(options).toEqual(["All Applications", "KaiMS", "Telemetry", "payment-gateway"]);
    expect(availableApplication("All Applications", options)).toBe("All Applications");
    expect(availableApplication("KaiMS", options)).toBe("KaiMS");
    expect(availableApplication("Telemetry", options)).toBe("Telemetry");
  });

  it("includes canary-audit-service and unknown services in All Applications unscoped view while keeping KaiMS scoped", () => {
    const canary = {
      id: "57f188cc-4bcf-47cc-a57f-f77103f7bb1f",
      name: "CanaryAlertQueryRunbookVerification",
      service: "canary-audit-service",
      severity: "warning",
      environment: "verification",
      labels: { service: "canary-audit-service", severity: "high" },
    };
    const coreAlert = {
      id: "core-1",
      name: "DiskSpaceLow",
      service: "node-exporter",
      labels: { service: "node-exporter" },
    };
    const paymentAlert = {
      id: "pay-1",
      name: "PaymentLatencySpike",
      service: "payments",
      application: "payment-gateway",
      labels: { service: "payments", application: "payment-gateway" },
    };
    const rows = [canary, coreAlert, paymentAlert];

    // All Applications unscoped view includes all production rows (including canary-audit-service)
    expect(filterAlertsForMonitor(rows, "All Applications").map((r) => r.id)).toEqual(["57f188cc-4bcf-47cc-a57f-f77103f7bb1f", "core-1", "pay-1"]);

    // KaiMS-only view retains only KaiMS core services, excluding canary-audit-service
    expect(filterAlertsForMonitor(rows, "KaiMS").map((r) => r.id)).toEqual(["core-1"]);

    // Known application view retains only that specific application
    expect(filterAlertsForMonitor(rows, "payment-gateway").map((r) => r.id)).toEqual(["pay-1"]);
  });

  it("keeps real opentelemetry-demo and node-exporter alerts in KaiMS and Telemetry alerts in Telemetry", () => {
    const otelSiteAlert = {
      id: "otel-real",
      name: "ExternalApplicationUnavailable",
      service: "opentelemetry-demo",
      project_name: "KaiOps",
      environment: "prod",
      labels: { synthetic: "false", event_mode: "real", project_name: "KaiOps" },
    };
    const diskAlert = {
      id: "disk-low",
      name: "DiskSpaceLow",
      service: "node-exporter",
      environment: "prod",
      labels: { alertname: "DiskSpaceLow", service: "node-exporter" },
    };
    const telemetryAlert = {
      id: "telemetry-unavail",
      name: "TelemetryApplicationUnavailable",
      service: "frontend-proxy",
      application: "Telemetry",
      environment: "demo",
      labels: { alertname: "TelemetryApplicationUnavailable", application: "Telemetry", monitoring_scope: "demo" },
    };
    const syntheticHttpbin = {
      id: "httpbin-sim",
      name: "HTTPProbeSuccessRateLow",
      service: "httpbin-failure-lab",
      application: "httpbin-failure-lab",
      environment: "public-internet",
      labels: { synthetic: "true", event_mode: "simulation" },
    };

    const allRows = [otelSiteAlert, diskAlert, telemetryAlert, syntheticHttpbin];
    expect(filterAlertsForMonitor(allRows, "KaiMS").map((r) => r.id)).toEqual(["otel-real", "disk-low"]);
    expect(filterAlertsForMonitor(allRows, "Telemetry").map((r) => r.id)).toEqual(["telemetry-unavail"]);
  });


  it("scopes service-derived projects to that exact service in alerts and incidents", () => {
    const rabbit = { title: "RobotShopServiceDown", service: "robot-shop-rabbitmq", environment: "prod" };
    const redis = { title: "RobotShopServiceDown", service: "robot-shop-redis", environment: "prod" };
    expect(filterAlertsForMonitor([rabbit, redis], "robot-shop-rabbitmq")).toEqual([rabbit]);
    expect(filterRowsForMonitor([rabbit, redis], "robot-shop-rabbitmq")).toEqual([rabbit]);
  });

  it("does not backfill the raw landing occurrence after consolidation", () => {
    const canonical = {
      id: "bbe1b2c1-2542-488c-81d3-f57b38a25296", name: "RobotShopServiceDown", service: "robot-shop-redis",
      labels: { alert_fingerprint: "8478690570ded4e4" }, source_channel: "prometheus",
    };
    const landing = {
      file: "20260812T095500Z_robotshop.json", name: "RobotShopServiceDown", service: "robot-shop-redis",
      labels: { alert_fingerprint: "8478690570ded4e4" }, source_channel: "prometheus",
    };
    expect(ensureMinimumAlertsBySource([canonical], [canonical, landing], { prometheus: 2, telemetry: 0, email: 0, ticket: 0, log: 0 })).toEqual([canonical]);
  });
});

describe("capLatestAlertsPerSource", () => {
  it("keeps the newest alert type for mysql-exporter during a noisy Prometheus burst", () => {
    const burst = Array.from({ length: 40 }, (_, index) => ({
      id: `api-${index}`,
      source: "prometheus",
      service: "api-gateway",
      name: "GatewayRequestFailed",
      created_at: new Date(Date.UTC(2026, 7, 14, 12, 0, index)).toISOString(),
    }));
    const mysqlExporter = {
      id: "mysql-exporter-alert",
      source: "prometheus",
      service: "mysql-exporter",
      name: "MySQLExporterDown",
      created_at: "2026-08-14T11:00:00.000Z",
    };

    const result = capLatestAlertsPerSource([...burst, mysqlExporter], 30);

    expect(result).toHaveLength(30);
    expect(result.some((row) => row.id === "mysql-exporter-alert")).toBe(true);
  });
});

describe("shouldRetainAlertSelection", () => {
  it("retains the selection when a matching, error-free payload is already loaded", () => {
    // This is the KAN-1469 scenario: the operator opened the alert, its
    // processed-result payload loaded successfully, and a background refresh
    // of the summary list should not discard that selection even if the
    // alert momentarily falls out of the list's scope (e.g. closure moving it
    // from the open-alerts stream to the closed-incidents stream).
    const retained = shouldRetainAlertSelection({
      selectedAlertId: "f030bdcd-2f9c-43f9-9976-b3626b059a86",
      payload: { mode: "db-processed", incident: { id: "2a3b34d2-b5e1-453f-924a-04ebe115a518", ticket_id: "KAN-1469" } },
      error: "",
      alertId: "f030bdcd-2f9c-43f9-9976-b3626b059a86",
    });
    expect(retained).toBe(true);
  });

  it("does not retain the selection when no payload has loaded yet", () => {
    const retained = shouldRetainAlertSelection({
      selectedAlertId: "f030bdcd-2f9c-43f9-9976-b3626b059a86",
      payload: null,
      error: "",
      alertId: "f030bdcd-2f9c-43f9-9976-b3626b059a86",
    });
    expect(retained).toBe(false);
  });

  it("does not retain the selection when the loaded payload errored", () => {
    const retained = shouldRetainAlertSelection({
      selectedAlertId: "f030bdcd-2f9c-43f9-9976-b3626b059a86",
      payload: { mode: "db-processed" },
      error: "Not found",
      alertId: "f030bdcd-2f9c-43f9-9976-b3626b059a86",
    });
    expect(retained).toBe(false);
  });

  it("does not retain the selection when the loaded payload belongs to a different alert", () => {
    // Guards against a stale in-flight payload for a previously selected
    // alert being mistaken for evidence that the *current* selection exists.
    const retained = shouldRetainAlertSelection({
      selectedAlertId: "f030bdcd-2f9c-43f9-9976-b3626b059a86",
      payload: { mode: "db-processed" },
      error: "",
      alertId: "89f4ab83-5520-4f83-bafc-6d8fc321d497",
    });
    expect(retained).toBe(false);
  });

  it("does not retain the selection when the selected alert id is empty but the loaded payload has an id", () => {
    const retained = shouldRetainAlertSelection({
      selectedAlertId: "",
      payload: { mode: "db-processed" },
      error: "",
      alertId: "f030bdcd-2f9c-43f9-9976-b3626b059a86",
    });
    expect(retained).toBe(false);
  });
});

describe("resolveCanonicalAlertForRow", () => {
  // Fixtures mirror the real robot-shop-redis / KAN-1246 landing-pad race:
  // the landing-pad file arrives with only a fingerprint identity, while the
  // canonical DB alert (once persisted and fetched into alerts.rows) carries
  // the same fingerprint plus a real UUID.
  const landingPadRow = {
    file: "20260812T095459039502Z_robotshopservicedown_8478690570ded4e4.json",
    name: "RobotShopServiceDown",
    service: "robot-shop-redis",
    severity: "critical",
    created_at: "2026-08-12T09:54:59.039502Z",
    labels: { alertname: "RobotShopServiceDown", alert_fingerprint: "8478690570ded4e4", service: "robot-shop-redis" },
    _stream_kind: "landing_pad",
  };
  const canonicalAlertRow = {
    id: "bbe1b2c1-2542-488c-81d3-f57b38a25296",
    alert_id: "bbe1b2c1-2542-488c-81d3-f57b38a25296",
    name: "RobotShopServiceDown",
    service: "robot-shop-redis",
    severity: "critical",
    ticket_id: "KAN-1246",
    created_at: "2026-08-12T09:54:59.072978Z",
    labels: { alertname: "RobotShopServiceDown", alert_fingerprint: "8478690570ded4e4", service: "robot-shop-redis" },
  };

  it("resolves immediately when the row already carries a canonical UUID", () => {
    const alreadyCanonical = { id: "f030bdcd-2f9c-43f9-9976-b3626b059a86", alert_id: "f030bdcd-2f9c-43f9-9976-b3626b059a86" };
    const result = resolveCanonicalAlertForRow(alreadyCanonical, []);
    expect(result.status).toBe("resolved");
    expect(result.row).toBe(alreadyCanonical);
  });

  it("resolves a landing-pad row once its canonical DB alert is present in alertRows", () => {
    // The canonical alert arrived after the landing-pad selection -- exactly
    // the case the retry effect re-checks on every alerts.rows refresh.
    const result = resolveCanonicalAlertForRow(landingPadRow, [canonicalAlertRow]);
    expect(result.status).toBe("resolved");
    expect(result.row).toBe(canonicalAlertRow);
    expect(result.row.alert_id).toBe("bbe1b2c1-2542-488c-81d3-f57b38a25296");
    expect(result.row.ticket_id).toBe("KAN-1246");
  });

  it("reports pending, not a raw-id fallback, when no canonical alert exists yet", () => {
    // This is the exact race: the landing-pad row is selected before
    // alerts.rows has been refreshed with the persisted DB alert.
    const result = resolveCanonicalAlertForRow(landingPadRow, []);
    expect(result.status).toBe("pending");
    expect(result.row).toBeNull();
  });

  it("reports pending even when alertRows contains unrelated alerts", () => {
    const unrelatedAlert = { id: "11111111-1111-1111-1111-111111111111", alert_id: "11111111-1111-1111-1111-111111111111", service: "orders-db" };
    const result = resolveCanonicalAlertForRow(landingPadRow, [unrelatedAlert]);
    expect(result.status).toBe("pending");
    expect(result.row).toBeNull();
  });

  it("reports unresolved for a row with no identity to ever match against", () => {
    const identityless = { name: "", service: "" };
    const result = resolveCanonicalAlertForRow(identityless, [canonicalAlertRow]);
    expect(result.status).toBe("unresolved");
    expect(result.row).toBeNull();
  });

  it("reports unresolved for a null row", () => {
    const result = resolveCanonicalAlertForRow(null, [canonicalAlertRow]);
    expect(result.status).toBe("unresolved");
  });

  it("resolves a URL-restored route id by matching the source landing-pad row's identity", () => {
    // Reproduces the hard-refresh bug: ?workspace=alert&alert_id=<filename>
    // carries only the filename, which has no identity of its own. Route
    // restoration must look the filename up in the landing-pad rows to find
    // its real fingerprint/name/service before it can ever resolve -- a bare
    // { id: filename } wrapper (no identity) always reports "unresolved" and
    // permanently gets stuck on a landing-pad-only snapshot even once the
    // canonical alert exists.
    const routeAlertId = landingPadRow.file;
    const landingPadRows = [landingPadRow];
    const sourceRow = landingPadRows.find((row) => row.file === routeAlertId) || { id: routeAlertId, alert_id: routeAlertId };

    const beforeCanonicalArrives = resolveCanonicalAlertForRow(sourceRow, []);
    expect(beforeCanonicalArrives.status).toBe("pending");

    const afterCanonicalArrives = resolveCanonicalAlertForRow(sourceRow, [canonicalAlertRow]);
    expect(afterCanonicalArrives.status).toBe("resolved");
    expect(afterCanonicalArrives.row.alert_id).toBe("bbe1b2c1-2542-488c-81d3-f57b38a25296");
  });

  it("reports unresolved (not pending) for a URL-restored route id with no matching landing-pad row", () => {
    // If the landing-pad row itself isn't found (e.g. it aged out of the
    // recent listing), the bare filename wrapper has no identity to retry
    // against -- this must not spin forever.
    const routeAlertId = "20260101T000000000000Z_unknownalert_deadbeef.json";
    const sourceRow = { id: routeAlertId, alert_id: routeAlertId, file: routeAlertId };
    const result = resolveCanonicalAlertForRow(sourceRow, [canonicalAlertRow]);
    expect(result.status).toBe("unresolved");
  });
});


describe("pending decision and inbox view reconciliation", () => {
  it("recognizes pending decisions and needs_me inbox rows when lifecycle_state is AWAITING_APPROVAL even if legacy status is investigating", () => {
    const row = {
      id: "00a3dd0a-42d4-4382-8293-0d909e7b56b0",
      incident_id: "00a3dd0a-42d4-4382-8293-0d909e7b56b0",
      status: "investigating",
      lifecycle_state: "AWAITING_APPROVAL",
      severity: "critical",
    };
    expect(hasPendingDecision(row)).toBe(true);
    expect(belongsToInboxView(row as any, "needs_me")).toBe(true);
    expect(belongsToInboxView(row as any, "kai_handling")).toBe(false);
  });
});
