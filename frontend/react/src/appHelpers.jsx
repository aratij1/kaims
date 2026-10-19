import { useState } from "react";
import { ONBOARDING_SOURCE_DOC_BUCKETS } from "./onboardingConfig";
import { looksLikeUuid } from "./onboardingUtils";
import { queryClient } from "./app/queryClient";
import { parseInternalApiResponse } from "./schemas/apiContracts";

const DEFAULT_ALERT = {
  source: "monitoring-adapter",
  name: "PaymentLatencySpike",
  service: "payments",
  severity: "high",
  description: "Payment latency crossed 2.5s threshold for 5m",
};

const REAL_USE_CASE_SCOPE = "real-usecases";
const TEST_USE_CASE_SCOPE = "test-usecases";
const CORE_MONITOR_PROJECTS = ["KaiMS", "Telemetry"];
const FIXED_MONITOR_SCOPES = [...CORE_MONITOR_PROJECTS];

const SERVICE_TOPIC_FLOW = [
  { service: "monitoring-adapter", consumes: "-", publishes: "raw-alerts", agent: "alert" },
  { service: "alert-intelligence", consumes: "raw-alerts", publishes: "enriched-alerts", agent: "Alert Intelligence Agent" },
  { service: "orchestrator", consumes: "enriched-alerts", publishes: "orchestration-events", agent: "Orchestrator Agent" },
  { service: "context-agent", consumes: "orchestration-events", publishes: "context-events", agent: "Context Intelligence Agent" },
  { service: "resolution-agent", consumes: "context-events", publishes: "resolution-events", agent: "Resolution Intelligence Agent" },
  { service: "approval-service", consumes: "resolution-events", publishes: "approval-events", agent: "Human Approval Layer" },
  { service: "remediation-engine", consumes: "approval-events", publishes: "remediation-events", agent: "Remediation Automation Engine" },
  { service: "closure-service", consumes: "remediation-events", publishes: "closure-events", agent: "Closure & Validation" },
];

const RECOMMENDED_WORKER_PROFILE = {
  "monitoring-adapter": { containers: 1, workers: 2, role: "landing-pad intake" },
  "alert-intelligence": { containers: 1, workers: 2, role: "dedupe and correlation workers" },
  orchestrator: { containers: 1, workers: 2, role: "master routing workers" },
  "context-agent": { containers: 1, workers: 3, role: "RAG and evidence workers" },
  "resolution-agent": { containers: 1, workers: 3, role: "RCA and recommendation workers" },
  "approval-service": { containers: 1, workers: 1, role: "decision gate" },
  "remediation-engine": { containers: 1, workers: 2, role: "execution policy workers" },
  "closure-service": { containers: 1, workers: 2, role: "post-check workers" },
};

const SCALE_CAPACITY_GUIDE = [
  {
    rate: "100/hr",
    perSecond: "0.03/sec",
    masters: "1 master",
    workers: "1 worker per service",
    vm: "1 VM: 2 vCPU / 8 GB RAM",
    config: "MESSAGE_BUS_WORKER_COUNT=1",
    state: "Local Compose state is acceptable for dev/smoke.",
  },
  {
    rate: "500/hr",
    perSecond: "0.14/sec",
    masters: "1 master",
    workers: "1 alert-intel, 2 context, 2 resolution, 1 remediation",
    vm: "1 VM: 4 vCPU / 16 GB RAM",
    config: "Use docker-compose.scale.yml; CONTEXT_AGENT_WORKERS=2, RESOLUTION_AGENT_WORKERS=2",
    state: "Move Redis/MySQL to managed or dedicated VM if dashboards and approvals are active.",
  },
  {
    rate: "1,000/hr",
    perSecond: "0.28/sec",
    masters: "2 orchestrators",
    workers: "2 alert-intel, 3 context, 3 resolution, 2 closure, 1-2 remediation",
    vm: "2 VMs: 4 vCPU / 16 GB each, or 1 VM: 8 vCPU / 32 GB",
    config: "Enable Kafka/RabbitMQ; ORCHESTRATOR_WORKERS=2, ALERT_INTELLIGENCE_WORKERS=2",
    state: "Use shared DB, shared cache, shared message bus, shared vector index.",
  },
  {
    rate: "10,000/hr",
    perSecond: "2.78/sec",
    masters: "3+ orchestrators",
    workers: "4+ alert-intel, 6-10 context, 6-10 resolution, 3+ remediation",
    vm: "3-6 VMs: 8 vCPU / 32 GB each, or AKS/VMSS node pool",
    config: "Externalize DB/Redis/bus/vector store; tune RAG_EMBEDDING_BATCH_SIZE and provider limits",
    state: "Production HA required: load balancer, managed DB, Kafka/Event Hubs, vector DB, object storage.",
  },
];

const AGENT_DISPLAY_ALIASES = {
  "orchestrator agent": "Master Agent",
  orchestrator: "Master Agent",
  "closure & validation": "Validator Agent",
  "closure-service": "Validator Agent",
};

const AGENT_ROUTE_ALIASES = {
  "master agent": "orchestrator agent",
  "master agent (orchestrator agent)": "orchestrator agent",
  "validator agent": "closure & validation",
  "validator agent (closure & validation)": "closure & validation",
};

const PREFERENCE_STORAGE_KEY = "kaiops.ui.preferences.v1";
const UI_THEME_VALUES = new Set(["auto", "light", "dark"]);
function extractObservedRoutingMetrics(workflow) {
  if (!workflow || typeof workflow !== "object") {
    return {};
  }
  const rawEvents = [workflow.events, workflow.workflow_events, workflow.agent_events]
    .find((items) => Array.isArray(items)) || [];
  const events = rawEvents.filter((item) => item && typeof item === "object");
  const traceRows = [workflow.event_trace, workflow.trace_events, workflow?.trace?.events]
    .find((items) => Array.isArray(items)) || [];
  const latestEvent = [...events].reverse().find((item) => item && typeof item === "object") || null;
  const orchestratorEvent = [...events].reverse().find((item) => {
    const agent = String(item?.agent || "").trim().toLowerCase();
    return agent.includes("orchestrator") || agent.includes("master");
  }) || latestEvent;
  const latestTrace = [...traceRows]
    .filter((row) => row && typeof row === "object")
    .sort((a, b) => {
      const aTime = parseUtcTimestamp(a.timestamp)?.getTime() || 0;
      const bTime = parseUtcTimestamp(b.timestamp)?.getTime() || 0;
      return bTime - aTime;
    })[0] || null;

  const recommendationMetadata =
    typeof workflow?.recommendation?.metadata === "object" ? workflow.recommendation.metadata : {};
  const metrics = typeof orchestratorEvent?.metrics === "object"
    ? { ...orchestratorEvent.metrics }
    : (typeof latestEvent?.metrics === "object" ? { ...latestEvent.metrics } : {});
  const decision =
    (typeof workflow?.decision === "object" && workflow.decision)
    || (typeof workflow?.orchestration_decision === "object" && workflow.orchestration_decision)
    || (typeof recommendationMetadata?.orchestration_decision === "object" && recommendationMetadata.orchestration_decision)
    || (typeof orchestratorEvent?.decision === "object" && orchestratorEvent.decision)
    || {};

  const provider =
    metrics.message_bus_provider
    || decision.message_bus_provider
    || latestTrace?.transport_provider
    || latestEvent?.input?.transport_provider
    || latestEvent?.transport_provider
    || workflow?.transport_provider
    || "";

  return {
    ...metrics,
    workflow: metrics.workflow || decision.workflow || workflow?.scenario?.id || "",
    next_action:
      metrics.next_action
      || decision.next_action
      || workflow?.next_step
      || workflow?.recommendation?.recommended_action
      || "",
    requires_approval:
      metrics.requires_approval
      ?? decision.requires_approval
      ?? workflow?.approval?.required
      ?? workflow?.recommendation?.requires_approval,
    risk_tier: metrics.risk_tier || decision.risk_tier || latestTrace?.risk_tier || "",
    execution_mode: metrics.execution_mode || decision.execution_mode || latestTrace?.execution_mode || "",
    policy_version: metrics.policy_version || decision.policy_version || workflow?.recommendation?.policy_version || "",
    message_bus_provider: provider,
  };
}

function normalizeMatchTokens(value) {
  return String(value || "")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .map((item) => item.trim())
    .filter((item) => item.length >= 3);
}

function hasTokenOverlap(left, right) {
  const leftTokens = normalizeMatchTokens(left);
  const rightTokens = normalizeMatchTokens(right);
  if (!leftTokens.length || !rightTokens.length) {
    return false;
  }
  const rightSet = new Set(rightTokens);
  return leftTokens.some((token) => rightSet.has(token));
}

const KAIOPS_CORE_SERVICE_SET = new Set([
  "api-gateway",
  "monitoring-adapter",
  "alert-intelligence",
  "orchestrator",
  "context-agent",
  "resolution-agent",
  "approval-service",
  "remediation-engine",
  "closure-service",
  "model-router",
]);

function normalizeMonitorToken(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, "-")
    .replace(/-+/g, "-");
}

function isKaiopsCoreSelection(value) {
  const token = normalizeMonitorToken(value);
  return token === "kaims" || token === "kaims-core" || token === "kaiops-core" || token === "kaiops-core1" || token === "kaiops" || token === "core";
}

function isKaiopsCoreAlert(row) {
  const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
  const metadata = typeof row?.metadata === "object" && row?.metadata ? row.metadata : {};
  const service = String(row?.service || labels?.service || "").trim().toLowerCase();
  const alertName = String(row?.name || labels?.alertname || "").trim().toLowerCase();
  const ownerTeam = String(metadata?.owner_team || labels?.team || "").trim().toLowerCase();
  const project = String(row?.project || row?.project_name || row?.application || labels?.project || labels?.project_name || "")
    .trim()
    .toLowerCase();

  if (project.includes("telemetry") || project.includes("astronomy")) {
    return false;
  }
  if (KAIOPS_CORE_SERVICE_SET.has(service)) {
    return true;
  }
  if (alertName.includes("kaiops")) {
    return true;
  }
  if (ownerTeam === "platform-ops" || ownerTeam === "kaiops") {
    return true;
  }
  return project.includes("kaiops");
}

const PROMPT_FRAGMENT_PATTERNS = [
  "identify the most likely root cause using only",
  "identify the most likely root cause using only supplied incident",
  "assess customer, service, dependency, and business impact",
  "generate an operator-safe remediation",
  "scenario:",
  "immediate triage:",
  "verification:",
  "apply a low-risk mitigation",
  "confirm recovery in dashboards and logs",
  "fallback rca (model unavailable)",
  "fallback impact analysis (model unavailable)",
  "fallback remediation guidance (model unavailable)",
];

function isPromptFragment(value) {
  const text = String(value || "").trim().toLowerCase();
  return PROMPT_FRAGMENT_PATTERNS.some((fragment) => text.includes(fragment));
}

function isPlaceholderRecommendationText(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text) {
    return true;
  }
  return [
    "undefined",
    "null",
    "none",
    "n/a",
    "na",
    "unknown",
    "tbd",
    "-",
  ].includes(text);
}

function cleanRecommendationText(value, fallback = "-") {
  if (value == null) {
    return fallback;
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => cleanRecommendationText(item, "")).filter(Boolean);
    return items.length ? Array.from(new Set(items)).join("; ") : fallback;
  }
  if (typeof value === "object") {
    const preferredKeys = [
      "summary", "description", "observed_impact", "impact_summary", "customer_impact",
      "service_impact", "dependency_impact", "severity_rationale", "urgency", "name", "service",
      "root_cause", "cause", "mechanism", "reasoning", "content", "value",
    ];
    const preferred = preferredKeys
      .map((key) => cleanRecommendationText(value[key], ""))
      .filter(Boolean);
    if (preferred.length) {
      return Array.from(new Set(preferred)).join("; ");
    }
    const scalarDetails = Object.entries(value)
      .filter(([, item]) => ["string", "number"].includes(typeof item))
      .map(([key, item]) => `${key.replaceAll("_", " ")}: ${String(item).trim()}`)
      .filter((item) => !isPlaceholderRecommendationText(item.split(":").slice(1).join(":").trim()));
    return scalarDetails.length ? scalarDetails.join("; ") : fallback;
  }
  const text = String(value).trim();
  if (!text || isPlaceholderRecommendationText(text)) {
    return fallback;
  }
  const payload = parseStructuredIntelligence(text);
  if (payload) {
    const payloadMetadata = payload.metadata && typeof payload.metadata === "object" ? payload.metadata : {};
    const fallbackDetected = Boolean(
      payload?.fallback
      || payloadMetadata?.fallback
      || String(payload?.source || "").trim().toLowerCase().includes("fallback")
    );
    if (fallbackDetected) {
      return fallback;
    }
    const keys = [
      "root_cause",
      "cause",
      "impact_summary",
      "service_impact",
      "impact",
      "customer_impact",
      "dependency_impact",
      "severity_rationale",
      "recommended_action",
      "action",
      "summary",
      "content",
      "title",
    ];
    for (const key of keys) {
      const candidate = cleanRecommendationText(payload[key], "");
      if (candidate && !isPromptFragment(candidate) && !isPlaceholderRecommendationText(candidate)) {
        return candidate;
      }
    }
    return fallback;
  }
  return (isPromptFragment(text) || isPlaceholderRecommendationText(text)) ? fallback : text;
}

function filterAlertsForMonitor(rows, applicationToMonitor) {
  const target = String(applicationToMonitor || "").trim().toLowerCase();
  const alertRows = Array.isArray(rows) ? rows : [];
  if (!target) {
    return alertRows;
  }
  if (target === REAL_USE_CASE_SCOPE) {
    return alertRows.filter((row) => !isGeneratedOrTestAlert(row));
  }
  if (target === TEST_USE_CASE_SCOPE) {
    return alertRows.filter((row) => isGeneratedOrTestAlert(row));
  }
  const productionRows = alertRows.filter((row) => !isGeneratedOrTestAlert(row));
  if (target === "telemetry") {
    return productionRows.filter((row) => inferMonitorScope(row) === "telemetry");
  }
  if (isKaiopsCoreSelection(target)) {
    return productionRows.filter((row) => inferMonitorScope(row) === "kaiops");
  }
  return productionRows.filter((row) => {
    const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
    const metadata = typeof row?.metadata === "object" && row?.metadata ? row.metadata : {};
    const candidates = [
      row?.application,
      row?.project,
      row?.project_name,
      metadata?.application,
      metadata?.project,
      metadata?.project_name,
      labels?.application,
      labels?.project,
      labels?.project_name,
      row?.service,
      labels?.service,
      labels?.job,
    ]
      .map((value) => normalizeMonitorToken(value))
      .filter(Boolean);
    return candidates.includes(normalizeMonitorToken(target));
  });
}

function filterRowsForMonitor(rows, applicationToMonitor) {
  const target = String(applicationToMonitor || "").trim().toLowerCase();
  const items = Array.isArray(rows) ? rows : [];
  if (!target) {
    return items;
  }
  if (target === REAL_USE_CASE_SCOPE) {
    return items.filter((row) => !isGeneratedOrTestAlert(row));
  }
  if (target === TEST_USE_CASE_SCOPE) {
    return items.filter((row) => isGeneratedOrTestAlert(row));
  }
  const productionRows = items.filter((row) => !isGeneratedOrTestAlert(row));
  if (target === "telemetry") {
    return productionRows.filter((row) => inferMonitorScope(row) === "telemetry");
  }
  if (isKaiopsCoreSelection(target)) {
    return productionRows.filter((row) => inferMonitorScope(row) === "kaiops");
  }
  return productionRows.filter((row) => {
    const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
    const metadata = typeof row?.metadata === "object" && row?.metadata ? row.metadata : {};
    const candidates = [
      row?.application,
      row?.project,
      row?.project_name,
      metadata?.application,
      metadata?.project,
      metadata?.project_name,
      labels?.application,
      labels?.project,
      labels?.project_name,
      row?.service,
      labels?.service,
      labels?.job,
    ]
      .map((value) => normalizeMonitorToken(value))
      .filter(Boolean);
    return candidates.includes(normalizeMonitorToken(target));
  });
}

function inferMonitorScope(row) {
  const projection = typeof row?.projection_payload === "object" && row?.projection_payload ? row.projection_payload : {};
  const event = typeof projection?.event_payload === "object" && projection?.event_payload ? projection.event_payload : {};
  const labels = [row?.labels, projection?.labels, event?.labels, projection?.alert_labels, event?.alert_labels]
    .find((candidate) => candidate && typeof candidate === "object") || {};
  const metadata = typeof row?.metadata === "object" && row?.metadata ? row.metadata : {};
  const explicitProject = String(
    row?.project_name
    || labels?.project_name
    || row?.project
    || labels?.project
    || row?.application
    || labels?.application
    || metadata?.project_name
    || metadata?.project
    || metadata?.application
    || ""
  ).trim().toLowerCase();
  if (explicitProject.includes("telemetry") || explicitProject.includes("astronomy")) {
    return "telemetry";
  }
  if (explicitProject.includes("kaiops") || explicitProject.includes("kai-ops")) {
    return "kaiops";
  }

  const sourcePath = String(row?.path || row?.file || row?.source_path || "").trim().toLowerCase();
  if (sourcePath.includes("opensearch://otel-") || sourcePath.includes("astronomy") || sourcePath.includes("telemetry")) {
    return "telemetry";
  }

  const namespace = String(labels?.namespace || metadata?.namespace || "").trim().toLowerCase();
  if (namespace.includes("otel") || namespace.includes("astronomy")) {
    return "telemetry";
  }

  const service = String(row?.service || labels?.service || labels?.job || "").trim().toLowerCase();
  if (KAIOPS_CORE_SERVICE_SET.has(service) || service.startsWith("kaiops-") || service.startsWith("kaiops_")) {
    return "kaiops";
  }

  if (isKaiopsCoreAlert(row)) {
    return "kaiops";
  }
  return "";
}

function isGeneratedOrTestAlert(row) {
  const labels = typeof row?.labels === "object" && row.labels ? row.labels : {};
  const metadata = typeof row?.metadata === "object" && row.metadata ? row.metadata : {};
  const annotations = typeof row?.annotations === "object" && row.annotations ? row.annotations : {};
  const projection = typeof row?.projection_payload === "object" && row.projection_payload ? row.projection_payload : {};
  const eventPayload = typeof projection?.event_payload === "object" && projection.event_payload ? projection.event_payload : {};
  const projectionLabels = typeof eventPayload?.labels === "object" && eventPayload.labels ? eventPayload.labels : {};
  const explicitTestFlag = [
    row?.is_test,
    row?.test_alert,
    labels?.is_test,
    labels?.test_alert,
    labels?.onboarding_test,
    metadata?.is_test,
    metadata?.test_alert,
  ].some((value) => ["1", "true", "yes", "test"].includes(String(value || "").trim().toLowerCase()));
  if (explicitTestFlag) {
    return true;
  }
  const tokens = [
    row?.id,
    row?.alert_id,
    row?.incident_id,
    row?.name,
    row?.title,
    row?.alert_name,
    row?.rule_name,
    row?.rule,
    row?.alert_rule,
    row?.labels?.alertname,
    row?.service,
    row?.application,
    row?.project_name,
    row?.project,
    row?.environment,
    row?.description,
    row?.summary,
    row?.source_path,
    labels?.application,
    labels?.project,
    labels?.project_name,
    labels?.environment,
    labels?.namespace,
    labels?.tenant,
    labels?.job,
    labels?.alertname,
    annotations?.summary,
    annotations?.description,
    metadata?.application,
    metadata?.project,
    metadata?.project_name,
    metadata?.environment,
    projection?.title,
    projection?.alert_name,
    projection?.application,
    projection?.environment,
    eventPayload?.title,
    eventPayload?.name,
    eventPayload?.alert_name,
    eventPayload?.application,
    eventPayload?.environment,
    projectionLabels?.alertname,
    projectionLabels?.application,
    projectionLabels?.environment,
  ].map((value) => String(value || "").toLowerCase()).join(" ");
  return /(^|[-_\s])(e2e|ui-e2e|admin-e2e|setup-doc-e2e|stress|smoke|onboarding-smoke-test|test\d*|testing|demo|sample|mock|synthetic|fake|dummy)([-_\s]|$)/i.test(tokens)
    || tokens.includes("stresspipelinealert")
    || tokens.includes("onboarding-smoke-test");
}

function isEphemeralProjectName(value) {
  const token = String(value || "").trim().toLowerCase();
  if (!token) {
    return false;
  }
  return /(^|[-_\s])(e2e|ui-e2e|admin-e2e|setup-doc-e2e|stress|smoke|onboarding-smoke-test)([-_\s]|$)/i.test(token);
}

function normalizeAlertChannel(row) {
  const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
  const metadata = typeof row?.metadata === "object" && row?.metadata ? row.metadata : {};
  const projectName = String(
    row?.project_name
    || row?.application
    || labels?.project_name
    || labels?.application
    || ""
  ).trim().toLowerCase();
  const explicitOrigin = String(
    labels?.origin_system
    || labels?.source_system
    || metadata?.origin_system
    || row?.origin_system
    || ""
  ).trim().toLowerCase();
  const explicitChannel = String(
    labels?.ingestion_channel
    || labels?.source_channel
    || metadata?.ingestion_channel
    || row?.ingestion_channel
    || ""
  ).trim().toLowerCase();
  // OpenSearch can transport OpenTelemetry application logs. Classify the
  // owning workload before classifying the transport.
  if (projectName === "telemetry" || projectName === "astronomy-shop") return "telemetry";
  if (explicitOrigin.includes("telemetry") || explicitOrigin.includes("opentelemetry")) return "telemetry";
  if (explicitOrigin.includes("email") || explicitChannel.includes("email")) return "email";
  if (explicitOrigin.includes("jira") || explicitOrigin.includes("ticket") || explicitChannel.includes("ticket")) return "ticket";
  if (explicitOrigin.includes("log") || explicitOrigin.includes("opensearch") || explicitChannel.includes("log")) return "log";
  const source = [
    row?.source,
    row?.provider,
    row?.provider_name,
    row?.source_type,
    row?.origin,
    row?.channel_type,
    row?.channel,
    row?.ticket_provider,
    row?.notification_channel,
    row?.integration,
    metadata?.source,
    metadata?.channel,
    labels?.source,
    labels?.channel,
    labels?.job,
    labels?.alertname,
  ]
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean)
    .join(" ");
  if (
    source.includes("telemetry")
    || source.includes("opentelemetry")
    || source.includes("astronomy")
  ) {
    return "telemetry";
  }
  if (
    source.includes("prometheus")
    || source.includes("alertmanager")
    || source.includes("monitoring-adapter")
  ) {
    return "prometheus";
  }
  if (source.includes("email") || source.includes("smtp") || source.includes("mail") || source.includes("outlook")) {
    return "email";
  }
  if (
    source.includes("opensearch")
    || source.includes("log-alert")
    || source.includes("log monitoring")
  ) {
    return "log";
  }
  if (
    source.includes("jira")
    || source.includes("ticket")
    || source.includes("itsm")
    || source.includes("servicenow")
    || source.includes("snow")
    || source.includes("incident")
    || source.includes("closed-incidents")
  ) {
    return "ticket";
  }
  if (
    String(labels?.alertname || "").trim()
    || String(row?.expr || row?.expression || row?.query || "").trim()
  ) {
    return "prometheus";
  }
  return "prometheus";
}

function sourceChannelLabel(value) {
  const key = String(value || "").trim().toLowerCase();
  if (key === "prometheus") return "Prometheus";
  if (key === "email") return "Email";
  if (key === "ticket") return "Ticket";
  if (key === "telemetry") return "Telemetry / Prometheus";
  if (key === "log") return "Logs / OpenSearch";
  if (key === "other") return "Other";
  return key || "Unknown";
}

const ALERT_SOURCE_CHANNELS = ["prometheus", "telemetry", "email", "ticket", "log"];
const MAX_LATEST_ALERTS_PER_SOURCE = 30;
const MIN_VISIBLE_ALERTS_BY_SOURCE = {
  prometheus: 2,
  telemetry: 2,
  email: 2,
  ticket: 2,
  log: 2,
};

function capLatestAlertsPerSource(rows, maxPerSource = MAX_LATEST_ALERTS_PER_SOURCE) {
  const safeMax = Math.max(1, Number(maxPerSource) || MAX_LATEST_ALERTS_PER_SOURCE);
  const sortedRows = (Array.isArray(rows) ? rows : [])
    .slice()
    .sort((left, right) => alertTimeMs(right) - alertTimeMs(left));
  const selected = new Set();
  const counters = Object.fromEntries(ALERT_SOURCE_CHANNELS.map((channel) => [channel, 0]));
  const identities = Object.fromEntries(ALERT_SOURCE_CHANNELS.map((channel) => [channel, new Set()]));

  // Reserve a slot for the newest occurrence of every alert type before a
  // noisy service can fill the source quota with duplicates. Without this,
  // bursts from one Prometheus job hid valid alerts such as mysql-exporter
  // even though their incidents remained visible in the incident table.
  sortedRows.forEach((row, index) => {
    const channel = normalizeAlertChannel(row);
    if (!ALERT_SOURCE_CHANNELS.includes(channel) || counters[channel] >= safeMax) return;
    const labels = typeof row?.labels === "object" && row.labels ? row.labels : {};
    const service = String(row?.service || labels?.service || labels?.job || "unknown-service").trim().toLowerCase();
    const name = String(row?.name || row?.alert_name || labels?.alertname || "unnamed-alert").trim().toLowerCase();
    const identity = `${service}:${name}`;
    if (identities[channel].has(identity)) return;
    identities[channel].add(identity);
    counters[channel] += 1;
    selected.add(index);
  });

  // Use any remaining capacity for repeated occurrences, retaining the
  // original newest-first ordering expected by the live stream.
  sortedRows.forEach((row, index) => {
    const channel = normalizeAlertChannel(row);
    if (selected.has(index) || !ALERT_SOURCE_CHANNELS.includes(channel) || counters[channel] >= safeMax) return;
    counters[channel] += 1;
    selected.add(index);
  });
  return sortedRows.filter((_row, index) => selected.has(index));
}

function ensureMinimumAlertsBySource(rows, sourceRows, minimums = MIN_VISIBLE_ALERTS_BY_SOURCE) {
  const selected = (Array.isArray(rows) ? rows : []).slice();
  const candidates = (Array.isArray(sourceRows) ? sourceRows : [])
    .slice()
    .sort((left, right) => alertTimeMs(right) - alertTimeMs(left));
  const seen = new Set(selected.flatMap((row) => alertIdentityKeys(row)));
  const counts = Object.fromEntries(
    Object.keys(minimums).map((channel) => [
      channel,
      selected.filter((row) => normalizeAlertChannel(row) === channel).length,
    ])
  );

  for (const row of candidates) {
    const channel = normalizeAlertChannel(row);
    const required = Number(minimums[channel] || 0);
    if (!required || counts[channel] >= required) {
      continue;
    }
    const identities = alertIdentityKeys(row);
    const fallbackIdentity = `${channel}:${row?.name || ""}:${row?.created_at || row?.received_at || ""}`;
    if (identities.some((identity) => seen.has(identity)) || (!identities.length && seen.has(fallbackIdentity))) {
      continue;
    }
    (identities.length ? identities : [fallbackIdentity]).forEach((identity) => seen.add(identity));
    selected.push(row);
    counts[channel] += 1;
  }

  return selected.sort((left, right) => alertTimeMs(right) - alertTimeMs(left));
}

function monitorScopeLabel(scope) {
  const key = String(scope || "").trim().toLowerCase();
  if (["kaiops", "kaims", "kaiops-core", "kaims-core"].includes(key)) {
    return "KaiMS";
  }
  if (key === REAL_USE_CASE_SCOPE) {
    return "Real Use Cases";
  }
  if (key === TEST_USE_CASE_SCOPE) {
    return "Test Use Cases";
  }
  return scope || "Real Use Cases";
}

function alertTimeMs(row) {
  return (
    parseUtcTimestamp(
      row?.created_at
      || row?.received_at
      || row?.modified_at
      || row?.starts_at
      || row?.closed_at
      || row?.updated_at
    )?.getTime()
    || 0
  );
}

function stableCrossSourceAlertSignature(row) {
  const labels = typeof row?.labels === "object" && row.labels ? row.labels : {};
  const text = String(
    labels?.error_signature
    || row?.error_signature
    || row?.name
    || row?.alert_name
    || row?.description
    || row?.annotations?.summary
    || ""
  ).toLowerCase();
  const ignored = new Set([
    "alert", "warning", "critical", "high", "error", "failed", "failure",
    "email", "ticket", "jira", "prometheus", "opensearch", "telemetry",
    "from", "with", "this", "that", "into", "prod", "production",
  ]);
  return Array.from(new Set(
    text
      .replace(/\b\d{4}-\d{2}-\d{2}[t\s][\d:.+\-z]+\b/gi, " ")
      .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, " ")
      .replace(/\b[0-9a-f]{16,}\b/gi, " ")
      .replace(/\b\d+\b/g, " ")
      .match(/[a-z][a-z0-9_.-]{2,}/g) || []
  ))
    .filter((token) => !ignored.has(token))
    .sort()
    .slice(0, 14)
    .join("|");
}

function alertIdentityKeys(row) {
  // Different sources populate different identity fields for the *same* real-world alert:
  // a landing-pad file listing carries no fingerprint/incident_id at all (see
  // _landing_pad_file_rows on the backend, which never surfaces labels), while the
  // primary /alerts/all API row for that same alert does. Returning every candidate key
  // (instead of picking just the single highest-priority one) lets the caller union two
  // rows together if ANY key overlaps, rather than requiring both sides to agree on which
  // identity field happened to be available.
  const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
  const keys = [];

  const fingerprint = String(
    row?.fingerprint
    || row?.alert_fingerprint
    || labels?.alert_fingerprint
    || labels?.fingerprint
    || ""
  ).trim();
  if (fingerprint) {
    keys.push(`fingerprint:${fingerprint.toLowerCase()}`);
  }

  const incidentId = String(row?.incident_id || "").trim();
  if (incidentId) {
    keys.push(`incident:${incidentId.toLowerCase()}`);
  }

  const correlation = String(row?.correlation_id || row?.trace_id || "").trim();
  if (correlation) {
    keys.push(`correlation:${correlation.toLowerCase()}`);
  }

  [
    row?.ticket_key,
    row?.issue_key,
    row?.jira_issue_key,
    labels?.ticket_key,
    labels?.issue_key,
    labels?.jira_issue_key,
    labels?.source_alert_id,
  ].forEach((value) => {
    const identity = String(value || "").trim().toLowerCase();
    if (identity) {
      keys.push(`external:${identity}`);
    }
  });

  const name = String(row?.name || row?.alert_name || labels?.alertname || "").trim().toLowerCase();
  const service = String(row?.service || labels?.service || labels?.job || "").trim().toLowerCase();
  if (name && service) {
    const severity = String(row?.severity || labels?.severity || "").trim().toLowerCase();
    const timestampMs = alertTimeMs(row);
    const bucket = timestampMs > 0 ? Math.floor(timestampMs / (5 * 60 * 1000)) : 0;
    keys.push(`composite:${name}|${service}|${severity}|${bucket}`);
  }

  const semanticSignature = stableCrossSourceAlertSignature(row);
  if (service && semanticSignature.split("|").length >= 2) {
    const timestampMs = alertTimeMs(row);
    const bucket = timestampMs > 0 ? Math.floor(timestampMs / (10 * 60 * 1000)) : 0;
    keys.push(`cross-source:${service}|${semanticSignature}|${bucket}`);
  }

  return keys;
}

function alertFingerprintValue(row) {
  const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
  return String(row?.fingerprint || row?.alert_fingerprint || labels?.alert_fingerprint || labels?.fingerprint || "")
    .trim().toLowerCase();
}

function alertApplicationCandidate(row) {
  const application = String(row?.application || "").trim();
  const service = String(row?.service || "").trim();
  // An application value that's just a copy of the service name is almost always a bad
  // fallback (some mappers default "application" to "service" when the real project/app
  // name is unknown), not a genuine project label -- don't let it win over a real one.
  return application && application.toLowerCase() !== service.toLowerCase() ? application : "";
}

function alertRowScore(row) {
  const status = String(row?.status || row?.state || "").trim().toLowerCase();
  const openScore = isApprovalResolvedStatus(status) || row?._closed_incident ? 0 : 10;
  const dataScore = [row?.trace_id, row?.correlation_id, row?.description, row?.annotations?.description]
    .filter((item) => String(item || "").trim()).length;
  return openScore + dataScore;
}

function resolveCanonicalAlertRow(row, candidates) {
  if (!row || typeof row !== "object") {
    return row;
  }
  const rowKeys = new Set(alertIdentityKeys(row));
  if (!rowKeys.size) {
    return row;
  }
  const matches = (Array.isArray(candidates) ? candidates : []).filter((candidate) => {
    if (!candidate || typeof candidate !== "object") {
      return false;
    }
    return alertIdentityKeys(candidate).some((key) => rowKeys.has(key));
  });
  if (!matches.length) {
    return row;
  }
  return matches
    .slice()
    .sort((left, right) => {
      const leftCanonical = ALERT_UUID_PATTERN.test(String(left?.alert_id || left?.id || "")) ? 1 : 0;
      const rightCanonical = ALERT_UUID_PATTERN.test(String(right?.alert_id || right?.id || "")) ? 1 : 0;
      if (leftCanonical !== rightCanonical) {
        return rightCanonical - leftCanonical;
      }
      const leftLanding = left?._stream_kind === "landing_pad" ? 1 : 0;
      const rightLanding = right?._stream_kind === "landing_pad" ? 1 : 0;
      if (leftLanding !== rightLanding) {
        return leftLanding - rightLanding;
      }
      return alertRowScore(right) - alertRowScore(left);
    })[0];
}

// A landing-pad ingestion row can be clicked before the same real-world alert
// has been persisted into the canonical alerts collection (alerts.rows) --
// the two are populated by separate, non-atomic sources. Opening it with the
// landing-pad row's own id (a filename, not a UUID) sends a doomed
// processed-result lookup, since that endpoint is keyed by the canonical
// alert UUID. This resolves a row to its canonical UUID-bearing counterpart
// via the same identity-key matching resolveCanonicalAlertRow already uses,
// and reports "pending" (rather than silently falling back to the raw row)
// when no canonical match exists yet, so the caller can wait/retry instead of
// fetching with an id that can never resolve.
function resolveCanonicalAlertForRow(row, alertRows) {
  if (!row || typeof row !== "object") {
    return { status: "unresolved", row: null };
  }
  const suppliedAlertId = String(
    row?.alert_id
    || row?.projection_payload?.alert_id
    || row?.projection_payload?.event_payload?.alert_id
    || row?.projection_payload?.event_payload?.source_alert_id
    || row?.id
    || row?.incident_id
    || ""
  ).trim();
  if (ALERT_UUID_PATTERN.test(suppliedAlertId)) {
    return { status: "resolved", row };
  }
  const canonicalRow = resolveCanonicalAlertRow(row, alertRows);
  const canonicalAlertId = String(canonicalRow?.alert_id || canonicalRow?.id || "").trim();
  if (canonicalRow && canonicalRow !== row && ALERT_UUID_PATTERN.test(canonicalAlertId)) {
    return { status: "resolved", row: canonicalRow };
  }
  // No UUID-bearing counterpart is available yet in alertRows. Report
  // "pending" (an operator can wait for it to appear) only when the row
  // carries real matchable identity (fingerprint, name+service, etc.) via
  // alertIdentityKeys -- the same signal resolveCanonicalAlertRow just used
  // above. A bare non-UUID id/incident_id with no other identity (e.g. a
  // landing-pad filename whose source row could not be found) can never gain
  // a match through retrying, so it must report "unresolved" rather than
  // retry forever.
  const hasIdentity = alertIdentityKeys(row).length > 0;
  return { status: hasIdentity ? "pending" : "unresolved", row: null };
}

function dedupeAndConsolidateAlertRows(rows, options = {}) {
  const preferLatestState = Boolean(options.preferLatestState);
  const allowedChannels = new Set(
    Array.isArray(options.channels)
      ? options.channels
      : ["prometheus", "telemetry", "email", "ticket", "log"]
  );
  const keyToGroup = new Map();
  const groups = [];

  (Array.isArray(rows) ? rows : []).forEach((row) => {
    if (!row || typeof row !== "object") {
      return;
    }
    const channel = normalizeAlertChannel(row);
    if (!allowedChannels.has(channel)) {
      return;
    }

    const candidateKeys = alertIdentityKeys(row);
    // A row with zero candidate keys (no name/service and no id at all) can't be matched
    // to anything -- give it a unique key so it still shows up as its own row instead of
    // silently colliding with every other keyless row under a single shared bucket.
    const lookupKeys = candidateKeys.length ? candidateKeys : [`row:${groups.length}:${Math.random()}`];
    let group = null;
    for (const key of lookupKeys) {
      if (keyToGroup.has(key)) {
        const candidate = keyToGroup.get(key);
        const incomingFingerprint = alertFingerprintValue(row);
        const candidateFingerprint = alertFingerprintValue(candidate?.row);
        // Strong, conflicting upstream identities must never be merged merely
        // because alert name/service/time happen to share a composite key.
        if (incomingFingerprint && candidateFingerprint && incomingFingerprint !== candidateFingerprint) {
          continue;
        }
        group = candidate;
        break;
      }
    }

    if (!group) {
      group = { row: { ...row, source_channel: channel, source_channels: [channel] }, channels: new Set([channel]) };
      groups.push(group);
    } else {
      group.channels.add(channel);
      const incomingScore = alertRowScore(row);
      const existingScore = alertRowScore(group.row);
      const incomingTime = alertTimeMs(row);
      const existingTime = alertTimeMs(group.row);
      const incomingIsLandingPad = row?._stream_kind === "landing_pad";
      const existingIsLandingPad = group.row?._stream_kind === "landing_pad";
      const shouldReplace = preferLatestState
        ? incomingTime > existingTime || (incomingTime === existingTime && incomingScore > existingScore)
        : existingIsLandingPad && !incomingIsLandingPad
          ? true
          : !existingIsLandingPad && incomingIsLandingPad
            ? false
          : incomingScore > existingScore || (incomingScore === existingScore && incomingTime > existingTime);
      const priorRow = group.row;
      const priorCanonicalId = [priorRow?.alert_id, priorRow?.id]
        .map((value) => String(value || "").trim())
        .find((value) => ALERT_UUID_PATTERN.test(value)) || "";
      const incomingCanonicalId = [row?.alert_id, row?.id]
        .map((value) => String(value || "").trim())
        .find((value) => ALERT_UUID_PATTERN.test(value)) || "";
      const priorApplication = alertApplicationCandidate(group.row);
      const incomingApplication = alertApplicationCandidate(row);
      if (shouldReplace) {
        group.row = { ...row, source_channel: channel };
        if (!alertApplicationCandidate(group.row) && priorApplication) {
          group.row.application = priorApplication;
        }
      } else if (!priorApplication && incomingApplication) {
        group.row.application = incomingApplication;
      }
      // Landing-pad occurrences can be newer than their canonical database
      // row regardless of input order. Their filename is not an alert
      // identity, so always merge the UUID and downstream relationship fields
      // from the row that was not selected as the display state.
      const canonicalId = incomingCanonicalId || priorCanonicalId;
      const selectedCanonicalId = [group.row?.alert_id, group.row?.id]
        .map((value) => String(value || "").trim())
        .find((value) => ALERT_UUID_PATTERN.test(value)) || "";
      if (!selectedCanonicalId && canonicalId) {
        group.row.id = canonicalId;
        group.row.alert_id = canonicalId;
      }
      const relationshipRow = shouldReplace ? priorRow : row;
      ["incident_id", "ticket_id", "jira_key", "jira_url", "incident_projection", "correlation_id", "trace_id"]
        .forEach((field) => {
          if (!group.row[field] && relationshipRow?.[field]) group.row[field] = relationshipRow[field];
        });
    }

    // Register every candidate key from this row against the resolved group so a later
    // row matching via a *different* one of these keys still merges into the same group.
    lookupKeys.forEach((key) => keyToGroup.set(key, group));
  });

  return groups
    .map((entry) => ({
      ...entry.row,
      source_channels: Array.from(entry.channels).sort(),
    }))
    .sort((a, b) => alertTimeMs(b) - alertTimeMs(a));
}

function mapClosedIncidentToAlertStreamRow(row) {
  const payload = row?.projection_payload && typeof row.projection_payload === "object" ? row.projection_payload : {};
  const eventPayload = payload?.event_payload && typeof payload.event_payload === "object" ? payload.event_payload : {};
  const service = String(row?.service || eventPayload.service || "-").trim();
  const incidentId = String(row?.incident_id || row?.flow_id || "").trim();
  const alertId = String(row?.alert_id || incidentId || "").trim();
  const status = String(row?.status || "closed").trim();
  const closedAt = String(row?.closed_at || row?.updated_at || "").trim();
  const alertName = String(
    row?.alert_name
    || row?.name
    || eventPayload.alert_name
    || eventPayload.alert_type
    || (service && service !== "-" ? `${service} closed incident` : "Closed incident")
  ).trim();
  return {
    ...row,
    alert_id: alertId,
    id: alertId || incidentId,
    incident_id: incidentId,
    name: alertName,
    alert_name: alertName,
    rule_name: row?.rule_name || row?.alert_type || eventPayload.alert_type || alertName,
    application: row?.application || row?.project_name || row?.project || service,
    service,
    severity: row?.severity || "info",
    status,
    state: status,
    created_at: closedAt || row?.created_at || row?.updated_at,
    starts_at: row?.starts_at || closedAt,
    closed_at: closedAt,
    source: row?.source || "closed-incidents",
    _stream_kind: "recent_closed",
    _closed_incident: true,
    annotations: {
      ...(row?.annotations || {}),
      description: eventPayload.action_taken || row?.summary || "Recently closed incident.",
    },
  };
}

function projectHintFromAlertRow(row) {
  const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
  const candidates = [
    row?.application,
    row?.project_name,
    row?.project,
    labels?.application,
    labels?.project_name,
    labels?.project,
  ]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  return candidates[0] || "";
}

const ALERT_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function mapLandingPadRowToAlertStreamRow(row, index = 0) {
  const payload = row && typeof row === "object" ? row : {};
  const labels = typeof payload.labels === "object" && payload.labels ? payload.labels : {};
  const alertIdentity = String(payload.alert_id || payload.id || payload.file || `landing-${index + 1}`).trim();
  const alertName = String(payload.name || payload.alert_name || payload.alertname || labels.alertname || "Landing Pad Alert").trim();
  const channel = normalizeAlertChannel(payload);
  return {
    ...payload,
    id: alertIdentity,
    alert_id: String(payload.alert_id || alertIdentity).trim(),
    // Alert identity is not incident identity. Keep this empty until the
    // backend returns a persisted incident projection for the alert.
    incident_id: String(payload.incident_id || "").trim(),
    name: alertName,
    alert_name: alertName,
    application: String(payload.application || payload.project_name || payload.project || labels.application || labels.project || labels.project_name || "").trim(),
    service: String(payload.service || labels.service || labels.job || "-").trim(),
    severity: String(payload.severity || labels.severity || "warning").trim().toLowerCase(),
    status: String(payload.alert_status || payload.status || "open").trim().toLowerCase(),
    state: String(payload.state || payload.alert_status || payload.status || "open").trim().toLowerCase(),
    created_at: payload.received_at || payload.created_at || payload.starts_at || payload.modified_at || payload.updated_at || "",
    starts_at: payload.starts_at || payload.received_at || payload.created_at || "",
    source: String(payload.source || payload.provider || payload.channel || "landing-pad").trim(),
    source_channel: channel,
    _stream_kind: "landing_pad",
  };
}

// An alert the operator explicitly opened can legitimately fall out of the
// summary list's scope without having stopped existing: closure moves it from
// the open-alerts stream to the closed-incidents stream on its own refresh
// cadence (the two fetches are not atomic), and monitor-scope filtering can
// exclude a row the summary list wasn't scoped for. A dedicated,
// already-loaded /processed-result payload for this exact alertId is the
// authoritative signal that the alert is real -- list membership is not.
function shouldRetainAlertSelection({ selectedAlertId, payload, error, alertId }) {
  return Boolean(
    payload
    && !error
    && String(alertId || "") === String(selectedAlertId || "")
  );
}

function mergeAlertStreamRows(openRows, recentClosedRows) {
  const merged = [];
  const seen = new Set();
  const add = (row) => {
    if (!row || typeof row !== "object") {
      return;
    }
    const key = String(row.alert_id || row.id || row.incident_id || "").trim();
    if (key && seen.has(key)) {
      return;
    }
    if (key) {
      seen.add(key);
    }
    merged.push(row);
  };
  (Array.isArray(openRows) ? openRows : []).forEach(add);
  (Array.isArray(recentClosedRows) ? recentClosedRows : []).map(mapClosedIncidentToAlertStreamRow).forEach(add);
  return dedupeAndConsolidateAlertRows(
    merged,
    { channels: ["prometheus", "telemetry", "email", "ticket", "log"] }
  );
}

function onboardingSourceDocCategoryLabel(category) {
  const key = String(category || "other").trim();
  if (key === "knowledge_pack") {
    return "Service Knowledge";
  }
  return ONBOARDING_SOURCE_DOC_BUCKETS.find((bucket) => bucket.key === key)?.label || "Other Evidence";
}

function fallbackFetchTargets(path) {
  const normalized = String(path || "").trim();
  if (!normalized) {
    return [];
  }
  const targets = [normalized];
  const processedResultPrefix = "/monitoring-adapter/alerts/";
  const processedResultSuffix = "/processed-result";
  if (normalized.startsWith(processedResultPrefix) && normalized.endsWith(processedResultSuffix)) {
    const alertId = normalized.slice(processedResultPrefix.length, normalized.length - processedResultSuffix.length);
    if (alertId) {
      targets.push(`/api-gateway/alerts/${alertId}/processed-result`);
    }
  }
  return Array.from(new Set(targets));
}

async function fetchJsonNetwork(path, options = {}) {
  const maxAttemptsRaw = Number(options?.maxAttempts);
  const maxAttempts = Number.isFinite(maxAttemptsRaw) && maxAttemptsRaw >= 1
    ? Math.min(Math.max(Math.floor(maxAttemptsRaw), 1), 4)
    : 3;
  let lastError = null;
  const { authenticated, onUnauthorized, maxAttempts: _maxAttempts, ...fetchOptions } = options || {};
  const targets = fallbackFetchTargets(path);
  const requestTarget = targets[0] || path;
  const timeoutMsRaw = Number(fetchOptions.timeoutMs);
  const timeoutMs = Number.isFinite(timeoutMsRaw) && timeoutMsRaw > 0 ? timeoutMsRaw : 15000;
  let refreshedAuthorizationHeaders = null;
  let refreshAttempted = false;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    for (const target of targets) {
      const controller = new AbortController();
      const abortFromCaller = () => controller.abort(fetchOptions.signal?.reason);
      fetchOptions.signal?.addEventListener("abort", abortFromCaller, { once: true });
      const timeoutHandle = setTimeout(() => controller.abort(new Error(`Request timeout after ${timeoutMs}ms`)), timeoutMs);
      try {
        let response = await fetch(target, {
          ...fetchOptions,
          signal: controller.signal,
          headers: {
            "Content-Type": "application/json",
            ...(fetchOptions.headers || {}),
            ...(refreshedAuthorizationHeaders || {}),
          },
        });

        if (response.status === 401 && authenticated && typeof onUnauthorized === "function" && !refreshAttempted) {
          refreshAttempted = true;
          const refreshHeaders = await onUnauthorized(await response.text(), requestTarget);
          if (refreshHeaders && typeof refreshHeaders === "object") {
            refreshedAuthorizationHeaders = refreshHeaders;
            response = await fetch(target, {
              ...fetchOptions,
              signal: controller.signal,
              headers: {
                "Content-Type": "application/json",
                ...(fetchOptions.headers || {}),
                ...refreshedAuthorizationHeaders,
              },
            });
          }
        }

        clearTimeout(timeoutHandle);
        fetchOptions.signal?.removeEventListener("abort", abortFromCaller);

        if (!response.ok) {
          const text = await response.text();
          if (response.status === 401 && authenticated) {
            throw new Error("Session expired. Please sign in again.");
          }
          const shouldRetry = response.status >= 500 && attempt < maxAttempts;
          if (shouldRetry) {
            await new Promise((resolve) => setTimeout(resolve, attempt * 500));
            break;
          }
          throw new Error(`HTTP ${response.status}: ${text || "request failed"}`);
        }

        const payload = await response.json();
        return parseInternalApiResponse(target, String(fetchOptions.method || "GET"), payload);
      } catch (error) {
        clearTimeout(timeoutHandle);
        fetchOptions.signal?.removeEventListener("abort", abortFromCaller);
        const message = String(error?.message || "");
        if (message === "Session expired. Please sign in again.") {
          throw error;
        }
        lastError = message === "Failed to fetch"
          ? new Error(`Failed to reach ${requestTarget}. Open the UI through http://localhost:8501 with Docker/nginx running, or use the Vite proxy with api-gateway on http://localhost:8010.`)
          : error;
        if (target !== targets[targets.length - 1]) {
          continue;
        }
        if (attempt < maxAttempts) {
          await new Promise((resolve) => setTimeout(resolve, attempt * 500));
        }
      }
    }
  }

  throw lastError || new Error("request failed");
}

async function fetchJson(path, options = {}) {
  const method = String(options?.method || "GET").toUpperCase();
  if (method !== "GET") {
    const mutation = queryClient.getMutationCache().build(queryClient, {
      mutationKey: ["api", method, String(path).split("?", 1)[0]],
      mutationFn: () => fetchJsonNetwork(path, options),
    });
    const result = await mutation.execute(undefined);
    await queryClient.invalidateQueries({ queryKey: ["api"] });
    return result;
  }
  const authorization = String(options?.headers?.Authorization || options?.headers?.authorization || "");
  const authScope = authorization ? "authenticated" : "public";
  return queryClient.fetchQuery({
    queryKey: ["api", authScope, String(path)],
    queryFn: ({ signal }) => fetchJsonNetwork(path, { ...options, signal }),
    staleTime: Number(options?.staleTimeMs || 0),
  });
}

function HealthBadge({ ok, label }) {
  return (
    <span className={`health ${ok ? "ok" : "error"}`}>
      <span className="health-dot" />
      {label}
    </span>
  );
}

function htmlEscape(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function asDisplayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch (_error) {
      return "[object]";
    }
  }
  return String(value);
}

function parseUtcTimestamp(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return null;
  }
  const normalized = /Z$|[+-]\d\d:\d\d$/.test(raw) ? raw : `${raw}Z`;
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed;
}

function formatIstTimestamp(value) {
  const parsed = parseUtcTimestamp(value);
  if (!parsed) {
    return "-";
  }
  return `${new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(parsed)} IST`;
}

function formatUtcTimestamp(value) {
  return formatIstTimestamp(value);
}

function clampQualityScore(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.min(Math.max(numeric, 0), 1);
}

function formatQualityPercent(value) {
  if (value === null || value === undefined || value === "") return "Unavailable";
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return "-";
  }
  return `${Math.round(clampQualityScore(numeric) * 100)}%`;
}

function qualityToneFromScore(value, inverse = false) {
  const score = clampQualityScore(value, inverse ? 1 : 0);
  const effective = inverse ? 1 - score : score;
  if (effective >= 0.82) {
    return "success";
  }
  if (effective >= 0.62) {
    return "warning";
  }
  return "error";
}

function normalizeEvaluationEnvelope(source = {}, fallback = {}) {
  const raw = source && typeof source === "object" ? source : {};
  const score = (value) => value === null || value === undefined || value === "" || !Number.isFinite(Number(value))
    ? null : clampQualityScore(value);
  const confidenceScore = score(raw.confidence_score ?? raw.confidenceScore ?? fallback.confidence);
  const groundingScore = score(raw.grounding_score ?? raw.groundingScore);
  const hallucinationRisk = score(raw.hallucination_risk ?? raw.hallucinationRisk);
  const hallucinationScore = score(raw.hallucination_score ?? raw.hallucinationScore);
  const citationCoverage = score(raw.citation_coverage ?? raw.citationCoverage);
  const evidenceCoverage = score(raw.evidence_coverage ?? raw.evidenceCoverage);
  const ragMatchScore = score(raw.rag_match_score ?? raw.ragMatchScore);
  const overallScore = score(raw.overall_score ?? raw.overallScore);
  const available = [overallScore, groundingScore, hallucinationRisk, citationCoverage, evidenceCoverage].some((value) => value !== null);
  return {
    contractVersion: raw.contract_version || "kaiops.evaluation.v1",
    provider: raw.provider || (available ? "recorded-evaluation" : "unavailable"),
    available,
    confidenceScore,
    groundingScore,
    hallucinationRisk,
    hallucinationScore,
    citationCoverage,
    evidenceCoverage,
    ragMatchScore,
    overallScore,
    qualityLabel: raw.quality_label || (overallScore === null ? "unavailable" : overallScore >= 0.82 ? "high" : overallScore >= 0.62 ? "medium" : "low"),
    requiresReview: Boolean(raw.requires_review ?? (!available || hallucinationRisk >= 0.45 || groundingScore < 0.55 || confidenceScore < 0.65)),
    externalJudge: raw.external_judge && typeof raw.external_judge === "object" ? raw.external_judge : {},
    signals: raw.signals && typeof raw.signals === "object" ? raw.signals : {},
  };
}

function elapsedSeconds(start, end) {
  const startDate = parseUtcTimestamp(start);
  const endDate = parseUtcTimestamp(end);
  if (!startDate || !endDate) {
    return "-";
  }
  const delta = Math.max(0, endDate.getTime() - startDate.getTime());
  return (delta / 1000).toFixed(3);
}

function normalizeTraceServiceName(event) {
  const eventType = String(event?.event_type || "").trim().toLowerCase();
  if (eventType.includes("closure")) {
    return "closure-service";
  }
  if (eventType.includes("recommendation") || eventType.includes("resolution")) {
    return "resolution-agent";
  }
  if (eventType.includes("approval")) {
    return "approval-service";
  }
  if (eventType.includes("context")) {
    return "context-agent";
  }
  if (eventType.includes("workflow") || eventType.includes("orchestration")) {
    return "orchestrator";
  }
  if (eventType.includes("remediation")) {
    return "remediation-engine";
  }

  const rawService = String(event?.service || "").trim();
  if (!rawService) {
    return "-";
  }
  if (!looksLikeUuid(rawService)) {
    return rawService;
  }
  return "monitoring-adapter";
}

function routeForAgent(agentName) {
  const rawNeedle = String(agentName || "").trim().toLowerCase();
  const needle = AGENT_ROUTE_ALIASES[rawNeedle] || rawNeedle;
  if (!needle) {
    return null;
  }
  return (
    SERVICE_TOPIC_FLOW.find((row) => String(row?.agent || "").trim().toLowerCase() === needle) || null
  );
}

function displayAgentName(agentName) {
  const token = String(agentName || "").trim();
  if (!token) {
    return "-";
  }
  const alias = AGENT_DISPLAY_ALIASES[token.toLowerCase()];
  return alias ? `${alias} (${token})` : token;
}

function compactText(value, maxLength = 180) {
  const text = String(value || "").trim();
  if (!text) {
    return "";
  }
  return text.length > maxLength ? `${text.slice(0, Math.max(24, maxLength - 1))}...` : text;
}

function hasMeaningfulValue(value) {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value === "string") {
    const normalized = value.trim();
    return Boolean(normalized && normalized !== "-");
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (typeof value === "object") {
    return Object.keys(value).length > 0;
  }
  return true;
}

function stringifyTimelineValue(value) {
  if (!hasMeaningfulValue(value)) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch (_error) {
    return String(value);
  }
}

function isFailureStatus(value) {
  const token = String(value || "").trim().toLowerCase();
  if (!token) {
    return false;
  }
  return ["fail", "failed", "failure", "error", "exception", "rejected", "timeout", "denied"].some((flag) => token.includes(flag));
}

function normalizeApprovalStatus(value) {
  return String(value || "").trim().toLowerCase();
}

function canonicalIncidentStatus(...values) {
  const statuses = values
    .flat()
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean);
  if (!statuses.length) {
    return "unknown";
  }

  const terminalPriority = ["closed", "resolved", "failed", "cancelled", "canceled"];
  const terminal = terminalPriority.find((candidate) => statuses.includes(candidate));
  return terminal || statuses[0];
}

function isApprovalResolvedStatus(value) {
  const token = normalizeApprovalStatus(value);
  if (!token) {
    return false;
  }
  return ["approved", "rejected", "closed", "resolved", "failed", "cancelled", "canceled"].includes(token);
}

function isApprovalPendingStatus(value) {
  const token = normalizeApprovalStatus(value);
  if (!token) {
    return false;
  }
  return ["awaiting_approval", "pending", "queued", "awaiting user approval", "standby"].includes(token);
}

function statusPillClass(value) {
  const token = normalizeApprovalStatus(value);
  if (!token) {
    return "status-open";
  }
  if (token.includes("approved")) {
    return "status-approved";
  }
  if (token.includes("rejected")) {
    return "status-rejected";
  }
  if (token.includes("closed") || token.includes("resolved")) {
    return "status-closed";
  }
  if (token.includes("failed") || token.includes("error") || token.includes("blocked") || token.includes("denied")) {
    return "status-failed";
  }
  const normalized = token.replace(/[^a-z0-9]+/g, "_");
  return normalized ? `status-${normalized}` : "status-open";
}

function extractEventError(event) {
  if (!event || typeof event !== "object") {
    return "";
  }
  const status = String(event.status || "").trim();
  const candidates = [
    event.error,
    event.errors,
    event.exception,
    event.failure,
    event.failure_reason,
    event.error_message,
    event.detail,
    event.message,
  ];
  const hit = candidates.find((item) => hasMeaningfulValue(item));
  if (hit !== undefined) {
    return stringifyTimelineValue(hit);
  }
  if (isFailureStatus(status)) {
    const reason = hasMeaningfulValue(event.policy_reason) ? stringifyTimelineValue(event.policy_reason) : "";
    return reason || `Status: ${status}`;
  }
  return "";
}

function extractEventInput(event) {
  if (!event || typeof event !== "object") {
    return null;
  }
  const payload = typeof event.payload === "object" && event.payload ? event.payload : null;
  const candidates = [
    event.input_value,
    event.input,
    event.input_payload,
    event.request,
    event.context,
    event.source_payload,
    payload?.input,
    payload?.request,
    payload?.context,
  ];
  const hit = candidates.find((item) => hasMeaningfulValue(item));
  return hit === undefined ? null : hit;
}

function extractEventOutput(event) {
  if (!event || typeof event !== "object") {
    return null;
  }
  const payload = typeof event.payload === "object" && event.payload ? event.payload : null;
  const candidates = [
    event.output_value,
    event.output,
    event.result,
    payload,
    event.response,
    event.recommendation,
    event.decision,
  ];
  const hit = candidates.find((item) => hasMeaningfulValue(item));
  if (!hasMeaningfulValue(hit)) {
    return null;
  }
  const eventType = String(event.event_type || "").trim();
  if (typeof hit === "string" && eventType && hit.trim() === eventType && hasMeaningfulValue(payload)) {
    return payload;
  }
  return hit;
}

function buildPreviewExecutionPlan(workflow) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const recommendation = typeof safeWorkflow.recommendation === "object" && safeWorkflow.recommendation ? safeWorkflow.recommendation : {};
  const incident = typeof safeWorkflow.incident === "object" && safeWorkflow.incident ? safeWorkflow.incident : {};
  const alert = typeof safeWorkflow.alert === "object" && safeWorkflow.alert ? safeWorkflow.alert : {};

  const target = String(
    recommendation?.metadata?.remediation_target
    || recommendation?.target
    || incident?.service
    || alert?.service
    || "unknown-target"
  ).trim();
  const environment = String(incident?.environment || alert?.environment || "prod").trim() || "prod";
  const recommendationText = String(recommendation?.recommended_action || "rollback deployment").trim() || "rollback deployment";
  const lowered = recommendationText.toLowerCase();

  const actionType = lowered.includes("restart pod")
    ? "restart_pod"
    : lowered.includes("scale")
      ? "scale_deployment"
      : lowered.includes("restart service")
        ? "restart_service"
        : lowered.includes("cache")
          ? "clear_cache"
          : lowered.includes("failover") || lowered.includes("database")
            ? "failover_database"
            : lowered.includes("terraform")
              ? "terraform_rollback"
              : "rollback_deployment";

  const preview = {
    commands: [],
    scripts: [],
    queries: [],
  };

  if (actionType === "restart_pod") {
    preview.commands = [
      `kubectl rollout restart deployment/${target} -n ${environment}`,
      `kubectl rollout status deployment/${target} -n ${environment} --timeout=180s`,
    ];
    preview.scripts = [`scripts/remediation/restart_pod.ps1 -Service ${target} -Namespace ${environment}`];
    preview.queries = [`sum(rate(http_requests_total{service='${target}',status=~'5..'}[5m]))`];
  } else if (actionType === "scale_deployment") {
    preview.commands = [
      `kubectl scale deployment/${target} --replicas=3 -n ${environment}`,
      `kubectl rollout status deployment/${target} -n ${environment} --timeout=180s`,
    ];
    preview.scripts = [`scripts/remediation/scale_deployment.ps1 -Service ${target} -Namespace ${environment} -Replicas 3`];
    preview.queries = [`avg_over_time(container_cpu_usage_seconds_total{pod=~'${target}.*'}[10m])`];
  } else if (actionType === "restart_service") {
    preview.commands = [`ansible-playbook playbooks/restart-service.yml -e service=${target} -e env=${environment}`];
    preview.scripts = [`scripts/remediation/restart_service.ps1 -Service ${target} -Environment ${environment}`];
    preview.queries = [`max_over_time(up{job='${target}'}[5m])`];
  } else if (actionType === "clear_cache") {
    preview.commands = [`redis-cli -h ${target}-redis -n 0 FLUSHDB`];
    preview.scripts = [`scripts/remediation/clear_cache.ps1 -Service ${target}`];
    preview.queries = [`sum(rate(cache_miss_total{service='${target}'}[5m]))`];
  } else if (actionType === "failover_database") {
    preview.commands = ["mysql -e \"CALL mysql.rds_failover();\""];
    preview.scripts = ["scripts/remediation/failover_database.ps1"];
    preview.queries = ["SHOW REPLICA STATUS;"];
  } else if (actionType === "terraform_rollback") {
    preview.commands = [
      "terraform init",
      `terraform apply -auto-approve -var service=${target} -var rollback=true`,
    ];
    preview.scripts = [`scripts/remediation/terraform_rollback.ps1 -Service ${target} -Environment ${environment}`];
    preview.queries = [`sum(rate(terraform_apply_failures_total{service='${target}'}[15m]))`];
  } else {
    preview.commands = [
      `kubectl rollout undo deployment/${target} -n ${environment}`,
      `kubectl rollout status deployment/${target} -n ${environment} --timeout=180s`,
    ];
    preview.scripts = [`scripts/remediation/rollback_deployment.ps1 -Service ${target} -Namespace ${environment}`];
    preview.queries = [`sum(rate(http_requests_total{service='${target}',status=~'5..'}[5m]))`];
  }

  return {
    actionType,
    recommendationText,
    plan: preview,
  };
}

function deriveExecutionCommands(workflow, traceRows) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeTraceRows = Array.isArray(traceRows) ? traceRows : [];
  const recommendation = typeof safeWorkflow.recommendation === "object" && safeWorkflow.recommendation ? safeWorkflow.recommendation : {};
  const recommendationMetadata = typeof recommendation.metadata === "object" && recommendation.metadata ? recommendation.metadata : {};
  const remediationAction = typeof safeWorkflow.remediation_action === "object" && safeWorkflow.remediation_action ? safeWorkflow.remediation_action : {};
  const decision =
    (typeof safeWorkflow.decision === "object" && safeWorkflow.decision)
    || (typeof safeWorkflow.orchestration_decision === "object" && safeWorkflow.orchestration_decision)
    || (typeof recommendationMetadata.orchestration_decision === "object" && recommendationMetadata.orchestration_decision)
    || {};

  const explicit =
    (Array.isArray(recommendation.commands) && recommendation.commands)
    || (Array.isArray(remediationAction.commands) && remediationAction.commands)
    || (Array.isArray(decision.commands) && decision.commands)
    || [];
  const derived = [];
  const seen = new Set();
  const pushUnique = (value, prefix = "") => {
    const token = String(value || "").trim();
    if (!token) {
      return;
    }
    const line = `${prefix}${token}`;
    const key = line.toLowerCase();
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    derived.push(line);
  };

  const pushPlan = (plan) => {
    if (!plan || typeof plan !== "object") {
      return;
    }
    (Array.isArray(plan.commands) ? plan.commands : []).forEach((item) => pushUnique(item, "cmd: "));
    (Array.isArray(plan.scripts) ? plan.scripts : []).forEach((item) => pushUnique(item, "script: "));
    (Array.isArray(plan.queries) ? plan.queries : []).forEach((item) => pushUnique(item, "query: "));
    (Array.isArray(plan.validation_commands) ? plan.validation_commands : []).forEach((item) => pushUnique(item, "query: "));
  };

  explicit.forEach((item) => pushUnique(item, "cmd: "));

  // Prefer the governed catalog contract when model analysis is diagnostic-only.
  pushPlan(recommendationMetadata.execution_plan);

  const remediationParams = typeof remediationAction.parameters === "object" && remediationAction.parameters
    ? remediationAction.parameters
    : {};
  pushPlan(remediationParams.execution_plan);
  (Array.isArray(remediationParams.commands) ? remediationParams.commands : []).forEach((item) => pushUnique(item, "cmd: "));

  safeTraceRows.forEach((row) => {
    const payload = typeof row?.payload === "object" && row.payload ? row.payload : {};
    pushPlan(payload?.execution_plan);

    const payloadAction = typeof payload?.remediation_action === "object" && payload.remediation_action ? payload.remediation_action : {};
    const payloadParams = typeof payloadAction.parameters === "object" && payloadAction.parameters ? payloadAction.parameters : {};
    pushPlan(payloadParams.execution_plan);
    (Array.isArray(payloadParams.commands) ? payloadParams.commands : []).forEach((item) => pushUnique(item, "cmd: "));

    const commands = Array.isArray(payload?.commands) ? payload.commands : [];
    commands.forEach((item) => pushUnique(item, "cmd: "));
  });

  return derived;
}

function remediationOutcomeFromAction(action) {
  const safeAction = action && typeof action === "object" ? action : {};
  const status = String(safeAction.status || "").trim().toLowerCase();
  const error = String(safeAction.error || "").trim();
  const output = String(safeAction.output || "").trim();
  const parameters = safeAction.parameters && typeof safeAction.parameters === "object" ? safeAction.parameters : {};
  const executionResult = parameters.execution_result && typeof parameters.execution_result === "object"
    ? parameters.execution_result
    : {};
  const executorError = String(executionResult.stderr || executionResult.error || "").trim();
  const executorOutput = String(executionResult.stdout || "").trim();
  const reason = error || executorError || output || executorOutput || "";
  const actionType = String(safeAction.action_type || "").trim().toLowerCase();
  const automaticPolicyBlocked = actionType === "policy-blocked" || /auto(?:matic)? execution blocked/i.test(reason);

  if (!status && !reason) {
    return null;
  }

  let title = "Remediation status";
  if (actionType === "diagnostic_completion" && status === "skipped") title = "Diagnostic assessment completed";
  else if (status === "succeeded") {
    title = "Remediation executed successfully";
  } else if (automaticPolicyBlocked) {
    title = "Human approval required";
  } else if (status === "skipped") {
    title = "Remediation was not executed";
  } else if (["failed", "dispatch_failed", "execution_failed", "validation_failed", "rollback_failed", "timed_out"].includes(status)) {
    title = "Remediation execution failed";
  } else if (status === "executor_accepted") {
    title = "Executor accepted the remediation";
  } else if (status === "dispatching") {
    title = "Dispatching remediation";
  } else if (status === "verifying") {
    title = "Verifying recovery";
  } else if (status === "rolled_back") {
    title = "Remediation rolled back";
  }

  let detail = reason || `Remediation engine returned status ${status || "unknown"}.`;
  if (actionType === "diagnostic_completion" && status === "skipped") detail = reason || "Diagnostic evidence was recorded and no corrective action was required.";
  if (automaticPolicyBlocked) {
    detail = `${reason || "Automatic execution did not meet the policy threshold."} Review and approve the plan, then confirm execution.`;
  }
  if (/no real .*executor is configured/i.test(detail) || /configure a connector executor/i.test(detail)) {
    detail = `${detail} Add a real remediation connector with executor settings and secret_ref, or edit the plan to use the approved local triage script.`;
  }

  return {
    status: status || "unknown",
    title,
    detail,
    actionType: safeAction.action_type || "-",
    target: safeAction.target || "-",
    automaticPolicyBlocked,
  };
}

function shellArg(value) {
  const token = String(value || "").trim();
  if (!token) {
    return "''";
  }
  if (/^[a-zA-Z0-9_./:@=-]+$/.test(token)) {
    return token;
  }
  return `'${token.replace(/'/g, "'\\''")}'`;
}

function buildKaiOpsRemediationScript({
  service,
  environment,
  apiGatewayUrl,
  prometheusUrl,
  mysqlHost,
  mysqlDatabase,
  mysqlUser,
} = {}) {
  return [
    "bash scripts/remediation/kaiops_alert_health_triage.sh",
    "--service", shellArg(service || "kaiops-service"),
    "--environment", shellArg(environment || "prod"),
    "--api-gateway-url", shellArg(apiGatewayUrl || "http://api-gateway:8000"),
    "--prometheus-url", shellArg(prometheusUrl || "http://prometheus:9090"),
    "--mysql-host", shellArg(mysqlHost || "mysql"),
    "--mysql-database", shellArg(mysqlDatabase || "kaiops"),
    "--mysql-user", shellArg(mysqlUser || "kaiops"),
    "--dry-run", "true",
  ].join(" ");
}

function firstTraceTimestamp(rows, predicate) {
  const safeRows = Array.isArray(rows) ? rows : [];
  const hit = safeRows.find((row) => {
    if (!row || typeof row !== "object") {
      return false;
    }
    return predicate(row);
  });
  return String(hit?.timestamp || "").trim();
}

function firstEventTimestamp(rows, predicate) {
  const safeRows = Array.isArray(rows) ? rows : [];
  const hit = safeRows.find((row) => {
    if (!row || typeof row !== "object") {
      return false;
    }
    return predicate(row);
  });
  return String(hit?.timestamp || "").trim();
}

function buildSyntheticFlowRows({ workflow, events, traceRows, ingestAt, incidentCreatedAt }) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeEvents = Array.isArray(events) ? events : [];
  const safeTraceRows = Array.isArray(traceRows) ? traceRows : [];

  const alert = typeof safeWorkflow.alert === "object" && safeWorkflow.alert ? safeWorkflow.alert : {};
  const incident = typeof safeWorkflow.incident === "object" && safeWorkflow.incident ? safeWorkflow.incident : {};
  const context = typeof safeWorkflow.context === "object" && safeWorkflow.context ? safeWorkflow.context : {};
  const contextMetadata = typeof context.metadata === "object" && context.metadata ? context.metadata : {};
  const recommendation = typeof safeWorkflow.recommendation === "object" && safeWorkflow.recommendation ? safeWorkflow.recommendation : {};
  const recommendationMetadata = typeof recommendation.metadata === "object" && recommendation.metadata ? recommendation.metadata : {};
  const remediationAction =
    typeof safeWorkflow.remediation_action === "object" && safeWorkflow.remediation_action
      ? safeWorkflow.remediation_action
      : {};
  const decision =
    (typeof safeWorkflow.decision === "object" && safeWorkflow.decision)
    || (typeof safeWorkflow.orchestration_decision === "object" && safeWorkflow.orchestration_decision)
    || (typeof recommendationMetadata.orchestration_decision === "object" && recommendationMetadata.orchestration_decision)
    || {};

  const contextTraceRow = safeTraceRows
    .slice()
    .reverse()
    .find((row) => String(row?.event_type || "").toLowerCase().includes("context"));
  const contextEventPayload = (contextTraceRow && typeof contextTraceRow.payload === "object" && contextTraceRow.payload)
    ? contextTraceRow.payload
    : {};
  const contextEventMetadata = typeof contextEventPayload?.metadata === "object" && contextEventPayload.metadata
    ? contextEventPayload.metadata
    : {};
  const contextAgentEvent = safeEvents
    .slice()
    .reverse()
    .find((event) => String(event?.agent || "").toLowerCase().includes("context intelligence"));
  const contextAgentDetails = typeof contextAgentEvent?.details === "object" && contextAgentEvent.details
    ? contextAgentEvent.details
    : {};
  const contextAgentMetrics = typeof contextAgentDetails?.metrics === "object" && contextAgentDetails.metrics
    ? contextAgentDetails.metrics
    : {};

  const ragMatches =
    (Array.isArray(contextMetadata.rag_matches) && contextMetadata.rag_matches)
    || (Array.isArray(recommendationMetadata.rag_matches) && recommendationMetadata.rag_matches)
    || (Array.isArray(contextEventMetadata.rag_matches) && contextEventMetadata.rag_matches)
    || (Array.isArray(contextAgentMetrics.rag_matches) && contextAgentMetrics.rag_matches)
    || [];

  const ragDocumentsRaw =
    contextMetadata.rag_documents
    ?? recommendationMetadata.rag_documents
    ?? contextEventMetadata.rag_documents
    ?? contextAgentMetrics.rag_documents
    ?? contextEventPayload.rag_document_count
    ?? null;
  const ragTopSimilarityRaw =
    contextMetadata.rag_top_similarity
    ?? recommendationMetadata.rag_top_similarity
    ?? contextEventMetadata.rag_top_similarity
    ?? null;
  const ragDocuments = ragDocumentsRaw === null || ragDocumentsRaw === undefined || ragDocumentsRaw === ""
    ? null
    : Number(ragDocumentsRaw);
  const ragTopSimilarity = ragTopSimilarityRaw === null || ragTopSimilarityRaw === undefined || ragTopSimilarityRaw === ""
    ? null
    : Number(ragTopSimilarityRaw);
  const runbookFound =
    Boolean(context.runbook)
    || Boolean(recommendationMetadata.runbook_found)
    || Boolean(contextEventPayload.document_available)
    || Boolean(contextEventMetadata.document_available)
    || Boolean(contextAgentMetrics.runbook_found);
  const ragDocumentDisplay = Number.isFinite(ragDocuments) ? ragDocuments : ragMatches.length;
  const executionCommands = deriveExecutionCommands(safeWorkflow, safeTraceRows);
  const traceEventTypes = safeTraceRows
    .map((row) => String(row?.event_type || "").trim())
    .filter(Boolean);

  const findTraceEvents = (needles) => {
    const tokens = Array.isArray(needles) ? needles : [];
    const matches = traceEventTypes.filter((eventType) => {
      const normalized = eventType.toLowerCase();
      return tokens.some((needle) => normalized.includes(String(needle || "").toLowerCase()));
    });
    return Array.from(new Set(matches));
  };
  const findTraceRows = (needles) => {
    const tokens = Array.isArray(needles) ? needles : [];
    return safeTraceRows.filter((row) => {
      const haystack = [
        row?.event_type,
        row?.event_stage,
        row?.source_channel,
        row?.transport_channel,
        row?.service_name,
      ].map((item) => String(item || "").toLowerCase()).join(" ");
      return tokens.some((needle) => haystack.includes(String(needle || "").toLowerCase()));
    });
  };

  const landingTimestamp =
    String(ingestAt || "").trim()
    || firstTraceTimestamp(safeTraceRows, (row) => {
      const eventType = String(row?.event_type || "").toLowerCase();
      const source = String(row?.source_channel || "").toLowerCase();
      return eventType.includes("alert") || source.includes("raw-alert");
    })
    || String(incidentCreatedAt || "").trim();

  const dedupeTimestamp =
    firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("alert intelligence"))
    || firstTraceTimestamp(safeTraceRows, (row) => String(row?.event_type || "").toLowerCase().includes("workflow"))
    || landingTimestamp;

  const configTimestamp =
    firstTraceTimestamp(safeTraceRows, (row) => {
      const eventType = String(row?.event_type || "").toLowerCase();
      const stage = String(row?.event_stage || "").toLowerCase();
      return eventType.includes("config") || eventType.includes("connection") || stage.includes("config");
    })
    || dedupeTimestamp;

  const contextTimestamp =
    firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("context intelligence"))
    || firstTraceTimestamp(safeTraceRows, (row) => String(row?.event_type || "").toLowerCase().includes("context"))
    || dedupeTimestamp;

  const routingTimestamp =
    firstTraceTimestamp(safeTraceRows, (row) => {
      const eventType = String(row?.event_type || "").toLowerCase();
      return eventType.includes("workflow.selected") || eventType.includes("recommendation.generated");
    })
    || firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("orchestrator"))
    || contextTimestamp;

  const recommendationTimestamp =
    firstTraceTimestamp(safeTraceRows, (row) => {
      const eventType = String(row?.event_type || "").toLowerCase();
      return eventType.includes("recommendation") || eventType.includes("resolution");
    })
    || firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("resolution"))
    || routingTimestamp;

  const approvalTimestamp =
    firstTraceTimestamp(safeTraceRows, (row) => String(row?.event_type || "").toLowerCase().includes("approval"))
    || firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("approval"))
    || recommendationTimestamp;

  const remediationTimestamp =
    String(remediationAction.completed_at || remediationAction.started_at || "").trim()
    || firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("remediation"))
    || firstTraceTimestamp(safeTraceRows, (row) => String(row?.event_type || "").toLowerCase().includes("remediation"))
    || approvalTimestamp;

  const closureTimestamp =
    firstTraceTimestamp(safeTraceRows, (row) => {
      const eventType = String(row?.event_type || "").toLowerCase();
      return eventType.includes("closure") || eventType.includes("validation");
    })
    || String(safeWorkflow?.closure_report?.completed_at || safeWorkflow?.closure_report?.created_at || "").trim()
    || "";

  const rows = [];
  const traceId = alert.trace_id || incident.trace_id || context.trace_id || recommendation.trace_id || remediationAction.trace_id || "";
  const pushBusRow = ({ flowOrder, stage, consumes, publishes, timestamp, detail, payload = {}, backendEvents = [] }) => {
    const observedBusRow = safeTraceRows
      .slice()
      .reverse()
      .find((row) => {
        const channel = String(row?.transport_channel || row?.source_channel || "").trim().toLowerCase();
        return channel === String(publishes || "").trim().toLowerCase();
      });
    const observedProvider = String(observedBusRow?.transport_provider || "").trim();
    const provider = observedProvider && observedProvider.toLowerCase() !== "unknown"
      ? observedProvider
      : (decision.message_bus_provider || "rabbitmq");
    rows.push({
      flowOrder,
      stage,
      agent: "Message Bus",
      service: provider,
      consumes,
      publishes,
      timestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, timestamp),
      detail,
      tables: "message_topics, incident_events",
      inputValueText: stringifyTimelineValue({
        provider,
        trace_id: traceId,
        ...payload,
      }),
      outputValueText: stringifyTimelineValue({
        delivered_to: publishes,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents,
    });
  };

  if (landingTimestamp || hasMeaningfulValue(alert)) {
    rows.push({
      flowOrder: 10,
      stage: "Alert Landed In Landing Pad",
      agent: "Monitoring Adapter",
      service: "monitoring-adapter",
      consumes: "provider webhook",
      publishes: "raw-alerts",
      timestamp: landingTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, landingTimestamp),
      detail: "Alert ingested from monitoring provider and staged for downstream workflow processing.",
      tables: "incident_events",
      inputValueText: stringifyTimelineValue({
        source: alert.source,
        name: alert.name,
        service: alert.service,
        severity: alert.severity,
      }),
      outputValueText: stringifyTimelineValue({
        correlation_id: alert.correlation_id,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["alert", "incident.opened", "incident.created"]),
    });
    pushBusRow({
      flowOrder: 20,
      stage: "Raw Alert Topic Handoff",
      consumes: "provider webhook",
      publishes: "raw-alerts",
      timestamp: landingTimestamp,
      detail: "Landing pad publishes the normalized alert envelope onto the raw-alerts topic for alert intelligence workers.",
      payload: {
        source_service: "monitoring-adapter",
        target_service: "alert-intelligence",
        topic: "raw-alerts",
      },
      backendEvents: findTraceEvents(["alert", "raw-alerts"]),
    });
  }

  if (hasMeaningfulValue(alert.deduplicated_count) || dedupeTimestamp) {
    rows.push({
      flowOrder: 30,
      stage: "Deduplication And Incident Correlation",
      agent: "Alert Intelligence Agent",
      service: "alert-intelligence",
      consumes: "raw-alerts",
      publishes: "enriched-alerts",
      timestamp: dedupeTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, dedupeTimestamp),
      detail: "Deduplication, severity classification, and incident correlation completed.",
      tables: "alerts, incidents, incident_events",
      inputValueText: stringifyTimelineValue({
        deduplicated_count: alert.deduplicated_count,
        correlation_id: alert.correlation_id,
        incident_id: incident.id,
      }),
      outputValueText: stringifyTimelineValue({
        incident_title: incident.title,
        severity: incident.severity,
        status: incident.status,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["workflow.selected", "context.collected"]),
    });
    pushBusRow({
      flowOrder: 40,
      stage: "Enriched Alert Topic Handoff",
      consumes: "raw-alerts",
      publishes: "enriched-alerts",
      timestamp: dedupeTimestamp,
      detail: "Alert intelligence publishes the correlated incident signal for orchestration routing.",
      payload: {
        source_service: "alert-intelligence",
        target_service: "orchestrator",
        incident_id: incident.id,
        topic: "enriched-alerts",
      },
      backendEvents: findTraceEvents(["workflow.selected", "enriched-alerts"]),
    });
  }

  if (hasMeaningfulValue(decision) || routingTimestamp) {
    rows.push({
      flowOrder: 50,
      stage: "Orchestrator Workflow Selection",
      agent: "Orchestrator Agent",
      service: "orchestrator",
      consumes: "enriched-alerts",
      publishes: "workflow request",
      timestamp: routingTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, routingTimestamp),
      detail: "Orchestrator selects the incident workflow, worker route, approval requirement, and execution policy.",
      tables: "incident_events, incident_projections, pending_workflows",
      inputValueText: stringifyTimelineValue({
        alert: alert.name,
        service: alert.service || incident.service,
        severity: alert.severity || incident.severity,
        incident_id: incident.id,
      }),
      outputValueText: stringifyTimelineValue({
        workflow: decision.workflow,
        next_action: decision.next_action,
        requires_approval: decision.requires_approval,
        risk_tier: decision.risk_tier,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["workflow.selected"]),
    });
  }

  rows.push({
    flowOrder: 60,
    stage: "Configuration And Connector Lookup",
    agent: "Config Service",
    service: "config",
    consumes: "workflow request",
    publishes: "connector profile",
    timestamp: configTimestamp,
    elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, configTimestamp),
    detail: "Service, environment, monitoring, message bus, RAG, and remediation connector settings resolved before agent execution.",
    tables: "kaiops-connections.json, service_profiles, connector registry",
    inputValueText: stringifyTimelineValue({
      service: alert.service || incident.service,
      environment: alert.environment || incident.environment,
      requested_profiles: ["monitoring", "message_bus", "rag", "remediation"],
    }),
    outputValueText: stringifyTimelineValue({
      monitoring_provider: decision.monitoring_provider || decision.provider || "prometheus",
      message_bus_provider: decision.message_bus_provider || "rabbitmq",
      workflow: decision.workflow || "guided-remediation",
      execution_mode: decision.execution_mode || "-",
      trace_id: traceId,
    }),
    errorValueText: "",
    backendEvents: findTraceEvents(["config", "connection", "workflow.selected"]),
  });
  pushBusRow({
    flowOrder: 70,
    stage: "Orchestration Event Topic Handoff",
    consumes: "workflow request + connector profile",
    publishes: "orchestration-events",
    timestamp: routingTimestamp,
    detail: "Orchestrator publishes the runnable work item for context-agent workers with config, policy, and trace metadata attached.",
    payload: {
      source_service: "orchestrator",
      target_service: "context-agent",
      topic: "orchestration-events",
      workflow: decision.workflow || "guided-remediation",
    },
    backendEvents: findTraceEvents(["workflow.selected", "orchestration-events"]),
  });

  if (ragDocuments > 0 || ragMatches.length || contextTimestamp) {
    rows.push({
      flowOrder: 80,
      stage: "RAG Context Retrieval",
      agent: "Context Intelligence Agent",
      service: "context-agent",
      consumes: "orchestration-events",
      publishes: "context-events",
      timestamp: contextTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, contextTimestamp),
      detail: "Context built from RAG corpus, dependencies, recent changes, and observability connectors.",
      tables: "incident_events, agent_work_items",
      inputValueText: stringifyTimelineValue({
        service: alert.service,
        deployment: context.deployment,
        related_incidents: Array.isArray(context.related_incidents) ? context.related_incidents.length : 0,
      }),
      outputValueText: stringifyTimelineValue({
        rag_documents: ragDocumentDisplay,
        rag_matches: ragMatches,
        runbook_found: runbookFound,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["context.collected"]),
    });
  }

  if (contextTimestamp || runbookFound || ragMatches.length) {
    rows.push({
      flowOrder: 90,
      stage: "Context Merge And Evidence Assembly",
      agent: "Context Intelligence Agent",
      service: "context-agent",
      consumes: "ranked rag matches + connector evidence",
      publishes: "context-events",
      timestamp: contextTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, contextTimestamp),
      detail: "RAG matches, dependency evidence, recent incidents, deployment metadata, and observability signals merged into one context payload.",
      tables: "incident_events, dependencies, changes, runbooks, agent_work_items",
      inputValueText: stringifyTimelineValue({
        documents_ranked: ragDocumentDisplay,
        dependency_count: Array.isArray(context.dependencies) ? context.dependencies.length : "-",
        related_incidents: Array.isArray(context.related_incidents) ? context.related_incidents.length : 0,
        connector_events: findTraceRows(["connector", "context"]).length,
      }),
      outputValueText: stringifyTimelineValue({
        runbook_found: runbookFound,
        document_available: Boolean(contextEventPayload.document_available || runbookFound),
        context_summary: context.summary || contextEventPayload.summary || "-",
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["context.collected", "connector", "dependency"]),
    });
    pushBusRow({
      flowOrder: 100,
      stage: "Context Event Topic Handoff",
      consumes: "orchestration-events",
      publishes: "context-events",
      timestamp: contextTimestamp,
      detail: "Context-agent publishes the assembled incident context for resolution-agent workers.",
      payload: {
        source_service: "context-agent",
        target_service: "resolution-agent",
        topic: "context-events",
        documents_ranked: ragDocumentDisplay,
      },
      backendEvents: findTraceEvents(["context.collected", "context-events"]),
    });
  }

  if (ragMatches.length || (typeof ragTopSimilarity === "number" && ragTopSimilarity > 0)) {
    rows.push({
      flowOrder: 85,
      stage: "Embedding And Semantic Search",
      agent: "VectorDB Connector",
      service: "context-agent",
      consumes: "context query",
      publishes: "ranked rag matches",
      timestamp: contextTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, contextTimestamp),
      detail: "Vector similarity and metadata ranking used to retrieve the most relevant runbook, incident, and deployment documents.",
      tables: "rag corpus",
      inputValueText: stringifyTimelineValue({
        query: `${alert.service || ""} ${alert.name || ""} ${alert.description || ""}`.trim(),
        rag_document_count: ragDocuments,
      }),
      outputValueText: stringifyTimelineValue({
        rag_top_similarity: ragTopSimilarity ?? "-",
        top_matches: ragMatches.slice(0, 5),
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["context.collected", "recommendation.generated"]),
    });
  }

  if (hasMeaningfulValue(recommendation) || recommendationTimestamp) {
    rows.push({
      flowOrder: 110,
      stage: "Resolution Recommendation Generated",
      agent: "Resolution Intelligence Agent",
      service: "resolution-agent",
      consumes: "context-events",
      publishes: "resolution-events",
      timestamp: recommendationTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, recommendationTimestamp),
      detail: "RCA, impact, recommended action, confidence, and operator-safe execution plan generated from the assembled context.",
      tables: "incident_events, recommendations, evaluation_records",
      inputValueText: stringifyTimelineValue({
        incident_id: incident.id || recommendation.incident_id,
        service: incident.service || alert.service,
        context_trace_id: context.trace_id || traceId,
      }),
      outputValueText: stringifyTimelineValue({
        recommendation_id: recommendation.id,
        root_cause: recommendation.root_cause,
        confidence: recommendation.confidence,
        grounding_score: recommendationMetadata.grounding_score,
        hallucination_score: recommendationMetadata.hallucination_score,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["recommendation.generated", "resolution"]),
    });
    pushBusRow({
      flowOrder: 120,
      stage: "Resolution Event Topic Handoff",
      consumes: "context-events",
      publishes: "resolution-events",
      timestamp: recommendationTimestamp,
      detail: "Resolution-agent publishes RCA, impact, confidence, and the editable remediation plan for approval routing.",
      payload: {
        source_service: "resolution-agent",
        target_service: "approval-service",
        topic: "resolution-events",
        recommendation_id: recommendation.id,
      },
      backendEvents: findTraceEvents(["recommendation.generated", "resolution-events"]),
    });
  }

  if (approvalTimestamp || hasMeaningfulValue(recommendation.id)) {
    rows.push({
      flowOrder: 130,
      stage: "Human Approval Gate",
      agent: "Approval Service",
      service: "approval-service",
      consumes: "resolution-events",
      publishes: "approval-events",
      timestamp: approvalTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, approvalTimestamp),
      detail: "Recommendation and editable remediation plan presented for human approval before execution.",
      tables: "approvals, pending_workflows, incident_events",
      inputValueText: stringifyTimelineValue({
        recommendation_id: recommendation.id,
        risk_tier: decision.risk_tier,
        requires_approval: decision.requires_approval ?? true,
        approver_role: decision.approver_role || "L2/L3/Admin",
      }),
      outputValueText: stringifyTimelineValue({
        approval_status: remediationAction.approval_id ? "approved" : "pending",
        approval_id: remediationAction.approval_id,
        editable_plan: true,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["approval.requested", "approval.recorded"]),
    });
    pushBusRow({
      flowOrder: 140,
      stage: "Approval Event Topic Handoff",
      consumes: "resolution-events",
      publishes: "approval-events",
      timestamp: approvalTimestamp,
      detail: "Approval-service publishes the human decision and edited execution plan for remediation-engine workers.",
      payload: {
        source_service: "approval-service",
        target_service: "remediation-engine",
        topic: "approval-events",
        approval_id: remediationAction.approval_id,
      },
      backendEvents: findTraceEvents(["approval.recorded", "approval-events"]),
    });
  }

  if (executionCommands.length || hasMeaningfulValue(remediationAction.output) || remediationTimestamp) {
    const remediationParameters =
      typeof remediationAction.parameters === "object" && remediationAction.parameters
        ? remediationAction.parameters
        : {};
    const executionPlan =
      typeof remediationParameters.execution_plan === "object" && remediationParameters.execution_plan
        ? remediationParameters.execution_plan
        : {};
    const executionResult =
      typeof remediationParameters.execution_result === "object" && remediationParameters.execution_result
        ? remediationParameters.execution_result
        : {};
    const remediationExecuted = hasMeaningfulValue(remediationAction.status) || hasMeaningfulValue(remediationAction.output);
    const executedLive = executionResult.executed === true || String(remediationAction.status || "").toLowerCase() === "succeeded";
    const skippedExecution = String(remediationAction.status || "").toLowerCase() === "skipped" || executionResult.executed === false;
    rows.push({
      flowOrder: 150,
      stage: "Remediation Command Execution",
      agent: "Remediation Automation Engine",
      service: "remediation-engine",
      consumes: "approval-events",
      publishes: "remediation-events",
      timestamp: remediationTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, remediationTimestamp),
      detail: executedLive
        ? "Approved remediation was executed by the configured backend executor and the execution result was captured."
        : skippedExecution
          ? "Approved remediation was not executed because no live executor/connector is configured; the approved command plan is preserved for operator action."
          : "Remediation command/script/query plan is waiting for approval or executor dispatch.",
      tables: "actions, audit_logs, incident_events",
      inputValueText: stringifyTimelineValue({
        mode: executedLive ? "live_executed" : skippedExecution ? "not_executed" : "pending_dispatch",
        action_type: remediationAction.action_type,
        target: remediationAction.target,
        executor: executionResult.executor,
        commands: Array.isArray(executionPlan.commands) ? executionPlan.commands : executionCommands,
        scripts: Array.isArray(executionPlan.scripts) ? executionPlan.scripts : [],
        queries: Array.isArray(executionPlan.queries) ? executionPlan.queries : [],
      }),
      outputValueText: stringifyTimelineValue({
        status: remediationAction.status || (remediationExecuted ? "-" : "pending"),
        executed: executionResult.executed,
        reason: executionResult.reason,
        output: remediationAction.output,
        error: remediationAction.error,
        trace_id: traceId,
      }),
      errorValueText: stringifyTimelineValue(remediationAction.error),
      backendEvents: findTraceEvents(["remediation.executed", "closure.completed"]),
    });
    pushBusRow({
      flowOrder: 160,
      stage: "Remediation Event Topic Handoff",
      consumes: "approval-events",
      publishes: "remediation-events",
      timestamp: remediationTimestamp,
      detail: "Remediation-engine publishes execution status, output, and connector result for closure validation.",
      payload: {
        source_service: "remediation-engine",
        target_service: "closure-service",
        topic: "remediation-events",
        action_id: remediationAction.id,
        status: remediationAction.status,
      },
      backendEvents: findTraceEvents(["remediation.executed", "remediation-events"]),
    });
  }

  if (closureTimestamp) {
    rows.push({
      flowOrder: 170,
      stage: "Closure Validation And Incident Update",
      agent: "Closure & Validation",
      service: "closure-service",
      consumes: "remediation-events",
      publishes: "closure-events",
      timestamp: closureTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, closureTimestamp),
      detail: "Post-remediation validation updates incident status, evidence, audit trail, and cockpit projection.",
      tables: "incident_events, incident_projections, actions, audit_logs",
      inputValueText: stringifyTimelineValue({
        remediation_status: remediationAction.status,
        action_id: remediationAction.id,
      }),
      outputValueText: stringifyTimelineValue({
        health_restored: safeWorkflow?.closure_report?.health_restored,
        incident_status: incident.status,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["closure.completed", "validation"]),
    });
  }

  return rows;
}

function summarizeEventType(value) {
  const token = String(value || "").trim();
  if (!token) {
    return "Workflow Event";
  }
  return token
    .split(".")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" -> ");
}

function timelinePhaseOrder(row) {
  const explicitOrder = Number(row?.flowOrder);
  if (Number.isFinite(explicitOrder) && explicitOrder > 0) {
    return explicitOrder;
  }
  const stage = String(row?.stage || "").toLowerCase();
  const eventHints = Array.isArray(row?.backendEvents)
    ? row.backendEvents.map((item) => String(item || "").toLowerCase())
    : [];
  const haystack = `${stage} ${eventHints.join(" ")}`;

  if (haystack.includes("landing pad") || haystack.includes("alert received") || haystack.includes("alert landed") || haystack.includes("incident.alert")) {
    return 10;
  }
  if (haystack.includes("raw alert topic")) {
    return 20;
  }
  if (haystack.includes("dedup") || haystack.includes("correlation") || haystack.includes("enrich")) {
    return 30;
  }
  if (haystack.includes("enriched alert topic")) {
    return 40;
  }
  if (haystack.includes("routing") || haystack.includes("orchestrator") || haystack.includes("workflow.selected")) {
    return 50;
  }
  if (haystack.includes("config") || haystack.includes("connector lookup") || haystack.includes("connection")) {
    return 60;
  }
  if (haystack.includes("orchestration event topic")) {
    return 70;
  }
  if (haystack.includes("rag context") || haystack.includes("context retrieval") || haystack.includes("context intelligence") || haystack.includes("incident.context.collected")) {
    return 80;
  }
  if (haystack.includes("embedding") || haystack.includes("semantic") || haystack.includes("vector")) {
    return 85;
  }
  if (haystack.includes("context merge") || haystack.includes("evidence assembly")) {
    return 90;
  }
  if (haystack.includes("context event topic")) {
    return 100;
  }
  if (haystack.includes("recommendation") || haystack.includes("resolution")) {
    return 110;
  }
  if (haystack.includes("policy")) {
    return 115;
  }
  if (haystack.includes("resolution event topic")) {
    return 120;
  }
  if (haystack.includes("approval")) {
    return 130;
  }
  if (haystack.includes("approval event topic")) {
    return 140;
  }
  if (haystack.includes("remediation") || haystack.includes("command") || haystack.includes("execute")) {
    return 150;
  }
  if (haystack.includes("remediation event topic")) {
    return 160;
  }
  if (haystack.includes("closure") || haystack.includes("validation")) {
    return 170;
  }
  return 99;
}

function buildAlertDocumentDrafts(alertRow, workflowPayload) {
  const alertName = String(alertRow?.name || alertRow?.alert_name || "Alert").trim();
  const service = String(alertRow?.service || "unknown-service").trim();
  const severity = String(alertRow?.severity || "high").trim().toLowerCase();
  const alertId = String(alertRow?.alert_id || alertRow?.id || "").trim();
  const workflow = workflowPayload?.workflow || workflowPayload || {};
  const recommendation = typeof workflow?.recommendation === "object" && workflow.recommendation ? workflow.recommendation : {};
  const incident = typeof workflow?.incident === "object" && workflow.incident ? workflow.incident : {};
  const rootCause = cleanRecommendationText(recommendation?.root_cause, "");
  const impact = cleanRecommendationText(recommendation?.impact, "");
  const suggestedAction = cleanRecommendationText(recommendation?.recommended_action, "");
  const commonHeader = `Alert ${alertName} observed on ${service} with severity ${severity.toUpperCase()}.`;
  const fallbackRootCause = "Investigate recent deploys, dependency health, and resource saturation.";
  const commonRoot = rootCause || fallbackRootCause;
  const remediationPreview = buildPreviewExecutionPlan(workflow);
  const remediationCommands = Array.isArray(remediationPreview?.plan?.commands) ? remediationPreview.plan.commands : [];
  const remediationScripts = Array.isArray(remediationPreview?.plan?.scripts) ? remediationPreview.plan.scripts : [];
  const remediationQueries = Array.isArray(remediationPreview?.plan?.queries) ? remediationPreview.plan.queries : [];
  const remediationPlanText = [
    remediationCommands.length ? `Commands:\n${remediationCommands.map((item) => `- ${item}`).join("\n")}` : "",
    remediationScripts.length ? `Scripts:\n${remediationScripts.map((item) => `- ${item}`).join("\n")}` : "",
    remediationQueries.length ? `Queries:\n${remediationQueries.map((item) => `- ${item}`).join("\n")}` : "",
  ].filter(Boolean).join("\n\n");

  return {
    incident: {
      kind: "incident",
      title: `${alertName} Incident Summary`.slice(0, 160),
      summary: [
        `${alertName} detected for ${service}.`,
        impact ? `Impact: ${impact}.` : "",
      ].filter(Boolean).join(" "),
      content: [
        commonHeader,
        `Probable root cause: ${commonRoot}`,
        incident?.id ? `Incident reference: ${String(incident.id)}.` : "",
        "Escalation path: L1 -> L2 -> L3 with timeline checkpoints at 5m, 15m, and 30m.",
      ].filter(Boolean).join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: suggestedAction,
    },
    jira: {
      kind: "jira",
      title: `${alertName} Jira Incident Ticket`.slice(0, 160),
      summary: `${severity.toUpperCase()} incident for ${service}: ${alertName}.`,
      content: [
        `Incident: ${alertName}`,
        `Alert ID: ${alertId || "Pending"}`,
        `Incident ID: ${String(incident?.id || workflow?.incident_id || "Pending")}`,
        `Jira ticket: ${String(alertRow?.ticket_id || alertRow?.jira_key || alertRow?.labels?.ticket_id || incident?.ticket_id || "Pending")}`,
        `Service: ${service}`,
        `Severity: ${severity.toUpperCase()}`,
        `Root cause: ${commonRoot}`,
        `Impact: ${impact || "Impact requires operator confirmation."}`,
        `Recommended action: ${suggestedAction || "Investigate logs, metrics, dependencies, and recent changes."}`,
      ].join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: suggestedAction,
    },
    runbook: {
      kind: "runbook",
      title: `${alertName} Runbook`.slice(0, 160),
      summary: [
        `${alertName} detected for ${service}.`,
        suggestedAction ? `Recommended action: ${suggestedAction}.` : "",
      ].filter(Boolean).join(" "),
      content: [
        commonHeader,
        `Probable root cause: ${commonRoot}`,
        suggestedAction ? `Immediate action: ${suggestedAction}.` : "Immediate action: inspect logs, metrics, and dependency health.",
        "Verification: confirm error rate and latency return to baseline before closure.",
      ].filter(Boolean).join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: suggestedAction,
    },
    deployment: {
      kind: "deployment",
      title: `${alertName} Deployment Guidance`.slice(0, 160),
      summary: `Deployment guardrails and rollback checks for ${service}.`,
      content: [
        commonHeader,
        "Pre-deploy checks: SLO burn rate, dependency readiness, and database migration safety.",
        "Post-deploy checks: p95 latency, error budget consumption, and alert noise monitoring for 30m.",
        "Rollback criteria: sustained critical alerts for 10m or failed synthetic checks.",
      ].join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: suggestedAction,
    },
    change: {
      kind: "change",
      title: `${alertName} Change Record`.slice(0, 160),
      summary: `Change notes and approvals for ${service} remediation actions.`,
      content: [
        commonHeader,
        "Change scope: configuration, deployment, and policy updates tied to this alert pattern.",
        "Approval checklist: peer review, CAB approval (if required), and blast-radius assessment.",
        "Backout plan: revert config, redeploy previous version, and validate health endpoints.",
      ].join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: suggestedAction,
    },
    dependency: {
      kind: "dependency",
      title: `${alertName} Dependency Map`.slice(0, 160),
      summary: `Dependency and upstream/downstream checks for ${service}.`,
      content: [
        commonHeader,
        "Dependencies to inspect: datastore latency, queue backlog, external API error rates, and network saturation.",
        "Signals to capture: timeout spikes, retry storms, and circuit breaker open rate.",
        "Mitigation path: isolate degraded dependency, apply traffic shaping, and monitor stabilization.",
      ].join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: suggestedAction,
    },
    remediation: {
      kind: "remediation",
      title: `${alertName} Remediation Command Plan`.slice(0, 160),
      summary: `Auto-generated remediation commands/scripts/queries for ${service}.`,
      content: [
        commonHeader,
        `Recommended remediation action: ${remediationPreview.recommendationText || suggestedAction || "Rollback deployment"}.`,
        `Probable root cause: ${commonRoot}`,
        remediationPlanText || "No remediation command plan was generated.",
      ].filter(Boolean).join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: remediationPreview.recommendationText || suggestedAction,
      execution_plan: remediationPlanText,
      commands: remediationCommands,
      scripts: remediationScripts,
      queries: remediationQueries,
    },
  };
}

function toFiniteNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function percentile(values, fraction) {
  const nums = (Array.isArray(values) ? values : [])
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value))
    .sort((a, b) => a - b);
  if (!nums.length) {
    return 0;
  }
  const index = Math.min(nums.length - 1, Math.max(0, Math.ceil(fraction * nums.length) - 1));
  return nums[index];
}

function normalizeUsageRow(row) {
  const entry = row && typeof row === "object" ? row : {};
  const usage = entry?.usage && typeof entry.usage === "object" ? entry.usage : {};
  const responseParams = entry?.response?.parameters && typeof entry.response.parameters === "object"
    ? entry.response.parameters
    : {};
  const inputTokens = toFiniteNumber(entry.input_tokens ?? usage.input_tokens ?? entry.prompt_tokens ?? usage.prompt_tokens);
  const outputTokens = toFiniteNumber(entry.output_tokens ?? usage.output_tokens ?? entry.completion_tokens ?? usage.completion_tokens);
  const totalTokens = toFiniteNumber(entry.total_tokens ?? usage.total_tokens ?? (inputTokens + outputTokens));
  const totalCostUsd = toFiniteNumber(
    entry.total_cost_usd
      ?? usage.total_cost_usd
      ?? entry.cost_usd
      ?? usage.cost_usd
      ?? entry.total_cost
      ?? usage.total_cost
  );
  const note = [entry.error, usage.error, entry.reason, usage.reason]
    .map((item) => String(item || "").trim())
    .find((item) => item && item !== "-") || "";
  const estimated = Boolean(entry.estimated ?? usage.estimated);
  const fallback = Boolean(entry.fallback ?? usage.fallback)
    || ["fallback", "heuristic-fallback", "provider-error"].includes(String(entry.provider || usage.provider || entry.model || usage.model || "").trim().toLowerCase());
  return {
    task: entry.task || entry.agent || entry.service || entry.action || entry.event_type || "-",
    provider: entry.provider || entry.vendor || entry.model_provider || usage.provider || responseParams.provider || "-",
    model: entry.model || entry.model_name || entry.deployment || usage.model || responseParams.model || "-",
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    total_tokens: totalTokens,
    total_cost_usd: totalCostUsd,
    note,
    estimated,
    fallback,
  };
}

function isPlaceholderUsageValue(value) {
  const token = String(value || "").trim().toLowerCase();
  return !token || token === "-" || token === "unknown" || token === "n/a" || token === "na" || token === "none" || token === "null";
}

function isMeaningfulUsageRow(row) {
  const hasUsage = toFiniteNumber(row?.input_tokens) > 0 || toFiniteNumber(row?.output_tokens) > 0 || toFiniteNumber(row?.total_tokens) > 0 || toFiniteNumber(row?.total_cost_usd) > 0;
  const hasProvider = !isPlaceholderUsageValue(row?.provider);
  const hasModel = !isPlaceholderUsageValue(row?.model);
  const hasErrorNote = Boolean(String(row?.note || "").trim());
  return hasUsage || hasProvider || hasModel || hasErrorNote;
}

function usageRowIdentity(row) {
  return [
    String(row?.task || "").trim().toLowerCase(),
    String(row?.provider || "").trim().toLowerCase(),
    String(row?.model || "").trim().toLowerCase(),
    String(row?.note || "").trim().toLowerCase(),
    Number(row?.input_tokens || 0),
    Number(row?.output_tokens || 0),
    Number(row?.total_tokens || 0),
  ].join("|");
}

function dedupeUsageRows(rows) {
  const seen = new Set();
  const out = [];
  rows.forEach((row) => {
    const key = usageRowIdentity(row);
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    out.push(row);
  });
  return out;
}

function HorizontalBarChart({ title, subtitle, items }) {
  const safeItems = Array.isArray(items) ? items : [];
  const maxValue = safeItems.reduce((best, item) => Math.max(best, toFiniteNumber(item?.value)), 0);
  return (
    <article className="panel executive-chart-card">
      <div className="panel-head">
        <h3>{title}</h3>
      </div>
      {subtitle ? <p className="subtitle">{subtitle}</p> : null}
      <div className="executive-bars">
        {safeItems.map((item, index) => {
          const value = toFiniteNumber(item?.value);
          const widthPct = maxValue > 0 ? (value / maxValue) * 100 : 0;
          const normalizedWidth = maxValue > 0 && value > 0 ? Math.max(4, widthPct) : 0;
          const tone = String(item?.tone || "ops");
          return (
            <div className="executive-bar-row" key={`bar-${index}`}>
              <span>{item?.label || "-"}</span>
              <strong>{item?.displayValue ?? String(value)}</strong>
              <div className="executive-bar-track">
                <div className={`executive-bar-fill tone-${tone}`} style={{ width: `${normalizedWidth}%` }} />
              </div>
            </div>
          );
        })}
        {!safeItems.length ? <p className="subtitle">No chart data available.</p> : null}
      </div>
    </article>
  );
}

function SuccessFailureDonut({ success, failure }) {
  const safeSuccess = Math.max(0, toFiniteNumber(success));
  const safeFailure = Math.max(0, toFiniteNumber(failure));
  const total = safeSuccess + safeFailure;
  const successPct = total > 0 ? (safeSuccess / total) * 100 : 0;
  return (
    <article className="panel executive-chart-card">
      <div className="panel-head">
        <h3>Success vs Failure</h3>
      </div>
      <div className="executive-donut-wrap">
        <div
          className="executive-donut"
          style={{
            background: `conic-gradient(var(--ok) 0 ${successPct}%, var(--danger) ${successPct}% 100%)`,
          }}
        >
          <div className="executive-donut-core">
            <strong>{total}</strong>
            <span>Requests</span>
          </div>
        </div>
        <div className="executive-donut-legend">
          <div><span className="legend-dot legend-ok" />Success: {safeSuccess}</div>
          <div><span className="legend-dot legend-danger" />Failure: {safeFailure}</div>
        </div>
      </div>
    </article>
  );
}

const ONBOARDING_STEP_BACKGROUND = {
  setup_monitoring: {
    1: "Saved to the OnboardingStateRecord table (keyed by project_name) via POST /onboarding/complete on monitoring-adapter.",
    2: "No backend call - determines which branch of the same request monitoring-adapter executes next (rule onboarding vs landing pad ingestion).",
    3: "Your plain-English lines are sent to the new-rule-onboarding pipeline, which asks the model-router (LLM) to translate them into concrete Prometheus rule specs (metric, threshold, duration).",
    4: "Generated rules are rendered into Prometheus rule YAML under backend/rag/changes/prometheus_rules, and Prometheus is asked to reload; a simulation check validates the rule behaves as expected.",
    5: "The discovery layer searches incident-only RAG records for similar historical tickets, extracts their resolution context, then creates and saves a new runbook via POST /rag/documents. Existing runbooks are not used as the primary source.",
  },
  existing_monitoring: {
    1: "Saved to the OnboardingStateRecord table (keyed by project_name) via POST /onboarding/complete on monitoring-adapter.",
    2: "No backend call - determines which branch of the same request monitoring-adapter executes next (rule onboarding vs landing pad ingestion).",
    3: "Saves the ingestion endpoint/connection profile you provide. This is the URL your monitoring tool's webhook (e.g. Alertmanager) should POST alerts to.",
    4: "Incoming alerts hit monitoring-adapter's /alerts/alertmanager endpoint, are written to the landing pad, published to the raw-alerts topic, and consumed by alert-intelligence -> orchestrator -> the rest of the incident pipeline.",
    5: "Optional. If rule onboarding was also enabled, documents are generated the same way as the Setup Monitoring path and appear under the Alert Knowledge tab.",
  },
};

function explainOnboardingStepBackground(stepNumber, isSetupMonitoring) {
  const table = ONBOARDING_STEP_BACKGROUND[isSetupMonitoring ? "setup_monitoring" : "existing_monitoring"];
  return table[stepNumber] || "No background detail available for this step.";
}

function findHistoricalTicketDiscoveryDocument(documents, applicationId, applicationName) {
  const normalizedId = String(applicationId || "").trim();
  const normalizedName = String(applicationName || "").trim().toLowerCase();
  return (Array.isArray(documents) ? documents : []).find((doc) => {
    const metadata = doc?.metadata && typeof doc.metadata === "object" ? doc.metadata : {};
    const services = Array.isArray(doc?.services) ? doc.services : [doc?.service];
    return String(doc?.kind || "").trim().toLowerCase() === "runbook"
      && String(metadata?.context_strategy || "").trim() === "similar-historical-tickets-first"
      && (
        (normalizedId && String(metadata?.application_id || "").trim() === normalizedId)
        || (normalizedName && services.some((service) => String(service || "").trim().toLowerCase() === normalizedName))
      );
  }) || null;
}

function HistoricalTicketDiscoveryPanel({ applicationId, applicationName, documents, loading = false }) {
  const discoveryDoc = findHistoricalTicketDiscoveryDocument(documents, applicationId, applicationName);
  const metadata = discoveryDoc?.metadata && typeof discoveryDoc.metadata === "object" ? discoveryDoc.metadata : {};
  const ticketPaths = Array.isArray(metadata.historical_ticket_paths)
    ? metadata.historical_ticket_paths.filter(Boolean)
    : [];
  const ticketCount = Number(metadata.historical_ticket_count ?? ticketPaths.length ?? 0);
  const discoveryComplete = Boolean(discoveryDoc);
  return (
    <section className="ticket-discovery-layer">
      <div className="panel-head">
        <div>
          <h3>Discovery Layer: Historical Ticket Context</h3>
          <p className="subtitle">Runbooks are grounded in similar resolved incidents before new guidance is generated.</p>
        </div>
        <span className={`workflow-pill ${discoveryComplete ? "workflow-pill-active" : "workflow-pill-idle"}`}>
          {loading ? "discovering" : discoveryComplete ? "complete" : "waiting"}
        </span>
      </div>
      <div className="ticket-discovery-flow" aria-label="Historical ticket discovery workflow">
        <div className="ticket-discovery-step"><strong>1. Alert Rules</strong><span>Service and generated rule patterns form the search query.</span></div>
        <span className="ticket-discovery-arrow" aria-hidden="true">→</span>
        <div className="ticket-discovery-step"><strong>2. Similar Tickets</strong><span>{discoveryComplete ? `${ticketCount} incident match${ticketCount === 1 ? "" : "es"} found` : "Incident-only search pending"}</span></div>
        <span className="ticket-discovery-arrow" aria-hidden="true">→</span>
        <div className="ticket-discovery-step"><strong>3. Context Extraction</strong><span>Root cause and resolution evidence are extracted from matched tickets.</span></div>
        <span className="ticket-discovery-arrow" aria-hidden="true">→</span>
        <div className="ticket-discovery-step"><strong>4. Runbook</strong><span>{discoveryDoc?.title || "Generated after discovery completes"}</span></div>
      </div>
      {discoveryComplete ? (
        <div className="ticket-discovery-evidence">
          <strong>Evidence sources</strong>
          {ticketPaths.length ? (
            <ul>{ticketPaths.map((path, index) => <li key={`historical-ticket-${index}`} title={String(path)}>{String(path)}</li>)}</ul>
          ) : (
            <p>Fallback guidance used because no sufficiently similar historical ticket was found.</p>
          )}
        </div>
      ) : (
        <p className="subtitle">This panel updates dynamically when the rule-generation agent publishes the application runbook.</p>
      )}
    </section>
  );
}

function FlowTimelineGraph({ rows }) {
  const timelineRows = Array.isArray(rows) ? rows : [];
  if (!timelineRows.length) {
    return <p className="subtitle">No timeline data found for selected alert.</p>;
  }

  const parseMaybeJson = (value) => {
    const text = String(value || "").trim();
    if (!text) {
      return null;
    }
    try {
      const parsed = JSON.parse(text);
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch (_error) {
      return null;
    }
  };

  const classifyStage = (row) => {
    const stage = String(row?.stage || "").toLowerCase();
    if (stage.includes("landing pad") || stage.includes("alert received") || stage.includes("alert landed")) {
      return { kind: "ingestion", short: "ING", label: "Landing Pad" };
    }
    if (stage.includes("topic handoff") || stage.includes("message bus")) {
      return { kind: "bus", short: "BUS", label: "Message Bus" };
    }
    if (stage.includes("dedup") || stage.includes("correlation") || stage.includes("enrich")) {
      return { kind: "dedupe", short: "DED", label: "Dedup" };
    }
    if (stage.includes("config") || stage.includes("connector lookup")) {
      return { kind: "config", short: "CFG", label: "Config" };
    }
    if (stage.includes("routing") || stage.includes("orchestrator") || stage.includes("workflow")) {
      return { kind: "orchestration", short: "ORC", label: "Orchestrator" };
    }
    if (stage.includes("discovery agent") || stage.includes("code and log context")) {
      return { kind: "discovery", short: "DSC", label: "Discovery" };
    }
    if (stage.includes("rag context") || stage.includes("context retrieval") || stage.includes("context intelligence")) {
      return { kind: "rag", short: "RAG", label: "RAG" };
    }
    if (stage.includes("embedding") || stage.includes("semantic") || stage.includes("vector")) {
      return { kind: "semantic", short: "SEM", label: "Semantic" };
    }
    if (stage.includes("context merge") || stage.includes("evidence assembly")) {
      return { kind: "context", short: "CTX", label: "Context" };
    }
    if (stage.includes("resolution") || stage.includes("recommendation")) {
      return { kind: "resolution", short: "RCA", label: "Resolution" };
    }
    if (stage.includes("approval")) {
      return { kind: "approval", short: "APR", label: "Approval" };
    }
    if (stage.includes("policy")) {
      return { kind: "policy", short: "POL", label: "Policy" };
    }
    if (stage.includes("remediation") || stage.includes("command") || stage.includes("execute")) {
      return { kind: "execution", short: "CMD", label: "Execution" };
    }
    if (stage.includes("closure") || stage.includes("validation")) {
      return { kind: "closure", short: "CLS", label: "Closure" };
    }
    return { kind: "generic", short: "EVT", label: "Event" };
  };

  const getRowBackendEvents = (row) => {
    const input = parseMaybeJson(row?.inputValueText);
    const output = parseMaybeJson(row?.outputValueText);
    const rawEvents = Array.from(
      new Set(
        [
          ...(Array.isArray(row?.backendEvents) ? row.backendEvents : []),
          String(input?.event_type || "").trim(),
          String(output?.event_type || "").trim(),
        ].filter(Boolean)
      )
    );

    const orderHints = [
      "incident.alert",
      "incident.workflow.selected",
      "incident.context.collected",
      "incident.recommendation.generated",
      "incident.approval.requested",
      "incident.approval.recorded",
      "incident.remediation.executed",
      "incident.closure.completed",
    ];

    const eventWeight = (eventName) => {
      const normalized = String(eventName || "").toLowerCase();
      const index = orderHints.findIndex((hint) => normalized.includes(hint));
      return index === -1 ? orderHints.length : index;
    };

    return rawEvents
      .slice()
      .sort((left, right) => {
        const leftWeight = eventWeight(left);
        const rightWeight = eventWeight(right);
        if (leftWeight !== rightWeight) {
          return leftWeight - rightWeight;
        }
        return String(left).localeCompare(String(right));
      });
  };

  const explainBackground = (row, stageMeta) => {
    const input = parseMaybeJson(row?.inputValueText);
    const output = parseMaybeJson(row?.outputValueText);
    const topicIn = String(row?.consumes || "-");
    const topicOut = String(row?.publishes || "-");
    const dbTables = String(row?.tables || "-");
    const mergedBackendEvents = getRowBackendEvents(row);
    const eventStage = String(output?.event_stage || input?.event_stage || row?.detail || "-").trim() || "-";
    const eventStatus = String(output?.status || input?.status || "-").trim() || "-";
    const traceId = String(output?.trace_id || input?.trace_id || "-").trim() || "-";

    return [
      `stage_kind: ${stageMeta.kind}`,
      `backend_events: ${mergedBackendEvents.length ? mergedBackendEvents.join(" | ") : "none"}`,
      `source_topic: ${topicIn}`,
      `target_topic: ${topicOut}`,
      `tables_touched: ${dbTables}`,
      `event_stage: ${eventStage}`,
      `event_status: ${eventStatus}`,
      `trace_id: ${traceId}`,
    ].join("\n");
  };

  const copyPlanStep = async (value) => {
    const text = String(value || "").trim();
    if (!text || typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
    } catch (_error) {
      // Best-effort copy for operator convenience.
    }
  };

  const extractExecutionPlan = (row) => {
    const input = parseMaybeJson(row?.inputValueText);
    const output = parseMaybeJson(row?.outputValueText);
    const commands = [];
    const scripts = [];
    const queries = [];
    const seenObjects = new WeakSet();

    const pushUnique = (target, value) => {
      const token = String(value || "").trim();
      if (!token) {
        return;
      }
      if (!target.some((item) => item.toLowerCase() === token.toLowerCase())) {
        target.push(token);
      }
    };

    const classifyLine = (raw) => {
      const token = String(raw || "").trim();
      if (!token) {
        return;
      }
      const lowered = token.toLowerCase();
      if (lowered.startsWith("cmd:")) {
        pushUnique(commands, token.slice(4).trim());
        return;
      }
      if (lowered.startsWith("script:")) {
        pushUnique(scripts, token.slice(7).trim());
        return;
      }
      if (lowered.startsWith("query:")) {
        pushUnique(queries, token.slice(6).trim());
        return;
      }
      pushUnique(commands, token);
    };

    const collectFromPlanText = (value) => {
      const text = String(value || "").trim();
      if (!text) {
        return;
      }
      let currentSection = "command";
      text.split(/\r?\n/).forEach((line) => {
        const token = String(line || "").trim();
        if (!token) {
          return;
        }
        if (/^commands?\s*:/i.test(token)) {
          currentSection = "command";
          const inline = token.replace(/^commands?\s*:/i, "").trim();
          if (inline) {
            classifyLine(`cmd: ${inline}`);
          }
          return;
        }
        if (/^scripts?\s*:/i.test(token)) {
          currentSection = "script";
          const inline = token.replace(/^scripts?\s*:/i, "").trim();
          if (inline) {
            classifyLine(`script: ${inline}`);
          }
          return;
        }
        if (/^(queries?|sql)\s*:/i.test(token)) {
          currentSection = "query";
          const inline = token.replace(/^(queries?|sql)\s*:/i, "").trim();
          if (inline) {
            classifyLine(`query: ${inline}`);
          }
          return;
        }

        const normalized = token.replace(/^[-*]\s*/, "").trim();
        if (!normalized) {
          return;
        }
        if (/^(cmd|command|script|query)\s*:/i.test(normalized)) {
          classifyLine(normalized);
          return;
        }
        if (currentSection === "script") {
          pushUnique(scripts, normalized);
          return;
        }
        if (currentSection === "query") {
          pushUnique(queries, normalized);
          return;
        }
        pushUnique(commands, normalized);
      });
    };

    const collectFromValue = (value) => {
      if (!hasMeaningfulValue(value)) {
        return;
      }
      if (Array.isArray(value)) {
        value.forEach(collectFromValue);
        return;
      }
      if (typeof value === "string") {
        collectFromPlanText(value);
        return;
      }
      if (typeof value !== "object" || value === null) {
        return;
      }
      if (seenObjects.has(value)) {
        return;
      }
      seenObjects.add(value);

      (Array.isArray(value.commands) ? value.commands : []).forEach(classifyLine);
      (Array.isArray(value.scripts) ? value.scripts : []).forEach((item) => pushUnique(scripts, item));
      (Array.isArray(value.queries) ? value.queries : []).forEach((item) => pushUnique(queries, item));

      if (hasMeaningfulValue(value.execution_plan)) {
        collectFromValue(value.execution_plan);
      }

      [
        value.parameters,
        value.remediation_action,
        value.source_payload,
        value.recommendation,
        value.decision,
        value.payload,
        value.input,
        value.output,
        value.result,
      ].forEach((item) => {
        if (item && typeof item === "object") {
          collectFromValue(item);
        }
      });
    };

    collectFromValue(input);
    collectFromValue(output);

    return {
      commands: commands.filter(Boolean),
      scripts: scripts.filter(Boolean),
      queries: queries.filter(Boolean),
    };
  };

  const observedPhases = Array.from(new Map(timelineRows.map((row) => {
    const meta = classifyStage(row);
    return [meta.kind, meta];
  })).values());
  const errorCount = timelineRows.filter((row) => timelineRowHasError(row)).length;
  const compactRows = timelineRows.map((row, index) => {
    const stageMeta = classifyStage(row);
    return {
      key: `compact-${index}`,
      phase: stageMeta.label,
      stage: row.stage || "-",
      agent: row.agent || "-",
      elapsed: row.elapsed !== "-" ? `${row.elapsed}s` : "-",
      status: timelineRowStatus(row) === "failed" ? "error" : timelineRowStatus(row) === "fallback" ? "fallback" : "ok",
      detail: compactText(row.detail, 120) || "-",
    };
  });
  const totalElapsedSeconds = timelineRows.reduce((sum, row) => {
    const value = Number(row?.elapsed);
    return Number.isFinite(value) ? sum + Math.max(0, value) : sum;
  }, 0);
  const totalElapsedDisplay = timelineRows.length ? `${totalElapsedSeconds.toFixed(3)}s` : "-";

  return (
    <div className="timeline-graph">
      <div className="timeline-summary-strip">
        <div className="timeline-summary-metric">
          <strong>{timelineRows.length}</strong>
          <span>Total Stages</span>
        </div>
        <div className="timeline-summary-metric">
          <strong>{observedPhases.length}</strong>
          <span>Observed Phases</span>
        </div>
        <div className="timeline-summary-metric">
          <strong>{Math.max(0, timelineRows.length - errorCount)}</strong>
          <span>Successful Stages</span>
        </div>
        <div className="timeline-phase-strip">
          {observedPhases.map((phase) => {
            return (
              <span
                key={`phase-${phase.kind}`}
                className={`timeline-phase-pill phase-${phase.kind} is-active`}
                title={`${phase.label} observed from runtime events`}
              >
                {phase.label}
              </span>
            );
          })}
        </div>
      </div>
      {timelineRows.map((row, index) => (
        (() => {
          const stageMeta = classifyStage(row);
          const backendEvents = getRowBackendEvents(row);
          const executionPlan = extractExecutionPlan(row);
          const nextRow = timelineRows[index + 1] || null;
          const fallbackStatus = timelineRowStatus(row, nextRow);
          const nextStep = inferTimelineNextStep(row, nextRow);
          const hasExecutionPlan = stageMeta.kind === "execution"
            && (executionPlan.commands.length || executionPlan.scripts.length || executionPlan.queries.length);
          return (
        <article
          className={`timeline-node stage-${stageMeta.kind} ${(fallbackStatus === "failed" || hasMeaningfulValue(row?.errorValueText)) ? "timeline-has-error" : ""}`}
          key={`timeline-node-${index}`}
          style={{ animationDelay: `${Math.min(index * 70, 560)}ms` }}
        >
          <div className="timeline-rail">
            <span className="timeline-dot" />
            {index < timelineRows.length - 1 ? <span className="timeline-line" /> : null}
          </div>
          <div className="timeline-body">
            <div className="timeline-headline">
              <strong>
                <span className={`timeline-stage-badge stage-${stageMeta.kind}`}>{stageMeta.short}</span>
                {" "}
                {row.stage || "-"}
              </strong>
              <span>{formatUtcTimestamp(row.timestamp)}</span>
            </div>
            <div className="timeline-meta">
              <span>{row.agent || "-"}</span>
              <span>{row.service || "-"}</span>
              <span>{row.elapsed !== "-" ? `${row.elapsed}s` : "-"}</span>
              {fallbackStatus === "fallback" ? <span>fallback path</span> : null}
            </div>
            <p>{row.detail || "-"}</p>
            {nextStep && nextStep !== "-" ? (
              <div className="timeline-tags">
                <span className="timeline-tag">next: {nextStep}</span>
              </div>
            ) : null}
            {row.inputValueText ? (
              <details>
                <summary>Input Value</summary>
                <pre className="result">{row.inputValueText}</pre>
              </details>
            ) : null}
            {row.outputValueText ? (
              <details>
                <summary>Output Value</summary>
                <pre className="result">{row.outputValueText}</pre>
              </details>
            ) : null}
            {hasExecutionPlan ? (
              <details open>
                <summary>Resolution Plan (Commands, Scripts, Queries)</summary>
                <div className="timeline-plan-grid">
                  <div className="timeline-plan-section">
                    <h4>Commands</h4>
                    {executionPlan.commands.length ? executionPlan.commands.map((step, stepIndex) => (
                      <div className="timeline-plan-row" key={`cmd-${index}-${stepIndex}`}>
                        <pre className="result">{step}</pre>
                        <button type="button" className="timeline-copy-btn" onClick={() => copyPlanStep(step)}>Copy</button>
                      </div>
                    )) : <p className="subtitle">No command steps.</p>}
                  </div>
                  <div className="timeline-plan-section">
                    <h4>Scripts</h4>
                    {executionPlan.scripts.length ? executionPlan.scripts.map((step, stepIndex) => (
                      <div className="timeline-plan-row" key={`script-${index}-${stepIndex}`}>
                        <pre className="result">{step}</pre>
                        <button type="button" className="timeline-copy-btn" onClick={() => copyPlanStep(step)}>Copy</button>
                      </div>
                    )) : <p className="subtitle">No script steps.</p>}
                  </div>
                  <div className="timeline-plan-section">
                    <h4>Queries</h4>
                    {executionPlan.queries.length ? executionPlan.queries.map((step, stepIndex) => (
                      <div className="timeline-plan-row" key={`query-${index}-${stepIndex}`}>
                        <pre className="result">{step}</pre>
                        <button type="button" className="timeline-copy-btn" onClick={() => copyPlanStep(step)}>Copy</button>
                      </div>
                    )) : <p className="subtitle">No validation queries.</p>}
                  </div>
                </div>
              </details>
            ) : null}
            {row.errorValueText ? (
              <details open>
                <summary>Error</summary>
                <pre className="result">{row.errorValueText}</pre>
              </details>
            ) : null}
            <details>
              <summary>How This Worked In Background</summary>
              <pre className="result">{explainBackground(row, stageMeta)}</pre>
            </details>
            <div className="timeline-tags">
              <span className="timeline-tag">in: {row.consumes || "-"}</span>
              <span className="timeline-tag">out: {row.publishes || "-"}</span>
              <span className="timeline-tag">db: {row.tables || "-"}</span>
            </div>
            <div className="timeline-backend-events">
              <span className="timeline-backend-label">backend:</span>
              {backendEvents.length ? backendEvents.map((eventName, eventIndex) => (
                <span className="timeline-backend-chip" key={`backend-${index}-${eventIndex}`}>
                  {eventName}
                </span>
              )) : <span className="timeline-backend-chip is-empty">none</span>}
            </div>
          </div>
        </article>
          );
        })()
      ))}
      <article className="panel" style={{ marginTop: 10 }}>
        <div className="panel-head">
          <h3>Stage Summary Table</h3>
          <p>Compact timeline view with phase, ownership, and status.</p>
        </div>
        <div className="table-wrap table-wrap-scroll-x">
          <table>
            <thead>
              <tr>
                <th>Phase</th>
                <th>Stage</th>
                <th>Agent</th>
                <th>Elapsed</th>
                <th>Status</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {compactRows.map((row) => (
                <tr key={row.key}>
                  <td>{row.phase}</td>
                  <td>{row.stage}</td>
                  <td>{row.agent}</td>
                  <td>{row.elapsed}</td>
                  <td><span className={`pill ${row.status === "error" ? "status-failed" : "status-approved"}`}>{row.status}</span></td>
                  <td>{row.detail}</td>
                </tr>
              ))}
              <tr>
                <td colSpan={3}><strong>Total Alert Time</strong></td>
                <td><strong>{totalElapsedDisplay}</strong></td>
                <td>-</td>
                <td>Cumulative elapsed time across all listed stages.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </article>
    </div>
  );
}

function UnifiedIncidentTimeline({ workflow, rows, documents = [] }) {
  const [expandedPhaseId, setExpandedPhaseId] = useState("");
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeRows = Array.isArray(rows) ? rows : [];
  const lanes = [
    { id: "detect", icon: "↗", label: "Detect", hint: "Signal received", match: ["landing", "ingest", "alert", "monitor"] },
    { id: "discover", icon: "⌕", label: "Discover", hint: "Evidence collected", match: ["discover", "ticket", "log", "trace", "code", "context"] },
    { id: "diagnose", icon: "◇", label: "Diagnose", hint: "Cause assessed", match: ["resolution", "root cause", "rca", "impact", "model"] },
    { id: "decide", icon: "✓", label: "Decide", hint: "Risk reviewed", match: ["approval", "decision", "policy", "risk"] },
    { id: "act", icon: "⚡", label: "Act", hint: "Fix executed", match: ["remedi", "execute", "command", "action"] },
    { id: "validate", icon: "◎", label: "Validate", hint: "Recovery confirmed", match: ["validat", "closure", "closed", "health restored"] },
  ];
  const assigned = new Set();
  // Lane text is built from curated, human-readable fields only -- NOT the raw
  // inputValueText/outputValueText JSON blobs, which almost always carry a trace_id
  // (matches "discover"'s "trace" token) or similar incidental substrings and would
  // otherwise pull unrelated events (e.g. ingestion/topic-handoff rows) into the wrong lane.
  const laneText = (row) => [row?.status, row?.stage, row?.detail, row?.agent, row?.service, row?.consumes, row?.publishes]
    .map((item) => String(item || "").toLowerCase())
    .join(" ");
  const laneIdForRow = (row) => {
    const order = Number(row?.flowOrder);
    if (Number.isFinite(order) && order > 0) {
      if (order >= 170) return "validate";
      if (order >= 150) return "act";
      if (order >= 130) return "decide";
      if (order >= 100) return "diagnose";
      if (order >= 50) return "discover";
      return "detect";
    }
    const stage = String(row?.stage || "").toLowerCase();
    if (["validat", "closure", "recovery", "closed", "resolved"].some((token) => stage.includes(token))) return "validate";
    if (["remedi", "execut", "command", "action"].some((token) => stage.includes(token))) return "act";
    if (["approval", "decision", "policy", "risk"].some((token) => stage.includes(token))) return "decide";
    if (["resolution", "root cause", "rca", "impact", "diagnos"].some((token) => stage.includes(token))) return "diagnose";
    if (["discover", "ticket", "log", "trace", "code", "context", "evidence"].some((token) => stage.includes(token))) return "discover";
    if (["landing", "ingest", "alert", "monitor", "detect"].some((token) => stage.includes(token))) return "detect";
    return "";
  };
  const laneRows = lanes.map((lane) => {
    // A row is claimed by at most one lane: the first (in detect -> validate order) whose
    // keywords match. Previously every lane re-tested every row independently, so a single
    // event could match more than one lane's keywords and appear duplicated across phases.
    const matched = safeRows.filter((row, index) => {
      if (assigned.has(index)) {
        return false;
      }
      const authoritativeLane = laneIdForRow(row);
      const text = laneText(row);
      const hit = authoritativeLane ? authoritativeLane === lane.id : lane.match.some((token) => text.includes(token));
      if (hit) assigned.add(index);
      return hit;
    });
    return { ...lane, rows: matched };
  });
  safeRows.forEach((row, index) => {
    if (!assigned.has(index)) {
      const target = laneRows[Math.min(laneRows.length - 1, Math.floor((index / Math.max(1, safeRows.length)) * laneRows.length))];
      target.rows.push(row);
    }
  });
  const recommendation = safeWorkflow?.recommendation || {};
  const contextMetadata = recommendation?.metadata || safeWorkflow?.context?.metadata || {};
  const retrievedSources = Array.from(new Set([
    ...(Array.isArray(contextMetadata?.sources) ? contextMetadata.sources : []),
    ...(Array.isArray(documents) ? documents.map((doc) => doc?.source || doc?.kind || doc?.path) : []),
    ...safeRows.flatMap((row) => {
      const text = timelineRowText(row).toLowerCase();
      return [
        text.includes("ticket") || text.includes("jira") ? "Jira / tickets" : "",
        text.includes("log") || text.includes("opensearch") ? "Logs" : "",
        text.includes("trace") || text.includes("jaeger") ? "Traces" : "",
        text.includes("code") || text.includes("repository") ? "Source code" : "",
        text.includes("prometheus") || text.includes("metric") ? "Metrics" : "",
      ].filter(Boolean);
    }),
  ].map((value) => String(value || "").trim()).filter(Boolean)));
  const expandedLane = laneRows.find((lane) => lane.id === expandedPhaseId && lane.rows.length) || null;

  return (
    <section className="unified-incident-timeline" aria-label="Unified incident timeline">
      <header className="unified-timeline-header">
        <div>
          <span className="discovery-eyebrow">Live incident journey</span>
          <h3>Signal to Recovery</h3>
          <p>One ordered view joining ingestion, discovery, context retrieval, reasoning, approval, remediation, and validation.</p>
        </div>
        <div className="unified-timeline-stats">
          <span><strong>{safeRows.length}</strong> events</span>
          <span><strong>{retrievedSources.length}</strong> sources</span>
          <span><strong>{laneRows.filter((lane) => lane.rows.length).length}</strong>/6 phases observed</span>
        </div>
      </header>
      <div className="unified-source-strip">
        <strong>Evidence</strong>
        {retrievedSources.length
          ? retrievedSources.map((source) => <span key={source}>{compactText(source, 42)}</span>)
          : <span>Waiting for source evidence</span>}
      </div>
      <div className="timeline-phase-map">
        {laneRows.map((lane, laneIndex) => {
          const failed = lane.rows.some((row) => timelineRowHasError(row));
          const fallback = lane.rows.some((row) => timelineRowStatus(row) === "fallback");
          const status = failed ? "failed" : fallback ? "fallback" : lane.rows.length ? "complete" : "waiting";
          const latest = lane.rows[lane.rows.length - 1] || {};
          return (
            <article className={`timeline-phase-card is-${status}`} key={lane.id}>
              <div className="timeline-phase-top">
                <span className="timeline-phase-icon" aria-hidden="true">{lane.icon}</span>
                <span className="timeline-phase-number">{String(laneIndex + 1).padStart(2, "0")}</span>
                <i className="timeline-phase-status">{status}</i>
              </div>
              <h4>{lane.label}</h4>
              <p>{lane.hint}</p>
              <div className="timeline-phase-summary">
                <strong>{lane.rows.length}</strong>
                <span>{lane.rows.length === 1 ? "event" : "events"}</span>
              </div>
              {lane.rows.length ? (
                <div className="timeline-phase-latest">
                  <strong>{compactText(latest.stage || latest.agent || latest.service || `${lane.label} event`, 60)}</strong>
                  <p>{compactText(latest.detail || latest.outputValueText || latest.inputValueText, 140) || "No additional detail was recorded for this event."}</p>
                  <small>
                    {latest.agent || latest.service || "KaiMS"} · {formatIstTimestamp(latest.timestamp || latest.created_at)}
                    {latest.status || timelineRowStatus(latest) ? ` · ${latest.status || timelineRowStatus(latest)}` : ""}
                  </small>
                </div>
              ) : (
                <small className="timeline-phase-latest timeline-phase-latest-empty">Not reached yet</small>
              )}
              {lane.rows.length ? (
                <button
                  type="button"
                  className={`timeline-phase-toggle ${expandedPhaseId === lane.id ? "is-active" : ""}`}
                  aria-expanded={expandedPhaseId === lane.id}
                  aria-controls="timeline-event-panel"
                  onClick={() => setExpandedPhaseId((current) => current === lane.id ? "" : lane.id)}
                >
                  {expandedPhaseId === lane.id ? "Hide events" : "View events"}
                </button>
              ) : null}
            </article>
          );
        })}
      </div>
      {expandedLane ? (
        <section className="timeline-event-panel" id="timeline-event-panel" aria-live="polite">
          <header>
            <div>
              <span className="timeline-phase-icon" aria-hidden="true">{expandedLane.icon}</span>
              <div>
                <strong>{expandedLane.label} events</strong>
                <small>{expandedLane.rows.length} recorded workflow event(s)</small>
              </div>
            </div>
            <button type="button" className="button-secondary" onClick={() => setExpandedPhaseId("")}>Close</button>
          </header>
          <div className="timeline-event-list">
            {expandedLane.rows.slice(0, 20).map((row, rowIndex) => (
              <article key={`${expandedLane.id}-expanded-${rowIndex}`}>
                <span className="timeline-event-index">{String(rowIndex + 1).padStart(2, "0")}</span>
                <div>
                  <header>
                    <strong>{row.stage || row.agent || row.service || `Event ${rowIndex + 1}`}</strong>
                    <span>{row.status || timelineRowStatus(row)}</span>
                  </header>
                  <p>{compactText(row.detail || row.outputValueText || row.inputValueText, 360) || "Stage completed."}</p>
                  <small>
                    {row.agent || row.service || "KaiMS"} · {formatIstTimestamp(row.timestamp || row.created_at)}
                    {row.executionTimeMs || row.execution_time_ms ? ` · ${row.executionTimeMs || row.execution_time_ms} ms` : ""}
                  </small>
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : null}
    </section>
  );
}

function DiscoveryFlowView({ workflow, timelineRows = [], selectedAlert = null, compact = false }) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const recommendation = safeWorkflow?.recommendation && typeof safeWorkflow.recommendation === "object"
    ? safeWorkflow.recommendation
    : {};
  const recommendationMetadata = recommendation?.metadata && typeof recommendation.metadata === "object"
    ? recommendation.metadata
    : {};
  const rcaAnalysis = recommendationMetadata.rca_analysis && typeof recommendationMetadata.rca_analysis === "object"
    ? recommendationMetadata.rca_analysis
    : {};
  const impactAnalysis = recommendationMetadata.impact_analysis && typeof recommendationMetadata.impact_analysis === "object"
    ? recommendationMetadata.impact_analysis
    : {};
  const metadataCandidates = [
    safeWorkflow?.context?.metadata,
    safeWorkflow?.recommendation?.metadata,
  ].filter((row) => row && typeof row === "object");
  const tracePayloads = (Array.isArray(safeWorkflow.event_trace) ? safeWorkflow.event_trace : [])
    .map((row) => row?.payload)
    .filter((row) => row && typeof row === "object");
  const eventContracts = [
    ...(Array.isArray(safeWorkflow.events) ? safeWorkflow.events : []),
    ...tracePayloads,
  ]
    .map((row) => row?.event_contract?.payload?.discovery || row?.payload?.discovery || row?.discovery)
    .filter((row) => row && typeof row === "object");
  const mcp = metadataCandidates.map((row) => row.discovery_report).find((row) => row && typeof row === "object") || {};
  const contractDiscovery = eventContracts[0] || {};
  const report =
    (mcp.report && typeof mcp.report === "object" && mcp.report)
    || contractDiscovery
    || {};
  const evidence =
    (Array.isArray(mcp.evidence) && mcp.evidence)
    || (Array.isArray(contractDiscovery.evidence) && contractDiscovery.evidence)
    || [];
  let stages =
    (Array.isArray(mcp.retrieval_stages) && mcp.retrieval_stages)
    || (Array.isArray(contractDiscovery.retrieval_stages) && contractDiscovery.retrieval_stages)
    || [];
  if (!stages.length) {
    stages = (Array.isArray(timelineRows) ? timelineRows : [])
      .filter((row) => String(row?.stage || "").toLowerCase().includes("discovery"))
      .map((row) => ({
        stage: row.stage,
        status: row.errorValueText ? "failed" : "completed",
        error: row.errorValueText || "",
      }));
  }
  if (!stages.length && evidence.length) {
    const sources = [...new Set(evidence.map((row) => row?.source).filter(Boolean))];
    stages = [
      { stage: "query_planned", status: "completed" },
      ...sources.map((source) => ({ stage: `${source}_search`, status: "completed", result_count: evidence.filter((row) => row?.source === source).length })),
      { stage: "evidence_correlated", status: "completed", result_count: evidence.length },
    ];
  }
  const hypotheses = Array.isArray(report.hypotheses) ? report.hypotheses : [];
  const modelInteraction =
    (mcp.model_interaction && typeof mcp.model_interaction === "object" && mcp.model_interaction)
    || (contractDiscovery.model_interaction && typeof contractDiscovery.model_interaction === "object" && contractDiscovery.model_interaction)
    || {};
  const sourceCounts = evidence.reduce((counts, row) => {
    const source = String(row?.source || "other").toLowerCase();
    counts[source] = (counts[source] || 0) + 1;
    return counts;
  }, {});
  const rootCause = cleanRecommendationText(
    recommendation?.root_cause,
    report.summary || safeWorkflow?.alert?.description || selectedAlert?.description || "-"
  );
  const impact = cleanRecommendationText(
    recommendation?.impact,
    `${selectedAlert?.service || safeWorkflow?.alert?.service || "Selected service"} may have degraded availability, latency, or downstream workflow impact until mitigation is validated.`
  );
  const recommendedAction = cleanRecommendationText(recommendation?.recommended_action, "-");
  const supportingReasonCandidates = [
    ...(Array.isArray(recommendationMetadata?.reasoning_steps) ? recommendationMetadata.reasoning_steps : []),
    ...(Array.isArray(recommendationMetadata?.reason_codes) ? recommendationMetadata.reason_codes : []),
    ...(Array.isArray(recommendationMetadata?.causal_factors) ? recommendationMetadata.causal_factors : []),
    ...hypotheses.flatMap((row) => Array.isArray(row?.supporting_evidence) ? row.supporting_evidence : []),
    ...(Array.isArray(timelineRows) ? timelineRows : [])
      .filter((row) => row?.errorValueText)
      .map((row) => `${row.stage || "stage"}: ${row.errorValueText}`),
  ]
    .map((row) => compactText(row, 220))
    .map((row) => String(row || "").trim())
    .filter(Boolean);
  const detailedReasons = Array.from(new Set(supportingReasonCandidates)).slice(0, 12);
  const protocol = mcp.protocol || "mcp-jsonrpc-2.0";
  const hasDiscovery = stages.length > 0 || evidence.length > 0 || Boolean(report.summary);
  const sourceOrder = ["log", "ticket", "code", "mysql", "metric", "trace", "opensearch"];
  const visibleSources = Array.from(new Set([...sourceOrder, ...Object.keys(sourceCounts)]))
    .filter((source) => sourceCounts[source]);
  const stageDetail = (stage) => {
    const name = String(stage?.stage || "").toLowerCase();
    if (name.includes("query_planned")) return "Build service, alert, environment, trace, scenario, application, and ticket search terms.";
    if (name.includes("log_search") || name.includes("logs_search")) return "Search runtime and landing-pad logs and preserve matching lines with source URIs.";
    if (name.includes("ticket_search") || name.includes("tickets_search")) return "Search Jira CSV, email, historical incidents, and landing-pad ticket content.";
    if (name.includes("code_search")) return "Search the affected service source first, then the full project repository.";
    if (name.includes("mysql_search")) return "Search KaiMS incident projections and related operational records.";
    if (name.includes("telemetry_search")) return "Correlate Prometheus metrics, Jaeger traces, and OpenSearch logs by service and trace ID.";
    if (name.includes("onboarding_context_merge")) return "Merge application ownership, environment, namespace, monitoring, and onboarding metadata into context.";
    if (name.includes("evidence_correlated")) return "Deduplicate and rank facts while retaining evidence IDs and provenance.";
    if (name.includes("llm_analysis")) return "Send only retrieved evidence to the model and require cited JSON RCA.";
    if (name.includes("discovery_completed")) return "Publish grounded discovery context to downstream RCA and impact analysis.";
    return "Execute the recorded discovery stage and preserve its input, status, and output.";
  };

  return (
    <section className={`discovery-workspace ${compact ? "is-compact" : ""}`}>
      {compact ? (
        <header className="discovery-compact-head">
          <h4>Discovery Agent Trace</h4>
          <div className="discovery-kpis">
            <span><strong>{stages.length}</strong> stages</span>
            <span><strong>{evidence.length}</strong> evidence</span>
            <span><strong>{hypotheses.length}</strong> hypotheses</span>
            <span><strong>{protocol.includes("mcp") ? "MCP" : protocol}</strong> protocol</span>
          </div>
        </header>
      ) : (
        <header className="discovery-hero">
          <div>
            <span className="discovery-eyebrow">Evidence-grounded investigation</span>
            <h3>Discovery Agent</h3>
            <p>Dynamic retrieval from logs, tickets, and code followed by cited RCA reasoning.</p>
          </div>
          <div className="discovery-kpis">
            <span><strong>{stages.length}</strong> stages</span>
            <span><strong>{evidence.length}</strong> evidence</span>
            <span><strong>{hypotheses.length}</strong> hypotheses</span>
            <span><strong>{protocol.includes("mcp") ? "MCP" : protocol}</strong> protocol</span>
          </div>
        </header>
      )}

      {hasDiscovery ? (
        <>
          <div className="discovery-flow" aria-label="Dynamic discovery agent flow">
            {stages.map((stage, index) => {
              const state = String(stage.status || "completed").toLowerCase();
              return (
                <div className="discovery-flow-segment" key={`discovery-stage-${index}-${stage.stage || ""}`}>
                  <article className={`discovery-stage is-${state}`}>
                    <span className="discovery-stage-index">{index + 1}</span>
                    <div>
                      <strong>{String(stage.stage || `stage ${index + 1}`).replaceAll("_", " ")}</strong>
                      <small>{state}{Number.isFinite(Number(stage.result_count)) ? ` · ${stage.result_count} result(s)` : ""}</small>
                      <p className="discovery-stage-detail">{stageDetail(stage)}</p>
                      {Number(stage.result_count) === 0 ? <small className="discovery-no-match">No matching evidence was returned by this source.</small> : null}
                      {Array.isArray(stage.terms) && stage.terms.length ? <small>Query: {stage.terms.join(", ")}</small> : null}
                      {stage.model ? <small>Model: {stage.model}</small> : null}
                      {stage.error ? <p>{stage.error}</p> : null}
                    </div>
                  </article>
                  {index < stages.length - 1 ? <span className="discovery-connector" aria-hidden="true">↓</span> : null}
                </div>
              );
            })}
          </div>

          <div className="discovery-grid">
            <article className="discovery-panel">
              <div className="panel-head">
                <h4>RCA synthesis</h4>
                <p>{report.model ? `Model: ${report.model}` : "Model details not reported"}</p>
              </div>
              <p className="discovery-summary">{report.summary || "Retrieval completed; no synthesis summary was returned."}</p>
              {hypotheses.length ? hypotheses.map((row, index) => (
                <div className="discovery-hypothesis" key={`discovery-hypothesis-${index}`}>
                  <strong>{row.cause || `Hypothesis ${index + 1}`}</strong>
                  <span>{Math.round(Number(row.confidence || 0) * 100)}% confidence</span>
                  <small>Evidence: {(row.supporting_evidence || []).join(", ") || "not cited"}</small>
                </div>
              )) : (
                <p className="subtitle">{report.insufficient_evidence ? "Insufficient evidence for a defensible root-cause hypothesis." : "No hypothesis was returned."}</p>
              )}
            </article>

            <article className="discovery-panel">
              <div className="panel-head">
                <h4>What Was Retrieved From Each Source</h4>
                <p>Every fact retains its source, search match, URI, location, and content hash.</p>
              </div>
              <div className="discovery-source-grid">
                {visibleSources.map((source) => (
                  <div key={`source-${source}`}>
                    <strong>{sourceCounts[source] || 0}</strong>
                    <span>{source}</span>
                  </div>
                ))}
              </div>
              <div className="discovery-evidence-list">
                {evidence.map((row, index) => {
                  const evidenceId = row.evidence_id || `EVIDENCE-${index + 1}`;
                  const citedHypotheses = hypotheses.filter((item) => Array.isArray(item.supporting_evidence) && item.supporting_evidence.includes(evidenceId));
                  const citedByRca = Array.isArray(rcaAnalysis.evidence_used) && rcaAnalysis.evidence_used.includes(evidenceId);
                  const citedByImpact = Array.isArray(impactAnalysis.evidence_used) && impactAnalysis.evidence_used.includes(evidenceId);
                  const contributions = [
                    ...citedHypotheses.map((item) => `Supports hypothesis: ${item.cause || "candidate cause"}`),
                    citedByRca ? "Cited in the derived root-cause conclusion" : "",
                    citedByImpact ? "Cited in the impact assessment" : "",
                  ].filter(Boolean);
                  const sourceType = String(row.source || "source").toLowerCase();
                  return <details key={`evidence-${evidenceId}`}>
                    <summary><strong>{row.evidence_id || `EVIDENCE-${index + 1}`}</strong> · {row.source || "source"}</summary>
                    <small>{row.uri || row.path || "No source URI"}</small>
                    <div className="evidence-purpose" data-cited={contributions.length ? "true" : "false"}>
                      <strong>{contributions.length ? "Used in reasoning" : "Retrieved context only"}</strong>
                      <span>{contributions.length
                        ? contributions.join(". ")
                        : `${sourceType === "code" ? "This source match identifies relevant implementation context" : "This observation provides runtime context"}, but it was not cited as proof of the conclusion.`}</span>
                    </div>
                    {sourceType === "code" ? <small className="evidence-code-label">Source code · lines {row.context_start_line || row.line || "?"}-{row.context_end_line || row.line || "?"}</small> : null}
                    <pre className={`result evidence-content is-${sourceType}`}>{row.snippet || "No evidence content returned."}</pre>
                    {Array.isArray(row.matched_terms) && row.matched_terms.length ? <small>Why retrieved: matched {row.matched_terms.join(", ")}</small> : null}
                    {row.sha256 ? <small>Content hash: {row.sha256}</small> : null}
                  </details>;
                })}
                {!evidence.length ? <p className="subtitle">No cited evidence was returned for this run.</p> : null}
              </div>
            </article>

            <article className="discovery-panel discovery-model-panel">
              <div className="panel-head">
                <h4>Prompt And Response Received</h4>
                <p>{modelInteraction.model ? `${modelInteraction.provider || "provider"} · ${modelInteraction.model}` : "Available for newly processed alerts"}</p>
              </div>
              {modelInteraction.prompt ? (
                <>
                  <div className="discovery-message-label">Prompt</div>
                  <pre className="result discovery-message">{modelInteraction.prompt}</pre>
                  <details>
                    <summary>Request payload sent with the prompt</summary>
                    <pre className="result discovery-message">{JSON.stringify(modelInteraction.request_payload || {}, null, 2)}</pre>
                  </details>
                  <div className="discovery-message-label">Response received</div>
                  <pre className="result discovery-message">{typeof modelInteraction.response_received === "string"
                    ? modelInteraction.response_received
                    : JSON.stringify(modelInteraction.response_received ?? modelInteraction.parsed_response ?? {}, null, 2)}</pre>
                  {modelInteraction.usage && Object.keys(modelInteraction.usage).length ? (
                    <small>Usage: {JSON.stringify(modelInteraction.usage)}</small>
                  ) : null}
                </>
              ) : (
                <p className="subtitle">This alert predates prompt auditing. Reprocess it to capture the exact prompt, evidence payload, model, and response.</p>
              )}
            </article>

            <article className="discovery-panel discovery-outcome-panel">
              <div className="panel-head">
                <h4>Detailed RCA and Impact</h4>
                <p>Root cause, impact scope, and explicit reasoning signals merged from discovery and context metadata.</p>
              </div>
              <div className="table-wrap table-wrap-scroll-x">
                <table>
                  <tbody>
                    <tr><th>Root Cause</th><td>{rootCause}</td></tr>
                    <tr><th>Impact</th><td>{impact}</td></tr>
                    <tr><th>Recommended Action</th><td>{recommendedAction}</td></tr>
                  </tbody>
                </table>
              </div>
              {detailedReasons.length ? (
                <div>
                  <h5 style={{ margin: "8px 0 6px" }}>Reason Breakdown</h5>
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {detailedReasons.map((reason, index) => (
                      <li key={`discovery-reason-${index}`}>{reason}</li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="subtitle">No explicit reason trace was returned by this run.</p>
              )}
            </article>
          </div>
        </>
      ) : (
        <div className="discovery-empty">
          <strong>No Discovery Agent trace exists for this alert.</strong>
          <p>Process a fresh alert after the MCP deployment. This view will construct itself from the stages and evidence returned by that run.</p>
        </div>
      )}
    </section>
  );
}

function parseStructuredIntelligence(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value;
  }
  const text = String(value || "").trim();
  if (!text) {
    return null;
  }
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidates = [fenced?.[1], text];
  const firstBrace = text.indexOf("{");
  const lastBrace = text.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    candidates.push(text.slice(firstBrace, lastBrace + 1));
  }
  for (const candidate of candidates.filter(Boolean)) {
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch (_error) {
      // Continue through compatible legacy model-response shapes.
    }
  }
  return null;
}

function intelligenceListText(value) {
  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (item && typeof item === "object") {
          return item.snippet || item.summary || item.evidence_id || item.id || Object.values(item).filter(Boolean).join(": ");
        }
        return String(item || "").trim();
      })
      .filter(Boolean)
      .join("; ");
  }
  if (value && typeof value === "object") {
    return Object.entries(value)
      .map(([key, item]) => `${key.replaceAll("_", " ")}: ${intelligenceListText(item)}`)
      .join("; ");
  }
  return String(value || "").trim();
}

function groundedIntelligenceDisplay(label, value, structuredOverride) {
  // structuredOverride is recommendation.metadata.grounding — the RCA
  // model's full structured response (evidence_used/alternative_causes/
  // missing_evidence/grounding_notes/confidence_score), preserved
  // server-side instead of being discarded. root_cause itself is always
  // plain text (never JSON), so it isn't in this object — headline still
  // falls back to `value` below.
  const hasOverride =
    structuredOverride &&
    typeof structuredOverride === "object" &&
    Object.values(structuredOverride).some((entry) => entry !== null && entry !== undefined && entry !== "");
  const parsed = hasOverride ? { ...(parseStructuredIntelligence(value) || {}), ...structuredOverride } : parseStructuredIntelligence(value);
  if (!parsed) {
    return { headline: cleanRecommendationText(value, `No ${label.toLowerCase()} was produced.`), details: [] };
  }
  const isRca = label === "RCA";
  const isImpact = label === "Impact";
  const isCodeReview = label === "Code review";
  const headlineCandidate = String(
    isRca
      ? parsed.root_cause || parsed.cause || parsed.summary || value
      : isImpact
        ? parsed.impact_summary || parsed.service_impact || parsed.customer_impact || parsed.severity_rationale || parsed.summary
        : isCodeReview
          ? parsed.summary || parsed.findings_summary || parsed.defensive_coding_summary || parsed.review_summary || parsed.recommended_action || parsed.action
        : parsed.recommended_action || parsed.action || parsed.summary
  ).trim();
  const headline = cleanRecommendationText(headlineCandidate, `No ${label.toLowerCase()} was produced.`);
  const detailCandidates = isRca
    ? [
        ["Evidence used", parsed.evidence_used],
        ["Alternative causes", parsed.alternative_causes],
        ["Missing evidence", parsed.missing_evidence],
        ["Grounding notes", parsed.grounding_notes],
      ]
    : isImpact
      ? [
          ["Impacted services", parsed.impacted_services],
          ["Customer impact", parsed.customer_impact],
          ["Dependency impact", parsed.dependency_impact],
          ["Blast radius", parsed.blast_radius],
          ["Evidence used", parsed.evidence_used],
          ["Missing evidence", parsed.missing_evidence],
          ["Assumptions", parsed.assumptions],
        ]
      : isCodeReview
        ? [
            ["Reviewed source code", parsed.reviewed_sources],
            ["Reviewed evidence IDs", parsed.reviewed_evidence_ids],
            ["Defensive coding required", parsed.defensive_coding_required],
            ["Issues", parsed.issues],
            ["Potential bugs", parsed.potential_bugs],
            ["Missing guards", parsed.missing_guards],
            ["Findings", parsed.findings],
            ["Proposed patches", parsed.code_patches],
            ["Evidence gaps", parsed.evidence_gaps],
            ["Review notes", parsed.review_notes],
            ["Recommended fix", parsed.recommended_fix],
          ]
      : [
          ["Why", parsed.why_this_action],
          ["Blocked corrective candidate", parsed.blocked_candidate_action],
          ["Validation", parsed.validation_queries],
          ["Rollback", parsed.rollback_plan],
          ["Missing evidence", parsed.missing_evidence],
        ];
  const details = detailCandidates
    .map(([detailLabel, detailValue]) => ({ label: detailLabel, value: intelligenceListText(detailValue) }))
    .filter((item) => item.value);
  const confidence = Number(parsed.confidence_score);
  if (Number.isFinite(confidence) && confidence >= 0) {
    details.push({ label: "Confidence", value: `${Math.round(confidence * 100)}%` });
  }
  return { headline, details };
}

function canonicalIncidentAnalysis(workflow, alertRow = null) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const recommendation = safeWorkflow.recommendation && typeof safeWorkflow.recommendation === "object"
    ? safeWorkflow.recommendation
    : {};
  const metadata = recommendation.metadata && typeof recommendation.metadata === "object"
    ? recommendation.metadata
    : {};
  const contextMetadata = safeWorkflow?.context?.metadata && typeof safeWorkflow.context.metadata === "object"
    ? safeWorkflow.context.metadata
    : {};
  const discovery = contextMetadata.discovery_report && typeof contextMetadata.discovery_report === "object"
    ? contextMetadata.discovery_report
    : {};
  const report = discovery.report && typeof discovery.report === "object" ? discovery.report : {};
  const hypotheses = Array.isArray(report.hypotheses) ? report.hypotheses : [];
  const rca = metadata.rca_analysis && typeof metadata.rca_analysis === "object" ? metadata.rca_analysis : {};
  const impact = metadata.impact_analysis && typeof metadata.impact_analysis === "object" ? metadata.impact_analysis : {};
  const remediation = metadata.remediation_analysis && typeof metadata.remediation_analysis === "object"
    ? metadata.remediation_analysis
    : {};
  const confirmedRootCause = cleanRecommendationText(
    rca.root_cause || recommendation.root_cause || safeWorkflow.root_cause,
    "",
  );
  const hypothesis = hypotheses.find((item) => item && item.cause);
  const rootCause = confirmedRootCause
    || (hypothesis ? `Hypothesis (not confirmed): ${cleanRecommendationText(hypothesis.cause, "")}` : "")
    || "RCA pending: available evidence is insufficient for a grounded conclusion.";
  const explicitImpact = cleanRecommendationText(
    impact.impact_summary
      || impact.customer_impact
      || impact.service_impact
      || recommendation.impact
      || safeWorkflow.impact,
    "",
  );
  const action = cleanRecommendationText(
    remediation.recommended_action || recommendation.recommended_action || safeWorkflow.recommended_action,
    "",
  );
  const externalKnowledgeUsed = Boolean(
    rca.external_knowledge_used
      || report.external_knowledge_used
      || metadata.external_knowledge_used
  );
  const externalKnowledgeEligible = Boolean(
    report.external_knowledge_eligible
      || metadata.external_knowledge_eligible
  );
  const externalKnowledgeError = cleanRecommendationText(
    report.external_knowledge_error || metadata.external_knowledge_error,
    "",
  );
  const rcaStatus = String(metadata.rca_status || "").trim().toLowerCase();
  const analysisStatus = rcaStatus === "insufficient_evidence"
    ? "insufficient-evidence"
    : rcaStatus === "grounded"
      ? "resolved-analysis"
      : confirmedRootCause
        ? "resolved-analysis"
        : hypothesis ? "hypothesis" : "insufficient-evidence";
  return {
    rootCause,
    impact: explicitImpact || "Impact not established from current evidence.",
    action: action || "Recommended action pending grounded RCA.",
    rca,
    impactAnalysis: impact,
    remediation,
    status: analysisStatus,
    confidence: Number(recommendation.confidence ?? rca.confidence_score ?? hypothesis?.confidence ?? 0),
    externalKnowledgeUsed,
    externalKnowledgeEligible,
    externalKnowledgeError,
    externalKnowledgeStatus: externalKnowledgeUsed
      ? "used"
      : externalKnowledgeError
        ? `failed: ${externalKnowledgeError}`
        : externalKnowledgeEligible
          ? "eligible; no configured external evidence returned"
          : "not required",
    externalToolsUsed: Array.isArray(metadata.external_tools_used)
      ? metadata.external_tools_used
      : Array.isArray(report.external_tools_used)
        ? report.external_tools_used
        : [],
    service: alertRow?.service || safeWorkflow?.alert?.service || recommendation?.metadata?.service || "unknown",
  };
}

function downloadInvestigationArtifact(filename, payload) {
  const safeName = String(filename || "kaiops-investigation.json")
    .replace(/[^a-z0-9._-]+/gi, "-")
    .replace(/-+/g, "-")
    .toLowerCase();
  const content = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  const blob = new Blob([content], {
    type: typeof payload === "string" ? "text/plain;charset=utf-8" : "application/json;charset=utf-8",
  });
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = safeName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

function IntelligenceConnectionView({
  workflow,
  documents = [],
  onDownloadDocument,
}) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const context = safeWorkflow.context && typeof safeWorkflow.context === "object" ? safeWorkflow.context : {};
  const metadata = context.metadata && typeof context.metadata === "object" ? context.metadata : {};
  const discovery = metadata.discovery_report && typeof metadata.discovery_report === "object" ? metadata.discovery_report : {};
  const report = discovery.report && typeof discovery.report === "object" ? discovery.report : {};
  const evidence = Array.isArray(discovery.evidence) ? discovery.evidence : [];
  const recommendation = safeWorkflow.recommendation && typeof safeWorkflow.recommendation === "object"
    ? safeWorkflow.recommendation
    : {};
  const canonicalAnalysis = canonicalIncidentAnalysis(safeWorkflow);
  const ragMatches = Array.isArray(metadata.rag_matches) ? metadata.rag_matches : [];
  const sourceCounts = evidence.reduce((result, item) => {
    const source = String(item?.source || "other").toLowerCase();
    result[source] = (result[source] || 0) + 1;
    return result;
  }, {});
  const contextItems = [
    context.deployment ? { label: "Deployment", value: context.deployment, source: "Jenkins / alert / RAG deployment" } : null,
    Array.isArray(context.dependency_services) && context.dependency_services.length
      ? { label: "Dependencies", value: context.dependency_services.join(", "), source: "CMDB + dependency documents" }
      : null,
    Array.isArray(context.related_incidents) && context.related_incidents.length
      ? { label: "Related incidents", value: `${context.related_incidents.length} historical incident(s)`, source: "RAG incident search" }
      : null,
    Array.isArray(context.recent_changes) && context.recent_changes.length
      ? { label: "Recent changes", value: `${context.recent_changes.length} change record(s)`, source: "ServiceNow + GitHub + RAG changes" }
      : null,
    context.runbook ? { label: "Runbook", value: compactText(context.runbook, 180), source: "RAG runbook retrieval" } : null,
    ragMatches.length ? { label: "Ranked documents", value: `${ragMatches.length} semantic/metadata match(es)`, source: "Vector and metadata search" } : null,
    evidence.length ? { label: "Discovery evidence", value: `${evidence.length} grounded fact(s)`, source: "Discovery MCP" } : null,
  ].filter(Boolean);
  const hypotheses = Array.isArray(report.hypotheses) ? report.hypotheses : [];
  const recommendationMetadata = recommendation.metadata && typeof recommendation.metadata === "object"
    ? recommendation.metadata
    : {};
  const rcaAnalysis = recommendationMetadata.rca_analysis && typeof recommendationMetadata.rca_analysis === "object"
    ? recommendationMetadata.rca_analysis
    : {};
  const impactAnalysis = recommendationMetadata.impact_analysis && typeof recommendationMetadata.impact_analysis === "object"
    ? recommendationMetadata.impact_analysis
    : {};
  const remediationAnalysis = recommendationMetadata.remediation_analysis && typeof recommendationMetadata.remediation_analysis === "object"
    ? recommendationMetadata.remediation_analysis
    : {};
  const detectedErrors = Array.isArray(report.detected_errors)
    ? report.detected_errors
    : Array.isArray(discovery.detected_errors)
      ? discovery.detected_errors
      : Array.isArray(recommendationMetadata.detected_errors)
        ? recommendationMetadata.detected_errors
        : [];
  const supportingIds = Array.from(new Set([
    ...(Array.isArray(report.citations) ? report.citations : []),
    ...hypotheses.flatMap((item) => Array.isArray(item?.supporting_evidence) ? item.supporting_evidence : []),
    // evidence_used entries are sometimes descriptive objects ({source,
    // details}), not evidence-ID strings — the RCA prompt schema allows
    // both. Only string entries belong in the citation-ID list; spreading
    // objects in here made them hit .join() below and render as the
    // literal text "[object Object]".
    ...(Array.isArray(rcaAnalysis.evidence_used) ? rcaAnalysis.evidence_used.filter((item) => typeof item === "string") : []),
    ...(Array.isArray(impactAnalysis.evidence_used) ? impactAnalysis.evidence_used.filter((item) => typeof item === "string") : []),
  ].filter(Boolean)));
  const queryTerms = Array.isArray(discovery.query_terms)
    ? discovery.query_terms
    : Array.isArray(metadata.query_terms)
      ? metadata.query_terms
      : [];
  const recentChanges = Array.isArray(context.recent_changes) ? context.recent_changes : [];
  const dependencies = Array.isArray(context.dependency_services) ? context.dependency_services : [];
  const relatedIncidents = Array.isArray(context.related_incidents) ? context.related_incidents : [];
  const reasoningConfidence = Number(
    recommendation.confidence
    ?? rcaAnalysis.confidence_score
    ?? report.confidence_score
    ?? 0
  );
  const storyStages = [
    {
      id: "signal",
      number: "01",
      eyebrow: "Question formed",
      title: "Alert becomes a search plan",
      summary: "Service, alert name, environment, symptoms, and scenario are converted into focused retrieval terms.",
      metric: queryTerms.length || "Auto",
      metricLabel: queryTerms.length === 1 ? "query term" : "query terms",
      tags: queryTerms.slice(0, 5),
      tone: "blue",
    },
    {
      id: "discover",
      number: "02",
      eyebrow: "Read-only discovery",
      title: "Tools return source facts",
      summary: "Logs, tickets, traces, metrics, and code are searched. Every useful fact keeps its source and immutable evidence ID.",
      metric: evidence.length,
      metricLabel: evidence.length === 1 ? "grounded fact" : "grounded facts",
      tags: Object.entries(sourceCounts).map(([source, count]) => `${source} ${count}`).slice(0, 5),
      tone: "violet",
    },
    {
      id: "context",
      number: "03",
      eyebrow: "Context retrieval",
      title: "Facts are connected to operations",
      summary: "Semantic and metadata search rank documents, then merge dependencies, recent changes, related incidents, and runbook guidance.",
      metric: ragMatches.length || documents.length,
      metricLabel: "ranked documents",
      tags: [
        dependencies.length ? `${dependencies.length} dependencies` : "",
        recentChanges.length ? `${recentChanges.length} changes` : "",
        relatedIncidents.length ? `${relatedIncidents.length} incidents` : "",
        context.runbook ? "runbook found" : "",
      ].filter(Boolean),
      tone: "green",
    },
    {
      id: "reason",
      number: "04",
      eyebrow: "Grounded reasoning",
      title: "RCA and impact are derived",
      summary: "The reasoning agent compares hypotheses against collected context, retains alternatives and missing evidence, and cites supporting facts.",
      metric: Number.isFinite(reasoningConfidence) && reasoningConfidence > 0 ? `${Math.round(reasoningConfidence * 100)}%` : supportingIds.length,
      metricLabel: Number.isFinite(reasoningConfidence) && reasoningConfidence > 0 ? "confidence" : "citations",
      tags: supportingIds.slice(0, 4),
      tone: "orange",
    },
    {
      id: "act",
      number: "05",
      eyebrow: "Decision ready",
      title: "Evidence becomes an action",
      summary: "RCA, impact, and safety constraints produce an operator-readable recommendation for approval, execution, and validation.",
      metric: recommendation.recommended_action ? "Ready" : "Pending",
      metricLabel: "recommended action",
      tags: ["approval gate", "guarded execution", "recovery validation"],
      tone: "red",
    },
  ];
  const outputs = [
    {
      label: "RCA",
      value: Object.keys(rcaAnalysis).length
        ? {
            ...rcaAnalysis,
            root_cause: cleanRecommendationText(
              rcaAnalysis.root_cause
              || recommendation.root_cause
              || (hypotheses[0]?.cause ? `Hypothesis (needs validation): ${hypotheses[0].cause}` : ""),
              "RCA pending: available evidence is insufficient for a grounded conclusion.",
            ),
            evidence_used: Array.isArray(rcaAnalysis.evidence_used) && rcaAnalysis.evidence_used.length
              ? rcaAnalysis.evidence_used
              : (hypotheses[0]?.supporting_evidence || []).filter((item) => typeof item === "string"),
            confidence_score: Number.isFinite(Number(rcaAnalysis.confidence_score))
              ? Number(rcaAnalysis.confidence_score)
              : Number(recommendation.confidence ?? report.confidence_score ?? hypotheses[0]?.confidence ?? 0),
          }
        : recommendation.root_cause || (hypotheses[0] && {
            root_cause: hypotheses[0].cause,
            evidence_used: hypotheses[0].supporting_evidence,
            alternative_causes: hypotheses.slice(1).map((item) => item.cause),
            confidence_score: hypotheses[0].confidence,
            grounding_notes: report.summary,
          }) || canonicalAnalysis.rootCause,
    },
    {
      label: "Impact",
      value: Object.keys(impactAnalysis).length
        ? {
            ...impactAnalysis,
            impact_summary: cleanRecommendationText(
              impactAnalysis.impact_summary
              || impactAnalysis.customer_impact
              || impactAnalysis.service_impact
              || recommendation.impact
              || report.impact,
              "Impact not established from current evidence.",
            ),
            evidence_used: Array.isArray(impactAnalysis.evidence_used) && impactAnalysis.evidence_used.length
              ? impactAnalysis.evidence_used
              : [],
            confidence_score: Number.isFinite(Number(impactAnalysis.confidence_score))
              ? Number(impactAnalysis.confidence_score)
              : Number(recommendation.confidence ?? report.confidence_score ?? 0),
          }
        : recommendation.impact || report.impact || canonicalAnalysis.impact,
    },
    {
      label: "Code review",
      value: report.code_review && typeof report.code_review === "object"
        ? {
            ...report.code_review,
            reviewed_sources: (Array.isArray(report.code_review.reviewed_sources) ? report.code_review.reviewed_sources : [])
              .map((source) => ({
                evidence_id: source?.evidence_id,
                source_uri: source?.source_uri,
                snippet: source?.snippet,
              })),
            findings: (Array.isArray(report.code_review.findings) ? report.code_review.findings : []).map((finding) => ({
              title: finding?.title,
              severity: finding?.severity,
              explanation: finding?.explanation,
              evidence_id: finding?.evidence_id,
              source_uri: finding?.source_uri,
              patch_limitations: finding?.patch_limitations,
            })),
            code_patches: (Array.isArray(report.code_review.findings) ? report.code_review.findings : [])
              .filter((finding) => String(finding?.patch || "").trim())
              .map((finding) => ({
                evidence_id: finding?.evidence_id,
                source_uri: finding?.source_uri,
                unified_diff: finding.patch,
              })),
          }
        : {
            status: "not_performed",
            summary: "Code review was not performed because discovery returned no source=\"code\" evidence for this alert. This is an evidence-coverage issue, not a performance timeout.",
            insufficient_context: true,
            findings: [],
            code_patches: [],
          },
    },
    {
      label: "Recommended action",
      value: Object.keys(remediationAnalysis).length
        ? remediationAnalysis.execution_ready === false
          ? {
              ...remediationAnalysis,
              recommended_action: Array.isArray(rcaAnalysis.missing_evidence) && rcaAnalysis.missing_evidence.length
                ? `Collect missing evidence (${rcaAnalysis.missing_evidence.join(", ")}) and rerun analysis.`
                : "Collect the next required diagnostic evidence and rerun analysis.",
              why_this_action: "Corrective execution is blocked because the causal hypothesis is not sufficiently corroborated.",
              blocked_candidate_action: remediationAnalysis.recommended_action,
            }
          : remediationAnalysis
        : recommendation.recommended_action || (Array.isArray(report.recommended_next_checks)
          ? {
              recommended_action: report.recommended_next_checks[0],
              validation_queries: report.recommended_next_checks.slice(1),
              missing_evidence: report.insufficient_evidence ? ["Resolution Agent output is not available yet."] : [],
            }
          : canonicalAnalysis.action),
    },
  ].map((item) => ({
    ...item,
    display: groundedIntelligenceDisplay(item.label, item.value, item.label === "RCA" ? recommendation.metadata?.grounding : null),
  }));
  const investigationPackage = {
    generated_at: new Date().toISOString(),
    alert: safeWorkflow.alert || {},
    incident: safeWorkflow.incident || {},
    query_plan: { query_terms: queryTerms, retrieval_stages: discovery.retrieval_stages || [] },
    discovery_evidence: evidence,
    assembled_context: context,
    ranked_documents: ragMatches,
    linked_documents: documents,
    hypotheses,
    detected_errors: detectedErrors,
    citations: supportingIds,
    recommendation,
  };
  const stageArtifact = (stageId) => {
    if (stageId === "signal") return investigationPackage.query_plan;
    if (stageId === "discover") return { source_counts: sourceCounts, evidence };
    if (stageId === "context") return { context, ranked_documents: ragMatches, linked_documents: documents };
    if (stageId === "reason") {
      return {
        report,
        hypotheses,
        citations: supportingIds,
        rca_analysis: rcaAnalysis,
        impact_analysis: impactAnalysis,
        root_cause: recommendation.root_cause,
        impact: recommendation.impact,
      };
    }
    return {
      recommended_action: recommendation.recommended_action,
      remediation_analysis: remediationAnalysis,
      preventive_action: recommendation.preventive_action,
      validation: recommendation.validation || report.recommended_next_checks || [],
      approval: safeWorkflow.approval || {},
    };
  };

  return (
    <section className="intelligence-connection">
      <header>
        <div>
          <span className="discovery-eyebrow">Connected data lineage</span>
          <h3>Discovery Evidence → Context Assembly → RCA & Impact</h3>
          <p>This is the handoff between the two agents. Only retrieved evidence and assembled context should support downstream conclusions.</p>
        </div>
        <div className="intelligence-header-actions">
          <span className={`workflow-pill ${evidence.length || contextItems.length ? "workflow-pill-active" : "workflow-pill-idle"}`}>
            {evidence.length || contextItems.length ? "connected" : "no context"}
          </span>
          <button type="button" className="button-primary" onClick={() => downloadInvestigationArtifact("kaiops-complete-investigation.json", investigationPackage)}>
            Download complete investigation
          </button>
        </div>
      </header>
      <div className="investigation-story">
        <div className="investigation-story-intro">
          <span>How KaiMS reached this conclusion</span>
          <strong>Every conclusion moves through an observable, evidence-backed handoff.</strong>
        </div>
        <div className="investigation-story-track">
          {storyStages.map((stage, index) => (
            <div className="investigation-story-segment" key={stage.id}>
              <article className={`investigation-story-card tone-${stage.tone}`}>
                <header>
                  <span className="investigation-story-number">{stage.number}</span>
                  <div>
                    <small>{stage.eyebrow}</small>
                    <h4>{stage.title}</h4>
                  </div>
                </header>
                <p>{stage.summary}</p>
                <div className="investigation-story-metric">
                  <strong>{stage.metric}</strong>
                  <span>{stage.metricLabel}</span>
                </div>
                <div className="investigation-story-tags">
                  {stage.tags.length
                    ? stage.tags.map((tag) => <span key={`${stage.id}-${tag}`}>{compactText(tag, 30)}</span>)
                    : <span>Awaiting persisted data</span>}
                </div>
                <button
                  type="button"
                  className="investigation-download-button"
                  onClick={() => downloadInvestigationArtifact(`kaiops-${stage.number}-${stage.id}.json`, stageArtifact(stage.id))}
                >
                  Download {stage.id === "discover" ? "evidence & logs" : stage.id === "context" ? "context & documents" : stage.id === "reason" ? "RCA & impact" : stage.id === "act" ? "action plan" : "search plan"}
                </button>
              </article>
              {index < storyStages.length - 1 ? (
                <div className="investigation-story-handoff" aria-hidden="true">
                  <i>→</i>
                  <small>{index === 0 ? "query" : index === 1 ? "evidence" : index === 2 ? "context" : "decision"}</small>
                </div>
              ) : null}
            </div>
          ))}
        </div>
      </div>
      <div className="intelligence-lineage-heading">
        <span className="discovery-eyebrow">Live lineage from this alert</span>
        <h4>Inspect exactly what entered each stage</h4>
        <p>Source facts are shown on the left, assembled operational context in the middle, and the derived conclusions on the right.</p>
      </div>
      <div className="intelligence-connection-flow">
        <article className="intelligence-column intelligence-discovery-column">
          <span className="intelligence-column-step">1</span>
          <h4>Issues and facts discovered</h4>
          <p className="subtitle">Raw facts with immutable evidence IDs and source provenance.</p>
          <div className="intelligence-source-list">
            {Object.entries(sourceCounts).map(([source, count]) => (
              <div key={`lineage-source-${source}`}><strong>{count}</strong><span>{source}</span></div>
            ))}
            {!Object.keys(sourceCounts).length ? <small>No MCP evidence stored for this alert.</small> : null}
          </div>
          {evidence.slice(0, 6).map((item, index) => (
            <div className="intelligence-fact" key={`lineage-evidence-${item.evidence_id || index}`}>
              <strong>{item.evidence_id || `FACT-${index + 1}`}</strong>
              <span>{item.source || "source"} · {compactText(item.snippet, 150)}</span>
              <button
                type="button"
                className="intelligence-inline-download"
                onClick={() => downloadInvestigationArtifact(`kaiops-${item.source || "evidence"}-${item.evidence_id || index + 1}.json`, item)}
              >
                Download {String(item.source || "evidence").toLowerCase()}
              </button>
            </div>
          ))}
        </article>
        <span className="intelligence-handoff" aria-hidden="true">→</span>
        <article className="intelligence-column intelligence-context-column">
          <span className="intelligence-column-step">2</span>
          <h4>Context Intelligence assembled</h4>
          <p className="subtitle">Operational context merged with Discovery evidence before reasoning.</p>
          {contextItems.map((item) => (
            <div className="intelligence-context-item" key={`context-item-${item.label}`}>
              <strong>{item.label}</strong>
              <span>{item.value}</span>
              <small>Retrieved from: {item.source}</small>
            </div>
          ))}
          {!contextItems.length ? <p className="subtitle">No structured context payload is attached to this alert.</p> : null}
        </article>
        <span className="intelligence-handoff" aria-hidden="true">→</span>
        <article className="intelligence-column intelligence-output-column">
          <span className="intelligence-column-step">3</span>
          <h4>Grounded intelligence produced</h4>
          <p className="subtitle">RCA, impact, and action generated from the context shown to the left.</p>
          {detectedErrors.length ? (
            <div className="intelligence-output-item">
              <strong>Detected application errors ({detectedErrors.length})</strong>
              {detectedErrors.map((error, index) => (
                <div className="intelligence-fact" key={`detected-error-${error?.evidence_id || index}`}>
                  <strong>{error?.service || error?.container || `Application error ${index + 1}`}</strong>
                  <span>{compactText(error?.message, 320)}</span>
                  <small>
                    {[error?.timestamp, ...(Array.isArray(error?.signals) ? error.signals : []), error?.evidence_id]
                      .filter(Boolean)
                      .join(" · ")}
                  </small>
                </div>
              ))}
              <button
                type="button"
                className="intelligence-inline-download"
                onClick={() => downloadInvestigationArtifact("kaiops-detected-application-errors.json", detectedErrors)}
              >
                Download detected errors
              </button>
            </div>
          ) : null}
          {outputs.map((item) => (
            <div className="intelligence-output-item" key={`output-${item.label}`}>
              <strong>{item.label}</strong>
              <span>{item.display.headline}</span>
              {item.display.details.length ? (
                <dl className="intelligence-output-details">
                  {item.display.details.map((detail) => (
                    <div key={`${item.label}-${detail.label}`}>
                      <dt>{detail.label}</dt>
                      <dd>{detail.value}</dd>
                    </div>
                  ))}
                </dl>
              ) : null}
              {item.label === "Code review" && Array.isArray(item.value?.reviewed_sources)
                ? item.value.reviewed_sources.map((source, sourceIndex) => (
                    <div
                      className="code-review-patch"
                      key={`code-review-source-${source?.evidence_id || sourceIndex}`}
                    >
                      <strong>{source?.source_uri || `Reviewed source ${sourceIndex + 1}`}</strong>
                      <small>Reviewed as {source?.evidence_id || "code evidence"}</small>
                      {String(source?.snippet || "").trim() ? (
                        <pre><code>{source.snippet}</code></pre>
                      ) : (
                        <span>No source excerpt was returned for this evidence item.</span>
                      )}
                    </div>
                  ))
                : null}
              {item.label === "Code review" && Array.isArray(item.value?.code_patches)
                ? item.value.code_patches.map((patch, patchIndex) => (
                    <div
                      className="code-review-patch"
                      key={`code-review-patch-${patch?.evidence_id || patchIndex}`}
                    >
                      <strong>{patch?.source_uri || patch?.evidence_id || `Patch ${patchIndex + 1}`}</strong>
                      <small>Grounded by {patch?.evidence_id || "unknown evidence"}</small>
                      <pre><code>{patch?.unified_diff}</code></pre>
                    </div>
                  ))
                : null}
              <button
                type="button"
                className="intelligence-inline-download"
                onClick={() => downloadInvestigationArtifact(`kaiops-${item.label}.json`, {
                  type: item.label,
                  value: item.value,
                  display: item.display,
                  citations: supportingIds,
                })}
              >
                Download {item.label}
              </button>
            </div>
          ))}
          <div className="intelligence-citations">
            <strong>Supporting evidence IDs</strong>
            <span>{supportingIds.join(", ") || "No explicit citations returned"}</span>
          </div>
          <div className="intelligence-document-downloads">
            <strong>{documents.length} linked document(s)</strong>
            {documents.length ? (
              <button
                type="button"
                className="button-primary"
                onClick={() => downloadInvestigationArtifact("kaiops-linked-document-package.json", {
                  documents,
                  ranked_matches: ragMatches,
                  assembled_context: context,
                })}
              >
                Download all documents + context
              </button>
            ) : null}
            {documents.slice(0, 6).map((doc, index) => (
              <button
                type="button"
                className="button-secondary"
                key={`intelligence-download-${doc?.path || doc?.document_id || doc?.title || index}`}
                disabled={!doc?.path && !doc?.content && !doc?.summary && !doc?.recommended_action}
                onClick={() => onDownloadDocument && onDownloadDocument(doc)}
              >
                Download {compactText(doc?.title || doc?.path || `Document ${index + 1}`, 34)}
              </button>
            ))}
            {!documents.length ? <small>No alert-linked document is available yet.</small> : null}
          </div>
        </article>
      </div>
    </section>
  );
}

function ContextRetrievalGraph({ workflow, timelineRows, documents, evaluation, documentContract, onLoadDocumentContent, onDownloadDocument, compact = false }) {
  const [documentPreviewState, setDocumentPreviewState] = useState({ key: "", loading: false, content: null, error: "" });
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeTimelineRows = Array.isArray(timelineRows) ? timelineRows : [];
  const safeDocuments = Array.isArray(documents) ? documents : [];
  const recommendation = safeWorkflow.recommendation && typeof safeWorkflow.recommendation === "object" ? safeWorkflow.recommendation : {};
  const recommendationMetadata = recommendation.metadata && typeof recommendation.metadata === "object" ? recommendation.metadata : {};
  const context = safeWorkflow.context && typeof safeWorkflow.context === "object" ? safeWorkflow.context : {};
  const contextMetadata = context.metadata && typeof context.metadata === "object" ? context.metadata : {};
  const contextTraceRow = safeTimelineRows
    .slice()
    .reverse()
    .find((row) => {
      const text = `${row?.stage || ""} ${row?.service || ""} ${row?.agent || ""} ${row?.outputValueText || ""}`.toLowerCase();
      return text.includes("context") || text.includes("rag") || text.includes("semantic") || text.includes("vector");
    });
  const parseMaybeJson = (value) => {
    const text = String(value || "").trim();
    if (!text) {
      return null;
    }
    try {
      const parsed = JSON.parse(text);
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch (_error) {
      return null;
    }
  };
  const contextTraceOutput = parseMaybeJson(contextTraceRow?.outputValueText) || {};
  const traceMetadata = contextTraceOutput.metadata && typeof contextTraceOutput.metadata === "object" ? contextTraceOutput.metadata : {};
  const discoveryEvidence =
    (contextMetadata.discovery_evidence && typeof contextMetadata.discovery_evidence === "object" && contextMetadata.discovery_evidence)
    || (recommendationMetadata.discovery_evidence && typeof recommendationMetadata.discovery_evidence === "object" && recommendationMetadata.discovery_evidence)
    || (traceMetadata.discovery_evidence && typeof traceMetadata.discovery_evidence === "object" && traceMetadata.discovery_evidence)
    || {};
  const discoveryMcp =
    (contextMetadata.discovery_report && typeof contextMetadata.discovery_report === "object" && contextMetadata.discovery_report)
    || (recommendationMetadata.discovery_report && typeof recommendationMetadata.discovery_report === "object" && recommendationMetadata.discovery_report)
    || (traceMetadata.discovery_report && typeof traceMetadata.discovery_report === "object" && traceMetadata.discovery_report)
    || {};
  const discoveryReport = discoveryMcp.report && typeof discoveryMcp.report === "object" ? discoveryMcp.report : {};
  const mcpEvidence = Array.isArray(discoveryMcp.evidence) ? discoveryMcp.evidence : [];
  const retrievalStages = Array.isArray(discoveryMcp.retrieval_stages) ? discoveryMcp.retrieval_stages : [];
  const hypotheses = Array.isArray(discoveryReport.hypotheses) ? discoveryReport.hypotheses : [];
  const codeMatches = Array.isArray(discoveryEvidence.code_matches) ? discoveryEvidence.code_matches : [];
  const logMatches = Array.isArray(discoveryEvidence.log_matches) ? discoveryEvidence.log_matches : [];
  const ragMatches =
    (Array.isArray(contextMetadata.rag_matches) && contextMetadata.rag_matches)
    || (Array.isArray(recommendationMetadata.rag_matches) && recommendationMetadata.rag_matches)
    || (Array.isArray(traceMetadata.rag_matches) && traceMetadata.rag_matches)
    || [];
  const ragIndex =
    (contextMetadata.rag_index && typeof contextMetadata.rag_index === "object" && contextMetadata.rag_index)
    || (recommendationMetadata.rag_index && typeof recommendationMetadata.rag_index === "object" && recommendationMetadata.rag_index)
    || (traceMetadata.rag_index && typeof traceMetadata.rag_index === "object" && traceMetadata.rag_index)
    || {};
  const firstDoc = safeDocuments[0] || {};
  const embeddingModel =
    (ragIndex.embedding_model && typeof ragIndex.embedding_model === "object" && ragIndex.embedding_model)
    || (firstDoc.embedding_model && typeof firstDoc.embedding_model === "object" && firstDoc.embedding_model)
    || {};
  const vectorStore =
    (ragIndex.vector_store && typeof ragIndex.vector_store === "object" && ragIndex.vector_store)
    || (firstDoc.vector_store && typeof firstDoc.vector_store === "object" && firstDoc.vector_store)
    || {};
  const alert = safeWorkflow.alert && typeof safeWorkflow.alert === "object" ? safeWorkflow.alert : {};
  const queryText = compactText(
    [
      alert.service || safeWorkflow.service,
      alert.name || safeWorkflow.alert_name,
      alert.description || safeWorkflow.description,
      recommendation.title,
    ].filter(Boolean).join(" "),
    180
  ) || "Selected alert service, name, severity, and description";
  const topSimilarity = Number(
    contextMetadata.rag_top_match_confidence
    ?? recommendationMetadata.rag_top_match_confidence
    ?? traceMetadata.rag_top_match_confidence
    ?? contextMetadata.rag_top_similarity
    ?? recommendationMetadata.rag_top_similarity
    ?? traceMetadata.rag_top_similarity
    ?? 0
  );
  const topSemanticScore = Number(
    contextMetadata.rag_top_semantic_score
    ?? recommendationMetadata.rag_top_semantic_score
    ?? traceMetadata.rag_top_semantic_score
    ?? 0
  );
  const topMetadataScore = Number(
    contextMetadata.rag_top_metadata_match_score
    ?? recommendationMetadata.rag_top_metadata_match_score
    ?? traceMetadata.rag_top_metadata_match_score
    ?? 0
  );
  const linkedSummary = documentContract?.document_link_summary && typeof documentContract.document_link_summary === "object"
    ? documentContract.document_link_summary
    : {};
  const reportedDocCount = Number(ragIndex.document_count ?? ragIndex.total_documents ?? linkedSummary.count ?? safeDocuments.length ?? ragMatches.length ?? 0);
  const docCount = Number.isFinite(reportedDocCount) && reportedDocCount > 0 ? reportedDocCount : 0;
  const reportedIndexedCount = Number(ragIndex.embedded_document_count ?? ragIndex.metadata_embedding_count ?? 0);
  const indexedCount = Number.isFinite(reportedIndexedCount) && reportedIndexedCount > 0 ? reportedIndexedCount : 0;
  const touchedDocuments = (safeDocuments.length ? safeDocuments : ragMatches)
    .filter((doc) => doc && typeof doc === "object")
    .slice(0, 8);
  const bestMatch = touchedDocuments[0] || {};
  const hasIndexInfo = hasMeaningfulValue(ragIndex) || hasMeaningfulValue(embeddingModel) || hasMeaningfulValue(vectorStore);
  const embeddingProvider = embeddingModel.provider || (hasIndexInfo ? "configured by backend" : "not reported");
  const embeddingName = embeddingModel.model || (hasIndexInfo ? "not reported" : "not reported");
  const vectorProvider = vectorStore.provider || (hasIndexInfo ? "configured by backend" : "not reported");
  const contextQuality = evaluation && typeof evaluation === "object" ? evaluation : {};
  const flowSteps = [
    {
      id: "receive",
      label: "Query Received",
      meta: "Context agent consumes orchestration-events",
      detail: queryText,
      status: safeWorkflow.incident || alert.name ? "observed" : "inferred",
    },
    {
      id: "normalize",
      label: "Signal Normalized",
      meta: "service + severity + labels + incident id",
      detail: compactText(`${alert.service || "-"} | ${alert.severity || recommendation.severity || "-"} | ${safeWorkflow?.incident?.id || safeWorkflow.incident_id || "-"}`, 160),
      status: alert.service || safeWorkflow.incident_id ? "observed" : "inferred",
    },
    {
      id: "index",
      label: "Index Checked",
      meta: `${docCount || touchedDocuments.length || 0} document(s), ${indexedCount || "metadata"} indexed`,
      detail: `Embedding: ${embeddingName} | Store: ${vectorProvider}`,
      status: docCount || touchedDocuments.length || hasIndexInfo ? "observed" : "warning",
    },
    {
      id: "search",
      label: "Search Ranked",
      meta: `${ragMatches.length || touchedDocuments.length || 0} match(es)`,
      detail: `Confidence ${Number.isFinite(topSimilarity) && topSimilarity > 0 ? `${Math.round(topSimilarity * 100)}%` : "not reported"} | semantic ${Number.isFinite(topSemanticScore) && topSemanticScore > 0 ? `${Math.round(topSemanticScore * 100)}%` : "-"} | metadata ${Number.isFinite(topMetadataScore) && topMetadataScore > 0 ? `${Math.round(topMetadataScore * 100)}%` : "-"}`,
      status: ragMatches.length || touchedDocuments.length ? "observed" : "warning",
    },
    {
      id: "touch",
      label: "Documents Touched",
      meta: bestMatch.title || bestMatch.path || "no linked document title",
      detail: compactText(bestMatch.match_reason || bestMatch.summary || bestMatch.content || bestMatch.path || "Linked alert documents are used as context evidence.", 180),
      status: touchedDocuments.length ? "observed" : "warning",
    },
    {
      id: "assemble",
      label: "Context Prepared",
      meta: "context-events published",
      detail: `Grounding ${Math.round((contextQuality.groundingScore || 0) * 100)}% | Confidence ${Math.round((contextQuality.confidenceScore || recommendation.confidence || 0) * 100)}%`,
      status: contextTraceRow || safeWorkflow.context || recommendation ? "observed" : "inferred",
    },
  ];
  const documentKey = (doc, index = 0) => String(doc?.path || doc?.document_id || doc?.title || `doc-${index}`).trim();
  const documentMetadata = (doc) => ({
    document_id: doc?.document_id || doc?.id || "-",
    title: doc?.title || "-",
    kind: doc?.kind || doc?.document_kind || "-",
    path: doc?.path || "-",
    services: doc?.services || doc?.service || "-",
    owner: doc?.owner || "-",
    version: doc?.version || "-",
    freshness_score: doc?.freshness_score ?? "-",
    embedding_status: doc?.embedding_status || "-",
    vector_store: doc?._vector_store || doc?.vector_store?.provider || "-",
    match_reason: doc?.match_reason || "-",
    match_confidence: doc?.match_confidence ?? doc?._similarity ?? doc?.score ?? "-",
    semantic_score: doc?.semantic_score ?? doc?._semantic_score ?? "-",
    metadata_match_score: doc?.metadata_match_score ?? doc?._metadata_match_score ?? "-",
    source_ref: doc?.source_ref || "-",
  });
  const documentContextExcerpt = (doc) => compactText(
    doc?.context_excerpt
    || doc?.matched_text
    || doc?.snippet
    || doc?.match_reason
    || doc?.summary
    || doc?.recommended_action
    || doc?.content
    || doc?.path,
    320
  ) || "No context excerpt was reported for this document.";
  const viewDocument = async (doc, index) => {
    const key = documentKey(doc, index);
    if (!key) {
      return;
    }
    if (documentPreviewState.key === key && documentPreviewState.content && !documentPreviewState.error) {
      setDocumentPreviewState({ key: "", loading: false, content: null, error: "" });
      return;
    }
    setDocumentPreviewState({ key, loading: true, content: null, error: "" });
    try {
      const loaded = typeof onLoadDocumentContent === "function"
        ? await onLoadDocumentContent(doc)
        : doc;
      setDocumentPreviewState({
        key,
        loading: false,
        content: loaded && typeof loaded === "object" ? loaded : doc,
        error: "",
      });
    } catch (error) {
      setDocumentPreviewState({
        key,
        loading: false,
        content: doc,
        error: String(error?.message || "Unable to load document content."),
      });
    }
  };
  const renderDocumentPreview = (doc, index) => {
    const key = documentKey(doc, index);
    if (documentPreviewState.key !== key) {
      return null;
    }
    const full = documentPreviewState.content && typeof documentPreviewState.content === "object"
      ? documentPreviewState.content
      : doc;
    const metadata = documentMetadata({ ...doc, ...full });
    const body = String(
      full?.content
      || full?.text
      || full?.summary
      || full?.recommended_action
      || doc?.content
      || doc?.summary
      || ""
    ).trim();
    return (
      <div className="context-doc-preview">
        {documentPreviewState.loading ? <p className="subtitle">Loading document content...</p> : null}
        {documentPreviewState.error ? <p className="error">{documentPreviewState.error}</p> : null}
        <details open>
          <summary>Document Metadata</summary>
          <pre className="result">{JSON.stringify(metadata, null, 2)}</pre>
        </details>
        <details open>
          <summary>Document View</summary>
          <pre className="result">{body || "No document body was returned. Metadata is shown above."}</pre>
        </details>
      </div>
    );
  };
  const indexRows = [
    ["Embedding Provider", embeddingProvider],
    ["Embedding Model", embeddingName],
    ["Fallback Model", embeddingModel.fallback_model || "-"],
    ["Fallback Active", embeddingModel.fallback_active ? "yes" : "no"],
    ["Vector Store", vectorProvider],
    ["Enterprise Index", ragIndex.enterprise_index_enabled ? "enabled" : "not enabled"],
    ["Vector Index", (vectorStore.index || vectorStore.index_name || vectorStore.configured) ? String(vectorStore.index || vectorStore.index_name || "configured") : "-"],
    ["Documents Seen", String(docCount || touchedDocuments.length || "-")],
  ];

  return (
    <div className={`context-flow-panel ${compact ? "is-compact" : ""}`}>
      <div className="context-flow-header">
        <div>
          <h3>Context Retrieval Flow</h3>
          <p>Query intake, document indexing, semantic search, document touchpoints, and context assembly for the selected alert.</p>
        </div>
        <div className="context-flow-scoreboard">
          <span><strong>{ragMatches.length || safeDocuments.length}</strong> matches</span>
          <span><strong>{Number.isFinite(topSimilarity) && topSimilarity > 0 ? `${Math.round(topSimilarity * 100)}%` : "-"}</strong> confidence</span>
          <span><strong>{Math.round((contextQuality.groundingScore || 0) * 100) || "-"}</strong> grounding</span>
        </div>
      </div>
      <div className="context-flow-track">
        {flowSteps.map((step, index) => (
          <div className="context-flow-segment" key={step.id}>
            <article className={`context-flow-node status-${step.status}`}>
              <span className="context-flow-step">{index + 1}</span>
              <strong>{step.label}</strong>
              <small>{step.meta}</small>
              <p>{step.detail}</p>
            </article>
            {index < flowSteps.length - 1 ? <span className="context-flow-arrow" aria-hidden="true">-&gt;</span> : null}
          </div>
        ))}
      </div>
      <div className="context-flow-grid">
        <article className="context-flow-detail">
          <div className="panel-head">
            <h4>MCP Discovery And LLM Analysis</h4>
            <p>Read-only log, ticket, and code tools followed by evidence-grounded model reasoning.</p>
          </div>
          <div className="context-flow-scoreboard">
            <span><strong>{mcpEvidence.length}</strong> cited evidence</span>
            <span><strong>{retrievalStages.length}</strong> stages</span>
            <span><strong>{hypotheses.length}</strong> hypotheses</span>
          </div>
          {retrievalStages.length ? (
            <div className="context-doc-list">
              {retrievalStages.map((stage, index) => (
                <div className="context-doc-row" key={`mcp-stage-${index}-${stage.stage || ""}`}>
                  <strong>{String(stage.stage || "stage").replaceAll("_", " ")}</strong>
                  <span>{stage.status || "unknown"}{Number.isFinite(Number(stage.result_count)) ? ` · ${stage.result_count} result(s)` : ""}</span>
                  {stage.error ? <small>{stage.error}</small> : null}
                </div>
              ))}
            </div>
          ) : <p className="subtitle">No MCP retrieval trace was returned for this alert.</p>}
          {discoveryReport.summary ? <p>{discoveryReport.summary}</p> : null}
          {hypotheses.map((hypothesis, index) => (
            <div className="context-doc-row" key={`mcp-hypothesis-${index}`}>
              <strong>{hypothesis.cause || `Hypothesis ${index + 1}`}</strong>
              <span>Confidence {Math.round(Number(hypothesis.confidence || 0) * 100)}%</span>
              <small>Citations: {(hypothesis.supporting_evidence || []).join(", ") || "none"}</small>
            </div>
          ))}
          {mcpEvidence.length ? (
            <details>
              <summary>Retrieved Evidence And Provenance</summary>
              <pre className="result">{JSON.stringify(mcpEvidence, null, 2)}</pre>
            </details>
          ) : null}
        </article>
        <article className="context-flow-detail">
          <div className="panel-head">
            <h4>Discovery Agent: Code And Log Evidence</h4>
            <p>Read-only evidence retrieved using service, alert, scenario, ticket, and component terms.</p>
          </div>
          <div className="context-flow-scoreboard">
            <span><strong>{codeMatches.length}</strong> code matches</span>
            <span><strong>{logMatches.length}</strong> log matches</span>
            <span><strong>{Array.isArray(discoveryEvidence.query_terms) ? discoveryEvidence.query_terms.length : 0}</strong> query terms</span>
          </div>
          {codeMatches.length || logMatches.length ? (
            <div className="context-doc-list">
              {[...logMatches, ...codeMatches].slice(0, 20).map((match, index) => (
                <div className="context-doc-row" key={`discovery-evidence-${index}-${match.path || ""}-${match.line || ""}`}>
                  <strong>{String(match.kind || "evidence").toUpperCase()} · {match.path || "unknown path"}{match.line ? `:${match.line}` : ""}</strong>
                  <span>Matched: {Array.isArray(match.matched_terms) ? match.matched_terms.join(", ") : "-"}</span>
                  <pre className="result">{match.snippet || "No snippet returned."}</pre>
                </div>
              ))}
            </div>
          ) : (
            <p className="subtitle">
              No code/log evidence was returned for this run. Configure CODE_DISCOVERY_ROOTS and LOG_DISCOVERY_ROOTS,
              rebuild the context-agent, and process a new alert to populate this panel.
            </p>
          )}
          <details>
            <summary>Discovery Query And Roots</summary>
            <pre className="result">{JSON.stringify({
              query_terms: discoveryEvidence.query_terms || [],
              code_roots: discoveryEvidence.code_roots || [],
              log_roots: discoveryEvidence.log_roots || [],
            }, null, 2)}</pre>
          </details>
        </article>
        <article className="context-flow-detail">
          <div className="panel-head">
            <h4>Documents And Metadata Touched</h4>
            <p>{safeDocuments.length ? "Backend linked documents for this alert." : ragMatches.length ? "RAG match metadata is shown because no backend linked-document rows were returned." : "No document match metadata was returned for this alert."}</p>
          </div>
          {touchedDocuments.length ? (
            <div className="context-doc-list">
              {touchedDocuments.map((doc, index) => (
                <div className="context-doc-row" key={`${doc?.document_id || doc?.path || doc?.title || index}`}>
                  <strong>{doc?.title || doc?.path || `Document ${index + 1}`}</strong>
                  <span>{doc.kind || doc.document_kind || "document"} | confidence {Math.round(Number(doc.match_confidence || doc._similarity || doc.score || 0) * 100) || "-"}%</span>
                  <small>semantic {Math.round(Number(doc.semantic_score || doc._semantic_score || 0) * 100) || "-"}% | metadata {Math.round(Number(doc.metadata_match_score || doc._metadata_match_score || 0) * 100) || "-"}%</small>
                  <div className="context-doc-highlight">
                    <strong>Context collected from this document</strong>
                    <p>{documentContextExcerpt(doc)}</p>
                  </div>
                  <details>
                    <summary>Metadata</summary>
                    <pre className="result">{JSON.stringify(documentMetadata(doc), null, 2)}</pre>
                  </details>
                  <div className="context-doc-actions">
                    <button type="button" className="button-secondary" onClick={() => viewDocument(doc, index)}>
                      {documentPreviewState.key === documentKey(doc, index) ? "Hide" : "View"} Document
                    </button>
                    <button
                      type="button"
                      className="button-secondary"
                      disabled={!doc.path && !doc.content && !doc.summary && !doc.recommended_action}
                      title="Download this document and its collected context"
                      onClick={() => onDownloadDocument && onDownloadDocument(doc)}
                    >
                      Download
                    </button>
                  </div>
                  {renderDocumentPreview(doc, index)}
                </div>
              ))}
            </div>
          ) : (
            <p className="subtitle">No linked documents are reported for this alert yet.</p>
          )}
        </article>
        <article className="context-flow-detail">
          <h4>Index And Embedding</h4>
          <div className="table-wrap table-wrap-scroll-x">
            <table>
              <tbody>
                {indexRows.map(([label, value]) => (
                  <tr key={`context-index-${label}`}><th>{label}</th><td>{value}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
          {!hasIndexInfo ? (
            <p className="subtitle">The selected payload did not include full RAG index metadata. The context agent may still have used fallback matching or historical metadata.</p>
          ) : null}
        </article>
      </div>
    </div>
  );
}

function AgentEventsGraph({ rows }) {
  const eventRows = Array.isArray(rows) ? rows : [];
  if (!eventRows.length) {
    return <p className="subtitle">No events found for selected alert.</p>;
  }

  const flowNodes = [
    { id: "alert-intelligence", label: "Alert Intelligence Agent", short: "A1" },
    { id: "orchestrator", label: "Master Agent", short: "M" },
    { id: "discovery-agent", label: "Discovery Agent", short: "D" },
    { id: "context-agent", label: "Context Intelligence Agent", short: "C" },
    { id: "resolution-agent", label: "Resolution Intelligence Agent", short: "R" },
    { id: "approval-service", label: "Human Approval Layer", short: "H" },
    { id: "remediation-engine", label: "Remediation Automation Engine", short: "X" },
    { id: "closure-service", label: "Validator Agent", short: "V" },
  ];

  const detectAgentId = (row) => {
    const haystack = [
      row?.agent,
      row?.action,
      row?.eventType,
      row?.detail,
      row?.backgroundDetailText,
      row?.inputValueText,
      row?.outputValueText,
    ]
      .map((item) => String(item || "").toLowerCase())
      .join(" | ");
    if (
      haystack.includes("alert intelligence")
      || haystack.includes("alert-intelligence")
      || haystack.includes("incident.alert")
      || haystack.includes("raw-alert")
      || haystack.includes("enriched-alert")
    ) {
      return "alert-intelligence";
    }
    if (haystack.includes("master agent") || haystack.includes("orchestrator")) {
      return "orchestrator";
    }
    if (haystack.includes("discovery agent") || haystack.includes("local-evidence") || haystack.includes("code_matches") || haystack.includes("log_matches")) {
      return "discovery-agent";
    }
    if (haystack.includes("context intelligence") || haystack.includes("context-agent")) {
      return "context-agent";
    }
    if (haystack.includes("resolution intelligence") || haystack.includes("resolution-agent") || haystack.includes("recommendation")) {
      return "resolution-agent";
    }
    if (haystack.includes("approval") || haystack.includes("human approval")) {
      return "approval-service";
    }
    if (haystack.includes("remediation")) {
      return "remediation-engine";
    }
    if (haystack.includes("validator") || haystack.includes("closure")) {
      return "closure-service";
    }
    return "";
  };

  const groupedRows = new Map(flowNodes.map((node) => [node.id, []]));
  eventRows.forEach((row) => {
    const id = detectAgentId(row);
    if (!id || !groupedRows.has(id)) {
      return;
    }
    groupedRows.get(id).push(row);
  });

  // Some runs persist sparse early-stage metadata; synthesize one Alert Intelligence row for visibility.
  if (!(groupedRows.get("alert-intelligence") || []).length && eventRows.length) {
    const seed = eventRows
      .slice()
      .sort((a, b) => toFiniteNumber(a?.sequence) - toFiniteNumber(b?.sequence))[0];
    groupedRows.set("alert-intelligence", [
      {
        ...seed,
        action: "Alert landed, deduped, and enriched for orchestration.",
        decision: seed?.decision || "severity + correlation applied",
        output: seed?.output || "enriched-alert emitted",
        communicates_to: seed?.communicates_to || "orchestration-events",
      },
    ]);
  }

  const visibleFlowNodes = flowNodes.filter((node) => (groupedRows.get(node.id) || []).length > 0);
  if (!visibleFlowNodes.length) {
    return <p className="subtitle">No mapped agent events found for this alert yet.</p>;
  }

  return (
    <div className="agent-dag-flow">
      <div className="agent-dag-track">
        {visibleFlowNodes.map((node, index) => {
          const rowsForNode = (groupedRows.get(node.id) || [])
            .slice()
            .sort((a, b) => toFiniteNumber(a?.sequence) - toFiniteNumber(b?.sequence));
          const latest = rowsForNode[rowsForNode.length - 1] || null;
          const hasError = hasMeaningfulValue(latest?.errorValueText);
          const statusLabel = hasError ? "error" : "observed";

          return (
            <div key={`agent-dag-${node.id}`} className="agent-dag-segment">
              <article className={`agent-dag-node status-${statusLabel}`}>
                <div className="agent-dag-head">
                  <span className="agent-dag-badge">{node.short}</span>
                  <strong>{node.label}</strong>
                  <span className={`agent-dag-status status-${statusLabel}`}>{statusLabel}</span>
                </div>
                <p>{latest?.action || "No agent event captured yet."}</p>
                <div className="agent-event-kv">
                  <span>Decision: {compactText(latest?.decision, 140) || "-"}</span>
                  <span>Output: {compactText(latest?.output, 140) || "-"}</span>
                  <span>Next: {latest?.communicates_to || "-"}</span>
                  <span>Events: {rowsForNode.length}</span>
                </div>
                {latest?.backgroundDetailText ? (
                  <details>
                    <summary>Background Details</summary>
                    <pre className="result">{latest.backgroundDetailText}</pre>
                  </details>
                ) : null}
                {rowsForNode.length ? (
                  <details>
                    <summary>Agent Event Timeline ({rowsForNode.length})</summary>
                    <div className="agent-event-rows">
                      {rowsForNode.map((row, rowIndex) => (
                        <div key={`agent-node-${node.id}-row-${rowIndex}`} className="agent-event-row timeline">
                          <strong>{row.sequence || rowIndex + 1}.</strong>
                          <span>{compactText(row.action, 120) || "-"}</span>
                          <span>{compactText(row.decision, 120) || "-"}</span>
                          <span>{formatUtcTimestamp(row.timestamp)}</span>
                          <span>{row.eventType || "-"}</span>
                        </div>
                      ))}
                    </div>
                  </details>
                ) : null}
              </article>
              {index < flowNodes.length - 1 ? <div className="agent-dag-arrow" aria-hidden="true">→</div> : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function TopicFlowGraph({ routing, timelineRows }) {
  const safeRouting = routing && typeof routing === "object" ? routing : {};
  const safeRows = Array.isArray(timelineRows) ? timelineRows : [];
  const published = Array.from(new Set(
    safeRows
      .map((row) => String(row?.publishes || "").trim())
      .filter((item) => item && item !== "-" && item.toLowerCase() !== "unknown")
  ));
  const consumed = Array.from(new Set(
    safeRows
      .map((row) => String(row?.consumes || "").trim())
      .filter((item) => item && item !== "-" && item.toLowerCase() !== "unknown")
  ));
  const provider = String(safeRouting?.message_bus_provider || "rabbitmq").trim().toUpperCase();
  const actualRows = SERVICE_TOPIC_FLOW.map((row) => {
    const hasTopicActivity = published.includes(row.publishes) || consumed.includes(row.consumes);
    return {
      service: row.service,
      consumed: hasTopicActivity ? row.consumes : "-",
      published: hasTopicActivity ? row.publishes : "-",
      provider,
      status: hasTopicActivity ? "Observed" : "Configured",
    };
  });
  const configuredRows = SERVICE_TOPIC_FLOW.map((row) => ({
    service: row.service,
    consumes: row.consumes === "-" ? "-" : `${row.consumes} (enabled transports)`,
    publishes: row.publishes,
  }));

  return (
    <MessageBusTopology
      actual={{ rows: actualRows, published, consumed }}
      configuredRows={configuredRows}
      routing={safeRouting}
      primaryTopic={published[0] || "raw-alerts"}
      compact
    />
  );
}

function classifySelectedAlertPath(workflow, timelineRows, selectedAlert) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeRows = Array.isArray(timelineRows) ? timelineRows : [];
  const safeAlert = selectedAlert && typeof selectedAlert === "object" ? selectedAlert : {};
  const recommendation = safeWorkflow?.recommendation && typeof safeWorkflow.recommendation === "object" ? safeWorkflow.recommendation : {};
  const recommendationMetadata = recommendation?.metadata && typeof recommendation.metadata === "object" ? recommendation.metadata : {};
  const decision =
    (safeWorkflow?.decision && typeof safeWorkflow.decision === "object" && safeWorkflow.decision)
    || (safeWorkflow?.orchestration_decision && typeof safeWorkflow.orchestration_decision === "object" && safeWorkflow.orchestration_decision)
    || (recommendationMetadata?.orchestration_decision && typeof recommendationMetadata.orchestration_decision === "object" && recommendationMetadata.orchestration_decision)
    || {};
  const approval = safeWorkflow?.approval && typeof safeWorkflow.approval === "object" ? safeWorkflow.approval : {};
  const remediation = safeWorkflow?.remediation_action && typeof safeWorkflow.remediation_action === "object" ? safeWorkflow.remediation_action : {};
  const closure = safeWorkflow?.closure_report && typeof safeWorkflow.closure_report === "object" ? safeWorkflow.closure_report : {};
  const rowText = safeRows
    .map((row) => `${row?.stage || ""} ${row?.agent || ""} ${row?.service || ""} ${row?.consumes || ""} ${row?.publishes || ""} ${row?.detail || ""} ${row?.inputValueText || ""} ${row?.outputValueText || ""}`)
    .join(" ")
    .toLowerCase();
  const incidentStatus = String(safeWorkflow?.incident?.status || safeAlert.status || safeAlert.state || "").trim().toLowerCase();
  const explicitApproval = safeWorkflow?.approval?.required ?? decision?.requires_approval ?? recommendation?.requires_approval;
  const approvalRequired = explicitApproval === true || ["awaiting_approval", "pending_approval"].some((token) => incidentStatus.includes(token));
  const hasApproval = approvalRequired || hasMeaningfulValue(approval.status || approval.id || approval.approval_id) || rowText.includes("approval");
  const hasRemediation = hasMeaningfulValue(remediation.status || remediation.id || remediation.action_type) || rowText.includes("remediation");
  const hasClosure = Boolean(closure.health_restored || closure.closed_at) || ["closed", "resolved", "complete", "completed", "validated"].some((token) => incidentStatus.includes(token)) || rowText.includes("closure-events") || rowText.includes("closure service");
  const hasResolution = hasMeaningfulValue(recommendation.id || recommendation.root_cause || recommendation.recommended_action) || rowText.includes("resolution") || rowText.includes("model router");
  const hasContext = hasMeaningfulValue(safeWorkflow?.context) || rowText.includes("context") || rowText.includes("rag");
  const hasOrchestration = hasContext || hasResolution || hasApproval || hasRemediation || hasClosure || rowText.includes("orchestrator") || rowText.includes("orchestration");
  const hasAlertIntelligence = hasOrchestration || rowText.includes("alert intelligence") || rowText.includes("enriched-alerts");
  const label = hasClosure
    ? "Closed path"
    : hasRemediation
      ? "Remediation path"
      : hasApproval
        ? "Approval path"
        : hasResolution
          ? "Resolution path"
          : hasContext
            ? "Context path"
            : hasAlertIntelligence
              ? "Intelligence path"
              : "Intake path";
  return {
    label,
    approvalRequired,
    hasAlertIntelligence,
    hasOrchestration,
    hasContext,
    hasResolution,
    hasApproval,
    hasRemediation,
    hasClosure,
  };
}

function parseTimelineJson(value) {
  const text = String(value || "").trim();
  if (!text) {
    return null;
  }
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch (_error) {
    return null;
  }
}

function classifyFlowStageFromRow(row) {
  const stage = String(row?.stage || "").toLowerCase();
  if (stage.includes("landing pad") || stage.includes("alert received") || stage.includes("alert landed")) {
    return { kind: "ingestion", short: "ING", label: "Landing Pad" };
  }
  if (stage.includes("topic handoff") || stage.includes("message bus")) {
    return { kind: "bus", short: "BUS", label: "Message Bus" };
  }
  if (stage.includes("dedup") || stage.includes("correlation") || stage.includes("enrich")) {
    return { kind: "dedupe", short: "DED", label: "Dedup" };
  }
  if (stage.includes("config") || stage.includes("connector lookup")) {
    return { kind: "config", short: "CFG", label: "Config" };
  }
  if (stage.includes("routing") || stage.includes("orchestrator") || stage.includes("workflow")) {
    return { kind: "orchestration", short: "ORC", label: "Orchestrator" };
  }
  if (stage.includes("discovery agent") || stage.includes("code and log context")) {
    return { kind: "discovery", short: "DSC", label: "Discovery" };
  }
  if (stage.includes("rag context") || stage.includes("context retrieval") || stage.includes("context intelligence")) {
    return { kind: "rag", short: "RAG", label: "RAG" };
  }
  if (stage.includes("embedding") || stage.includes("semantic") || stage.includes("vector")) {
    return { kind: "semantic", short: "SEM", label: "Semantic" };
  }
  if (stage.includes("context merge") || stage.includes("evidence assembly")) {
    return { kind: "context", short: "CTX", label: "Context" };
  }
  if (stage.includes("resolution") || stage.includes("recommendation")) {
    return { kind: "resolution", short: "RCA", label: "Resolution" };
  }
  if (stage.includes("approval")) {
    return { kind: "approval", short: "APR", label: "Approval" };
  }
  if (stage.includes("policy")) {
    return { kind: "policy", short: "POL", label: "Policy" };
  }
  if (stage.includes("remediation") || stage.includes("command") || stage.includes("execute")) {
    return { kind: "execution", short: "CMD", label: "Execution" };
  }
  if (stage.includes("closure") || stage.includes("validation")) {
    return { kind: "closure", short: "CLS", label: "Closure" };
  }
  return { kind: "generic", short: "EVT", label: "Event" };
}

function timelineRowText(row) {
  return [
    row?.status,
    row?.stage,
    row?.detail,
    row?.agent,
    row?.service,
    row?.consumes,
    row?.publishes,
    row?.errorValueText,
    row?.inputValueText,
    row?.outputValueText,
  ].map((item) => String(item || "").toLowerCase()).join(" ");
}

function timelineRowIndicatesFallback(text) {
  return [
    "fallback",
    "heuristic-fallback",
    "skipped",
    "not executed",
    "no live executor",
    "no real",
    "policy-blocked",
    "safety gate",
    "live mutation blocked",
    "requires_human_review",
  ].some((token) => text.includes(token));
}

function timelineRowIndicatesSuccess(text) {
  return [
    "succeeded",
    "success",
    "completed",
    "closed",
    "observed",
    "validated",
    "recommendation_id",
    "approval_id",
  ].some((token) => text.includes(token));
}

function timelineRowHasError(row) {
  if (!hasMeaningfulValue(row?.errorValueText)) {
    return false;
  }
  const text = timelineRowText(row);
  if (timelineRowIndicatesFallback(text) || timelineRowIndicatesSuccess(text)) {
    return false;
  }
  return text.includes("error") || text.includes("failed") || text.includes("exception") || text.includes("timeout");
}

function timelineRowStatus(row, nextRow = null) {
  const text = timelineRowText(row);
  if (timelineRowIndicatesFallback(text)) {
    return "fallback";
  }
  if (timelineRowHasError(row)) {
    return "failed";
  }
  if (timelineRowIndicatesSuccess(text) || hasMeaningfulValue(row)) {
    return "observed";
  }
  if (nextRow) {
    return "continued";
  }
  return "waiting";
}

function inferTimelineNextStep(row, nextRow = null) {
  const outputText = String(row?.outputValueText || "").trim();
  const inputText = String(row?.inputValueText || "").trim();
  const detailText = String(row?.detail || "").trim();
  const transport = String(row?.publishes || "").trim();
  const parsedOutput = parseTimelineJson(outputText) || {};
  const parsedInput = parseTimelineJson(inputText) || {};
  const explicit = [
    parsedOutput?.next_action,
    parsedOutput?.fallback_path,
    parsedInput?.next_action,
    parsedInput?.fallback_path,
    row?.communicates_to,
  ].find((value) => hasMeaningfulValue(value));
  if (explicit) {
    return String(explicit).trim();
  }
  if (nextRow?.stage) {
    return `${transport || "next"} -> ${nextRow.stage}`;
  }
  if (transport && transport !== "-") {
    return transport;
  }
  if (timelineRowIndicatesFallback(`${outputText} ${detailText}`.toLowerCase())) {
    return "Guarded path preserved for operator review";
  }
  return "-";
}

function buildDynamicFlowSections(rows) {
  const safeRows = Array.isArray(rows) ? rows.filter(Boolean) : [];
  const sections = [];
  safeRows.forEach((row, index) => {
    const meta = classifyFlowStageFromRow(row);
    const current = sections[sections.length - 1];
    if (!current || current.kind !== meta.kind) {
      sections.push({
        key: `${meta.kind}-${sections.length}`,
        kind: meta.kind,
        label: meta.label,
        short: meta.short,
        rows: [row],
        startIndex: index,
      });
      return;
    }
    current.rows.push(row);
  });
  return sections.map((section) => {
    const lastRow = section.rows[section.rows.length - 1] || null;
    const nextRow = safeRows[section.startIndex + section.rows.length] || null;
    const status = section.rows.some((row) => timelineRowHasError(row))
      ? "failed"
      : section.rows.some((row) => timelineRowStatus(row) === "fallback")
        ? "fallback"
        : "observed";
    return {
      ...section,
      lastRow,
      nextRow,
      status,
      nextStep: inferTimelineNextStep(lastRow, nextRow),
    };
  });
}

function ApplicationSankeyFlow({ workflow, timelineRows, routing, alertRows, selectedAlert, selectedAlertId, onDrillTimeline }) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeRows = Array.isArray(timelineRows) ? timelineRows : [];
  const safeRouting = routing && typeof routing === "object" ? routing : {};
  const safeAlert = selectedAlert && typeof selectedAlert === "object" ? selectedAlert : {};
  const safeAlerts = Array.isArray(alertRows) ? alertRows : [];
  const publishedTopics = new Set(
    safeRows
      .map((row) => String(row?.publishes || "").trim())
      .filter((topic) => topic && topic !== "-" && topic.toLowerCase() !== "unknown")
  );
  const consumedTopics = new Set(
    safeRows
      .map((row) => String(row?.consumes || "").trim())
      .filter((topic) => topic && topic !== "-" && topic.toLowerCase() !== "unknown")
  );
  const observedTopics = new Set([...publishedTopics, ...consumedTopics]);
  const path = classifySelectedAlertPath(safeWorkflow, safeRows, safeAlert);
  const dynamicSections = buildDynamicFlowSections(safeRows);
  const topicRows = SERVICE_TOPIC_FLOW.map((row, index) => {
    const topic = String(row.publishes || "").trim();
    const consumed = String(row.consumes || "").trim();
    const observed = observedTopics.has(topic) || observedTopics.has(consumed);
    return {
      ...row,
      index: index + 1,
      observed,
      status: observed ? "observed" : "configured",
    };
  }).filter((row) => row.observed || row.service === "monitoring-adapter" || row.service === "alert-intelligence" || (path.hasOrchestration && row.service === "orchestrator"));
  const workerRows = SERVICE_TOPIC_FLOW.slice(1).map((row) => {
    const text = safeRows
      .map((item) => `${item?.agent || ""} ${item?.service || ""} ${item?.stage || ""} ${item?.detail || ""}`)
      .join(" ")
      .toLowerCase();
    const service = String(row.service || "").toLowerCase();
    const agent = String(row.agent || "").toLowerCase();
    const observed = text.includes(service) || text.includes(agent) || observedTopics.has(row.consumes) || observedTopics.has(row.publishes);
    const profile = RECOMMENDED_WORKER_PROFILE[row.service] || { containers: 1, workers: 1, role: "worker" };
    return { ...row, observed, profile, slots: Number(profile.containers || 1) * Number(profile.workers || 1) };
  }).filter((row) => {
    if (row.observed) return true;
    if (row.service === "alert-intelligence") return true;
    if (row.service === "orchestrator") return path.hasOrchestration;
    if (row.service === "context-agent") return path.hasContext;
    if (row.service === "resolution-agent") return path.hasResolution;
    if (row.service === "approval-service") return path.hasApproval;
    if (row.service === "remediation-engine") return path.hasRemediation;
    if (row.service === "closure-service") return path.hasClosure;
    return false;
  });
  const landedAlertCount = Math.max(
    safeAlerts.length,
    safeWorkflow?.alert ? 1 : 0,
    safeRows.some((row) => String(row?.stage || "").toLowerCase().includes("landing")) ? 1 : 0,
  );
  const provider = String(safeRouting.message_bus_provider || "rabbitmq").trim();
  const workflowName = String(safeRouting.workflow || safeWorkflow?.decision?.workflow || "guided-remediation").trim();
  const executionMode = String(safeRouting.execution_mode || safeWorkflow?.decision?.execution_mode || "parallel-workers").trim();
  const incidentId = String(safeWorkflow?.incident?.id || safeWorkflow?.incident_id || "-").trim();
  const approvalRequired = Boolean(
    safeWorkflow?.approval?.required
    ?? safeWorkflow?.decision?.requires_approval
    ?? safeWorkflow?.recommendation?.requires_approval
  );
  const remediationStatus = String(safeWorkflow?.remediation_action?.status || "pending").trim();
  const alertName = String(
    safeAlert.name
    || safeAlert.alert_name
    || safeWorkflow?.alert?.name
    || safeWorkflow?.alert?.alertname
    || selectedAlertId
    || "selected alert"
  ).trim();
  const landedFile = String(
    safeAlert.file_name
    || safeAlert.filename
    || safeAlert.source_file
    || safeAlert.file_path
    || safeAlert.path
    || safeWorkflow?.alert?.source_file
    || safeWorkflow?.alert?.file_name
    || ""
  ).trim();
  const landingSource = String(safeAlert.source || safeAlert.provider || safeWorkflow?.alert?.source || "landing pad").trim();
  const landingTime = formatIstTimestamp(
    safeAlert.created_at
    || safeAlert.starts_at
    || safeAlert.received_at
    || safeWorkflow?.alert?.starts_at
    || safeRows[0]?.timestamp
    || ""
  );
  const alertService = String(safeAlert.service || safeWorkflow?.alert?.service || "-").trim();
  const alertSeverity = String(safeAlert.severity || safeWorkflow?.alert?.severity || "-").trim();
  const activeWorkerCount = workerRows.filter((row) => row.observed).length;
  const observedTopicCount = topicRows.filter((row) => row.observed).length;
  const masterProfile = RECOMMENDED_WORKER_PROFILE.orchestrator;
  const masterSlots = Number(masterProfile.containers || 1) * Number(masterProfile.workers || 1);
  const workerSlots = workerRows.reduce((sum, row) => sum + Number(row.slots || 0), 0);
  const sankeyStats = [
    ["Alerts Landed", landedAlertCount || "-"],
    ["Topics Observed", `${observedTopicCount}/${topicRows.length}`],
    ["Master Nodes", `${masterProfile.containers} x orchestrator`],
    ["Worker Slots", workerSlots],
    ["Path", path.label],
  ];
  const staticStageRows = [
    { id: "landed", title: landedFile ? "File Landed" : "Alert Landed", detail: landedFile || alertName, meta: `${landingSource} | ${landingTime || "time not reported"}`, tone: "blue", status: landedAlertCount ? "observed" : "ready" },
    { id: "normalized", title: "Landing Pad Normalized", detail: `${alertService} | ${alertSeverity}`, meta: "labels + severity + trace id", tone: "blue", status: safeRows.length ? "observed" : "ready" },
    { id: "topics", title: "Topics Created", detail: `${observedTopicCount}/${topicRows.length} observed`, meta: provider, tone: "purple", status: observedTopicCount ? "observed" : "configured" },
    ...(path.hasOrchestration ? [{ id: "master", title: "Master Nodes Route Work", detail: `${masterProfile.containers} orchestrator container(s), ${masterSlots} consumer slot(s)`, meta: `${workflowName} | ${executionMode}`, tone: "green", status: observedTopics.has("orchestration-events") ? "observed" : "ready" }] : []),
    ...(workerRows.length ? [{ id: "workers", title: "Parallel Workers Process", detail: `${activeWorkerCount}/${workerRows.length} worker services observed`, meta: `${workerSlots} recommended worker slots`, tone: "teal", status: activeWorkerCount ? "observed" : "ready" }] : []),
    { id: "outputs", title: "Cockpit Updated", detail: incidentId, meta: path.hasRemediation ? `remediation ${remediationStatus}` : path.hasApproval ? `approval ${approvalRequired ? "required" : "observed"}` : path.label, tone: "orange", status: incidentId !== "-" ? "observed" : "ready" },
  ];
  const staticStageColumns = [
    {
      id: "source",
      title: landedFile ? "Landed File" : "Landed Alert",
      subtitle: landingSource,
      nodes: [
        { title: alertName, meta: landedFile || selectedAlertId || "selected row", status: landedAlertCount ? "observed" : "ready" },
        { title: "Service / Severity", meta: `${alertService} / ${alertSeverity}`, status: "ready" },
      ],
    },
    {
      id: "landing",
      title: "Landing Pad",
      subtitle: "/alerts/alertmanager",
      nodes: [
        { title: "Normalize Alert", meta: "labels + severity + trace", status: safeRows.length ? "observed" : "ready" },
        { title: "Persist Intake", meta: "alerts, incidents, incident_events", status: safeRows.length ? "observed" : "ready" },
      ],
    },
    {
      id: "topics",
      title: "Topic Creation",
      subtitle: provider,
      nodes: topicRows.map((row) => ({
        title: row.publishes,
        meta: row.consumes === "-" ? "seed topic" : `after ${row.consumes}`,
        status: row.status,
      })),
    },
    ...(path.hasOrchestration ? [{
      id: "master",
      title: "Master Node",
      subtitle: executionMode,
      nodes: [
        { title: "orchestrator masters", meta: `${masterProfile.containers} container(s) x ${masterProfile.workers} worker(s) = ${masterSlots} route slot(s)`, status: observedTopics.has("orchestration-events") ? "observed" : "ready" },
        { title: "workflow policy", meta: `${workflowName}; ${approvalRequired ? "approval required" : "approval optional"}`, status: approvalRequired ? "observed" : "ready" },
      ],
    }] : []),
    ...(workerRows.length ? [{
      id: "workers",
      title: "Parallel Workers",
      subtitle: "independent consumers",
      nodes: workerRows.map((row) => ({
        title: row.service,
        meta: `${row.profile.containers} container(s) x ${row.profile.workers} worker(s) = ${row.slots} slot(s); ${row.consumes} -> ${row.publishes}`,
        status: row.observed ? "observed" : "ready",
      })),
    }] : []),
    {
      id: "outputs",
      title: "Cockpit Outputs",
      subtitle: "operator workspace",
      nodes: [
        { title: "Incident", meta: incidentId, status: incidentId !== "-" ? "observed" : "ready" },
        ...(path.hasContext ? [{ title: "Documents + RAG", meta: "context, matches, citations", status: safeRows.some((row) => String(row?.stage || "").toLowerCase().includes("rag")) ? "observed" : "ready" }] : []),
        ...(path.hasApproval ? [{ title: "Approval", meta: approvalRequired ? "decision gate" : "observed decision", status: approvalRequired ? "observed" : "ready" }] : []),
        ...(path.hasRemediation ? [{ title: "Remediation", meta: remediationStatus || "pending", status: remediationStatus !== "pending" ? "observed" : "ready" }] : []),
        ...(path.hasClosure ? [{ title: "Closure", meta: safeWorkflow?.incident?.status || "validated", status: "observed" }] : []),
      ],
    },
  ];

  const stageRows = dynamicSections.length
    ? dynamicSections.map((section) => ({
        id: section.key,
        title: section.label,
        detail: section.lastRow?.stage || section.label,
        meta: `${section.lastRow?.agent || "-"} | ${section.lastRow?.consumes || "-"} -> ${section.lastRow?.publishes || "-"}`,
        tone: section.status === "failed" ? "orange" : section.status === "fallback" ? "purple" : "blue",
        status: section.status === "failed" ? "ready" : "observed",
        nextStep: section.nextStep,
      }))
    : staticStageRows;
  const stageColumns = dynamicSections.length
    ? dynamicSections.map((section) => ({
        id: section.key,
        title: section.label,
        subtitle: section.nextStep && section.nextStep !== "-"
          ? `next: ${section.nextStep}`
          : (section.lastRow?.publishes || section.lastRow?.service || "observed"),
        nodes: section.rows.map((row, index) => ({
          title: row.stage || `${section.label} ${index + 1}`,
          meta: `${row.agent || "-"} | ${row.consumes || "-"} -> ${row.publishes || "-"}`,
          status: timelineRowStatus(row, safeRows[safeRows.indexOf(row) + 1]) === "failed" ? "ready" : "observed",
        })),
      }))
    : staticStageColumns;

  return (
    <div className="application-sankey">
      <div className="context-flow-header">
        <div>
          <h3>Application Alert Flow</h3>
          <p>Actual landed alert/file first, then the downstream processing path. Use drilldown to inspect each stage in Flow Timeline.</p>
          <p>Best single-VM profile: one service container per stage with broker-backed worker consumers; add more VMs behind a load balancer for horizontal replicas.</p>
        </div>
        <div className="context-flow-scoreboard">
          {sankeyStats.map(([label, value]) => (
            <span key={`sankey-stat-${label}`}>
              {label}
              <strong>{value}</strong>
            </span>
          ))}
        </div>
      </div>

      <div className="app-flow-landed-card">
        <div>
          <span>{landedFile ? "Actual File Landed" : "Actual Alert Landed"}</span>
          <strong>{landedFile || alertName}</strong>
          <small>{alertName} | {alertService} | {alertSeverity}</small>
        </div>
        <button type="button" className="button-secondary" onClick={onDrillTimeline}>
          View Flow Timeline Detail
        </button>
      </div>

      <div className="app-sankey-stage-flow" aria-label="Actual alert processing flow">
        {stageRows.map((stage, index) => (
          <div className="app-sankey-stage-wrap" key={stage.id}>
            <article className={`app-sankey-stage tone-${stage.tone} status-${stage.status}`} style={{ animationDelay: `${index * 70}ms` }}>
              <span>{index + 1}</span>
              <div>
                <strong>{stage.title}</strong>
                <p>{stage.detail}</p>
                <small>{stage.meta}</small>
                {stage.nextStep && stage.nextStep !== "-" ? <small>next: {stage.nextStep}</small> : null}
              </div>
              <button type="button" className="timeline-copy-btn" onClick={onDrillTimeline}>Timeline</button>
            </article>
            {index < stageRows.length - 1 ? <i className={`app-sankey-stage-link tone-${stage.tone}`} aria-hidden="true" /> : null}
          </div>
        ))}
      </div>

      <div className="app-sankey-columns">
        {stageColumns.map((column) => (
          <section className={`app-sankey-column column-${column.id}`} key={column.id}>
            <div className="app-sankey-column-head">
              <strong>{column.title}</strong>
              <span>{column.subtitle}</span>
            </div>
            <div className="app-sankey-node-list">
              {column.nodes.map((node, index) => (
                <article className={`app-sankey-node status-${node.status}`} key={`${column.id}-${node.title}-${index}`}>
                  <strong>{node.title}</strong>
                  <span>{node.meta}</span>
                </article>
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}

function ProcessingFlowMap({ workflow, timelineRows, routing, selectedAlert, selectedAlertId, onDrillTimeline }) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeRows = Array.isArray(timelineRows) ? timelineRows : [];
  const safeRouting = routing && typeof routing === "object" ? routing : {};
  const safeAlert = selectedAlert && typeof selectedAlert === "object" ? selectedAlert : {};
  const path = classifySelectedAlertPath(safeWorkflow, safeRows, safeAlert);
  const dynamicSections = buildDynamicFlowSections(safeRows);
  const rowByOrder = (order) => safeRows.find((row) => Number(row?.flowOrder) === order) || {};
  const firstRowMatching = (tokens) => {
    const needles = Array.isArray(tokens) ? tokens : [];
    return safeRows.find((row) => {
      const haystack = `${row?.stage || ""} ${row?.service || ""} ${row?.agent || ""} ${row?.consumes || ""} ${row?.publishes || ""}`.toLowerCase();
      return needles.some((token) => haystack.includes(String(token || "").toLowerCase()));
    }) || {};
  };
  const alertName = String(
    safeAlert.name
    || safeAlert.alert_name
    || safeWorkflow?.alert?.name
    || safeWorkflow?.alert?.alertname
    || selectedAlertId
    || "selected alert"
  ).trim();
  const service = String(safeAlert.service || safeWorkflow?.alert?.service || safeWorkflow?.incident?.service || "-").trim();
  const severity = String(safeAlert.severity || safeWorkflow?.alert?.severity || safeWorkflow?.incident?.severity || "-").trim();
  const incidentId = String(safeWorkflow?.incident?.id || safeWorkflow?.incident_id || "-").trim();
  const workflowName = String(safeRouting.workflow || safeWorkflow?.decision?.workflow || "guided-remediation").trim();
  const busProvider = String(safeRouting.message_bus_provider || safeWorkflow?.decision?.message_bus_provider || "rabbitmq").trim();
  const executionMode = String(safeRouting.execution_mode || safeWorkflow?.decision?.execution_mode || "parallel-workers").trim();
  const traceId = String(
    safeWorkflow?.alert?.trace_id
    || safeWorkflow?.incident?.trace_id
    || safeWorkflow?.context?.trace_id
    || safeWorkflow?.recommendation?.trace_id
    || ""
  ).trim();
  const recommendation = safeWorkflow?.recommendation && typeof safeWorkflow.recommendation === "object" ? safeWorkflow.recommendation : {};
  const contextPayload = safeWorkflow?.context && typeof safeWorkflow.context === "object" ? safeWorkflow.context : {};
  const contextMetadata = contextPayload?.metadata && typeof contextPayload.metadata === "object" ? contextPayload.metadata : {};
  const recommendationMetadata = recommendation?.metadata && typeof recommendation.metadata === "object" ? recommendation.metadata : {};
  const remediation = safeWorkflow?.remediation_action && typeof safeWorkflow.remediation_action === "object" ? safeWorkflow.remediation_action : {};
  const documentsRow = firstRowMatching(["rag context", "semantic", "context merge"]);
  const remediationPlan = remediation?.parameters?.execution_plan && typeof remediation.parameters.execution_plan === "object"
    ? remediation.parameters.execution_plan
    : {};
  const parseFlowJson = (value) => {
    const text = String(value || "").trim();
    if (!text) {
      return {};
    }
    try {
      const parsed = JSON.parse(text);
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch (_error) {
      return {};
    }
  };
  const contextRetrievalRow = rowByOrder(80);
  const semanticSearchRow = rowByOrder(85);
  const contextMergeRow = rowByOrder(90);
  const resolutionRow = rowByOrder(110);
  const contextRetrievalOutput = parseFlowJson(contextRetrievalRow.outputValueText);
  const semanticSearchOutput = parseFlowJson(semanticSearchRow.outputValueText);
  const contextMergeOutput = parseFlowJson(contextMergeRow.outputValueText);
  const resolutionOutput = parseFlowJson(resolutionRow.outputValueText);
  const contextRetrievalInput = parseFlowJson(contextRetrievalRow.inputValueText);
  const resolutionInput = parseFlowJson(resolutionRow.inputValueText);
  const ragMatches = Array.isArray(contextRetrievalOutput.rag_matches)
    ? contextRetrievalOutput.rag_matches
    : Array.isArray(semanticSearchOutput.top_matches)
      ? semanticSearchOutput.top_matches
      : [];
  const topRagMatches = ragMatches.slice(0, 5);
  const ragIndex =
    (contextMetadata.rag_index && typeof contextMetadata.rag_index === "object" && contextMetadata.rag_index)
    || (recommendationMetadata.rag_index && typeof recommendationMetadata.rag_index === "object" && recommendationMetadata.rag_index)
    || {};
  const embeddingModel =
    (ragIndex.embedding_model && typeof ragIndex.embedding_model === "object" && ragIndex.embedding_model)
    || {};
  const vectorStore =
    (ragIndex.vector_store && typeof ragIndex.vector_store === "object" && ragIndex.vector_store)
    || {};
  const embeddingProvider = String(embeddingModel.provider || contextMetadata.embedding_provider || "not reported").trim();
  const embeddingName = String(embeddingModel.model || contextMetadata.embedding_model || "not reported").trim();
  const embeddingFallback = String(embeddingModel.fallback_active ? embeddingModel.fallback_model || "active" : embeddingModel.fallback_model || "-").trim();
  const vectorProvider = String(vectorStore.provider || contextMetadata.vector_store || "not reported").trim();
  const vectorIndexName = String(vectorStore.index || vectorStore.index_name || ragIndex.index_name || ragIndex.name || "-").trim();
  const indexedDocuments = ragIndex.document_count ?? ragIndex.total_documents ?? ragIndex.embedded_document_count ?? contextRetrievalOutput.rag_documents ?? "-";
  const modelUsage = Array.isArray(recommendationMetadata.model_usage)
    ? recommendationMetadata.model_usage
    : Array.isArray(recommendation.model_usage)
      ? recommendation.model_usage
      : [];
  const primaryModelCall = modelUsage[0] || {};
  const modelRouterProvider = String(primaryModelCall.provider || primaryModelCall.model_provider || recommendationMetadata.model_provider || "model-router").trim();
  const modelRouterModel = String(primaryModelCall.model || primaryModelCall.model_name || recommendationMetadata.model_name || "not reported").trim();
  const modelRouterTask = String(primaryModelCall.task || primaryModelCall.model_task || recommendationMetadata.model_task || "rca").trim();
  const modelRouterCalls = modelUsage.length;
  const modelRouterTokens = modelUsage.reduce((sum, row) => sum + Number(row.total_tokens || row.input_tokens || 0), 0);
  const modelRouterFailed = modelUsage.some((row) => {
    const safeRow = row && typeof row === "object" ? row : {};
    return hasMeaningfulValue(safeRow.error) || String(safeRow.status || "").trim().toLowerCase() === "failed";
  });
  const modelRouterFallback = modelUsage.some((row) => {
    const safeRow = row && typeof row === "object" ? row : {};
    const provider = String(safeRow.provider || safeRow.model_provider || "").trim().toLowerCase();
    const model = String(safeRow.model || safeRow.model_name || "").trim().toLowerCase();
    return provider.includes("fallback") || model.includes("fallback");
  });
  const modelRouterStatus = modelRouterFailed
    ? "failed"
    : modelRouterFallback
      ? "fallback"
      : modelRouterCalls > 0
        ? "observed"
        : "waiting";
  const contextDetailRows = [
    ["Query", contextRetrievalInput.service || contextRetrievalInput.query || service],
    ["Deployment", contextRetrievalInput.deployment || "-"],
    ["Related Incidents", contextRetrievalInput.related_incidents ?? "-"],
    ["RAG Documents", contextRetrievalOutput.rag_documents ?? "-"],
    ["Index Name", vectorIndexName],
    ["Vector Store", vectorProvider],
    ["Embedding Model", `${embeddingProvider} / ${embeddingName}`],
    ["Embedding Fallback", embeddingFallback || "-"],
    ["Runbook Found", String(contextRetrievalOutput.runbook_found ?? contextMergeOutput.runbook_found ?? "-")],
    ["Top Match Confidence", semanticSearchOutput.rag_top_match_confidence ?? semanticSearchOutput.rag_top_similarity ?? "-"],
    ["Top Semantic Score", semanticSearchOutput.rag_top_semantic_score ?? "-"],
    ["Top Metadata Score", semanticSearchOutput.rag_top_metadata_match_score ?? "-"],
    ["Context Summary", contextMergeOutput.context_summary || "-"],
  ];
  const resolutionDetailRows = [
    ["Incident", resolutionInput.incident_id || incidentId],
    ["Recommendation ID", resolutionOutput.recommendation_id || recommendation.id || "-"],
    ["Root Cause", cleanRecommendationText(resolutionOutput.root_cause || recommendation.root_cause, "-")],
    ["Impact", cleanRecommendationText(recommendation.impact, "-")],
    ["Recommended Action", cleanRecommendationText(recommendation.recommended_action, "-")],
    ["Model Router", `${modelRouterProvider} / ${modelRouterModel}`],
    ["Model Task", modelRouterTask],
    ["LLM Calls", modelRouterCalls || "-"],
    ["Tokens", modelRouterTokens || "-"],
    ["Confidence", resolutionOutput.confidence ?? recommendation.confidence ?? "-"],
    ["Grounding Score", resolutionOutput.grounding_score ?? recommendation?.metadata?.grounding_score ?? "-"],
    ["Hallucination Score", resolutionOutput.hallucination_score ?? recommendation?.metadata?.hallucination_score ?? "-"],
  ];
  const incidentStatusText = String(safeWorkflow?.incident?.status || safeAlert.status || safeAlert.state || "").trim().toLowerCase();
  const isClosed = ["closed", "resolved", "validated", "complete", "completed"].some((token) => incidentStatusText.includes(token));
  const allTimelineText = safeRows
    .map((row) => `${row?.stage || ""} ${row?.detail || ""} ${row?.errorValueText || ""} ${row?.inputValueText || ""} ${row?.outputValueText || ""}`)
    .join(" ")
    .toLowerCase();
  const fallbackDetected = ["fallback", "skipped", "not executed", "no live executor", "no real", "blocked", "policy"].some((token) => allTimelineText.includes(token));
  const rowIndicatesFallback = (text) => [
    "fallback",
    "heuristic-fallback",
    "skipped",
    "not executed",
    "no live executor",
    "no real",
    "policy-blocked",
    "safety gate",
    "live mutation blocked",
  ].some((token) => text.includes(token));
  const rowIndicatesSuccess = (text) => [
    "succeeded",
    "success",
    "completed",
    "closed",
    "observed",
    "validated",
    "confidence",
    "recommendation_id",
  ].some((token) => text.includes(token));
  const rowHasFailure = (row) => {
    const text = `${row?.status || ""} ${row?.detail || ""} ${row?.errorValueText || ""} ${row?.inputValueText || ""} ${row?.outputValueText || ""}`.toLowerCase();
    if (!hasMeaningfulValue(row?.errorValueText)) {
      return false;
    }
    if (rowIndicatesFallback(text) || rowIndicatesSuccess(text)) {
      return false;
    }
    return text.includes("error") || text.includes("failed") || text.includes("exception");
  };
  const failedCount = safeRows.filter(rowHasFailure).length;

  const nodeStatus = (row, order, fallbackHint = "") => {
    // Only trust the dedicated error/fallback signal for this stage, not the
    // stringified input/output JSON blobs — those often contain unrelated
    // fields (e.g. the incident's overall lifecycle status) whose text can
    // coincidentally include words like "failed", which previously caused
    // unrelated stages to be mislabeled as failed.
    const errorText = String(row?.errorValueText || "").toLowerCase();
    const hintText = String(fallbackHint || "").toLowerCase();
    const statusText = `${errorText} ${hintText}`;
    if (statusText.includes("error") || statusText.includes("failed") || statusText.includes("exception")) {
      return "failed";
    }
    if (
      statusText.includes("fallback")
      || statusText.includes("skipped")
      || statusText.includes("not executed")
      || statusText.includes("no live executor")
      || statusText.includes("no real")
      || statusText.includes("policy-blocked")
      || statusText.includes("safety gate")
      || statusText.includes("live mutation blocked")
    ) {
      return "fallback";
    }
    if (rowIndicatesSuccess(statusText)) {
      return "observed";
    }
    if (statusText.includes("error") || statusText.includes("failed") || statusText.includes("exception")) {
      return "failed";
    }
    if (isClosed && Number(order || 0) >= 170) {
      return "closed";
    }
    if (hasMeaningfulValue(row) || safeRows.some((item) => Number(item?.flowOrder) === order)) {
      return "observed";
    }
    return "waiting";
  };

  const makeNode = ({ key, title, meta, detail, type = "service", row = {}, order, fallbackHint = "", statusOverride = "", nextStep = "" }) => {
    const observed = hasMeaningfulValue(row) || safeRows.some((item) => Number(item?.flowOrder) === order);
    const status = statusOverride || nodeStatus(row, order, fallbackHint);
    return { key, title, meta, detail, type, row, order, observed, status, nextStep };
  };

  const mainNodes = [
    makeNode({ key: "source", title: "Alerts ingested by third party", meta: "Prometheus / Grafana / external tools", detail: alertName, order: 5, type: "source", row: safeAlert }),
    makeNode({ key: "landing", title: "Alerts landed in Landing Pad", meta: "/input or /alerts/alertmanager", detail: `${service} | ${severity}`, order: 10, row: rowByOrder(10) }),
    makeNode({ key: "normalize", title: "Alert normalized to canonical format", meta: "labels + annotations + trace id", detail: traceId || "trace generated by intake", order: 10, row: rowByOrder(10) }),
    makeNode({ key: "raw-bus", title: "Raw alert message published", meta: `${busProvider}: raw-alerts`, detail: "Monitoring Adapter -> Alert Intelligence", order: 20, type: "bus", row: rowByOrder(20) }),
    makeNode({
      key: "alert-ai",
      title: "Alert intelligence: classify, dedupe, correlate",
      meta: "policy + labels + fingerprint + service",
      detail: `severity=${severity}; incident=${incidentId}`,
      order: 30,
      row: {
        ...rowByOrder(30),
        inputValueText: stringifyTimelineValue({
          alert: alertName,
          service,
          environment: safeAlert.environment || safeWorkflow?.alert?.environment || "-",
          fingerprint: safeAlert.fingerprint || safeAlert.labels?.alert_fingerprint || "-",
        }),
        outputValueText: stringifyTimelineValue({
          severity_classification: severity,
          deduplicated_count: safeAlert.deduplicated_count ?? safeWorkflow?.alert?.deduplicated_count ?? "-",
          correlation_id: safeAlert.correlation_id || safeWorkflow?.alert?.correlation_id || "-",
          incident_id: incidentId,
        }),
      },
    }),
  ];

  const orchestrationNodes = path.hasOrchestration ? [
    makeNode({ key: "enriched-bus", title: "Enriched alert message published", meta: `${busProvider}: enriched-alerts`, detail: "Alert Intelligence -> Orchestrator", order: 40, type: "bus", row: rowByOrder(40) }),
    makeNode({ key: "orchestrator", title: "Orchestrator workflow selected", meta: workflowName, detail: `execution=${executionMode}`, order: 50, row: rowByOrder(50) }),
    makeNode({ key: "config", title: "Config and connector lookup", meta: "connections + playbooks + action catalog", detail: "workflow, bus provider, risk, executor profile", order: 60, type: "config", row: rowByOrder(60) }),
    makeNode({ key: "orch-bus", title: "Execution work item published", meta: `${busProvider}: orchestration-events`, detail: "Orchestrator -> Context Agent", order: 70, type: "bus", row: rowByOrder(70) }),
  ] : [];

  const workerLanes = [
    ...(path.hasContext ? [{
      key: "context",
      title: "Context",
      nodes: [
        makeNode({ key: "ctx-agent", title: "Context Agent consumes orchestration-events", meta: "query + signal + service", detail: service, order: 80, row: rowByOrder(80) }),
        makeNode({ key: "index", title: "Checks index and documents", meta: `${vectorProvider} / ${vectorIndexName}`, detail: `${indexedDocuments} document(s), embedding ${embeddingProvider}/${embeddingName}`, order: 85, type: "store", row: documentsRow }),
        makeNode({ key: "ranked", title: "Search ranked", meta: "semantic + metadata ranking", detail: `top similarity ${semanticSearchOutput.rag_top_similarity ?? "not reported"}`, order: 85, type: "store", row: rowByOrder(85) }),
        makeNode({ key: "context-merge", title: "Context merged and evidence assembled", meta: "docs + deps + connector evidence", detail: "context-events payload prepared", order: 90, row: rowByOrder(90) }),
        makeNode({ key: "context-bus", title: "Context message published", meta: `${busProvider}: context-events`, detail: "Context Agent -> Resolution Agent", order: 100, type: "bus", row: rowByOrder(100) }),
      ],
    }] : []),
    ...(path.hasResolution ? [{
      key: "resolution",
      title: "Resolution",
      nodes: [
        makeNode({
          key: "model-router",
          title: "Model Router LLM call",
          meta: `${modelRouterProvider} / ${modelRouterModel}`,
          detail: `${modelRouterTask} | ${modelRouterCalls || 0} call(s) | ${modelRouterTokens || 0} token(s)`,
          order: 109,
          type: "config",
          row: modelUsage.length
            ? {
                inputValueText: stringifyTimelineValue({ task: modelRouterTask, provider: modelRouterProvider, model: modelRouterModel }),
                outputValueText: stringifyTimelineValue({
                  calls: modelRouterCalls,
                  tokens: modelRouterTokens,
                  status: modelRouterStatus,
                  errors: modelUsage.map((row) => row?.error).filter(Boolean),
                }),
                errorValueText: modelRouterFailed ? stringifyTimelineValue(modelUsage.map((row) => row?.error).filter(Boolean)) : "",
              }
            : {},
          fallbackHint: modelRouterFallback ? "fallback" : "",
          statusOverride: modelRouterStatus,
        }),
        makeNode({ key: "resolution-agent", title: "Resolution Agent consumes context-events", meta: "RCA + impact + action", detail: cleanRecommendationText(recommendation.root_cause, "root cause analysis"), order: 110, row: rowByOrder(110) }),
        makeNode({ key: "impact", title: "Impact analysis", meta: "customer + dependency impact", detail: cleanRecommendationText(recommendation.impact, "-"), order: 110, row: rowByOrder(110) }),
        makeNode({ key: "action", title: "Recommendation action", meta: "safe next step", detail: cleanRecommendationText(recommendation.recommended_action, "-"), order: 110, row: rowByOrder(110) }),
        makeNode({ key: "confidence", title: "Confidence and grounding", meta: "quality guardrails", detail: `confidence ${recommendation.confidence ?? "-"}`, order: 110, row: rowByOrder(110) }),
        ...(path.hasApproval || path.hasRemediation ? [makeNode({ key: "resolution-bus", title: "Resolution message published", meta: `${busProvider}: resolution-events`, detail: "Resolution Agent -> Approval Service", order: 120, type: "bus", row: rowByOrder(120) })] : []),
      ],
    }] : []),
    ...(path.hasApproval || path.hasRemediation ? [{
      key: "remediation",
      title: "Approval + Remediation",
      nodes: [
        ...(path.hasApproval ? [
          makeNode({ key: "approval", title: "Human approval gate", meta: "L2/L3/Admin can edit plan", detail: remediation.approval_id || "pending decision", order: 130, row: rowByOrder(130) }),
          makeNode({ key: "approval-bus", title: "Approval message published", meta: `${busProvider}: approval-events`, detail: "Approval Service -> Remediation Engine", order: 140, type: "bus", row: rowByOrder(140) }),
        ] : []),
        ...(path.hasRemediation ? [makeNode({ key: "execute", title: "Remediation Engine validates and executes", meta: "policy + executor + secret_ref", detail: remediation.status || "pending", order: 150, row: rowByOrder(150), fallbackHint: remediation?.error || remediation?.output || "" })] : []),
        ...(fallbackDetected ? [
          makeNode({
            key: "fallback",
            title: "Fallback or safety gate applied",
            meta: "plan preserved, live mutation blocked",
            detail: remediation.error || remediation.output || "No live executor/connector was available, so the approved plan remains available for operator action.",
            order: 151,
            type: "config",
            row: rowByOrder(150),
            fallbackHint: "fallback",
          }),
        ] : []),
        ...(path.hasRemediation ? [
          makeNode({ key: "script", title: "Execution plan script", meta: "editable before approval", detail: Array.isArray(remediationPlan.scripts) && remediationPlan.scripts.length ? remediationPlan.scripts[0] : "no script reported", order: 150, type: "config", row: rowByOrder(150) }),
          makeNode({ key: "rem-bus", title: "Remediation message published", meta: `${busProvider}: remediation-events`, detail: "Remediation Engine -> Closure Service", order: 160, type: "bus", row: rowByOrder(160) }),
        ] : []),
      ],
    }] : []),
    ...(path.hasClosure ? [{
      key: "closure",
      title: "Closure",
      nodes: [
        makeNode({ key: "closure-service", title: "Closure Service validates outcome", meta: "post-checks + incident projection", detail: safeWorkflow?.incident?.status || "-", order: 170, row: rowByOrder(170) }),
        makeNode({ key: "closure-bus", title: "Closure message published", meta: `${busProvider}: closure-events`, detail: "Dashboard, reports, notifications", order: 180, type: "bus", row: firstRowMatching(["closure-events"]) }),
      ],
    }] : []),
  ];

  const statusLabel = (status) => {
    if (status === "failed") return "Failed";
    if (status === "fallback") return "Review required";
    if (status === "closed") return "Closed";
    if (status === "observed") return "Observed";
    return "Waiting";
  };
  const renderNode = (node) => (
    <article className={`processing-flow-node node-${node.type} status-${node.status}`} key={node.key}>
      <div className="processing-node-head">
        <strong>{node.title}</strong>
        <em>{statusLabel(node.status)}</em>
      </div>
      <span>{node.meta}</span>
      <p>{compactText(node.detail, 150) || "-"}</p>
      <small>
        {node.status === "fallback"
          ? "fallback, blocked execution, or safety gate path used"
          : node.status === "failed"
            ? "error detected in selected alert flow"
            : node.status === "closed"
              ? "incident closure path completed"
              : node.status === "observed"
                ? "observed from selected alert flow"
                : "configured path, not observed yet"}
      </small>
        {node.nextStep && node.nextStep !== "-" ? <small>next step: {node.nextStep}</small> : null}
      {node.row?.inputValueText || node.row?.outputValueText ? (
        <details>
          <summary>Details</summary>
          {node.row?.inputValueText ? <pre className="result">{node.row.inputValueText}</pre> : null}
          {node.row?.outputValueText ? <pre className="result">{node.row.outputValueText}</pre> : null}
        </details>
      ) : null}
    </article>
  );

  return (
    <div className="processing-flow-map">
      <div className="context-flow-header">
        <div>
          <h3>Complete Processing Flow</h3>
          <p>Architecture-style view for the selected alert. Use Flow Timeline for full event payload details.</p>
        </div>
        <button type="button" className="button-secondary" onClick={onDrillTimeline}>Open Detailed Timeline</button>
      </div>
      <div className="processing-flow-status-strip">
        <span><strong>{safeRows.length}</strong> timeline rows</span>
        <span><strong>{failedCount}</strong> failures</span>
        <span><strong>{fallbackDetected ? "yes" : "no"}</strong> fallback</span>
        <span><strong>{isClosed ? "closed" : incidentStatusText || "open"}</strong> incident</span>
        <span><strong>{path.label}</strong> selected path</span>
      </div>
      {fallbackDetected || failedCount ? (
        <div className={`processing-flow-banner ${failedCount ? "is-failed" : "is-fallback"}`}>
          <strong>{failedCount ? "Flow needs attention" : "Fallback path detected"}</strong>
          <span>
            {failedCount
              ? "One or more stages reported errors. Open the detailed timeline to inspect exact payloads."
              : "A safety gate, fallback, or skipped execution was detected. The plan is preserved and closure should reflect the guarded outcome."}
          </span>
        </div>
      ) : null}
      {dynamicSections.length ? (
      <div className="processing-flow-lanes">
        {dynamicSections.map((section) => {
          const nodes = section.rows.map((row, index) => {
            const rowIndex = safeRows.indexOf(row);
            const nextRow = rowIndex >= 0 ? safeRows[rowIndex + 1] : null;
            return makeNode({
              key: `${section.key}-${index}`,
              title: row.stage || section.label,
              meta: `${row.agent || "-"} | ${row.consumes || "-"} -> ${row.publishes || "-"}`,
              detail: row.detail || "Observed stage from incident timeline.",
              type: row.publishes && row.publishes !== "-" ? "bus" : "service",
              row,
              order: row.flowOrder || row.sequence || index + 1,
              fallbackHint: inferTimelineNextStep(row, nextRow),
              statusOverride: timelineRowStatus(row, nextRow),
              nextStep: inferTimelineNextStep(row, nextRow),
            });
          });
          return (
            <section className="processing-flow-lane" key={section.key}>
              <h4>{section.label}</h4>
              {section.nextStep && section.nextStep !== "-" ? <p className="subtitle">next: {section.nextStep}</p> : null}
              {nodes.map((node, index) => (
                <div className="processing-flow-step" key={node.key}>
                  {renderNode(node)}
                  {index < nodes.length - 1 ? <span className="processing-flow-arrow" aria-hidden="true">v</span> : null}
                </div>
              ))}
            </section>
          );
        })}
      </div>
      ) : (
      <>
      <div className="processing-flow-spine">
        {mainNodes.map((node, index) => (
          <div className="processing-flow-step" key={node.key}>
            {renderNode(node)}
            {index < mainNodes.length - 1 ? <span className="processing-flow-arrow" aria-hidden="true">v</span> : null}
          </div>
        ))}
      </div>
      {orchestrationNodes.length ? (
        <div className="processing-flow-spine">
          {orchestrationNodes.map((node, index) => (
            <div className="processing-flow-step" key={node.key}>
              {renderNode(node)}
              {index < orchestrationNodes.length - 1 ? <span className="processing-flow-arrow" aria-hidden="true">v</span> : null}
            </div>
          ))}
        </div>
      ) : null}
      {workerLanes.length ? (
      <div className="processing-flow-lanes">
        {workerLanes.map((lane) => (
          <section className="processing-flow-lane" key={lane.key}>
            <h4>{lane.title}</h4>
            {lane.nodes.map((node, index) => (
              <div className="processing-flow-step" key={node.key}>
                {renderNode(node)}
                {index < lane.nodes.length - 1 ? <span className="processing-flow-arrow" aria-hidden="true">v</span> : null}
              </div>
            ))}
          </section>
        ))}
      </div>
      ) : (
        <div className="processing-flow-banner">
          <strong>No downstream worker cycle required</strong>
          <span>This selected alert currently only shows intake/intelligence stages. Context, resolution, approval, remediation, and closure will appear only if the workflow reaches those stages.</span>
        </div>
      )}
      </>
      )}
      <div className="processing-flow-detail-grid">
        <article className="processing-flow-detail-card">
          <div className="panel-head">
            <h4>Context Details</h4>
            <p>Same evidence path as Context Flow, shown inline for this processing map.</p>
          </div>
          <div className="table-wrap table-wrap-scroll-x">
            <table>
              <tbody>
                {contextDetailRows.map(([label, value]) => (
                  <tr key={`processing-context-${label}`}><th>{label}</th><td>{String(value ?? "-")}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
          <h4>Documents / Matches Touched</h4>
          {topRagMatches.length ? (
            <div className="processing-flow-match-list">
              {topRagMatches.map((match, index) => (
                <div className="processing-flow-match" key={`processing-match-${index}`}>
                  <strong>{match.title || match.document_id || match.path || `Match ${index + 1}`}</strong>
                  <span>{match.kind || match.document_kind || "document"} | confidence {Math.round(Number(match.match_confidence || match._similarity || match.score || 0) * 100) || "-"}%</span>
                  <small>{compactText(match.match_reason || match.summary || match.path || JSON.stringify(match), 180)}</small>
                </div>
              ))}
            </div>
          ) : (
            <p className="subtitle">No RAG match list was reported for this selected alert.</p>
          )}
        </article>
        <article className="processing-flow-detail-card">
          <div className="panel-head">
          <h4>Resolution Details</h4>
          <p>RCA, impact, recommendation, and quality scores from the Resolution Agent.</p>
          </div>
          <div className="table-wrap table-wrap-scroll-x">
            <table>
              <tbody>
                {resolutionDetailRows.map(([label, value]) => (
                  <tr key={`processing-resolution-${label}`}><th>{label}</th><td>{String(value ?? "-")}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
          <h4>LLM Calls Through Model Router</h4>
          {modelUsage.length ? (
            <div className="processing-flow-match-list">
              {modelUsage.slice(0, 6).map((usage, index) => (
                <div className="processing-flow-match" key={`processing-llm-${index}`}>
                  <strong>{usage.provider || usage.model_provider || "model-router"}</strong>
                  <span>{usage.model || usage.model_name || "-"} | task {usage.task || usage.model_task || "-"}</span>
                  <small>
                    input {usage.input_tokens ?? "-"} | output {usage.output_tokens ?? "-"} | total {usage.total_tokens ?? "-"} | cost {usage.total_cost_usd ?? "-"}
                  </small>
                </div>
              ))}
            </div>
          ) : (
            <p className="subtitle">No persisted model-router usage rows were reported for this selected alert.</p>
          )}
          <h4>Execution Plan Preview</h4>
          <div className="processing-flow-match-list">
            <div className="processing-flow-match">
              <strong>Commands</strong>
              <span>{Array.isArray(remediationPlan.commands) ? remediationPlan.commands.length : 0} item(s)</span>
              <small>{Array.isArray(remediationPlan.commands) && remediationPlan.commands.length ? remediationPlan.commands.join(" | ") : "No command list reported."}</small>
            </div>
            <div className="processing-flow-match">
              <strong>Scripts</strong>
              <span>{Array.isArray(remediationPlan.scripts) ? remediationPlan.scripts.length : 0} item(s)</span>
              <small>{Array.isArray(remediationPlan.scripts) && remediationPlan.scripts.length ? remediationPlan.scripts.join(" | ") : "No script reported."}</small>
            </div>
            <div className="processing-flow-match">
              <strong>Queries</strong>
              <span>{Array.isArray(remediationPlan.queries) ? remediationPlan.queries.length : 0} item(s)</span>
              <small>{Array.isArray(remediationPlan.queries) && remediationPlan.queries.length ? remediationPlan.queries.join(" | ") : "No validation query reported."}</small>
            </div>
          </div>
        </article>
      </div>
    </div>
  );
}

function MessageBusTopology({ actual, configuredRows, routing, primaryTopic, compact = false }) {
  const safeActual = actual && typeof actual === "object" ? actual : {};
  const safeRouting = routing && typeof routing === "object" ? routing : {};
  const published = Array.isArray(safeActual.published) ? safeActual.published : [];
  const consumed = Array.isArray(safeActual.consumed) ? safeActual.consumed : [];
  const observedTopics = new Set([...published, ...consumed].map((topic) => String(topic || "").trim()).filter(Boolean));
  const rows = Array.isArray(configuredRows) ? configuredRows : [];
  const provider = String(safeRouting?.message_bus_provider || safeActual?.rows?.[0]?.provider || "Azure Service Bus").trim();
  const workflow = String(safeRouting?.workflow || "alert-workflow").trim();
  const executionMode = String(safeRouting?.execution_mode || "parallel-workers").trim();
  const sourceTopic = String(primaryTopic || rows.find((row) => row?.publishes)?.publishes || "kaiops-orchestration-events").trim();
  const workerNodes = [
    { title: "Alert Intelligence", service: "alert-intelligence", topic: "enriched-alerts", lane: "worker" },
    { title: "Context Worker", service: "context-agent", topic: "context-events", lane: "worker" },
    { title: "Resolution Worker", service: "resolution-agent", topic: "resolution-events", lane: "worker" },
    { title: "Approval Worker", service: "approval-service", topic: "approval-events", lane: "gate" },
    { title: "Remediation Worker", service: "remediation-engine", topic: "remediation-events", lane: "worker" },
    { title: "Closure Worker", service: "closure-service", topic: "closure-events", lane: "worker" },
  ];

  const isObserved = (topic) => observedTopics.has(String(topic || "").replace(" (enabled transports)", ""));

  return (
    <div className={`message-bus-topology ${compact ? "compact" : ""}`} aria-label="Message bus topology">
      <div className="bus-summary-strip">
        <div>
          <span>Provider</span>
          <strong>{provider}</strong>
        </div>
        <div>
          <span>Workflow</span>
          <strong>{workflow}</strong>
        </div>
        <div>
          <span>Execution</span>
          <strong>{executionMode}</strong>
        </div>
        <div>
          <span>Primary Topic</span>
          <strong>{sourceTopic}</strong>
        </div>
      </div>

      <div className="bus-path-stage-grid">
        <section className="bus-stage bus-stage-ingest">
          <div className="bus-stage-head">
            <span className="bus-node-icon">LP</span>
            <div>
              <strong>Landing Pad</strong>
              <span>Alert intake and normalization</span>
            </div>
          </div>
          <div className="bus-endpoint-box">
            <span>HTTP ingestion</span>
            <code>/alerts/alertmanager</code>
          </div>
          <div className="bus-topic-pill active">raw-alerts</div>
        </section>

        <section className="bus-stage bus-stage-topic">
          <div className="bus-stage-head">
            <span className="bus-node-icon">TC</span>
            <div>
              <strong>Topic Creation</strong>
              <span>Provisioned routing channels</span>
            </div>
          </div>
          <div className="bus-topic-sequence" aria-label="Sequential topic creation flow">
            {rows.map((row, index) => {
              const topic = String(row?.publishes || "").trim();
              const consumes = String(row?.consumes || "").replace(" (enabled transports)", "").trim();
              const state = isObserved(topic) ? "created" : "configured";
              return (
                <div className="bus-topic-sequence-step" key={`${topic || "topic"}-${index}`}>
                  <div className={`bus-topic-create-row ${state}`}>
                    <span>{index + 1}</span>
                    <div>
                      <strong>{topic || "-"}</strong>
                      <small>{consumes && consumes !== "-" ? `after ${consumes}` : "landing pad seed topic"}</small>
                    </div>
                    <em>{state}</em>
                  </div>
                  {index < rows.length - 1 ? (
                    <div className="bus-topic-sequence-arrow" aria-hidden="true">
                      <i />
                      <span>next</span>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        </section>

        <section className="bus-stage bus-stage-master">
          <div className="bus-stage-head">
            <span className="bus-node-icon">MN</span>
            <div>
              <strong>Master Node</strong>
              <span>Orchestrator coordinates workers</span>
            </div>
          </div>
          <div className="bus-master-node">
            <strong>orchestrator</strong>
            <span>Consumes enriched-alerts</span>
            <span>Publishes orchestration-events</span>
          </div>
        </section>
      </div>

      <div className="bus-flow-arrow-row" aria-hidden="true">
        <span>Landing Pad</span>
        <i />
        <span>Topics</span>
        <i />
        <span>Master Node</span>
        <i />
        <span>Parallel Workers</span>
      </div>

      <section className="bus-parallel-section">
        <div className="bus-stage-head">
          <span className="bus-node-icon">PW</span>
          <div>
            <strong>Parallel Processing Workers</strong>
            <span>Independent consumers process topic events concurrently</span>
          </div>
        </div>
        <div className="bus-worker-grid">
          {workerNodes.map((worker) => (
            <div className={`bus-worker-node ${worker.lane}`} key={worker.service}>
              <span>{worker.service}</span>
              <strong>{worker.title}</strong>
              <em className={isObserved(worker.topic) ? "observed" : "pending"}>
                {isObserved(worker.topic) ? "observed" : "ready"}
              </em>
              <code>{worker.topic}</code>
            </div>
          ))}
        </div>
      </section>

      <div className="bus-observed-rail">
        <strong>Observed Topics</strong>
        <div>
          {[...observedTopics].map((topic) => (
            <span key={`observed-topic-${topic}`}>{topic}</span>
          ))}
          {!observedTopics.size ? <span>No live topic activity yet</span> : null}
        </div>
      </div>
    </div>
  );
}

function ExecutionPlanGraph({ plan }) {
  const safePlan = plan && typeof plan === "object" ? plan : {};
  const commands = Array.isArray(safePlan.commands) ? safePlan.commands : [];
  const grouped = { commands: [], scripts: [], queries: [] };
  commands.forEach((item) => {
    const token = String(item || "").trim();
    if (!token) {
      return;
    }
    if (/^script\s*:/i.test(token)) {
      grouped.scripts.push(token.replace(/^script\s*:/i, "").trim());
      return;
    }
    if (/^query\s*:/i.test(token)) {
      grouped.queries.push(token.replace(/^query\s*:/i, "").trim());
      return;
    }
    grouped.commands.push(token.replace(/^cmd\s*:/i, "").trim());
  });

  return (
    <div className="execution-graph">
      <article className="execution-card">
        <h4>Plan Core</h4>
        <div className="execution-grid">
          <span>Workflow</span><strong>{safePlan.workflow || "-"}</strong>
          <span>Action</span><strong>{safePlan.action || "-"}</strong>
          <span>Rationale</span><strong>{safePlan.rationale || "-"}</strong>
          <span>Mode</span><strong>{safePlan.executionMode || "-"}</strong>
          <span>Risk</span><strong>{safePlan.riskTier || "-"}</strong>
          <span>Provider</span><strong>{String(safePlan.provider || "-").toUpperCase()}</strong>
          <span>Approval</span><strong>{String(safePlan.requiresApproval)}</strong>
          <span>Incident Status</span><strong>{safePlan.incidentStatus || "-"}</strong>
          <span>Approval Status</span><strong>{safePlan.approvalStatus || "-"}</strong>
        </div>
      </article>
      <article className="execution-card">
        <h4>Remediation Plan</h4>
        <div className="execution-command-list">
          {grouped.commands.length ? grouped.commands.map((command, index) => (
            <div className="execution-command" key={`cmd-${index}`} style={{ animationDelay: `${Math.min(index * 80, 640)}ms` }}>
              <span>{index + 1}</span>
              <code>{String(command || "-")}</code>
            </div>
          )) : <p className="subtitle">No command sequence found.</p>}
          {grouped.scripts.length ? (
            <>
              <h4>Scripts</h4>
              {grouped.scripts.map((script, index) => (
                <div className="execution-command" key={`script-${index}`}>
                  <span>S{index + 1}</span>
                  <code>{script}</code>
                </div>
              ))}
            </>
          ) : null}
          {grouped.queries.length ? (
            <>
              <h4>Validation Queries</h4>
              {grouped.queries.map((query, index) => (
                <div className="execution-command" key={`query-${index}`}>
                  <span>Q{index + 1}</span>
                  <code>{query}</code>
                </div>
              ))}
            </>
          ) : null}
        </div>
      </article>
    </div>
  );
}

function renderHtmlTable(headers, rows) {
  const safeHeaders = Array.isArray(headers) ? headers : [];
  const safeRows = Array.isArray(rows) ? rows : [];
  const head = safeHeaders.map((header) => `<th>${htmlEscape(header)}</th>`).join("");
  const body = safeRows.length
    ? safeRows
        .map((row) => {
          const cells = Array.isArray(row) ? row : [];
          return `<tr>${cells.map((cell) => `<td>${htmlEscape(asDisplayValue(cell))}</td>`).join("")}</tr>`;
        })
        .join("")
    : `<tr><td colspan="${Math.max(1, safeHeaders.length)}">No rows available.</td></tr>`;
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function normalizeGeneratedRuleRows(source) {
  const payload = source && typeof source === "object" ? source : {};
  const candidates = [
    payload.generated_rules,
    payload.rules,
    payload.rule_candidates,
    payload.rule_set,
    payload.output?.rules,
    payload.result?.rules,
    payload.data?.rules,
  ];
  const first = candidates.find((item) => Array.isArray(item) && item.length) || [];
  return first.map((item, index) => {
    const row = item && typeof item === "object" ? item : {};
    return {
      id: String(row.id || row.rule_id || row.name || `rule-${index + 1}`),
      name: String(row.name || row.rule_name || row.alertname || `rule-${index + 1}`),
      platform: String(row.platform || row.target_platform || row.provider || "prometheus"),
      contractMode: String(row.contract_mode || row.adapter_mode || "-"),
      contractStatus: String(row.contract_status || row.adapter_status || "-"),
      severity: String(row.severity || row.level || "-").toLowerCase(),
      expression: String(row.expression || row.expr || row.query || row.condition || "-").trim(),
      status: String(row.status || row.state || "generated"),
    };
  });
}

function cleanRuleIntentLine(line) {
  return String(line || "")
    .replace(/^[^\n:]{1,180}\.(?:md|markdown|txt|log|json|ya?ml|csv)\s*:\s*/i, "")
    .trim();
}

function slugForPrometheus(value) {
  return String(value || "kaiops")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_:-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "kaiops";
}

function yamlQuote(value) {
  return JSON.stringify(String(value ?? ""));
}

function inferPrometheusExpression(requirement, serviceName) {
  const text = String(requirement || "").toLowerCase();
  const service = String(serviceName || "service").trim() || "service";
  const numberMatch = text.match(/(?:above|over|greater than|exceeds?|>=?)\s+([0-9]+(?:\.[0-9]+)?)/i);
  const threshold = numberMatch ? Number(numberMatch[1]) : null;
  if (text.includes("unavailable") || text.includes("down") || text.includes("not reachable") || text.includes("not available")) {
    return `up{service="${service}"} == 0`;
  }
  if (text.includes("latency") || text.includes("p95") || text.includes("p99")) {
    const metric = text.includes("p99") ? "request_latency_ms_p99" : "request_latency_ms_p95";
    return `quantile_over_time(0.95, ${metric}{service="${service}"}[5m]) > ${threshold || 500}`;
  }
  if (text.includes("error rate") || text.includes("5xx") || text.includes("errors")) {
    return `avg_over_time(error_rate_percent{service="${service}"}[5m]) > ${threshold || 5}`;
  }
  if (text.includes("row") || text.includes("table")) {
    return `sum_over_time(mysql_table_rows{service="${service}"}[5m]) > ${threshold || 20}`;
  }
  if (text.includes("cpu")) {
    return `avg_over_time(cpu_usage_percent{service="${service}"}[5m]) > ${threshold || 85}`;
  }
  if (text.includes("memory")) {
    return `avg_over_time(memory_usage_percent{service="${service}"}[5m]) > ${threshold || 85}`;
  }
  return `vector(1)`;
}

function inferRuleDuration(requirement) {
  const match = String(requirement || "").match(/for\s+([0-9]+)\s*(minutes?|mins?|m|hours?|hrs?|h)\b/i);
  if (!match) {
    return "5m";
  }
  const value = match[1];
  const unit = String(match[2] || "m").toLowerCase();
  return unit.startsWith("h") ? `${value}h` : `${value}m`;
}

function inferRuleSeverity(requirement) {
  const text = String(requirement || "").toLowerCase();
  if (text.includes("critical")) return "critical";
  if (text.includes("high")) return "high";
  if (text.includes("low")) return "low";
  if (text.includes("info")) return "info";
  return "warning";
}

function buildPrometheusRulePreview({ projectName, serviceName, environment, requirements }) {
  const project = slugForPrometheus(projectName || serviceName || "kaiops-project");
  const service = String(serviceName || project).trim() || project;
  const env = String(environment || "prod").trim() || "prod";
  const lines = (Array.isArray(requirements) ? requirements : [])
    .map((item) => String(item || "").trim())
    .filter(Boolean);
  const ruleLines = lines.length ? lines : [`Alert when ${service} is unavailable for 5 minutes.`];
  const rendered = ruleLines.map((line, index) => {
    const severity = inferRuleSeverity(line);
    const name = `${project}-${slugForPrometheus(line).slice(0, 52) || `rule-${index + 1}`}-${severity}`;
    const expr = inferPrometheusExpression(line, service);
    const duration = inferRuleDuration(line);
    return [
      `    - alert: ${name}`,
      `      expr: ${expr}`,
      `      for: ${duration}`,
      "      labels:",
      `        severity: ${severity}`,
      `        project: ${project}`,
      `        service: ${service}`,
      `        environment: ${env}`,
      "      annotations:",
      `        summary: ${yamlQuote(line)}`,
      `        description: ${yamlQuote(`Generated from KaiMS guided setup for ${project}.`)}`,
    ].join("\n");
  });
  return [
    "groups:",
    `  - name: ${project}-generated-rules`,
    "    rules:",
    ...rendered,
  ].join("\n");
}

function summarizeAlertRuleContext(row, workflow = {}) {
  const alertRow = row && typeof row === "object" ? row : {};
  const alertLabels = typeof alertRow.labels === "object" && alertRow.labels ? alertRow.labels : {};
  const alertAnnotations = typeof alertRow.annotations === "object" && alertRow.annotations ? alertRow.annotations : {};
  const workflowPayload = workflow && typeof workflow === "object" ? workflow : {};
  const recommendation = typeof workflowPayload.recommendation === "object" && workflowPayload.recommendation ? workflowPayload.recommendation : {};
  const recommendationMetadata = typeof recommendation.metadata === "object" && recommendation.metadata ? recommendation.metadata : {};
  const candidates = [
    alertRow.rule_name,
    alertRow.rule,
    alertRow.alert_rule,
    alertRow.rule_expression,
    alertRow.rule_query,
    alertLabels.rule_name,
    alertLabels.alertname,
    alertLabels.alert,
    alertLabels.rule,
    recommendationMetadata.rule_name,
    recommendationMetadata.rule,
  ]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  const expressionCandidates = [
    alertRow.expression,
    alertRow.expr,
    alertRow.query,
    alertRow.rule_expression,
    alertRow.rule_query,
    recommendationMetadata.rule_expression,
    recommendationMetadata.rule_query,
    alertAnnotations.expression,
    alertAnnotations.query,
  ]
    .map((value) => String(value || "").trim())
    .filter(Boolean);

  const ruleName = candidates[0] || String(alertRow.name || alertRow.alert_name || alertLabels.alertname || "Alert Rule").trim();
  const expression = expressionCandidates[0] || "No explicit rule expression was surfaced in the incident payload.";
  const service = String(alertRow.service || alertLabels.service || recommendationMetadata.service || "").trim();
  const environment = String(alertRow.environment || alertLabels.environment || recommendationMetadata.environment || "").trim();
  const note = [service ? `service=${service}` : "", environment ? `environment=${environment}` : ""].filter(Boolean).join(" | ");
  const expandRuleValues = (value) => {
    if (Array.isArray(value)) return value;
    if (value && typeof value === "object") return Object.values(value);
    const text = String(value || "").trim();
    if (!text) return [];
    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) return parsed;
    } catch (_error) {
      // Plain rule names can be comma or newline separated.
    }
    return text.split(/\r?\n|,\s*(?=[A-Za-z])/);
  };
  const rules = [
    ...candidates,
    ...expandRuleValues(alertRow.rules),
    ...expandRuleValues(alertRow.matched_rules),
    ...expandRuleValues(alertRow.correlated_rules),
    ...expandRuleValues(alertLabels.rules),
    ...expandRuleValues(alertLabels.matched_rules),
    ...expandRuleValues(alertLabels.correlated_rules),
    ...expandRuleValues(recommendationMetadata.rules),
    ...expandRuleValues(recommendationMetadata.matched_rules),
  ]
    .map((value, index) => {
      const item = value && typeof value === "object" ? value : {};
      const name = String(item.name || item.rule_name || item.alert || value || "").trim();
      const ruleExpression = String(item.expression || item.expr || item.query || (index === 0 ? expressionCandidates[0] : "") || "").trim();
      return name ? { name, expression: ruleExpression } : null;
    })
    .filter(Boolean)
    .filter((item, index, all) => all.findIndex((candidate) => candidate.name.toLowerCase() === item.name.toLowerCase()) === index);
  if (!rules.length) {
    rules.push({ name: ruleName, expression: expressionCandidates[0] || "" });
  }

  return {
    ruleName: rules[0]?.name || ruleName,
    expression,
    rules,
    summary: compactText(alertAnnotations.summary || alertRow.summary || alertRow.description, 220) || "No concise incident summary was supplied.",
    note: note || "Derived from alert labels and workflow metadata.",
    source: String(alertRow.source || alertRow.provider || alertLabels.job || "payload metadata").trim(),
    severity: String(alertRow.severity || alertLabels.severity || recommendation?.severity || "warning").trim().toLowerCase(),
  };
}

export {
  DEFAULT_ALERT,
  REAL_USE_CASE_SCOPE,
  TEST_USE_CASE_SCOPE,
  CORE_MONITOR_PROJECTS,
  FIXED_MONITOR_SCOPES,
  SERVICE_TOPIC_FLOW,
  RECOMMENDED_WORKER_PROFILE,
  SCALE_CAPACITY_GUIDE,
  AGENT_DISPLAY_ALIASES,
  AGENT_ROUTE_ALIASES,
  PREFERENCE_STORAGE_KEY,
  UI_THEME_VALUES,
  extractObservedRoutingMetrics,
  normalizeMatchTokens,
  hasTokenOverlap,
  KAIOPS_CORE_SERVICE_SET,
  normalizeMonitorToken,
  isKaiopsCoreSelection,
  isKaiopsCoreAlert,
  PROMPT_FRAGMENT_PATTERNS,
  isPromptFragment,
  isPlaceholderRecommendationText,
  cleanRecommendationText,
  filterAlertsForMonitor,
  filterRowsForMonitor,
  inferMonitorScope,
  isGeneratedOrTestAlert,
  isEphemeralProjectName,
  normalizeAlertChannel,
  sourceChannelLabel,
  ALERT_SOURCE_CHANNELS,
  MAX_LATEST_ALERTS_PER_SOURCE,
  MIN_VISIBLE_ALERTS_BY_SOURCE,
  capLatestAlertsPerSource,
  ensureMinimumAlertsBySource,
  monitorScopeLabel,
  alertTimeMs,
  stableCrossSourceAlertSignature,
  alertIdentityKeys,
  alertApplicationCandidate,
  alertRowScore,
  resolveCanonicalAlertRow,
  resolveCanonicalAlertForRow,
  dedupeAndConsolidateAlertRows,
  shouldRetainAlertSelection,
  mapClosedIncidentToAlertStreamRow,
  projectHintFromAlertRow,
  ALERT_UUID_PATTERN,
  mapLandingPadRowToAlertStreamRow,
  mergeAlertStreamRows,
  onboardingSourceDocCategoryLabel,
  fallbackFetchTargets,
  fetchJson,
  HealthBadge,
  htmlEscape,
  asDisplayValue,
  parseUtcTimestamp,
  formatIstTimestamp,
  formatUtcTimestamp,
  clampQualityScore,
  formatQualityPercent,
  qualityToneFromScore,
  normalizeEvaluationEnvelope,
  elapsedSeconds,
  normalizeTraceServiceName,
  routeForAgent,
  displayAgentName,
  compactText,
  hasMeaningfulValue,
  stringifyTimelineValue,
  isFailureStatus,
  normalizeApprovalStatus,
  canonicalIncidentStatus,
  isApprovalResolvedStatus,
  isApprovalPendingStatus,
  statusPillClass,
  extractEventError,
  extractEventInput,
  extractEventOutput,
  buildPreviewExecutionPlan,
  deriveExecutionCommands,
  remediationOutcomeFromAction,
  shellArg,
  buildKaiOpsRemediationScript,
  firstTraceTimestamp,
  firstEventTimestamp,
  buildSyntheticFlowRows,
  summarizeEventType,
  timelinePhaseOrder,
  buildAlertDocumentDrafts,
  toFiniteNumber,
  percentile,
  normalizeUsageRow,
  isPlaceholderUsageValue,
  isMeaningfulUsageRow,
  usageRowIdentity,
  dedupeUsageRows,
  HorizontalBarChart,
  SuccessFailureDonut,
  ONBOARDING_STEP_BACKGROUND,
  explainOnboardingStepBackground,
  findHistoricalTicketDiscoveryDocument,
  HistoricalTicketDiscoveryPanel,
  FlowTimelineGraph,
  UnifiedIncidentTimeline,
  DiscoveryFlowView,
  parseStructuredIntelligence,
  intelligenceListText,
  groundedIntelligenceDisplay,
  canonicalIncidentAnalysis,
  downloadInvestigationArtifact,
  IntelligenceConnectionView,
  ContextRetrievalGraph,
  AgentEventsGraph,
  TopicFlowGraph,
  classifySelectedAlertPath,
  parseTimelineJson,
  classifyFlowStageFromRow,
  timelineRowText,
  timelineRowIndicatesFallback,
  timelineRowIndicatesSuccess,
  timelineRowHasError,
  timelineRowStatus,
  inferTimelineNextStep,
  buildDynamicFlowSections,
  ApplicationSankeyFlow,
  ProcessingFlowMap,
  MessageBusTopology,
  ExecutionPlanGraph,
  renderHtmlTable,
  normalizeGeneratedRuleRows,
  cleanRuleIntentLine,
  slugForPrometheus,
  yamlQuote,
  inferPrometheusExpression,
  inferRuleDuration,
  inferRuleSeverity,
  buildPrometheusRulePreview,
  summarizeAlertRuleContext,
};
