import {
  cleanRecommendationText,
  CORE_MONITOR_PROJECTS,
  isGeneratedOrTestAlert,
  normalizeMonitorToken,
  parseStructuredIntelligence,
  REAL_USE_CASE_SCOPE,
  TEST_USE_CASE_SCOPE,
} from "../appHelpers.jsx";

export function readableImpactText(value, fallback) {
  if (value == null || value === "") return fallback;
  if (Array.isArray(value)) {
    const items = value.map((item) => readableImpactText(item, "")).filter(Boolean);
    return items.length ? Array.from(new Set(items)).join("; ") : fallback;
  }
  if (typeof value === "object") {
    const rows = Object.entries(value).map(([key, detail]) => {
      const text = readableImpactText(detail, "");
      return text ? `${key.replaceAll("_", " ")}: ${text}` : "";
    }).filter(Boolean);
    return rows.length ? rows.join("; ") : fallback;
  }
  const raw = String(value).trim();
  const parsed = parseStructuredIntelligence(raw);
  if (parsed) {
    return readableImpactText(
      parsed.impact_summary || parsed.observed_impact || parsed.service_impact
        || parsed.customer_impact || parsed.business_impact || parsed.severity_rationale,
      fallback,
    );
  }
  if (["[", "{"].some((token) => raw.startsWith(token))
    || ["]", "}"].some((token) => raw.endsWith(token))) return fallback;
  return cleanRecommendationText(raw, fallback);
}

export const INGESTION_SAVED_VIEWS = [
  { id: "critical-active", label: "Critical active", section: "active", channel: "all", filters: { timeRange: "24h", severity: "critical", application: "selected", environment: "all" } },
  { id: "failed-ingestion", label: "Failed ingestion", section: "failed", channel: "failed", filters: { timeRange: "24h", severity: "all", application: "selected", environment: "all" } },
  { id: "my-applications", label: "My applications", section: "active", channel: "all", filters: { timeRange: "24h", severity: "all", application: "selected", environment: "all" } },
];

export function redactOperationalSecrets(value) {
  return String(value || "")
    .replace(/((?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*)([^\s'";]+)/gi, "$1[REDACTED]")
    .replace(/(authorization:\s*bearer\s+)[^\s'";]+/gi, "$1[REDACTED]");
}

export function isTestApplicationRecord(row) {
  const metadata = row?.metadata && typeof row.metadata === "object" ? row.metadata : {};
  const labels = row?.labels && typeof row.labels === "object" ? row.labels : {};
  const environment = String(row?.environment || metadata?.environment || labels?.environment || "").toLowerCase();
  const projectType = String(row?.project_type || metadata?.project_type || labels?.project_type || "").toLowerCase();
  const name = String(row?.name || row?.application || row?.project_name || row?.project || "").toLowerCase();
  return isGeneratedOrTestAlert(row)
    || ["test", "testing", "qa", "demo", "sandbox"].includes(environment)
    || ["test", "demo", "sample"].includes(projectType)
    || /(^|[-_\s])(test|demo|sample|sandbox)([-_\s]|$)/.test(name);
}

export function uniqueMonitorApplications(names) {
  const canonicalCore = new Map(CORE_MONITOR_PROJECTS.map((name) => [normalizeMonitorToken(name), name]));
  const unique = new Map();
  [...CORE_MONITOR_PROJECTS, ...(Array.isArray(names) ? names : [])].forEach((value) => {
    const name = String(value || "").trim();
    const key = normalizeMonitorToken(name);
    if (!key || [normalizeMonitorToken(REAL_USE_CASE_SCOPE), normalizeMonitorToken(TEST_USE_CASE_SCOPE)].includes(key)) return;
    const canonical = canonicalCore.get(key) || name;
    if (!unique.has(key) || canonicalCore.has(key)) unique.set(key, canonical);
  });
  return Array.from(unique.values());
}
