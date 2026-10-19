import { describe, expect, it, vi, afterEach } from "vitest";

import { incidentStartedAt, dashboardAttentionRows, dashboardIncidentRows, dashboardSubject, dashboardAnalysisState, dashboardKaiHandling, dashboardLanes, needsDashboardApproval, timeAgo } from "./DashboardRoute";

it("distinguishes queued work, missing evidence and failed analysis", () => {
  expect(dashboardAnalysisState({ status: "queued" })).toBe("Queued");
  expect(dashboardAnalysisState({ status: "collecting" })).toBe("Collecting evidence");
  expect(dashboardAnalysisState({ analysis_summary: { rca_status: "insufficient_evidence" } })).toBe("More evidence needed");
  expect(dashboardAnalysisState({ analysis_summary: { outcome: "failed" } })).toBe("Analysis failed");
  expect(dashboardAnalysisState({ status: "collecting", analysis_summary: { rca_status: "insufficient_evidence" } })).toBe("Collecting evidence");
});

it("keeps critical incidents with active investigations in the Kai handling lane", () => {
  expect(dashboardKaiHandling({severity: "critical", status: "collecting"})).toBe(true);
  expect(dashboardKaiHandling({severity: "critical", status: "awaiting_approval"})).toBe(false);
  expect(dashboardKaiHandling({severity: "critical", status: "closed"})).toBe(false);
});

it("partitions open incidents without duplicating critical incidents or implying a worker is running", () => {
  const rows = [{incident_id: "a", severity: "critical", status: "investigating"},
    {incident_id: "b", status: "awaiting_approval"}, {incident_id: "c", status: "failed"},
    {incident_id: "d", status: "rca_ready"}, {incident_id: "closed", status: "closed"}];
  const lanes = dashboardLanes(rows);
  expect(lanes.active).toHaveLength(4);
  expect(lanes.attention.map(({row}) => row.incident_id)).toEqual(["b", "c"]);
  expect(lanes.investigations.map(row => row.incident_id)).toEqual(["a", "d"]);
});

describe("needsDashboardApproval", () => {
  it("does not treat the configured human approval mode as a pending decision", () => {
    expect(needsDashboardApproval({ execution_mode: "human-approval", status: "investigating" })).toBe(false);
  });

  it("uses authoritative approval and incident states", () => {
    expect(needsDashboardApproval({ approval_status: "pending" })).toBe(true);
    expect(needsDashboardApproval({ status: "awaiting_approval" })).toBe(true);
    expect(needsDashboardApproval({ approval_status: "approved", status: "investigating" })).toBe(false);
  });
});

describe("dashboardAttentionRows", () => {
  it("counts occurrences of the same canonical incident once and retains its decision", () => {
    const decision = { incident_id: "occurrence-1", canonical_incident_id: "canonical-1" };
    const repeat = { incident_id: "occurrence-2", canonical_incident_id: "canonical-1" };
    expect(dashboardAttentionRows([decision], [], [repeat])).toEqual([{ row: decision, action: "Review decision" }]);
    expect(dashboardIncidentRows([decision, repeat])).toHaveLength(1);
  });

  it("does not merge different incidents just because their alert titles match", () => {
    const rows = [{ incident_id: "a", title: "KaiOpsHighLatencyP99" }, { incident_id: "b", title: "KaiOpsHighLatencyP99" }];
    expect(dashboardAttentionRows([], [], rows)).toHaveLength(2);
    expect(dashboardSubject({ environment: "prod", source_alert: { labels: { operation: "/checkout" } } })).toBe("prod · /checkout");
    expect(dashboardSubject({ environment: "prod", operation: "/onboarding/templates", source_alert: {} })).toBe("prod · /onboarding/templates");
  });
  it("renders critical incidents counted as attention and deduplicates higher-priority reasons", () => {
    const pending = { incident_id: "incident-1", severity: "critical" } as any;
    const criticalOnly = { incident_id: "incident-2", severity: "critical" } as any;
    const rows = dashboardAttentionRows([pending], [], [pending, criticalOnly]);

    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ row: pending, action: "Review decision" });
    expect(rows[1]).toMatchObject({ row: criticalOnly, action: "Review critical incident" });
  });
});

 describe("homepage UTC record ages", () => {
  afterEach(() => vi.useRealTimers());
  it("treats timezone-less API timestamps as UTC", () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-15T15:17:00Z"));
    expect(timeAgo("2026-10-15T14:25:00")).toBe("52m ago");
    expect(timeAgo("2026-10-15T14:25:00Z")).toBe("52m ago");
    expect(timeAgo("2026-10-15T19:55:00+05:30")).toBe("52m ago");
    expect(timeAgo("invalid")).toBe("Time unavailable");
  });
});

it("does not present a background RCA update as a new incident", () => {
  expect(incidentStartedAt({first_seen_at:"2026-10-15T10:00:00Z",updated_at:"2026-10-17T10:00:00Z"})).toBe("2026-10-15T10:00:00Z");
  expect(incidentStartedAt({updated_at:"2026-10-17T10:00:00Z"})).toBeUndefined();
});
