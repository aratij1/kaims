import { describe, expect, it } from "vitest";
import { belongsToInboxView, analysisBlocker, currentLifecycleStage, isActionableInboxIncident, lifecycleFor } from "./IncidentsRoute";
import { journeyIndexForStatus } from "../../features/incidents/IncidentCommand";

describe("Unified Inbox actionability", () => {
  it("excludes warnings while retaining other severity policies", () => {
    expect(isActionableInboxIncident({ severity: "warning" } as any)).toBe(false);
    expect(isActionableInboxIncident({ severity: "medium" } as any)).toBe(true);
    expect(isActionableInboxIncident({ severity: "low" } as any)).toBe(true);
    expect(isActionableInboxIncident({ severity: "high" } as any)).toBe(true);
    expect(isActionableInboxIncident({ severity: "critical" } as any)).toBe(true);
  });

  it("excludes incidents explicitly classified as non-actionable", () => {
    expect(isActionableInboxIncident({
      severity: "critical",
      projection_payload: { event_payload: { incident_candidate: { actionable: false } } },
    } as any)).toBe(false);
  });
});

describe("Incident command journey mapping", () => {
  it("maps approval and execution states to the correct stages", () => {
    expect(journeyIndexForStatus("awaiting_approval")).toBe(3);
    expect(journeyIndexForStatus("approved")).toBe(4);
    expect(journeyIndexForStatus("remediating")).toBe(4);
    expect(journeyIndexForStatus("validating")).toBe(5);
    expect(journeyIndexForStatus("resolved")).toBe(6);
  });

  it("uses the published cause when status is still generic", () => {
    expect(journeyIndexForStatus("open", true)).toBe(2);
    expect(journeyIndexForStatus("investigating")).toBe(1);
  });
});

describe("Triage queue lifecycle captions", () => {
  it("shows a grounded RCA as complete, not stuck generating", () => {
    // "rca_ready" is real forward progress - a grounded, conclusive RCA with
    // no ready-to-execute plan yet - ranked strictly above "investigating"
    // by the backend's own status precedence. Before this fix, the
    // "Evidence & Understanding" stage stayed captioned "Generating RCA"
    // forever for a genuinely completed RCA, even once the backend's status
    // correctly advanced to "rca_ready".
    const stages = lifecycleFor({
      status: "rca_ready", recommendation_id: "rec-1", service: "api-gateway",
    } as any);
    const understand = stages.find((stage) => stage.id === "understand");
    expect(understand?.state).toBe("complete");
    expect(understand?.caption).toBe("RCA generated");
  });

  it("still shows an in-progress investigation as generating", () => {
    const stages = lifecycleFor({
      status: "investigating", recommendation_id: "rec-1", service: "api-gateway",
    } as any);
    const understand = stages.find((stage) => stage.id === "understand");
    expect(understand?.state).toBe("current");
    expect(understand?.caption).toBe("Generating RCA");
  });
});


describe("Completed analysis blockers", () => {
  const row = {
    status: "investigating", recommendation_id: "rec-blocked", service: "mysql",
    analysis_summary: {
      rca_status: "insufficient_evidence", completed_at: "2026-09-07T04:00:00Z",
      blockers: ["Retention policy is required"], missing_evidence: ["causal_corroboration"],
    },
  };
  it("shows completed analysis as blocked with its actionable reason", () => {
    expect(analysisBlocker(row)).toBe("Retention policy is required");
    const stage = lifecycleFor(row).find(item => item.id === "understand");
    expect(stage?.state).toBe("stopped");
    expect(stage?.caption).toBe("Analysis completed; more evidence needed");
  });
  it("does not let an old analysis override execution or closure", () => {
    for (const status of ["awaiting_approval", "remediating", "validating", "closed"]) {
      expect(analysisBlocker({ ...row, status })).toBe("");
    }
  });
  it("does not claim incomplete analysis has stopped", () => {
    expect(analysisBlocker({ ...row, analysis_summary: { rca_status: "insufficient_evidence" } })).toBe("");
  });
});


describe("Observed recovery closure", () => {
  it("shows verified recovery without claiming corrective execution or grounded RCA", () => {
    const stages = lifecycleFor({status: "closed", recommendation_id: "rec-1",
      resolution_lifecycle: {validation: {closure_kind: "observed_recovery", administrative_disposition: false}},
    } as any);
    expect(stages.find(s => s.id === "understand")?.caption).toBe("Cause remains inconclusive");
    expect(stages.find(s => s.id === "approval")?.caption).toBe("Operator authorized recovery assessment");
    expect(stages.find(s => s.id === "resolve")?.state).toBe("stopped");
    expect(stages.find(s => s.id === "validate")?.caption).toBe("Recovery independently verified and closed");
    expect(stages.some(s => s.caption === "Remediation completed")).toBe(false);
    expect(currentLifecycleStage({status: "closed"} as any, stages)?.id).toBe("validate");
  });
});


describe("Inbox human evidence ownership", () => {
  it("puts an actual human evidence wait in Needs me", () => {
    const row = { status: "waiting_for_human", severity: "high" } as any;
    expect(belongsToInboxView(row, "needs_me")).toBe(true);
    expect(belongsToInboxView(row, "kai_handling")).toBe(false);
  });
  it("keeps ongoing collection in Kai handling", () => {
    const row = { status: "collecting", severity: "high" } as any;
    expect(belongsToInboxView(row, "needs_me")).toBe(false);
    expect(belongsToInboxView(row, "kai_handling")).toBe(true);
  });
});

it.each(["collecting", "waiting_for_human", "collection_blocked"])("does not label completed RCA as generating while %s", status => {
 const row = { status, recommendation_id: "recorded-rca", analysis_summary: { completed_at: "2026-10-17T14:00:00Z", rca_status: "insufficient_evidence", blockers: ["Independent causal evidence is missing"] } };
 expect(analysisBlocker(row)).toBe("Independent causal evidence is missing");
 const stage = lifecycleFor(row).find(item => item.id === "understand");
 expect(stage?.caption).not.toBe("Generating RCA");
 expect(stage?.caption).toBe(status === "waiting_for_human" ? "Waiting for human evidence" : "Analysis completed; more evidence needed");
});
