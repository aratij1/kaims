// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { RcaSequenceReport, eventSummary } from "./RcaSequenceReport";
afterEach(cleanup);
it("shows event citations and a proposed remedy even when execution is gated", () => {
  render(<RcaSequenceReport rca={{timeline: {events: [{event: "Process exited", evidence_ids: ["log-1"]}]}}}
    resolution={{status: "blocked", proposed_remedy: "Investigate memory pressure", blocking_reasons: ["RCA_NOT_GROUNDED"]}}
    execution={{}} validation={{}} confirmed={false} />);
  expect(screen.getByText("Process exited")).toBeTruthy();
  expect(screen.getByText("Event time not recorded")).toBeTruthy();
  expect(screen.getByText(/Sources: log-1/)).toBeTruthy();
  expect(screen.getByText("Investigate memory pressure")).toBeTruthy();
  expect(screen.getByText("Recovery has not been verified.")).toBeTruthy();
});
it("does not treat closure or healthy checks without a proof receipt as verified recovery", () => {
  render(<RcaSequenceReport rca={{}} resolution={{}} execution={{status: "completed"}}
    validation={{health_restored: true, alerts_cleared: true, closure_kind: "administrative"}} confirmed={false} />);
  expect(screen.getByText("Closure was recorded without verified recovery proof.")).toBeTruthy();
});
it("displays the validation receipt when recovery is verified", () => {
  render(<RcaSequenceReport rca={{}} resolution={{}} execution={{status: "completed"}}
    validation={{health_restored: true, alerts_cleared: true, report_id: "report-1", validation_checksum: "abc"}} confirmed={true} />);
  expect(screen.getByText("Recovery verified by the recorded validation report.")).toBeTruthy();
});

it("renders structured source observations as readable events while retaining the raw payload", () => {
  const raw = JSON.stringify({runtime_service: "frontend-proxy", state: "exited", status: "Exited (137)"});
  render(<RcaSequenceReport rca={{timeline: {events: [{event: raw, evidence_ids: ["runtime-1"]}]}}}
    resolution={{}} execution={{}} validation={{}} confirmed={false} />);
  expect(screen.getByText("frontend-proxy: exited")).toBeTruthy();
  expect(screen.getByText(raw)).toBeTruthy();
  expect(eventSummary(JSON.stringify({metric: {__name__: "probe_success"}, value: [123, "0"]}))).toBe("probe_success: 0");
});
it("does not imply that an incomplete timeline invalidates a supported cause", () => {
  render(<RcaSequenceReport rca={{timeline: {events: []}}} resolution={{}} execution={{}} validation={{}} confirmed />);
  expect(screen.getByText(/The cause is supported. Complete event ordering is not confirmed/)).toBeTruthy();
});
