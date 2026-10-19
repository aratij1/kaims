// @vitest-environment jsdom
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import ResolutionJourney from "./ResolutionJourney";

afterEach(cleanup);
const props = { status: "collecting", phase: "collecting", grounded: false,
  resolutionReady: false, executionStatus: "not_started", recoveryVerified: false, observedRecovery: false };
const step = (name: string) => screen.getByText(name, { exact: true }).closest("li")!;

it("shows human waiting with recorded assignment and concurrent automated collection", () => {
  render(<ResolutionJourney {...props} status="waiting_for_human" requirements={[{
    status: "open", question: "Provide the deployment change", active_human_request: { expected_responder: "Platform team" },
  }]} />);
  expect(within(screen.getByRole("status")).getByText("Human evidence needed")).toBeTruthy();
  expect(screen.getByText("Automated evidence collection is also running.")).toBeTruthy();
  expect(screen.getByText("Owner: Platform team")).toBeTruthy();
  expect(step("Understanding").className).toBe("is-waiting");
  expect(within(step("Understanding")).getByText("Human evidence needed")).toBeTruthy();
});

it("does not mark missing causal evidence complete when execution has advanced", () => {
  render(<ResolutionJourney {...props} status="remediating" resolutionReady />);
  expect(within(step("Root cause")).getByText("Not confirmed")).toBeTruthy();
  expect(step("Root cause").className).not.toBe("is-complete");
  expect(step("Executing").getAttribute("aria-current")).toBe("step");
});

it.each(["closed", "cancelled"])("does not present %s as verified recovery", status => {
  render(<ResolutionJourney {...props} status={status} />);
  expect(screen.queryByText("Recovered", { exact: true })).toBeNull();
  expect(screen.queryByText("Recovery verified")).toBeNull();
  expect(screen.getByText("Recorded", { exact: true })).toBeTruthy();
});

it.each([["queued", "Evidence collection queued"], ["retry_wait", "Evidence collection awaiting retry"]])("distinguishes collection phase %s", (phase, title) => {
  render(<ResolutionJourney {...props} phase={phase} />);
  expect(screen.getByText(title)).toBeTruthy();
  expect(step("Understanding").className).toBe("is-waiting");
});

it("does not assume a failed validation is complete", () => {
  render(<ResolutionJourney {...props} status="validation_failed" executionStatus="succeeded" />);
  expect(step("Verifying").className).toBe("is-failed");
  expect(within(step("Verifying")).getByText("Blocked")).toBeTruthy();
  expect(step("Recovered").className).toBe("is-pending");
});

it("confirms recovery only with the verified outcome", () => {
  render(<ResolutionJourney {...props} status="closed" recoveryVerified grounded resolutionReady executionStatus="succeeded" />);
  expect(step("Recovered").className).toBe("is-complete");
});

it("does not present earlier human requests as outstanding after closure", () => {
  render(<ResolutionJourney {...props} status="closed" requirements={[{
    status: "open", question: "Historical evidence request", active_human_request: { expected_responder: "Team" },
  }]} />);
  expect(screen.queryByText("Historical evidence request")).toBeNull();
});

it("shows an inconclusive RCA as assessed while evidence is queued, not as unstarted", () => {
  render(<ResolutionJourney {...props} phase="queued" rcaVersion={3} rcaStatus="insufficient_evidence" resolutionStatus="blocked" />);
  expect(within(step("Root cause")).getByText("Assessed; needs evidence")).toBeTruthy();
  expect(within(step("Root cause")).queryByText("Not started")).toBeNull();
  expect(within(step("Understanding")).getByText("Evidence queued")).toBeTruthy();
  expect(within(step("Resolution")).getByText("Blocked by prerequisites")).toBeTruthy();
  expect(within(step("Executing")).getByText("Not executed")).toBeTruthy();
  expect(within(step("Recovered")).getByText("Not verified")).toBeTruthy();
  expect(step("Root cause").className).not.toBe("is-complete");
});

it("does not call a running RCA finished", () => {
  render(<ResolutionJourney {...props} rcaVersion={2} rcaStatus="in_progress" />);
  expect(within(step("Root cause")).getByText("Analysis in progress")).toBeTruthy();
  expect(screen.queryByText(/assessment is recorded/)).toBeNull();
});

it("keeps recorded execution and validation results when an incident returns to evidence collection", () => {
  render(<ResolutionJourney {...props} phase="queued" executionStatus="failed" validationStatus="passed" />);
  expect(within(step("Executing")).getByText("Execution failed")).toBeTruthy();
  expect(within(step("Verifying")).getByText("Report recorded; unverified")).toBeTruthy();
  expect(step("Recovered").className).toBe("is-pending");
});
