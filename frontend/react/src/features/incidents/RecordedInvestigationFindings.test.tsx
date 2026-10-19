// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { investigationFindings } from "./incidentTruth";
import { RecordedInvestigationFindings, InvestigationAlternatives } from "./RecordedInvestigationFindings";
afterEach(cleanup);
it("shows diagnostic observations and limitations when there is no confirmed cause", () => {
  const findings = investigationFindings({causal_chain: ["Proxy exited with status 137."], grounding_notes: "Exit status does not establish the cause."});
  render(<RecordedInvestigationFindings findings={findings} />);
  expect(screen.getByRole("heading", {name: "Recorded investigation findings"})).toBeTruthy();
  expect(screen.getByText("Proxy exited with status 137.")).toBeTruthy();
  expect(screen.getByText(/Exit status does not establish the cause/)).toBeTruthy();
  expect(screen.getByText(/do not establish the cause or customer impact/)).toBeTruthy();
});
it("shows alternative checks even when no contradictions were recorded", () => {
  const findings = investigationFindings({contradictions: [], alternative_causes: [{cause: "Resource pressure", falsification_check: "Inspect memory history."}]});
  render(<InvestigationAlternatives findings={findings} />);
  expect(screen.getByRole("heading", {name: "Alternative explanations to investigate"})).toBeTruthy();
  expect(screen.getByText("Resource pressure")).toBeTruthy();
  expect(screen.getByText(/Inspect memory history/)).toBeTruthy();
});
it("does not display empty results as findings", () => {
  const findings = investigationFindings({});
  const {container} = render(<><RecordedInvestigationFindings findings={findings} /><InvestigationAlternatives findings={findings} /></>);
  expect(container.textContent).toBe("");
});
