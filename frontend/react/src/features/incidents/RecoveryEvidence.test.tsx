// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import RecoveryEvidence, { groupRecoveryObservations } from "./RecoveryEvidence";
afterEach(cleanup);
it("groups every sample by validator without dropping distinct checks", () => {
  const observations = Array.from({length: 66}, (_, index) => ({
    validator_id: `validator-${Math.floor(index / 11)}`, kind: "availability", passed: true,
    observed_at: new Date(Date.UTC(2026, 9, 18, 15, 25, index % 11)).toISOString(),
    measured_value: 1, expected_value: 1, connector_id: "prometheus", target_resource_id: "frontend-proxy",
  }));
  const groups = groupRecoveryObservations([...observations].reverse());
  expect(groups).toHaveLength(6);
  expect(groups.every(group => group.samples.length === 11 && group.passed)).toBe(true);
  render(<RecoveryEvidence observations={observations} />);
  expect(screen.getByText("6 recorded checks / 66 samples")).toBeTruthy();
  expect(screen.getAllByRole("article")).toHaveLength(6);
});
it("does not present missing or failed sample results as a passed check", () => {
  const groups = groupRecoveryObservations([
    {validator_id: "a", passed: true}, {validator_id: "a", passed: false},
    {validator_id: "b"},
  ]);
  expect(groups.every(group => !group.passed)).toBe(true);
});
it("reports absent observations explicitly", () => {
  render(<RecoveryEvidence observations={[]} />);
  expect(screen.getByText("No immutable post-state observations were published.")).toBeTruthy();
});
