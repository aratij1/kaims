// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import IncidentWorkflowNav from "./IncidentWorkflowNav";

afterEach(cleanup);
const props = { incidentId: "incident", status: "collecting", evidenceCount: 14, grounded: false,
  approvalPending: false, executionStatus: "not_started", recoveryVerified: false,
  onRefresh: vi.fn().mockResolvedValue(undefined) };

it("opens the deferred source browser before its detailed context exists", () => {
  const browser = document.createElement("details"); browser.className = "ic-raw-context";
  document.body.append(browser);
  try {
    render(<IncidentWorkflowNav {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Review collected context" }));
    expect(browser.open).toBe(true);
  } finally { browser.remove(); }
});

it("navigates the requested four-stage flow and opens historical evidence", () => {
  const scroll = vi.fn();
  const details = document.createElement("details"); details.className = "ic-investigation-history";
  const target = document.createElement("section"); target.id = "incident-detailed-context"; target.scrollIntoView = scroll;
  const sourceBrowser = document.createElement("details");
  sourceBrowser.append(target); details.append(sourceBrowser); document.body.append(details);
  try {
    render(<IncidentWorkflowNav {...props} />);
    const navigation = screen.getByRole("navigation", { name: "Incident workflow" });
    expect([...navigation.querySelectorAll("strong")].map(node => node.textContent)).toEqual([
      "Orient", "Evidence & Understanding", "Resolve", "Validate"]);
    fireEvent.click(screen.getByRole("button", { name: /Evidence & Understanding/ }));
    fireEvent.click(screen.getByRole("button", { name: "Review collected context" }));
    expect(details.open).toBe(true); expect(sourceBrowser.open).toBe(true); expect(document.activeElement).toBe(target); expect(scroll).toHaveBeenCalled();
  } finally { details.remove(); target.remove(); }
});

it("keeps a large evidence count separate from causal and impact confirmation", () => {
  render(<IncidentWorkflowNav {...props} evidenceCount={84} />);
  const summary = screen.getByRole("region", { name: "Evidence review summary" });
  expect(summary.textContent).toContain("84");
  expect(summary.textContent).toContain("Not established");
  expect(screen.getByText("Review evidence", { exact: true })).toBeTruthy();
});

it("shows resolution prerequisites and target before any approval action", () => {
  render(<IncidentWorkflowNav {...props} target="api-gateway" risk="low" blockers={["grounded_rca_required"]} />);
  fireEvent.click(screen.getByRole("button", { name: /03 Resolve/ }));
  expect(screen.getByRole("heading", { name: "Complete resolution prerequisites" })).toBeTruthy();
  expect(screen.getByText("api-gateway")).toBeTruthy();
  expect(screen.getByText("grounded rca required")).toBeTruthy();
  expect(screen.queryByRole("button", { name: /^Approve/ })).toBeNull();
});

it("keeps administrative closure separate from verified recovery and pending approval", () => {
  render(<IncidentWorkflowNav {...props} status="closed" />);
  expect(screen.getByRole("button", { name: /Validate/ }).getAttribute("aria-current")).toBe("step");
  expect(screen.queryByText("Recovery verified")).toBeNull();
  expect(screen.queryByText("Waiting for approval")).toBeNull();
  expect(screen.getByText("Closed · review recovery evidence")).toBeTruthy();
});

it("reloads authoritative incident details on request", async () => {
  const refresh = vi.fn().mockResolvedValue(undefined);
  render(<IncidentWorkflowNav {...props} onRefresh={refresh} />);
  fireEvent.click(screen.getByRole("button", { name: "Reload Alert Details" }));
  await waitFor(() => expect(refresh).toHaveBeenCalledOnce());
});

it("reports a failed reload and allows retry without an unhandled rejection", async () => {
  const refresh = vi.fn().mockRejectedValueOnce(new Error("Network unavailable")).mockResolvedValueOnce(undefined);
  render(<IncidentWorkflowNav {...props} onRefresh={refresh} />);
  fireEvent.click(screen.getByRole("button", { name: "Reload Alert Details" }));
  await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("Could not reload"));
  const button = screen.getByRole("button", { name: "Reload Alert Details" }) as HTMLButtonElement;
  expect(button.disabled).toBe(false);
  fireEvent.click(button);
  await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
  expect(refresh).toHaveBeenCalledTimes(2);
});
