// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
import IncidentWorkspaceNav, { incidentView, type IncidentView } from "./IncidentWorkspaceNav";

afterEach(cleanup);
function Workspace() {
  const [active, onChange] = useState<IncidentView>("overview");
  return <><IncidentWorkspaceNav active={active} onChange={onChange} onRefresh={() => {}} refreshing={false} />
    {["overview", "evidence", "analysis", "resolution", "recovery", "activity"].map(view =>
      <section key={view} id={`incident-panel-${view}`} role="tabpanel" aria-labelledby={`incident-tab-${view}`}
        hidden={active !== view}>{view} content</section>)}</>;
}
describe("Focused incident workspace", () => {
  it("exposes one panel at a time with accessible tab relationships", () => {
    render(<Workspace />);
    expect(screen.getAllByRole("tab")).toHaveLength(6);
    expect(screen.getAllByRole("tabpanel")).toHaveLength(1);
    fireEvent.click(screen.getByRole("tab", {name: "Evidence"}));
    expect(screen.getByRole("tabpanel").textContent).toBe("evidence content");
    expect(screen.getByRole("tab", {name: "Evidence"}).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("tab", {name: "Overview"}).tabIndex).toBe(-1);
  });
  it("supports arrow keys, wrapping, Home and End", () => {
    render(<Workspace />);
    const overview = screen.getByRole("tab", {name: "Overview"});
    fireEvent.keyDown(overview, {key: "ArrowLeft"});
    expect(document.activeElement).toBe(screen.getByRole("tab", {name: "Activity"}));
    fireEvent.keyDown(document.activeElement!, {key: "Home"});
    expect(document.activeElement).toBe(overview);
    fireEvent.keyDown(overview, {key: "ArrowRight"});
    expect(document.activeElement).toBe(screen.getByRole("tab", {name: "Evidence"}));
    fireEvent.keyDown(document.activeElement!, {key: "End"});
    expect(document.activeElement).toBe(screen.getByRole("tab", {name: "Activity"}));
  });
  it("preserves valid deep links and falls back for unknown sections", () => {
    expect(incidentView("recovery")).toBe("recovery");
    expect(incidentView("analysis")).toBe("analysis");
    expect(incidentView("unknown")).toBe("overview");
    expect(incidentView(null)).toBe("overview");
  });
  it("refreshes without changing the selected task and disables duplicate requests", () => {
    const refresh = vi.fn();
    const {rerender} = render(<IncidentWorkspaceNav active="analysis" onChange={vi.fn()} onRefresh={refresh} refreshing={false} />);
    fireEvent.click(screen.getByRole("button", {name: "Refresh"}));
    expect(refresh).toHaveBeenCalledTimes(1);
    rerender(<IncidentWorkspaceNav active="analysis" onChange={vi.fn()} onRefresh={refresh} refreshing />);
    expect(screen.getByRole("button", {name: "Refreshing..."}).hasAttribute("disabled")).toBe(true);
    expect(screen.getByRole("tab", {name: "Cause & impact"}).getAttribute("aria-selected")).toBe("true");
  });
});
