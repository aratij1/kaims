// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup } from "@testing-library/react";
import IncidentsRoute from "./IncidentsRoute";

const state = vi.hoisted(() => ({
  incidents: { application: "KaiMS", rows: [], page: {}, loading: false, error: "",
    filters: { service: "api-gateway", status: "closed", risk_tier: "all", execution_mode: "all", transport_provider: "all" },
    updateFilter: vi.fn(), loadPage: vi.fn(), refresh: vi.fn() },
  alerts: { rows: [], inboxRows: [], loading: false, refresh: vi.fn() },
  session: { accessToken: "test-token" },
}));
vi.mock("../../app/routeRuntime", () => ({ useRouteRuntimeSlice: (key: keyof typeof state) => state[key] }));
vi.mock("./useInboxFeed", () => ({ useInboxFeed: () => ({ data: { rows: [], record_counts: {}, view_counts: {}, filtered_count: 0 }, loading: false, error: "", refresh: vi.fn() }) }));
function Location() { return <output data-testid="location">{useLocation().search}</output>; }
afterEach(() => { cleanup(); vi.clearAllMocks(); });
it("clears previous application cursor and filters when switching to Telemetry", async () => {
  state.incidents.application = "KaiMS";
  const view = () => <MemoryRouter initialEntries={["/incidents?cursor=old-page&service=api-gateway&status=closed&inbox_view=resolved"]}><IncidentsRoute /><Location /></MemoryRouter>;
  const rendered = render(view());
  expect(screen.getByTestId("location").textContent).toContain("cursor=old-page");
  state.incidents.application = "Telemetry";
  rendered.rerender(view());
  await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("?inbox_view=all&record_type=all"));
  expect(state.incidents.updateFilter).toHaveBeenCalledWith("service", "");
  expect(state.incidents.updateFilter).toHaveBeenCalledWith("status", "all");
});
it("lets users clear hidden filters without changing applications", () => {
  state.incidents.application = "Telemetry";
  render(<MemoryRouter initialEntries={["/incidents?status=closed&cursor=old"]}><IncidentsRoute /><Location /></MemoryRouter>);
  fireEvent.click(screen.getByRole("button", { name: "Show all incidents and alerts" }));
  expect(screen.getByTestId("location").textContent).toBe("?inbox_view=all&record_type=all");
  expect(state.incidents.updateFilter).toHaveBeenCalledWith("transport_provider", "all");
});
