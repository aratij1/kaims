// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import DashboardRoute from "../dashboard/DashboardRoute";
import IncidentsRoute from "./IncidentsRoute";
import IncidentCommand from "../../features/incidents/IncidentCommand";
import { requestValidated } from "../../services/apiClient";

const data = vi.hoisted(() => {
  const row = { incident_id: "32f77019-ab6b-4945-8942-4b305022b18d", title: "ProductionApiUnavailable", service: "api-gateway", severity: "critical", status: "investigating" };
  return { row, runtime: {
    incidents: { application: "KaiMS", rows: [row], page: {}, filters: { service: "", status: "all", risk_tier: "all", execution_mode: "all", transport_provider: "all" }, loading: false, updateFilter: vi.fn(), loadPage: vi.fn(), refresh: vi.fn(), open: vi.fn(() => { throw new Error("Legacy navigation must not be used"); }) },
    alerts: { rows: [], inboxRows: [], loading: false, refresh: vi.fn() },
    session: { accessToken: "test-token" },
    dashboard: { openSection: vi.fn(), refresh: vi.fn() }, approvals: { rows: [] }, executive: { recentlyClosed: [] },
  } };
});
vi.mock("../../app/routeRuntime", () => ({ useRouteRuntime: () => data.runtime, useRouteRuntimeSlice: (key: keyof typeof data.runtime) => data.runtime[key] }));
vi.mock("./useInboxFeed", () => ({ useInboxFeed: () => ({ data: { rows: [{ record_type: "incident", row: data.row, score: 180 }], filtered_count: 1, record_counts: { incidents: 1 }, view_counts: { all: 1 } }, loading: false, error: "", refresh: vi.fn() }) }));
vi.mock("../../services/apiClient", async (importOriginal) => ({ ...await importOriginal<typeof import("../../services/apiClient")>(), requestValidated: vi.fn(async () => ({ incident: data.row, operations: { lifecycle_state: "INVESTIGATING", investigation_workspace: {} }, evidence: {} })) }));
function Destination() {
  const { incidentId } = useParams(); const navigate = useNavigate();
  return <><IncidentCommand /><output>{incidentId}</output><button onClick={() => navigate(-1)}>Back</button></>;
}
function Location() { return <output data-testid="location">{useLocation().pathname}</output>; }
function mount(path: string) {
  return render(<MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/" element={<DashboardRoute />} />
    <Route path="/incidents" element={<IncidentsRoute />} />
    <Route path="/incidents/:incidentId" element={<Destination />} />
  </Routes><Location /></MemoryRouter>);
}
afterEach(() => { cleanup(); localStorage.clear(); vi.clearAllMocks(); });
async function assertDestination() {
  await waitFor(() => expect(screen.getByRole("heading", { name: "ProductionApiUnavailable" })).toBeTruthy());
  expect(requestValidated).toHaveBeenCalledWith(`/api-gateway/incidents/${data.row.incident_id}/command?include_source_records=false`, expect.anything(), expect.anything());
  expect(screen.getByTestId("location").textContent).toBe(`/incidents/${data.row.incident_id}`);
  expect(data.runtime.incidents.open).not.toHaveBeenCalled();
}
it("opens Overview's incident in the canonical route and supports Back", async () => {
  mount("/");
  fireEvent.click(screen.getByRole("button", { name: /ProductionApiUnavailable/ }));
  await assertDestination(); fireEvent.click(screen.getByRole("button", { name: "Back" }));
  expect(screen.getByRole("button", { name: /ProductionApiUnavailable/ })).toBeTruthy();
});
it("opens the unified inbox card in the same canonical route", async () => {
  mount("/incidents"); fireEvent.click(screen.getByRole("button", { name: "Open incident" })); await assertDestination();
});
it("opens incidents-only View details in the same route even with a saved legacy layout", async () => {
  localStorage.setItem("kaiops.incident-presentation", "details");
  mount("/incidents?record_type=incidents");
  expect(screen.queryByText("Split Workspace")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "View details" })); await assertDestination();
});
it("redirects an old incident query link without needing the incident on the current page", async () => {
  mount(`/incidents?incident_id=${data.row.incident_id}&cursor=old`); await assertDestination();
});
it("supports a direct incident URL", async () => { mount(`/incidents/${data.row.incident_id}`); await assertDestination(); });

it("shows the linked Jira issue in the canonical incident header", async () => {
  vi.mocked(requestValidated).mockResolvedValueOnce({ incident: { ...data.row, jira_key: "KAN-123", jira_url: "https://example.atlassian.net/browse/KAN-123" }, operations: {}, evidence: {} } as any);
  mount(`/incidents/${data.row.incident_id}`);
  const link = await screen.findByRole("link", { name: /KAN-123/ });
  expect(link.getAttribute("href")).toBe("https://example.atlassian.net/browse/KAN-123");
});
it("shows Not linked when no Jira issue exists", async () => {
  mount(`/incidents/${data.row.incident_id}`);
  await assertDestination();
  expect(screen.getByText("Not linked")).toBeTruthy();
});


it("opens the canonical incident from a lifecycle stage", async () => {
  localStorage.setItem("kaiops.incident-presentation", "flow");
  mount("/incidents?record_type=incidents");
  const timeline = screen.getByLabelText(/Lifecycle for ProductionApiUnavailable/);
  const stage = timeline.querySelector("button:not(:disabled)");
  expect(stage).toBeTruthy();
  fireEvent.click(stage!);
  await assertDestination();
});

it("keeps the inbox reachable while a slow incident workspace is loading", async () => {
  vi.mocked(requestValidated).mockImplementationOnce(() => new Promise(() => {}));
  mount(`/incidents/${data.row.incident_id}`);
  const opening = await screen.findByRole("region", { name: "Opening incident" });
  fireEvent.click(opening.querySelector("button")!);
  expect(screen.getByTestId("location").textContent).toBe("/incidents");
});
