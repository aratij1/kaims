// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { env } from "node:process";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import IncidentCommand from "./IncidentCommand";
import { requestValidated } from "../../services/apiClient";
import { routeJson } from "../../services/routeApi";
const runtime = vi.hoisted(() => ({ incidents: { rows: [], loading: false, error: "", refresh: vi.fn(), application: "KaiMS" }, approvals: { rows: [] }, session: { accessToken: "local-fixture-test" } }));
vi.mock("../../app/routeRuntime", () => ({ useRouteRuntimeSlice: (key: keyof typeof runtime) => runtime[key] }));
vi.mock("../../services/apiClient", async original => ({ ...await original<typeof import("../../services/apiClient")>(), requestValidated: vi.fn() }));
vi.mock("../../services/routeApi", () => ({ routeJson: vi.fn() }));
vi.mock("./HumanEscalation", () => ({ default: () => null }));
const fixturePath = env.KAIMS_WORKSPACE_FIXTURE;
const workspaces = fixturePath ? JSON.parse(readFileSync(fixturePath, "utf8")) : [];
afterEach(() => { cleanup(); vi.clearAllMocks(); });
it.skipIf(!fixturePath)("renders the ten captured backend workspaces with real evidence panels", async () => {
  expect(workspaces).toHaveLength(10);
  for (const workspace of workspaces) {
    const id = workspace.incident.incident_id;
    vi.mocked(requestValidated).mockResolvedValue(workspace);
    vi.mocked(routeJson).mockResolvedValue(workspace.operations);
    render(<MemoryRouter initialEntries={[`/incidents/${id}`]}><Routes><Route path="/incidents/:incidentId" element={<IncidentCommand />} /></Routes></MemoryRouter>);
    expect(await screen.findByRole("heading", { name: workspace.incident.title })).toBeTruthy();
    expect(await screen.findByText("Current RCA evidence funnel")).toBeTruthy();
    expect(screen.queryByText("Workspace could not be displayed")).toBeNull();
    cleanup();
  }
});
