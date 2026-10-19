// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useNavigate } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import IncidentCommand from "./IncidentCommand";
import { ApiRequestError, requestValidated } from "../../services/apiClient";
const runtime = vi.hoisted(() => ({ incidents: { rows: [{ incident_id: "first", title: "Compact inbox title" }], loading: false, error: "", refresh: vi.fn(), application: "Telemetry" }, approvals: { rows: [] }, session: { accessToken: "test" } }));
vi.mock("../../app/routeRuntime", () => ({ useRouteRuntimeSlice: (key: keyof typeof runtime) => runtime[key] }));
vi.mock("../../services/apiClient", async (original) => ({ ...await original<typeof import("../../services/apiClient")>(), requestValidated: vi.fn() }));
vi.mock("./ContextEnrichmentPanel", () => ({ default: () => <textarea aria-label="Evidence draft" defaultValue="" /> }));
vi.mock("./HumanEscalation", () => ({ default: () => null }));
function workspace(id = "first") {
  return { incident: { incident_id: id, title: `Incident ${id}`, service: "frontend-proxy", status: "investigating" }, operations: { incident_id: id, lifecycle_state: "INVESTIGATING", investigation_workspace: { evidence: [{ evidence_id: `evidence-${id}`, category: "logs", citation: `Retained context ${id}` }], rca: {} } }, evidence: { counts: { latest_context_records: 1 } } } as any;
}
function Navigation() { const navigate = useNavigate(); return <button onClick={() => navigate("/incidents/second")}>Second incident</button>; }
function mount() { return render(<MemoryRouter initialEntries={["/incidents/first"]}><Navigation /><Routes><Route path="/incidents/:incidentId" element={<IncidentCommand />} /></Routes></MemoryRouter>); }
beforeEach(() => { vi.mocked(requestValidated).mockReset(); runtime.incidents.error = ""; runtime.incidents.rows = [{ incident_id: "first", title: "Compact inbox title" }]; });
afterEach(() => cleanup());
it("shows the committed administrative closure without claiming technical recovery", async () => {
  const payload = workspace();
  payload.incident.status = "closed";
  payload.operations.lifecycle_state = "CLOSED";
  payload.operations.validation = { report_id: "closure-report", status: "closed", closure_kind: "manual",
    health_restored: false, alerts_cleared: false,
    details: { action_taken: "Administrative closure: duplicate incident reviewed." } };
  vi.mocked(requestValidated).mockResolvedValue(payload);
  mount();
  await screen.findByRole("heading", { name: "Incident first" });
  fireEvent.click(screen.getByRole("tab", {name: "Recovery"}));
  await screen.findByRole("heading", { name: "Administrative closure recorded" });
  expect(screen.getByText("Administrative closure: duplicate incident reviewed.")).toBeTruthy();
  expect(screen.getByText(/Technical recovery was not verified by this closure/)).toBeTruthy();
  expect(screen.queryByText("Closure recorded without verified recovery evidence")).toBeNull();
});
it("retains context with a warning after a failed refresh", async () => {
  vi.mocked(requestValidated).mockResolvedValueOnce(workspace()).mockRejectedValueOnce(new Error("HTTP 503"));
  mount(); await screen.findByRole("heading", { name: "Incident first" });
  act(() => window.dispatchEvent(new Event("focus")));
  await screen.findByText(/Context refresh failed/);
  expect(screen.getByText("Retained context first")).toBeTruthy();
  expect(screen.getByText("Kai context record")).toBeTruthy();
});
it("shows a load error instead of a context-free compact inbox row", async () => {
  vi.mocked(requestValidated).mockRejectedValue(new Error("HTTP 503"));
  mount(); await screen.findByText("Incident data is temporarily unavailable");
  expect(screen.queryByText("Compact inbox title")).toBeNull();
  expect(screen.queryByText("Evidence library")).toBeNull();
});
it("keeps a valid workspace visible when the unrelated inbox request fails", async () => {
  runtime.incidents.error = "Inbox failed"; runtime.incidents.rows = [];
  vi.mocked(requestValidated).mockResolvedValue(workspace()); mount();
  await screen.findByRole("heading", { name: "Incident first" });
  expect(screen.getByText("Retained context first")).toBeTruthy();
});
it("ignores a late response from the previously selected incident", async () => {
  let finish!: (value: any) => void;
  vi.mocked(requestValidated).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; })).mockResolvedValueOnce(workspace("second"));
  mount(); fireEvent.click(screen.getByRole("button", { name: "Second incident" }));
  await screen.findByRole("heading", { name: "Incident second" });
  await act(async () => finish(workspace("first")));
  expect(screen.getByText("Retained context second")).toBeTruthy();
  expect(screen.queryByText("Retained context first")).toBeNull();
});
it("rejects a mismatched workspace rather than displaying the wrong incident", async () => {
  vi.mocked(requestValidated).mockResolvedValue(workspace("second"));mount();
  await screen.findByText("Incident workspace identity does not match the requested incident.");
  expect(screen.queryByText("Retained context second")).toBeNull();
});

it.each([401, 403, 404])("clears retained context when refresh returns %s", async (status) => {
  vi.mocked(requestValidated).mockResolvedValueOnce(workspace()).mockRejectedValueOnce(new ApiRequestError({ endpoint: "/command", status, code: `http_${status}`, message: "Workspace no longer accessible" }));
  mount(); await screen.findByRole("heading", { name: "Incident first" });
  act(() => window.dispatchEvent(new Event("focus")));
  await screen.findByText("Workspace no longer accessible");
  expect(screen.queryByText("Retained context first")).toBeNull();
});

it("shows recorded RCA and impact even while conclusions remain unconfirmed", async () => {
  const payload = workspace();
  payload.operations.investigation_workspace.impact = { status: "unconfirmed", statement: "Checkout requests may time out." };
  payload.operations.investigation_workspace.rca = { status: "insufficient_evidence", hypothesis: "Connection pool exhaustion needs verification.", resolved_evidence_ids: [] };
  vi.mocked(requestValidated).mockResolvedValue(payload);
  mount();
  await screen.findByRole("heading", { name: "Incident first" });
  fireEvent.click(screen.getByRole("tab", {name: "Cause & impact"}));
  expect(screen.getByRole("heading", { name: "Recorded impact assessment" })).toBeTruthy();
  expect(screen.getByText("Checkout requests may time out.")).toBeTruthy();
  expect(screen.getByText("Connection pool exhaustion needs verification.")).toBeTruthy();
  expect(screen.getByRole("heading", { name: "Impact has not been established" })).toBeTruthy();
  expect(screen.queryByRole("heading", { name: "Verified impact" })).toBeNull();
});

it("preserves an unsaved evidence draft when reviewing another tab", async () => {
  vi.mocked(requestValidated).mockResolvedValue(workspace());
  mount();
  await screen.findByRole("heading", {name: "Incident first"});
  expect(screen.queryByRole("textbox", {name: "Evidence draft"})).toBeNull();
  fireEvent.click(screen.getByRole("tab", {name: "Evidence"}));
  fireEvent.change(screen.getByRole("textbox", {name: "Evidence draft"}), {target: {value: "Verified observation in progress"}});
  fireEvent.click(screen.getByRole("tab", {name: "Cause & impact"}));
  expect(screen.queryByRole("textbox", {name: "Evidence draft"})).toBeNull();
  fireEvent.click(screen.getByRole("tab", {name: "Evidence"}));
  expect((screen.getByRole("textbox", {name: "Evidence draft"}) as HTMLTextAreaElement).value).toBe("Verified observation in progress");
});
it("explains the causal gap and links to evidence without hiding observed impact", async () => {
  const payload = workspace();
  payload.operations.investigation_workspace.rca = {
    status: "insufficient_evidence",
    grounding_notes: "Slow downstream spans are present; the database wait mechanism has not been established.",
    missing_evidence: [{ category: "database", question: "Were database locks or I/O waits elevated?" }],
  };
  payload.operations.investigation_workspace.impact = {
    status: "observed", statement: "The inbox request took 14.4 seconds.",
  };
  vi.mocked(requestValidated).mockResolvedValue(payload);
  mount();
  await screen.findByRole("heading", { name: "Incident first" });
  fireEvent.click(screen.getByRole("tab", { name: "Cause & impact" }));
  expect(screen.getByRole("heading", { name: "Why this path is incomplete" })).toBeTruthy();
  expect(screen.getByText(/Were database locks or I\/O waits elevated/)).toBeTruthy();
  expect(screen.getByRole("heading", { name: "Verified impact" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Review evidence gaps" }));
  expect(screen.getByRole("tab", { name: "Evidence" }).getAttribute("aria-selected")).toBe("true");
});
it("shows an evidence-bearing RCA as inconclusive rather than unavailable", async () => {
  const payload = workspace();
  payload.operations.investigation_workspace.binding = {rca_version: 2};
  payload.operations.investigation_workspace.rca = {
    status: "insufficient_evidence", hypothesis: "Investigation inconclusive: only a symptom is established.",
    confidence: .73, grounding_notes: "The container exited; its exit reason remains unknown.",
    resolved_evidence_ids: ["evidence-first"], traceable_citation_count: 1,
  };
  vi.mocked(requestValidated).mockResolvedValue(payload);
  mount();
  await screen.findByRole("heading", {name: "Incident first"});
  fireEvent.click(screen.getByRole("tab", {name: "Cause & impact"}));
  expect(screen.getByRole("heading", {name: "Cause not established"})).toBeTruthy();
  expect(screen.getAllByText("Inconclusive")).toHaveLength(2);
  expect(screen.getByText(/no causal claim confidence has been assigned/)).toBeTruthy();
});
it("links an administrative duplicate's retained RCA to the incident cited in its closure note", async () => {
  const payload = workspace();
  payload.incident.status = "closed";
  payload.operations.lifecycle_state = "CLOSED";
  payload.operations.validation = {closure_kind: "manual", health_restored: false, details: {metadata: {
    operator_comment: "Administrative duplicate closure: redundant rules. Canonical incident abc2a6b3-9cc1-40c3-a4e5-fb1a1755f7ac records recovery.",
  }}};
  vi.mocked(requestValidated).mockResolvedValue(payload);
  mount();
  await screen.findByRole("heading", {name: "Duplicate incident closed"});
  expect(screen.getByRole("link", {name: "Open referenced incident"}).getAttribute("href"))
    .toBe("/incidents/abc2a6b3-9cc1-40c3-a4e5-fb1a1755f7ac?section=recovery");
  expect(screen.queryByRole("heading", {name: "Recovery verified"})).toBeNull();
});
it("separates an investigation blocker from later execution prerequisites", async () => {
  const payload = workspace();
  payload.operations.investigation_workspace.rca = {status: "hypothesis", grounding_notes: "The failed consumer has not been identified."};
  payload.operations.investigation_workspace.resolution = {status: "blocked", blocking_reasons: [
    "Queue-level metrics are missing.", "GOVERNED_EXECUTION_PLAN_NOT_PUBLISHED",
  ]};
  vi.mocked(requestValidated).mockResolvedValue(payload);
  mount(); await screen.findByRole("heading", {name: "Incident first"});
  fireEvent.click(screen.getByRole("tab", {name: "Resolution"}));
  expect(screen.getByText("Confirm the cause before choosing a remedy")).toBeTruthy();
  expect(screen.getByText("Plan and execution requirements")).toBeTruthy();
  expect(screen.queryByText(/Required before resolution:/)).toBeNull();
  fireEvent.click(screen.getByRole("button", {name: "Review evidence gaps"}));
  expect(screen.getByRole("tab", {name: "Evidence"}).getAttribute("aria-selected")).toBe("true");
});

it("keeps overview hypothesis, assessment and evidence scope consistent with analysis", async () => {
  const payload = workspace();
  const hypothesis = "Connection pool exhaustion needs verification.";
  payload.operations.investigation_workspace.rca = { status: "insufficient_evidence", grounded: false,
    hypothesis, resolved_evidence_ids: ["e1"], claims: [{kind: "CAUSAL", statement: hypothesis,
      confidence: .4, supporting_evidence_ids: ["e1"]}] };
  payload.operations.investigation_workspace.impact = {status: "unconfirmed", statement: "Checkout requests may time out."};
  payload.evidence.counts = {latest_context_records: 610, bound_snapshot_records: 50, rca_bound_records: 2};
  vi.mocked(requestValidated).mockResolvedValue(payload);
  const view = mount();
  await screen.findByRole("heading", {name: "Incident first"});
  const overview = view.container.querySelector('#incident-panel-overview')!;
  expect(overview.textContent).toContain("Working hypothesis");
  expect(overview.textContent).toContain(`Unconfirmed: ${hypothesis}`);
  expect(overview.textContent).toContain("Unconfirmed assessment");
  expect(overview.textContent).toContain("Unconfirmed: Checkout requests may time out.");
  expect(overview.textContent).toContain("2 referenced by this RCA; 50 in its frozen snapshot");
  fireEvent.click(screen.getByRole("tab", {name: "Cause & impact"}));
  expect(screen.getByRole("heading", {name: hypothesis})).toBeTruthy();
  expect(screen.getByText("Checkout requests may time out.")).toBeTruthy();
});


it("pauses interval polling while the incident tab is hidden", async () => {
  vi.mocked(requestValidated).mockResolvedValue(workspace());
  const descriptor = Object.getOwnPropertyDescriptor(document, "hidden");
  vi.useFakeTimers();
  try {
    await act(async () => { mount(); });
    expect(screen.getByRole("heading", {name: "Incident first"})).toBeTruthy();
    Object.defineProperty(document, "hidden", {value: true, configurable: true});
    await act(async () => { vi.advanceTimersByTime(30000); });
    expect(requestValidated).toHaveBeenCalledTimes(1);
    Object.defineProperty(document, "hidden", {value: false, configurable: true});
    await act(async () => { vi.advanceTimersByTime(30000); });
    expect(requestValidated).toHaveBeenCalledTimes(2);
  } finally {
    cleanup();
    vi.useRealTimers();
    if (descriptor) Object.defineProperty(document, "hidden", descriptor);
    else Reflect.deleteProperty(document, "hidden");
  }
});
