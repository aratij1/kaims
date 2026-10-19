// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import ContextEnrichmentPanel from "./ContextEnrichmentPanel";

const { fetchJson } = vi.hoisted(() => ({ fetchJson: vi.fn() }));

vi.mock("../../services/routeApi", () => ({ routeJson: fetchJson }));
vi.mock("../../utils/presentation", () => ({ formatUtcTimestamp: (value: string) => value }));

describe("ContextEnrichmentPanel polling", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  it("explains an expired bound trace before assignment synchronization failure", async () => {
    fetchJson.mockResolvedValue({
      schema_version: "kaiops.operations-state.v1",
      lifecycle_state: "WAITING_FOR_HUMAN",
      context: { evidence_ids: [] },
      requirements: [{
        requirement_id: "trace-gap", rca_version: 4, category: "traces",
        question: "Collect traces evidence for this incident.", status: "human_requested",
        latest_job: { connector_id: "discovery-mcp", status: "dead_letter", last_error: "TRACE_NOT_FOUND_OR_EXPIRED" },
        active_human_request: { request_id: "human-trace", expected_responder: "owner@example.com", status: "pending", assignment_failure_reason: "JIRA_SYNC_FAILED" },
      }],
      requirement_history: [],
    });

    render(<ContextEnrichmentPanel
      incidentId="incident-1" accessToken="token" declaredGaps={[{ category: "traces" }]}
      onIncidentRefresh={vi.fn().mockResolvedValue(undefined)}
    />);

    expect(await screen.findByText(/No matching trace was retrieved/)).toBeInTheDocument();
    expect(screen.queryByText("Human evidence assignment needs attention.")).not.toBeInTheDocument();
  });

  it("does not restart polling when the parent refresh callback changes", async () => {
    vi.useFakeTimers();
    fetchJson.mockResolvedValue({
      schema_version: "kaiops.operations-state.v1",
      lifecycle_state: "DETECTED",
      context: { evidence_ids: [] },
      requirements: [],
      requirement_history: [],
    });

    const props = {
      incidentId: "incident-1",
      accessToken: "token",
      declaredGaps: [],
      onIncidentRefresh: vi.fn().mockResolvedValue(undefined),
    };
    const view = render(<ContextEnrichmentPanel {...props} />);

    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(fetchJson).toHaveBeenCalledTimes(1);

    view.rerender(<ContextEnrichmentPanel {...props} onIncidentRefresh={vi.fn().mockResolvedValue(undefined)} />);
    await act(async () => { await Promise.resolve(); });

    expect(fetchJson).toHaveBeenCalledTimes(1);
  });

  it("shows an empty approved corpus before an obsolete assignment failure", async () => {
    vi.useFakeTimers();
    fetchJson.mockResolvedValue({
      schema_version: "kaiops.operations-state.v1",
      lifecycle_state: "COLLECTION_BLOCKED",
      context: { evidence_ids: [] },
      requirements: [{
        requirement_id: "requirement-1", category: "runbook", question: "Find an approved runbook.", status: "blocked",
        latest_job: { connector_id: "vector-db", status: "dead_letter", last_error: "NO_MATCHING_APPROVED_EVIDENCE" },
        active_human_request: { request_id: "request-1", status: "assignment_blocked", assignment_failure_reason: "NO_AUTHORIZED_RESPONDER" },
      }],
      requirement_history: [],
    });

    const view = render(<ContextEnrichmentPanel
      incidentId="incident-1" accessToken="token" declaredGaps={[{ category: "runbook" }]}
      onIncidentRefresh={vi.fn().mockResolvedValue(undefined)}
    />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });

    expect(screen.getByText(/No approved runbook matched this incident/)).toBeInTheDocument();
    expect(screen.queryByText(/No authorized responder could be resolved/)).not.toBeInTheDocument();
    view.unmount();
  });

  it("opens the active response form with requirement context and a verified source suggestion", async () => {
    fetchJson.mockResolvedValue({
      schema_version: "kaiops.operations-state.v1",
      lifecycle_state: "WAITING_FOR_HUMAN",
      context: { evidence_ids: [] },
      requirements: [{
        requirement_id: "metric-gap", category: "metrics", question: "Collect resource metrics.",
        status: "scheduled", collection_mode: "automatic",
      }, {
        requirement_id: "trace-gap", category: "traces",
        question: "Provide the incident-window trace that shows the slow dependency.",
        reason: "The metric confirms latency but not its cause.",
        suggested_source_reference: "jaeger://trace/verified-trace-id",
        status: "human_requested",
        active_human_request: { request_id: "request-1", status: "pending", expected_responder: "owner@example.com" },
      }],
      requirement_history: [],
    });
    const props = {
      incidentId: "incident-1", accessToken: "token",
      declaredGaps: [{ category: "traces", reason: "Causal trace required." }],
      proposedRcaDraft: "A downstream call may explain the latency.",
      onIncidentRefresh: vi.fn().mockResolvedValue(undefined),
    };
    const view = render(<ContextEnrichmentPanel {...props} reviewRequestToken={0} />);
    expect(await screen.findByText("What KaiMS needs to establish")).toBeInTheDocument();
    expect(screen.getAllByText("waiting for human evidence").length).toBeGreaterThan(0);
    expect(screen.getByText(/No automated collection job is recorded/)).toBeInTheDocument();
    expect(screen.queryByText(/KaiMS is searching/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Automated discovery is still running/)).not.toBeInTheDocument();
    expect(screen.getByLabelText("Response for metrics")).not.toBeVisible();

    view.rerender(<ContextEnrichmentPanel {...props} reviewRequestToken={1} />);

    expect((await screen.findByLabelText("Response for traces") as HTMLTextAreaElement).value).toContain("Evidence requirement: Provide the incident-window trace");
    expect((screen.getByLabelText("Response for traces") as HTMLTextAreaElement).value).toContain("AI hypothesis to verify or correct");
    expect(screen.getByLabelText("Source reference for traces")).toHaveValue("jaeger://trace/verified-trace-id");
    await waitFor(() => expect(screen.getByLabelText("Response for traces")).toHaveFocus());
    fetchJson.mockResolvedValue({
      schema_version: "kaiops.operations-state.v1", lifecycle_state: "WAITING_FOR_HUMAN",
      context: { evidence_ids: [] }, investigation: { rca_version: 2 },
      requirements: [{ requirement_id: "new-log-gap", category: "logs", question: "Verify the exporter startup error.",
        status: "human_requested", active_human_request: { request_id: "new-request", status: "pending" } }],
      requirement_history: [],
    });
    fireEvent.click(screen.getByRole("button", { name: "Reload status" }));
    await waitFor(() => expect(screen.getByLabelText("Response for logs")).toHaveFocus());
  });

  it("allows direct evidence input when automated assignment is blocked", async () => {
    const refresh = vi.fn().mockResolvedValue(undefined);
    fetchJson.mockResolvedValueOnce({
      schema_version: "kaiops.operations-state.v1",
      lifecycle_state: "COLLECTION_BLOCKED",
      context: { evidence_ids: [] },
      requirements: [{
        requirement_id: "runbook-gap", category: "runbook",
        question: "Provide an approved incident runbook.",
        reason: "A governed recovery procedure is required.",
        suggested_source_reference: "runbook://payments/recovery/v3",
        status: "blocked",
        latest_job: { connector_id: "vector-db", status: "dead_letter", last_error: "NO_MATCHING_APPROVED_EVIDENCE" },
        active_human_request: { request_id: "request-1", status: "assignment_blocked" },
      }],
      requirement_history: [],
    }).mockResolvedValueOnce({
      schema_version: "kaiops.operations-state.v1", lifecycle_state: "INVESTIGATING",
      context: { evidence_ids: ["HUMAN-1"] }, requirements: [], requirement_history: [],
    });

    render(<ContextEnrichmentPanel
      incidentId="incident-1" accessToken="token" declaredGaps={[{ category: "runbook" }]}
      proposedRcaDraft="Payments dependency failed." onIncidentRefresh={refresh}
    />);

    const response = await screen.findByLabelText("Response for runbook");
    expect((response as HTMLTextAreaElement).value).toContain("Evidence requirement: Provide an approved incident runbook.");
    expect(screen.getByLabelText("Source reference for runbook")).toHaveValue("runbook://payments/recovery/v3");
    fireEvent.change(response, { target: { value: "Runbook v3 was verified for the affected payments deployment." } });
    fireEvent.click(screen.getByRole("button", { name: "Submit reviewed evidence and rerun RCA" }));

    await waitFor(() => expect(fetchJson).toHaveBeenCalledWith(
      "/api-gateway/incidents/incident-1/context-gaps/runbook-gap/responses",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          response: "Runbook v3 was verified for the affected payments deployment.",
          source_reference: "runbook://payments/recovery/v3",
        }),
      }),
    ));
  });

  it("offers evidence input without claiming discovery when no job is recorded", async () => {
    fetchJson.mockResolvedValue({
      schema_version: "kaiops.operations-state.v1",
      lifecycle_state: "COLLECTING",
      context: { evidence_ids: [] },
      requirements: [{
        requirement_id: "topology-gap", category: "topology",
        question: "Identify affected dependencies.", status: "identified",
      }],
      requirement_history: [],
    });

    render(<ContextEnrichmentPanel
      incidentId="incident-1" accessToken="token" declaredGaps={[{ category: "topology" }]}
      onIncidentRefresh={vi.fn().mockResolvedValue(undefined)}
    />);

    expect(await screen.findByText(/No automated collection job is recorded/)).toBeInTheDocument();
    expect(screen.getByLabelText("Response for topology")).toBeInTheDocument();
    expect(screen.getByLabelText("Source reference for topology")).toBeInTheDocument();
  });
});

it("does not describe an ungrounded RCA without collection requests as gap-free", async () => {
  fetchJson.mockResolvedValue({ schema_version: "kaiops.operations-state.v1", lifecycle_state: "INVESTIGATING", context: { evidence_ids: ["metric-1"] }, requirements: [], investigation_workspace: { rca: { status: "insufficient_evidence", grounded: false } } });
  render(<ContextEnrichmentPanel incidentId="gap-handoff" accessToken="token" declaredGaps={[]} onIncidentRefresh={vi.fn()} />);
  expect(await screen.findByText(/No active collection requests are published/)).toBeInTheDocument();
  expect(screen.queryByText("No unresolved evidence gaps are declared.")).not.toBeInTheDocument();
  cleanup();
});

it("opens the requested human form from the prominent entry point and preserves input across refresh", async () => {
  fetchJson.mockResolvedValue({ schema_version: "kaiops.operations-state.v1", lifecycle_state: "WAITING_FOR_HUMAN",
    requirements: [
      { requirement_id: "metrics", category: "metrics", question: "Check metrics", status: "collected" },
      { requirement_id: "impact", category: "business_impact", question: "Which customers were affected?", status: "human_requested",
        active_human_request: { request_id: "human-impact", status: "pending" } },
    ] });
  render(<ContextEnrichmentPanel incidentId="incident-human" accessToken="token" declaredGaps={[]} onIncidentRefresh={vi.fn()} />);
  fireEvent.click(await screen.findByRole("button", { name: "Provide human evidence for business impact" }));
  const response = await screen.findByLabelText("Response for business_impact");
  await waitFor(() => expect(response).toHaveFocus());
  expect(response.closest("details")).toHaveAttribute("open");
  fireEvent.change(response, { target: { value: "Three customers reported checkout failures during the incident." } });
  const submit = screen.getByRole("button", { name: "Submit reviewed evidence and rerun RCA" });
  expect(submit).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Source reference for business_impact"), { target: { value: "https://support.example/incidents/42" } });
  expect(submit).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "Reload status" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Reload status" })).toBeEnabled());
  expect(screen.getByLabelText("Response for business_impact")).toHaveValue("Three customers reported checkout failures during the incident.");
  cleanup();
});

it("filters the work queue without expanding forms or rendering archived cards", async () => {
  fetchJson.mockResolvedValue({ schema_version: "kaiops.operations-state.v1", lifecycle_state: "COLLECTING",
    requirements: [
      { requirement_id: "queued", category: "metrics", question: "Check metrics", status: "scheduled", latest_job: { connector_id: "prometheus", status: "scheduled" } },
      { requirement_id: "blocked", category: "database", question: "Check database latency", status: "blocked" },
      { requirement_id: "done", category: "logs", question: "Review error logs", status: "collected", evidence_ids: ["LOG-1"] },
    ], requirement_history: [{ requirement_id: "old", category: "traces", question: "Old trace request", status: "collected" }] });
  render(<ContextEnrichmentPanel incidentId="work-queue" accessToken="token" declaredGaps={[]} onIncidentRefresh={vi.fn()} />);
  await screen.findByText("Check metrics");
  expect(screen.getByLabelText("Response for metrics")).not.toBeVisible();
  expect(screen.queryByText("Old trace request")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /Needs attention/ }));
  expect(screen.getByText("Check database latency")).toBeVisible();
  expect(screen.queryByText("Check metrics")).not.toBeInTheDocument();
  expect(screen.getByLabelText("Response for database")).not.toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: /Recorded/ }));
  expect(screen.getByText("Review error logs")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Submit reviewed evidence and rerun RCA" })).not.toBeInTheDocument();
  cleanup();
});

it("distinguishes analysis revisions from confirmed RCA and archives mismatched requests", async () => {
  render(<ContextEnrichmentPanel incidentId="revision-72" accessToken="token" declaredGaps={[]}
    operationsState={{ schema_version: "kaiops.operations-state.v1", lifecycle_state: "COLLECTING",
      investigation: { rca_version: 72 }, investigation_workspace: { rca: { grounded: false } }, requirements: [
        { requirement_id: "old", rca_version: 71, category: "database", question: "Old request", status: "human_requested", active_human_request: { request_id: "old-human", status: "pending" } },
        { requirement_id: "current", rca_version: 72, category: "logs", question: "Current question", status: "scheduled" },
        { requirement_id: "recorded", rca_version: 72, category: "metrics", question: "Recorded question", status: "collected" },
      ] }} onIncidentRefresh={vi.fn()} />);
  expect(await screen.findByText("1 open · 1 recorded")).toBeVisible();
  expect(screen.getByText(/Analysis revision 72.*Cause not established/)).toBeVisible();
  expect(screen.queryByText("Current RCA · v72")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Provide human evidence for database" })).not.toBeInTheDocument();
  expect(screen.queryByText("Old request")).not.toBeInTheDocument();
  cleanup();
});

it("uses the verified command workspace instead of issuing a duplicate operations poll", async () => {
  fetchJson.mockClear();
  render(<ContextEnrichmentPanel incidentId="shared-workspace" accessToken="token" declaredGaps={[]}
    operationsState={{ schema_version: "kaiops.operations-state.v1", lifecycle_state: "COLLECTING", requirements: [
      { requirement_id: "shared-gap", category: "logs", question: "Shared current requirement", status: "scheduled" },
    ] }} onIncidentRefresh={vi.fn()} />);
  expect(await screen.findByText("Shared current requirement")).toBeVisible();
  expect(fetchJson).not.toHaveBeenCalled();
  cleanup();
});

it("refreshes the shared command workspace instead of replacing only embedded operations", async () => {
  cleanup();
  const refresh = vi.fn().mockResolvedValue(undefined);
  const calls = fetchJson.mock.calls.length;
  render(<ContextEnrichmentPanel incidentId="shared" accessToken="token" declaredGaps={[]}
    operationsState={{schema_version: "kaiops.operations-state.v1", lifecycle_state: "COLLECTING", requirements: []}}
    onIncidentRefresh={refresh} />);
  fireEvent.click(screen.getByRole("button", {name: "Reload status"}));
  await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
  expect(fetchJson.mock.calls.length).toBe(calls);
});
