// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { IncidentSourceRecords } from "./IncidentSourceRecords";
import { requestValidated } from "../../services/apiClient";
vi.mock("../../services/apiClient", () => ({ requestValidated: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
it("loads raw evidence only on expansion and reuses it on reopening", async () => {
  vi.mocked(requestValidated).mockResolvedValue({ incident_id: "incident-1", incident: {
    context: { metadata: { context_evidence: { logs: [{ message: "Verified source record" }] } } },
  } } as never);
  const view = render(<IncidentSourceRecords incidentId="incident-1" accessToken="test" />);
  expect(requestValidated).not.toHaveBeenCalled();
  expect(screen.queryByRole("region", { name: "Detailed context" })).toBeNull();
  const details = view.container.querySelector("details")!;
  details.open = true;
  fireEvent(details, new Event("toggle"));
  await screen.findByText("Verified source record");
  details.open = false; fireEvent(details, new Event("toggle"));
  details.open = true; fireEvent(details, new Event("toggle"));
  await waitFor(() => expect(requestValidated).toHaveBeenCalledTimes(1));
});
it("keeps failure actionable and rejects evidence from another incident", async () => {
  vi.mocked(requestValidated).mockResolvedValue({ incident_id: "other", incident: {} } as never);
  const view = render(<IncidentSourceRecords incidentId="incident-1" />);
  const details = view.container.querySelector("details")!;
  details.open = true; fireEvent(details, new Event("toggle"));
  await screen.findByRole("alert");
  expect(screen.getByRole("button", { name: "Retry source records" })).toBeTruthy();
  expect(screen.queryByRole("region", { name: "Detailed context" })).toBeNull();
});

it("reloads open source records when the canonical workspace generation changes", async () => {
  const response = (message: string) => ({incident_id: "incident-1", incident: {context: {metadata: {context_evidence: {logs: [{message}]}}}}});
  vi.mocked(requestValidated).mockResolvedValueOnce(response("Earlier snapshot") as never).mockResolvedValueOnce(response("Current snapshot") as never);
  const view = render(<IncidentSourceRecords incidentId="incident-1" accessToken="test" revision="old" />);
  const details = view.container.querySelector("details")!;
  details.open = true; fireEvent(details, new Event("toggle"));
  await screen.findByText("Earlier snapshot");
  view.rerender(<IncidentSourceRecords incidentId="incident-1" accessToken="test" revision="new" />);
  await screen.findByText("Current snapshot");
  expect(screen.queryByText("Earlier snapshot")).toBeNull();
  expect(requestValidated).toHaveBeenCalledTimes(2);
});
