// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it } from "vitest";
import { AlertIncidentHandoff } from "./AlertIncidentHandoff";
import { alertIncidentId } from "../../domain/alertIncidentLink";
afterEach(cleanup);
it("preserves alert identity separately from its incident and links directly to that incident", () => {
  const row = { id: "alert-1", alert_id: "alert-1", incident_id: "incident-2" };
  render(<MemoryRouter><AlertIncidentHandoff row={row}/></MemoryRouter>);
  expect(screen.getByRole("link", { name: "Open incident ?" })).toHaveAttribute("href", "/incidents/incident-2");
});
it("supports nested incident projections without treating an alert identifier as an incident", () => {
  expect(alertIncidentId({ alert_id: "alert-1", incident_projection: { id: "incident-2" } })).toBe("incident-2");
  expect(alertIncidentId({ alert_id: "alert-1", incident_id: "alert-1" })).toBe("");
});
it.each([
  [{ id: "alert", status: "queued" }, "Queued for processing"],
  [{ id: "alert", incident_disposition: "duplicate" }, "Duplicate recorded"],
  [{ id: "alert", incident_disposition: "noise" }, "No incident required"],
  [{ id: "alert", status: "processed" }, "Incident link pending"],
])("shows a recorded handoff state without inventing an incident", (row, label) => {
  render(<MemoryRouter><AlertIncidentHandoff row={row}/></MemoryRouter>);
  expect(screen.getByText(label)).toBeVisible(); expect(screen.queryByRole("link")).toBeNull();
});
