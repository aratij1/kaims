import { describe, expect, it } from "vitest";

import { durableIncidentId, durableIncidentPath } from "./incidentNavigation";

describe("durable incident navigation", () => {
  it("opens the canonical incident when an occurrence has a different id", () => {
    expect(durableIncidentPath({ canonical_incident_id: "canonical-id", incident_id: "occurrence-id" })).toBe("/incidents/canonical-id");
  });
  it("uses and URL-encodes the durable incident identifier", () => {
    expect(durableIncidentPath({ incident_id: "tenant/a incident" })).toBe("/incidents/tenant%2Fa%20incident");
  });

  it("reads a linked incident projection without treating an alert id as the destination", () => {
    expect(durableIncidentPath({ id: "alert-id", incident_projection: { incident_id: "incident-id" } })).toBe("/incidents/incident-id");
  });

  it("returns an explicit unavailable result when identity is missing", () => {
    expect(durableIncidentId({})).toBe("");
    expect(durableIncidentPath({})).toBeNull();
  });
});

it("ignores blank identifiers before a valid canonical projection", () => {
  expect(durableIncidentPath({ incident_id: "  ", id: "alert-id", incident_projection: { incident_id: "incident-id" } })).toBe("/incidents/incident-id");
});
