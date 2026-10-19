// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { contextSources, emptySourceStatus, hasContextData, IncidentContextDetails } from "./IncidentContextDetails";

afterEach(cleanup);

it("exposes collected evidence instead of empty infrastructure placeholders", () => {
  render(<IncidentContextDetails context={{ cloud: {}, kubernetes: {}, recent_changes: [], metadata: { context_evidence: { logs: [{ message: "Collector connection refused" }], traces: [{ span: "Failed request" }], database: [] } } }} source={{}} snapshot={{}} />);
  expect(screen.getByText("Collector connection refused")).toBeTruthy();
  expect(screen.queryByRole("option", { name: "Cloud" })).toBeNull();
  expect(screen.getByText("Cloud")).toBeTruthy();
  expect(screen.queryByText(/No data returned:/)).toBeNull();
  fireEvent.change(screen.getByLabelText("Context section"), { target: { value: "traces_evidence" } });
  expect(screen.getByText("Failed request")).toBeTruthy();
});

it("does not treat nested empty objects as collected data or discard zero and false", () => {
  expect(hasContextData({ metrics: [], logs: { items: null } })).toBe(false);
  expect(hasContextData({ failures: 0, healthy: false })).toBe(true);
  expect(contextSources({ cloud: { resources: [] }, observability: { up: 0 } }, {}, {}).available.map(([key]) => key)).toEqual(["observability"]);
});

it("falls back to a real source alert and preserves missing-source information", () => {
  const sources = contextSources({ alert: {}, cloud: null, deployment: {} }, { name: "ServiceDown" }, {});
  expect(sources.available).toEqual([["alert", { name: "ServiceDown" }]]);
  expect(sources.unavailable).toEqual(["cloud", "deployment"]);
});

it("clearly reports when no detailed context was returned", () => {
  render(<IncidentContextDetails context={{ cloud: {}, logs: [] }} source={{}} snapshot={{}} />);
  expect(screen.getByText(/No detailed context has been returned/)).toBeTruthy();
  expect(screen.queryByLabelText("Context section")).toBeNull();
});


it("separates historical ingestion artifacts from application logs", () => {
  const artifact = { uri: "log:///data/landing/failed/alert.json#L8", message: "Original alert" };
  const log = { uri: "log:///var/log/api.log#L1", message: "Database connection refused" };
  const sources = contextSources({ metadata: { context_evidence: { logs: [artifact, log] } } }, {}, {});
  expect(sources.available.find(([key]) => key === "logs_evidence")?.[1]).toEqual([log]);
  expect(sources.available.find(([key]) => key === "alert_ingestion_artifacts")?.[1]).toEqual([artifact]);
  render(<IncidentContextDetails context={{ metadata: { context_evidence: { logs: [artifact, log] } } }} source={{}} snapshot={{}} />);
  expect(screen.getByText(/not application logs or independent RCA evidence/)).toBeTruthy();
});


it("does not report empty legacy aliases when enriched evidence is present", () => {
  const context = { deployment: {}, recent_changes: [], dependency_services: [], metadata: {
    context_evidence: { deployment: [{ id: "deploy" }], changes: [{ id: "change" }], dependency: [{ id: "dep" }], database: [{ id: "db" }] },
    context_sources: { database: { attempted: false, status: "skipped", result_count: 0 } },
  } };
  const result = contextSources(context, {}, {});
  expect(result.unavailable).toEqual([]);
  expect(result.available.map(([key]) => key)).toContain("database_evidence");
});

it("distinguishes no matches from skipped, unattempted, failed and unknown sources", () => {
  const context = { metadata: { context_sources: {
    rag: { attempted: true, collection_status: "no_matches" },
    other: { attempted: false, collection_status: "no_matches" },
    database: { status: "failed", error: "timeout" },
  }, discovery_report: { retrieval_stages: [{ stage: "runbooks_search", status: "skipped" }] } } };
  expect(emptySourceStatus("rag_evidence", context)).toBe("Search completed with no matching records");
  expect(emptySourceStatus("other_evidence", context)).toBe("Not attempted");
  expect(emptySourceStatus("runbook", context)).toBe("Skipped by collection policy");
  expect(emptySourceStatus("database_evidence", context)).toContain("Collection failed");
  expect(emptySourceStatus("cloud", context)).toBe("No collection outcome recorded");
});
