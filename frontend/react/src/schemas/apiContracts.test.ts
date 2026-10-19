import { describe, expect, it } from "vitest";

import { ApiValidationError } from "../services/apiClient";
import { internalApiContractCount, parseInternalApiResponse } from "./apiContracts";
import { OperationalEventSchema } from "./operationalEvents";
import { OidcDiscoverySchema, OidcTokenResponseSchema } from "./oidc";

describe("internal API contract registry", () => {
  it("covers every internal endpoint family and fails closed for unknown paths", () => {
    expect(internalApiContractCount).toBeGreaterThanOrEqual(21);
    expect(parseInternalApiResponse("/api-gateway/healthz", "GET", { status: "ok" })).toMatchObject({ status: "ok" });
    expect(parseInternalApiResponse("/api-gateway/operations/queue-health", "GET", {
      status: "healthy",
      provider: "rabbitmq",
      healthy: true,
      queues: 4,
      messages: 2,
      ready: 2,
      unacknowledged: 0,
    })).toMatchObject({ status: "healthy", healthy: true, queues: 4 });
    expect(parseInternalApiResponse("/api-gateway/operations/queues", "GET", {
      provider: "rabbitmq", queues: [{ name: "kaiops.context" }], summary: { queues: 1 },
    })).toMatchObject({ provider: "rabbitmq", queues: [{ name: "kaiops.context" }] });
    expect(parseInternalApiResponse("/api-gateway/model/providers/status", "GET", {
      trace_id: "trace-1",
      data: {
        providers: {
          "azure-openai": { configured: true, healthy: true, model: "gpt-4o", circuit_open: false, failure_count: 0 },
        },
        selected: { default: "azure-openai" }, prompt_cache: { enabled: true },
      },
    })).toMatchObject({ providers: { "azure-openai": { healthy: true, model: "gpt-4o" } } });
    expect(parseInternalApiResponse("/api-gateway/incidents/metadata?limit=10", "GET", { rows: [] })).toMatchObject({ rows: [] });
    expect(parseInternalApiResponse(
      "/api-gateway/incidents/1f11cbe9-274a-490a-ae4c-aebb3d70e58a/context-gaps",
      "GET",
      { data: { schema_version: "kaiops.context-enrichment.v1", requirements: [{ requirement_id: "r1" }], jobs: [], human_requests: [] } },
    )).toEqual({
      schema_version: "kaiops.context-enrichment.v1",
      requirements: [{ requirement_id: "r1" }],
      jobs: [],
      human_requests: [],
    });
    expect(parseInternalApiResponse("/api-gateway/evaluations/by-recommendation/1f11cbe9-274a-490a-ae4c-aebb3d70e58a/feedback", "POST", { updated: true })).toEqual({ updated: true });
    expect(parseInternalApiResponse("/context-agent/collect?publish_events=false", "POST", {
      incident_id: "1f11cbe9-274a-490a-ae4c-aebb3d70e58a",
      alert: { id: "c38d2327-72e8-41a3-bb25-9a403c820d13", name: "HighLatency", service: "checkout" },
      related_incidents: [],
      runbook: "Restart the unhealthy worker.",
    })).toMatchObject({ incident_id: "1f11cbe9-274a-490a-ae4c-aebb3d70e58a" });
    expect(parseInternalApiResponse("/resolution-agent/resolve?publish_events=true", "POST", {
      incident_id: "1f11cbe9-274a-490a-ae4c-aebb3d70e58a",
      root_cause: "Worker saturation",
      confidence: 0.91,
      impact: "Checkout requests are delayed.",
      recommended_action: "Scale the worker pool.",
      severity: "high",
      rationale: "Queue depth and latency increased together.",
      commands: [],
      risk: "low",
    })).toMatchObject({ confidence: 0.91, severity: "high" });
    expect(parseInternalApiResponse("/api-gateway/analysis/context/collect?publish_events=false", "POST", {
      trace_id: "trace-context",
      data: {
        incident_id: "1f11cbe9-274a-490a-ae4c-aebb3d70e58a",
        alert: { id: "c38d2327-72e8-41a3-bb25-9a403c820d13", name: "HighLatency", service: "checkout" },
      },
    })).toMatchObject({ data: { incident_id: "1f11cbe9-274a-490a-ae4c-aebb3d70e58a" } });
    expect(parseInternalApiResponse("/api-gateway/analysis/resolution/resolve?publish_events=true", "POST", {
      trace_id: "trace-resolution",
      data: {
        incident_id: "1f11cbe9-274a-490a-ae4c-aebb3d70e58a",
        root_cause: "Worker saturation",
        confidence: 0.91,
        impact: "Checkout requests are delayed.",
        recommended_action: "Scale the worker pool.",
        severity: "high",
        rationale: "Queue depth and latency increased together.",
      },
    })).toMatchObject({ data: { confidence: 0.91 } });
    expect(parseInternalApiResponse("/api-gateway/analysis/alerts/c38d2327-72e8-41a3-bb25-9a403c820d13/regenerate", "POST", {
      request_id: "ab6cd3a8-83b4-4df8-b123-7366283767dd",
      status: "accepted",
      delivery: "published",
      alert_id: "c38d2327-72e8-41a3-bb25-9a403c820d13",
      incident_id: "1f11cbe9-274a-490a-ae4c-aebb3d70e58a",
      previous_recommendation_id: null,
      expected_recommendation_id: "753a1e18-7999-5b70-8f6d-553b85d62a62",
      analysis_mode: "fresh",
      context_strategy: "realtime",
      poll_after_ms: 2500,
    })).toMatchObject({ status: "accepted", delivery: "published", analysis_mode: "fresh" });
    expect(parseInternalApiResponse("/api-gateway/analysis/requests/ab6cd3a8-83b4-4df8-b123-7366283767dd/status?incident_id=1f11cbe9-274a-490a-ae4c-aebb3d70e58a", "GET", {
      request_id: "ab6cd3a8-83b4-4df8-b123-7366283767dd",
      incident_id: "1f11cbe9-274a-490a-ae4c-aebb3d70e58a",
      recommendation_id: "753a1e18-7999-5b70-8f6d-553b85d62a62",
      status: "complete",
      ready: true,
    })).toMatchObject({ status: "complete", ready: true });
    expect(() => parseInternalApiResponse("/api-gateway/unregistered", "GET", {})).toThrow(ApiValidationError);
  });

  it("rejects malformed authentication and streaming payloads", () => {
    expect(() => parseInternalApiResponse("/api-gateway/auth/login", "POST", { access_token: "" })).toThrow(ApiValidationError);
    expect(() => parseInternalApiResponse("/api-gateway/evaluations/by-recommendation/1f11cbe9-274a-490a-ae4c-aebb3d70e58a/feedback", "POST", { updated: "yes" })).toThrow(ApiValidationError);
    expect(OperationalEventSchema.safeParse({ id: "", type: "alert.created", data: {} }).success).toBe(false);
  });

  it("unwraps the authenticated gateway operations-state envelope", () => {
    const state = {
      schema_version: "kaiops.operations-state.v1",
      incident_id: "1f11cbe9-274a-490a-ae4c-aebb3d70e58a",
      lifecycle_state: "COLLECTION_BLOCKED",
      context: {}, investigation: {}, requirements: [], requirement_history: [],
      resolution: {}, approval: {}, updated_at: "2026-08-31T16:00:00Z",
      investigation_workspace: {
        schema_version: "kaiops.investigation-workspace.v1", binding: {}, impact: {}, rca: {},
        evidence: [], requirements: [], resolution: {}, operator_review: {},
      },
    };
    expect(parseInternalApiResponse(
      "/api-gateway/incidents/1f11cbe9-274a-490a-ae4c-aebb3d70e58a/operations-state",
      "GET", { trace_id: "safe-trace", data: state },
    )).toEqual(state);
  });

  it("validates the canonical incident command workspace", () => {
    const incidentId = "1f11cbe9-274a-490a-ae4c-aebb3d70e58a";
    const state = {
      schema_version: "kaiops.operations-state.v1",
      incident_id: incidentId,
      lifecycle_state: "RCA_READY",
      validation: {
        report_id: null, status: "closed", closure_kind: "recovery", validation_checksum: "sha256:recorded",
        action_id: null, health_restored: true, alerts_cleared: true, details: {}, updated_at: null,
        pre_state_observations: [], post_state_observations: [{validator_id: "availability", passed: true}],
        observation_window: {elapsed_seconds: 338.818, required_seconds: 300},
        outcome_decision: {closure_authorized: true}, knowledge_draft: null,
      },
      context: {}, investigation: {}, requirements: [], requirement_history: [],
      resolution: {}, approval: {}, updated_at: "2026-09-01T10:00:00Z",
    };
    const workspace = {
      schema_version: "kaiops.incident-command.v2",
      incident_id: incidentId,
      revision: "a".repeat(64),
      incident: { incident_id: incidentId, status: "investigating" },
      operations: state,
      evidence: {
        latest_snapshot_id: null, bound_snapshot_id: null, binding_consistent: false,
        evidence_collection_exhausted: false,
        counts: {
          latest_context_records: 0, bound_snapshot_records: 0, rca_bound_records: 0,
          traceable_citations: 0, unresolved_bindings: 0, open_requirements: 0,
          pending_requirements: 0, exhausted_requirements: 0, open_conflicts: 0,
        },
        scores: [{
          key: "context_quality", label: "Context quality", percent: null,
          status: "unavailable", ratio: null, reason: "Context quality was not published", blockers: [],
        }],
        blockers: ["RCA_SNAPSHOT_NOT_BOUND"],
      },
    };

    expect(parseInternalApiResponse(
      `/api-gateway/incidents/${incidentId}/command`, "GET", workspace,
    )).toEqual(workspace);
  });

  it("validates identity-provider discovery and token contracts", () => {
    expect(OidcDiscoverySchema.parse({ authorization_endpoint: "https://id.example/authorize", token_endpoint: "https://id.example/token" })).toBeTruthy();
    expect(OidcTokenResponseSchema.safeParse({ access_token: "" }).success).toBe(false);
  });
});
