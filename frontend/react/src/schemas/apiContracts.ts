import { z, type ZodTypeAny } from "zod";

import { ApiValidationError } from "../services/apiClient";

const JsonRecord = z.record(z.unknown());
const RecordList = z.array(JsonRecord);
const Identifier = z.union([z.string(), z.number()]);

const User = z.object({
  id: Identifier.optional(),
  username: z.string(),
  role_name: z.string().optional(),
  role: z.union([z.string(), JsonRecord]).optional(),
}).passthrough();

const AuthConfig = z.object({ mode: z.enum(["local", "oidc"]) }).passthrough();
const Login = z.object({ access_token: z.string().min(1), user: User }).passthrough();
const AuthenticatedUser = z.union([User, z.object({ user: User }).passthrough()]);
const Refresh = z.object({ access_token: z.string().min(1) }).passthrough();
const Health = z.object({ status: z.string().min(1) }).passthrough();
const QueueHealth = z.object({
  status: z.string().min(1),
  provider: z.string().min(1),
  healthy: z.boolean(),
  queues: z.number().nonnegative(),
  messages: z.number().nonnegative(),
  ready: z.number().nonnegative(),
  unacknowledged: z.number().nonnegative(),
}).passthrough();
const OperationsQueues = z.object({
  provider: z.string().min(1),
  queues: RecordList,
  summary: JsonRecord,
}).passthrough();
const ModelProviderStatus = z.object({
  providers: z.record(z.object({
    configured: z.boolean(), healthy: z.boolean(), model: z.string().min(1),
    circuit_open: z.boolean(), failure_count: z.number().int().nonnegative(),
    reason: z.string().nullable().optional(),
  }).passthrough()),
  selected: JsonRecord,
  prompt_cache: JsonRecord,
}).passthrough();
const GatewayModelProviderStatus = z.union([
  z.object({ data: ModelProviderStatus }).passthrough().transform((payload) => payload.data),
  ModelProviderStatus,
]);
const EvaluationFeedback = z.object({ updated: z.boolean() }).passthrough();
const CollectedContext = z.object({
  incident_id: z.string().uuid(),
  alert: z.object({
    id: z.string().uuid().optional(),
    name: z.string().min(1),
    service: z.string().min(1),
  }).passthrough(),
  related_incidents: z.array(JsonRecord).optional(),
  runbook: z.string().optional(),
  dependency_services: z.array(z.string()).optional(),
  recent_changes: z.array(JsonRecord).optional(),
}).passthrough();
const ResolutionRecommendation = z.object({
  incident_id: z.string().uuid(),
  root_cause: z.string(),
  confidence: z.number().min(0).max(1),
  impact: z.string(),
  recommended_action: z.string(),
  severity: z.string().min(1),
  rationale: z.string(),
  commands: z.array(z.string()).optional(),
  risk: z.string().optional(),
}).passthrough();
const ObjectResponse = z.object({}).passthrough();
const GatewayCollectedContext = z.object({ data: CollectedContext }).passthrough();
const GatewayResolutionRecommendation = z.object({ data: ResolutionRecommendation }).passthrough();
const GatewayObjectResponse = z.object({ data: ObjectResponse }).passthrough();
const KnowledgeDevelopmentResponse = z.union([
  z.object({ data: ObjectResponse }).passthrough().transform((payload) => payload.data),
  ObjectResponse,
]);
const AnalysisRegenerationAccepted = z.object({
  request_id: z.string().uuid(),
  status: z.literal("accepted"),
  delivery: z.enum(["published", "queued"]),
  alert_id: z.string().uuid(),
  incident_id: z.string().uuid(),
  previous_recommendation_id: z.string().nullable().optional(),
  expected_recommendation_id: z.string().uuid(),
  analysis_mode: z.enum(["smart", "fresh", "cache"]),
  context_strategy: z.enum(["auto", "realtime", "historical"]),
  poll_after_ms: z.number().int().positive(),
}).passthrough();
const AnalysisRegenerationStatus = z.object({
  request_id: z.string().uuid(),
  incident_id: z.string().uuid(),
  recommendation_id: z.string().uuid().nullable().optional(),
  status: z.enum(["running", "complete", "failed", "timed_out", "superseded"]),
  ready: z.boolean(),
  terminal: z.boolean().optional(),
  retryable: z.boolean().optional(),
  terminal_reason: z.string().nullable().optional(),
}).passthrough();
const ObjectOrList = z.union([ObjectResponse, RecordList]);
const RowsEnvelope = z.union([
  z.object({ rows: z.array(z.unknown()) }).passthrough(),
  z.object({ data: z.object({ rows: z.array(z.unknown()) }).passthrough() }).passthrough(),
  z.array(z.unknown()),
]);
const ContextEnrichmentActivity = z.object({
  schema_version: z.literal("kaiops.context-enrichment.v1"),
  requirements: RecordList,
  jobs: RecordList,
  human_requests: RecordList,
}).passthrough();
const GatewayContextEnrichmentActivity = z.union([
  ContextEnrichmentActivity,
  z.object({ data: ContextEnrichmentActivity }).passthrough().transform((payload) => payload.data),
]);
const InvestigationWorkspace = z.object({
  schema_version: z.literal("kaiops.investigation-workspace.v1"),
  binding: JsonRecord, impact: JsonRecord, rca: JsonRecord,
  evidence: RecordList, requirements: RecordList,
  resolution: JsonRecord, operator_review: JsonRecord,
}).passthrough();
const IncidentOperationsState = z.object({
  schema_version: z.literal("kaiops.operations-state.v1"),
  incident_id: z.string().uuid(), lifecycle_state: z.string().min(1),
  context: JsonRecord, investigation: JsonRecord,
  requirements: RecordList, requirement_history: RecordList,
  resolution: JsonRecord, approval: JsonRecord,
  execution: z.object({
    action_id: z.string().uuid().nullable(), status: z.string().min(1),
    action_type: z.string().nullable(), target: z.string().nullable(),
    recommendation_id: z.string().uuid().nullable(), plan_id: z.string().uuid().nullable(),
    plan_fingerprint: z.string().nullable(), approval_id: z.string().uuid().nullable(),
    updated_at: z.string().or(z.date()).nullable(),
  }).optional(),
  validation: z.object({
    report_id: z.string().uuid().nullable(), status: z.string().min(1),
    closure_kind: z.string().nullable(), validation_checksum: z.string().nullable(),
    action_id: z.string().uuid().nullable(), health_restored: z.boolean(),
    alerts_cleared: z.boolean(), details: JsonRecord,
    pre_state_observations: RecordList.optional(), post_state_observations: RecordList.optional(),
    observation_window: JsonRecord.optional(), outcome_decision: JsonRecord.optional(),
    knowledge_draft: JsonRecord.nullable().optional(),
    updated_at: z.string().or(z.date()).nullable(),
  }).optional(),
  investigation_workspace: InvestigationWorkspace.optional(),
  updated_at: z.string().or(z.date()),
}).passthrough();
const GatewayIncidentOperationsState = z.union([
  IncidentOperationsState,
  z.object({ data: IncidentOperationsState }).passthrough().transform((payload) => payload.data),
]);
export const IncidentCommandWorkspaceSchema = z.object({
  schema_version: z.literal("kaiops.incident-command.v2"),
  incident_id: z.string().uuid(),
  revision: z.string().length(64),
  incident: JsonRecord,
  operations: IncidentOperationsState,
  evidence: z.object({
    latest_snapshot_id: z.string().nullable(),
    bound_snapshot_id: z.string().nullable(),
    binding_consistent: z.boolean(),
    counts: z.object({
      latest_context_records: z.number().int().nonnegative(),
      bound_snapshot_records: z.number().int().nonnegative(),
      rca_bound_records: z.number().int().nonnegative(),
      traceable_citations: z.number().int().nonnegative(),
      unresolved_bindings: z.number().int().nonnegative(),
      open_requirements: z.number().int().nonnegative(),
      pending_requirements: z.number().int().nonnegative(),
      exhausted_requirements: z.number().int().nonnegative(),
      open_conflicts: z.number().int().nonnegative(),
    }).strict(),
    // True once every declared evidence gap has either been satisfied or has
    // exhausted automated + human collection (dead-lettered / no authorized
    // responder) - i.e. nothing is still actively in flight. Lets the UI offer
    // an operator-reviewable recommendation instead of an indefinite block when
    // a service structurally can't produce richer evidence. Never affects
    // auto-execution eligibility.
    evidence_collection_exhausted: z.boolean(),
    scores: z.array(z.object({
      key: z.enum(["context_quality", "grounding_coverage", "rca_readiness"]),
      label: z.string().min(1), percent: z.number().int().min(0).max(100).nullable(),
      status: z.enum(["available", "blocked", "unavailable"]),
      ratio: z.object({
        numerator: z.number().int().nonnegative(), denominator: z.number().int().nonnegative(),
        percent: z.number().int().min(0).max(100).nullable(),
      }).strict().nullable(),
      reason: z.string().min(1), blockers: z.array(z.string()),
    }).strict()),
    blockers: z.array(z.string()),
  }).strict(),
}).strict();
const GatewayIncidentCommandWorkspace = z.union([
  IncidentCommandWorkspaceSchema,
  z.object({ data: IncidentCommandWorkspaceSchema }).passthrough().transform((payload) => payload.data),
]);

type Contract = { method?: string; path: RegExp; schema: ZodTypeAny; name: string };

const contracts: readonly Contract[] = [
  { method: "GET", path: /^\/api-gateway\/auth\/config$/, schema: AuthConfig, name: "auth-config" },
  { method: "GET", path: /^\/api-gateway\/auth\/me$/, schema: AuthenticatedUser, name: "authenticated-user" },
  { method: "POST", path: /^\/api-gateway\/auth\/login$/, schema: Login, name: "login" },
  { method: "POST", path: /^\/api-gateway\/auth\/refresh$/, schema: Refresh, name: "token-refresh" },
  { path: /^\/api-gateway\/auth\/logout$/, schema: ObjectResponse, name: "logout" },
  { method: "GET", path: /^\/api-gateway\/healthz$/, schema: Health, name: "health" },
  { method: "GET", path: /^\/api-gateway\/operations\/queue-health$/, schema: QueueHealth, name: "queue-health" },
  { method: "GET", path: /^\/api-gateway\/operations\/queues$/, schema: OperationsQueues, name: "operations-queues" },
  { method: "GET", path: /^\/api-gateway\/model\/providers\/status$/, schema: GatewayModelProviderStatus, name: "model-provider-status" },
  { method: "GET", path: /^\/api-gateway\/incidents\/[0-9a-f-]+\/context-gaps$/i, schema: GatewayContextEnrichmentActivity, name: "context-enrichment-activity" },
  { method: "GET", path: /^\/api-gateway\/incidents\/[0-9a-f-]+\/operations-state$/i, schema: GatewayIncidentOperationsState, name: "incident-operations-state" },
  { method: "GET", path: /^\/api-gateway\/incidents\/[0-9a-f-]+\/command$/i, schema: GatewayIncidentCommandWorkspace, name: "incident-command-workspace" },
  { method: "POST", path: /^\/api-gateway\/evaluations\/by-recommendation\/[0-9a-f-]+\/feedback$/i, schema: EvaluationFeedback, name: "evaluation-feedback" },
  { method: "POST", path: /^\/context-agent\/collect$/, schema: CollectedContext, name: "collected-context" },
  { method: "POST", path: /^\/resolution-agent\/resolve$/, schema: ResolutionRecommendation, name: "resolution-recommendation" },
  { method: "POST", path: /^\/api-gateway\/analysis\/alerts\/[0-9a-f-]+\/regenerate$/i, schema: AnalysisRegenerationAccepted, name: "analysis-regeneration-accepted" },
  { method: "GET", path: /^\/api-gateway\/analysis\/requests\/[0-9a-f-]+\/status$/i, schema: AnalysisRegenerationStatus, name: "analysis-regeneration-status" },
  { method: "POST", path: /^\/api-gateway\/analysis\/context\/collect$/, schema: GatewayCollectedContext, name: "gateway-collected-context" },
  { method: "POST", path: /^\/api-gateway\/analysis\/resolution\/resolve$/, schema: GatewayResolutionRecommendation, name: "gateway-resolution-recommendation" },
  { method: "POST", path: /^\/api-gateway\/analysis\/resolution-catalog\/(?:relevant|select)$/, schema: GatewayObjectResponse, name: "gateway-resolution-catalog" },
  { path: /^\/api-gateway\/knowledge-development(?:\/|$)/, schema: KnowledgeDevelopmentResponse, name: "knowledge-development" },
  { path: /^\/(?:api-gateway|monitoring-adapter)\/alerts(?:\/|$)/, schema: ObjectOrList, name: "alerts" },
  { path: /^\/api-gateway\/landing-pad(?:\/|$)/, schema: RowsEnvelope, name: "landing-pad" },
  { path: /^\/api-gateway\/incidents(?:\/|$)/, schema: ObjectOrList, name: "incidents" },
  { path: /^\/api-gateway\/approval(?:\/|$)/, schema: ObjectResponse, name: "approvals" },
  { path: /^\/api-gateway\/remediation(?:\/|$)/, schema: ObjectResponse, name: "remediation" },
  { path: /^\/api-gateway\/applications(?:\/|$)/, schema: ObjectOrList, name: "applications" },
  { path: /^\/api-gateway\/rag(?:\/|$)/, schema: ObjectOrList, name: "knowledge" },
  { path: /^\/api-gateway\/knowledge-pack(?:\/|$)/, schema: ObjectResponse, name: "knowledge-pack" },
  { path: /^\/api-gateway\/onboarding(?:\/|$)/, schema: ObjectOrList, name: "onboarding" },
  { path: /^\/api-gateway\/observability(?:\/|$)/, schema: ObjectOrList, name: "observability" },
  { path: /^\/api-gateway\/sample(?:\/|$)/, schema: ObjectOrList, name: "samples" },
  { path: /^\/api-gateway\/model(?:\/|$)/, schema: ObjectResponse, name: "model-routing" },
  { path: /^\/api-gateway\/users(?:\/|$)/, schema: ObjectOrList, name: "users" },
  { path: /^\/api-gateway\/roles(?:\/|$)/, schema: ObjectOrList, name: "roles" },
];

function normalizedPath(endpoint: string): string {
  return endpoint.split("?", 1)[0];
}

export function parseInternalApiResponse(endpoint: string, method: string, payload: unknown): unknown {
  const path = normalizedPath(endpoint);
  const normalizedMethod = method.toUpperCase();
  const contract = contracts.find((candidate) => (!candidate.method || candidate.method === normalizedMethod) && candidate.path.test(path));
  if (!contract) {
    throw new ApiValidationError(path, 1, `No Zod contract is registered for ${normalizedMethod} ${path}.`);
  }
  const parsed = contract.schema.safeParse(payload);
  if (!parsed.success) {
    throw new ApiValidationError(path, parsed.error.issues.length, `${contract.name} response failed validation.`);
  }
  return parsed.data;
}

export const internalApiContractCount = contracts.length;
