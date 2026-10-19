import { createContext, useContext, useLayoutEffect, useRef, useSyncExternalStore, type PropsWithChildren } from "react";
import type { FormEvent } from "react";

export interface CopilotRouteRuntime {
  isAdministrator: boolean;
  role: string;
  projectCount: number;
  alertDocumentCount: number;
  userCount: number;
  platformReady: boolean;
  openWorkspace: (workspace: "project" | "alerts" | "users") => void;
  openIncidentMetadata: () => void;
  refresh: () => void;
}
export interface ClosedIncidentRow { incident_id?: string | number; ticket_id?: string; jira_link?: string; jira_status?: string; jira_key?: string; jira_url?: string; service?: string; severity?: string; risk_tier?: string; execution_mode?: string; status?: string; closed_at?: string; updated_at?: string; }
export interface ClosedRouteRuntime { hasMore?: boolean; loadMore?: () => void; rows: ClosedIncidentRow[]; risk: string; mode: string; riskOptions: string[]; modeOptions: string[]; loading: boolean; error: string; refresh: () => void; setRisk: (value: string) => void; setMode: (value: string) => void; }
export interface WorkflowEventRow { sequence?: string | number; agent?: string; action?: string; decision?: string; output?: string; communicates_to?: string; }
export interface GatewayEventRow { id?: string | number; created_at?: string; path?: string; status_code?: string | number; safety?: { decision?: string }; trace_id?: string; }
export interface AgentFlowRouteRuntime { workflowRows: WorkflowEventRow[]; gatewayRows: GatewayEventRow[]; gatewayLoading: boolean; gatewayError: string; workflowResult: unknown; }
export interface SafetySummary { total_events?: number; allowed?: number; review?: number; blocked?: number; latest_trace_id?: string; }
export interface SafetyEventRow extends GatewayEventRow { latency_ms?: number; safety?: { decision?: string; score?: number; reasons?: string[] }; }
export interface LandingPadRow { file?: string; received_at?: string; modified_at?: string; name?: string; alertname?: string; service?: string; severity?: string; alert_status?: string; }
export interface SafetyRouteRuntime { summary: SafetySummary; summaryError: string; events: SafetyEventRow[]; landingRows: LandingPadRow[]; landingError: string; refresh: () => void; }
export interface BusActivityRow { service?: string; consumed?: string; published?: string; provider?: string; status?: string; }
export interface BusTopologyRow { service?: string; consumes?: string; publishes?: string; }
export interface ModelProviderRow { name: string; configured: boolean; healthy: boolean; model: string; circuitOpen: boolean; failures: number; reason: string; }
export interface KnowledgeRouteRuntime { actual: { rows: BusActivityRow[]; published: string[]; consumed: string[] }; configuredRows: BusTopologyRow[]; routing: { workflow?: string; next_action?: string } | null; primaryTopic: string; application: string; providers: ModelProviderRow[]; providersLoading: boolean; providersError: string; refresh: () => void; refreshProviders: () => void; }
export interface IncidentRow { analysis_summary?: { rca_status?: string; outcome?: string; completed_at?: string; blockers?: string[]; missing_evidence?: string[] }; id?: string | number; incident_id?: string | number; alert_id?: string | number; ticket_id?: string; jira_key?: string; jira_url?: string; jira_status?: string; jira_assignee?: string; jira_priority?: string; approval_status?: string; approved_by?: string; approval_comment?: string; recommendation_id?: string; latest_event_type?: string; latest_event_at?: string; trace_id?: string; title?: string; summary?: string; severity?: string; service?: string; environment?: string; source?: string; origin_system?: string; ingestion_channel?: string; fingerprint?: string; correlation_id?: string; deduplicated_count?: number; deduplication_reason?: string; customer_impact?: string; business_impact?: string; root_cause?: string; confidence?: number; risk_tier?: string; execution_mode?: string; requires_approval?: boolean; transport_provider?: string; status?: string; status_source?: string; status_reason?: string; updated_at?: string; created_at?: string; orchestration_path?: Record<string, any>; resolution_lifecycle?: Record<string, any>; projection_payload?: Record<string, unknown>; source_alert?: Record<string, any>; context?: Record<string, any>; context_snapshot?: Record<string, any>; recommendation?: Record<string, any>; }
export interface IncidentFilters { risk_tier: string; execution_mode: string; transport_provider: string; status: string; service: string; }
export interface IncidentPageMetadata { next_cursor: string | null; previous_cursor: string | null; total_count: number; filtered_count: number; active_count: number; needs_attention_count: number; unlinked_signal_count: number; generated_at?: string; snapshot_at?: string; }
export interface IncidentsRouteRuntime { rows: IncidentRow[]; page: IncidentPageMetadata; loading: boolean; error: string; application: string; filters: IncidentFilters; refresh: () => void; loadPage: (cursor?: string) => void; updateFilter: (name: keyof IncidentFilters, value: string) => void; open: (row: IncidentRow, stage?: string) => void; openTechnical: (row: IncidentRow, stage?: string) => void; }
export interface AlertStreamRow { id?: string | number; ticket_id?: string; jira_key?: string; jira_url?: string; file?: string; source_channel?: string; status?: string; error?: string; name?: string; alert_name?: string; description?: string; labels?: { alertname?: string; alert_fingerprint?: string; fingerprint?: string; service?: string; job?: string; severity?: string; application?: string; project_name?: string; project?: string; ticket_id?: string; jira_issue_key?: string }; annotations?: { description?: string }; received_at?: string; created_at?: string; modified_at?: string; first_seen?: string; starts_at?: string; last_seen?: string; ends_at?: string; updated_at?: string; service?: string; application?: string; project_name?: string; project?: string; severity?: string; occurrence_count?: number; occurrences?: unknown[]; assignee?: string; owner?: string; jira_assignee?: string; deduplication_reason?: string; correlation_reason?: string; suppression_reason?: string; maintenance_window?: string; }
export interface AlertStreamRow { alert_id?: string | number; incident_id?: string | number; incident_projection?: IncidentRow; jira_key?: string; jira_url?: string; trace_id?: string; incident_disposition?: string; source?: string; origin_system?: string; ingestion_channel?: string; deduplicated_count?: number; summary?: unknown; message?: unknown; title?: unknown; component?: unknown; priority?: unknown; alert_status?: unknown; }
export interface IncidentRow {
  // Compact responses retain the affected operation for otherwise identical titles.
  operation?: string;
  incident_disposition?: string;
  canonical_incident_id?: string;
  correlation_family_id?: string;
  correlation_generation?: number;
  generation?: number;
  canonical_status?: string;
  active_occurrence_count?: number;
  total_occurrence_count?: number;
  terminal_history_count?: number;
  attention_state?: string;
  latest_occurrences?: Array<Record<string, unknown>>;
  project_id?: string;
}
export interface AlertStreamFilters { timeRange: string; severity: string; application: string; environment: string; }
export interface AlertsRouteRuntime { loading: boolean; error: string; paused: boolean; liveState: string; lastEventAt: string; rows: AlertStreamRow[]; inboxRows: AlertStreamRow[]; totalRows: number; project: string; updatedAt: string; section: string; view: string; savedViews: { id: string; label: string }[]; filters: AlertStreamFilters; filterOptions: { applications: string[]; environments: string[] }; density: string; counts: Record<string, number>; channel: string; query: string; refresh: () => void; open: (row: AlertStreamRow, stage?: string) => void; openIncident: (row: AlertStreamRow) => void; togglePaused: () => void; setSection: (value: string) => void; setView: (value: string) => void; applyView: (value: string) => void; updateFilter: (name: keyof AlertStreamFilters, value: string) => void; setDensity: (value: string) => void; setChannel: (value: string) => void; setQuery: (value: string) => void; }
export interface ChartItem { label: string; value: number; displayValue?: string; tone?: string; }
export interface WorkflowStage { id: string; label: string; status: string; detail?: string; }
export interface ServiceFlowRow { service: string; consumes: string; publishes: string; agent: string; }
export interface FinopsProviderRow { provider?: string; calls?: number; total_tokens?: number; total_cost_usd?: number; }
export interface ExecutiveClosedRow extends IncidentRow { risk?: string; severity?: string; closed_at?: string; updated_at?: string; }
export interface ExecutiveRouteRuntime { statCards: { label: string; value: string | number }[]; requestChart: ChartItem[]; successRequests: number; failedRequests: number; latencyChart: ChartItem[]; latencySubtitle: string; finopsChart: ChartItem[]; riskChart: ChartItem[]; modeChart: ChartItem[]; weeklyOpenChart: ChartItem[]; weeklyClosedChart: ChartItem[]; workflowStages: WorkflowStage[]; serviceFlow: ServiceFlowRow[]; finopsRows: FinopsProviderRow[]; slaAtRisk: number; approvalWaitMinutes: number; automationRate: number; incidents: IncidentRow[]; recentlyClosed: ExecutiveClosedRow[]; application: string; openIncident: (row: IncidentRow) => void; }
export interface GuidanceRow { path?: string; title?: string; id?: string; kind?: string; document_kind?: string; score?: number; }
export interface ApprovalRow extends IncidentRow { alert_id?: string; recommendation_id?: string; recommendation?: { id?: string }; remediation_recommendation_id?: string; recommended_action_id?: string; severity?: string; risk_tier?: string; }
export interface ApprovalForm { action: string; incident_id: string; recommendation_id: string; approver: string; channel: string; comment: string; modified_action: string; }
export interface ApprovalsRouteRuntime { guidanceQuery: string; guidanceRows: GuidanceRow[]; guidanceLoading: boolean; guidanceError: string; filter: string; rows: ApprovalRow[]; selectedIncidentId: string; selectedRecommendationId: string; selectedFlowContext: string; latestIncidentId: string; contextLoading: boolean; contextError: string; contextPayload: unknown; showAdvanced: boolean; form: ApprovalForm; ready: boolean; actionLoading: boolean; actionError: string; actionResult: unknown; inlineReject: { incidentId: string; comment: string }; setGuidanceQuery: (value: string) => void; searchGuidance: () => void; setFilter: (value: string) => void; incidentId: (row: ApprovalRow) => string; recommendationId: (row: ApprovalRow) => string; select: (row: ApprovalRow) => void; open: (row: ApprovalRow) => void; approve: (row: ApprovalRow) => void; approveDryRun: (row: ApprovalRow) => void; approveExecution: (row: ApprovalRow) => void; requestEvidence: (row: ApprovalRow, reason: string) => void; toggleReject: (incidentId: string) => void; setRejectComment: (incidentId: string, comment: string) => void; reject: (row: ApprovalRow) => void; refresh: () => void; openIncidents: () => void; openAgentFlow: () => void; sync: () => void; toggleAdvanced: () => void; updateForm: (name: keyof ApprovalForm, value: string) => void; submit: (event: FormEvent<HTMLFormElement>) => void; }
export interface AdminRole { id: number; name: string; }
export interface AdminUser { id?: number; username?: string; email?: string; first_name?: string; last_name?: string; role_id?: number; role_name?: string; status?: string; is_active?: boolean; }
export interface AdminUserForm { username: string; email: string; first_name: string; last_name: string; password?: string; role_id: number; status: string; is_active: boolean; id?: number; }
export interface AdminRouteRuntime { sessionUser: { username?: string; role_name?: string } | null; sessionError: string; authenticated: boolean; users: AdminUser[]; roles: AdminRole[]; loading: boolean; error: string; createForm: AdminUserForm; editForm: AdminUserForm; resetUserId?: number; resetPassword: string; refresh: () => void; selectUser: (user: AdminUser) => void; updateCreate: (name: keyof AdminUserForm, value: string | number | boolean) => void; updateEdit: (name: keyof AdminUserForm, value: string | number | boolean) => void; setResetPassword: (value: string) => void; create: (event: FormEvent<HTMLFormElement>) => void; update: (event: FormEvent<HTMLFormElement>) => void; reset: (event: FormEvent<HTMLFormElement>) => void; }
export interface SessionRouteRuntime { accessToken: string; username: string; }
export interface DashboardCard { label: string; value: string | number; detail: string; tone: string; tab: string; }
export interface DashboardProject { name?: string; namespace?: string; metrics_endpoint?: string; status?: string; }
export interface DashboardRuntime { processing?: { evidence_collection?: { status: string; scheduled?: number; retry?: number; collecting?: number }; status?: string; analysis_backlog_ready?: number | null; alert_processing?: { status: string; limit: number; active: number | null; waiting?: number } }; role: { kind: string; title: string; description: string; period: string; timezone: string; partial: boolean; refreshing: boolean; cards: DashboardCard[] }; allowedTabs: string[]; projects: DashboardProject[]; observedProjects: string[]; selectedProject: string; workflow: { cards: { id: string; label: string; status: string; detail: string }[]; nextAction: string }; openSection: (tab: string) => void; refreshProjects: () => void; selectProject: (name: string) => void; }
export interface RouteRuntime { session: SessionRouteRuntime; dashboard: DashboardRuntime; copilot: CopilotRouteRuntime; closed: ClosedRouteRuntime; agentFlow: AgentFlowRouteRuntime; safety: SafetyRouteRuntime; knowledge: KnowledgeRouteRuntime; incidents: IncidentsRouteRuntime; alerts: AlertsRouteRuntime; executive: ExecutiveRouteRuntime; approvals: ApprovalsRouteRuntime; admin: AdminRouteRuntime; }

type RuntimeListener = () => void;
type RuntimeStore = {
  current: RouteRuntime;
  listeners: Set<RuntimeListener>;
  subscribe: (listener: RuntimeListener) => () => void;
  emit: () => void;
};

function sameRuntimeSlice(previous: unknown, next: unknown): boolean {
  if (Object.is(previous, next)) return true;
  if (!previous || !next || typeof previous !== "object" || typeof next !== "object") return false;
  const left = previous as Record<string, unknown>;
  const right = next as Record<string, unknown>;
  const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
  for (const key of keys) {
    if (typeof left[key] === "function" && typeof right[key] === "function") continue;
    if (!Object.is(left[key], right[key])) return false;
  }
  return true;
}

const RouteRuntimeContext = createContext<RuntimeStore | null>(null);

export function RouteRuntimeProvider({ value, children }: PropsWithChildren<{ value: RouteRuntime }>) {
  const storeRef = useRef<RuntimeStore | null>(null);
  const changedRef = useRef(false);
  if (!storeRef.current) {
    const listeners = new Set<RuntimeListener>();
    storeRef.current = {
      current: value,
      listeners,
      subscribe: (listener) => { listeners.add(listener); return () => listeners.delete(listener); },
      emit: () => listeners.forEach((listener) => listener()),
    };
  } else {
    const previous = storeRef.current.current;
    let reconciled = previous;
    (Object.keys(value) as Array<keyof RouteRuntime>).forEach((key) => {
      const nextSlice = value[key];
      const previousSlice = previous[key];
      if (sameRuntimeSlice(previousSlice, nextSlice)) {
        Object.assign(previousSlice as object, nextSlice as object);
      } else {
        if (reconciled === previous) reconciled = { ...previous };
        (reconciled as unknown as Record<string, unknown>)[key] = nextSlice;
      }
    });
    changedRef.current = changedRef.current || reconciled !== previous;
    storeRef.current.current = reconciled;
  }
  // App.jsx still owns substantial legacy state and therefore renders often.
  // Notify route subscribers only when a public runtime slice actually changed;
  // waking every route after every parent render caused avoidable CPU usage and
  // visible table/header flicker during background refreshes.
  useLayoutEffect(() => {
    if (!changedRef.current) return;
    changedRef.current = false;
    storeRef.current?.emit();
  });
  return <RouteRuntimeContext.Provider value={storeRef.current}>{children}</RouteRuntimeContext.Provider>;
}

function useRuntimeStore(): RuntimeStore {
  const store = useContext(RouteRuntimeContext);
  if (!store) throw new Error("Route runtime is unavailable outside the authenticated application shell.");
  return store;
}

export function useRouteRuntime(): RouteRuntime {
  const store = useRuntimeStore();
  return useSyncExternalStore(store.subscribe, () => store.current, () => store.current);
}

export function useRouteRuntimeSlice<K extends keyof RouteRuntime>(key: K): RouteRuntime[K] {
  const store = useRuntimeStore();
  return useSyncExternalStore(store.subscribe, () => store.current[key], () => store.current[key]);
}
