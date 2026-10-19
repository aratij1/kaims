import { hasPendingDecision } from "./domain/pendingDecision";
import { visibleManagedApplication } from "./app/visibleManagedApplication";
import { availableApplication } from "./domain/applicationSelection";
import { memo, useEffect, useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Archive, BookOpen, Bot, Boxes, ChartNoAxesCombined, CircleCheckBig, ClipboardCheck, Cloud, Database, Gauge, PlugZap, RadioTower, ScrollText, Server, Settings, ShieldCheck, Siren, Workflow } from "lucide-react";
import { alertRowsQueryOptions, landingPadRowsQueryOptions } from "./services/alerts";
import { useOperationalEvents } from "./services/operationalEvents";
import { beginOidcLogin, clearStoredSession, completeOidcLogin, restoreStoredSession, storeSessionTokens } from "./services/oidcClient";
import { RouteRuntimeProvider } from "./app/routeRuntime";
import { projectIdentityFromAlert } from "./domain/projectIdentity";
import { canHydrateCompletedAnalysis } from "./domain/analysisVersion";
import { analysisFailureMessage, analysisRequestOutcome } from "./domain/analysisRequestStatus";
import { effectiveExecutionStatus, effectiveIncidentStatus, executionProcessPresentation, incidentStatusLabel } from "./domain/incidentStatus";
import { resolveResolutionControl } from "./domain/resolutionControl";
import { incidentDraftHasSubstantiveContent, simpleIncidentReport } from "./domain/incidentReport";
import { approvalFlowFromPayload, approvalFlowId, approvalIncidentId, approvalRecommendationFromPayload, approvalRecommendationId, approvalTraceId } from "./domain/approvalContext";
import { buildOnboardingSources } from "./domain/onboardingSources";
import { buildAlertDocumentDraft as buildRcaEvidenceDocumentDraft } from "./domain/alertDocumentDraft";
import { canonicalIncidentEvidence, draftEvidenceProvenance } from "./domain/incidentEvidence";
import { canonicalApprovalEligibility } from "./domain/approvalEligibility";
import { buildIncidentGroupQuery } from "./features/incidents/incidentGroupQuery";
import { isEvidenceDraftConflict, useEvidenceDraftBundle } from "./features/incidents/useEvidenceDraftBundle";
import RcaPanel from "./routes/incidents/RcaPanel";
import ResolutionPanel from "./routes/incidents/ResolutionPanel";
import VerifyWorkspace from "./routes/incidents/VerifyWorkspace";
import "./routes/incidents/ExecutionWorkspace.css";
import "./routes/incidents/AnalysisModeSelector.css";
import "./styles/product-ui.css";
import "./styles/product-foundation.css";
import "./styles/legacy-operations.css";
import CopilotRoute from "./routes/copilot/CopilotRoute";
import { breadcrumbForPath, groupedNavigationForRole, navigationItemForPath, TAB_SHORTCUT_BY_CODE, VALID_LEGACY_TABS } from "./app/navigation";
import { allowedLegacyTabsForRole, canAccessDestination } from "./app/permissions";
import { KAI_BRAND } from "./config/brand";
import KaiCommandPalette from "./app/KaiCommandPalette";
import { KaiOperationsShell } from "./components/shell/KaiOperationsShell";
const LOCAL_JENKINS_ENDPOINT = "http://jenkins:8080", LOCAL_JENKINS_JOB = "kaiops-auto-remediation", LOCAL_JENKINS_CREDENTIAL_REF = "vault://kaiops/local/jenkins#api-token";
import { ALERT_DOC_KIND_OPTIONS, DOCUMENT_PROVIDER_ROLES, ONBOARDING_SOURCE_DOC_EXTENSIONS, ONBOARDING_SOURCE_DOC_SAMPLE_FILES } from "./onboardingConfig";
import { classifyOnboardingDocumentType, deriveMonitoringRequirementsFromDocument, extractMonitoringToolAndUrl, extractOnboardingProjectName, looksLikeUuid, normalizeRoleName, severityOverrideKey, simplifyMonitoringUrl, summarizeUploadedDocument } from "./onboardingUtils";
import {
  DEFAULT_ALERT,
  REAL_USE_CASE_SCOPE,
  TEST_USE_CASE_SCOPE,
  CORE_MONITOR_PROJECTS,
  SERVICE_TOPIC_FLOW,
  SCALE_CAPACITY_GUIDE,
  PREFERENCE_STORAGE_KEY,
  UI_THEME_VALUES,
  extractObservedRoutingMetrics,
  cleanRecommendationText,
  filterAlertsForMonitor,
  filterRowsForMonitor,
  isGeneratedOrTestAlert,
  normalizeAlertChannel,
  sourceChannelLabel,
  ALERT_SOURCE_CHANNELS,
  MAX_LATEST_ALERTS_PER_SOURCE,
  capLatestAlertsPerSource,
  ensureMinimumAlertsBySource,
  monitorScopeLabel,
  alertTimeMs,
  resolveCanonicalAlertForRow,
  dedupeAndConsolidateAlertRows,
  shouldRetainAlertSelection,
  ALERT_UUID_PATTERN,
  mapLandingPadRowToAlertStreamRow,
  mergeAlertStreamRows,
  onboardingSourceDocCategoryLabel,
  fetchJson,
  asDisplayValue,
  parseUtcTimestamp,
  formatIstTimestamp,
  formatUtcTimestamp,
  formatQualityPercent,
  normalizeEvaluationEnvelope,
  elapsedSeconds,
  normalizeTraceServiceName,
  routeForAgent,
  displayAgentName,
  compactText,
  hasMeaningfulValue,
  stringifyTimelineValue,
  normalizeApprovalStatus,
  canonicalIncidentStatus,
  isApprovalResolvedStatus,
  isApprovalPendingStatus,
  statusPillClass,
  extractEventError,
  extractEventInput,
  extractEventOutput,
  deriveExecutionCommands,
  remediationOutcomeFromAction,
  buildKaiOpsRemediationScript,
  buildSyntheticFlowRows,
  summarizeEventType,
  timelinePhaseOrder,
  buildAlertDocumentDrafts,
  toFiniteNumber,
  percentile,
  normalizeUsageRow,
  isMeaningfulUsageRow,
  dedupeUsageRows,
  explainOnboardingStepBackground,
  findHistoricalTicketDiscoveryDocument,
  HistoricalTicketDiscoveryPanel,
  FlowTimelineGraph,
  UnifiedIncidentTimeline,
  canonicalIncidentAnalysis,
  ContextRetrievalGraph,
  AgentEventsGraph,
  ApplicationSankeyFlow,
  ProcessingFlowMap,
  MessageBusTopology,
  ExecutionPlanGraph,
  normalizeGeneratedRuleRows,
  cleanRuleIntentLine,
  buildPrometheusRulePreview,
  summarizeAlertRuleContext,
} from "./appHelpers.jsx";
import { buildWorkflowFlowStages } from "./domain/workflowStages";
import { INGESTION_SAVED_VIEWS, isTestApplicationRecord, readableImpactText, redactOperationalSecrets, uniqueMonitorApplications } from "./app/legacyShellHelpers";
const NAVIGATION_ICONS = {
  dashboard: Database,
  alerts: RadioTower,
  incidents: Siren,
  approvals: CircleCheckBig,
  copilot: Bot,
  agentFlow: Workflow,
  knowledge: BookOpen,
  safety: ShieldCheck,
  audit: ScrollText,
  closed: Archive,
  applications: Boxes,
  operationsCockpit: ChartNoAxesCombined,
  platformOverview: Workflow,
  cloudConnections: Cloud,
  cloudResources: Server,
  serviceOnboarding: ClipboardCheck,
  services: Gauge,
  integrations: PlugZap,
  admin: Settings,
  settings: Settings,
  executive: ChartNoAxesCombined,
};
// Estimate only -- rowVirtualizer.measureElement (attached to each <tr> ref
// below) measures the actual rendered height and self-corrects, so this
// doesn't need to be exact.
const ALERT_ROW_ESTIMATED_HEIGHT_PX = 44;

const AlertStreamTable = memo(function AlertStreamTable({ rows, loading, selectedAlertId, onSelectAlert, scopeLabel }) {
  const scrollRef = useRef(null);
  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ALERT_ROW_ESTIMATED_HEIGHT_PX,
    overscan: 10,
  });
  const virtualRows = rowVirtualizer.getVirtualItems();
  const paddingTop = virtualRows.length > 0 ? virtualRows[0].start : 0;
  const paddingBottom = virtualRows.length > 0 ? rowVirtualizer.getTotalSize() - virtualRows[virtualRows.length - 1].end : 0;

  return (
    <div
      className="table-wrap table-wrap-scroll-x alert-stream-wrap"
      tabIndex={0}
      role="region"
      aria-label="Alert stream table"
      ref={scrollRef}
    >
      <table className="alert-stream-table">
        <thead>
          <tr>
            <th>Alert ID</th>
            <th>Time (UTC)</th>
            <th className="alert-name-col">Name</th>
            <th>Rule</th>
            <th>Application</th>
            <th>Service</th>
            <th>Source</th>
            <th>Severity</th>
            <th>Tier</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {paddingTop > 0 ? (
            <tr aria-hidden="true" style={{ height: paddingTop }}>
              <td colSpan={11} style={{ padding: 0, border: 0 }} />
            </tr>
          ) : null}
          {virtualRows.map((virtualRow) => {
            const row = rows[virtualRow.index];
            const index = virtualRow.index;
            const rowId = String(row.alert_id || row.id || row.incident_id || index);
            const fullAlertId = String(row.alert_id || row.id || row.incident_id || "-");
            const compactAlertId = fullAlertId.length > 16 ? `${fullAlertId.slice(0, 8)}...${fullAlertId.slice(-6)}` : fullAlertId;
            const severity = String(row.severity || "-").toUpperCase();
            const supportTier = String(row.labels?.support_tier || "-");
            const status = String(row.status || row.state || "open");
            const application = row.application || row.project_name || row.project || row.service || "-";
            const sourceChannels = Array.isArray(row?.source_channels) && row.source_channels.length
              ? row.source_channels
              : [normalizeAlertChannel(row)];
            const alertRuleName = String(
              row.rule_name
              || row.rule
              || row.alert_rule
              || row.labels?.alertname
              || row.name
              || row.alert_name
              || "-"
            ).trim();
            const alertName = row.name || row.alert_name || "-";
            return (
              <tr
                key={rowId}
                data-index={index}
                ref={rowVirtualizer.measureElement}
                className={`alert-row ${selectedAlertId === rowId ? "row-selected" : ""}`}
                onClick={() => onSelectAlert(row)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelectAlert(row);
                  }
                }}
                tabIndex={0}
                role="button"
                aria-label={`Open alert ${rowId}`}
              >
                <td title={fullAlertId}>{compactAlertId}</td>
                <td>{formatUtcTimestamp(row.created_at || row.starts_at || row.closed_at)}</td>
                <td className="alert-name-col" title={alertName}>{alertName}</td>
                <td title={String(row.expression || row.expr || row.query || row.description || row.annotations?.description || "").trim()}>{alertRuleName}</td>
                <td>{application}</td>
                <td>{row.service || "-"}</td>
                <td>
                  <div className="alert-source-chips">
                    {sourceChannels.map((sourceChannel) => {
                      const sourceKey = String(sourceChannel || "").toLowerCase();
                      return (
                        <span key={`${rowId}-${sourceKey}`} className={`source-badge source-${sourceKey}`}>
                          {sourceChannelLabel(sourceKey)}
                        </span>
                      );
                    })}
                  </div>
                </td>
                <td><span className={`pill severity-${severity.toLowerCase()}`}>{severity}</span></td>
                <td><span className={`pill tier-${supportTier.toLowerCase().replace("/", "-")}`}>{supportTier}</span></td>
                <td><span className={`pill status-${status.toLowerCase()}`}>{status}</span></td>
                <td>
                  <button
                    type="button"
                    className="button-secondary"
                    onClick={(event) => {
                      event.stopPropagation();
                      onSelectAlert(row);
                    }}
                  >
                    Inspect
                  </button>
                </td>
              </tr>
            );
          })}
          {paddingBottom > 0 ? (
            <tr aria-hidden="true" style={{ height: paddingBottom }}>
              <td colSpan={11} style={{ padding: 0, border: 0 }} />
            </tr>
          ) : null}
          {!rows.length && !loading ? (
            <tr>
              <td colSpan={11}>No alerts match current filters for {scopeLabel}.</td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
});

/**
 * Temporary Phase 1 compatibility boundary. URL routing owns the requested
 * top-level tab while the existing application retains its in-memory session
 * and operational state. See docs/TECHNICAL_DEBT.md (TD-FE-001).
 *
 * @param {{ initialTab?: string, currentPath?: string, currentSearch?: string, onActiveTabChange?: (tabId: string) => void, onNavigatePath?: (path: string) => void, routeOutlet?: import("react").ReactNode }} props
 */
function KaiMSBrand({ compact = false, inverse = false, onActivate = null }) {
  const content = <>
    <span className="kaims-brand-mark" aria-hidden="true">
      <svg viewBox="0 0 48 48" role="img">
        <path className="kaims-mark-ms" d="M7 35V13l8 12 8-12v22M40 15c-3-3-11-3-14 1-4 7 16 6 14 14-1 6-11 7-16 2" />
        <path className="kaims-mark-signal" d="M6 39h8l3-4 4 6 4-4h17" />
      </svg>
    </span>
    <span className="kaims-brand-copy">
      <strong><span className="kaims-brand-prefix">Kai</span><span className="kaims-brand-managed">MS</span></strong>
      {!compact ? <small>{KAI_BRAND.category}</small> : null}
    </span>
  </>;
  return (
    onActivate
      ? <button type="button" className={`kaims-brand kaims-brand-home ${compact ? "is-compact" : ""} ${inverse ? "is-inverse" : ""}`} aria-label="Go to KaiMS home" onClick={onActivate}>{content}</button>
      : <div className={`kaims-brand ${compact ? "is-compact" : ""} ${inverse ? "is-inverse" : ""}`} aria-label={`${KAI_BRAND.productName} ${KAI_BRAND.category}`}>{content}</div>
  );
}


export default function App({ initialTab = "home", currentPath = "/", currentSearch = "", onActiveTabChange, onNavigatePath, routeOutlet = null } = {}) {
  const queryClient = useQueryClient();
  const skipNextActiveTabNavigationRef = useRef(false);
  const skipInitialPreferencesPersistRef = useRef(true);
  const [applicationToMonitor, setApplicationToMonitor] = useState("KaiMS");
  const [monitorApplications, setMonitorApplications] = useState([]);
  const [activeTab, setActiveTab] = useState(() => (VALID_LEGACY_TABS.has(initialTab) ? initialTab : "home"));
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [uiDensity, setUiDensity] = useState("comfortable");
  const [uiTheme, setUiTheme] = useState("auto");
  const [health, setHealth] = useState({ loading: false, ok: false, message: "Not checked" });
  const [queueHealth, setQueueHealth] = useState({ loading: true, status: "checking", provider: "rabbitmq", healthy: false, queues: 0, messages: 0, ready: 0, unacknowledged: 0 });
  const [alerts, setAlerts] = useState({ loading: false, rows: [], error: "" });
  const [alertsLimit, setAlertsLimit] = useState(25);
  const [alertSeverityOverrides, setAlertSeverityOverrides] = useState({ loading: false, rows: [], error: "", savingKey: "" });
  const [alertSeverityDrafts, setAlertSeverityDrafts] = useState({});
  const [alertSeverityReasons, setAlertSeverityReasons] = useState({});
  const [dashboardAlertQuery, setDashboardAlertQuery] = useState("");
  const [globalOperationsView, setGlobalOperationsView] = useState("search");
  const [globalOperationsQuery, setGlobalOperationsQuery] = useState("");
  // Debounce the client-side alert filter so typing does not rescan every row.
  const [dashboardAlertQueryDebounced, setDashboardAlertQueryDebounced] = useState("");
  useEffect(() => {
    const handle = setTimeout(() => setDashboardAlertQueryDebounced(dashboardAlertQuery), 250);
    return () => clearTimeout(handle);
  }, [dashboardAlertQuery]);
  const [dashboardAlertFocus, setDashboardAlertFocus] = useState("all");
  const [dashboardAlertSource, setDashboardAlertSource] = useState("all");
  const [incidentMetadata, setIncidentMetadata] = useState({ loading: false, rows: [], error: "", page: {} });
  const [closedIncidents, setClosedIncidents] = useState({ loading: false, rows: [], error: "" });
  const [flows, setFlows] = useState({ loading: false, rows: [], error: "" });
  const [gatewaySummary, setGatewaySummary] = useState({ loading: false, data: {}, error: "" });
  const [gatewayRecent, setGatewayRecent] = useState({ loading: false, rows: [], error: "" });
  const [modelProviderStatus, setModelProviderStatus] = useState({ loading: false, data: null, error: "" });
  const [landingPadRecent, setLandingPadRecent] = useState({ loading: false, rows: [], error: "" });
  const [ingestionStreamChannel, setIngestionStreamChannel] = useState("all");
  const [ingestionStreamQuery, setIngestionStreamQuery] = useState("");
  const [ingestionStreamSection, setIngestionStreamSection] = useState("active");
  const [ingestionStreamPaused, setIngestionStreamPaused] = useState(false);
  const [ingestionStreamUpdatedAt, setIngestionStreamUpdatedAt] = useState("");
  const [ingestionStreamView, setIngestionStreamView] = useState("");
  const [ingestionStreamFilters, setIngestionStreamFilters] = useState({ timeRange: "all", severity: "all", application: "selected", environment: "all" });
  const [ragDocs, setRagDocs] = useState({ loading: false, rows: [], error: "" });
  const [guidanceQuery, setGuidanceQuery] = useState("");
  const [guidanceState, setGuidanceState] = useState({ loading: false, rows: [], error: "" });
  const [submitState, setSubmitState] = useState({ loading: false, result: null, error: "" });
  const [workflowState, setWorkflowState] = useState({ loading: false, result: null, error: "" });
  const [approvalState, setApprovalState] = useState({ loading: false, result: null, error: "" });
  const [inlineRejectState, setInlineRejectState] = useState({ incidentId: "", comment: "" });
  const [showAdvancedApprovalForm, setShowAdvancedApprovalForm] = useState(false);
  const [approvalFilter, setApprovalFilter] = useState("all");
  const [approvalIncidentContext, setApprovalIncidentContext] = useState({
    loading: false,
    incident_id: "",
    payload: null,
    error: "",
  });
  const [selectedAlertId, setSelectedAlertId] = useState("");
  const [selectedAlertSnapshot, setSelectedAlertSnapshot] = useState(null);
  // A landing-pad row opened before its canonical DB alert exists yet: keep
  // the raw row here so the cockpit stays on it while a background effect
  // retries resolveCanonicalAlertForRow against alerts.rows as it refreshes.
  const [pendingCanonicalAlert, setPendingCanonicalAlert] = useState(null);
  const pendingCanonicalAlertRetryRef = useRef({ key: "", attempts: 0 });
  const selectedAlertAnalysisPollRef = useRef({ alertId: "", attempts: 0 });
  const alertStreamRefreshInFlight = useRef(false);
  const landingPadStreamRefreshInFlight = useRef(false);
  const [selectedApprovalIncidentId, setSelectedApprovalIncidentId] = useState("");
  const [selectedAlertData, setSelectedAlertData] = useState({ loading: false, payload: null, error: "", alertId: "" });
  const [selectedAlertRegeneration, setSelectedAlertRegeneration] = useState({ loading: false, message: "", error: "" });
  const [selectedCatalogStatus, setSelectedCatalogStatus] = useState({ loading: false, incidentId: "", data: null, error: "" });
  const [rcaAnalysisMode, setRcaAnalysisMode] = useState("smart");
  const [aiFeedbackState, setAiFeedbackState] = useState({ loading: false, decision: "", message: "", error: "" });
  const [selectedAlertDocumentLinks, setSelectedAlertDocumentLinks] = useState({
    loading: false,
    alertId: "",
    rows: [],
    canonicalAlert: null,
    contract: null,
    error: "",
  });
  const [selectedStageCompleteness, setSelectedStageCompleteness] = useState({
    loading: false,
    data: null,
    error: "",
    incidentId: "",
  });
  const [homeDetailTab, setHomeDetailTab] = useState("evidence");
  const [rcaDetailView, setRcaDetailView] = useState("simple");
  const [diagnosticsDetailTab, setDiagnosticsDetailTab] = useState("pipeline");
  const [approvalForm, setApprovalForm] = useState({
    action: "approve",
    incident_id: "",
    recommendation_id: "",
    approver: "admin",
    channel: "web",
    comment: "",
    modified_action: "",
  });
  const [remediationPlanEditor, setRemediationPlanEditor] = useState({
    commands: "",
    scripts: "",
    queries: "",
    connection_url: "",
    connection_type: "application",
    executor_type: "",
    job_name: "",
    namespace: "",
    credential_ref: "",
    credential_store: "hashicorp_vault",
    notes: "",
  });
  const [evidenceDraftReview, setEvidenceDraftReview] = useState({ loading: false, draft: null, content: "", notes: "", error: "", message: "" });
  const [incidentReportView, setIncidentReportView] = useState("simple");
  const [executionOutcomeReview, setExecutionOutcomeReview] = useState({ outcome: "successful", notes: "", reusable: true, loading: false, error: "", message: "", reviewedAlertId: "" });
  const [showExecutionCredential, setShowExecutionCredential] = useState(false);
  const [remediationExecutionState, setRemediationExecutionState] = useState({ loading: false, result: null, error: "" });
  const [emergencyStopState, setEmergencyStopState] = useState({ reason: "", loading: false, error: "", message: "" });
  const [executionPreflightState, setExecutionPreflightState] = useState({ signature: "", checkedAt: "", passed: false });
  const [approvedExecutionSignature, setApprovedExecutionSignature] = useState("");
  const [approvedExecutionApprovalId, setApprovedExecutionApprovalId] = useState("");
  const [executionApprovalRequiresRenewal, setExecutionApprovalRequiresRenewal] = useState(false);
  const [executionConfirmationText, setExecutionConfirmationText] = useState("");
  const [selectedFlow, setSelectedFlow] = useState("payment-latency");
  const [metadataFilters, setMetadataFilters] = useState({
    risk_tier: "all",
    execution_mode: "all",
    transport_provider: "all",
    status: "all",
    service: "",
  });
  const [closedFilters, setClosedFilters] = useState({ risk: "all", mode: "all" });
  const [form, setForm] = useState(DEFAULT_ALERT);
  const [adminWorkspace, setAdminWorkspace] = useState("users");
  const [adminAuthForm, setAdminAuthForm] = useState({ username: "admin", password: "", device: "react-ui" });
  const [loginPasswordVisible, setLoginPasswordVisible] = useState(false);
  const [adminSession, setAdminSession] = useState({ loading: true, accessToken: "", refreshToken: "", user: null, error: "" });
  const [authConfig, setAuthConfig] = useState({ loading: true, mode: "local", local_development_only: true, issuer: null, client_id: null, audience: null, pkce_required: false, error: "" });
  const liveEvents = useOperationalEvents({
    accessToken: String(adminSession?.accessToken || ""),
    paused: ingestionStreamPaused,
    onEvent: (event) => {
      if (event.type === "alert.created" && activeTab === "home" && !selectedAlertId) {
        void loadRecentAlerts({ background: true });
      }
      if (event.type === "alert.created" && activeTab === "stream" && !ingestionStreamPaused) {
        // The server event is the freshness signal; never let the periodic
        // polling throttle suppress this event-driven refresh.
        void loadLandingPadRecent({ background: true, force: true });
      }
      if (["incident.status", "approval.state", "remediation.progress"].includes(event.type) && activeTab === "summary") {
        void loadIncidentMetadata({ background: true });
      }
    },
  });
  const adminSessionRef = useRef(adminSession);
  const adminRefreshPromiseRef = useRef(null);
  const [adminRoles, setAdminRoles] = useState([]);
  const [adminUsers, setAdminUsers] = useState({ loading: false, rows: [], error: "" });
  const [adminCreateUser, setAdminCreateUser] = useState({
    username: "",
    email: "",
    password: "",
    first_name: "",
    last_name: "",
    role_id: 1,
    status: "active",
    is_active: true,
  });
  const [adminEditUser, setAdminEditUser] = useState({
    id: null,
    username: "",
    email: "",
    first_name: "",
    last_name: "",
    role_id: 1,
    status: "active",
    is_active: true,
  });
  const [adminEditPanelOpen, setAdminEditPanelOpen] = useState(false);
  const [adminResetPasswordForm, setAdminResetPasswordForm] = useState({ user_id: null, new_password: "" });
  const [onboardingForm, setOnboardingForm] = useState({
    name: "kaiops-project",
    owner_team: "platform-ops",
    description: "",
    business_service: "",
    owner_email: "",
    criticality: "high",
    cost_center: "",
    repository_url: "",
    environment: "prod",
    region: "us-east-1",
    deployment_mode: "cloud_neutral",
    monitoring_tool: "prometheus",
    monitoring_url: "http://prometheus:9090",
    prometheus_url: "http://prometheus:9090",
    new_relic_url: "",
    datadog_url: "",
    logs_url: "",
    traces_url: "",
    telemetry_url: "",
    ticketing_url: "",
    email_url: "",
    healthcheck_url: "",
    network_zone: "",
    connection_auth_type: "none",
    connection_secret_store: "hashicorp_vault",
    connection_secret_ref: "",
    context_strategy: "auto",
    azure_subscription_id: "",
    azure_resource_group: "",
    azure_service_bus_namespace: "",
    azure_service_bus_topic: "kaiops-orchestration-events",
    azure_service_bus_subscription: "kaiops-orchestration-sub",
    azure_content_safety_enabled: false,
    azure_content_safety_endpoint: "",
    assignment_username: "",
    assignment_project: "",
    onboarding_path: "setup_monitoring",
    start_rule_onboarding: true,
    service_knowledge_prompt: "",
    rule_onboarding_plain_language: "",
  });
  const [onboardingState, setOnboardingState] = useState({ loading: false, connectivity: {}, rows: [], error: "", success: "" });
  const [onboardingRuleCapabilities, setOnboardingRuleCapabilities] = useState({ loading: false, rows: [], error: "" });
  const [onboardingRuleWizardStep, setOnboardingRuleWizardStep] = useState(1);
  const [onboardingRuleWizardMode, setOnboardingRuleWizardMode] = useState("existing");
  const [existingRulePipelineForm, setExistingRulePipelineForm] = useState({
    platform: "prometheus",
    mode: "bidirectional",
    connection_url: "",
    rules_json: JSON.stringify([
      {
        name: "project_cpu_high",
        metric: "cpu_usage_percent",
        threshold: 85,
        duration: "5m",
        aggregation: "avg",
        severity: "high",
        labels: { project: "kaiops-project" },
      },
    ], null, 2),
  });
  const [newRulePipelineForm, setNewRulePipelineForm] = useState({
    requirements_text: [
      "Alert if CPU stays above 80% for more than 5 minutes with high severity",
      "Alert when latency is over 2000 for 10 minutes critical",
    ].join("\n"),
    selected_tool: "prometheus",
  });
  const [onboardingProjectMode, setOnboardingProjectMode] = useState("existing");
  const [onboardingRuleRunState, setOnboardingRuleRunState] = useState({ loading: false, result: null, error: "" });
  const [onboardingWorkflowSteps, setOnboardingWorkflowSteps] = useState([]);
  const [onboardingLandingPadSummary, setOnboardingLandingPadSummary] = useState({});
  const [onboardingGeneratedDocs, setOnboardingGeneratedDocs] = useState([]);
  const [onboardingSourceDocs, setOnboardingSourceDocs] = useState({ loading: false, rows: [], error: "" });
  const [knowledgePackState, setKnowledgePackState] = useState({
    loading: false,
    draft: null,
    error: "",
    success: "",
    approved: false,
  });
  const [knowledgePackCorrections, setKnowledgePackCorrections] = useState({});
  // Backend re-validation results for manually corrected fields, keyed by fact key.
  // Populated by revalidateKnowledgeCorrections(); until a field has been re-validated
  // here, its correction is treated as unverified rather than auto-"accepted".
  const [knowledgePackRevalidation, setKnowledgePackRevalidation] = useState({ loading: false, error: "", facts: {}, validatedCorrections: {} });
  const [onboardingReviewAck, setOnboardingReviewAck] = useState({ rules: false, docs: false, metadata: false });
  const [onboardingDocApprovalState, setOnboardingDocApprovalState] = useState({
    loading: false,
    error: "",
    success: "",
    approved: false,
  });
  const [onboardingRuleLookup, setOnboardingRuleLookup] = useState({ workflow_id: "", loading: false, result: null, error: "" });
  const [selectedOnboardingProject, setSelectedOnboardingProject] = useState("");
  const [monitoringAppForm, setMonitoringAppForm] = useState({
    tenant_id: "default",
    name: "",
    owner_team: "platform-ops",
    owner_email: "",
    environment: "prod",
    namespace: "default",
    region: "us-east-1",
    technology: "python-fastapi",
    metrics_endpoint: "http://api-gateway:8000/metrics",
    labels_text: "security=internal,compliance=sox,workload_kind=Deployment",
  });
  const [monitoringApps, setMonitoringApps] = useState({ loading: false, rows: [], error: "" });
  const [monitoringAppSubmit, setMonitoringAppSubmit] = useState({ loading: false, error: "", success: "" });
  const [selectedMonitoringAppId, setSelectedMonitoringAppId] = useState("");
  const [monitoringAppDetails, setMonitoringAppDetails] = useState({ loading: false, history: [], validations: [], dashboards: [], error: "" });
  const [onboardingRuleEditor, setOnboardingRuleEditor] = useState({
    workflow_id: "",
    project_name: "",
    payload_json: "",
  });
  const [onboardingRuleEditorState, setOnboardingRuleEditorState] = useState({ loading: false, error: "", success: "" });
  const [alertOnboarding, setAlertOnboarding] = useState({
    kind: "incident",
    title: "New Alert Onboarding",
    summary: "",
    content: "Provide troubleshooting and escalation steps for this alert scenario.",
    services: "payments",
    severity: "high",
    alert_type: "availability",
    alert_id: "",
    execution_plan: "",
    remediation_commands_text: "",
    remediation_scripts_text: "",
    remediation_queries_text: "",
  });
  const [alertKnowledgePrompt, setAlertKnowledgePrompt] = useState("");
  const [alertKnowledgeSourceDoc, setAlertKnowledgeSourceDoc] = useState({
    loading: false,
    name: "",
    size: 0,
    text: "",
    excerpt: "",
    error: "",
  });
  const [alertKnowledgeView, setAlertKnowledgeView] = useState("onboarding");
  const [projectSetupStep, setProjectSetupStep] = useState("setup");
  const [projectSetupShowAll, setProjectSetupShowAll] = useState(false);
  const [alertOnboardingState, setAlertOnboardingState] = useState({ loading: false, result: null, error: "" });
  const [docPromptAlert, setDocPromptAlert] = useState(null);
  const [isBrowserOnline, setIsBrowserOnline] = useState(() => typeof navigator === "undefined" || navigator.onLine);
  const [docPromptKind, setDocPromptKind] = useState("runbook");
  const [docPromptMode, setDocPromptMode] = useState("create");
  const [docPromptExistingDoc, setDocPromptExistingDoc] = useState(null);
  const [docPromptDocsByKind, setDocPromptDocsByKind] = useState({});
  const [alertRuleDraft, setAlertRuleDraft] = useState({ platform: "prometheus", requirement: "" });
  const [alertRuleState, setAlertRuleState] = useState({ loading: false, result: null, error: "" });
  const alertDetailsRef = useRef(null);
  const docPromptRef = useRef(null);
  const docPromptReturnFocusRef = useRef(null);
  const approvalQueueRef = useRef(null);
  const monitoringInspectRef = useRef(null);
  const alertKnowledgeRef = useRef(null);
  const approvalIncidentRequestRef = useRef({ incidentId: "", inFlight: false, lastFetchedAt: 0 });
  const selectedAlertDetailsRetryRef = useRef({ alertId: "", lastAttemptAt: 0 });
  const healthRequestRef = useRef(0);
  const recentAlertsRequestRef = useRef({
    inFlight: false,
    requestId: "",
    startedAt: 0,
    lastFetchedAt: 0,
  });

  useEffect(() => {
    if (!docPromptAlert || !docPromptRef.current) return undefined;
    const dialog = docPromptRef.current;
    dialog.querySelector("button")?.focus();
    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeDocumentPrompt();
      }
    };
    dialog.addEventListener("keydown", handleKeyDown);
    return () => dialog.removeEventListener("keydown", handleKeyDown);
  }, [docPromptAlert]);

  useEffect(() => {
    const markOnline = () => setIsBrowserOnline(true);
    const markOffline = () => setIsBrowserOnline(false);
    window.addEventListener("online", markOnline);
    window.addEventListener("offline", markOffline);
    return () => {
      window.removeEventListener("online", markOnline);
      window.removeEventListener("offline", markOffline);
    };
  }, []);
  const landingPadRecentRequestRef = useRef({ inFlight: false, lastFetchedAt: 0 });
  const incidentMetadataRequestRef = useRef({ inFlight: false, lastFetchedAt: 0 });
  const incidentMetadataFiltersRef = useRef(metadataFilters);
  const queueHealthRequestRef = useRef({ inFlight: false, lastFetchedAt: 0 });
  const closedIncidentsRequestRef = useRef(false);

  const formValid = useMemo(() => {
    return [form.source, form.name, form.service, form.severity, form.description].every((v) => String(v || "").trim());
  }, [form]);

  async function checkHealth() {
    const requestId = Date.now() + Math.floor(Math.random() * 1000);
    healthRequestRef.current = requestId;
    setHealth({ loading: true, ok: false, message: "Checking API Gateway..." });
    try {
      const data = await fetchJson("/api-gateway/healthz", { timeoutMs: 10000 });
      if (healthRequestRef.current !== requestId) {
        return;
      }
      setHealth({ loading: false, ok: data?.status === "ok", message: `${data?.service || "api-gateway"} is ${data?.status || "unknown"}` });
    } catch (error) {
      if (healthRequestRef.current !== requestId) {
        return;
      }
      setHealth({ loading: false, ok: false, message: error.message });
    }
  }

  async function checkQueueHealth(options = {}) {
    const background = Boolean(options?.background);
    const requestState = queueHealthRequestRef.current;
    if (requestState.inFlight) return;
    if (background && Date.now() - Number(requestState.lastFetchedAt || 0) < 55000) return;
    queueHealthRequestRef.current = { ...requestState, inFlight: true };
    if (!background) setQueueHealth((current) => ({ ...current, loading: true }));
    try {
      const data = await fetchJson("/api-gateway/operations/queue-health", authenticatedOptions({ timeoutMs: 6500 }));
      queueHealthRequestRef.current.lastFetchedAt = Date.now();
      setQueueHealth({ loading: false, ...data });
    } catch (error) {
      setQueueHealth((current) => ({ ...current, loading: false, status: "unreachable", healthy: false,
        alert_processing: { status: "unavailable", limit: 50, active: null },
        analysis_backlog_ready: null, evidence_collection: { status: "unavailable" }, error: error.message }));
    } finally {
      queueHealthRequestRef.current.inFlight = false;
    }
  }

  useEffect(() => {
    if (!String(adminSession.accessToken || "").trim()) return undefined;
    if (!["home", "rag"].includes(activeTab)) return undefined;
    const refreshQueueHealth = () => {
      if (document.visibilityState === "visible") void checkQueueHealth({ background: true });
    };
    refreshQueueHealth();
    const timer = window.setInterval(refreshQueueHealth, 60000);
    return () => window.clearInterval(timer);
  }, [adminSession.accessToken, activeTab]);

  function unwrap(payload) {
    return payload?.data || payload || {};
  }

  async function loadRecentAlerts(options = {}) {
    const background = Boolean(options && options.background);
    if (
      background
      && Date.now() - Number(recentAlertsRequestRef.current.lastFetchedAt || 0) < 45000
    ) {
      return;
    }
    if (recentAlertsRequestRef.current.inFlight) {
      const startedAt = Number(recentAlertsRequestRef.current.startedAt || 0);
      if (startedAt && Date.now() - startedAt > 15000) {
        recentAlertsRequestRef.current = {
          ...recentAlertsRequestRef.current,
          inFlight: false,
          requestId: "",
          startedAt: 0,
        };
      } else {
        return;
      }
    }
    if (recentAlertsRequestRef.current.inFlight) {
      return;
    }
    const requestId = `${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    // Fetch enough candidates before balancing. During log bursts the newest
    // 200 rows can all be logs, hiding otherwise valid Email and Jira rows.
    const sourceBalancedFetchLimit = Math.min(
      200,
      Math.max(
        Number(alertsLimit) || 0,
        MAX_LATEST_ALERTS_PER_SOURCE * ALERT_SOURCE_CHANNELS.length,
        100,
      ),
    );
    recentAlertsRequestRef.current = {
      ...recentAlertsRequestRef.current,
      inFlight: true,
      requestId,
      startedAt: Date.now(),
    };
    setAlerts((prev) => ({ ...prev, loading: !background, error: "" }));
    try {
      const rows = await queryClient.fetchQuery({
        ...alertRowsQueryOptions(sourceBalancedFetchLimit, String(adminSessionRef.current?.accessToken || "")),
        staleTime: background ? 45000 : 0,
      });
      const balancedRows = capLatestAlertsPerSource(Array.isArray(rows) ? rows : []);
      if (recentAlertsRequestRef.current.requestId !== requestId) {
        return;
      }
      setAlerts((prev) => {
        if (
          background
          && !prev.loading
          && !prev.error
          && JSON.stringify(prev.rows) === JSON.stringify(balancedRows)
        ) {
          return prev;
        }
        return { loading: false, rows: balancedRows, error: "" };
      });
    } catch (error) {
      if (background) {
        if (recentAlertsRequestRef.current.requestId !== requestId) {
          return;
        }
        setAlerts((prev) => ({
          loading: false,
          rows: Array.isArray(prev.rows) ? prev.rows : [],
          error: Array.isArray(prev.rows) && prev.rows.length ? "" : String(error?.message || "Unable to refresh alerts"),
        }));
        return;
      }
      try {
        const fallbackRowsRaw = await queryClient.fetchQuery({
          // Share the same landing-pad query key as the live stream. This lets
          // TanStack coalesce fallback and stream loads instead of cancelling
          // two equivalent requests with different limits.
          ...landingPadRowsQueryOptions(100),
          staleTime: 0,
        });
        const fallbackRows = capLatestAlertsPerSource(
          (Array.isArray(fallbackRowsRaw) ? fallbackRowsRaw : []).map((row, index) => mapLandingPadRowToAlertStreamRow(row, index))
        );
        if (recentAlertsRequestRef.current.requestId !== requestId) {
          return;
        }
        setAlerts({
          loading: false,
          rows: fallbackRows,
          error: fallbackRows.length ? "Primary alert endpoint is slow. Showing latest landing-pad ingestion." : String(error?.message || "Unable to load alerts"),
        });
        return;
      } catch (_fallbackError) {
        // Fall through to existing error path if fallback also fails.
      }
      if (recentAlertsRequestRef.current.requestId !== requestId) {
        return;
      }
      setAlerts((prev) => ({
        loading: false,
        rows: Array.isArray(prev.rows) ? prev.rows : [],
        error: background && Array.isArray(prev.rows) && prev.rows.length ? "" : error.message,
      }));
    } finally {
      if (recentAlertsRequestRef.current.requestId === requestId) {
        recentAlertsRequestRef.current = {
          inFlight: false,
          requestId: "",
          startedAt: 0,
          lastFetchedAt: Date.now(),
        };
      }
    }
  }

  async function loadAlertSeverityOverrides() {
    setAlertSeverityOverrides((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/alerts/severity-overrides", authenticatedOptions());
      const data = unwrap(payload);
      const rows = (Array.isArray(data?.rows) ? data.rows : []).map(visibleManagedApplication).filter(Boolean);
      setAlertSeverityOverrides((prev) => ({ ...prev, loading: false, rows, error: "" }));
    } catch (error) {
      setAlertSeverityOverrides((prev) => ({ ...prev, loading: false, rows: [], error: error.message }));
    }
  }





  async function loadMonitoringApplications() {
    setMonitoringApps((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/applications", authenticatedOptions());
      const data = unwrap(payload);
      const rows = (Array.isArray(data?.rows) ? data.rows : []).map(visibleManagedApplication).filter(Boolean);
      setMonitoringApps({ loading: false, rows, error: "" });
      setSelectedMonitoringAppId((current) => {
        const normalizedCurrent = String(current || "").trim();
        if (normalizedCurrent && rows.some((row) => String(row?.id || "").trim() === normalizedCurrent)) {
          return normalizedCurrent;
        }
        return String(rows[0]?.id || "").trim();
      });
    } catch (error) {
      setMonitoringApps({ loading: false, rows: [], error: error.message });
    }
  }

  async function loadMonitoringApplicationDetails(applicationId) {
    const normalized = String(applicationId || "").trim();
    if (!normalized) {
      setMonitoringAppDetails({ loading: false, history: [], validations: [], dashboards: [], error: "" });
      return;
    }
    setMonitoringAppDetails((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const [historyPayload, validationsPayload, dashboardsPayload] = await Promise.all([
        fetchJson(`/api-gateway/applications/${normalized}/history`, authenticatedOptions()),
        fetchJson(`/api-gateway/applications/${normalized}/validations`, authenticatedOptions()),
        fetchJson(`/api-gateway/applications/${normalized}/dashboards`, authenticatedOptions()),
      ]);
      const historyRows = Array.isArray(unwrap(historyPayload)?.rows) ? unwrap(historyPayload).rows : [];
      const validationRows = Array.isArray(unwrap(validationsPayload)?.rows) ? unwrap(validationsPayload).rows : [];
      const dashboardRows = Array.isArray(unwrap(dashboardsPayload)?.rows) ? unwrap(dashboardsPayload).rows : [];
      setMonitoringAppDetails({ loading: false, history: historyRows, validations: validationRows, dashboards: dashboardRows, error: "" });
    } catch (error) {
      setMonitoringAppDetails({ loading: false, history: [], validations: [], dashboards: [], error: error.message });
    }
  }

  async function submitMonitoringApplication(event) {
    event.preventDefault();
    setMonitoringAppSubmit({ loading: true, error: "", success: "" });
    try {
      const metricsEndpoint = String(monitoringAppForm.metrics_endpoint || "").trim() || "http://api-gateway:8000/metrics";
      if (!/^https?:\/\//i.test(metricsEndpoint)) {
        setMonitoringAppSubmit({
          loading: false,
          error: "Metrics Endpoint must start with http:// or https:// (for example, http://api-gateway:8000/metrics).",
          success: "",
        });
        return;
      }
      const labels = Object.fromEntries(
        String(monitoringAppForm.labels_text || "")
          .split(",")
          .map((entry) => entry.trim())
          .filter(Boolean)
          .map((entry) => {
            const [key, ...rest] = entry.split("=");
            return [String(key || "").trim(), rest.join("=").trim()];
          })
          .filter(([key]) => key)
      );
      const payload = {
        tenant_id: monitoringAppForm.tenant_id,
        name: monitoringAppForm.name,
        owner_team: monitoringAppForm.owner_team,
        owner_email: monitoringAppForm.owner_email || null,
        environment: monitoringAppForm.environment,
        namespace: monitoringAppForm.namespace,
        region: monitoringAppForm.region,
        technology: monitoringAppForm.technology,
        metrics_endpoint: metricsEndpoint,
        monitoring_platform: "prometheus",
        labels,
      };
      await fetchJson("/api-gateway/applications", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      }));
      setMonitoringAppSubmit({ loading: false, error: "", success: `Queued onboarding for ${monitoringAppForm.name}` });
      setMonitoringAppForm((curr) => ({ ...curr, name: "", owner_email: "", metrics_endpoint: "http://api-gateway:8000/metrics" }));
      await loadMonitoringApplications();
      await loadMonitorApplications();
      await refreshViewsAfterSubmit();
    } catch (error) {
      setMonitoringAppSubmit({ loading: false, error: error.message, success: "" });
    }
  }

  async function loadAlertDetails(alertId, fallbackRow = null, options = {}) {
    const normalized = String(alertId || "").trim();
    const background = Boolean(options?.background);
    if (!normalized) {
      return;
    }
    if (!ALERT_UUID_PATTERN.test(normalized)) {
      const landingAlert = fallbackRow && typeof fallbackRow === "object" ? fallbackRow : {};
      setSelectedAlertData({
        loading: false,
        payload: {
          data: {
            alert: landingAlert,
            incident: null,
            context: {
              metadata: {
                source: landingAlert.source || "landing-pad",
                origin_system: landingAlert.origin_system || landingAlert.labels?.origin_system || "",
                ingestion_channel: landingAlert.ingestion_channel || landingAlert.labels?.ingestion_channel || "",
                processing_state: "landing_pad_only",
              },
            },
            timeline: [],
          },
        },
        error: "",
        alertId: normalized,
      });
      return;
    }
    const immediatePayload = fallbackRow && typeof fallbackRow === "object"
      ? {
          data: {
            alert: fallbackRow,
            incident: fallbackRow.incident_id || fallbackRow.projection_payload
              ? {
                  id: fallbackRow.incident_id || fallbackRow.id || "",
                  status: fallbackRow.status || fallbackRow.state || "",
                  service: fallbackRow.service || "",
                  environment: fallbackRow.environment || "",
                }
              : null,
            context: { metadata: { processing_state: "loading" } },
            timeline: [],
          },
        }
      : null;
    setSelectedAlertData((prev) => ({
      loading: background ? prev.loading : true,
      payload: String(prev.alertId || "") === normalized ? prev.payload : immediatePayload,
      error: "",
      alertId: normalized,
    }));
    try {
      const payload = await queryClient.fetchQuery({
        queryKey: ["alert-processed-result", normalized],
        queryFn: () => fetchJson(`/api-gateway/alerts/${normalized}/processed-result`, authenticatedOptions({
          timeoutMs: 12000,
          // This is a safe read. Absorb the brief connection-refused interval
          // while Docker replaces monitoring-adapter without discarding the
          // persisted cockpit snapshot already rendered above.
          maxAttempts: 4,
        })),
        // Background hydration must bypass the query cache. Incident stages
        // can complete between polls, and returning a 15-second-old partial
        // payload makes the cockpit appear permanently stuck.
        // Processed results are mutable projections. Never treat a previous
        // recommendation revision as fresh after correlation or regeneration.
        staleTime: 0,
      });
      setSelectedAlertData((prev) => {
        if (String(prev.alertId || "") !== normalized) {
          return prev;
        }
        return { loading: false, payload, error: "", alertId: normalized };
      });
      return payload;
    } catch (error) {
      const rawError = String(error?.message || "Unable to load processed alert details");
      const displayError = /HTTP 502|All connection attempts failed|Bad Gateway/i.test(rawError)
        ? "The latest processed analysis is temporarily unavailable. Showing the last persisted incident and RCA data; refresh to retry."
        : rawError;
      setSelectedAlertData((prev) => {
        if (String(prev.alertId || "") !== normalized) {
          return prev;
        }
        return {
          loading: false,
          payload: prev.payload,
          error: displayError,
          alertId: normalized,
        };
      });
    }
  }

  async function loadSelectedAlertDocumentLinks(alertId, fallbackRow = null) {
    const normalized = String(alertId || "").trim();
    if (!normalized) {
      setSelectedAlertDocumentLinks({ loading: false, alertId: "", rows: [], canonicalAlert: null, contract: null, error: "" });
      return;
    }
    if (!ALERT_UUID_PATTERN.test(normalized)) {
      setSelectedAlertDocumentLinks({
        loading: false,
        alertId: normalized,
        rows: [],
        canonicalAlert: fallbackRow && typeof fallbackRow === "object" ? fallbackRow : null,
        contract: {
          document_link_summary: {
            count: 0,
            source: "landing-pad-local-fallback",
            processing_state: "landing_pad_only",
          },
        },
        error: "",
      });
      return;
    }
    setSelectedAlertDocumentLinks((current) => ({
      ...current,
      loading: true,
      alertId: normalized,
      error: "",
    }));
    try {
      const payload = await fetchJson(
        `/api-gateway/alerts/${encodeURIComponent(normalized)}/linked-documents?limit=${alertsLimit}`,
        authenticatedOptions(),
      );
      const data = unwrap(payload);
      const rows = Array.isArray(data?.linked_documents) ? data.linked_documents : [];
      setSelectedAlertDocumentLinks((current) => {
        if (String(current.alertId || "") !== normalized) {
          return current;
        }
        return {
          loading: false,
          alertId: normalized,
          rows,
          canonicalAlert: data?.canonical_alert || null,
          contract: data || null,
          error: "",
        };
      });
    } catch (error) {
      setSelectedAlertDocumentLinks((current) => {
        if (String(current.alertId || "") !== normalized) {
          return current;
        }
        return {
          ...current,
          loading: false,
          rows: [],
          canonicalAlert: null,
          contract: null,
          error: String(error?.message || "Unable to load linked documents"),
        };
      });
    }
  }

  async function loadIncidentStageCompleteness(incidentId, options = {}) {
    const normalized = String(incidentId || "").trim();
    const background = Boolean(options?.background);
    if (!normalized) {
      setSelectedStageCompleteness({ loading: false, data: null, error: "", incidentId: "" });
      return;
    }
    setSelectedStageCompleteness((prev) => ({
      loading: background ? prev.loading : true,
      data: background && String(prev.incidentId || "") === normalized ? prev.data : null,
      error: "",
      incidentId: normalized,
    }));
    try {
      const payload = await fetchJson(
        `/api-gateway/incidents/${normalized}/stage-completeness`,
        authenticatedOptions(),
      );
      const stageData = payload?.data || payload;
      setSelectedStageCompleteness((prev) => {
        if (String(prev.incidentId || "") !== normalized) {
          return prev;
        }
        return { loading: false, data: stageData, error: "", incidentId: normalized };
      });
    } catch (error) {
      setSelectedStageCompleteness((prev) => {
        if (String(prev.incidentId || "") !== normalized) {
          return prev;
        }
        return { loading: false, data: null, error: error.message, incidentId: normalized };
      });
    }
  }

  function openAlertDetails(row, initialTab = "evidence") {
    // Incident projections already carry the authoritative alert UUID. Do not
    // replace it with a semantically similar landing-pad row whose id is a
    // filename; processed RCA endpoints are keyed by the canonical UUID.
    const resolution = resolveCanonicalAlertForRow(row, alerts.rows);
    const pending = resolution.status === "pending";
    // While pending (canonical DB alert not in alerts.rows yet -- landing-pad
    // ingestion fires before the alert row is persisted/fetched), keep the
    // row itself as the selection so it stays visible in the cockpit.
    // loadAlertDetails already has a dedicated non-UUID branch that renders a
    // local "landing_pad_only" snapshot without an API call, so this never
    // sends a doomed processed-result lookup. The retry effect below promotes
    // the selection to the real UUID once alerts.rows catches up.
    const canonicalRow = pending ? row : resolution.row;
    const alertId = String(canonicalRow?.alert_id || canonicalRow?.id || canonicalRow?.incident_id || "").trim();
    if (!alertId) {
      return;
    }
    setPendingCanonicalAlert(pending ? row : null);
    setSelectedAlertSnapshot(canonicalRow);
    setSelectedAlertId(alertId);
    // This action owns the complete cockpit URL below. Prevent the legacy tab
    // synchronization effect from racing it with a navigation to plain `/`,
    // which would remove workspace=alert and leave the details view hidden.
    skipNextActiveTabNavigationRef.current = true;
    setActiveTab("home");
    setHomeDetailTab(initialTab === "rca" ? "evidence" : initialTab);
    if (initialTab === "rca") setRcaDetailView("simple");
    loadAlertDetails(alertId, canonicalRow);
    const detail = initialTab === "rca" ? "evidence" : initialTab;
    onNavigatePath?.(`/?workspace=alert&alert_id=${encodeURIComponent(alertId)}&detail=${encodeURIComponent(detail)}`);
  }

  function openAlertDetailsFromIncident(row, initialTab = "evidence") {
    const incidentId = String(row?.incident_id || row?.incident_projection?.incident_id || row?.incident_projection?.id || row?.id || "").trim();
    if (!incidentId) {
      return;
    }
    if (onNavigatePath) {
      onNavigatePath(`/incidents/${encodeURIComponent(incidentId)}`);
      return;
    }
    setApprovalState({ loading: false, result: null, error: "" });
    const projection = row?.projection_payload && typeof row.projection_payload === "object"
      ? row.projection_payload
      : {};
    const eventPayload = projection?.event_payload && typeof projection.event_payload === "object"
      ? projection.event_payload
      : {};
    const sourceAlert = row?.source_alert && typeof row.source_alert === "object"
      ? row.source_alert
      : projection?.source_alert && typeof projection.source_alert === "object"
        ? projection.source_alert
        : eventPayload?.alert && typeof eventPayload.alert === "object"
          ? eventPayload.alert
          : {};
    const projectedAlertId = String(
      row?.alert_id
      || projection?.alert_id
      || eventPayload?.alert_id
      || eventPayload?.source_alert_id
      || sourceAlert?.alert_id
      || sourceAlert?.id
      || ""
    ).trim();
    // Incident navigation must not depend on the current alert filters. Search
    // the complete backend collection so dashboard/approval drill-downs retain
    // their canonical alert identity even when that alert is not visible in the
    // active Signals view.
    const matchedAlert = alerts.rows.find((alertRow) => {
      const alertId = String(alertRow?.alert_id || alertRow?.id || alertRow?.incident_id || "").trim();
      const sourceIncident = String(alertRow?.incident_id || "").trim();
      return alertId === projectedAlertId || alertId === incidentId || sourceIncident === incidentId;
    });
    const canonicalAlertId = String(
      matchedAlert?.alert_id
      || matchedAlert?.id
      || projectedAlertId
      || ""
    ).trim();
    if (!canonicalAlertId || canonicalAlertId === incidentId) {
      // Stay on the incident record instead of opening an alert endpoint with
      // an incident UUID. A subsequent metadata refresh can supply the missing
      // canonical relationship without corrupting the cockpit URL.
      setActiveTab("summary");
      onNavigatePath?.(`/incidents?incident_id=${encodeURIComponent(incidentId)}&stage=${encodeURIComponent(initialTab)}`);
      return;
    }
    const canonicalRow = matchedAlert || { ...row, ...sourceAlert, alert_id: canonicalAlertId, incident_id: incidentId };
    openAlertDetails(canonicalRow, initialTab);
  }

  useEffect(() => {
    if (!adminSession.accessToken || activeTab !== "home") return;
    const params = new URLSearchParams(currentSearch || "");
    if (params.get("workspace") !== "alert") return;
    const routeAlertId = String(params.get("alert_id") || "").trim();
    if (!routeAlertId || routeAlertId === String(selectedAlertId || "")) return;

    // Detail URLs are durable application state. Reconstruct the selection on
    // refresh, browser history navigation, and shared links instead of relying
    // on an in-memory summary-row click from the current session.
    if (ALERT_UUID_PATTERN.test(routeAlertId)) {
      const snapshotId = String(selectedAlertSnapshot?.alert_id || selectedAlertSnapshot?.id || selectedAlertSnapshot?.incident_id || "").trim();
      const fallbackRow = snapshotId === routeAlertId
        ? selectedAlertSnapshot
        : alerts.rows.find((row) => String(row?.alert_id || row?.id || row?.incident_id || "").trim() === routeAlertId) || null;
      setSelectedAlertId(routeAlertId);
      setSelectedAlertSnapshot(fallbackRow);
      const requestedDetail = String(params.get("detail") || "evidence").trim();
      setHomeDetailTab(requestedDetail === "rca" ? "evidence" : requestedDetail);
      if (requestedDetail === "evidence") setRcaDetailView("evidence");
      if (requestedDetail === "rca") setRcaDetailView("simple");
      void loadAlertDetails(routeAlertId, fallbackRow);
      return;
    }
    // A landing-pad filename can end up in the URL from an earlier click that
    // happened before the canonical DB alert existed (see openAlertDetails /
    // resolveCanonicalAlertForRow). Route restoration must go through the same
    // canonicalization -- otherwise every refresh/shared-link re-opens with an
    // id that can never resolve, permanently stuck on a landing-pad-only
    // snapshot even after the canonical alert is long since available. Find
    // the original landing-pad row by filename so matching has its real
    // fingerprint/name/service identity, not just the bare filename string.
    const landingPadSourceRow = (Array.isArray(landingPadRecent.rows) ? landingPadRecent.rows : [])
      .find((row) => String(row?.file || "") === routeAlertId)
      || { id: routeAlertId, alert_id: routeAlertId, file: routeAlertId };
    const resolution = resolveCanonicalAlertForRow(landingPadSourceRow, alerts.rows);
    if (resolution.status === "resolved") {
      const canonicalRow = resolution.row;
      const alertId = String(canonicalRow?.alert_id || canonicalRow?.id || canonicalRow?.incident_id || "").trim();
      if (alertId) {
        setSelectedAlertId(alertId);
        setSelectedAlertSnapshot(canonicalRow);
        setHomeDetailTab("evidence");
        void loadAlertDetails(alertId, canonicalRow);
        onNavigatePath?.(`/?workspace=alert&alert_id=${encodeURIComponent(alertId)}`);
      }
      return;
    }
    setSelectedAlertId(routeAlertId);
    setSelectedAlertSnapshot(null);
    setHomeDetailTab("evidence");
    void loadAlertDetails(routeAlertId);
    if (resolution.status === "pending") {
      setPendingCanonicalAlert(landingPadSourceRow);
    }
  }, [adminSession.accessToken, activeTab, currentSearch, selectedAlertId, selectedAlertSnapshot, alerts.rows, landingPadRecent.rows]);

  function openGlobalOperationalItem(item) {
    if (!item?.row) return;
    if (["Alert", "Ticket"].includes(item.kind)) {
      openAlertDetails(item.row);
    } else if (["Incident", "Assigned incident", "Approval", "Failed action", "Approval reminder", "Resolved", "Reopened"].includes(item.kind)) {
      openAlertDetailsFromIncident(item.row);
    } else if (item.kind === "Application") {
      setActiveTab("home");
    } else if (item.kind === "Service") {
      setDashboardAlertQuery(String(item.row.service || ""));
      setActiveTab("home");
    }
    setGlobalOperationsQuery("");
  }

  useEffect(() => {
    if (activeTab !== "home" || !selectedAlertId) {
      return;
    }
    if (typeof window === "undefined") {
      return;
    }
    window.requestAnimationFrame(() => {
      alertDetailsRef.current?.scrollIntoView({ behavior: "auto", block: "start" });
      alertDetailsRef.current?.focus({ preventScroll: true });
    });
  }, [activeTab, selectedAlertId]);

  useEffect(() => {
    if (activeTab !== "home") {
      return;
    }
    const payload = selectedAlertData?.payload?.data || selectedAlertData?.payload || {};
    const workflow = payload?.workflow || payload || {};
    const currentIncidentId = String(workflow?.incident?.id || workflow?.incident_id || "").trim();

    if (!currentIncidentId) {
      setSelectedStageCompleteness({ loading: false, data: null, error: "", incidentId: "" });
      return;
    }
    if (
      String(selectedStageCompleteness.incidentId || "") === String(currentIncidentId)
      && (selectedStageCompleteness.data || selectedStageCompleteness.loading || selectedStageCompleteness.error)
    ) {
      return;
    }
    loadIncidentStageCompleteness(currentIncidentId);
  }, [activeTab, selectedAlertData.payload, selectedStageCompleteness.incidentId, selectedStageCompleteness.data, selectedStageCompleteness.loading, selectedStageCompleteness.error]);

  useEffect(() => {
    const incidentId = String(selectedStageCompleteness.incidentId || "").trim();
    const completion = selectedStageCompleteness.data?.stage_completion;
    const completed = Number(completion?.completed || 0);
    const total = Number(completion?.total || 0);
    if (activeTab !== "home" || !incidentId || selectedStageCompleteness.loading || (total > 0 && completed >= total)) {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      loadIncidentStageCompleteness(incidentId, { background: true });
    }, 10000);
    return () => window.clearTimeout(timer);
  }, [activeTab, selectedStageCompleteness.incidentId, selectedStageCompleteness.data, selectedStageCompleteness.loading]);

  useEffect(() => {
    const scopedRows = mergeAlertStreamRows(
      filterAlertsForMonitor(alerts.rows, applicationToMonitor),
      filterRowsForMonitor(closedIncidents.rows, applicationToMonitor),
    );
    const snapshotAlertId = String(
      selectedAlertSnapshot?.alert_id
      || selectedAlertSnapshot?.id
      || selectedAlertSnapshot?.incident_id
      || ""
    );
    // An explicit incident drill-down owns its selection. Dashboard scope
    // filters must not discard the clicked row while its full payload hydrates.
    const hasSelectedSnapshot = Boolean(selectedAlertId && snapshotAlertId === String(selectedAlertId));
    if (activeTab !== "home") {
      return;
    }
    if (!scopedRows.length) {
      // A landing-pad event is immediately actionable even before it has been
      // persisted into the canonical alerts collection. Keep the clicked row
      // available as the cockpit snapshot while asynchronous processing runs.
      if (hasSelectedSnapshot) {
        return;
      }
      if (
        selectedAlertId
        && String(selectedAlertData.alertId || "") === String(selectedAlertId)
        && (selectedAlertData.loading || selectedAlertData.payload || selectedAlertData.error)
      ) {
        return;
      }
      if (selectedAlertId) {
        setSelectedAlertId("");
      }
      if (selectedAlertData.payload || selectedAlertData.error) {
        setSelectedAlertData({ loading: false, payload: null, error: "", alertId: "" });
      }
      return;
    }
    const selectedExists = scopedRows.some(
      (row) => String(row?.alert_id || row?.id || row?.incident_id || "") === selectedAlertId
    );
    if (selectedExists) {
      const normalizedSelectedAlertId = String(selectedAlertId || "");
      if (String(selectedAlertData.alertId || "") !== normalizedSelectedAlertId) {
        loadAlertDetails(selectedAlertId);
      } else if (!selectedAlertData.payload && !selectedAlertData.loading) {
        const now = Date.now();
        const retryState = selectedAlertDetailsRetryRef.current;
        const sameAlert = String(retryState.alertId || "") === normalizedSelectedAlertId;
        const elapsedMs = now - Number(retryState.lastAttemptAt || 0);
        if (!sameAlert || elapsedMs > 15000) {
          selectedAlertDetailsRetryRef.current = { alertId: normalizedSelectedAlertId, lastAttemptAt: now };
          loadAlertDetails(selectedAlertId);
        }
      }
      return;
    }
    if (hasSelectedSnapshot && (!selectedAlertData.error || selectedAlertData.loading)) {
      return;
    }
    if (selectedAlertData.loading && String(selectedAlertData.alertId || "") === String(selectedAlertId || "")) {
      return;
    }
    // See shouldRetainAlertSelection: list membership in scopedRows is not
    // authoritative for whether the selected alert still exists (closure and
    // monitor-scope filtering can both drop it from this summary list without
    // it having stopped existing) -- only clear the selection when there is no
    // already-loaded payload to fall back on.
    if (shouldRetainAlertSelection({
      selectedAlertId,
      payload: selectedAlertData.payload,
      error: selectedAlertData.error,
      alertId: selectedAlertData.alertId,
    })) {
      return;
    }
    // The incident summary must not implicitly open the newest row. That row may
    // still be moving through enrichment/RCA, which made the first cockpit
    // appear incomplete before the operator selected an alert.
    if (selectedAlertId) {
      setSelectedAlertId("");
      setSelectedAlertSnapshot(null);
      setSelectedAlertData({ loading: false, payload: null, error: "", alertId: "" });
    }
  }, [activeTab, alerts.rows, closedIncidents.rows, applicationToMonitor, selectedAlertId, selectedAlertSnapshot, selectedAlertData.loading, selectedAlertData.payload, selectedAlertData.error, selectedAlertData.alertId]);

  useEffect(() => {
    // A landing-pad row was opened before its canonical DB alert existed in
    // alerts.rows (see openAlertDetails / resolveCanonicalAlertForRow). Retry
    // resolution on every alerts.rows refresh; once the canonical UUID-bearing
    // alert appears, promote the selection to it and load the real processed
    // result. Bounded so a landing-pad event that never gets persisted (e.g.
    // discovery classified it as noise) doesn't retry forever.
    if (activeTab !== "home" || !pendingCanonicalAlert) {
      return undefined;
    }
    const resolution = resolveCanonicalAlertForRow(pendingCanonicalAlert, alerts.rows);
    if (resolution.status === "resolved") {
      const canonicalRow = resolution.row;
      const alertId = String(canonicalRow?.alert_id || canonicalRow?.id || canonicalRow?.incident_id || "").trim();
      if (alertId) {
        setPendingCanonicalAlert(null);
        setSelectedAlertSnapshot(canonicalRow);
        setSelectedAlertId(alertId);
        loadAlertDetails(alertId, canonicalRow);
        onNavigatePath?.(`/?workspace=alert&alert_id=${encodeURIComponent(alertId)}`);
      }
      return undefined;
    }
    if (resolution.status === "unresolved") {
      // The row itself carries no identity to ever match against -- retrying
      // cannot help.
      setPendingCanonicalAlert(null);
      return undefined;
    }
    const previous = pendingCanonicalAlertRetryRef.current;
    const pendingKey = String(
      pendingCanonicalAlert?.file
      || pendingCanonicalAlert?.id
      || pendingCanonicalAlert?.alert_id
      || ""
    );
    const attempts = previous.key === pendingKey ? Number(previous.attempts || 0) : 0;
    // loadRecentAlerts throttles background refreshes to at most once per 45s
    // (see recentAlertsRequestRef), so polling faster than that only re-checks
    // the same alerts.rows snapshot. Match that cadence; ten attempts (~7.5
    // minutes) covers slow discovery processing without retrying forever for
    // an event that never gets persisted (e.g. classified as noise).
    if (attempts >= 10) {
      return undefined;
    }
    pendingCanonicalAlertRetryRef.current = { key: pendingKey, attempts: attempts + 1 };
    const timer = window.setTimeout(() => {
      void loadRecentAlerts({ background: true });
    }, 45000);
    return () => window.clearTimeout(timer);
  }, [activeTab, pendingCanonicalAlert, alerts.rows]);

  useEffect(() => {
    const needsEvidence = homeDetailTab === "evidence" && rcaDetailView === "evidence";
    if (!needsEvidence || !selectedAlertId) return;
    if (String(selectedAlertDocumentLinks.alertId || "") === String(selectedAlertId)) return;
    loadSelectedAlertDocumentLinks(selectedAlertId, selectedAlertRow);
  }, [homeDetailTab, rcaDetailView, selectedAlertId, selectedAlertDocumentLinks.alertId]);

  useEffect(() => {
    const alertId = String(selectedAlertId || "").trim();
    if (activeTab !== "home" || !ALERT_UUID_PATTERN.test(alertId)) {
      selectedAlertAnalysisPollRef.current = { alertId: "", attempts: 0 };
      return undefined;
    }
    if (alertAnalysisReady(selectedAlertData.payload)) {
      selectedAlertAnalysisPollRef.current = { alertId, attempts: 0 };
      return undefined;
    }
    const previous = selectedAlertAnalysisPollRef.current;
    const attempts = previous.alertId === alertId ? Number(previous.attempts || 0) : 0;
    // Model-backed RCA can legitimately take several minutes when the queue is
    // draining. Keep the selected incident hydrated for up to ten minutes.
    if (attempts >= 60) {
      return undefined;
    }
    selectedAlertAnalysisPollRef.current = { alertId, attempts: attempts + 1 };
    const timer = window.setTimeout(() => {
      loadAlertDetails(alertId, null, { background: true });
    }, 10000);
    return () => window.clearTimeout(timer);
  }, [activeTab, selectedAlertId, selectedAlertData.payload]);

  async function loadIncidentMetadata(options = {}) {
    const background = Boolean(options && options.background);
    const ignoreFilters = Boolean(options && options.ignoreFilters);
    const requestState = incidentMetadataRequestRef.current;
    if (requestState.inFlight) {
      incidentMetadataRequestRef.current = { ...requestState, pending: true };
      return;
    }
    // Coalesce bursts of incident lifecycle notifications instead of flooding
    // the gateway and repainting the Operations workspace for every event.
    if (background && Date.now() - Number(requestState.lastFetchedAt || 0) < 15000) {
      return;
    }
    incidentMetadataRequestRef.current = { ...requestState, inFlight: true };
    setIncidentMetadata((prev) => {
      const loading = background ? prev.loading : true;
      return prev.loading === loading && !prev.error ? prev : { ...prev, loading, error: "" };
    });
    try {
      const currentFilters = ignoreFilters
        ? { risk_tier: "all", execution_mode: "all", transport_provider: "all", status: "all", service: "" }
        : incidentMetadataFiltersRef.current;
      const payload = await fetchJson(
        `/api-gateway/incidents/groups?${buildIncidentGroupQuery(options || {}, currentFilters)}`,
        authenticatedOptions({ staleTimeMs: 0 }),
      );
      const data = unwrap(payload);
      const rows = data?.rows || [];
      const nextRows = Array.isArray(rows) ? rows : [];
      setIncidentMetadata({ loading: false, rows: nextRows, error: "", page: data || {} });
    } catch (error) {
      setIncidentMetadata((prev) => ({
        loading: false,
        rows: Array.isArray(prev.rows) ? prev.rows : [],
        error: error.message,
        page: prev.page || {},
      }));
    } finally {
      const pending = Boolean(incidentMetadataRequestRef.current.pending);
      incidentMetadataRequestRef.current = { inFlight: false, pending: false, lastFetchedAt: Date.now() };
      if (pending) {
        window.setTimeout(() => loadIncidentMetadata(), 0);
      }
    }
  }

  async function loadClosedIncidents({ append = false } = {}) {
    if (closedIncidentsRequestRef.current) return;
    const offset = append ? closedIncidents.nextOffset : 0;
    if (append && offset == null) return;
    closedIncidentsRequestRef.current = true;
    setClosedIncidents((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson(
        `/api-gateway/incidents/closed?limit=120&offset=${offset}`,
        authenticatedOptions({ timeoutMs: 12000 }),
      );
      const data = unwrap(payload);
      const rows = Array.isArray(data?.rows) ? data.rows : [];
      setClosedIncidents((previous) => {
        const combined = append ? [...previous.rows, ...rows] : rows;
        const unique = new Map(combined.map((row) => [String(row.incident_id || row.id), row]));
        return { loading: false, rows: [...unique.values()], error: "", nextOffset: data?.next_offset ?? null };
      });
    } catch (error) {
      setClosedIncidents((prev) => ({ ...prev, loading: false, error: error.message }));
    } finally {
      closedIncidentsRequestRef.current = false;
    }
  }

  async function refreshApprovalDrivenViews(incidentId = "") {
    const normalizedIncidentId = String(incidentId || "").trim();
    const tasks = [
      loadRecentAlerts(),
      loadIncidentMetadata(),
      loadGatewayRecent(),
      loadGatewaySummary(),
      loadClosedIncidents(),
    ];

    if (selectedAlertId) {
      tasks.push(loadAlertDetails(selectedAlertId));
      tasks.push(loadSelectedAlertDocumentLinks(selectedAlertId));
    }

    if (selectedApprovalIncidentId && (!normalizedIncidentId || selectedApprovalIncidentId === normalizedIncidentId)) {
      tasks.push(loadApprovalIncidentContext(selectedApprovalIncidentId));
    }

    await Promise.all(tasks);
  }

  async function pollIncidentTerminalStatus(incidentId, timeoutMs = 25 * 60 * 1000) {
    const normalizedIncidentId = String(incidentId || "").trim();
    if (!normalizedIncidentId) return;

    const terminalStatuses = new Set([
      "succeeded", "failed", "skipped", "completed", "closed", "resolved",
      "policy_blocked", "dispatch_failed", "execution_failed", "validation_failed",
      "rolled_back", "rollback_failed", "timed_out", "cancelled", "manual_intervention_required",
    ]);
    const startedAt = Date.now();
    let attempt = 0;
    while (Date.now() - startedAt < timeoutMs) {
      const delayMs = attempt === 0 ? 800 : Math.min(10000, 2000 + Math.floor(attempt / 10) * 1000);
      await new Promise((resolve) => window.setTimeout(resolve, delayMs));
      attempt += 1;
      try {
        const actionPayload = await fetchJson(`/api-gateway/remediation/actions/by-incident/${encodeURIComponent(normalizedIncidentId)}/latest`, authenticatedOptions());
        const action = unwrap(actionPayload);
        const actionStatus = String(action?.status || "").trim().toLowerCase();
        if (terminalStatuses.has(actionStatus)) {
          setRemediationExecutionState({ loading: false, result: actionPayload, error: "" });
          applyApprovalResolutionToUi(normalizedIncidentId, actionStatus === "succeeded" ? "validating" : "failed");
          await refreshApprovalDrivenViews(normalizedIncidentId);
          return;
        }
        // Preserve the latest durable phase (dispatching, accepted, running,
        // verifying) so the UI reflects progress rather than a stale submit response.
        setRemediationExecutionState({ loading: true, result: actionPayload, error: "" });
        const payload = await fetchJson(
          `/api-gateway/incidents/${encodeURIComponent(normalizedIncidentId)}/stage-completeness`,
          authenticatedOptions(),
        );
        const data = unwrap(payload) || {};
        const status = String(data.status || "").trim().toLowerCase();
        if (["closed", "resolved", "failed"].includes(status)) {
          applyApprovalResolutionToUi(normalizedIncidentId, status);
          await refreshApprovalDrivenViews(normalizedIncidentId);
          return;
        }
      } catch {
        // A transient projection read must not stop later terminal refreshes.
      }
    }
    await refreshApprovalDrivenViews(normalizedIncidentId);
    setRemediationExecutionState((current) => ({
      ...current,
      loading: false,
      error: "Execution status did not become terminal before the monitoring deadline. The durable workflow continues in the backend; refresh or inspect the executor run.",
    }));
  }





  async function loadGatewaySummary() {
    setGatewaySummary((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/observability/summary");
      setGatewaySummary({ loading: false, data: payload || {}, error: "" });
    } catch (error) {
      setGatewaySummary({ loading: false, data: {}, error: error.message });
    }
  }

  async function loadGatewayRecent() {
    setGatewayRecent((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/observability/recent?limit=120");
      const rows = payload?.events || [];
      setGatewayRecent({ loading: false, rows: Array.isArray(rows) ? rows : [], error: "" });
    } catch (error) {
      setGatewayRecent({ loading: false, rows: [], error: error.message });
    }
  }

  async function loadLandingPadRecent(options = {}) {
    const background = Boolean(options && options.background);
    const force = Boolean(options && options.force);
    if (landingPadRecentRequestRef.current.inFlight) {
      return;
    }
    if (background && !force && Date.now() - landingPadRecentRequestRef.current.lastFetchedAt < 12000) {
      return;
    }
    landingPadRecentRequestRef.current.inFlight = true;
    // Keep existing cards mounted while the periodic poll runs. New rows are
    // swapped in atomically when the background request completes.
    setLandingPadRecent((prev) => {
      const loading = background ? prev.loading : true;
      return prev.loading === loading && !prev.error ? prev : { ...prev, loading, error: "" };
    });
    try {
      // Interactive refreshes only read the live landing-pad window. Historical
      // source coverage is supplied by /alerts/all, so walking the mounted
      // archive here adds tens of seconds without improving the visible stream.
      const rows = await queryClient.fetchQuery({
        ...landingPadRowsQueryOptions(100),
        staleTime: force ? 0 : background ? 12000 : 0,
      });
      const balancedRows = capLatestAlertsPerSource(
        (Array.isArray(rows) ? rows : []).map((row, index) => mapLandingPadRowToAlertStreamRow(row, index))
      );
      const rowsChanged = JSON.stringify(landingPadRecent.rows) !== JSON.stringify(balancedRows);
      setLandingPadRecent((prev) => !rowsChanged && !prev.loading && !prev.error
        ? prev
        : { loading: false, rows: rowsChanged ? balancedRows : prev.rows, error: "" });
      if (rowsChanged) setIngestionStreamUpdatedAt(new Date().toISOString());
    } catch (error) {
      setLandingPadRecent((prev) => ({ ...prev, loading: false, error: error.message }));
    } finally {
      landingPadRecentRequestRef.current = { inFlight: false, lastFetchedAt: Date.now() };
    }
  }

  async function loadRagDocs() {
    setRagDocs((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/rag/documents", authenticatedOptions());
      const rows = payload?.documents || payload?.data?.documents || [];
      setRagDocs({ loading: false, rows: Array.isArray(rows) ? rows : [], error: "" });
    } catch (error) {
      setRagDocs({ loading: false, rows: [], error: error.message });
    }
  }

  async function loadMonitorApplications({ preLogin = false } = {}) {
    try {
      // The login selector is rendered before a bearer token exists. Keep its
      // inventory request public and independent from alert discovery so a
      // protected/unavailable alert endpoint cannot collapse the selector to
      // the two built-in workspaces.
      const requestOptions = preLogin
        ? { headers: { Accept: "application/json" }, maxAttempts: 1, staleTimeMs: 0 }
        : authenticatedOptions();
      const payload = await fetchJson("/api-gateway/applications", requestOptions);
      const data = unwrap(payload);
      const applicationRows = (Array.isArray(data?.rows) ? data.rows : []).map(visibleManagedApplication).filter(Boolean);
      setMonitoringApps({ loading: false, rows: applicationRows, error: "" });
      const options = uniqueMonitorApplications(applicationRows.map((row) => String(row?.name || row?.application || "").trim()).filter(Boolean));
      setMonitorApplications(options);
      if (preLogin) setApplicationToMonitor((current) => availableApplication(current, options));
    } catch (_error) {
      // A failed request is not proof that the selected application was removed.
      setMonitoringApps((current) => ({ ...current, loading: false, error: "Unable to refresh application workspaces. Retry when the registry is available." }));
    }
  }

  async function searchGuidanceDocs() {
    const query = String(guidanceQuery || "").trim();
    if (!query) {
      setGuidanceState({ loading: false, rows: [], error: "Enter search text to find guidance." });
      return;
    }
    setGuidanceState({ loading: true, rows: [], error: "" });
    try {
      const params = new URLSearchParams({ query, limit: "8" });
      const payload = await fetchJson(`/api-gateway/rag/search?${params.toString()}`, authenticatedOptions());
      const rows = payload?.matches || payload?.data?.matches || [];
      setGuidanceState({ loading: false, rows: Array.isArray(rows) ? rows : [], error: "" });
    } catch (error) {
      setGuidanceState({ loading: false, rows: [], error: error.message });
    }
  }





  async function runWorkflow(flowId) {
    const normalized = String(flowId || "").trim();
    if (!normalized) {
      return;
    }
    setWorkflowState({ loading: true, result: null, error: "" });
    try {
      const payload = await fetchJson(`/api-gateway/sample/${normalized}/workflow`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      setWorkflowState({ loading: false, result: payload, error: "" });
      await Promise.all([loadRecentAlerts(), loadGatewaySummary(), loadGatewayRecent(), loadIncidentMetadata(), loadClosedIncidents()]);
    } catch (error) {
      setWorkflowState({ loading: false, result: null, error: error.message });
    }
  }



  function coerceText(value, fallback = "") {
    const text = String(value ?? "").trim();
    return text || fallback;
  }

  function alertAnalysisReady(payload) {
    const data = unwrap(payload);
    const workflow = data?.workflow && typeof data.workflow === "object" ? data.workflow : data;
    const recommendation = workflow?.recommendation && typeof workflow.recommendation === "object"
      ? workflow.recommendation
      : data?.recommendation && typeof data.recommendation === "object"
        ? data.recommendation
        : {};
    const metadata = recommendation?.metadata && typeof recommendation.metadata === "object"
      ? recommendation.metadata
      : {};
    const rcaAnalysis = metadata?.rca_analysis && typeof metadata.rca_analysis === "object"
      ? metadata.rca_analysis
      : {};
    const impactAnalysis = metadata?.impact_analysis && typeof metadata.impact_analysis === "object"
      ? metadata.impact_analysis
      : {};
    const hasRcaText = Boolean(
      coerceText(data?.rootCause)
      || coerceText(recommendation?.root_cause)
      || coerceText(rcaAnalysis?.root_cause)
    );
    const hasImpactText = Boolean(
      coerceText(data?.impact)
      || coerceText(recommendation?.impact)
      || coerceText(impactAnalysis?.impact_summary)
      || coerceText(impactAnalysis?.customer_impact)
      || coerceText(impactAnalysis?.service_impact)
    );
    const hasEvidence = Array.isArray(rcaAnalysis?.evidence_used) && rcaAnalysis.evidence_used.length > 0;
    const discovery = metadata?.discovery_report && typeof metadata.discovery_report === "object"
      ? metadata.discovery_report
      : workflow?.context?.metadata?.discovery_report && typeof workflow.context.metadata.discovery_report === "object"
        ? workflow.context.metadata.discovery_report
        : {};
    const discoveryEvidence = Array.isArray(discovery?.evidence) ? discovery.evidence : [];
    const isProvisional = workflow?.mode === "alert-only-fallback"
      || metadata?.fallback === true
      || metadata?.fallback_reason === "No linked incident projection exists for this alert yet.";
    return !isProvisional
      && hasRcaText
      && hasImpactText
      && (hasEvidence || discoveryEvidence.length > 0);
  }

  async function waitForAlertAnalysis(alertId, options = {}) {
    const normalized = String(alertId || "").trim();
    if (!normalized) {
      return { ready: false, payload: null, attempts: 0 };
    }
    const attempts = Number(options.attempts || 40);
    const intervalMs = Number(options.intervalMs || 3000);
    const requestId = String(options.requestId || "").trim();
    const incidentId = String(options.incidentId || "").trim();
    const expectedRecommendationId = String(options.expectedRecommendationId || "").trim();
    if (!requestId || !incidentId || !expectedRecommendationId) {
      return { ready: false, payload: null, attempts: 0 };
    }
    let latestPayload = null;
    let statusReady = false;
    for (let index = 0; index < attempts; index += 1) {
      try {
        if (!statusReady) {
          const status = await fetchJson(
            `/api-gateway/analysis/requests/${encodeURIComponent(requestId)}/status?incident_id=${encodeURIComponent(incidentId)}`,
            authenticatedOptions({ timeoutMs: 10000, maxAttempts: 1 }),
          );
          const outcome = analysisRequestOutcome(status, expectedRecommendationId);
          if (outcome.terminalFailure) {
            return { ready: false, terminal: true, status, error: analysisFailureMessage(status), payload: latestPayload, attempts: index + 1 };
          }
          statusReady = outcome.ready;
        }
        if (statusReady) {
          // Hydrate the full cockpit once, after the indexed completion signal.
          const payload = await fetchJson(`/api-gateway/alerts/${normalized}/processed-result`, authenticatedOptions({
            timeoutMs: 120000,
            maxAttempts: 4,
          }));
          latestPayload = payload;
          const data = unwrap(payload) || {};
          if (canHydrateCompletedAnalysis(statusReady, data, expectedRecommendationId)) {
            return { ready: true, payload, attempts: index + 1 };
          }
        }
      } catch (_error) {
        // Regenerated alerts can race backend indexing; retry until timeout.
      }
      if (index < attempts - 1) {
        await new Promise((resolve) => {
          window.setTimeout(resolve, intervalMs);
        });
      }
    }
    return { ready: false, payload: latestPayload, attempts };
  }

  async function regenerateSelectedAlertAnalysis(modeOverride) {
    if (!selectedAlertRow || selectedAlertRegeneration.loading) {
      return;
    }
    const canonicalIncidentId = String(selectedAlertWorkflow?.incident?.id || selectedAlertWorkflow?.incident_id || "").trim();
    if (!canonicalIncidentId) {
      setSelectedAlertRegeneration({
        loading: false,
        message: "This alert was deduplicated or is still awaiting incident correlation. RCA runs only for a persisted canonical incident.",
        error: "",
      });
      return;
    }
    const alertId = String(selectedAlertRow?.id || selectedAlertRow?.alert_id || selectedAlertId || "").trim();
    const requestedMode = typeof modeOverride === "string" && ["smart", "fresh", "cache"].includes(modeOverride)
      ? modeOverride
      : rcaAnalysisMode;
    setSelectedAlertRegeneration({ loading: true, message: "", error: "" });
    try {
      if (!ALERT_UUID_PATTERN.test(alertId)) {
        throw new Error("The alert is still being persisted. Wait for its canonical alert ID, then retry RCA.");
      }
      const command = await fetchJson(`/api-gateway/analysis/alerts/${encodeURIComponent(alertId)}/regenerate`, authenticatedOptions({
        method: "POST",
        body: JSON.stringify({ mode: requestedMode }),
        timeoutMs: 30000,
        maxAttempts: 1,
      }));
      const acceptedRequestId = String(command?.request_id || "").trim();
      const acceptedIncidentId = String(command?.incident_id || selectedAlertWorkflow?.incident?.id || "").trim();
      const expectedRecommendationId = String(command?.expected_recommendation_id || "").trim();
      setSelectedAlertRegeneration({
        loading: true,
        message: acceptedRequestId
          ? `Analysis request ${acceptedRequestId.slice(0, 8)} accepted. Collecting evidence and generating RCA in the governed backend workflow…`
          : "Analysis request accepted. Collecting evidence and generating RCA in the governed backend workflow…",
        error: "",
      });
      const persistedAnalysis = await waitForAlertAnalysis(alertId, {
        attempts: 100,
        intervalMs: Number(command?.poll_after_ms || 3000),
        requestId: acceptedRequestId,
        incidentId: acceptedIncidentId,
        expectedRecommendationId,
      });
      if (persistedAnalysis.terminal) {
        throw new Error(persistedAnalysis.error);
      }
      if (persistedAnalysis.payload) {
        // Keep React Query and the local cockpit state on the same immutable
        // recommendation revision. Without this write-through, a subsequent
        // detail hydration can restore the pre-regeneration cached payload.
        queryClient.setQueryData(["alert-processed-result", alertId], persistedAnalysis.payload);
        setSelectedAlertData((current) => String(current.alertId || "") === alertId
          ? { loading: false, payload: persistedAnalysis.payload, error: "", alertId }
          : current);
      } else {
        await loadAlertDetails(alertId);
      }
      await loadSelectedAlertDocumentLinks(alertId);
      let catalogStatus = null;
      try {
        catalogStatus = unwrap(await fetchJson(
          `/api-gateway/knowledge-development/incidents/${encodeURIComponent(acceptedIncidentId)}/catalog-status`,
          authenticatedOptions({ timeoutMs: 15000, maxAttempts: 2 }),
        ));
      } catch (_error) {
        // Analysis completion remains authoritative if catalog status is
        // temporarily unavailable; the scheduled learner provides recovery.
      }
      if (catalogStatus) {
        setSelectedCatalogStatus({ loading: false, incidentId: acceptedIncidentId, data: catalogStatus, error: "" });
      }
      const catalogProgress = catalogStatus?.candidate_stage
        ? ` Catalog: ${String(catalogStatus.candidate_stage).replaceAll("_", " ")} with ${Number(catalogStatus.evidence_sources || 0)} independent source(s).${catalogStatus.execution_eligible ? " Execution eligible." : " Safety review remains required."}`
        : "";
      const completedWorkflow = persistedAnalysis.payload?.workflow && typeof persistedAnalysis.payload.workflow === "object"
        ? persistedAnalysis.payload.workflow
        : persistedAnalysis.payload;
      const completedRecommendation = completedWorkflow?.recommendation && typeof completedWorkflow.recommendation === "object"
        ? completedWorkflow.recommendation
        : {};
      const completedMetadata = completedRecommendation?.metadata && typeof completedRecommendation.metadata === "object"
        ? completedRecommendation.metadata
        : {};
      const completedRca = completedMetadata?.rca_analysis && typeof completedMetadata.rca_analysis === "object"
        ? completedMetadata.rca_analysis
        : {};
      const rcaGrounded = String(completedMetadata?.rca_status || "").toLowerCase() === "grounded"
        && Array.isArray(completedRca.evidence_used)
        && completedRca.evidence_used.length > 0;
      const completionState = rcaGrounded
        ? "RCA grounded with accepted evidence."
        : "Analysis completed, but the RCA remains ungrounded; resolution stays blocked until evidence is cited.";
      setSelectedAlertRegeneration({
        loading: false,
        message: persistedAnalysis.ready
          ? requestedMode === "fresh"
            ? `Fresh context collected for alert ${alertId}. ${completionState}${catalogProgress}`
            : requestedMode === "cache"
              ? `Verified cached context loaded for alert ${alertId}. ${completionState}${catalogProgress}`
              : `Smart analysis completed for alert ${alertId}; verified context was reused when eligible. ${completionState}${catalogProgress}`
          : `Analysis for alert ${alertId} is still running in the backend. You can leave this page and refresh the incident later.`,
        error: "",
      });
      void Promise.all([loadRecentAlerts(), loadLandingPadRecent(), loadGatewayRecent(), loadGatewaySummary()])
        .catch(() => {});
    } catch (error) {
      setSelectedAlertRegeneration({
        loading: false,
        message: "",
        error: String(error?.message || "Unable to run the selected RCA analysis mode"),
      });
    }
  }

  async function submitAiRecommendationFeedback(feedback) {
    const payload = typeof feedback === "string" ? { decision: feedback } : feedback;
    const decision = String(payload?.decision || "").trim().toLowerCase();
    if (!selectedAlertRecommendationId || aiFeedbackState.loading) {
      setAiFeedbackState({ loading: false, decision: "", message: "", error: "Feedback requires a persisted recommendation ID." });
      return;
    }
    setAiFeedbackState({ loading: true, decision, message: "", error: "" });
    try {
      const response = unwrap(await fetchJson(
        `/api-gateway/evaluations/by-recommendation/${encodeURIComponent(selectedAlertRecommendationId)}/feedback`,
        authenticatedOptions({
          method: "POST",
          body: JSON.stringify({
            ...payload,
            decision,
            approver: adminSession?.user?.username || "operator",
            comment: String(payload?.comment || `RCA recommendation marked ${decision} from the incident cockpit.`),
          }),
        }),
      ));
      setAiFeedbackState({
        loading: false,
        decision,
        message: response?.updated === false
          ? "Feedback received, but no persisted evaluation was linked to this recommendation."
          : `Feedback recorded: ${decision}.`,
        error: "",
      });
    } catch (error) {
      setAiFeedbackState({ loading: false, decision: "", message: "", error: String(error?.message || "Unable to record feedback") });
    }
  }

  function adminHeaders() {
    const token = String(adminSession.accessToken || "").trim();
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  function expireAdminSession() {
    clearStoredSession(); const expired = {
      loading: false,
      accessToken: "",
      refreshToken: "",
      user: null,
      error: "Session expired. Please sign in again.",
    };
    adminSessionRef.current = expired;
    setAdminSession(expired);
    setAdminUsers({ loading: false, rows: [], error: "" });
    setActiveTab("home");
  }

  async function refreshAdminAccessToken() {
    if (adminRefreshPromiseRef.current) {
      return adminRefreshPromiseRef.current;
    }
    const refreshToken = String(adminSessionRef.current?.refreshToken || "").trim();
    if (!refreshToken) {
      expireAdminSession();
      return null;
    }
    adminRefreshPromiseRef.current = (async () => {
      try {
        const response = await fetchJson("/api-gateway/auth/refresh", {
          method: "POST",
          maxAttempts: 1,
          body: JSON.stringify({ refresh_token: refreshToken }),
        });
        const renewed = {
          loading: false,
          accessToken: response?.access_token || "",
          refreshToken: response?.refresh_token || "",
          user: response?.user || adminSessionRef.current?.user || null,
          error: "",
        };
        if (!renewed.accessToken || !renewed.refreshToken) {
          throw new Error("Token refresh returned an incomplete session.");
        }
        adminSessionRef.current = renewed; storeSessionTokens(renewed);
        setAdminSession(renewed);
        return { Authorization: `Bearer ${renewed.accessToken}` };
      } catch (_error) {
        expireAdminSession();
        return null;
      } finally {
        adminRefreshPromiseRef.current = null;
      }
    })();
    return adminRefreshPromiseRef.current;
  }

  function authenticatedOptions(options = {}) {
    const headers = adminHeaders();
    return {
      ...options,
      authenticated: true,
      onUnauthorized: refreshAdminAccessToken,
      headers: {
        ...headers,
        ...(options.headers || {}),
      },
    };
  }
  const evidenceDraftApi = useEvidenceDraftBundle({ fetchJson, authenticatedOptions, unwrap });

  function resetNavigationAfterLogin() {
    const incidentDestination = /^\/incidents\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(currentPath) ? currentPath : "/";
    // App is intentionally kept mounted while the login screen is visible, so
    // selections from the previous session would otherwise survive a new
    // authentication. Reset every persistent workspace to its first tab and
    // preserve explicit incident links while resetting prior session selections.
    skipNextActiveTabNavigationRef.current = true;
    setActiveTab("home");
    setGlobalOperationsView("search");
    setIngestionStreamSection("active");
    setIngestionStreamView("");
    setHomeDetailTab("evidence");
    setRcaDetailView("simple");
    setDiagnosticsDetailTab("pipeline");
    setAdminWorkspace("users");
    setAlertKnowledgeView("onboarding");
    setSelectedAlertId("");
    setSelectedApprovalIncidentId("");
    onNavigatePath?.(incidentDestination);
  }

  async function adminLogin(event) {
    event.preventDefault();
    setAdminSession((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = await fetchJson("/api-gateway/auth/login", {
        method: "POST",
        body: JSON.stringify({
          username: String(adminAuthForm.username || "").trim(),
          password: String(adminAuthForm.password || ""),
          device: String(adminAuthForm.device || "react-ui").trim(),
        }),
      });
      const authenticatedSession = {
        loading: false,
        accessToken: response?.access_token || "",
        refreshToken: response?.refresh_token || "",
        user: response?.user || null,
        error: "",
      };
      adminSessionRef.current = authenticatedSession; storeSessionTokens(authenticatedSession);
      setAdminSession(authenticatedSession);
      resetNavigationAfterLogin();
    } catch (error) {
      setAdminSession((current) => ({ ...current, loading: false, error: error.message }));
    }
  }

  async function oidcLogin() {
    setAdminSession((current) => ({ ...current, loading: true, error: "" }));
    try {
      await beginOidcLogin(authConfig);
    } catch (error) {
      setAdminSession((current) => ({ ...current, loading: false, error: String(error?.message || error) }));
    }
  }

  async function adminLogout() {
    clearStoredSession(); const headers = adminHeaders();
    try {
      if (headers.Authorization) {
        await fetchJson("/api-gateway/auth/logout", { method: "POST", headers, body: JSON.stringify({}) });
      }
    } catch (_error) {
      // Ignore logout errors and clear local session regardless.
    }
    const clearedSession = { loading: false, accessToken: "", refreshToken: "", user: null, error: "" };
    adminSessionRef.current = clearedSession;
    setAdminSession(clearedSession);
    setAdminUsers({ loading: false, rows: [], error: "" });
    setAdminEditUser({ id: null, username: "", email: "", first_name: "", last_name: "", role_id: 1, status: "active", is_active: true });
    setAdminEditPanelOpen(false);
    setAdminResetPasswordForm({ user_id: null, new_password: "" });
    setActiveTab("home");
  }

  async function loadAdminUsersAndRoles() {
    const headers = adminHeaders();
    if (!headers.Authorization) {
      return;
    }
    setAdminUsers((current) => ({ ...current, loading: true, error: "" }));
    try {
      const [usersPayload, rolesPayload] = await Promise.all([
        fetchJson("/api-gateway/users?page=1&page_size=50", authenticatedOptions()),
        fetchJson("/api-gateway/roles", authenticatedOptions()),
      ]);
      const usersRows = usersPayload?.rows || usersPayload?.data?.rows || [];
      const rolesRows = rolesPayload?.data || rolesPayload || [];
      setAdminUsers({ loading: false, rows: Array.isArray(usersRows) ? usersRows : [], error: "" });
      setAdminRoles(Array.isArray(rolesRows) ? rolesRows : []);
    } catch (error) {
      setAdminUsers({ loading: false, rows: [], error: error.message });
    }
  }

  async function createAdminUser(event) {
    event.preventDefault();
    const headers = adminHeaders();
    if (!headers.Authorization) {
      setAdminUsers((current) => ({ ...current, error: "Admin login required." }));
      return;
    }
    setAdminUsers((current) => ({ ...current, loading: true, error: "" }));
    try {
      await fetchJson("/api-gateway/users", authenticatedOptions({
        method: "POST",
        body: JSON.stringify({
          ...adminCreateUser,
          role_id: Number(adminCreateUser.role_id || 1),
        }),
      }));
      setAdminCreateUser({
        username: "",
        email: "",
        password: "",
        first_name: "",
        last_name: "",
        role_id: 1,
        status: "active",
        is_active: true,
      });
      await loadAdminUsersAndRoles();
    } catch (error) {
      setAdminUsers((current) => ({ ...current, loading: false, error: error.message }));
    }
  }

  function selectAdminUserForEdit(row) {
    const selectedId = Number(row?.id || 0);
    if (!selectedId) {
      return;
    }
    setAdminEditUser({
      id: selectedId,
      username: String(row?.username || "").trim(),
      email: String(row?.email || "").trim(),
      first_name: String(row?.first_name || "").trim(),
      last_name: String(row?.last_name || "").trim(),
      role_id: Number(row?.role_id || 1),
      status: String(row?.status || "active").trim(),
      is_active: Boolean(row?.is_active),
    });
    setAdminEditPanelOpen(true);
    setAdminResetPasswordForm((current) => ({ ...current, user_id: selectedId, new_password: "" }));
  }

  async function updateAdminUser(event) {
    event.preventDefault();
    const headers = adminHeaders();
    if (!headers.Authorization || !adminEditUser.id) {
      setAdminUsers((current) => ({ ...current, error: "Admin login and selected user are required." }));
      return;
    }
    setAdminUsers((current) => ({ ...current, loading: true, error: "" }));
    try {
      await fetchJson(`/api-gateway/users/${adminEditUser.id}`, authenticatedOptions({
        method: "PUT",
        body: JSON.stringify({
          email: String(adminEditUser.email || "").trim(),
          first_name: String(adminEditUser.first_name || "").trim(),
          last_name: String(adminEditUser.last_name || "").trim(),
          role_id: Number(adminEditUser.role_id || 1),
          status: String(adminEditUser.status || "active").trim(),
          is_active: Boolean(adminEditUser.is_active),
        }),
      }));
      await loadAdminUsersAndRoles();
      setAdminEditPanelOpen(false);
    } catch (error) {
      setAdminUsers((current) => ({ ...current, loading: false, error: error.message }));
    }
  }

  async function resetAdminUserPassword(event) {
    event.preventDefault();
    const headers = adminHeaders();
    const selectedUserId = Number(adminResetPasswordForm.user_id || 0);
    if (!headers.Authorization || !selectedUserId) {
      setAdminUsers((current) => ({ ...current, error: "Select a user to reset password." }));
      return;
    }
    setAdminUsers((current) => ({ ...current, loading: true, error: "" }));
    try {
      await fetchJson(`/api-gateway/users/${selectedUserId}/reset-password`, authenticatedOptions({
        method: "PATCH",
        body: JSON.stringify({ new_password: String(adminResetPasswordForm.new_password || "") }),
      }));
      setAdminResetPasswordForm((current) => ({ ...current, new_password: "" }));
      await loadAdminUsersAndRoles();
    } catch (error) {
      setAdminUsers((current) => ({ ...current, loading: false, error: error.message }));
    }
  }

  function applyProjectOnboardingRow(row) {
    if (!row || typeof row !== "object") {
      return;
    }
    const projectPayload = row.project_payload && typeof row.project_payload === "object" ? row.project_payload : {};
    const connectivityPayload = row.connectivity_payload && typeof row.connectivity_payload === "object" ? row.connectivity_payload : {};
    const monitoring = extractMonitoringToolAndUrl(connectivityPayload);
    setSelectedOnboardingProject(String(row.project_name || projectPayload.name || "").trim());
    setOnboardingForm((curr) => ({
      ...curr,
      name: String(row.project_name || projectPayload.name || curr.name || "").trim(),
      owner_team: String(row.owner_team || projectPayload.owner_team || curr.owner_team || "").trim(),
      description: String(projectPayload.description || "").trim(),
      business_service: String(projectPayload.business_service || "").trim(),
      owner_email: String(projectPayload.owner_email || "").trim(),
      criticality: String(projectPayload.criticality || "medium").trim(),
      cost_center: String(projectPayload.cost_center || "").trim(),
      repository_url: String(projectPayload.repository_url || "").trim(),
      environment: String(row.environment || projectPayload.environment || curr.environment || "prod").trim(),
      region: String(row.region || projectPayload.region || curr.region || "").trim(),
      deployment_mode: String(connectivityPayload.deployment_mode || curr.deployment_mode || "cloud_neutral").trim(),
      monitoring_tool: monitoring.tool,
      monitoring_url: monitoring.url,
      prometheus_url: monitoring.tool === "prometheus" ? monitoring.url : "",
      new_relic_url: monitoring.tool === "new_relic" ? monitoring.url : "",
      datadog_url: monitoring.tool === "datadog" ? monitoring.url : "",
      logs_url: String(connectivityPayload.logs_url || "").trim(),
      traces_url: String(connectivityPayload.traces_url || "").trim(),
      telemetry_url: String(connectivityPayload.telemetry_url || "").trim(),
      ticketing_url: String(connectivityPayload.ticketing_url || "").trim(),
      email_url: String(connectivityPayload.email_url || "").trim(),
      healthcheck_url: String(connectivityPayload.healthcheck_url || "").trim(),
      network_zone: String(connectivityPayload.network_zone || "").trim(),
      connection_auth_type: String(connectivityPayload.monitoring_sources?.[0]?.auth_type || "none").trim(),
      connection_secret_ref: String(connectivityPayload.monitoring_sources?.[0]?.secret_ref || "").trim(),
      context_strategy: String(connectivityPayload.context_strategy || "auto").trim(),
      azure_subscription_id: String(connectivityPayload.azure_subscription_id || curr.azure_subscription_id || "").trim(),
      azure_resource_group: String(connectivityPayload.azure_resource_group || curr.azure_resource_group || "").trim(),
      azure_service_bus_namespace: String(connectivityPayload.azure_service_bus_namespace || curr.azure_service_bus_namespace || "").trim(),
      azure_service_bus_topic: String(connectivityPayload.azure_service_bus_topic || curr.azure_service_bus_topic || "").trim(),
      azure_service_bus_subscription: String(connectivityPayload.azure_service_bus_subscription || curr.azure_service_bus_subscription || "").trim(),
      azure_content_safety_enabled: Boolean(connectivityPayload.azure_content_safety_enabled ?? curr.azure_content_safety_enabled),
      azure_content_safety_endpoint: String(connectivityPayload.azure_content_safety_endpoint || curr.azure_content_safety_endpoint || "").trim(),
      assignment_project: String(row.project_name || projectPayload.name || curr.name || "").trim(),
    }));
    setOnboardingProjectMode("existing");
    setExistingRulePipelineForm((curr) => ({
      ...curr,
      platform: monitoring.tool,
      connection_url: monitoring.url,
    }));
    setNewRulePipelineForm((curr) => ({
      ...curr,
      selected_tool: monitoring.tool,
    }));
    setOnboardingSourceDocs({ loading: false, rows: [], error: "" });
  }

  function resetNewProjectOnboardingDraft() {
    setSelectedOnboardingProject("");
    setOnboardingWorkflowSteps([]);
    setOnboardingGeneratedDocs([]);
    setOnboardingSourceDocs({ loading: false, rows: [], error: "" });
    setOnboardingDocApprovalState({ loading: false, error: "", success: "", approved: false });
    setOnboardingForm((curr) => ({
      ...curr,
      name: "",
      owner_team: "",
      description: "",
      business_service: "",
      owner_email: "",
      criticality: "high",
      cost_center: "",
      repository_url: "",
      environment: "prod",
      region: curr.region || "us-east-1",
      monitoring_tool: "prometheus",
      monitoring_url: "http://prometheus:9090",
      prometheus_url: "http://prometheus:9090",
      new_relic_url: "",
      datadog_url: "",
      logs_url: "",
      traces_url: "",
      telemetry_url: "",
      ticketing_url: "",
      email_url: "",
      healthcheck_url: "",
      network_zone: "",
      connection_auth_type: "none",
      connection_secret_ref: "",
      context_strategy: "auto",
      assignment_username: "",
      assignment_project: "",
      onboarding_path: "setup_monitoring",
      start_rule_onboarding: true,
      service_knowledge_prompt: "",
      rule_onboarding_plain_language: "",
    }));
  }

  async function loadModelProviderStatus() {
    setModelProviderStatus((curr) => ({ ...curr, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/model/providers/status", { timeoutMs: 15000, maxAttempts: 3 });
      setModelProviderStatus({ loading: false, data: unwrap(payload), error: "" });
    } catch (error) {
      // Preserve last-known health during a rolling restart. The recurring
      // status refresh replaces stale data when the route is available again.
      setModelProviderStatus((current) => ({ ...current, loading: false, error: error.message }));
    }
  }

  function currentOnboardedApplicationName() {
    return String(selectedOnboardingProject || onboardingForm.name || monitoringAppForm.name || "").trim();
  }

  function findMonitoringApplicationForName(name) {
    const normalized = String(name || "").trim().toLowerCase();
    if (!normalized) {
      return null;
    }
    return (Array.isArray(monitoringApps.rows) ? monitoringApps.rows : []).find((row) => {
      const candidates = [
        row?.id,
        row?.name,
        row?.application,
        row?.project_name,
        row?.service,
      ].map((value) => String(value || "").trim().toLowerCase()).filter(Boolean);
      return candidates.some((candidate) => candidate === normalized || candidate.includes(normalized) || normalized.includes(candidate));
    }) || null;
  }

  async function openOnboardedApplicationDashboard(url = "") {
    const appName = currentOnboardedApplicationName();
    if (appName) {
      const row = findMonitoringApplicationForName(appName);
      const appId = String(row?.id || "").trim();
      if (appId) {
        setSelectedMonitoringAppId(appId);
        loadMonitoringApplicationDetails(appId);
      }
    }
    setDashboardAlertFocus("all");
    setDashboardAlertQuery("");
    setActiveTab("home");
    if (url && typeof window !== "undefined") {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  }

  async function ingestGeneratedOnboardingDocuments(documents) {
    const rows = Array.isArray(documents) ? documents : [];
    if (!rows.length) {
      return { total: 0, ingested: 0, failed: 0 };
    }

    let ingested = 0;
    let failed = 0;
    for (const row of rows) {
      try {
        await fetchJson("/api-gateway/rag/knowledge-drafts", authenticatedOptions({
          method: "POST",
          body: JSON.stringify(row),
        }));
        ingested += 1;
      } catch (_error) {
        failed += 1;
      }
    }
    if (ingested > 0) {
      await loadRagDocs();
    }
    return { total: rows.length, ingested, failed };
  }

  async function approveGeneratedOnboardingDocuments() {
    const docs = Array.isArray(onboardingGeneratedDocs) ? onboardingGeneratedDocs : [];
    if (!docs.length) {
      return;
    }
    setOnboardingDocApprovalState({ loading: true, error: "", success: "", approved: false });
    try {
      const summary = await ingestGeneratedOnboardingDocuments(docs);
      if (summary.failed > 0) {
        setOnboardingDocApprovalState({
          loading: false,
          error: `Approved, but ${summary.failed} document(s) failed to ingest.`,
          success: "",
          approved: false,
        });
        return;
      }
      setOnboardingDocApprovalState({
        loading: false,
        error: "",
        success: `Approved and ingested ${summary.ingested}/${summary.total} document(s).`,
        approved: true,
      });
      setOnboardingReviewAck((current) => ({ ...current, docs: true }));
      setOnboardingState((current) => ({ ...current, success: `Project onboarding saved. Documents approved: ${summary.ingested}/${summary.total}.` }));
      const appName = currentOnboardedApplicationName();
      if (appName) {
        }
      setProjectSetupStep("status");
    } catch (error) {
      setOnboardingDocApprovalState({ loading: false, error: error.message, success: "", approved: false });
    }
  }

  const onboardingDerivedRequirements = useMemo(() => {
    const rows = Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : [];
    const merged = [];
    rows.forEach((row) => {
      (Array.isArray(row?.derived_requirements) ? row.derived_requirements : []).forEach((item) => {
        const token = cleanRuleIntentLine(item);
        if (token && !merged.some((existing) => existing.toLowerCase() === token.toLowerCase())) {
          merged.push(token);
        }
      });
    });
    return merged;
  }, [onboardingSourceDocs.rows]);

  const onboardingKnowledgePack = knowledgePackState.draft?.knowledge_pack || knowledgePackState.draft || null;
  const onboardingKnowledgeFacts = onboardingKnowledgePack?.facts || {};
  const onboardingKnowledgeValidation = onboardingKnowledgePack?.validation || {};
  const KNOWLEDGE_LIST_FACTS = new Set(["dependencies", "alert_patterns", "commands", "rollback_plan", "validation_checks"]);
  const KNOWLEDGE_FACT_LABELS = {
    service: "Service",
    environment: "Environment",
    owner_team: "Owner team",
    dependencies: "Dependencies",
    alert_patterns: "Alert patterns",
    commands: "Commands or queries",
    rollback_plan: "Rollback or failback",
    validation_checks: "Validation checks",
  };
  const KNOWLEDGE_FACT_HINTS = {
    service: "Example: kaiops-core1 or checkout-api",
    environment: "Example: prod, qa, dev",
    dependencies: "Example: mysql, redis, rabbitmq, kafka",
    commands: "Example: kubectl logs deployment/service -n prod",
    rollback_plan: "Example: rollback deployment to previous version and restore config",
    validation_checks: "Example: verify /health, Prometheus target up, and error rate recovered",
    alert_patterns: "Example: alert when exporter is down for 5m",
    owner_team: "Example: platform-ops",
  };
  const KNOWLEDGE_FACT_QUESTIONS = {
    service: "Which service or application is this knowledge for?",
    environment: "Which environment should this apply to?",
    owner_team: "Which team owns this service?",
    dependencies: "Which upstream/downstream dependencies should KaiMS check during triage?",
    alert_patterns: "Which alert conditions should create monitoring rules?",
    commands: "Which commands, scripts, or queries are safe for operators to review?",
    rollback_plan: "What rollback or failback plan should be used if remediation fails?",
    validation_checks: "Which checks prove the service recovered?",
  };

  function knowledgeFactDisplayValue(fact) {
    const value = fact?.value;
    if (Array.isArray(value)) {
      return value.join(" | ") || "-";
    }
    return String(value || "-");
  }

  function normalizeKnowledgeCorrectionValue(key, value) {
    const text = String(value || "").trim();
    if (!text) {
      return KNOWLEDGE_LIST_FACTS.has(key) ? [] : "";
    }
    if (KNOWLEDGE_LIST_FACTS.has(key)) {
      return text.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
    }
    return text;
  }

  function knowledgeFactEditValue(key, fact) {
    if (Object.prototype.hasOwnProperty.call(knowledgePackCorrections, key)) {
      return knowledgePackCorrections[key] || "";
    }
    const value = fact?.value;
    if (Array.isArray(value)) {
      return value.join("\n");
    }
    return String(value || "");
  }

  function updateKnowledgeFactCorrection(key, value) {
    setKnowledgePackCorrections((current) => ({
      ...current,
      [key]: value,
    }));
    if (key === "service") {
      setOnboardingForm((current) => ({ ...current, name: value, assignment_project: value }));
    }
    if (key === "environment") {
      setOnboardingForm((current) => ({ ...current, environment: value || current.environment }));
    }
    if (key === "owner_team") {
      setOnboardingForm((current) => ({ ...current, owner_team: value }));
    }
  }

  const correctedKnowledgeFacts = useMemo(() => {
    const next = {};
    Object.entries(onboardingKnowledgeFacts).forEach(([key, fact]) => {
      const correction = knowledgePackCorrections[key];
      const hasCorrection = Object.prototype.hasOwnProperty.call(knowledgePackCorrections, key);
      const normalizedCorrection = normalizeKnowledgeCorrectionValue(key, correction);
      const correctionEmpty = Array.isArray(normalizedCorrection)
        ? normalizedCorrection.length === 0
        : !String(normalizedCorrection || "").trim();
      if (!hasCorrection) {
        next[key] = fact;
        return;
      }
      if (correctionEmpty) {
        next[key] = {
          ...(fact || {}),
          value: normalizedCorrection,
          confidence: 0,
          status: "needs_review",
          sources: Array.isArray(fact?.sources) ? fact.sources : [],
        };
        return;
      }
      // Only trust a backend-verified confidence/status if it was computed from
      // the exact text currently in the box. If the user has typed something
      // new since the last revalidation call, treat it as unverified again
      // rather than keep showing a stale "accepted" badge.
      const validatedSnapshot = knowledgePackRevalidation.validatedCorrections?.[key];
      const backendFact = validatedSnapshot === correction ? knowledgePackRevalidation.facts?.[key] : null;
      next[key] = backendFact
        ? {
          // Keep backendFact.value as-is (what the backend actually detected —
          // may legitimately be empty if the correction didn't match anything).
          // The edit textarea itself reads straight from knowledgePackCorrections,
          // so it still shows exactly what the user typed regardless of this.
          ...backendFact,
          sources: [...(Array.isArray(backendFact.sources) ? backendFact.sources : []), "user-confirmed"],
        }
        : {
          ...(fact || {}),
          value: normalizedCorrection,
          confidence: 0,
          status: "pending_validation",
          sources: [...(Array.isArray(fact?.sources) ? fact.sources : []), "user-confirmed"],
        };
    });
    return next;
  }, [knowledgePackCorrections, onboardingKnowledgeFacts, knowledgePackRevalidation]);
  const knowledgeReviewFields = useMemo(
    () => Object.entries(correctedKnowledgeFacts).filter(([, fact]) => {
      const value = fact?.value;
      const empty = Array.isArray(value) ? value.length === 0 : !String(value || "").trim();
      return empty || Number(fact?.confidence || 0) < 0.78 || String(fact?.status || "") === "needs_review";
    }),
    [correctedKnowledgeFacts],
  );
  const correctedKnowledgeConfidence = useMemo(() => {
    const rows = Object.values(correctedKnowledgeFacts);
    if (!rows.length) {
      return Number(onboardingKnowledgeValidation.overall_confidence || 0);
    }
    return rows.reduce((sum, fact) => sum + Number(fact?.confidence || 0), 0) / rows.length;
  }, [correctedKnowledgeFacts, onboardingKnowledgeValidation.overall_confidence]);
  const knowledgeReviewReady = Boolean(onboardingKnowledgePack) && knowledgeReviewFields.length === 0;
  const knowledgeHasUnvalidatedInput = Boolean(
    (Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : []).some((row) => String(row?.text || "").trim() && !String(row?.warning || "").trim())
    && onboardingKnowledgePack
    && !knowledgePackState.approved
  );
  const knowledgeReviewSummary = useMemo(() => {
    if (!onboardingKnowledgePack) {
      return "Describe the service, alerts, dependencies, checks, commands, rollback, and owner. KaiMS will extract the details for review.";
    }
    if (knowledgeReviewReady) {
      return "All required details are accepted. Review the table once, then approve Service Knowledge.";
    }
    return `${knowledgeReviewFields.length} detail${knowledgeReviewFields.length === 1 ? "" : "s"} need input before validation can pass.`;
  }, [knowledgeReviewFields.length, knowledgeReviewReady, onboardingKnowledgePack]);

  useEffect(() => {
    if (!onboardingKnowledgePack || !Object.keys(onboardingKnowledgeFacts).length) {
      return;
    }
    const factValue = (key) => {
      const fact = onboardingKnowledgeFacts[key] || {};
      const value = fact.value;
      if (Array.isArray(value)) {
        return String(value[0] || "").trim();
      }
      return String(value || "").trim();
    };
    const service = factValue("service");
    const environment = factValue("environment");
    const ownerTeam = factValue("owner_team");
    setOnboardingForm((current) => {
      const next = { ...current };
      if (service && (!String(current.name || "").trim() || ["kaiops-project", "service"].includes(String(current.name || "").trim().toLowerCase()))) {
        next.name = service;
        next.assignment_project = service;
      }
      if (environment && (!String(current.environment || "").trim() || String(current.environment || "").trim() === "prod")) {
        next.environment = environment;
      }
      if (ownerTeam && (!String(current.owner_team || "").trim() || String(current.owner_team || "").trim() === "platform-ops")) {
        next.owner_team = ownerTeam;
      }
      return next;
    });
  }, [onboardingKnowledgeFacts, onboardingKnowledgePack]);

  function buildKnowledgePackPayload(rows = onboardingSourceDocs.rows) {
    const validRows = (Array.isArray(rows) ? rows : []).filter((row) => String(row?.text || "").trim() && !String(row?.warning || "").trim());
    return {
      service: String(onboardingForm.name || monitoringAppForm.name || "kaiops-project").trim(),
      environment: String(onboardingForm.environment || monitoringAppForm.environment || "prod").trim(),
      owner_team: String(onboardingForm.owner_team || monitoringAppForm.owner_team || "platform-ops").trim(),
      documents: validRows.map((row) => ({
        name: String(row?.name || "uploaded-document").trim(),
        category: String(row?.category || "knowledge_pack").trim(),
        text: String(row?.text || ""),
        excerpt: String(row?.excerpt || ""),
      })),
    };
  }

  async function draftKnowledgePackFromPrompt() {
    const text = String(onboardingForm.service_knowledge_prompt || "").trim();
    if (!text) {
      setKnowledgePackState((current) => ({
        ...current,
        loading: false,
        error: "Describe the service knowledge first. Include service, owner, alerts, dependencies, checks, and rollback if known.",
        success: "",
        approved: false,
      }));
      return;
    }
    const serviceName = String(onboardingForm.name || monitoringAppForm.name || "service").trim() || "service";
    const promptRow = {
      category: "knowledge_pack",
      name: `${serviceName}-prompt-service-knowledge.md`,
      size: text.length,
      text,
      excerpt: summarizeUploadedDocument(text),
      derived_requirements: deriveMonitoringRequirementsFromDocument(`${serviceName}-prompt-service-knowledge.md`, text).map(cleanRuleIntentLine).filter(Boolean),
      warning: "",
      source: "prompt",
    };
    const existingRows = Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : [];
    const retainedRows = existingRows.filter((row) => String(row?.source || "") !== "prompt");
    const nextRows = [promptRow, ...retainedRows];
    setOnboardingSourceDocs({ loading: false, rows: nextRows, error: "" });
    await draftKnowledgePack(nextRows);
    if (promptRow.derived_requirements.length) {
      // Replace (not merge) with the current prompt's derived requirements.
      // The previous version folded in whatever was already sitting in
      // rule_onboarding_plain_language — which, after a prior Auto-Complete
      // run, was itself already the merged result of an even earlier run.
      // That let stale requirement lines from long-past prompts accumulate
      // indefinitely across re-runs in the same session, silently bleeding
      // into unrelated projects' generated rule summaries.
      const nextText = promptRow.derived_requirements
        .map(cleanRuleIntentLine)
        .filter(Boolean)
        .filter((line, index, array) => array.findIndex((item) => item.toLowerCase() === line.toLowerCase()) === index)
        .join("\n");
      setOnboardingForm((curr) => ({ ...curr, rule_onboarding_plain_language: nextText }));
      setNewRulePipelineForm((curr) => ({ ...curr, requirements_text: nextText }));
    }
  }

  async function draftKnowledgePack(rows = onboardingSourceDocs.rows) {
    const payload = buildKnowledgePackPayload(rows);
    if (!payload.documents.length) {
      setKnowledgePackState({ loading: false, draft: null, error: "", success: "", approved: false });
      setKnowledgePackCorrections({});
      return null;
    }
    setKnowledgePackState((current) => ({ ...current, loading: true, error: "", success: "", approved: false }));
    try {
      const response = unwrap(await fetchJson("/api-gateway/knowledge-pack/draft", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      })));
      setKnowledgePackCorrections({});
      setKnowledgePackRevalidation({ loading: false, error: "", facts: {}, validatedCorrections: {} });
      setKnowledgePackState({ loading: false, draft: response?.knowledge_pack ? response : { knowledge_pack: response }, error: "", success: "", approved: false });
      return response;
    } catch (error) {
      setKnowledgePackState((current) => ({ ...current, loading: false, error: error.message, success: "", approved: false }));
      return null;
    }
  }

  // Formats manual corrections into a synthetic document using the same
  // keyword vocabulary the backend's extractor looks for (service:, owner:,
  // dependency:, alert:, rollback:, validate:), so re-running extraction with
  // this text folded in can actually detect the corrected values.
  function knowledgePackCorrectionDocumentText() {
    const lines = [];
    const prefixByKey = {
      service: "service",
      environment: "environment",
      owner_team: "owner",
      dependencies: "dependency",
      alert_patterns: "alert",
      rollback_plan: "rollback",
      validation_checks: "validate",
    };
    Object.entries(knowledgePackCorrections).forEach(([key, rawValue]) => {
      const normalized = normalizeKnowledgeCorrectionValue(key, rawValue);
      const items = (Array.isArray(normalized) ? normalized : [normalized]).filter((item) => String(item || "").trim());
      items.forEach((item) => {
        // "commands" must be left as-is: the backend only recognizes lines that
        // already start with a real tool name (kubectl, helm, mysql, etc.).
        lines.push(key === "commands" ? item : `${prefixByKey[key] || key}: ${item}`);
      });
    });
    return lines.join("\n");
  }

  async function revalidateKnowledgeCorrections() {
    const correctionText = knowledgePackCorrectionDocumentText();
    if (!correctionText.trim()) {
      setKnowledgePackRevalidation((current) => ({ ...current, loading: false, error: "No manual edits to validate yet." }));
      return null;
    }
    const basePayload = buildKnowledgePackPayload(onboardingSourceDocs.rows);
    // service/environment/owner_team are matched by the backend from these
    // top-level request fields FIRST, before it ever looks at document text —
    // so a correction to one of these three has to override the field here,
    // not just get folded into the corrections document (which would be
    // silently ignored otherwise).
    const topLevelOverrides = {};
    ["service", "environment", "owner_team"].forEach((key) => {
      if (!Object.prototype.hasOwnProperty.call(knowledgePackCorrections, key)) {
        return;
      }
      const normalized = normalizeKnowledgeCorrectionValue(key, knowledgePackCorrections[key]);
      const text = String(normalized || "").trim();
      if (text) {
        topLevelOverrides[key] = text;
      }
    });
    const payload = {
      ...basePayload,
      ...topLevelOverrides,
      documents: [
        ...basePayload.documents,
        {
          name: "user-corrections.md",
          category: "knowledge_pack",
          text: correctionText,
          excerpt: correctionText.slice(0, 220),
        },
      ],
    };
    const validatedSnapshot = { ...knowledgePackCorrections };
    setKnowledgePackRevalidation((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = unwrap(await fetchJson("/api-gateway/knowledge-pack/validate", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      })));
      const facts = response?.knowledge_pack?.facts || response?.facts || {};
      setKnowledgePackRevalidation({ loading: false, error: "", facts, validatedCorrections: validatedSnapshot });
      return facts;
    } catch (error) {
      setKnowledgePackRevalidation((current) => ({ ...current, loading: false, error: error.message }));
      return null;
    }
  }

  async function approveKnowledgePack() {
    const payload = buildKnowledgePackPayload(onboardingSourceDocs.rows);
    if (!payload.documents.length) {
      setKnowledgePackState((current) => ({ ...current, error: "Upload at least one knowledge document before approval.", success: "" }));
      return;
    }
    setKnowledgePackState((current) => ({ ...current, loading: true, error: "", success: "" }));
    try {
      const acceptedFacts = Object.fromEntries(
        Object.entries(correctedKnowledgeFacts).map(([key, fact]) => [key, fact?.value]),
      );
      const response = unwrap(await fetchJson("/api-gateway/knowledge-pack/approve", authenticatedOptions({
        method: "POST",
        body: JSON.stringify({
          ...payload,
          accepted_facts: acceptedFacts,
          approved_by: currentRole || "administrator",
        }),
      })));
      setKnowledgePackState({
        loading: false,
        draft: response?.knowledge_pack ? response : { knowledge_pack: response },
        error: "",
        success: "Alert Knowledge validated and saved. Next, click Generate Documents & Rules to create reviewable artifacts.",
        approved: true,
      });
      setOnboardingReviewAck((current) => ({ ...current, docs: true }));
      applyUploadedDocumentsToRuleIntent();
      await Promise.all([loadRagDocs(), loadRecentAlerts()]);
    } catch (error) {
      setKnowledgePackState((current) => ({ ...current, loading: false, error: error.message, success: "", approved: false }));
    }
  }

  function buildServiceKnowledgeGeneratedDocs({ projectName, selectedTool }) {
    if (!onboardingKnowledgePack || !onboardingSourceDocRows.length) {
      return [];
    }
    const factValue = (key, fallback = "") => {
      const value = correctedKnowledgeFacts?.[key]?.value;
      return value == null || value === "" ? fallback : value;
    };
    const asList = (value) => Array.isArray(value) ? value.filter((item) => String(item || "").trim()) : [value].filter((item) => String(item || "").trim());
    const service = String(factValue("service", projectName || onboardingForm.name || "service")).trim();
    const environment = String(factValue("environment", onboardingForm.environment || "prod")).trim();
    const owner = String(factValue("owner_team", onboardingForm.owner_team || "platform-ops")).trim();
    const alertPatterns = asList(factValue("alert_patterns", []));
    const dependencies = asList(factValue("dependencies", []));
    const commands = asList(factValue("commands", []));
    const rollback = asList(factValue("rollback_plan", []));
    const checks = asList(factValue("validation_checks", []));
    const sourceLines = onboardingSourceDocRows.map((row) => `- ${String(row?.name || "service-knowledge").trim()}: ${String(row?.excerpt || "").trim()}`).join("\n");
    const bulletSection = (title, rows, empty = "Not provided") => `${title}:\n${rows.length ? rows.map((item) => `- ${item}`).join("\n") : `- ${empty}`}`;
    const metadata = {
      project_name: String(projectName || service).trim(),
      owner_team: owner,
      environment,
      selected_monitoring_tool: String(selectedTool || onboardingForm.monitoring_tool || "prometheus").trim(),
      source_system: "service-knowledge",
      knowledge_confidence: String(correctedKnowledgeConfidence || ""),
    };
    return [
      {
        kind: "runbook",
        alert_id: `${service}-service-knowledge-runbook`,
        alert_type: "service-knowledge-onboarding",
        severity: "high",
        title: `${service} Service Knowledge Runbook`,
        summary: "Generated from uploaded Service Knowledge for triage, RCA, and remediation.",
        content: [
          `Service ${service} in ${environment}.`,
          bulletSection("Alert patterns", alertPatterns),
          bulletSection("Dependencies", dependencies),
          bulletSection("Validation checks", checks),
          bulletSection("Rollback plan", rollback),
          "Source evidence:",
          sourceLines || "- Uploaded Service Knowledge",
        ].join("\n\n"),
        services: [service],
        deployment: environment,
        dependencies,
        commands,
        queries: checks,
        recommended_action: "Use this runbook during alert triage and update it after the first live incident.",
        source_system: "service-knowledge",
        resolved_by: owner,
        metadata,
      },
      {
        kind: "incident",
        alert_id: `${service}-service-knowledge-incident`,
        alert_type: "service-knowledge-baseline",
        severity: "warning",
        title: `${service} Service Knowledge Incident Baseline`,
        summary: "Incident baseline generated from uploaded Service Knowledge.",
        content: [
          `Baseline incident guidance for ${service}.`,
          bulletSection("Expected alert patterns", alertPatterns),
          bulletSection("Known dependencies", dependencies),
          bulletSection("Evidence", [sourceLines].filter(Boolean), "Uploaded Service Knowledge"),
        ].join("\n\n"),
        services: [service],
        deployment: environment,
        source_system: "service-knowledge",
        resolved_by: owner,
        metadata,
      },
    ];
  }

  async function handleOnboardingSourceDocuments(files, category = "other") {
    const rows = Array.from(files || []);
    if (!rows.length) {
      return;
    }
    setOnboardingSourceDocs((current) => ({ ...current, loading: true, error: "" }));
    try {
      const parsedRows = await Promise.all(rows.map(async (file) => {
        const fileName = String(file?.name || "uploaded-document").trim() || "uploaded-document";
        const extension = fileName.includes(".") ? fileName.split(".").pop().toLowerCase() : "";
        if (!ONBOARDING_SOURCE_DOC_EXTENSIONS.has(extension)) {
          return {
            category,
            name: fileName,
            size: Number(file?.size || 0),
            text: "",
            excerpt: "",
            derived_requirements: [],
            warning: `Unsupported file type .${extension || "unknown"}. Use text-based docs such as .md, .txt, .json, .csv, .yaml.`,
          };
        }
        const text = await file.text();
        return {
          category,
          name: fileName,
          size: Number(file?.size || 0),
          text,
          excerpt: summarizeUploadedDocument(text),
          derived_requirements: deriveMonitoringRequirementsFromDocument(fileName, text),
          warning: "",
        };
      }));
      const existingRows = Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : [];
      const retainedRows = existingRows.filter((row) => String(row?.category || "other") !== category);
      const nextRows = [...retainedRows, ...parsedRows];
      setOnboardingSourceDocs({ loading: false, rows: nextRows, error: "" });
      await draftKnowledgePack(nextRows);
      const derived = parsedRows.flatMap((row) => (Array.isArray(row.derived_requirements) ? row.derived_requirements : []));
      if (derived.length) {
        const manual = String(onboardingForm.rule_onboarding_plain_language || "")
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean);
        const combined = [...manual, ...derived].filter(
          (line, index, array) => array.findIndex((item) => item.toLowerCase() === line.toLowerCase()) === index,
        );
        const nextText = combined.join("\n");
        setOnboardingForm((curr) => ({ ...curr, rule_onboarding_plain_language: nextText }));
        setNewRulePipelineForm((curr) => ({ ...curr, requirements_text: nextText }));
      }
    } catch (error) {
      setOnboardingSourceDocs((current) => ({
        loading: false,
        rows: Array.isArray(current?.rows) ? current.rows : [],
        error: String(error?.message || "Failed to read uploaded documents."),
      }));
    }
  }

  async function handleAlertKnowledgeSourceDocument(files) {
    const file = Array.from(files || [])[0];
    if (!file) {
      return;
    }
    const fileName = String(file?.name || "uploaded-document").trim() || "uploaded-document";
    const extension = fileName.includes(".") ? fileName.split(".").pop().toLowerCase() : "";
    setAlertKnowledgeSourceDoc((current) => ({ ...current, loading: true, error: "" }));
    try {
      if (!ONBOARDING_SOURCE_DOC_EXTENSIONS.has(extension)) {
        setAlertKnowledgeSourceDoc({
          loading: false,
          name: fileName,
          size: Number(file?.size || 0),
          text: "",
          excerpt: "",
          error: `Unsupported file type .${extension || "unknown"}. Upload a text-based file such as .md, .txt, .json, .csv, .yaml, or .log.`,
        });
        return;
      }
      const text = await file.text();
      const excerpt = summarizeUploadedDocument(text);
      const derivedRequirements = deriveMonitoringRequirementsFromDocument(fileName, text);
      setAlertKnowledgeSourceDoc({
        loading: false,
        name: fileName,
        size: Number(file?.size || 0),
        text,
        excerpt,
        error: "",
      });
      if (!String(alertKnowledgePrompt || "").trim() && derivedRequirements.length) {
        setAlertKnowledgePrompt(derivedRequirements.slice(0, 6).join("\n"));
      }
    } catch (error) {
      setAlertKnowledgeSourceDoc({
        loading: false,
        name: fileName,
        size: Number(file?.size || 0),
        text: "",
        excerpt: "",
        error: String(error?.message || "Failed to read the uploaded alert knowledge document."),
      });
    }
  }

  function buildAlertKnowledgePromptInput() {
    const prompt = String(alertKnowledgePrompt || "").trim();
    const sourceText = String(alertKnowledgeSourceDoc?.text || "").trim();
    if (!sourceText) {
      return prompt;
    }
    const sourceName = String(alertKnowledgeSourceDoc?.name || "uploaded alert knowledge document").trim();
    const sourceExcerpt = String(alertKnowledgeSourceDoc?.excerpt || "").trim();
    const sourceBlock = [
      `Supporting document: ${sourceName}`,
      sourceExcerpt ? `Extracted summary: ${sourceExcerpt}` : "",
      "Document content:",
      sourceText.slice(0, 12000),
    ].filter(Boolean).join("\n");
    return [prompt, sourceBlock].filter(Boolean).join("\n\n");
  }

  function clearAlertKnowledgeSourceDocument() {
    setAlertKnowledgeSourceDoc({ loading: false, name: "", size: 0, text: "", excerpt: "", error: "" });
  }

  function applyUploadedDocumentsToRuleIntent() {
    if (!onboardingDerivedRequirements.length) {
      return;
    }
    const manual = String(onboardingForm.rule_onboarding_plain_language || "").trim();
    const combined = [
      ...manual.split(/\r?\n/).map(cleanRuleIntentLine).filter(Boolean),
      ...onboardingDerivedRequirements,
    ].map(cleanRuleIntentLine).filter(Boolean).filter((line, index, array) => array.findIndex((item) => item.toLowerCase() === line.toLowerCase()) === index);
    const nextText = combined.join("\n");
    setOnboardingForm((curr) => ({ ...curr, rule_onboarding_plain_language: nextText }));
    setNewRulePipelineForm((curr) => ({ ...curr, requirements_text: nextText }));
  }

  function openRuleWorkflowEditor(row) {
    const connectivityPayload = row?.connectivity_payload && typeof row.connectivity_payload === "object" ? row.connectivity_payload : {};
    const workflowId = String(connectivityPayload.workflow_id || "").trim();
    const resultPayload = connectivityPayload.result && typeof connectivityPayload.result === "object" ? connectivityPayload.result : {};
    setOnboardingRuleEditor({
      workflow_id: workflowId,
      project_name: String(row?.project_name || "").trim(),
      payload_json: JSON.stringify(resultPayload, null, 2),
    });
    setOnboardingRuleEditorState({ loading: false, error: "", success: "" });
    setOnboardingRuleLookup((current) => ({ ...current, workflow_id: workflowId }));
  }

  async function saveRuleWorkflowEditor(event) {
    event.preventDefault();
    const workflowId = String(onboardingRuleEditor.workflow_id || "").trim();
    const projectName = String(onboardingRuleEditor.project_name || onboardingForm.name || "").trim();
    if (!workflowId || !projectName) {
      setOnboardingRuleEditorState({ loading: false, error: "Workflow ID and project name are required.", success: "" });
      return;
    }
    setOnboardingRuleEditorState({ loading: true, error: "", success: "" });
    try {
      const parsedResult = JSON.parse(String(onboardingRuleEditor.payload_json || "{}").trim() || "{}");
      await fetchJson(`/api-gateway/onboarding/rules/pipeline/${encodeURIComponent(workflowId)}`, authenticatedOptions({
        method: "PUT",
        body: JSON.stringify({
          project_name: projectName,
          result: parsedResult,
          status: "updated",
        }),
      }));
      await loadOnboardingAdminData();
      setOnboardingRuleEditorState({ loading: false, error: "", success: "Rule workflow updated." });
    } catch (error) {
      setOnboardingRuleEditorState({ loading: false, error: error.message, success: "" });
    }
  }

  async function deleteRuleWorkflow(workflowId) {
    const normalizedWorkflowId = String(workflowId || "").trim();
    if (!normalizedWorkflowId) {
      return;
    }
    setOnboardingRuleEditorState({ loading: true, error: "", success: "" });
    try {
      await fetchJson(`/api-gateway/onboarding/rules/pipeline/${encodeURIComponent(normalizedWorkflowId)}`, authenticatedOptions({
        method: "DELETE",
      }));
      await loadOnboardingAdminData();
      setOnboardingRuleEditor((current) => (
        String(current.workflow_id || "") === normalizedWorkflowId
          ? { workflow_id: "", project_name: "", payload_json: "" }
          : current
      ));
      setOnboardingRuleEditorState({ loading: false, error: "", success: "Rule workflow deleted." });
    } catch (error) {
      setOnboardingRuleEditorState({ loading: false, error: error.message, success: "" });
    }
  }

  async function deleteProjectOnboarding(projectName) {
    const normalizedProject = String(projectName || "").trim();
    if (!normalizedProject) {
      return;
    }
    setOnboardingState((current) => ({ ...current, loading: true, error: "", success: "" }));
    try {
      await fetchJson(`/api-gateway/onboarding/state/${encodeURIComponent(normalizedProject)}`, authenticatedOptions({
        method: "DELETE",
      }));
      await loadOnboardingAdminData();
      await refreshViewsAfterSubmit();
      setOnboardingState((current) => ({ ...current, success: "Project onboarding deleted." }));
    } catch (error) {
      setOnboardingState((current) => ({ ...current, loading: false, error: error.message, success: "" }));
    }
  }

  async function loadOnboardingAdminData() {
    setOnboardingState((current) => ({ ...current, loading: true, error: "", success: "" }));
    try {
      const [connectivityPayload, statePayload] = await Promise.all([
        fetchJson("/api-gateway/onboarding/connectivity", authenticatedOptions()),
        fetchJson("/api-gateway/onboarding/state", authenticatedOptions()),
      ]);
      const connectivity = connectivityPayload?.data?.connectivity || connectivityPayload?.connectivity || {};
      const rows = statePayload?.data?.rows || statePayload?.rows || [];
      const project = connectivity?.project || {};
      const allRows = Array.isArray(rows) ? rows : [];
      const projectRows = allRows.filter((row) => extractOnboardingProjectName(row));
      const preferredProjectName = String(project?.name || selectedOnboardingProject || "").trim();
      const preferredProjectRow = projectRows.find((row) => extractOnboardingProjectName(row) === preferredProjectName)
        || projectRows[0]
        || null;
      const monitoring = extractMonitoringToolAndUrl(connectivity);
      setOnboardingForm((curr) => ({
        ...curr,
        name: String(project?.name || curr.name || "").trim(),
        owner_team: String(project?.owner_team || curr.owner_team || "").trim(),
        description: String(project?.description || curr.description || "").trim(),
        business_service: String(project?.business_service || curr.business_service || "").trim(),
        owner_email: String(project?.owner_email || curr.owner_email || "").trim(),
        criticality: String(project?.criticality || curr.criticality || "medium").trim(),
        cost_center: String(project?.cost_center || curr.cost_center || "").trim(),
        repository_url: String(project?.repository_url || curr.repository_url || "").trim(),
        environment: String(project?.environment || curr.environment || "prod").trim(),
        region: String(project?.region || curr.region || "").trim(),
        deployment_mode: String(connectivity?.deployment_mode || curr.deployment_mode || "cloud_neutral").trim(),
        monitoring_tool: monitoring.tool,
        monitoring_url: monitoring.url,
        prometheus_url: monitoring.tool === "prometheus" ? monitoring.url : "",
        new_relic_url: monitoring.tool === "new_relic" ? monitoring.url : "",
        datadog_url: monitoring.tool === "datadog" ? monitoring.url : "",
        logs_url: String(connectivity?.logs_url || curr.logs_url || "").trim(),
        traces_url: String(connectivity?.traces_url || curr.traces_url || "").trim(),
        telemetry_url: String(connectivity?.telemetry_url || curr.telemetry_url || "").trim(),
        ticketing_url: String(connectivity?.ticketing_url || curr.ticketing_url || "").trim(),
        email_url: String(connectivity?.email_url || curr.email_url || "").trim(),
        healthcheck_url: String(connectivity?.healthcheck_url || curr.healthcheck_url || "").trim(),
        network_zone: String(connectivity?.network_zone || curr.network_zone || "").trim(),
        connection_auth_type: String(connectivity?.monitoring_sources?.[0]?.auth_type || curr.connection_auth_type || "none").trim(),
        connection_secret_ref: String(connectivity?.monitoring_sources?.[0]?.secret_ref || curr.connection_secret_ref || "").trim(),
        context_strategy: ({ continuous: "auto", immediate: "realtime" }[String(connectivity?.context_strategy || "").trim()] || String(connectivity?.context_strategy || curr.context_strategy || "auto").trim()),
        azure_subscription_id: String(connectivity?.azure_subscription_id || curr.azure_subscription_id || "").trim(),
        azure_resource_group: String(connectivity?.azure_resource_group || curr.azure_resource_group || "").trim(),
        azure_service_bus_namespace: String(connectivity?.azure_service_bus_namespace || curr.azure_service_bus_namespace || "").trim(),
        azure_service_bus_topic: String(connectivity?.azure_service_bus_topic || curr.azure_service_bus_topic || "").trim(),
        azure_service_bus_subscription: String(connectivity?.azure_service_bus_subscription || curr.azure_service_bus_subscription || "").trim(),
        azure_content_safety_enabled: Boolean(connectivity?.azure_content_safety_enabled ?? curr.azure_content_safety_enabled),
        azure_content_safety_endpoint: String(connectivity?.azure_content_safety_endpoint || curr.azure_content_safety_endpoint || "").trim(),
        assignment_project: String(project?.name || curr.name || "").trim(),
      }));
      setExistingRulePipelineForm((curr) => ({ ...curr, platform: monitoring.tool, connection_url: monitoring.url }));
      setNewRulePipelineForm((curr) => ({ ...curr, selected_tool: monitoring.tool }));
      if (preferredProjectRow && onboardingProjectMode !== "new") {
        applyProjectOnboardingRow(preferredProjectRow);
      } else if (String(project?.name || "").trim()) {
        setSelectedOnboardingProject(String(project.name).trim());
      }
      setOnboardingState({ loading: false, connectivity, rows: allRows, error: "", success: "" });
    } catch (error) {
      setOnboardingState({ loading: false, connectivity: {}, rows: [], error: error.message, success: "" });
    }
  }

  async function saveOnboardingConnectivity(event) {
    event.preventDefault();
    const pendingApprovalDocs = Array.isArray(onboardingGeneratedDocs) ? onboardingGeneratedDocs : [];
    const hasPendingApproval = pendingApprovalDocs.length > 0 && !Boolean(onboardingDocApprovalState.approved);
    if (hasPendingApproval) {
      setOnboardingState((current) => ({
        ...current,
        loading: false,
        error: "Please review and approve generated documents before creating/updating another project.",
        success: "",
      }));
      return;
    }
    if (knowledgeHasUnvalidatedInput) {
      setOnboardingState((current) => ({
        ...current,
        loading: false,
        error: "Review the extracted Alert Knowledge, answer missing details, then click Validate & Save Knowledge before generating documents and rules.",
        success: "",
      }));
      return;
    }
    setOnboardingState((current) => ({ ...current, loading: true, error: "", success: "" }));
    setOnboardingGeneratedDocs([]);
    setOnboardingDocApprovalState({ loading: false, error: "", success: "", approved: false });
    setOnboardingReviewAck({ rules: false, docs: false, metadata: false });
    try {
      const onboardingPath = String(onboardingForm.onboarding_path || "setup_monitoring").trim().toLowerCase();
      const selectedMonitoringTool = onboardingPath === "setup_monitoring"
        ? "prometheus"
        : String(onboardingForm.monitoring_tool || "prometheus").trim().toLowerCase();
      const monitoringUrl = simplifyMonitoringUrl(onboardingForm.monitoring_url || (onboardingPath === "setup_monitoring" ? "http://prometheus:9090" : ""));
      const username = String(onboardingForm.assignment_username || "").trim();
      const assignmentProject = String(onboardingForm.name || "").trim();
      const userAssignments = username && assignmentProject ? { [username]: [assignmentProject] } : {};
      const monitoringUrls = {
        prometheus_url: selectedMonitoringTool === "prometheus" ? monitoringUrl : "",
        new_relic_url: selectedMonitoringTool === "new_relic" ? monitoringUrl : "",
        datadog_url: selectedMonitoringTool === "datadog" ? monitoringUrl : "",
      };
      const monitoringSources = buildOnboardingSources(onboardingForm, selectedMonitoringTool, monitoringUrl);
      const payload = {
        project: {
          name: String(onboardingForm.name || "").trim(),
          owner_team: String(onboardingForm.owner_team || "").trim(),
          description: String(onboardingForm.description || "").trim(),
          business_service: String(onboardingForm.business_service || "").trim(),
          owner_email: String(onboardingForm.owner_email || "").trim(),
          criticality: String(onboardingForm.criticality || "medium").trim(),
          cost_center: String(onboardingForm.cost_center || "").trim(),
          repository_url: String(onboardingForm.repository_url || "").trim(),
          environment: String(onboardingForm.environment || "prod").trim(),
          region: String(onboardingForm.region || "").trim(),
        },
        deployment_mode: String(onboardingForm.deployment_mode || "cloud_neutral").trim(),
        ...monitoringUrls,
        monitoring_sources: monitoringSources,
        logs_url: String(onboardingForm.logs_url || "").trim(),
        traces_url: String(onboardingForm.traces_url || "").trim(),
        telemetry_url: String(onboardingForm.telemetry_url || "").trim(),
        ticketing_url: String(onboardingForm.ticketing_url || "").trim(),
        email_url: String(onboardingForm.email_url || "").trim(),
        healthcheck_url: String(onboardingForm.healthcheck_url || "").trim(),
        network_zone: String(onboardingForm.network_zone || "").trim(),
        context_strategy: String(onboardingForm.context_strategy || "auto").trim(),
        azure_subscription_id: String(onboardingForm.azure_subscription_id || "").trim(),
        azure_resource_group: String(onboardingForm.azure_resource_group || "").trim(),
        azure_service_bus_namespace: String(onboardingForm.azure_service_bus_namespace || "").trim(),
        azure_service_bus_topic: String(onboardingForm.azure_service_bus_topic || "").trim(),
        azure_service_bus_subscription: String(onboardingForm.azure_service_bus_subscription || "").trim(),
        azure_content_safety_enabled: Boolean(onboardingForm.azure_content_safety_enabled),
        azure_content_safety_endpoint: String(onboardingForm.azure_content_safety_endpoint || "").trim(),
        user_assignments: userAssignments,
        active_provider: selectedMonitoringTool,
      };

      const plainLanguageRequirements = [
        ...String(onboardingForm.rule_onboarding_plain_language || "")
          .split(/\r?\n/)
          .map(cleanRuleIntentLine)
          .filter(Boolean),
        ...onboardingDerivedRequirements,
      ].map(cleanRuleIntentLine).filter(Boolean).filter((line, index, array) => array.findIndex((item) => item.toLowerCase() === line.toLowerCase()) === index);
      const shouldStartRuleOnboarding = plainLanguageRequirements.length > 0;

      const response = await fetchJson("/api-gateway/onboarding/complete", authenticatedOptions({
        method: "POST",
        body: JSON.stringify({
          project_mode: onboardingProjectMode === "new" ? "new" : "existing",
          onboarding_path: onboardingPath,
          connectivity: payload,
          start_rules_onboarding: shouldStartRuleOnboarding,
          plain_language_requirements: plainLanguageRequirements,
          source_documents: onboardingSourceDocRows.map((row) => ({
            name: String(row?.name || "uploaded-document").trim() || "uploaded-document",
            kind: String(row?.category || classifyOnboardingDocumentType(row?.name, row?.text)).trim().toLowerCase() || "other",
            excerpt: String(row?.excerpt || "").trim(),
            content: String(row?.text || "").slice(0, 12000),
            size: Number(row?.size || 0),
          })),
          selected_monitoring_tool: selectedMonitoringTool,
          generate_documents: true,
        }),
      }));

      const completePayload = unwrap(response);
      const workflowSteps = Array.isArray(completePayload?.workflow_steps) ? completePayload.workflow_steps : [];
      const landingPadSummary = completePayload?.landing_pad_ingestion && typeof completePayload.landing_pad_ingestion === "object"
        ? completePayload.landing_pad_ingestion
        : {};
      setOnboardingWorkflowSteps(workflowSteps);
      setOnboardingLandingPadSummary(landingPadSummary);
      setOnboardingForm((curr) => ({
        ...curr,
        monitoring_tool: selectedMonitoringTool,
        monitoring_url: monitoringUrl,
        assignment_project: String(curr.name || "").trim(),
        ...monitoringUrls,
      }));

      const rulesOnboarding = completePayload?.rules_onboarding || {};
      if (rulesOnboarding?.started && rulesOnboarding?.result) {
        const ruleResult = rulesOnboarding.result;
        setOnboardingRuleRunState({ loading: false, result: ruleResult, error: "" });
        setOnboardingRuleLookup((current) => ({
          ...current,
          workflow_id: String(rulesOnboarding.workflow_id || ruleResult?.workflow_id || current.workflow_id || "").trim(),
        }));
      } else {
        setOnboardingRuleRunState((current) => ({ ...current, loading: false }));
      }
      const backendGeneratedDocs = Array.isArray(completePayload?.rag_documents) ? completePayload.rag_documents : [];
      const generatedDocs = backendGeneratedDocs.length
        ? backendGeneratedDocs
        : buildServiceKnowledgeGeneratedDocs({ projectName: payload.project.name, selectedTool: selectedMonitoringTool });
      setOnboardingGeneratedDocs(generatedDocs);

      setSelectedOnboardingProject(String(payload.project.name || "").trim());
      if (onboardingProjectMode === "new") {
        setOnboardingProjectMode("existing");
      }
      await loadOnboardingAdminData();
      const knowledgeAutoGenerated = onboardingSourceDocCount > 0
        ? await autoGenerateAlertKnowledgeFromSourceDocs({ projectName: payload.project.name, onboardingPath })
        : false;
      await refreshViewsAfterSubmit();
      setOnboardingState((current) => ({
        ...current,
        success: shouldStartRuleOnboarding
          ? generatedDocs.length
            ? `Workflow completed through step ${workflowSteps.length || 0}. Review generated documents and click Approve.`
            : onboardingSourceDocCount > 0
              ? `Workflow completed through step ${workflowSteps.length || 0}. Generated ${generatedDocs.length} Service Knowledge document(s) for review.`
              : `Workflow completed through step ${workflowSteps.length || 0}. No Service Knowledge file was uploaded.`
          : onboardingSourceDocCount > 0
            ? knowledgeAutoGenerated
              ? "Project onboarding saved. Alert Knowledge Onboarding draft was auto-generated from Service Knowledge."
              : "Project onboarding saved. Service Knowledge was detected, but Alert Knowledge auto-generation failed; use manual prompt flow below."
            : "Project onboarding saved. No Service Knowledge uploaded; continue with manual Alert Knowledge prompt and click Create Alert Onboarding Doc.",
      }));
      if (adminWorkspace === "project" && projectSetupStep === "setup") {
        setProjectSetupStep("docs_rules");
      }
      if (onboardingSourceDocCount === 0) {
        setAlertKnowledgeView("onboarding");
      }
    } catch (error) {
      setOnboardingState((current) => ({ ...current, loading: false, error: error.message, success: "" }));
      setOnboardingRuleRunState((current) => ({ ...current, loading: false }));
    }
  }



  async function loadOnboardingRuleCapabilities() {
    setOnboardingRuleCapabilities((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = await fetchJson("/api-gateway/onboarding/rules/capabilities", authenticatedOptions());
      const payload = unwrap(response);
      const rows = Array.isArray(payload?.rows) ? payload.rows : [];
      setOnboardingRuleCapabilities({ loading: false, rows, error: "" });
    } catch (error) {
      setOnboardingRuleCapabilities({ loading: false, rows: [], error: error.message });
    }
  }





  async function lookupOnboardingRuleWorkflow(event) {
    event.preventDefault();
    const workflowId = String(onboardingRuleLookup.workflow_id || "").trim();
    if (!workflowId) {
      setOnboardingRuleLookup((current) => ({ ...current, error: "Workflow ID is required." }));
      return;
    }
    setOnboardingRuleLookup((current) => ({ ...current, loading: true, result: null, error: "" }));
    try {
      const response = await fetchJson(`/api-gateway/onboarding/rules/pipeline/${encodeURIComponent(workflowId)}`, authenticatedOptions());
      const result = unwrap(response);
      setOnboardingRuleLookup((current) => ({ ...current, loading: false, result, error: "" }));
    } catch (error) {
      setOnboardingRuleLookup((current) => ({ ...current, loading: false, result: null, error: error.message }));
    }
  }

  function normalizeDocumentToken(value) {
    return String(value || "")
      .trim()
      .toLowerCase()
      .replace(/[\s_]+/g, "-")
      .replace(/-+/g, "-");
  }

  function collectDocumentTokens(...values) {
    const tokens = new Set();
    values.forEach((value) => {
      if (Array.isArray(value)) {
        value.forEach((item) => collectDocumentTokens(item).forEach((token) => tokens.add(token)));
        return;
      }
      const raw = String(value || "").trim();
      if (!raw) {
        return;
      }
      const normalizedRaw = normalizeDocumentToken(raw);
      if (normalizedRaw) {
        tokens.add(normalizedRaw);
      }
      raw
        .split(/[,;|\s]+/)
        .map(normalizeDocumentToken)
        .filter(Boolean)
        .forEach((token) => tokens.add(token));
    });
    return tokens;
  }

  function getAlertDocumentMatchContext(alertRow) {
    const labels = typeof alertRow?.labels === "object" && alertRow?.labels ? alertRow.labels : {};
    const metadata = typeof alertRow?.metadata === "object" && alertRow?.metadata ? alertRow.metadata : {};
    const ids = collectDocumentTokens(
      alertRow?.alert_id,
      alertRow?.id,
      alertRow?.incident_id,
      metadata?.alert_id,
      metadata?.incident_id,
      labels?.alert_id,
    );
    const alertTypes = collectDocumentTokens(
      alertRow?.alert_type,
      alertRow?.name,
      alertRow?.alert_name,
      alertRow?.alertname,
      labels?.alertname,
      labels?.alert_type,
      labels?.rule,
    );
    const services = collectDocumentTokens(
      alertRow?.service,
      alertRow?.application,
      alertRow?.project,
      alertRow?.project_name,
      alertRow?.component,
      metadata?.service,
      metadata?.application,
      metadata?.project,
      labels?.service,
      labels?.job,
      labels?.application,
      labels?.project,
      labels?.project_name,
      labels?.deployment,
      labels?.namespace,
      labels?.instance,
    );
    const genericServiceDocsAllowed = alertRow?.document_available === true || Boolean(metadata?.runbook_hint);
    return { ids, alertTypes, services, genericServiceDocsAllowed };
  }

  function ragDocumentMatchesAlert(doc, context) {
    const docIds = collectDocumentTokens(doc?.alert_id, doc?.id, doc?.metadata?.alert_id, doc?.metadata?.incident_id);
    if ([...context.ids].some((id) => docIds.has(id))) {
      return true;
    }
    const docAlertTypes = collectDocumentTokens(doc?.alert_type, doc?.alert_name, doc?.alertname, doc?.metadata?.alert_type);
    const docServices = collectDocumentTokens(doc?.services, doc?.service, doc?.metadata?.service, doc?.metadata?.services);
    const hasAlertTypeMatch = [...context.alertTypes].some((type) => docAlertTypes.has(type));
    const hasServiceMatch = [...context.services].some((service) => docServices.has(service));
    if (hasAlertTypeMatch && hasServiceMatch) {
      return true;
    }
    const docKind = String(doc?.kind || doc?.document_kind || "").trim().toLowerCase();
    const isGenericServiceDoc = !docIds.size && hasServiceMatch && ["runbook", "incident", "sop", "onboarding"].includes(docKind);
    return Boolean(context.genericServiceDocsAllowed && isGenericServiceDoc);
  }

  function findMatchingRagDocument(alertRow, preferredKind = "") {
    const context = getAlertDocumentMatchContext(alertRow);
    const normalizedKind = String(preferredKind || "").trim().toLowerCase();
    const docs = Array.isArray(ragDocs.rows) ? ragDocs.rows : [];
    return docs.find((doc) => {
      const docKind = String(doc?.kind || doc?.document_kind || "").trim().toLowerCase();
      if (normalizedKind && docKind && docKind !== normalizedKind) {
        return false;
      }
      return ragDocumentMatchesAlert(doc, context);
    }) || null;
  }

  function findAlertRagDocuments(alertRow) {
    if (!alertRow || typeof alertRow !== "object") {
      return [];
    }
    const context = getAlertDocumentMatchContext(alertRow);
    const docs = Array.isArray(ragDocs.rows) ? ragDocs.rows : [];
    return docs.filter((doc) => ragDocumentMatchesAlert(doc, context));
  }

  async function downloadRagDocument(doc) {
    const path = String(doc?.path || "").trim();
    try {
      const full = path
        ? unwrap(await fetchJson(`/api-gateway/rag/documents/content?path=${encodeURIComponent(path)}`, authenticatedOptions()))
        : doc;
      const title = String(full?.title || doc?.title || (path ? path.split(/[\\/]/).pop() : "") || "alert-document").trim();
      const content = [
        `# ${title}`,
        "",
        full?.summary ? `Summary: ${String(full.summary).trim()}` : "",
        full?.kind || doc?.kind ? `Kind: ${String(full?.kind || doc?.kind).trim()}` : "",
        full?.alert_id || doc?.alert_id ? `Alert ID: ${String(full?.alert_id || doc?.alert_id).trim()}` : "",
        doc?.match_reason ? `Context match: ${String(doc.match_reason).trim()}` : "",
        doc?.match_confidence ? `Match confidence: ${Math.round(Number(doc.match_confidence) * 100)}%` : "",
        "",
        String(full?.content || doc?.content || doc?.recommended_action || doc?.summary || "").trim(),
      ].filter((line) => line !== "").join("\n");
      const safeName = `${title || "alert-document"}`.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "alert-document";
      const blob = new Blob([content || JSON.stringify(full || doc, null, 2)], { type: "text/markdown;charset=utf-8" });
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `${safeName}.md`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
    } catch (error) {
      setRagDocs((current) => ({ ...current, error: `Download failed: ${String(error?.message || "Unknown error")}` }));
    }
  }

  async function loadRagDocumentContent(doc) {
    const path = String(doc?.path || "").trim();
    if (!path) {
      return doc;
    }
    const full = unwrap(await fetchJson(`/api-gateway/rag/documents/content?path=${encodeURIComponent(path)}`, authenticatedOptions()));
    return {
      ...doc,
      ...(full && typeof full === "object" ? full : {}),
      path: full?.path || doc?.path || path,
    };
  }

  function backendDocumentPreview(doc) {
    const summary = String(doc?.summary || "").trim();
    const action = String(doc?.recommended_action || "").trim();
    const content = String(doc?.content || "").trim();
    const rootCause = String(doc?.root_cause || "").trim();
    const impact = String(doc?.impact || "").trim();
    const fallback = [rootCause, impact, action].filter(Boolean).join(" ");
    return String(summary || content || fallback || "Open the document view to inspect backend metadata and download the document.")
      .replace(/\s+/g, " ")
      .slice(0, 240);
  }

  async function downloadConsolidatedAlertDocument(docs) {
    const rows = Array.isArray(docs) ? docs.filter(Boolean) : [];
    if (!rows.length) {
      return;
    }
    const alertName = String(selectedAlertRow?.name || selectedAlertId || "alert").trim();
    const service = String(selectedAlertRow?.service || rows[0]?.services?.[0] || rows[0]?.service || "service").trim();
    try {
      const sections = [];
      for (const [index, doc] of rows.entries()) {
        const path = String(doc?.path || "").trim();
        let full = {};
        if (path) {
          try {
            full = unwrap(await fetchJson(`/api-gateway/rag/documents/content?path=${encodeURIComponent(path)}`, authenticatedOptions()));
          } catch (_error) {
            full = {};
          }
        }
        const title = String(full?.title || doc?.title || `Document ${index + 1}`).trim();
        sections.push([
          `## ${title}`,
          "",
          `Kind: ${String(full?.kind || doc?.kind || doc?.document_kind || "document").trim()}`,
          doc?.match_reason ? `Match reason: ${String(doc.match_reason).trim()}` : "",
          doc?.match_confidence ? `Match confidence: ${Math.round(Number(doc.match_confidence) * 100)}%` : "",
          full?.summary || doc?.summary ? `Summary: ${String(full?.summary || doc?.summary).trim()}` : "",
          "",
          String(full?.content || doc?.content || doc?.recommended_action || "Document content is available in backend metadata.").trim(),
        ].filter((line) => line !== "").join("\n"));
      }
      const content = [
        `# ${service} Alert Knowledge Document`,
        "",
        `Alert: ${alertName}`,
        `Service: ${service}`,
        `Linked backend documents: ${rows.length}`,
        "",
        ...sections,
      ].join("\n\n");
      const safeName = `${service || "service"}-${alertName || "alert"}-knowledge`
        .replace(/[^a-zA-Z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "") || "alert-knowledge";
      const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `${safeName}.md`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
    } catch (error) {
      setRagDocs((current) => ({ ...current, error: `Download failed: ${String(error?.message || "Unknown error")}` }));
    }
  }

  function hasAlertDocuments(alertRow) {
    if (!alertRow || typeof alertRow !== "object") {
      return false;
    }
    const explicitFlag = alertRow.document_available === true;
    if (explicitFlag) {
      return true;
    }
    return Boolean(findMatchingRagDocument(alertRow));
  }

  function buildAlertDocumentDraft(alertRow, workflowPayload, preferredKind = "runbook") {
    const allDrafts = buildAlertDocumentDrafts(alertRow, workflowPayload);
    const kind = String(preferredKind || "runbook").trim().toLowerCase();
    return allDrafts[kind] || allDrafts.runbook;
  }

  async function buildAlertDocumentDraftWithAnalysis(alertRow, preferredKind = "runbook") {
    const alertId = String(alertRow?.alert_id || alertRow?.id || "").trim();
    let workflowPayload = {};
    if (alertId && String(selectedAlertData?.alertId || "").trim() === alertId && selectedAlertData?.payload) {
      workflowPayload = selectedAlertData.payload?.data || selectedAlertData.payload;
    } else if (alertId) {
      try {
        const payload = await fetchJson(
          `/api-gateway/alerts/${encodeURIComponent(alertId)}/processed-result`,
          authenticatedOptions({ timeoutMs: 12000, maxAttempts: 4 }),
        );
        workflowPayload = payload?.data || payload;
      } catch (_error) {
        workflowPayload = {};
      }
    }
    return buildAlertDocumentDraft(alertRow, workflowPayload, preferredKind);
  }

  function buildDocPayloadFromDraft(draft) {
    const toPlanLines = (value) => {
      if (Array.isArray(value)) {
        return value.map((item) => String(item || "").trim()).filter(Boolean);
      }
      return String(value || "")
        .split(/\r?\n/)
        .map((item) => item.trim())
        .filter(Boolean);
    };

    const commands = toPlanLines(draft.remediation_commands_text ?? draft.commands);
    const scripts = toPlanLines(draft.remediation_scripts_text ?? draft.scripts);
    const queries = toPlanLines(draft.remediation_queries_text ?? draft.queries);
    const executionPlan = String(draft.execution_plan || "").trim() || [
      commands.length ? `Commands:\n${commands.map((item) => `- ${item}`).join("\n")}` : "",
      scripts.length ? `Remediation Script:\n${scripts.map((item) => `- ${item}`).join("\n")}` : "",
      queries.length ? `Queries:\n${queries.map((item) => `- ${item}`).join("\n")}` : "",
    ].filter(Boolean).join("\n\n");

    return {
      kind: draft.kind,
      title: draft.title,
      summary: draft.summary || null,
      content: draft.content,
      services: String(draft.services || "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
      severity: draft.severity,
      alert_type: draft.alert_type,
      alert_id: draft.alert_id || null,
      root_cause: draft.root_cause || null,
      impact: draft.impact || null,
      execution_plan: executionPlan || null,
      commands,
      scripts,
      queries,
      recommended_action: draft.recommended_action || null,
    };
  }

  async function setDocPromptDraftForKind(row, kind) {
    const normalizedKind = String(kind || "runbook").trim().toLowerCase();
    const alertId = String(row?.alert_id || row?.id || "").trim();
    const existingDoc = findMatchingRagDocument(row, normalizedKind);
    setDocPromptKind(normalizedKind);
    setDocPromptExistingDoc(existingDoc);
    setDocPromptMode(existingDoc?.path ? "update" : "create");

    if (existingDoc?.path) {
      // Show the real saved document instead of a freshly generated draft.
      setAlertOnboardingState({ loading: true, result: null, error: "" });
      try {
        const full = unwrap(await fetchJson(`/api-gateway/rag/documents/content?path=${encodeURIComponent(existingDoc.path)}`, authenticatedOptions()));
        setAlertOnboarding((curr) => ({
          ...curr,
          kind: normalizedKind,
          title: String(full.title || existingDoc.title || "Alert Document").slice(0, 160),
          summary: String(full.summary || "").trim(),
          content: String(full.content || "").trim(),
          services: Array.isArray(full.services) ? full.services.join(", ") : String(full.services || "").trim(),
          severity: String(full.severity || "high").toLowerCase(),
          alert_type: String(full.alert_type || "").trim(),
          alert_id: alertId,
        }));
        setAlertOnboardingState({ loading: false, result: null, error: "" });
      } catch (error) {
        setAlertOnboardingState({ loading: false, result: null, error: error.message });
      }
      return;
    }

    const selectedPayload = String(selectedAlertData?.alertId || "").trim() === alertId
      ? (selectedAlertData.payload?.data || selectedAlertData.payload || {})
      : {};
    const draft = buildAlertDocumentDraft(row, selectedPayload, normalizedKind);
    setAlertOnboarding((curr) => ({
      ...curr,
      kind: draft.kind,
      title: String(draft.title || "Alert Document").slice(0, 160),
      summary: String(draft.summary || "").trim(),
      content: String(draft.content || "Provide troubleshooting and escalation steps for this alert scenario.").trim(),
      services: String(draft.services || "").trim(),
      severity: String(draft.severity || "high").toLowerCase(),
      alert_type: String(draft.alert_type || "").trim(),
      alert_id: alertId,
      execution_plan: String(draft.execution_plan || "").trim(),
      remediation_commands_text: Array.isArray(draft.commands) ? draft.commands.join("\n") : "",
      remediation_scripts_text: Array.isArray(draft.scripts) ? draft.scripts.join("\n") : "",
      remediation_queries_text: Array.isArray(draft.queries) ? draft.queries.join("\n") : "",
    }));
  }

  async function autoGenerateRemediationPlan(alertRow = null) {
    const sourceRow = alertRow && typeof alertRow === "object"
      ? alertRow
      : {
          alert_id: alertOnboarding.alert_id,
          name: alertOnboarding.alert_type || alertOnboarding.title || "Alert",
          service: String(alertOnboarding.services || "").split(",")[0]?.trim() || "unknown-service",
          severity: alertOnboarding.severity || "high",
        };
    const draft = alertRow && typeof alertRow === "object"
      ? await buildAlertDocumentDraftWithAnalysis(sourceRow, "remediation")
      : buildAlertDocumentDraft(sourceRow, {}, "remediation");
    setAlertOnboarding((curr) => ({
      ...curr,
      kind: "remediation",
      title: String(draft.title || curr.title || "Remediation Plan").slice(0, 160),
      summary: String(draft.summary || curr.summary || "").trim(),
      content: String(draft.content || curr.content || "").trim(),
      services: String(draft.services || curr.services || "").trim(),
      severity: String(draft.severity || curr.severity || "high").toLowerCase(),
      alert_type: String(draft.alert_type || curr.alert_type || "").trim(),
      alert_id: String(draft.alert_id || curr.alert_id || "").trim(),
      execution_plan: String(draft.execution_plan || "").trim(),
      remediation_commands_text: Array.isArray(draft.commands) ? draft.commands.join("\n") : "",
      remediation_scripts_text: Array.isArray(draft.scripts) ? draft.scripts.join("\n") : "",
      remediation_queries_text: Array.isArray(draft.queries) ? draft.queries.join("\n") : "",
    }));
  }

  function parseAiDraftContent(content) {
    const text = String(content || "").trim();
    if (!text) {
      return null;
    }
    const candidates = [text];
    const fenced = text.match(/```json\s*([\s\S]*?)```/i);
    if (fenced?.[1]) {
      candidates.push(String(fenced[1]).trim());
    }
    const objectBlock = text.match(/\{[\s\S]*\}/);
    if (objectBlock?.[0]) {
      candidates.push(String(objectBlock[0]).trim());
    }
    for (const candidate of candidates) {
      try {
        const parsed = JSON.parse(candidate);
        if (parsed && typeof parsed === "object") {
          return parsed;
        }
      } catch (_error) {
        // Try next extraction candidate.
      }
    }
    return null;
  }

  function normalizeDraftList(value) {
    if (Array.isArray(value)) {
      return value.map((item) => String(item || "").trim()).filter(Boolean);
    }
    return String(value || "")
      .split(/\r?\n/)
      .map((item) => item.replace(/^[-*]\s*/, "").trim())
      .filter(Boolean);
  }

  async function generateAlertKnowledgeDraftFromPrompt() {
    const prompt = buildAlertKnowledgePromptInput();
    if (!prompt) {
      setAlertOnboardingState({ loading: false, result: null, error: "Enter a prompt or upload a supporting document to generate the document draft." });
      return;
    }

    const normalizedKind = String(alertOnboarding.kind || "incident").trim().toLowerCase();
    const sourceDocName = String(alertKnowledgeSourceDoc?.name || "").trim();
    const lines = prompt
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    const sentences = prompt
      .split(/(?<=[.!?])\s+/)
      .map((item) => item.trim())
      .filter(Boolean);
    const summary = String(sentences[0] || lines[0] || prompt).slice(0, 260);
    const titleSeed = String(lines[0] || prompt)
      .replace(/^[-*#\d.\s]+/, "")
      .split(/\s+/)
      .slice(0, 8)
      .join(" ")
      .trim();
    const fallbackTitle = `${normalizedKind[0]?.toUpperCase() || "D"}${normalizedKind.slice(1)} Doc`;
    const generatedTitle = titleSeed ? titleSeed.slice(0, 160) : fallbackTitle;

    const commandMatches = [];
    const scriptMatches = [];
    const queryMatches = [];

    const cleanToken = (value) => String(value || "").trim().replace(/^[-*]\s*/, "");
    const pushUnique = (target, value) => {
      const normalized = cleanToken(value);
      if (!normalized) {
        return;
      }
      if (!target.some((item) => item.toLowerCase() === normalized.toLowerCase())) {
        target.push(normalized);
      }
    };

    const extractTaggedValues = (inputText, tagPattern) => {
      const regex = new RegExp(`\\b(?:${tagPattern})\\s*[:\\-]\\s*([^\\n;|]+)`, "ig");
      const values = [];
      let match = regex.exec(inputText);
      while (match) {
        values.push(match[1]);
        match = regex.exec(inputText);
      }
      return values;
    };

    const shellLike = /^(kubectl|kubeadm|helm|docker|docker-compose|compose|terraform|ansible|oc|az|aws|gcloud|systemctl|journalctl|curl|wget|psql|mysql|redis-cli|kafka-|python\s+|pip\s+|npm\s+|node\s+|pwsh\s+|powershell\s+|bash\s+)/i;
    const sqlLike = /\b(select|update|delete|insert|with|merge|create\s+table|drop\s+table|alter\s+table)\b/i;

    extractTaggedValues(prompt, "cmd|command").forEach((value) => pushUnique(commandMatches, value));
    extractTaggedValues(prompt, "script|ps1|sh|bash").forEach((value) => pushUnique(scriptMatches, value));
    extractTaggedValues(prompt, "query|sql").forEach((value) => pushUnique(queryMatches, value));

    const codeFenceRegex = /```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g;
    let fenceMatch = codeFenceRegex.exec(prompt);
    while (fenceMatch) {
      const lang = String(fenceMatch[1] || "").trim().toLowerCase();
      const body = String(fenceMatch[2] || "")
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .join(" ; ");
      if (body) {
        if (lang.includes("sql") || sqlLike.test(body)) {
          pushUnique(queryMatches, body);
        } else if (lang.includes("bash") || lang.includes("sh") || lang.includes("ps") || lang.includes("powershell")) {
          pushUnique(scriptMatches, body);
        } else if (shellLike.test(body)) {
          pushUnique(commandMatches, body);
        }
      }
      fenceMatch = codeFenceRegex.exec(prompt);
    }

    const taggedSegment = /\b(cmd|command|script|query|sql|ps1|bash|sh)\s*[:\-]/i;
    const fallbackSegments = prompt
      .split(/[\r\n;]+/)
      .map((item) => item.trim())
      .filter(Boolean);

    fallbackSegments.forEach((segment) => {
      if (taggedSegment.test(segment)) {
        return;
      }
      if (shellLike.test(segment)) {
        pushUnique(commandMatches, segment);
        return;
      }
      if (sqlLike.test(segment)) {
        pushUnique(queryMatches, segment);
      }
    });

    const narrativeSegments = fallbackSegments.filter((segment) => {
      if (taggedSegment.test(segment)) {
        return false;
      }
      if (shellLike.test(segment) || sqlLike.test(segment)) {
        return false;
      }
      return true;
    });

    const sentenceTail = sentences
      .slice(1, 4)
      .map((item) => item.trim())
      .filter(Boolean)
      .join(" ");

    const narrativeDetail = [
      ...narrativeSegments,
      sentenceTail,
    ]
      .map((item) => String(item || "").trim())
      .filter(Boolean)
      .filter((item, index, arr) => arr.findIndex((other) => other.toLowerCase() === item.toLowerCase()) === index)
      .join("\n");

    const contentBody = [
      summary,
      narrativeDetail,
    ].filter(Boolean).join("\n\n");

    let aiDraft = null;
    let aiUsage = null;
    try {
      const aiResponseRaw = await fetchJson("/api-gateway/model/route", authenticatedOptions({
        method: "POST",
        body: JSON.stringify({
          severity: String(alertOnboarding.severity || "high").trim().toLowerCase(),
          task: normalizedKind === "remediation" ? "fix" : "summarization",
          prompt: [
            `Generate a meaningful ${normalizedKind} document draft for SRE operations from user input.`,
            "Return ONLY valid JSON with keys: title, summary, content, commands, scripts, queries, metadata.",
            "For remediation, prefer one guarded script with connection details over scattered command/query fragments.",
          ].join(" "),
          payload: {
            kind: normalizedKind,
            alert_type: String(alertOnboarding.alert_type || "").trim(),
            services: String(alertOnboarding.services || "").trim(),
            user_prompt: prompt,
            source_document: sourceDocName || null,
          },
        }),
      }));
      const aiResponse = aiResponseRaw?.data && typeof aiResponseRaw.data === "object"
        ? aiResponseRaw.data
        : aiResponseRaw;
      aiUsage = aiResponse?.usage || null;
      aiDraft = parseAiDraftContent(aiResponse?.content || "");
    } catch (_error) {
      aiDraft = null;
    }

    const mergeUnique = (base, extra) => {
      const out = [];
      [...normalizeDraftList(base), ...normalizeDraftList(extra)].forEach((item) => {
        if (!out.some((existing) => existing.toLowerCase() === item.toLowerCase())) {
          out.push(item);
        }
      });
      return out;
    };

    const aiCommands = normalizeDraftList(aiDraft?.commands);
    const aiScripts = normalizeDraftList(aiDraft?.scripts);
    const aiQueries = normalizeDraftList(aiDraft?.queries);
    const mergedCommands = mergeUnique(aiCommands, commandMatches);
    const mergedScripts = mergeUnique(aiScripts, scriptMatches);
    const mergedQueries = mergeUnique(aiQueries, queryMatches);
    const serviceForScript = String(alertOnboarding.services || alertOnboarding.alert_type || applicationToMonitor || "kaiops-service")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)[0] || "kaiops-service";
    const environmentForScript = String(alertOnboarding.environment || onboardingForm.environment || "prod").trim() || "prod";
    const generatedScript = buildKaiOpsRemediationScript({
      service: serviceForScript,
      environment: environmentForScript,
      apiGatewayUrl: "http://api-gateway:8000",
      prometheusUrl: onboardingForm.prometheus_url || onboardingForm.monitoring_url || "http://prometheus:9090",
      mysqlHost: "mysql",
      mysqlDatabase: "kaiops",
      mysqlUser: "kaiops",
    });
    const finalCommands = normalizedKind === "remediation" ? [] : mergedCommands;
    const finalQueries = normalizedKind === "remediation" ? [] : mergedQueries;
    const finalScripts = normalizedKind === "remediation"
      ? [generatedScript]
      : mergedScripts;
    const mergedExecutionPlan = [
      finalCommands.length ? `Commands:\n${finalCommands.map((item) => `- ${item}`).join("\n")}` : "",
      finalScripts.length ? `Remediation Script:\n${finalScripts.map((item) => `- ${item}`).join("\n")}` : "",
      finalQueries.length ? `Queries:\n${finalQueries.map((item) => `- ${item}`).join("\n")}` : "",
    ].filter(Boolean).join("\n\n");

    setAlertOnboarding((curr) => ({
      ...curr,
      title: String(aiDraft?.title || generatedTitle).slice(0, 160),
      summary: String(aiDraft?.summary || summary).trim(),
      content: String(aiDraft?.content || contentBody || prompt).trim(),
      execution_plan: normalizedKind === "remediation" ? mergedExecutionPlan : curr.execution_plan,
      remediation_commands_text: normalizedKind === "remediation" ? finalCommands.join("\n") : curr.remediation_commands_text,
      remediation_scripts_text: normalizedKind === "remediation" ? finalScripts.join("\n") : curr.remediation_scripts_text,
      remediation_queries_text: normalizedKind === "remediation" ? finalQueries.join("\n") : curr.remediation_queries_text,
    }));

    setAlertOnboardingState({
      loading: false,
      result: {
        message: aiDraft
          ? `Draft generated from ${sourceDocName ? "prompt + document" : "prompt"} using AI + heuristics. Review and click Create Alert Onboarding Doc.`
          : `Draft generated from ${sourceDocName ? "prompt + document" : "prompt"} using heuristics fallback. Review and click Create Alert Onboarding Doc.`,
        source_document: sourceDocName || null,
        ai_usage: aiUsage,
      },
      error: "",
    });
  }

  async function autoCreateAlertDocument(alertRow, preferredKind = "runbook") {
    if (!alertRow || alertOnboardingState.loading) {
      return;
    }
    setAlertOnboardingState({ loading: true, result: null, error: "" });
    try {
      const draft = await buildAlertDocumentDraftWithAnalysis(alertRow, preferredKind);
      const existingDoc = findMatchingRagDocument(alertRow, draft.kind);
      const payload = buildDocPayloadFromDraft(draft);
      const response = await fetchJson("/api-gateway/rag/knowledge-drafts", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      }));
      const responseData = response?.data || response || {};
      setAlertOnboardingState({
        loading: false,
        error: "",
        result: {
          ...response,
          message: existingDoc?.path
            ? `${draft.kind} document updated from alert analysis.`
            : `${draft.kind} document created from alert analysis.`,
        },
      });
      await Promise.all([loadRagDocs(), loadRecentAlerts()]);
      if (docPromptAlert) {
        const mergedDoc = {
          ...(existingDoc || {}),
          ...(typeof responseData === "object" && responseData ? responseData : {}),
          kind: draft.kind,
          path: responseData?.path || existingDoc?.path,
          alert_id: draft.alert_id || existingDoc?.alert_id || null,
        };
        setDocPromptDocsByKind((curr) => ({ ...curr, [draft.kind]: mergedDoc }));
        if (String(docPromptKind || "").trim().toLowerCase() === draft.kind) {
          setDocPromptExistingDoc(mergedDoc);
          setDocPromptMode(mergedDoc?.path ? "update" : "create");
        }
      }
    } catch (error) {
      setAlertOnboardingState({ loading: false, result: null, error: error.message });
    }
  }

  async function autoCreateAllAlertDocuments(alertRow) {
    if (!alertRow || alertOnboardingState.loading) {
      return;
    }
    setAlertOnboardingState({ loading: true, result: null, error: "" });
    try {
      const results = [];
      for (const kind of ALERT_DOC_KIND_OPTIONS) {
        const draft = await buildAlertDocumentDraftWithAnalysis(alertRow, kind);
        const existingDoc = findMatchingRagDocument(alertRow, kind);
        const payload = buildDocPayloadFromDraft(draft);
        const response = await fetchJson("/api-gateway/rag/knowledge-drafts", authenticatedOptions({
          method: "POST",
          body: JSON.stringify(payload),
        }));
        results.push({ kind, path: response?.data?.path || response?.path || existingDoc?.path || "" });
      }
      await Promise.all([loadRagDocs(), loadRecentAlerts()]);
      setAlertOnboardingState({
        loading: false,
        error: "",
        result: {
          message: `Created/updated ${results.length} document types: ${results.map((item) => item.kind).join(", ")}`,
          results,
        },
      });
      if (docPromptAlert) {
        const refreshedByKind = {};
        ALERT_DOC_KIND_OPTIONS.forEach((kind) => {
          const matched = findMatchingRagDocument(docPromptAlert, kind);
          if (matched) {
            refreshedByKind[kind] = matched;
          }
        });
        setDocPromptDocsByKind(refreshedByKind);
        setDocPromptExistingDoc(refreshedByKind[docPromptKind] || null);
        setDocPromptMode(refreshedByKind[docPromptKind]?.path ? "update" : "create");
      }
    } catch (error) {
      setAlertOnboardingState({ loading: false, result: null, error: error.message });
    }
  }

  async function addRuleFromAlertPrompt() {
    const row = docPromptAlert;
    const requirement = String(alertRuleDraft.requirement || "").trim();
    if (!row || !requirement) {
      setAlertRuleState({ loading: false, result: null, error: "Provide a rule requirement first." });
      return;
    }
    setAlertRuleState({ loading: true, result: null, error: "" });
    try {
      const service = String(row?.service || "unknown-service").trim();
      const projectName = String(row?.application || row?.project_name || service || "alert-onboarding").trim();
      const platform = String(alertRuleDraft.platform || "prometheus").trim().toLowerCase();
      const payload = {
        project: {
          project_name: projectName,
          environment: String(row?.environment || onboardingForm.environment || "prod").trim().toLowerCase(),
          criticality: String(row?.severity || "high").trim().toLowerCase() === "critical" ? "high" : "medium",
          support_team: String(onboardingForm.owner_team || "platform-ops").trim(),
          region: String(onboardingForm.region || "us-east-1").trim(),
          cloud_provider: ({ azure_cloud: "azure", aws_cloud: "aws", gcp_cloud: "gcp", private_cloud: "private-cloud", on_prem: "on-prem" }[onboardingForm.deployment_mode] || "cloud-neutral"),
          monitoring_platforms: [platform],
          notification_platforms: ["slack", "teams"],
        },
        monitoring_requirements: [requirement],
        target_platforms: [platform],
        discovery_inputs: {
          source_alert_id: String(row?.alert_id || row?.id || "").trim(),
          alert_type: String(row?.name || row?.alert_name || "").trim(),
          service,
          severity: String(row?.severity || "high").trim().toLowerCase(),
          endpoint_url: simplifyMonitoringUrl(onboardingForm.monitoring_url),
          generated_from_alert_analysis: true,
        },
      };
      const response = await fetchJson("/api-gateway/onboarding/rules/pipeline/create", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      }));
      const data = unwrap(response);
      const workflowId = String(data?.workflow_id || "").trim();
      if (workflowId) {
        setOnboardingRuleLookup((current) => ({ ...current, workflow_id: workflowId }));
      }
      setAlertRuleState({ loading: false, result: data, error: "" });
    } catch (error) {
      setAlertRuleState({ loading: false, result: null, error: error.message });
    }
  }

  async function submitAlertOnboarding(event) {
    event.preventDefault();
    setAlertOnboardingState({ loading: true, result: null, error: "" });
    try {
      const payload = {
        ...buildDocPayloadFromDraft(alertOnboarding),
        kind: String(alertOnboarding.kind || "incident").trim(),
        title: String(alertOnboarding.title || "").trim(),
        content: String(alertOnboarding.content || "").trim(),
        severity: String(alertOnboarding.severity || "").trim(),
      };
      const isUpdate = docPromptMode === "update" && Boolean(docPromptExistingDoc?.path);
      const response = await fetchJson("/api-gateway/rag/knowledge-drafts", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      }));
      const responseData = response?.data || response || {};
      const normalizedKind = String(payload.kind || docPromptKind || "runbook").trim().toLowerCase();
      const mergedDoc = {
        ...(docPromptExistingDoc || {}),
        ...(typeof responseData === "object" && responseData ? responseData : {}),
        kind: normalizedKind,
        alert_id: payload.alert_id,
        alert_type: payload.alert_type,
        services: payload.services,
        path: responseData?.path || docPromptExistingDoc?.path,
      };
      setAlertOnboardingState({
        loading: false,
        result: {
          ...response,
          message: isUpdate ? `${normalizedKind} document updated.` : `${normalizedKind} document created.`,
        },
        error: "",
      });
      setDocPromptDocsByKind((curr) => ({ ...curr, [normalizedKind]: mergedDoc }));
      setDocPromptExistingDoc(mergedDoc);
      setDocPromptMode(mergedDoc?.path ? "update" : "create");
      await Promise.all([loadRagDocs(), loadRecentAlerts()]);
      await refreshViewsAfterSubmit();
    } catch (error) {
      setAlertOnboardingState({ loading: false, result: null, error: error.message });
    }
  }

  async function autoGenerateAlertKnowledgeFromSourceDocs({ projectName, onboardingPath }) {
    const sourceRows = onboardingSourceDocRows;
    if (!sourceRows.length) {
      return false;
    }

    const safeProject = String(projectName || onboardingForm.name || "").trim() || "Project";
    const summary = `Auto-generated from ${sourceRows.length} uploaded source document(s).`;
    const evidenceLines = sourceRows.slice(0, 8).map((row) => {
      const label = onboardingSourceDocCategoryLabel(row?.category);
      const excerpt = String(row?.excerpt || "").trim();
      return `- [${label}] ${String(row?.name || "uploaded-document").trim()}${excerpt ? `: ${excerpt}` : ""}`;
    });
    const requirementLines = onboardingDerivedRequirements.slice(0, 8).map((line) => `- ${line}`);
    const content = [
      `Auto-generated alert onboarding for ${safeProject}.`,
      "",
      "Source evidence:",
      ...evidenceLines,
      "",
      "Derived requirements:",
      ...(requirementLines.length ? requirementLines : ["- No derived requirements captured."]),
      "",
      "Use this draft to refine final triage and remediation guidance.",
    ].join("\n");

    const autoDraft = {
      kind: "runbook",
      title: `${safeProject} Alert Knowledge Onboarding`,
      summary,
      content,
      services: safeProject,
      severity: "high",
      alert_type: onboardingPath === "setup_monitoring" ? "configuration" : "availability",
      alert_id: "",
      root_cause: "",
      impact: "",
      execution_plan: "",
      remediation_commands_text: "",
      remediation_scripts_text: "",
      remediation_queries_text: "",
      recommended_action: "Review generated draft and finalize onboarding knowledge.",
    };

    try {
      const response = await fetchJson("/api-gateway/rag/knowledge-drafts", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(buildDocPayloadFromDraft(autoDraft)),
      }));
      setAlertOnboarding((curr) => ({ ...curr, ...autoDraft }));
      setAlertOnboardingState({
        loading: false,
        result: {
          ...response,
          message: "Alert Knowledge Onboarding auto-generated from Service Knowledge.",
        },
        error: "",
      });
      setAlertKnowledgeView("onboarding");
      return true;
    } catch (error) {
      setAlertOnboardingState({
        loading: false,
        result: null,
        error: `Automatic Alert Knowledge generation failed: ${String(error?.message || "Unknown error")}`,
      });
      setAlertKnowledgeView("onboarding");
      return false;
    }
  }

  function openDocumentPrompt(row) {
    if (!canProvideAlertDocuments) {
      setDocPromptAlert(null);
      return;
    }
    docPromptReturnFocusRef.current = document.activeElement;
    const byKind = {};
    ALERT_DOC_KIND_OPTIONS.forEach((kind) => {
      const doc = findMatchingRagDocument(row, kind);
      if (doc) {
        byKind[kind] = doc;
      }
    });
    setDocPromptDocsByKind(byKind);
    setDocPromptAlert(row);
    // If documents already exist for this alert, open on the first available
    // one so the real saved content is shown; otherwise default to runbook
    // for creating a new document.
    const initialKind = ALERT_DOC_KIND_OPTIONS.find((kind) => byKind[kind]) || "runbook";
    setDocPromptDraftForKind(row, initialKind);
    const defaultRequirement = `Create a ${String(row?.severity || "high").toLowerCase()} alert rule for ${String(row?.service || "this service").trim()} based on ${String(row?.name || row?.alert_name || "service degradation").trim()} and route incidents to on-call.`;
    setAlertRuleDraft({ platform: String(onboardingForm.monitoring_tool || "prometheus").trim().toLowerCase(), requirement: defaultRequirement });
    setAlertRuleState({ loading: false, result: null, error: "" });
    setAlertOnboardingState({ loading: false, result: null, error: "" });
    setTimeout(() => {
      docPromptRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 50);
  }

  function closeDocumentPrompt() {
    setDocPromptAlert(null);
    setDocPromptExistingDoc(null);
    setDocPromptDocsByKind({});
    setDocPromptKind("runbook");
    setDocPromptMode("create");
    setAlertRuleState({ loading: false, result: null, error: "" });
    window.setTimeout(() => docPromptReturnFocusRef.current?.focus?.(), 0);
  }


  async function refreshAll({ includeAlerts = true } = {}) {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    // Stage loading so login does not blast all heavy endpoints concurrently.
    await Promise.allSettled([
      checkHealth(),
      checkQueueHealth({ background: true }),
      includeAlerts ? loadRecentAlerts() : Promise.resolve(),
      loadMonitorApplications(),
    ]);
    window.setTimeout(() => {
      if (activeTab === "stream") void loadLandingPadRecent({ background: true });
      if (activeTab === "summary") void Promise.allSettled([loadGatewaySummary(), loadIncidentMetadata({ background: true })]);
      void loadModelProviderStatus();
      if (activeTab === "admin" && adminWorkspace === "alerts") void loadAlertSeverityOverrides();
    }, 250);
  }

  async function refreshViewsAfterSubmit() {
    await Promise.allSettled([
      refreshAll(),
      loadOnboardingAdminData(),
      loadMonitoringApplications(),
    ]);
    if (selectedMonitoringAppId) {
      await loadMonitoringApplicationDetails(selectedMonitoringAppId);
    }
  }

  useEffect(() => {
    let cancelled = false;
    const initializeAuthentication = async () => {
      try {
        const config = await fetchJson("/api-gateway/auth/config", { headers: { Accept: "application/json" }, maxAttempts: 1, staleTimeMs: 60_000 });
        if (cancelled) return;
        setAuthConfig({ ...config, loading: false, error: "" });
        if (config.mode === "oidc" && new URLSearchParams(window.location.search).has("code")) {
          const accessToken = await completeOidcLogin(config);
          if (!accessToken) throw new Error("Identity provider did not return an access token");
          const me = await fetchJson("/api-gateway/auth/me", { headers: { Authorization: `Bearer ${accessToken}` }, maxAttempts: 1 });
          const session = { loading: false, accessToken, refreshToken: "", user: me.user || null, error: "" };
          adminSessionRef.current = session; storeSessionTokens(session);
          setAdminSession(session);
          resetNavigationAfterLogin();
        } else { const session = await restoreStoredSession(config, fetchJson); if (session) { adminSessionRef.current = session; storeSessionTokens(session); setAdminSession(session); } else setAdminSession((current) => ({ ...current, loading: false })); }
      } catch (error) {
        if (!cancelled) { clearStoredSession(); setAuthConfig((current) => ({ ...current, loading: false, error: String(error?.message || error) }));
          setAdminSession((current) => ({ ...current, loading: false, error: String(error?.message || error) }));
        }
      }
    };
    void initializeAuthentication();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!String(adminSession.accessToken || "").trim()) {
      return undefined;
    }
    // Recover from api-gateway/model-router startup races instead of pinning a
    // transient provider-status error in the global shell for the whole login.
    const initialRetry = window.setTimeout(() => { void loadModelProviderStatus(); }, 1_500);
    const interval = window.setInterval(() => { void loadModelProviderStatus(); }, 30_000);
    return () => {
      window.clearTimeout(initialRetry);
      window.clearInterval(interval);
    };
  }, [adminSession.accessToken]);

  useEffect(() => {
    if (VALID_LEGACY_TABS.has(initialTab) && initialTab !== activeTab) {
      // The router is authoritative for top-level navigation. Without this
      // guard, the following effect can publish the previous local tab during
      // the same commit and bounce the URL back, continuously remounting the
      // active route (most visible as Live Alerts / Approvals flicker).
      skipNextActiveTabNavigationRef.current = true;
      setActiveTab(initialTab);
    }
  }, [initialTab]);

  useEffect(() => {
    if (skipNextActiveTabNavigationRef.current) {
      skipNextActiveTabNavigationRef.current = false;
      return;
    }
    if (typeof onActiveTabChange === "function") {
      onActiveTabChange(activeTab);
    }
  }, [activeTab, onActiveTabChange]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    try {
      const raw = window.localStorage.getItem(PREFERENCE_STORAGE_KEY);
      if (!raw) {
        return;
      }
      const prefs = JSON.parse(raw);
      if (prefs && typeof prefs === "object") {
        if (typeof prefs.applicationToMonitor === "string" && prefs.applicationToMonitor.trim()) {
          setApplicationToMonitor(prefs.applicationToMonitor);
        }
        if (prefs.uiDensity === "comfortable" || prefs.uiDensity === "compact") {
          setUiDensity(prefs.uiDensity);
        }
        if (typeof prefs.uiTheme === "string" && UI_THEME_VALUES.has(prefs.uiTheme)) {
          setUiTheme(prefs.uiTheme);
        }
        if (typeof prefs.selectedFlow === "string" && prefs.selectedFlow.trim()) {
          setSelectedFlow(prefs.selectedFlow);
        }
        // The URL is authoritative for the top-level destination. Keep reading
        // the remaining legacy preferences until their owning features move to
        // typed route state.
        if (prefs.closedFilters && typeof prefs.closedFilters === "object") {
          setClosedFilters((current) => ({ ...current, ...prefs.closedFilters }));
        }
        if (prefs.ingestionStreamFilters && typeof prefs.ingestionStreamFilters === "object") {
          // Live Stream is always scoped to the selected project. Do not let a
          // legacy preference restore the former global feed.
          const savedFilters = { ...prefs.ingestionStreamFilters, application: "selected" };
          setIngestionStreamFilters((current) => ({ ...current, ...savedFilters }));
        }
        if (typeof prefs.ingestionStreamView === "string") setIngestionStreamView(prefs.ingestionStreamView);
        if (typeof prefs.ingestionStreamSection === "string") setIngestionStreamSection(prefs.ingestionStreamSection);
      }
    } catch (_error) {
      // Ignore malformed preference payloads and continue with defaults.
    }
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    const root = window.document?.documentElement;
    if (!root) {
      return;
    }
    root.classList.remove("dm-theme-light", "dm-theme-dark");
    if (uiTheme === "light") {
      root.classList.add("dm-theme-light");
    } else if (uiTheme === "dark") {
      root.classList.add("dm-theme-dark");
    }
    root.setAttribute("data-ui-theme", uiTheme);
  }, [uiTheme]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    if (skipInitialPreferencesPersistRef.current) { skipInitialPreferencesPersistRef.current = false; return; }
    const payload = {
      applicationToMonitor,
      uiDensity,
      uiTheme,
      selectedFlow,
      activeTab,
      closedFilters,
      ingestionStreamFilters,
      ingestionStreamView,
      ingestionStreamSection,
      liveStreamScopeVersion: 2,
    };
    window.localStorage.setItem(PREFERENCE_STORAGE_KEY, JSON.stringify(payload));
  }, [applicationToMonitor, uiDensity, uiTheme, selectedFlow, activeTab, closedFilters, ingestionStreamFilters, ingestionStreamView, ingestionStreamSection]);

  useEffect(() => {
    const onKeyDown = (event) => {
      const authenticated = Boolean(String(adminSession.accessToken || "").trim());
      if (!authenticated) {
        return;
      }
      const roleName = normalizeRoleName(adminSession?.user?.role_name);
      const roleTabs = allowedLegacyTabsForRole(roleName);
      if (!event.altKey) {
        return;
      }
      const target = event.target;
      const tagName = String(target?.tagName || "").toLowerCase();
      if (tagName === "input" || tagName === "textarea" || tagName === "select" || target?.isContentEditable) {
        return;
      }
      const tabId = TAB_SHORTCUT_BY_CODE[event.code];
      if (!tabId) {
        return;
      }
      if (!roleTabs.includes(tabId)) {
        return;
      }
      event.preventDefault();
      setActiveTab(tabId);
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [adminSession.accessToken, adminSession?.user?.role_name]);

  useEffect(() => {
    // Application names are non-secret workspace metadata and the selector is
    // shown before authentication. Load them on mount so registered workspaces
    // such as ParaBank are available at sign-in, not only after sign-in.
    loadMonitorApplications({ preLogin: true });
  }, []);

  useEffect(() => {
    incidentMetadataFiltersRef.current = metadataFilters;
  }, [metadataFilters]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    refreshAll({ includeAlerts: false });
  }, [adminSession.accessToken]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    loadRecentAlerts();
  }, [adminSession.accessToken, alertsLimit]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim()) || activeTab !== "safety") {
      return;
    }
    void Promise.allSettled([loadGatewaySummary(), loadGatewayRecent(), loadLandingPadRecent({ force: true })]);
  }, [adminSession.accessToken, activeTab]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    if (activeTab !== "home") {
      return undefined;
    }
    const refreshAlertStream = async () => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") {
        return;
      }
      if (alertStreamRefreshInFlight.current) {
        return;
      }
      alertStreamRefreshInFlight.current = true;
      try {
        const tasks = [
          loadRecentAlerts({ background: true }),
          loadIncidentMetadata({ background: true, ignoreFilters: true, limit: 100 }),
          loadClosedIncidents(),
          loadGatewaySummary(),
          loadGatewayRecent(),
        ];
        await Promise.allSettled(tasks);
      } finally {
        alertStreamRefreshInFlight.current = false;
      }
    };
    void refreshAlertStream();
    const timer = window.setInterval(refreshAlertStream, 20000);
    window.addEventListener("focus", refreshAlertStream);
    document.addEventListener("visibilitychange", refreshAlertStream);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("focus", refreshAlertStream);
      document.removeEventListener("visibilitychange", refreshAlertStream);
    };
  }, [adminSession.accessToken, activeTab, alertsLimit, applicationToMonitor]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    if (activeTab !== "stream") {
      return undefined;
    }
    if (ingestionStreamPaused) {
      return undefined;
    }
    const refreshLandingPadStream = async () => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") {
        return;
      }
      if (landingPadStreamRefreshInFlight.current) {
        return;
      }
      landingPadStreamRefreshInFlight.current = true;
      try {
        await Promise.allSettled([
          loadLandingPadRecent({ background: true }),
          loadIncidentMetadata({ background: true, ignoreFilters: true }),
        ]);
      } finally {
        landingPadStreamRefreshInFlight.current = false;
      }
    };
    refreshLandingPadStream();
    // Event delivery is primary; this bounded 15-second poll covers dropped
    // events and keeps the visible Live Stream honest.
    const timer = window.setInterval(refreshLandingPadStream, 15000);
    return () => window.clearInterval(timer);
  }, [adminSession.accessToken, activeTab, ingestionStreamPaused]);

  useEffect(() => {
    if (activeTab !== "home") {
      return;
    }
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        loadRecentAlerts({ background: true });
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, [activeTab]);

  useEffect(() => {
    if (activeTab !== "home") {
      return;
    }
    const timer = window.setInterval(() => {
      const requestState = recentAlertsRequestRef.current;
      const ageMs = Date.now() - Number(requestState.startedAt || 0);
      if (!requestState.inFlight || ageMs <= 16000) {
        return;
      }
      recentAlertsRequestRef.current = {
        ...recentAlertsRequestRef.current,
        inFlight: false,
        requestId: "",
        startedAt: 0,
      };
      setAlerts((prev) => ({
        ...prev,
        loading: false,
        error: prev.error || "Alert stream refresh timed out. Retrying in background.",
      }));
    }, 4000);
    return () => window.clearInterval(timer);
  }, [activeTab]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    if (!["summary", "approval"].includes(activeTab)) {
      return;
    }
    loadIncidentMetadata();
  }, [
    activeTab,
    metadataFilters.risk_tier,
    metadataFilters.execution_mode,
    metadataFilters.transport_provider,
    metadataFilters.status,
    metadataFilters.service,
    adminSession.accessToken,
  ]);

  // SSE is the fast path, but the incident list must still converge if a
  // proxy, browser, or network temporarily interrupts the event stream.
  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim()) || activeTab !== "summary") {
      return undefined;
    }
    const refreshVisibleIncidents = () => {
      if (document.visibilityState === "visible") {
        void loadIncidentMetadata({ background: true });
      }
    };
    const timer = window.setInterval(refreshVisibleIncidents, 20000);
    document.addEventListener("visibilitychange", refreshVisibleIncidents);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshVisibleIncidents);
    };
  }, [adminSession.accessToken, activeTab]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    if (activeTab !== "admin") {
      return;
    }
    loadOnboardingAdminData();
  }, [adminSession.accessToken, activeTab]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    if (activeTab !== "admin" || adminWorkspace !== "project") {
      return;
    }
    loadOnboardingRuleCapabilities();
  }, [adminSession.accessToken, activeTab, adminWorkspace]);

  useEffect(() => {
    const canonical = monitorApplications.find(
      (item) => item.toLowerCase() === String(applicationToMonitor || "").trim().toLowerCase()
    );
    if (canonical) {
      if (canonical !== applicationToMonitor) setApplicationToMonitor(canonical);
      return;
    }
    // Do not silently cross a tenant/project boundary while the authenticated
    // registry is refreshing. loadMonitorApplications owns explicit fallback
    // selection once its authoritative response is available.
    // Do not clear the saved selection while the initial list is empty.
    // Only loadMonitorApplications may select a fallback after a successful response.
  }, [adminSession.accessToken, monitorApplications, applicationToMonitor]);

  useEffect(() => {
    if (!adminSession.accessToken || activeTab !== "admin") {
      return;
    }
    loadAdminUsersAndRoles();
  }, [adminSession.accessToken, activeTab]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    loadMonitorApplications();
  }, [adminSession.accessToken]);

  useEffect(() => {
    const discovered = alerts.rows.map(projectIdentityFromAlert).map(visibleManagedApplication).filter(Boolean);
    if (!discovered.length) return;
    setMonitorApplications((current) => {
      const merged = uniqueMonitorApplications([...current, ...discovered]);
      return merged.join("\u0000") === current.join("\u0000") ? current : merged;
    });
  }, [alerts.rows]);

  const latestWorkflow = useMemo(() => {
    return workflowState?.result?.data || {};
  }, [workflowState]);

  const latestIncidentId = useMemo(() => {
    return String(latestWorkflow?.incident?.id || latestWorkflow?.incident_id || "").trim();
  }, [latestWorkflow]);

  const latestRecommendationId = useMemo(() => {
    return String(latestWorkflow?.recommendation?.id || latestWorkflow?.recommendation_id || "").trim();
  }, [latestWorkflow]);

  const monitorScopedAlerts = useMemo(() => {
    const scopedRows = filterAlertsForMonitor(alerts.rows, applicationToMonitor);
    return capLatestAlertsPerSource(
      // Source balancing must never escape the selected application scope.
      // Using the global list here reintroduced test/demo alerts into Real.
      ensureMinimumAlertsBySource(scopedRows, scopedRows)
    );
  }, [alerts.rows, applicationToMonitor]);

  const monitorScopedRecentClosedAlerts = useMemo(() => {
    return filterRowsForMonitor(closedIncidents.rows, applicationToMonitor);
  }, [closedIncidents.rows, applicationToMonitor]);

  const visibleAlerts = useMemo(() => {
    return mergeAlertStreamRows(monitorScopedAlerts, monitorScopedRecentClosedAlerts);
  }, [monitorScopedAlerts, monitorScopedRecentClosedAlerts]);

  const dashboardAlertSummary = useMemo(() => {
    const summary = { total: visibleAlerts.length, ops: 0, test: 0, critical: 0, high: 0, awaiting: 0, active: 0, closed: 0 };
    visibleAlerts.forEach((row) => {
      const severity = String(row?.severity || "").toLowerCase();
      const status = String(row?.status || row?.state || "open").toLowerCase();
      if (isGeneratedOrTestAlert(row)) {
        summary.test += 1;
      } else {
        summary.ops += 1;
      }
      if (severity === "critical") {
        summary.critical += 1;
      }
      if (severity === "high") {
        summary.high += 1;
      }
      if (status === "awaiting_approval") {
        summary.awaiting += 1;
      }
      if (status === "open" || status === "pending" || status === "investigating") {
        summary.active += 1;
      }
      if (isApprovalResolvedStatus(status) || row?._closed_incident) {
        summary.closed += 1;
      }
    });
    return summary;
  }, [visibleAlerts]);

  const dashboardVisibleAlerts = useMemo(() => {
    const query = String(dashboardAlertQueryDebounced || "").trim().toLowerCase();
    return visibleAlerts.filter((row) => {
      const severity = String(row?.severity || "").toLowerCase();
      const status = String(row?.status || row?.state || "open").toLowerCase();
      const generatedOrTest = isGeneratedOrTestAlert(row);
      const sourceChannels = Array.isArray(row?.source_channels) && row.source_channels.length
        ? row.source_channels.map((channel) => String(channel || "").trim().toLowerCase())
        : [normalizeAlertChannel(row)];
      if (dashboardAlertSource !== "all" && !sourceChannels.includes(dashboardAlertSource)) {
        return false;
      }
      if (dashboardAlertFocus === "ops" && generatedOrTest) {
        return false;
      }
      if (dashboardAlertFocus === "test" && !generatedOrTest) {
        return false;
      }
      if (dashboardAlertFocus === "critical" && severity !== "critical") {
        return false;
      }
      if (dashboardAlertFocus === "high" && severity !== "high") {
        return false;
      }
      if (dashboardAlertFocus === "awaiting" && status !== "awaiting_approval") {
        return false;
      }
      if (dashboardAlertFocus === "active" && !["open", "pending", "investigating"].includes(status)) {
        return false;
      }
      if (dashboardAlertFocus === "closed" && !(isApprovalResolvedStatus(status) || row?._closed_incident)) {
        return false;
      }
      if (!query) {
        return true;
      }
      const haystack = [
        row?.alert_id,
        row?.id,
        row?.incident_id,
        row?.name,
        row?.alert_name,
        row?.service,
        row?.application,
        row?.project_name,
        row?.project,
      ]
        .map((value) => String(value || "").toLowerCase())
        .join(" ");
      return haystack.includes(query);
    });
  }, [visibleAlerts, dashboardAlertFocus, dashboardAlertQueryDebounced, dashboardAlertSource]);

  const monitorScopedIncidentMetadata = useMemo(() => {
    const scoped = filterRowsForMonitor(incidentMetadata.rows, applicationToMonitor);
    return scoped.map((incidentRow) => {
      const projection = incidentRow?.projection_payload && typeof incidentRow.projection_payload === "object" ? incidentRow.projection_payload : {};
      const eventPayload = projection?.event_payload && typeof projection.event_payload === "object" ? projection.event_payload : {};
      const alertId = String(incidentRow?.alert_id || projection?.alert_id || eventPayload?.alert_id || "").trim();
      const alertRow = alerts.rows.find((row) => String(row?.alert_id || row?.id || "").trim() === alertId);
      return alertRow ? { ...incidentRow, source_alert: alertRow } : incidentRow;
    });
  }, [incidentMetadata.rows, alerts.rows, applicationToMonitor]);

  const selectedMonitorScopeLabel = useMemo(
    () => monitorScopeLabel(applicationToMonitor),
    [applicationToMonitor],
  );
  const monitorApplicationGroups = useMemo(() => {
    const rowByName = new Map();
    monitoringApps.rows.forEach((row) => {
      const name = String(row?.name || row?.application || "").trim();
      if (name) rowByName.set(name.toLowerCase(), row);
    });
    alerts.rows.forEach((row) => {
      const name = projectIdentityFromAlert(row);
      if (name && !rowByName.has(name.toLowerCase())) rowByName.set(name.toLowerCase(), row);
    });
    const groups = { applications: [], tests: [], platform: [] };
    monitorApplications.forEach((name) => {
      if ([REAL_USE_CASE_SCOPE, TEST_USE_CASE_SCOPE].includes(name)) return;
      const row = rowByName.get(String(name).toLowerCase());
      if (CORE_MONITOR_PROJECTS.some((item) => item.toLowerCase() === String(name).toLowerCase())) {
        groups.platform.push(name);
      } else if (row && isTestApplicationRecord(row)) {
        groups.tests.push(name);
      } else {
        groups.applications.push(name);
      }
    });
    return groups;
  }, [alerts.rows, monitorApplications, monitoringApps.rows]);

  const visibleAlertSourceSummary = useMemo(() => {
    const summary = { prometheus: 0, telemetry: 0, email: 0, ticket: 0, log: 0 };
    visibleAlerts.forEach((row) => {
      const channels = Array.isArray(row?.source_channels) && row.source_channels.length
        ? row.source_channels
        : [normalizeAlertChannel(row)];
      channels.forEach((channel) => {
        const key = String(channel || "").trim().toLowerCase();
        if (summary[key] !== undefined) {
          summary[key] += 1;
        }
      });
    });
    return summary;
  }, [visibleAlerts]);

  const selectedAlertRow = useMemo(() => {
    const matchedRow = visibleAlerts.find(
      (row) => String(row?.alert_id || row?.id || row?.incident_id || "") === selectedAlertId
    );
    const snapshotId = String(
      selectedAlertSnapshot?.alert_id
      || selectedAlertSnapshot?.id
      || selectedAlertSnapshot?.incident_id
      || ""
    );
    const snapshotRow = snapshotId === selectedAlertId ? selectedAlertSnapshot : null;
    const payload = selectedAlertData?.payload?.data || selectedAlertData?.payload || {};
    const processedAlert = payload?.alert && typeof payload.alert === "object" ? payload.alert : {};
    const processedIncident = payload?.incident && typeof payload.incident === "object" ? payload.incident : {};
    const processedAlertId = String(processedAlert.alert_id || processedAlert.id || selectedAlertId || "").trim();
    const processedMatchesSelection = Boolean(
      processedAlertId
      && processedAlertId === String(selectedAlertId || "")
      && Object.keys(processedAlert).length
    );
    const baseRow = matchedRow || snapshotRow || (processedMatchesSelection ? processedAlert : null);
    if (!baseRow) return null;

    // Summary projections make the cockpit available immediately. Once the
    // processed result arrives, overlay its canonical fields so both views
    // describe the same record without losing the alert/incident relationship.
    return {
      ...baseRow,
      ...processedIncident,
      ...processedAlert,
      id: processedAlertId || baseRow.id,
      alert_id: processedAlertId || baseRow.alert_id,
      incident_id: processedIncident.id || processedIncident.incident_id || baseRow.incident_id,
      projection_payload: baseRow.projection_payload,
    };
  }, [visibleAlerts, selectedAlertId, selectedAlertSnapshot, selectedAlertData.payload, applicationToMonitor]);

  const evidenceDraftLoadRef = useRef({ key: "", loadedAt: 0 });

  // A landing-pad filename can be selected briefly while the backend promotes
  // it to a canonical alert. Never carry an RCA error from that transient
  // identity into the fully persisted incident cockpit.
  useEffect(() => {
    setSelectedAlertRegeneration({ loading: false, message: "", error: "" });
  }, [selectedAlertId]);

  const selectedAlertNavigation = useMemo(() => {
    const selectedIdentities = new Set([
      selectedAlertId,
      selectedAlertRow?.alert_id,
      selectedAlertRow?.id,
      selectedAlertRow?.incident_id,
    ].map((value) => String(value || "").trim()).filter(Boolean));
    const index = dashboardVisibleAlerts.findIndex((row) => [
      row?.alert_id,
      row?.id,
      row?.incident_id,
    ].some((value) => selectedIdentities.has(String(value || "").trim())));
    return {
      index,
      total: dashboardVisibleAlerts.length,
      previous: index > 0 ? dashboardVisibleAlerts[index - 1] : null,
      next: index >= 0 && index < dashboardVisibleAlerts.length - 1 ? dashboardVisibleAlerts[index + 1] : null,
    };
  }, [dashboardVisibleAlerts, selectedAlertId, selectedAlertRow]);

  const selectedAlertPayload = useMemo(() => {
    return selectedAlertData?.payload?.data || selectedAlertData?.payload || {};
  }, [selectedAlertData]);

  const selectedAlertWorkflow = useMemo(() => {
    return selectedAlertPayload?.workflow || selectedAlertPayload || {};
  }, [selectedAlertPayload]);

  const selectedAlertEvents = useMemo(() => {
    const events =
      selectedAlertWorkflow?.events
      || selectedAlertWorkflow?.workflow_events
      || selectedAlertWorkflow?.agent_events
      || [];
    return Array.isArray(events) ? events : [];
  }, [selectedAlertWorkflow]);

  const selectedAlertEventTrace = useMemo(() => {
    const rows =
      selectedAlertWorkflow?.event_trace
      || selectedAlertWorkflow?.trace_events
      || selectedAlertWorkflow?.trace?.events
      || [];
    if (!Array.isArray(rows)) {
      return [];
    }
    return rows
      .filter((row) => row && typeof row === "object")
      .sort((a, b) => {
        const aTime = parseUtcTimestamp(a.timestamp)?.getTime() || 0;
        const bTime = parseUtcTimestamp(b.timestamp)?.getTime() || 0;
        return aTime - bTime;
      })
      .slice(-300);
  }, [selectedAlertWorkflow]);

  const selectedAlertEventsDisplay = useMemo(() => {
    const buildBackgroundDetailText = (event) => {
      const items = [
        ["event_type", event?.event_type],
        ["event_stage", event?.event_stage],
        ["status", event?.status],
        ["source_channel", event?.source_channel],
        ["transport_channel", event?.transport_channel],
        ["transport_provider", event?.transport_provider],
        ["risk_tier", event?.risk_tier],
        ["execution_mode", event?.execution_mode],
        ["policy_reason", event?.policy_reason],
        ["trace_id", event?.trace_id],
      ]
        .map(([key, value]) => [key, String(value || "").trim()])
        .filter(([, value]) => value && value !== "-")
        .map(([key, value]) => `${key}: ${value}`);
      return items.join("\n");
    };

    const mappedEvents = selectedAlertEvents.map((event, index) => {
      const decision = event?.decision;
      const inputValue = extractEventInput(event);
      const outputValue = extractEventOutput(event);
      const input = typeof inputValue === "object" && inputValue ? inputValue : {};
      return {
        sequence: event?.sequence || index + 1,
        agent: displayAgentName(event?.agent || normalizeTraceServiceName(event) || "-"),
        action: event?.action || event?.event_type || event?.status || "-",
        eventType: event?.event_type || "",
        timestamp: event?.timestamp || "",
        decision: decision && typeof decision === "object" ? JSON.stringify(decision) : String(decision || "-"),
        output: stringifyTimelineValue(outputValue) || String(event?.event_type || "-"),
        communicates_to: event?.communicates_to || event?.transport_channel || input?.transport_channel || "-",
        inputValueText: stringifyTimelineValue(inputValue),
        outputValueText: stringifyTimelineValue(outputValue),
        errorValueText: extractEventError(event),
        backgroundDetailText: buildBackgroundDetailText(event),
      };
    });

    const traceRows = selectedAlertEventTrace.map((row, index) => {
      const inputValue = extractEventInput(row);
      const outputValue = extractEventOutput(row);
      return {
        sequence: index + 1,
        agent: displayAgentName(normalizeTraceServiceName(row)),
        action: summarizeEventType(row?.event_type),
        eventType: row?.event_type || "",
        timestamp: row?.timestamp || "",
        decision: row?.policy_reason || row?.status || row?.event_stage || "-",
        output: stringifyTimelineValue(outputValue) || row?.event_type || "-",
        communicates_to: row?.transport_channel || "-",
        inputValueText: stringifyTimelineValue(inputValue),
        outputValueText: stringifyTimelineValue(outputValue),
        errorValueText: extractEventError(row),
        backgroundDetailText: buildBackgroundDetailText(row),
      };
    });

    if (!traceRows.length) {
      return mappedEvents.map((row, index) => ({
        ...row,
        sequence: index + 1,
      }));
    }

    const mergedRows = [...mappedEvents];
    const seen = new Set(
      mappedEvents.map((row) => `${String(row.agent || "").toLowerCase()}|${String(row.action || "").toLowerCase()}|${String(row.decision || "").toLowerCase()}`)
    );

    traceRows.forEach((row) => {
      const key = `${String(row.agent || "").toLowerCase()}|${String(row.action || "").toLowerCase()}|${String(row.decision || "").toLowerCase()}`;
      if (!seen.has(key)) {
        seen.add(key);
        mergedRows.push(row);
      }
    });

    return mergedRows
      .map((row, index) => ({ ...row, sequence: index + 1 }))
      .slice(0, 300);
  }, [selectedAlertEvents, selectedAlertEventTrace]);

  const selectedAlertRagDocuments = useMemo(
    () => {
      if (Array.isArray(selectedAlertDocumentLinks.rows) && selectedAlertDocumentLinks.rows.length) {
        return selectedAlertDocumentLinks.rows;
      }
      return findAlertRagDocuments(selectedAlertRow);
    },
    [selectedAlertDocumentLinks.rows, selectedAlertRow, ragDocs.rows],
  );

  const selectedAlertKnowledgeDocument = useMemo(() => {
    const seen = new Set();
    const docs = selectedAlertRagDocuments.filter((doc) => {
      const key = String(doc?.path || doc?.title || doc?.document_id || "").trim().toLowerCase();
      if (!key) {
        return true;
      }
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
    if (!docs.length) {
      return null;
    }
    const first = docs[0] || {};
    const service = Array.isArray(first.services) ? first.services.join(", ") : String(first.services || selectedAlertRow?.service || "-");
    const severity = String(first.severity || selectedAlertRow?.severity || "-").toLowerCase();
    const kinds = Array.from(new Set(docs.map((doc) => String(doc?.kind || doc?.document_kind || "document").trim()).filter(Boolean)));
    const reasons = Array.from(new Set(docs.map((doc) => String(doc?.match_reason || "").trim()).filter(Boolean)));
    const confidence = docs
      .map((doc) => Number(doc?.match_confidence || 0))
      .filter((value) => Number.isFinite(value) && value > 0)
      .sort((a, b) => b - a)[0];
    return {
      title: docs.length === 1
        ? String(first.title || first.path || "Alert Knowledge Document").trim()
        : `${selectedAlertRow?.service || service || "Alert"} Knowledge Document`,
      summary: docs.length === 1
        ? String(first.summary || first.recommended_action || "Backend-linked document is available for download.").trim()
        : `Single dashboard document composed from ${docs.length} backend-linked knowledge source(s).`,
      service,
      severity,
      kinds,
      reasons,
      confidence,
      docs,
    };
  }, [selectedAlertRagDocuments, selectedAlertRow]);

  const selectedAlertDocumentContract = selectedAlertDocumentLinks.contract;

  const selectedAlertDetailsSource = useMemo(() => {
    if (selectedAlertData.loading) {
      if (selectedAlertData.payload) {
        return "Refreshing processed workflow result from monitoring-adapter.";
      }
      return "Loading processed result from monitoring adapter.";
    }
    if (selectedAlertData.payload) {
      return "Canonical processed workflow result; Discovery and Resolution LLM outputs are shown when available.";
    }
    if (selectedAlertData.error) {
      return "Processed workflow result unavailable; showing alert-stream fallback fields only.";
    }
    return "Alert-stream row selected; processed workflow result has not loaded yet.";
  }, [selectedAlertData.loading, selectedAlertData.payload, selectedAlertData.error]);

  const selectedAlertUsage = useMemo(() => {
    const rows = [];
    const appendUsage = (candidate) => {
      if (!Array.isArray(candidate)) {
        return;
      }
      candidate.forEach((item) => rows.push(normalizeUsageRow(item)));
    };

    const appendErrorUsage = (candidate) => {
      if (!Array.isArray(candidate)) {
        return;
      }
      candidate
        .filter((item) => item && typeof item === "object")
        .forEach((item) => {
          rows.push(normalizeUsageRow({
            task: item.task || item.agent || "llm-error",
            provider: item.provider || item.model_provider || "router",
            model: item.model || item.model_name || "-",
            note: item.error || item.message || item.reason || JSON.stringify(item),
            estimated: true,
          }));
        });
    };

    appendUsage(selectedAlertWorkflow?.recommendation?.metadata?.model_usage);
    appendUsage(selectedAlertWorkflow?.finops?.calls);
    appendUsage(selectedAlertWorkflow?.recommendation?.metadata?.llm_calls);
    appendErrorUsage(selectedAlertWorkflow?.finops?.errors);

    selectedAlertEventTrace.forEach((event) => {
      const payload = event?.payload && typeof event.payload === "object" ? event.payload : {};
      appendUsage(payload?.model_usage);
      appendUsage(payload?.llm_calls);
      appendUsage(payload?.finops?.calls);
      appendErrorUsage(payload?.finops?.errors);
    });

    return dedupeUsageRows(rows.filter((row) => isMeaningfulUsageRow(row)));
  }, [selectedAlertWorkflow, selectedAlertEventTrace]);

  const selectedFinopsDiagnostics = useMemo(() => {
    const workflowCalls = Array.isArray(selectedAlertWorkflow?.finops?.calls)
      ? selectedAlertWorkflow.finops.calls.length
      : 0;
    const workflowErrors = Array.isArray(selectedAlertWorkflow?.finops?.errors)
      ? selectedAlertWorkflow.finops.errors.length
      : 0;
    const recommendationUsage = Array.isArray(selectedAlertWorkflow?.recommendation?.metadata?.model_usage)
      ? selectedAlertWorkflow.recommendation.metadata.model_usage.length
      : 0;

    let traceCalls = 0;
    let traceErrors = 0;
    selectedAlertEventTrace.forEach((row) => {
      const payload = row?.payload && typeof row.payload === "object" ? row.payload : {};
      traceCalls += Array.isArray(payload?.finops?.calls) ? payload.finops.calls.length : 0;
      traceErrors += Array.isArray(payload?.finops?.errors) ? payload.finops.errors.length : 0;
    });

    return {
      usageRows: selectedAlertUsage.length,
      fallbackRows: selectedAlertUsage.filter((row) => row.fallback).length,
      workflowCalls,
      workflowErrors,
      recommendationUsage,
      traceCalls,
      traceErrors,
    };
  }, [selectedAlertWorkflow, selectedAlertEventTrace, selectedAlertUsage]);

  const selectedModelProviderRows = useMemo(() => {
    const providers = modelProviderStatus?.data?.providers && typeof modelProviderStatus.data.providers === "object"
      ? modelProviderStatus.data.providers
      : {};
    return Object.entries(providers).map(([name, value]) => ({
      name,
      configured: Boolean(value?.configured),
      healthy: Boolean(value?.healthy),
      model: String(value?.model || name),
      circuitOpen: Boolean(value?.circuit_open),
      failures: Number(value?.failure_count || 0),
      reason: String(value?.reason || ""),
    }));
  }, [modelProviderStatus]);

  const aiCapabilityStatus = useMemo(() => {
    const explicitStatus = String(modelProviderStatus?.data?.status || modelProviderStatus?.data?.overall_status || "").trim().toLowerCase();
    const configuredProviders = selectedModelProviderRows.filter((provider) => provider.configured);
    const unhealthyProviders = configuredProviders.filter((provider) => !provider.healthy || provider.circuitOpen);
    const statusUnavailable = Boolean(modelProviderStatus.error) && !modelProviderStatus.data;
    const degraded = ["degraded", "unavailable", "error", "failed", "unhealthy"].includes(explicitStatus)
      || unhealthyProviders.length > 0
      || statusUnavailable;
    const affectedProviders = unhealthyProviders.map((provider) => provider.name).join(", ");
    return {
      degraded,
      loading: Boolean(modelProviderStatus.loading),
      message: affectedProviders
          ? `${affectedProviders} reported an unhealthy or open-circuit state. Deterministic monitoring remains active and execution stays governed by backend policy.`
          : statusUnavailable
            ? "Provider status is unavailable. AI investigation may be delayed; deterministic monitoring remains active and execution stays governed by backend policy."
            : "",
    };
  }, [modelProviderStatus, selectedModelProviderRows]);

  const selectedAlertRouting = useMemo(() => extractObservedRoutingMetrics(selectedAlertWorkflow), [selectedAlertWorkflow]);

  const selectedAlertEvaluation = useMemo(() => {
    const recommendation = selectedAlertWorkflow?.recommendation && typeof selectedAlertWorkflow.recommendation === "object"
      ? selectedAlertWorkflow.recommendation
      : {};
    const metadata = recommendation?.metadata && typeof recommendation.metadata === "object" ? recommendation.metadata : {};
    const workflowIncidentId = String(selectedAlertWorkflow?.incident?.id || selectedAlertWorkflow?.incident_id || "").trim();
    const incidentMetaMatch = [
      ...monitorScopedIncidentMetadata,
      ...incidentMetadata.rows,
    ].find((row) => {
      const rowIncidentId = String(row?.incident_id || "").trim();
      const rowAlertId = String(row?.alert_id || "").trim();
      return (workflowIncidentId && rowIncidentId === workflowIncidentId)
        || (selectedAlertId && rowAlertId === selectedAlertId);
    }) || null;
    const projectionPayload =
      incidentMetaMatch?.projection_payload && typeof incidentMetaMatch.projection_payload === "object"
        ? incidentMetaMatch.projection_payload
        : {};
    const projectionEventPayload =
      projectionPayload?.event_payload && typeof projectionPayload.event_payload === "object"
        ? projectionPayload.event_payload
        : {};
    const projectedEvaluation =
      (projectionEventPayload?.evaluation && typeof projectionEventPayload.evaluation === "object" && projectionEventPayload.evaluation)
      || (projectionPayload?.evaluation && typeof projectionPayload.evaluation === "object" && projectionPayload.evaluation)
      || {};
    const evaluation = {
      ...projectedEvaluation,
      ...(metadata?.evaluation && typeof metadata.evaluation === "object" ? metadata.evaluation : {}),
    };
    const ragMatches = Array.isArray(metadata.rag_matches) ? metadata.rag_matches : [];
    const bestRagMatch = ragMatches.reduce((best, row) => {
      const value = Number(row?.match_confidence ?? row?._similarity ?? row?.similarity ?? row?.score ?? 0);
      return Number.isFinite(value) ? Math.max(best, value) : best;
    }, Number(metadata.rag_top_similarity || 0) || 0);
    const projectedCitationCoverage = Number(projectedEvaluation?.citation_coverage ?? projectedEvaluation?.citationCoverage);
    const projectedEvidenceCoverage = Number(projectedEvaluation?.evidence_coverage ?? projectedEvaluation?.evidenceCoverage);
    const projectedConfidence = Number(projectedEvaluation?.confidence_score ?? projectedEvaluation?.confidenceScore);
    const projectedRagMatch = Number(projectedEvaluation?.rag_match_score ?? projectedEvaluation?.ragMatchScore);
    const citations = Array.isArray(metadata.citations) ? metadata.citations : [];
    return normalizeEvaluationEnvelope(evaluation, {
      confidence: Number.isFinite(projectedConfidence) ? projectedConfidence : recommendation?.confidence,
      ragMatchScore: bestRagMatch || (Number.isFinite(projectedRagMatch) ? projectedRagMatch : 0),
      citationCoverage: Number.isFinite(projectedCitationCoverage)
        ? projectedCitationCoverage
        : Math.min(citations.length / 3, 1),
      evidenceCoverage: Number.isFinite(projectedEvidenceCoverage)
        ? projectedEvidenceCoverage
        : Math.min(
        (metadata.runbook_found ? 0.35 : 0)
        + (ragMatches.length ? 0.4 : 0)
        + (selectedAlertRagDocuments.length ? 0.25 : 0),
        1,
      ),
    });
  }, [
    selectedAlertWorkflow,
    selectedAlertRagDocuments.length,
    monitorScopedIncidentMetadata,
    incidentMetadata.rows,
    selectedAlertId,
  ]);

  const selectedIncidentId = useMemo(() => {
    const projection = selectedAlertRow?.projection_payload && typeof selectedAlertRow.projection_payload === "object"
      ? selectedAlertRow.projection_payload
      : {};
    const eventPayload = projection?.event_payload && typeof projection.event_payload === "object"
      ? projection.event_payload
      : {};
    return String(
      selectedAlertWorkflow?.incident?.id
      || selectedAlertWorkflow?.incident_id
      || selectedAlertRow?.incident_id
      || projection?.incident_id
      || eventPayload?.incident_id
      || ""
    ).trim();
  }, [selectedAlertWorkflow, selectedAlertRow]);

  useEffect(() => {
    if (!selectedIncidentId || !adminSession?.accessToken) {
      setSelectedCatalogStatus({ loading: false, incidentId: selectedIncidentId, data: null, error: "" });
      return undefined;
    }
    const controller = new AbortController();
    setSelectedCatalogStatus({ loading: true, incidentId: selectedIncidentId, data: null, error: "" });
    fetchJson(
      `/api-gateway/knowledge-development/incidents/${encodeURIComponent(selectedIncidentId)}/catalog-status`,
      authenticatedOptions({ signal: controller.signal, timeoutMs: 15000, maxAttempts: 1, staleTimeMs: 0 }),
    ).then((response) => {
      if (!controller.signal.aborted) setSelectedCatalogStatus({ loading: false, incidentId: selectedIncidentId, data: unwrap(response), error: "" });
    }).catch((error) => {
      if (!controller.signal.aborted) setSelectedCatalogStatus({ loading: false, incidentId: selectedIncidentId, data: null, error: String(error?.message || error) });
    });
    return () => controller.abort();
  }, [selectedIncidentId, adminSession?.accessToken, selectedAlertData.payload]);

  const selectedIncidentMetadataRow = useMemo(() => {
    if (!selectedIncidentId) {
      return null;
    }
    const scoped = monitorScopedIncidentMetadata.find(
      (row) => String(row?.incident_id || "").trim() === selectedIncidentId
    );
    if (scoped) {
      return scoped;
    }
    return incidentMetadata.rows.find((row) => String(row?.incident_id || "").trim() === selectedIncidentId) || null;
  }, [selectedIncidentId, monitorScopedIncidentMetadata, incidentMetadata.rows]);

  const selectedCanonicalIncidentStatus = useMemo(
    () => effectiveIncidentStatus(
      selectedIncidentMetadataRow?.status
        || selectedStageCompleteness.data?.status
        || canonicalIncidentStatus(
        selectedAlertWorkflow?.incident?.status,
        selectedAlertRow?.status,
        selectedAlertRow?.state,
        ),
      selectedIncidentMetadataRow?.approval_status
        || selectedIncidentMetadataRow?.projection_payload?.approval_status
        || (selectedIncidentMetadataRow?.latest_event_type === "incident.approval.recorded"
          ? selectedIncidentMetadataRow?.projection_payload?.event_payload?.decision
          : "")
        || selectedAlertWorkflow?.approval?.status,
    ),
    [
      selectedStageCompleteness.data?.status,
      selectedIncidentMetadataRow?.status,
      selectedAlertWorkflow?.incident?.status,
      selectedAlertWorkflow?.approval?.status,
      selectedIncidentMetadataRow?.approval_status,
      selectedIncidentMetadataRow?.projection_payload?.approval_status,
      selectedIncidentMetadataRow?.projection_payload?.event_payload?.decision,
      selectedIncidentMetadataRow?.latest_event_type,
      selectedAlertRow?.status,
      selectedAlertRow?.state,
    ],
  );

  const selectedAlertRecommendationId = useMemo(() => {
    if (!selectedIncidentId) {
      return "";
    }
    return (
      approvalRecommendationId(selectedIncidentMetadataRow)
      || approvalRecommendationFromPayload(selectedAlertWorkflow)
      || approvalRecommendationFromPayload(selectedAlertData?.payload)
      || ""
    );
  }, [selectedIncidentId, selectedIncidentMetadataRow, selectedAlertWorkflow, selectedAlertData?.payload]);

  const selectedAiTrust = useMemo(() => {
    const recommendation = selectedAlertWorkflow?.recommendation && typeof selectedAlertWorkflow.recommendation === "object"
      ? selectedAlertWorkflow.recommendation
      : {};
    const metadata = recommendation?.metadata && typeof recommendation.metadata === "object" ? recommendation.metadata : {};
    const canonical = canonicalIncidentEvidence(selectedAlertWorkflow);
    const hasAcceptedEvidence = canonical.evidence.some((row) => row.accepted === true);
    const providerRow = selectedAlertUsage.find((row) => row.provider !== "-" || row.model !== "-");
    const fallbackUsed = selectedAlertUsage.some((row) => row.fallback);
    const confidenceReasons = [
      `${canonical.evidence.length} linked evidence source(s)`,
      `${formatQualityPercent(selectedAlertEvaluation.citationCoverage)} citation coverage`,
      `${formatQualityPercent(selectedAlertEvaluation.groundingScore)} grounding`,
      canonical.missing.length ? `${canonical.missing.length} evidence gap(s)` : "No declared evidence gaps",
    ];
    return {
      ...canonical,
      confidence: hasAcceptedEvidence ? canonical.confidence : 0,
      confidenceLabel: hasAcceptedEvidence ? canonical.confidenceLabel : "Ungrounded",
      confidenceActionable: hasAcceptedEvidence && canonical.confidenceActionable === true,
      providerRow,
      fallbackUsed,
      confidenceReasons,
    };
  }, [selectedAlertWorkflow, selectedAlertUsage, selectedAlertEvaluation]);

  const selectedRcaDecision = useMemo(() => {
    const analysis = canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow);
    const impact = analysis.impactAnalysis && typeof analysis.impactAnalysis === "object" ? analysis.impactAnalysis : {};
    const impactedServices = Array.isArray(impact.impacted_services)
      ? impact.impacted_services.map((value) => cleanRecommendationText(value, "")).filter(Boolean)
      : [];
    const evidenceUsed = Array.isArray(impact.evidence_used) ? impact.evidence_used.map((value) => cleanRecommendationText(value, "")).filter(Boolean) : [];
    const causalDetails = cleanRecommendationText(
      analysis.rca?.causal_chain || analysis.rca?.mechanism || analysis.rca?.reasoning || analysis.rca?.contributing_factors,
      "The causal mechanism was not supplied by the current analysis.",
    );
    const hasLinkedEvidence = selectedAiTrust.evidence.some((row) => row.accepted === true);
    // This is the backend's bounded diagnostic confidence. Grounding and
    // execution eligibility are enforced independently below.
    const confidence = Number(selectedAiTrust.confidence ?? 0);
    const investigation = selectedAlertWorkflow?.recommendation?.metadata?.investigation_report
      || selectedAlertWorkflow?.recommendation?.metadata?.iterative_investigation
      || {};
    const investigationConclusive = investigation?.conclusive === true
      && String(investigation?.status || "").toLowerCase() === "conclusive";
    const investigationConfidence = Number(investigation?.conclusion?.confidence || 0);
    const groundingScore = Number(selectedAlertEvaluation.groundingScore || 0);
    const reviewRequired = Boolean(
      selectedAlertEvaluation.requiresReview
      || !hasLinkedEvidence
      || confidence < 0.85
      || groundingScore < 0.85
      || !investigationConclusive
      || investigationConfidence < 0.85
      || selectedAiTrust.missing.length
      || selectedAiTrust.conflicting.length
      || analysis.status !== "resolved-analysis"
    );
    return {
      ...analysis,
      confidence,
      reviewRequired,
      confidenceKind: selectedAiTrust.confidenceKind,
      confidenceActionable: selectedAiTrust.confidenceActionable,
      confidenceLabel: !hasLinkedEvidence ? "Ungrounded" : selectedAiTrust.confidenceLabel,
      impactedServices,
      causalDetails,
      impactEvidence: evidenceUsed,
      customerImpact: readableImpactText(
        impact.customer_impact || impact.user_impact || impact.business_impact,
        "No confirmed customer or business impact was found in the collected evidence.",
      ),
      serviceImpact: readableImpactText(
        impact.observed_impact || impact.service_impact || impact.impact_summary || analysis.impact,
        impactedServices.length
          ? `Observed operational signals affect ${impactedServices.join(", ")}; customer impact remains unconfirmed.`
          : "Observed service impact is not yet quantified.",
      ),
      dependencyImpact: readableImpactText(impact.dependency_impact, "Dependency impact was not established by the collected evidence."),
      urgency: cleanRecommendationText(impact.severity_rationale || impact.urgency, selectedAlertRow?.severity ? `${selectedAlertRow.severity} alert priority; business urgency requires operator validation.` : "Operational urgency was not established."),
    };
  }, [selectedAlertWorkflow, selectedAlertRow, selectedAlertEvaluation, selectedAiTrust.evidence.length, selectedAiTrust.missing.length, selectedAiTrust.conflicting.length]);

  const selectedInvestigationReport = selectedAlertWorkflow?.recommendation?.metadata?.investigation_report
    || selectedAlertWorkflow?.recommendation?.metadata?.iterative_investigation
    || {};
  const selectedInvestigationConclusive = selectedInvestigationReport?.conclusive === true
    && String(selectedInvestigationReport?.status || "").toLowerCase() === "conclusive";
  const selectedInvestigationConfidence = Number(selectedInvestigationReport?.conclusion?.confidence || 0);

  const selectedRelevantRcaEvidence = useMemo(() => {
    // Preserve backend-linked evidence; free-text rematching can discard normalized records.
    return selectedAiTrust.evidence;
  }, [selectedAiTrust.evidence]);
  const selectedAlertAuthenticity = String(
    selectedAlertRow?.labels?.event_authenticity
    || selectedAlertRow?.event_authenticity
    || "unverified"
  ).toLowerCase();

  useEffect(() => {
    const alertId = String(selectedAlertId || "").trim();
    if (!adminSession.accessToken || !alertId || selectedAlertDocumentLinks.loading || selectedAlertDocumentLinks.rows.length) {
      if (selectedAlertDocumentLinks.rows.length) setEvidenceDraftReview({ loading: false, draft: null, content: "", notes: "", error: "", message: "" });
      return;
    }
    const requestKey = [
      alertId,
      selectedAlertDocumentLinks.rows.length,
      selectedRcaDecision.rootCause,
      selectedRelevantRcaEvidence.length,
      selectedRcaDecision.reviewRequired,
    ].join("|");
    const now = Date.now();
    if (
      evidenceDraftLoadRef.current.key === requestKey
      && now - evidenceDraftLoadRef.current.loadedAt < 30_000
    ) return;
    evidenceDraftLoadRef.current = { key: requestKey, loadedAt: now };
    let cancelled = false;
    setEvidenceDraftReview((current) => ({ ...current, loading: true, error: "" }));
    fetchJson(`/api-gateway/rag/evidence-drafts?alert_id=${encodeURIComponent(alertId)}`, authenticatedOptions())
      .then(async (response) => {
        if (cancelled) return;
        let drafts = unwrap(response)?.drafts || [];
        let draft = drafts[0] || null;
        if (drafts.filter((item) => item?.document_kind).length < ALERT_DOC_KIND_OPTIONS.length && selectedRcaDecision.rootCause && selectedRelevantRcaEvidence.length) {
          const { evidenceIds, sourceUris, ready: provenanceReady } = draftEvidenceProvenance(selectedRelevantRcaEvidence);
          if (!provenanceReady) {
            throw new Error("A review document requires at least one accepted evidence record with a traceable source citation. Collect or review source evidence before creating the draft.");
          }
          const content = buildRcaEvidenceDocumentDraft({ alertId, alert: selectedAlertRow, decision: selectedRcaDecision, workflow: selectedAlertWorkflow, evidence: selectedRelevantRcaEvidence });
          const workflowBinding = selectedAlertWorkflow?.incident_investigation || {};
          const incidentId = String(workflowBinding.incident_id || selectedIncidentId || "").trim();
          let binding = workflowBinding;
          if (incidentId) {
            const operationsResponse = await fetchJson(
              `/api-gateway/incidents/${encodeURIComponent(incidentId)}/operations-state`,
              authenticatedOptions({ maxAttempts: 1, staleTimeMs: 0 }),
            );
            binding = unwrap(operationsResponse)?.investigation_workspace?.binding || workflowBinding;
          }
          const requiredBinding = {
            incident_id: binding.incident_id || incidentId,
            alert_id: binding.alert_id || alertId,
            analysis_request_id: binding.analysis_request_id,
            context_snapshot_id: binding.context_snapshot_id || binding.snapshot_id,
            context_fingerprint: binding.context_fingerprint,
            recommendation_id: binding.recommendation_id,
            rca_version: binding.rca_version,
          };
          if (Object.values(requiredBinding).some((value) => value === undefined || value === null || value === "" || value === 0)) {
            throw new Error("A current governed RCA binding is not available yet. Run fresh analysis before creating review documents.");
          }
          const created = await fetchJson("/api-gateway/rag/evidence-drafts", authenticatedOptions({ method: "POST", body: JSON.stringify({ ...requiredBinding, alert_type: selectedAlertRow?.name || selectedAlertRow?.alert_name, severity: selectedAlertRow?.severity, environment: selectedAlertRow?.environment, content, services: [selectedAlertRow?.service].filter(Boolean), evidence_ids: evidenceIds, source_uris: sourceUris }) }));
          drafts = unwrap(created)?.drafts || [unwrap(created)?.draft].filter(Boolean);
          draft = unwrap(created)?.draft || drafts[0] || null;
        }
        const draftContent = String(draft?.content || "");
        const canonicalContent = buildRcaEvidenceDocumentDraft({
          alertId,
          alert: selectedAlertRow,
          decision: selectedRcaDecision,
          workflow: selectedAlertWorkflow,
          evidence: selectedRelevantRcaEvidence,
        });
        const resolvedDraftContent = incidentDraftHasSubstantiveContent(draftContent)
          ? draftContent
          : canonicalContent;
        const alreadyContainsRca = Boolean(selectedRcaDecision.rootCause && resolvedDraftContent.toLowerCase().includes(String(selectedRcaDecision.rootCause).trim().toLowerCase()));
        const rcaAppendix = draft && selectedRcaDecision.rootCause && !selectedRcaDecision.reviewRequired && selectedRelevantRcaEvidence.length && !alreadyContainsRca ? ["", "## Completed RCA", selectedRcaDecision.rootCause, "", "## Impact", selectedRcaDecision.customerImpact, "", "## Recommended response", selectedRcaDecision.action || "No action supplied.", "", `Confidence: ${Math.round(Number(selectedRcaDecision.confidence || 0) * 100)}%`].join("\n") : "";
        const insufficientMessage = selectedRelevantRcaEvidence.length ? "A root-cause hypothesis is not available yet. Continue investigation before creating a review draft." : "Relevant project evidence is missing. KaiMS will not generate or publish an RCA until real source evidence arrives.";
        setEvidenceDraftReview({ loading: false, drafts, draft, content: draft ? `${resolvedDraftContent}${rcaAppendix}` : "", notes: "", error: draft ? "" : insufficientMessage, message: draft ? "Document drafts created and stored automatically. Review and edit each draft before publication." : "" });
      })
      .catch((error) => { if (!cancelled) setEvidenceDraftReview((current) => ({ ...current, loading: false, error: String(error?.message || error) })); });
    return () => { cancelled = true; };
  }, [adminSession.accessToken, selectedAlertId, selectedAlertDocumentLinks.loading, selectedAlertDocumentLinks.rows.length, selectedRcaDecision.rootCause, selectedRcaDecision.customerImpact, selectedRcaDecision.action, selectedRcaDecision.reviewRequired, selectedRelevantRcaEvidence]);

  const selectedExecutionPlan = useMemo(() => {
    const projectionPayload =
      selectedIncidentMetadataRow?.projection_payload && typeof selectedIncidentMetadataRow.projection_payload === "object"
        ? selectedIncidentMetadataRow.projection_payload
        : {};
    const recommendation =
      typeof selectedAlertWorkflow?.recommendation === "object" && selectedAlertWorkflow.recommendation
        ? selectedAlertWorkflow.recommendation
        : {};
    const recommendationMetadata =
      typeof recommendation?.metadata === "object" && recommendation.metadata
        ? recommendation.metadata
        : {};
    const decision =
      (typeof selectedAlertWorkflow?.decision === "object" && selectedAlertWorkflow.decision)
      || (typeof selectedAlertWorkflow?.orchestration_decision === "object" && selectedAlertWorkflow.orchestration_decision)
      || (typeof recommendationMetadata?.orchestration_decision === "object" && recommendationMetadata.orchestration_decision)
      || {};
    const remediationAction =
      typeof selectedAlertWorkflow?.remediation_action === "object" && selectedAlertWorkflow.remediation_action
        ? selectedAlertWorkflow.remediation_action
        : typeof projectionPayload?.remediation_action === "object" && projectionPayload.remediation_action
          ? projectionPayload.remediation_action
          : {};
    const approval =
      typeof selectedAlertWorkflow?.approval === "object" && selectedAlertWorkflow.approval
        ? selectedAlertWorkflow.approval
        : typeof projectionPayload?.approval === "object" && projectionPayload.approval
          ? projectionPayload.approval
        : {};
    const workflowForExecution = {
      ...(projectionPayload && typeof projectionPayload === "object" ? projectionPayload : {}),
      ...(selectedAlertWorkflow && typeof selectedAlertWorkflow === "object" ? selectedAlertWorkflow : {}),
      remediation_action: remediationAction,
      approval,
    };
    const commands = deriveExecutionCommands(workflowForExecution, selectedAlertEventTrace);
    const catalogPlan =
      (typeof recommendationMetadata?.execution_plan === "object" && recommendationMetadata.execution_plan)
      || (typeof decision?.execution_plan === "object" && decision.execution_plan)
      || {};

    return {
      action:
        recommendation?.recommended_action
        || remediationAction?.action
        || selectedAlertRouting?.next_action
        || selectedAlertWorkflow?.next_step
        || "-",
      target:
        catalogPlan?.remediation_target
        || catalogPlan?.actions?.[0]?.target_resource_id
        || "",
      expectedOutcome:
        catalogPlan?.actions?.[0]?.expected_outcome
        || "",
      rationale:
        recommendation?.rationale
        || remediationAction?.reason
        || selectedAlertRouting?.policy_reason
        || recommendation?.policy_reason
        || "-",
      requiresApproval:
        // Unlike the other fields on this object, this one is consumed as a
        // This value controls approval routing and must remain a real boolean;
        // the shared "-" placeholder would be truthy and incorrectly require
        // approval when no routing decision is available yet.
        selectedAlertRouting?.requires_approval
        ?? decision?.requires_approval
        ?? selectedAlertWorkflow?.approval?.required
        ?? false,
      workflow: selectedAlertRouting?.workflow || decision?.workflow || selectedAlertWorkflow?.scenario?.id || "-",
      executionMode: selectedAlertRouting?.execution_mode || decision?.execution_mode || "-",
      riskTier: selectedAlertRouting?.risk_tier || decision?.risk_tier || "-",
      provider: selectedAlertRouting?.message_bus_provider || decision?.message_bus_provider || "-",
      incidentStatus: selectedCanonicalIncidentStatus,
      approvalStatus:
        approval?.status
        || projectionPayload?.approval_status
        || (selectedIncidentMetadataRow?.latest_event_type === "incident.approval.recorded"
          ? projectionPayload?.event_payload?.decision
          : "")
        || "pending",
      approval,
      commands,
      catalogPlan,
      recommendationId: String(recommendation?.id || recommendation?.recommendation_id || "").trim(),
      remediationAction,
      remediationAnalysis: typeof recommendationMetadata?.remediation_analysis === "object" ? recommendationMetadata.remediation_analysis : {},
    };
  }, [selectedAlertWorkflow, selectedAlertRouting, selectedAlertEventTrace, selectedIncidentMetadataRow, selectedCanonicalIncidentStatus]);
  const selectedGovernedExecutionTarget = String(
    selectedExecutionPlan.target
    || selectedExecutionPlan.catalogPlan?.remediation_target
    || selectedExecutionPlan.catalogPlan?.actions?.[0]?.target_resource_id
    || ""
  ).trim();
  const selectedExecutionBreakdown = useMemo(() => {
    const grouped = { commands: [], scripts: [], queries: [] };
    (Array.isArray(selectedExecutionPlan.commands) ? selectedExecutionPlan.commands : []).forEach((item) => {
      const line = String(item || "").trim();
      if (!line) {
        return;
      }
      const normalized = line
        .replace(/^\s*(cmd|command)\s*:/i, "")
        .replace(/^\s*script\s*:/i, "script: ")
        .replace(/^\s*query\s*:/i, "query: ")
        .trim();
      if (!normalized || /^#/.test(normalized) || /^preview only/i.test(normalized) || /^recommended_action/i.test(normalized)) {
        return;
      }
      if (/^script\s*:/i.test(normalized)) {
        grouped.scripts.push(normalized.replace(/^script\s*:/i, "").trim());
        return;
      }
      if (/^query\s*:/i.test(normalized)) {
        grouped.queries.push(normalized.replace(/^query\s*:/i, "").trim());
        return;
      }
      grouped.commands.push(normalized);
    });
    const agentValidation = Array.isArray(selectedExecutionPlan.remediationAnalysis?.validation_queries)
      ? selectedExecutionPlan.remediationAnalysis.validation_queries
      : [];
    agentValidation.forEach((item) => {
      const query = String(item || "").trim();
      if (query && !grouped.queries.includes(query)) grouped.queries.push(query);
    });
    const hasPlan = grouped.commands.length > 0 || grouped.scripts.length > 0 || grouped.queries.length > 0;
    return {
      ...grouped,
      hasPlan,
      incidentStatus: String(selectedExecutionPlan.incidentStatus || "-").trim().toLowerCase(),
      approvalStatus: normalizeApprovalStatus(selectedExecutionPlan.approvalStatus || "pending"),
    };
  }, [selectedExecutionPlan]);
  const selectedRemediationOutcome = useMemo(() => {
    const latestResponse = unwrap(remediationExecutionState.result);
    const responseOutcome = remediationOutcomeFromAction(latestResponse);
    const persistedAction = selectedExecutionPlan.remediationAction;
    const persistedOutcome = remediationOutcomeFromAction(persistedAction);
    const responseId = String(latestResponse?.id || "");
    const persistedId = String(persistedAction?.id || "");
    const persistedStatus = String(persistedAction?.status || "").trim().toLowerCase();
    const persistedIsTerminal = ["succeeded", "failed", "skipped", "completed", "closed", "resolved", "policy_blocked", "dispatch_failed", "execution_failed", "validation_failed", "rolled_back", "rollback_failed", "timed_out", "cancelled", "manual_intervention_required"].includes(persistedStatus);
    // Hydrated persistence is authoritative once it represents the same
    // action. Temporal acknowledges an asynchronous execution with a preview
    // action ID, while the worker may persist the completed action under a
    // different ID. A terminal action for this selected incident must replace
    // that non-terminal preview or the cockpit remains stuck on "running".
    if (persistedOutcome && (persistedIsTerminal || (responseId && responseId === persistedId))) {
      return persistedOutcome;
    }
    if (responseOutcome) {
      return responseOutcome;
    }
    return persistedOutcome;
  }, [remediationExecutionState.result, selectedExecutionPlan.remediationAction]);
  const selectedExecutionTechnicalResponse = useMemo(() => {
    const latestResponse = unwrap(remediationExecutionState.result);
    const persistedAction = selectedExecutionPlan.remediationAction;
    const responseId = String(latestResponse?.id || "");
    const persistedId = String(persistedAction?.id || "");
    const persistedStatus = String(persistedAction?.status || "").trim().toLowerCase();
    const persistedIsTerminal = ["succeeded", "failed", "skipped", "completed", "closed", "resolved", "policy_blocked", "dispatch_failed", "execution_failed", "validation_failed", "rolled_back", "rollback_failed", "timed_out", "cancelled", "manual_intervention_required"].includes(persistedStatus);
    const candidates = [
      ...(persistedIsTerminal || (responseId && responseId === persistedId) ? [persistedAction?.parameters?.execution_result, persistedAction] : []),
      latestResponse?.parameters?.execution_result,
      latestResponse,
      persistedAction?.parameters?.execution_result,
      persistedAction,
    ];
    return candidates.find((value) => value && typeof value === "object" && Object.keys(value).length > 0) || { message: "No executor details were returned." };
  }, [remediationExecutionState.result, selectedExecutionPlan.remediationAction]);

  const persistedExecutionStatus = String(selectedExecutionPlan.remediationAction?.status || "").trim().toLowerCase();
  useEffect(() => {
    if (!remediationExecutionState.loading || !remediationExecutionState.result) return;
    if (!["succeeded", "failed", "skipped", "completed", "closed", "resolved", "policy_blocked", "dispatch_failed", "execution_failed", "validation_failed", "rolled_back", "rollback_failed", "timed_out", "cancelled", "manual_intervention_required"].includes(persistedExecutionStatus)) return;
    setRemediationExecutionState((current) => ({ ...current, loading: false }));
  }, [persistedExecutionStatus, remediationExecutionState.loading, remediationExecutionState.result]);

  useEffect(() => {
    if (!remediationExecutionState.loading || !remediationExecutionState.result || !selectedAlertId) return undefined;
    // Execution is asynchronous. Keep the selected workflow hydrated until the
    // remediation action reaches a terminal state so Act and Validate advance
    // without requiring an operator to reload the page.
    const timer = window.setTimeout(() => {
      void loadAlertDetails(selectedAlertId, selectedAlertRow, { background: true });
    }, 3000);
    return () => window.clearTimeout(timer);
  }, [remediationExecutionState.loading, remediationExecutionState.result, persistedExecutionStatus, selectedAlertId, selectedAlertData.payload]);

  const selectedApplicationConnection = useMemo(() => {
    const workflowContext = typeof selectedAlertWorkflow?.context === "object" && selectedAlertWorkflow.context
      ? selectedAlertWorkflow.context
      : {};
    const incident = typeof selectedAlertWorkflow?.incident === "object" && selectedAlertWorkflow.incident
      ? selectedAlertWorkflow.incident
      : {};
    const recommendation = typeof selectedAlertWorkflow?.recommendation === "object" && selectedAlertWorkflow.recommendation
      ? selectedAlertWorkflow.recommendation
      : {};
    const metadata = typeof recommendation?.metadata === "object" && recommendation.metadata ? recommendation.metadata : {};
    const workflowDecision =
      (typeof selectedAlertWorkflow?.decision === "object" && selectedAlertWorkflow.decision)
      || (typeof selectedAlertWorkflow?.orchestration_decision === "object" && selectedAlertWorkflow.orchestration_decision)
      || (typeof metadata?.orchestration_decision === "object" && metadata.orchestration_decision)
      || selectedAlertRouting
      || {};
    const resolvedExecutionPlan = typeof workflowDecision?.execution_plan === "object" && workflowDecision.execution_plan
      ? workflowDecision.execution_plan
      : {};
    const resolvedConnector = typeof resolvedExecutionPlan?.connection?.connector === "object" && resolvedExecutionPlan.connection.connector
      ? resolvedExecutionPlan.connection.connector
      : {};
    const service = String(
      selectedAlertRow?.service
      || incident?.service
      || selectedIncidentMetadataRow?.service
      || metadata?.service
      || workflowContext?.service
      || ""
    ).trim();
    const application = String(
      selectedAlertRow?.application
      || selectedAlertRow?.project_name
      || selectedAlertRow?.project
      || selectedIncidentMetadataRow?.application
      || applicationToMonitor
      || ""
    ).trim();
    const appRow = monitoringApps.rows.find((row) => {
      const rowName = String(row?.name || "").trim().toLowerCase();
      const rowService = String(row?.service || row?.labels?.service || "").trim().toLowerCase();
      return (application && rowName === application.toLowerCase()) || (service && rowService === service.toLowerCase());
    }) || {};
    const endpoint = String(
      metadata?.connection_url
      || metadata?.endpoint_url
      || resolvedConnector?.endpoint
      || workflowContext?.observability?.metrics_endpoint
      || appRow?.metrics_endpoint
      || onboardingForm.monitoring_url
      || onboardingForm.prometheus_url
      || ""
    ).trim();
    const environment = String(
      selectedAlertRow?.environment
      || incident?.environment
      || selectedIncidentMetadataRow?.environment
      || metadata?.environment
      || appRow?.environment
      || "prod"
    ).trim();
    const namespace = String(metadata?.namespace || appRow?.namespace || environment || "prod").trim();
    // Older persisted incidents may predate execution-connector metadata. The
    // governed connector catalog resolves those services through generic-api,
    // whose production credential reference is the default platform token.
    // Persist/reference the URI only; no credential value is exposed here.
    const governedDefaultCredential = ["prod", "production"].includes(environment.toLowerCase())
      ? "vault://kaiops/prod/default-token"
      : `vault://kaiops/${environment.toLowerCase() || "local"}/default-token`;
    const credentialRef = String(
      metadata?.credential_ref
      || metadata?.secret_ref
      || resolvedConnector?.secret_ref
      || appRow?.secret_ref
      || onboardingForm.connection_secret_ref
      || governedDefaultCredential
    ).trim();
    return {
      application: application || "-",
      service: service || "-",
      environment: environment || "prod",
      namespace,
      endpoint: endpoint || "Not configured",
      connection_type: String(resolvedConnector?.type || (endpoint ? "metrics/application endpoint" : "missing connection details")),
      source: Object.keys(resolvedConnector).length ? "resolved workflow connector" : endpoint ? "onboarding/application metadata + governed default identity" : "governed default connector",
      credential_ref: credentialRef,
      credential_store: credentialRef.startsWith("arn:aws:secretsmanager:")
        ? "aws_secrets_manager"
        : credentialRef.startsWith("k8s-secret://")
          ? "kubernetes_secret"
          : credentialRef.startsWith("https://") && credentialRef.includes(".vault.azure.net/secrets/")
            ? "azure_key_vault"
            : "hashicorp_vault",
    };
  }, [
    selectedAlertWorkflow,
    selectedAlertRow,
    selectedIncidentMetadataRow,
    selectedAlertRouting,
    monitoringApps.rows,
    onboardingForm.monitoring_url,
    onboardingForm.prometheus_url,
    onboardingForm.connection_secret_ref,
    applicationToMonitor,
  ]);

  useEffect(() => {
    const suggestedScript = selectedExecutionBreakdown.scripts.length
      ? selectedExecutionBreakdown.scripts.join("\n")
      : !selectedExecutionBreakdown.commands.length && selectedExecutionBreakdown.hasPlan
        ? buildKaiOpsRemediationScript({
            service: selectedApplicationConnection.service !== "-" ? selectedApplicationConnection.service : selectedApplicationConnection.application,
            environment: selectedApplicationConnection.environment,
            apiGatewayUrl: "http://api-gateway:8000",
            prometheusUrl: selectedApplicationConnection.endpoint !== "Not configured"
              ? selectedApplicationConnection.endpoint
              : onboardingForm.prometheus_url || onboardingForm.monitoring_url || "http://prometheus:9090",
            mysqlHost: "mysql",
            mysqlDatabase: "kaiops",
            mysqlUser: "kaiops",
          })
        : "";
    setRemediationPlanEditor({
      commands: suggestedScript ? "" : selectedExecutionBreakdown.commands.join("\n"),
      scripts: redactOperationalSecrets(suggestedScript),
      // Validation is an independent safety contract. A remediation script
      // must never hide or discard the checks that prove recovery.
      queries: selectedExecutionBreakdown.queries.join("\n"),
      connection_url: selectedExecutionBreakdown.hasPlan
        ? LOCAL_JENKINS_ENDPOINT
        : selectedApplicationConnection.endpoint === "Not configured" ? "" : selectedApplicationConnection.endpoint,
      connection_type: selectedExecutionBreakdown.hasPlan ? "jenkins" : selectedApplicationConnection.connection_type || "application",
      executor_type: selectedExecutionBreakdown.hasPlan ? "jenkins" : "",
      job_name: selectedExecutionBreakdown.hasPlan ? LOCAL_JENKINS_JOB : "",
      namespace: selectedApplicationConnection.namespace || "",
      credential_ref: selectedExecutionBreakdown.hasPlan
        ? selectedApplicationConnection.credential_ref || LOCAL_JENKINS_CREDENTIAL_REF
        : selectedApplicationConnection.credential_ref || "",
      credential_store: selectedApplicationConnection.credential_store || "hashicorp_vault",
      notes: "",
    });
    setRemediationExecutionState({ loading: false, result: null, error: "" });
  }, [
    selectedAlertId,
    selectedExecutionBreakdown.commands.join("\n"),
    selectedExecutionBreakdown.scripts.join("\n"),
    selectedExecutionBreakdown.queries.join("\n"),
    selectedExecutionBreakdown.hasPlan,
    selectedApplicationConnection.endpoint,
    selectedApplicationConnection.connection_type,
    selectedApplicationConnection.namespace,
    selectedApplicationConnection.service,
    selectedApplicationConnection.application,
    selectedApplicationConnection.environment,
    selectedApplicationConnection.credential_ref,
    selectedApplicationConnection.credential_store,
    onboardingForm.prometheus_url,
    onboardingForm.monitoring_url,
  ]);

  useEffect(() => {
    setExecutionPreflightState({ signature: "", checkedAt: "", passed: false });
    setApprovedExecutionSignature("");
    setApprovedExecutionApprovalId("");
    setExecutionApprovalRequiresRenewal(false);
    setExecutionConfirmationText("");
    setRemediationExecutionState({ loading: false, result: null, error: "" });
  }, [selectedAlertId]);

  const dangerousProductionAction = ["prod", "production"].includes(String(selectedApplicationConnection.environment || "").toLowerCase())
    && (["high", "critical"].includes(String(selectedExecutionPlan.riskTier || selectedAlertRow?.severity || "").toLowerCase()) || selectedExecutionBreakdown.hasPlan);
  const executionPlanLines = [...toPlanLines(remediationPlanEditor.commands), ...toPlanLines(remediationPlanEditor.scripts)]
    .map((line) => line.trim().toLowerCase())
    .filter((line) => line && !line.startsWith("#"));
  const executionIsReadOnly = executionPlanLines.length > 0 && executionPlanLines.every((line) => {
    // This script is a diagnostic collector for every flag value. The legacy
    // --dry-run switch never adds a corrective capability.
    if (/kaiops_alert_health_triage\.sh\b/.test(line)) return true;
    if (/^(set\s+-|[a-z_][a-z0-9_]*=|echo\b|printf\b)/.test(line)) return true;
    if (/--dry-run(?:=|\s+)(?:true|1)\b/.test(line)) return true;
    if (/^kubectl\s+(?:get|describe|logs|top|auth\s+can-i)\b/.test(line)) return true;
    if (/^kubectl\s+rollout\s+(?:status|history)\b/.test(line)) return true;
    if (/^(?:systemctl|service)\s+status\b/.test(line)) return true;
    if (/^(?:mysql|psql)\b/.test(line) && /\b(?:select|show|describe|explain)\b/.test(line) && !/\b(?:update|insert|delete|alter|drop|truncate|grant|revoke)\b/.test(line)) return true;
    if (/^curl\b/.test(line) && !/(?:\s-x\s*(?:post|put|patch|delete)\b|\s--request\s+(?:post|put|patch|delete)\b|\s(?:-d|--data(?:-raw|-binary)?)\b)/.test(line)) return true;
    return false;
  });
  // Only the persisted execution plan is authoritative for the diagnostic
  // completion transition. The model's remediation_analysis is advisory and
  // may describe an earlier diagnostic proposal that the catalog subsequently
  // replaced with a corrective plan.
  const finalizedExecutionIsDiagnosticOnly = String(selectedExecutionPlan.catalogPlan?.plan_kind || "").trim().toLowerCase() === "diagnostic"
    || selectedExecutionPlan.catalogPlan?.diagnostic_only === true
    || selectedExecutionPlan.catalogPlan?.classification?.diagnostic_only === true
    || selectedExecutionPlan.catalogPlan?.execution_ready === false;
  const analysisSuggestsDiagnosticOnly = String(selectedExecutionPlan.remediationAnalysis?.plan_kind || "").trim().toLowerCase() === "diagnostic"
    || selectedExecutionPlan.remediationAnalysis?.execution_ready === false;
  const inferredExecutionIsDiagnosticOnly = executionIsReadOnly
    || finalizedExecutionIsDiagnosticOnly
    || analysisSuggestsDiagnosticOnly
    || selectedExecutionPlan.remediationAction?.parameters?.diagnostic_closure === true;
  const watchOnlyCandidates = [
    selectedAlertWorkflow?.recommendation,
    selectedAlertWorkflow?.recommendation?.metadata,
    selectedAlertWorkflow?.decision,
    selectedAlertWorkflow?.incident,
    selectedAlertRow,
    selectedAlertRow?.metadata,
  ].filter((value) => value && typeof value === "object");
  const resolutionControl = resolveResolutionControl(watchOnlyCandidates, {
    diagnosticOnly: inferredExecutionIsDiagnosticOnly,
    finalizedDiagnostic: finalizedExecutionIsDiagnosticOnly,
  });
  const executionIsDiagnosticOnly = resolutionControl.diagnosticOnly;
  const executionIsWatchOnly = resolutionControl.disposition === "watch_only";
  // Viewing an incident must never mutate its lifecycle. Watch-only closure is
  // rendered only after the backend has persisted a terminal incident state;
  // it is not initiated by opening the cockpit.
  const executionAutoCloses = resolutionControl.autoClose
    && ["closed", "resolved"].includes(selectedCanonicalIncidentStatus);
  const executionRequiresCredential = dangerousProductionAction && !executionIsReadOnly;
  const executionEndpoint = String(remediationPlanEditor.connection_url || "").trim();
  const executionEndpointValid = !executionEndpoint || /^https?:\/\/[^\s/$.?#].[^\s]*$/i.test(executionEndpoint);
  const jenkinsExecutorSelected = remediationPlanEditor.executor_type === "jenkins" || remediationPlanEditor.connection_type === "jenkins";
  const liveExecutionPlanAvailable = executionPlanLines.length > 0 && !executionIsReadOnly;
  const catalogStage = String(selectedCatalogStatus.data?.candidate_stage || "").trim().toLowerCase();
  const catalogCandidateAvailable = ["diagnostic_candidate", "resolution_candidate"].includes(catalogStage);
  const catalogReviewRequired = catalogCandidateAvailable && !selectedCatalogStatus.data?.execution_eligible;
  const executionConfirmationPhrase = `EXECUTE ${String(selectedGovernedExecutionTarget || "GOVERNED-TARGET").toUpperCase()}`;
  const executionConfirmationValid = !dangerousProductionAction || executionConfirmationText.trim() === executionConfirmationPhrase;

  const selectedAlertTimelineRows = useMemo(() => {
    const ingestAt =
      selectedAlertWorkflow?.alert?.created_at ||
      selectedAlertRow?.created_at ||
      selectedAlertRow?.starts_at ||
      "";
    const incidentCreatedAt = selectedAlertWorkflow?.incident?.created_at || selectedIncidentMetadataRow?.created_at || "";

    const workflowRows = selectedAlertEvents
      .filter((event) => event && typeof event === "object")
      .sort((a, b) => {
        const aSeq = Number(a.sequence || 0);
        const bSeq = Number(b.sequence || 0);
        if (aSeq && bSeq && aSeq !== bSeq) {
          return aSeq - bSeq;
        }
        const aTime = parseUtcTimestamp(a.timestamp)?.getTime() || 0;
        const bTime = parseUtcTimestamp(b.timestamp)?.getTime() || 0;
        return aTime - bTime;
      })
      .map((event, index) => {
        const route = routeForAgent(event.agent);
        const inputPayload = extractEventInput(event);
        const outputPayload = extractEventOutput(event);
        const inputObject = typeof inputPayload === "object" && inputPayload ? inputPayload : {};
        const outputObject = typeof outputPayload === "object" && outputPayload ? outputPayload : {};
        const tableHints = [
          ...(Array.isArray(outputObject.table_hints) ? outputObject.table_hints : []),
          ...(Array.isArray(event?.metrics?.table_hints) ? event.metrics.table_hints : []),
        ].filter(Boolean);
        const consumes =
          String(inputObject.source_channel || inputObject.topic || inputObject.from_topic || route?.consumes || "").trim() || "-";
        const publishes =
          String(
            event.communicates_to
            || inputObject.transport_channel
            || inputObject.to_topic
            || outputObject.transport_channel
            || route?.publishes
            || ""
          ).trim() || "-";
        const actionLabel = String(event.action || event.event_type || "").trim();
        const stageName = actionLabel ? summarizeEventType(actionLabel) : `Workflow Event ${index + 1}`;
        const detailParts = [
          compactText(event.status, 40),
          compactText(
            event.decision && typeof event.decision === "object"
              ? JSON.stringify(event.decision)
              : event.decision,
            120
          ),
        ].filter(Boolean);

        return {
          stage: stageName,
          sequence: event.sequence || index + 1,
          agent: displayAgentName(event.agent || "-"),
          service: route?.service || event.service || "-",
          consumes,
          publishes,
          timestamp: event.timestamp || "",
          elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, event.timestamp || ""),
          detail: detailParts.join(" | ") || "Workflow event recorded.",
          tables: tableHints.length ? tableHints.join(", ") : "-",
          inputValueText: stringifyTimelineValue(inputPayload),
          outputValueText: stringifyTimelineValue(outputPayload),
          errorValueText: extractEventError(event),
          backendEvents: [String(event?.event_type || "").trim()].filter(Boolean),
        };
      });

    const traceRows = selectedAlertEventTrace.map((event, index) => {
      const stageName = summarizeEventType(event.event_type);
      const tableHints = Array.isArray(event.table_hints) ? event.table_hints.filter(Boolean) : [];
      const detailParts = [
        compactText(event.event_stage, 40),
        compactText(event.status, 40),
        compactText(event.policy_reason, 120),
      ].filter(Boolean);
      return {
        stage: `${stageName}${index + 1 <= 9 ? ` (${index + 1})` : ""}`,
        sequence: index + 1,
        agent: displayAgentName(normalizeTraceServiceName(event)),
        service: normalizeTraceServiceName(event),
        consumes: event.source_channel || "-",
        publishes: event.transport_channel || "-",
        timestamp: event.timestamp || "",
        elapsed: elapsedSeconds(ingestAt, event.timestamp || ""),
        detail: detailParts.join(" | ") || "Trace event recorded.",
        tables: tableHints.join(", ") || "-",
        inputValueText: stringifyTimelineValue(
          hasMeaningfulValue(event.input_value)
            ? event.input_value
            : {
                source_channel: event.source_channel,
                transport_provider: event.transport_provider,
                risk_tier: event.risk_tier,
                execution_mode: event.execution_mode,
                trace_id: event.trace_id,
              }
        ),
        outputValueText: stringifyTimelineValue(
          hasMeaningfulValue(event.output_value)
            ? { trace_id: event.trace_id, ...event.output_value }
            : {
                event_type: event.event_type,
                event_stage: event.event_stage,
                status: event.status,
                transport_channel: event.transport_channel,
                table_hints: event.table_hints,
                query_hint: event.query_hint,
                trace_id: event.trace_id,
              }
        ),
        errorValueText: stringifyTimelineValue(event.error) || extractEventError(event),
        backendEvents: [String(event?.event_type || "").trim()].filter(Boolean),
      };
    });

    const syntheticRows = buildSyntheticFlowRows({
      workflow: selectedAlertWorkflow,
      events: selectedAlertEvents,
      traceRows: selectedAlertEventTrace,
      ingestAt,
      incidentCreatedAt,
    });
    const discoveryEvidence =
      selectedAlertWorkflow?.context?.metadata?.discovery_evidence
      || selectedAlertWorkflow?.recommendation?.metadata?.discovery_evidence
      || null;
    const discoveryMcp =
      selectedAlertWorkflow?.context?.metadata?.discovery_report
      || selectedAlertWorkflow?.recommendation?.metadata?.discovery_report
      || null;
    const contextMetadata =
      selectedAlertWorkflow?.context?.metadata
      || selectedAlertWorkflow?.recommendation?.metadata
      || {};
    const contextRagMatches =
      (Array.isArray(contextMetadata?.rag_matches) && contextMetadata.rag_matches)
      || [];
    if (discoveryMcp && typeof discoveryMcp === "object") {
      const stages = Array.isArray(discoveryMcp.retrieval_stages) ? discoveryMcp.retrieval_stages : [];
      stages.forEach((stage, index) => {
        syntheticRows.push({
          stage: `Discovery Agent · ${String(stage.stage || "stage").replaceAll("_", " ")}`,
          sequence: 80 + index,
          agent: "Discovery Agent",
          service: "context-agent",
          consumes: index === 0 ? "orchestration-events" : "discovery-mcp",
          publishes: stage.stage === "discovery_completed" ? "context-events" : "discovery-evidence",
          timestamp: selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt,
          elapsed: elapsedSeconds(ingestAt, selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt),
          detail: `${stage.status || "unknown"}${Number.isFinite(Number(stage.result_count)) ? ` · ${stage.result_count} result(s)` : ""}`,
          tables: "-",
          inputValueText: stringifyTimelineValue({ protocol: discoveryMcp.protocol, server: discoveryMcp.server }),
          outputValueText: stringifyTimelineValue(stage),
          errorValueText: stage.error || "",
          backendEvents: [`discovery.${stage.stage || "stage"}`],
        });
      });
    }
    if (discoveryEvidence && typeof discoveryEvidence === "object") {
      const codeCount = Array.isArray(discoveryEvidence.code_matches) ? discoveryEvidence.code_matches.length : 0;
      const logCount = Array.isArray(discoveryEvidence.log_matches) ? discoveryEvidence.log_matches.length : 0;
      syntheticRows.push({
        stage: "Discovery Agent Retrieved Code And Log Context",
        sequence: 85,
        agent: "Discovery Agent",
        service: "context-agent",
        consumes: "orchestration-events",
        publishes: "context-evidence",
        timestamp: selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt,
        elapsed: elapsedSeconds(ingestAt, selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt),
        detail: `${codeCount} code match${codeCount === 1 ? "" : "es"} and ${logCount} log match${logCount === 1 ? "" : "es"} retrieved.`,
        tables: "-",
        inputValueText: stringifyTimelineValue({
          query_terms: discoveryEvidence.query_terms || [],
          code_roots: discoveryEvidence.code_roots || [],
          log_roots: discoveryEvidence.log_roots || [],
        }),
        outputValueText: stringifyTimelineValue(discoveryEvidence),
        errorValueText: "",
        backendEvents: ["context.discovery.completed"],
      });
    }
    if (contextMetadata && typeof contextMetadata === "object") {
      const queryTerms = Array.isArray(discoveryEvidence?.query_terms) ? discoveryEvidence.query_terms : [];
      syntheticRows.push({
        stage: "Context Agent Merged Alert And Onboarding Inputs",
        sequence: 86,
        agent: "Context Agent",
        service: "context-agent",
        consumes: "orchestration-events",
        publishes: "context-events",
        timestamp: selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt,
        elapsed: elapsedSeconds(ingestAt, selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt),
        detail: `${queryTerms.length || 0} query term(s) with alert labels, service, and onboarding profile were merged.`,
        tables: "-",
        inputValueText: stringifyTimelineValue({
          alert_id: selectedAlertWorkflow?.alert?.id || selectedAlertRow?.alert_id || selectedAlertRow?.id || "",
          service: selectedAlertWorkflow?.alert?.service || selectedAlertRow?.service || "",
          query_terms: queryTerms,
        }),
        outputValueText: stringifyTimelineValue({
          metadata_keys: Object.keys(contextMetadata || {}),
          rag_matches: contextRagMatches.length,
        }),
        errorValueText: "",
        backendEvents: ["context.input.merged"],
      });
      syntheticRows.push({
        stage: "Context Agent Published RCA Context",
        sequence: 87,
        agent: "Context Agent",
        service: "context-agent",
        consumes: "context-events",
        publishes: "resolution-events",
        timestamp: selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt,
        elapsed: elapsedSeconds(ingestAt, selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt),
        detail: `${contextRagMatches.length} RAG match(es) and ${Array.isArray(discoveryMcp?.retrieval_stages) ? discoveryMcp.retrieval_stages.length : 0} discovery stage(s) were propagated to downstream RCA evaluation.`,
        tables: "-",
        inputValueText: stringifyTimelineValue({
          discovery_protocol: discoveryMcp?.protocol || "-",
          rag_top_similarity: contextMetadata?.rag_top_similarity ?? contextMetadata?.rag_top_match_confidence ?? "-",
        }),
        outputValueText: stringifyTimelineValue({
          root_cause: selectedAlertWorkflow?.recommendation?.root_cause || "",
          impact: selectedAlertWorkflow?.recommendation?.impact || "",
          recommended_action: selectedAlertWorkflow?.recommendation?.recommended_action || "",
        }),
        errorValueText: "",
        backendEvents: ["context.output.published"],
      });
    }

    const baseRows = traceRows.length ? traceRows : workflowRows;
    const orderedRows = [...syntheticRows, ...baseRows]
      .map((row, index) => ({ ...row, __rowIndex: index }))
      .sort((left, right) => {
        const leftPhase = timelinePhaseOrder(left);
        const rightPhase = timelinePhaseOrder(right);
        if (leftPhase !== rightPhase) {
          return leftPhase - rightPhase;
        }

        const leftTime = parseUtcTimestamp(left.timestamp)?.getTime();
        const rightTime = parseUtcTimestamp(right.timestamp)?.getTime();
        const leftHasTime = Number.isFinite(leftTime);
        const rightHasTime = Number.isFinite(rightTime);

        if (leftHasTime && rightHasTime && leftTime !== rightTime) {
          return leftTime - rightTime;
        }

        if (leftHasTime !== rightHasTime) {
          return leftHasTime ? -1 : 1;
        }

        const leftSeq = Number(left.sequence || 0);
        const rightSeq = Number(right.sequence || 0);
        if (leftSeq && rightSeq && leftSeq !== rightSeq) {
          return leftSeq - rightSeq;
        }

        return Number(left.__rowIndex || 0) - Number(right.__rowIndex || 0);
      });

    const rows = orderedRows.filter(
      (row, index, allRows) => {
        const stage = String(row.stage || "").trim();
        const agent = String(row.agent || "").trim();
        const timestamp = String(row.timestamp || "").trim();
        const key = `${stage}|${agent}|${timestamp}`;
        return allRows.findIndex((candidate) => {
          const cStage = String(candidate.stage || "").trim();
          const cAgent = String(candidate.agent || "").trim();
          const cTime = String(candidate.timestamp || "").trim();
          return `${cStage}|${cAgent}|${cTime}` === key;
        }) === index;
      }
    ).map((row) => {
      const { __rowIndex, ...rest } = row;
      return rest;
    });

    if (rows.length) {
      return rows;
    }

    const fallbackStatus = String(selectedIncidentMetadataRow?.status || selectedAlertWorkflow?.incident?.status || "").trim();
    if (!fallbackStatus) {
      return [];
    }

    return [
      {
        stage: "Current Incident Status",
        agent: "incident-projection",
        service: "monitoring-adapter",
        consumes: "-",
        publishes: "-",
        timestamp: selectedIncidentMetadataRow?.updated_at || selectedIncidentMetadataRow?.latest_event_at || incidentCreatedAt || ingestAt,
        elapsed: "-",
        detail: fallbackStatus,
        tables: "-",
        inputValueText: "",
        outputValueText: stringifyTimelineValue(selectedIncidentMetadataRow),
        errorValueText: "",
      },
    ];
  }, [selectedAlertWorkflow, selectedAlertRow, selectedIncidentMetadataRow, selectedAlertEvents, selectedAlertEventTrace]);

  const selectedWorkflowFlowStages = useMemo(
    () => buildWorkflowFlowStages(selectedAlertWorkflow, selectedAlertTimelineRows),
    [selectedAlertWorkflow, selectedAlertTimelineRows],
  );

  const hasSelectedWorkflowData = useMemo(() => {
    if (!selectedAlertWorkflow || typeof selectedAlertWorkflow !== "object") {
      return false;
    }
    const events = Array.isArray(selectedAlertWorkflow.events) ? selectedAlertWorkflow.events : [];
    return Boolean(events.length || selectedAlertWorkflow.incident || selectedAlertWorkflow.recommendation);
  }, [selectedAlertWorkflow]);

  const panelWorkflow = useMemo(() => {
    return hasSelectedWorkflowData ? selectedAlertWorkflow : latestWorkflow;
  }, [hasSelectedWorkflowData, selectedAlertWorkflow, latestWorkflow]);

  const globalWorkflowFlowStages = useMemo(
    () => buildWorkflowFlowStages(panelWorkflow, selectedAlertTimelineRows),
    [panelWorkflow, selectedAlertTimelineRows],
  );

  const panelWorkflowEvents = useMemo(() => {
    const events = panelWorkflow?.events || [];
    return Array.isArray(events) ? events : [];
  }, [panelWorkflow]);

  const panelWorkflowUsage = useMemo(() => {
    const directUsage = panelWorkflow?.recommendation?.metadata?.model_usage;
    if (Array.isArray(directUsage) && directUsage.length) {
      return directUsage;
    }
    const finopsCalls = panelWorkflow?.finops?.calls;
    if (Array.isArray(finopsCalls)) {
      return finopsCalls;
    }
    return [];
  }, [panelWorkflow]);

  const allUsageRows = useMemo(() => {
    const merged = [];

    const appendUsage = (candidate) => {
      if (!Array.isArray(candidate)) {
        return;
      }
      candidate.forEach((row) => {
        merged.push(normalizeUsageRow(row));
      });
    };

    appendUsage(panelWorkflowUsage);
    appendUsage(selectedAlertUsage);
    appendUsage(latestWorkflow?.finops?.calls);
    appendUsage(latestWorkflow?.recommendation?.metadata?.model_usage);
    appendUsage(latestWorkflow?.recommendation?.metadata?.llm_calls);

    monitorScopedIncidentMetadata.forEach((row) => {
      appendUsage(row?.finops?.calls);
      appendUsage(row?.model_usage);
      appendUsage(row?.llm_usage);

      const synthetic = normalizeUsageRow({
        task: row?.latest_event_type || "incident",
        provider: row?.provider || row?.llm_provider,
        model: row?.model || row?.llm_model,
        input_tokens: row?.input_tokens,
        output_tokens: row?.output_tokens,
        total_tokens: row?.total_tokens,
        total_cost_usd: row?.total_cost_usd || row?.cost_usd,
      });
      if (isMeaningfulUsageRow(synthetic)) {
        merged.push(synthetic);
      }
    });

    gatewayRecent.rows.forEach((row) => {
      appendUsage(row?.finops?.calls);
      appendUsage(row?.model_usage);
      appendUsage(row?.llm_usage);
    });

    return merged.filter((row) => isMeaningfulUsageRow(row));
  }, [panelWorkflowUsage, selectedAlertUsage, latestWorkflow, monitorScopedIncidentMetadata, gatewayRecent.rows]);

  useEffect(() => {
    const validDiagnosticsTabs = new Set(["pipeline", "processing", "timeline", "context", "events", "finops", "api", "raw"]);
    if (!validDiagnosticsTabs.has(diagnosticsDetailTab)) {
      setDiagnosticsDetailTab("pipeline");
      return;
    }
    if (diagnosticsDetailTab === "application" || diagnosticsDetailTab === "topics") {
      setDiagnosticsDetailTab("processing");
    }
  }, [diagnosticsDetailTab]);

  useEffect(() => {
    if (activeTab !== "home" || homeDetailTab !== "diagnostics" || diagnosticsDetailTab !== "api") {
      return;
    }
    loadGatewayRecent();
  }, [activeTab, homeDetailTab, diagnosticsDetailTab]);

  const workflowEventRows = useMemo(() => {
    const mapped = panelWorkflowEvents
      .filter((event) => event && typeof event === "object")
      .sort((a, b) => Number(a.sequence || 0) - Number(b.sequence || 0))
      .map((event) => {
        const decisionValue = event.decision;
        const outputValue = event.output;
        return {
          sequence: event.sequence || "-",
            agent: displayAgentName(event.agent || "-"),
          action: event.action || "-",
          decision: typeof decisionValue === "object" ? JSON.stringify(decisionValue) : String(decisionValue || "-"),
          output: typeof outputValue === "object" ? JSON.stringify(outputValue) : String(outputValue || "-"),
          communicates_to: event.communicates_to || "-",
        };
      });
    if (mapped.length) {
      return mapped;
    }
    return gatewayRecent.rows.slice(0, 80).map((event, index) => ({
      sequence: index + 1,
      agent: displayAgentName("API Gateway"),
      action: event.path || "gateway.event",
      decision: event?.safety?.decision || "-",
      output: String(event.status_code || "-") + (event.trace_id ? ` | trace ${event.trace_id}` : ""),
      communicates_to: event.target_url || "monitoring-adapter",
    }));
  }, [panelWorkflowEvents, gatewayRecent.rows]);

  const observedRouting = useMemo(() => extractObservedRoutingMetrics(panelWorkflow), [panelWorkflow]);

  const messageBusTopicRows = useMemo(() => {
    return SERVICE_TOPIC_FLOW.map((row) => ({
      service: row.service,
      consumes: row.consumes === "-" ? "-" : `${row.consumes} (enabled transports)`,
      publishes: row.publishes,
    }));
  }, []);

  const messageBusActual = useMemo(() => {
    const workflow = panelWorkflow;
    const events = Array.isArray(workflow.events) ? workflow.events : [];
    const traceRows = Array.isArray(workflow.event_trace) ? workflow.event_trace : [];
    const observedAgents = new Set(events.map((item) => String(item?.agent || "").trim()));
    const observedServices = new Set(traceRows.map((item) => String(item?.service || "").trim()));
    const observedProvider = String(observedRouting?.message_bus_provider || "").trim().toUpperCase() || "N/A";
    const approval = typeof workflow.approval === "object" ? workflow.approval : {};
    const remediation = typeof workflow.remediation_action === "object" ? workflow.remediation_action : {};
    const closure = typeof workflow.closure_report === "object" ? workflow.closure_report : {};
    const hasWorkflow = Boolean(workflow.alert || workflow.incident || events.length);
    const observedChannels = new Set();
    traceRows.forEach((row) => {
      const source = String(row?.source_channel || "").trim();
      const transport = String(row?.transport_channel || "").trim();
      if (source) {
        observedChannels.add(source);
      }
      if (transport) {
        observedChannels.add(transport);
      }
    });

    const published = [];
    const consumed = [];
    const rows = SERVICE_TOPIC_FLOW.map((row) => {
      let isObserved = false;
      if (row.agent === "alert") {
        isObserved = hasWorkflow;
      } else if (observedAgents.has(row.agent)) {
        isObserved = true;
      } else if (observedServices.has(row.service)) {
        isObserved = true;
      } else if (row.agent === "Human Approval Layer" && Object.keys(approval).length) {
        isObserved = true;
      } else if (row.agent === "Remediation Automation Engine" && Object.keys(remediation).length) {
        isObserved = true;
      } else if (row.agent === "Closure & Validation" && Object.keys(closure).length) {
        isObserved = true;
      }

      if (isObserved) {
        if (row.consumes !== "-" && !consumed.includes(row.consumes)) {
          consumed.push(row.consumes);
        }
        if (!published.includes(row.publishes)) {
          published.push(row.publishes);
        }
      }

      return {
        service: row.service,
        consumed: isObserved ? row.consumes : "-",
        published: isObserved ? row.publishes : "-",
        provider: observedProvider,
        status: isObserved ? "Observed" : "Not reached",
      };
    });

    observedChannels.forEach((channel) => {
      if (!published.includes(channel)) {
        published.push(channel);
      }
      if (!consumed.includes(channel)) {
        consumed.push(channel);
      }
    });

    return { published, consumed, rows };
  }, [panelWorkflow, observedRouting]);

  const executiveMetrics = useMemo(() => {
    const rows = Array.isArray(gatewayRecent.rows) ? gatewayRecent.rows : [];
    const summaryTotal = toFiniteNumber(gatewaySummary.data?.window_events || gatewaySummary.data?.total_events || 0);
    const recentSuccess = rows.filter((row) => {
      const status = Number(row?.status_code || 0);
      return status >= 200 && status < 400;
    }).length;
    const recentFailure = rows.filter((row) => Number(row?.status_code || 0) >= 400).length;
    const totalRequests = rows.length || summaryTotal;
    const successRequests = rows.length ? recentSuccess : toFiniteNumber(gatewaySummary.data?.allowed || 0);
    const failedRequests = rows.length
      ? recentFailure
      : toFiniteNumber(gatewaySummary.data?.blocked || 0) + toFiniteNumber(gatewaySummary.data?.review || 0);
    const latencyValues = rows
      .map((row) => Number(row?.latency_ms ?? row?.gateway?.latency_ms ?? row?.latency ?? 0))
      .filter((value) => Number.isFinite(value) && value > 0);
    const avgLatencyMs = latencyValues.length
      ? latencyValues.reduce((sum, value) => sum + value, 0) / latencyValues.length
      : 0;
    const p95LatencyMs = percentile(latencyValues, 0.95);

    const latencyTrend = rows
      .filter((row) => {
        const value = Number(row?.latency_ms ?? row?.gateway?.latency_ms ?? row?.latency);
        return Number.isFinite(value) && value > 0;
      })
      .slice(0, 12)
      .reverse()
      .map((row, index) => {
        const value = Number(row?.latency_ms ?? row?.gateway?.latency_ms ?? row?.latency ?? 0);
        const status = Number(row?.status_code || 0);
        return {
          label: `${index + 1}`,
          value: Number.isFinite(value) ? value : 0,
          displayValue: `${Number.isFinite(value) ? value.toFixed(1) : "0.0"} ms`,
          tone: status >= 400 ? "risk" : "ops",
        };
      });

    const finopsTotals =
      panelWorkflow?.finops?.totals
      || selectedAlertWorkflow?.finops?.totals
      || latestWorkflow?.finops?.totals
      || {};
    const finopsCalls = toFiniteNumber(finopsTotals?.calls || allUsageRows.length);
    const finopsTokens = toFiniteNumber(finopsTotals?.total_tokens || allUsageRows.reduce((sum, row) => sum + toFiniteNumber(row?.total_tokens), 0));
    const finopsCost = toFiniteNumber(finopsTotals?.total_cost_usd || allUsageRows.reduce((sum, row) => sum + toFiniteNumber(row?.total_cost_usd), 0));

    return {
      totalRequests,
      successRequests,
      failedRequests,
      avgLatencyMs,
      p95LatencyMs,
      latencyTrend,
      finopsCalls,
      finopsTokens,
      finopsCost,
    };
  }, [gatewayRecent.rows, gatewaySummary.data, panelWorkflow, selectedAlertWorkflow, latestWorkflow, allUsageRows]);

  const finopsByProvider = useMemo(() => {
    const grouped = new Map();
    allUsageRows.forEach((row) => {
      const key = String(row?.provider || "unknown");
      const current = grouped.get(key) || { provider: key, calls: 0, total_tokens: 0, total_cost_usd: 0 };
      current.calls += 1;
      current.total_tokens += Number(row?.total_tokens || 0);
      current.total_cost_usd += Number(row?.total_cost_usd || 0);
      grouped.set(key, current);
    });
    return Array.from(grouped.values());
  }, [allUsageRows]);

  const closedRiskOptions = useMemo(() => {
    return Array.from(
      new Set(closedIncidents.rows.map((row) => String(row?.risk_tier || row?.risk || "unknown").toLowerCase()))
    ).sort();
  }, [closedIncidents.rows]);

  const closedModeOptions = useMemo(() => {
    return Array.from(
      new Set(closedIncidents.rows.map((row) => String(row?.execution_mode || "unknown").toLowerCase()))
    ).sort();
  }, [closedIncidents.rows]);

  const filteredClosedRows = useMemo(() => {
    return closedIncidents.rows.filter((row) => {
      const risk = String(row?.risk_tier || row?.risk || "unknown").toLowerCase();
      const mode = String(row?.execution_mode || "unknown").toLowerCase();
      const riskPass = closedFilters.risk === "all" || closedFilters.risk === risk;
      const modePass = closedFilters.mode === "all" || closedFilters.mode === mode;
      return riskPass && modePass;
    });
  }, [closedIncidents.rows, closedFilters]);

  const executiveClosedSummary = useMemo(() => {
    const rows = Array.isArray(closedIncidents.rows) ? closedIncidents.rows : [];
    const restored = rows.filter((row) => row?.health_restored === true).length;
    const byRisk = new Map();
    const byMode = new Map();

    rows.forEach((row) => {
      const risk = String(row?.risk_tier || row?.risk || row?.severity || "unknown").toLowerCase();
      const mode = String(row?.execution_mode || "unknown").toLowerCase();
      byRisk.set(risk, (byRisk.get(risk) || 0) + 1);
      byMode.set(mode, (byMode.get(mode) || 0) + 1);
    });

    const riskItems = Array.from(byRisk.entries()).map(([label, value]) => ({ label, value, tone: "risk" }));
    const modeItems = Array.from(byMode.entries()).map(([label, value]) => ({ label, value, tone: "meta" }));

    return {
      total: rows.length,
      restored,
      closureRate: rows.length ? (restored / rows.length) * 100 : 0,
      riskItems,
      modeItems,
      // MTTR must use the complete loaded closure population; truncating this
      // list silently removed Sev 2 samples when newer Sev 1 rows dominated.
      recentRows: rows,
    };
  }, [closedIncidents.rows]);

  useEffect(() => {
    if (!latestIncidentId && !latestRecommendationId) {
      return;
    }
    setApprovalForm((current) => ({
      ...current,
      incident_id: latestIncidentId || current.incident_id,
      recommendation_id: latestRecommendationId || current.recommendation_id,
    }));
  }, [latestIncidentId, latestRecommendationId]);

  function mergeRecommendationIdIntoApprovalRow(incidentId, recommendationId) {
    const normalizedIncidentId = String(incidentId || "").trim();
    const normalizedRecommendationId = String(recommendationId || "").trim();
    if (!normalizedIncidentId || !looksLikeUuid(normalizedRecommendationId)) {
      return;
    }
    const patchRow = (row) => {
      const rowIncidentId = approvalIncidentId(row);
      if (rowIncidentId !== normalizedIncidentId) {
        return row;
      }
      return {
        ...row,
        recommendation_id: normalizedRecommendationId,
        remediation_recommendation_id: row?.remediation_recommendation_id || normalizedRecommendationId,
      };
    };
    setIncidentMetadata((prev) => ({
      ...prev,
      rows: Array.isArray(prev.rows) ? prev.rows.map(patchRow) : prev.rows,
    }));
    setAlerts((prev) => ({
      ...prev,
      rows: Array.isArray(prev.rows) ? prev.rows.map(patchRow) : prev.rows,
    }));
  }

  async function loadApprovalIncidentContext(incidentId, options = {}) {
    const forceRefresh = Boolean(options?.force);
    const normalized = String(incidentId || "").trim();
    if (!normalized) {
      return;
    }
    const now = Date.now();
    const requestState = approvalIncidentRequestRef.current;
    if (requestState.inFlight && requestState.incidentId === normalized) {
      return;
    }
    if (!forceRefresh && (
      approvalIncidentContext.incident_id === normalized
      && approvalIncidentContext.payload
      && now - requestState.lastFetchedAt < 10000
    )) {
      return;
    }

    approvalIncidentRequestRef.current = { ...requestState, incidentId: normalized, inFlight: true };
    setApprovalIncidentContext((current) => ({
      loading: true,
      incident_id: normalized,
      payload: current.incident_id === normalized ? current.payload : null,
      error: "",
    }));
    try {
      const options = adminHeaders().Authorization ? authenticatedOptions() : {};
      const response = await fetchJson(`/api-gateway/approval/incident/${encodeURIComponent(normalized)}`, options);
      const payload = unwrap(response);
      const recommendationId = approvalRecommendationFromPayload(payload);
      setApprovalIncidentContext({ loading: false, incident_id: normalized, payload, error: "" });
      approvalIncidentRequestRef.current = {
        incidentId: normalized,
        inFlight: false,
        lastFetchedAt: Date.now(),
      };
      if (recommendationId) {
        mergeRecommendationIdIntoApprovalRow(normalized, recommendationId);
        setApprovalForm((current) => ({
          ...current,
          incident_id: normalized || current.incident_id,
          recommendation_id: recommendationId || current.recommendation_id,
        }));
      }
    } catch (error) {
      const raw = String(error?.message || "");
      const brief = raw.includes("HTTP 502") || raw.includes("500 Internal Server Error")
        ? "Approval context service is temporarily unavailable. You can continue using selected incident details."
        : raw;
      approvalIncidentRequestRef.current = {
        incidentId: normalized,
        inFlight: false,
        lastFetchedAt: Date.now(),
      };
      setApprovalIncidentContext({ loading: false, incident_id: normalized, payload: null, error: brief });
    }
  }

  const pendingApprovals = useMemo(() => {
    return monitorScopedIncidentMetadata.filter(hasPendingDecision);
  }, [monitorScopedIncidentMetadata]);

  const globalOperationalData = useMemo(() => {
    const username = String(adminSession?.user?.username || "").trim().toLowerCase();
    const query = globalOperationsQuery.trim().toLowerCase();
    const results = [];
    const push = (kind, label, meta, row) => {
      const haystack = `${label} ${meta}`.toLowerCase();
      if (query && haystack.includes(query)) results.push({ kind, label, meta, row });
    };
    monitorScopedAlerts.forEach((row) => {
      const alertId = String(row?.alert_id || row?.id || "");
      const ticket = String(row?.ticket_id || row?.external_ticket_id || row?.labels?.ticket_id || "");
      push("Alert", row?.name || alertId || "Alert", `${alertId} ${row?.service || ""} ${row?.application || ""} ${ticket}`, row);
      if (ticket) push("Ticket", ticket, `${row?.name || ""} ${row?.service || ""}`, row);
    });
    monitorScopedIncidentMetadata.forEach((row) => push("Incident", row?.incident_id || row?.id || "Incident", `${row?.service || ""} ${row?.status || ""} ${row?.ticket_id || ""}`, row));
    monitoringApps.rows.forEach((row) => push("Application", row?.name || row?.id || "Application", `${row?.service || ""} ${row?.namespace || ""} ${row?.environment || ""}`, row));
    Array.from(new Set(monitorScopedAlerts.map((row) => String(row?.service || "").trim()).filter(Boolean))).forEach((service) => push("Service", service, "Service in current monitoring scope", { service }));

    const assignedIncidents = monitorScopedIncidentMetadata.filter((row) => [row?.owner, row?.assignee, row?.assigned_engineer, row?.assigned_to].some((value) => String(value || "").trim().toLowerCase() === username));
    const failedActions = monitorScopedIncidentMetadata.filter((row) => ["failed", "rollback_failed", "remediation_failed"].includes(String(row?.status || row?.remediation_status || "").toLowerCase()));
    const myWork = [
      ...assignedIncidents.map((row) => ({ kind: "Assigned incident", label: row?.incident_id || row?.id || "Incident", meta: `${row?.service || "-"} · ${row?.status || "-"}`, row })),
      ...pendingApprovals.map((row) => ({ kind: "Approval", label: row?.incident_id || row?.id || "Incident", meta: `${row?.service || "-"} · ${row?.risk_tier || row?.severity || "unknown"} risk`, row })),
      ...failedActions.map((row) => ({ kind: "Failed action", label: row?.incident_id || row?.id || "Incident", meta: `${row?.service || "-"} · ${row?.status || "failed"}`, row })),
    ];
    const notifications = [
      ...pendingApprovals.map((row) => ({ kind: "Approval reminder", label: row?.incident_id || row?.id || "Incident", meta: `${row?.service || "-"} requires review`, row })),
      ...monitorScopedAlerts.filter((row) => ["critical", "high"].includes(String(row?.severity || "").toLowerCase())).slice(0, 8).map((row) => ({ kind: "Alert", label: row?.name || row?.id || "Alert", meta: `${row?.severity || "-"} · ${row?.service || "-"}`, row })),
      ...(closedIncidents.rows || []).slice(0, 5).map((row) => ({ kind: String(row?.status || "").toLowerCase().includes("reopen") ? "Reopened" : "Resolved", label: row?.incident_id || row?.id || "Incident", meta: `${row?.service || "-"} · ${row?.status || "closed"}`, row })),
    ];
    return { results: results.slice(0, 12), myWork, notifications };
  }, [adminSession?.user?.username, closedIncidents.rows, globalOperationsQuery, monitorScopedAlerts, monitorScopedIncidentMetadata, monitoringApps.rows, pendingApprovals]);

  const filteredPendingApprovals = useMemo(() => {
    return pendingApprovals.filter((row) => {
      if (approvalFilter === "all") {
        return true;
      }
      const severity = String(row?.severity || row?.risk_tier || "").toLowerCase();
      const status = String(row?.status || "").toLowerCase();
      if (approvalFilter === "awaiting_approval") {
        return status === "awaiting_approval";
      }
      return severity === approvalFilter;
    });
  }, [pendingApprovals, approvalFilter]);

  const pendingApprovalByIncidentId = useMemo(() => {
    const index = new Map();
    pendingApprovals.forEach((row) => {
      const incidentId = approvalIncidentId(row);
      if (incidentId) {
        index.set(incidentId, row);
      }
    });
    return index;
  }, [pendingApprovals]);

  const executiveInsights = useMemo(() => {
    const openRows = monitorScopedIncidentMetadata.filter((row) => !isApprovalResolvedStatus(row?.status || row?.state));
    const slaAtRisk = openRows.filter((row) => {
      const risk = String(row?.risk_tier || row?.risk || row?.severity || "").toLowerCase();
      const mode = String(row?.execution_mode || "").toLowerCase();
      return risk === "high" || risk === "critical" || mode.includes("manual");
    }).length;

    const pendingApprovalAges = pendingApprovals
      .map((row) => parseUtcTimestamp(row?.created_at || row?.updated_at || row?.timestamp)?.getTime() || 0)
      .filter((value) => value > 0)
      .map((time) => Math.max(0, (Date.now() - time) / 60000));
    const avgApprovalWaitMinutes = pendingApprovalAges.length
      ? pendingApprovalAges.reduce((sum, value) => sum + value, 0) / pendingApprovalAges.length
      : 0;

    const closedRows = Array.isArray(closedIncidents.rows) ? closedIncidents.rows : [];
    const autoClosed = closedRows.filter((row) => String(row?.execution_mode || "").toLowerCase().includes("auto")).length;
    const automationRate = closedRows.length ? (autoClosed / closedRows.length) * 100 : 0;

    const dayBuckets = Array.from({ length: 7 }).map((_, idx) => {
      const date = new Date();
      date.setHours(0, 0, 0, 0);
      date.setDate(date.getDate() - (6 - idx));
      const key = date.toISOString().slice(0, 10);
      return { key, label: date.toLocaleDateString(undefined, { month: "short", day: "numeric" }), open: 0, closed: 0 };
    });
    const bucketMap = new Map(dayBuckets.map((item) => [item.key, item]));

    monitorScopedAlerts.forEach((row) => {
      const parsed = parseUtcTimestamp(row?.created_at || row?.starts_at);
      if (!parsed) {
        return;
      }
      const key = parsed.toISOString().slice(0, 10);
      const bucket = bucketMap.get(key);
      if (bucket) {
        bucket.open += 1;
      }
    });

    closedRows.forEach((row) => {
      const parsed = parseUtcTimestamp(row?.closed_at || row?.updated_at || row?.created_at);
      if (!parsed) {
        return;
      }
      const key = parsed.toISOString().slice(0, 10);
      const bucket = bucketMap.get(key);
      if (bucket) {
        bucket.closed += 1;
      }
    });

    const weeklyOpenTrend = dayBuckets.map((item) => ({ label: item.label, value: item.open, tone: "risk" }));
    const weeklyClosedTrend = dayBuckets.map((item) => ({ label: item.label, value: item.closed, tone: "ops" }));

    return {
      openIncidents: openRows.length,
      slaAtRisk,
      avgApprovalWaitMinutes,
      automationRate,
      weeklyOpenTrend,
      weeklyClosedTrend,
    };
  }, [monitorScopedIncidentMetadata, pendingApprovals, closedIncidents.rows, monitorScopedAlerts]);

  const selectedApprovalRow = useMemo(() => {
    return filteredPendingApprovals.find((row) => approvalIncidentId(row) === selectedApprovalIncidentId) || null;
  }, [filteredPendingApprovals, selectedApprovalIncidentId]);

  const selectedApprovalRecommendationId = useMemo(() => {
    if (selectedApprovalRow) {
      const rowRecommendationId = approvalRecommendationId(selectedApprovalRow);
      if (rowRecommendationId) {
        return rowRecommendationId;
      }
    }
    if (approvalIncidentContext.incident_id && approvalIncidentContext.incident_id === selectedApprovalIncidentId) {
      return approvalRecommendationFromPayload(approvalIncidentContext.payload);
    }
    return "";
  }, [selectedApprovalRow, approvalIncidentContext, selectedApprovalIncidentId]);

  const selectedApprovalFlowContext = useMemo(() => {
    if (selectedApprovalRow) {
      const rowFlow = approvalFlowId(selectedApprovalRow) || approvalTraceId(selectedApprovalRow);
      if (rowFlow) {
        return rowFlow;
      }
    }
    if (approvalIncidentContext.incident_id && approvalIncidentContext.incident_id === selectedApprovalIncidentId) {
      return approvalFlowFromPayload(approvalIncidentContext.payload);
    }
    return "";
  }, [selectedApprovalRow, approvalIncidentContext, selectedApprovalIncidentId]);

  useEffect(() => {
    if (!selectedApprovalIncidentId) {
      return;
    }
    setApprovalForm((current) => {
      const nextIncidentId = String(selectedApprovalIncidentId || "").trim() || current.incident_id;
      const nextRecommendationId = String(selectedApprovalRecommendationId || "").trim() || current.recommendation_id;
      if (nextIncidentId === current.incident_id && nextRecommendationId === current.recommendation_id) {
        return current;
      }
      return {
        ...current,
        incident_id: nextIncidentId,
        recommendation_id: nextRecommendationId,
      };
    });
  }, [selectedApprovalIncidentId, selectedApprovalRecommendationId]);

  useEffect(() => {
    if (activeTab === "home" && homeDetailTab === "approval" && selectedIncidentId) {
      return;
    }
    if (!filteredPendingApprovals.length) {
      if (selectedApprovalIncidentId) {
        setSelectedApprovalIncidentId("");
      }
      return;
    }
    const selectedExists = filteredPendingApprovals.some((row) => approvalIncidentId(row) === selectedApprovalIncidentId);
    if (selectedExists) {
      return;
    }
    setSelectedApprovalIncidentId(approvalIncidentId(filteredPendingApprovals[0]));
  }, [activeTab, filteredPendingApprovals, homeDetailTab, selectedApprovalIncidentId, selectedIncidentId]);

  useEffect(() => {
    if (!selectedApprovalIncidentId) {
      return;
    }
    loadApprovalIncidentContext(selectedApprovalIncidentId);
  }, [selectedApprovalIncidentId]);

  useEffect(() => {
    if (activeTab !== "home" || homeDetailTab !== "execution" || !selectedIncidentId) {
      return;
    }
    setSelectedApprovalIncidentId((current) => current === selectedIncidentId ? current : selectedIncidentId);
    setApprovalForm((current) => {
      const nextRecommendationId = selectedAlertRecommendationId || current.recommendation_id;
      if (current.incident_id === selectedIncidentId && current.recommendation_id === nextRecommendationId) {
        return current;
      }
      return {
        ...current,
        incident_id: selectedIncidentId,
        recommendation_id: nextRecommendationId,
      };
    });
    loadApprovalIncidentContext(selectedIncidentId);
  }, [activeTab, homeDetailTab, selectedIncidentId, selectedAlertRecommendationId]);

  function selectApprovalIncident(row) {
    const incidentId = approvalIncidentId(row);
    const recommendationId = approvalRecommendationId(row);
    if (!incidentId) {
      return;
    }
    setSelectedApprovalIncidentId(incidentId);
    setApprovalForm((current) => ({
      ...current,
      incident_id: incidentId || current.incident_id,
      recommendation_id: recommendationId || current.recommendation_id,
    }));
    setApprovalState({ loading: false, result: null, error: "" });
    loadApprovalIncidentContext(incidentId);
  }

  function resolvePendingApprovalFromAlertRow(alertRow) {
    const directIncidentId = approvalIncidentId(alertRow);
    if (directIncidentId && pendingApprovalByIncidentId.has(directIncidentId)) {
      return pendingApprovalByIncidentId.get(directIncidentId) || null;
    }

    const service = String(alertRow?.service || "").trim().toLowerCase();
    const severity = String(alertRow?.severity || "").trim().toLowerCase();
    if (!service) {
      return null;
    }

    const byServiceAndSeverity = pendingApprovals.find((row) => {
      const rowService = String(row?.service || "").trim().toLowerCase();
      const rowSeverity = String(row?.severity || row?.risk_tier || "").trim().toLowerCase();
      return rowService === service && (!severity || !rowSeverity || rowSeverity === severity);
    });
    if (byServiceAndSeverity) {
      return byServiceAndSeverity;
    }

    return pendingApprovals.find((row) => String(row?.service || "").trim().toLowerCase() === service) || null;
  }

  // Single source of truth for "what is the approval status of the selected alert" so the
  // Decision Gate, Decision & Approval section, and any other view agree instead of each
  // computing their own answer from a different subset of fields.
  const selectedMatchedApproval = useMemo(
    () => resolvePendingApprovalFromAlertRow(selectedAlertRow),
    [selectedAlertRow, pendingApprovals, pendingApprovalByIncidentId],
  );

  const selectedApprovalStatus = useMemo(
    () => normalizeApprovalStatus(selectedMatchedApproval?.status || selectedAlertWorkflow?.approval?.status),
    [selectedMatchedApproval, selectedAlertWorkflow?.approval?.status],
  );

  function selectApprovalFromAlertRow(alertRow) {
    const matchedRow = resolvePendingApprovalFromAlertRow(alertRow);
    if (!matchedRow) {
      setApprovalState((current) => ({
        ...current,
        error: "No pending approval incident matched this alert. Open incident details or adjust the pending filter.",
      }));
      return null;
    }
    selectApprovalIncident(matchedRow);
    approvalQueueRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    return matchedRow;
  }

  function applyApprovalResolutionToUi(incidentId, nextStatus, comment = "") {
    const normalizedIncidentId = String(incidentId || "").trim();
    const normalizedStatus = String(nextStatus || "").trim().toLowerCase();
    if (!normalizedIncidentId || !normalizedStatus) {
      return;
    }

    const patchIncidentRow = (row) => {
      const rowIncidentId = String(row?.incident_id || row?.id || row?.alert_id || "").trim();
      if (rowIncidentId !== normalizedIncidentId) {
        return row;
      }
      return {
        ...row,
        status: normalizedStatus,
        approval_status: normalizedStatus,
        updated_at: new Date().toISOString(),
        latest_comment: comment || row?.latest_comment || "",
      };
    };

    setIncidentMetadata((prev) => ({
      ...prev,
      rows: Array.isArray(prev.rows) ? prev.rows.map(patchIncidentRow) : prev.rows,
    }));

    setAlerts((prev) => ({
      ...prev,
      rows: Array.isArray(prev.rows)
        ? prev.rows.map((row) => {
            const rowIncidentId = String(row?.incident_id || row?.id || row?.alert_id || "").trim();
            if (rowIncidentId !== normalizedIncidentId) {
              return row;
            }
            return {
              ...row,
              status: normalizedStatus,
              state: normalizedStatus,
              updated_at: new Date().toISOString(),
            };
          })
        : prev.rows,
    }));

    setSelectedAlertData((prev) => {
      const payloadRoot = prev?.payload?.data || prev?.payload;
      if (!payloadRoot || typeof payloadRoot !== "object") {
        return prev;
      }
      const workflow = payloadRoot?.workflow || payloadRoot;
      const workflowIncidentId = String(
        workflow?.incident?.id
        || workflow?.incident_id
        || payloadRoot?.incident?.id
        || payloadRoot?.incident_id
        || ""
      ).trim();
      if (workflowIncidentId !== normalizedIncidentId) {
        return prev;
      }

      const nextWorkflow = {
        ...(workflow || {}),
        incident: {
          ...(workflow?.incident || {}),
          status: normalizedStatus,
          updated_at: new Date().toISOString(),
        },
        approval: {
          ...(workflow?.approval || {}),
          status: normalizedStatus,
          comment: comment || workflow?.approval?.comment || "",
        },
      };

      if (prev?.payload?.data && typeof prev.payload === "object") {
        return {
          ...prev,
          payload: {
            ...prev.payload,
            data: {
              ...payloadRoot,
              workflow: nextWorkflow,
            },
          },
        };
      }

      return {
        ...prev,
        payload: {
          ...payloadRoot,
          workflow: nextWorkflow,
        },
      };
    });

    setApprovalIncidentContext((prev) => {
      if (String(prev?.incident_id || "").trim() !== normalizedIncidentId) {
        return prev;
      }
      const root = prev?.payload && typeof prev.payload === "object" ? prev.payload : {};
      const data = root?.data && typeof root.data === "object" ? root.data : root;
      const patched = {
        ...data,
        status: normalizedStatus,
        state: normalizedStatus,
        approval_status: normalizedStatus,
        updated_at: new Date().toISOString(),
      };
      return {
        ...prev,
        payload: root?.data ? { ...root, data: patched } : patched,
        error: "",
      };
    });
  }

  const approvalReady = useMemo(() => {
    const cockpitIncidentId = activeTab === "home" && ["approval", "execution"].includes(homeDetailTab) ? selectedIncidentId : "";
    const approvalIncidentId = String(cockpitIncidentId || approvalForm.incident_id || selectedApprovalIncidentId || "").trim();
    const hasBase = approvalIncidentId && String(approvalForm.approver || "").trim();
    if (!hasBase) {
      return false;
    }
    if (approvalForm.action !== "approve") {
      if (approvalForm.action === "modify") {
        return String(approvalForm.modified_action || "").trim().length > 0;
      }
      return true;
    }
    if (approvalIncidentContext.incident_id !== approvalIncidentId) {
      return false;
    }
    const contextRoot = unwrap(approvalIncidentContext.payload) || {};
    return canonicalApprovalEligibility({ workflow: contextRoot }).executionEligible;
  }, [activeTab, approvalForm, approvalIncidentContext, homeDetailTab, selectedApprovalIncidentId, selectedIncidentId]);

  async function executeApprovalAction({
    incidentId,
    recommendationId,
    action,
    approver,
    channel,
    comment,
    modifiedAction,
    authorizationScope = "execution",
  }) {
    const normalizedIncidentId = String(incidentId || "").trim();
    const normalizedRecommendationId = String(recommendationId || "").trim();
    const normalizedAction = String(action || "approve").trim().toLowerCase() || "approve";

    if (!looksLikeUuid(normalizedIncidentId)) {
      throw new Error("Approval requires a valid incident_id. Select a pending approval incident first.");
    }
    if (normalizedAction === "modify") {
      throw new Error("Free-text approval modifications are disabled. Generate and approve a new typed plan.");
    }

    let contextRoot = unwrap(approvalIncidentContext.payload) || {};
    const contextRecommendation = contextRoot?.recommendation && typeof contextRoot.recommendation === "object"
      ? contextRoot.recommendation
      : {};
    const contextPlan = contextRecommendation?.metadata?.execution_plan
      && typeof contextRecommendation.metadata.execution_plan === "object"
      ? contextRecommendation.metadata.execution_plan
      : {};
    let selectedPlan = normalizedIncidentId === String(selectedIncidentId || "")
      ? selectedExecutionPlan.catalogPlan || {}
      : contextPlan;
    let boundRecommendationId = normalizedRecommendationId;

    if (normalizedAction === "approve") {
      // Approval must bind to the context returned by this request, not a
      // previous React render. State updates from queue selection are async
      // and previously caused plan_id/fingerprint to be omitted from the POST.
      const liveResponse = await fetchJson(
        `/api-gateway/approval/incident/${encodeURIComponent(normalizedIncidentId)}`,
        authenticatedOptions({ timeoutMs: 30000, maxAttempts: 1 }),
      );
      const liveRoot = unwrap(liveResponse) || {};
      const liveRecommendation = liveRoot?.recommendation && typeof liveRoot.recommendation === "object"
        ? liveRoot.recommendation
        : {};
      const livePlan = liveRecommendation?.metadata?.execution_plan
        && typeof liveRecommendation.metadata.execution_plan === "object"
        ? liveRecommendation.metadata.execution_plan
        : {};
      const liveRecommendationId = String(
        liveRecommendation?.id
        || liveRecommendation?.recommendation_id
        || liveRoot?.recommendation_id
        || "",
      ).trim();
      setApprovalIncidentContext({
        loading: false,
        incident_id: normalizedIncidentId,
        payload: liveRoot,
        error: "",
      });
      if (boundRecommendationId && liveRecommendationId && boundRecommendationId !== liveRecommendationId) {
        throw new Error("The approval queue changed while this incident was open. Review the latest recommendation before approving.");
      }
      boundRecommendationId = liveRecommendationId || boundRecommendationId;
      contextRoot = liveRoot;
      selectedPlan = livePlan;

      const planId = String(selectedPlan?.plan_id || "").trim();
      const planFingerprint = String(selectedPlan?.plan_fingerprint || "").trim();
      if (!planId || !/^sha256:[0-9a-f]{64}$/.test(planFingerprint)) {
        throw new Error(
          "Approval unavailable: this recommendation has no current governed execution plan. Open the incident, run fresh analysis, then review the new plan.",
        );
      }
      const eligibility = canonicalApprovalEligibility({ workflow: liveRoot, plan: selectedPlan });
      if (!eligibility.executionEligible) {
        const missingDetail = eligibility.reasons.length ? ` Missing controls: ${eligibility.reasons.join(", ")}.` : "";
        throw new Error(
          `Approval unavailable: the backend has not marked this plan execution-eligible.${missingDetail} Refresh evidence or regenerate analysis before approval.`,
        );
      }
    }
    const tenantId = String(
      adminSession?.user?.tenant_id
      || selectedPlan?.tenant_id
      || contextRoot?.tenant_id
      || contextRoot?.incident?.tenant_id
      || selectedAlertWorkflow?.context?.tenant_id
      || selectedAlertRow?.tenant_id
      || (authConfig.mode === "local" && authConfig.local_development_only ? "default" : "")
      || ""
    ).trim();
    if (!tenantId) {
      throw new Error("Approval requires a verified tenant identity from the authenticated session.");
    }

    const payload = {
      tenant_id: tenantId,
      incident_id: normalizedIncidentId,
      approver: String(approver || "").trim(),
      channel: String(channel || "web").trim(),
      comment: String(comment || "").trim() || null,
      authorization_scope: authorizationScope,
    };
    if (looksLikeUuid(boundRecommendationId)) {
      payload.recommendation_id = boundRecommendationId;
    }

    if (normalizedAction === "approve") {
      payload.plan_id = selectedPlan?.plan_id;
      payload.plan_fingerprint = selectedPlan?.plan_fingerprint;
    }

    return fetchJson(`/api-gateway/approval/${normalizedAction}`, authenticatedOptions({
      method: "POST",
      body: JSON.stringify(payload),
    }));
  }

  async function resolveRecommendationIdForIncident(incidentId, preferredRecommendationId = "") {
    const normalizedIncidentId = String(incidentId || "").trim();
    const preferred = String(preferredRecommendationId || "").trim();
    if (looksLikeUuid(preferred)) {
      return preferred;
    }

    if (approvalIncidentContext.incident_id === normalizedIncidentId) {
      const fromContext = approvalRecommendationFromPayload(approvalIncidentContext.payload);
      if (looksLikeUuid(fromContext)) {
        return fromContext;
      }
    }

    const options = adminHeaders().Authorization ? authenticatedOptions() : {};
    const response = await fetchJson(`/api-gateway/approval/incident/${encodeURIComponent(normalizedIncidentId)}`, options);
    const payload = unwrap(response);
    const resolved = approvalRecommendationFromPayload(payload);
    if (looksLikeUuid(resolved)) {
      setApprovalIncidentContext({ loading: false, incident_id: normalizedIncidentId, payload, error: "" });
      mergeRecommendationIdIntoApprovalRow(normalizedIncidentId, resolved);
      setApprovalForm((current) => ({
        ...current,
        incident_id: normalizedIncidentId || current.incident_id,
        recommendation_id: resolved || current.recommendation_id,
      }));
      return resolved;
    }
    return "";
  }

  function toPlanLines(value) {
    if (Array.isArray(value)) {
      return value.map((item) => String(item || "").trim()).filter(Boolean);
    }
    return String(value || "")
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean);
  }

  function buildEditedRemediationPlan() {
    return {
      ...(selectedExecutionPlan.catalogPlan && typeof selectedExecutionPlan.catalogPlan === "object" ? selectedExecutionPlan.catalogPlan : {}),
      commands: toPlanLines(remediationPlanEditor.commands),
      scripts: toPlanLines(remediationPlanEditor.scripts),
      queries: toPlanLines(remediationPlanEditor.queries),
    };
  }

  function buildRemediationExecutionPayload({ incidentId, recommendationId, approvalId, approver, action, comment, editedPlan }) {
    const decision = action === "reject" ? "rejected" : "approved";
    const executionTarget = [
      editedPlan?.remediation_target,
      editedPlan?.actions?.[0]?.target_resource_id,
    ].map((value) => String(value || "").trim()).find((value) => value && value !== "-" && !looksLikeUuid(value));

    return {
      ...(looksLikeUuid(approvalId) ? { id: approvalId } : {}),
      tenant_id: String(editedPlan?.tenant_id || selectedAlertWorkflow?.context?.tenant_id || selectedAlertRow?.tenant_id || "").trim(),
      incident_id: incidentId,
      recommendation_id: recommendationId,
      plan_id: editedPlan?.plan_id,
      plan_fingerprint: editedPlan?.plan_fingerprint,
      approval_expires_at: editedPlan?.expiry,
      decision,
      approver,
      channel: approvalForm.channel || "web",
      comment: String(comment || remediationPlanEditor.notes || "approved remediation execution").trim(),
      metadata: {
        recommended_action: selectedExecutionPlan.action,
        recommended_commands: [
          ...editedPlan.commands,
          ...editedPlan.scripts.map((item) => `script: ${item}`),
          ...editedPlan.queries.map((item) => `query: ${item}`),
        ],
        execution_plan: editedPlan,
        rollback_plan: executionRollbackPlan || undefined,
        execution_confirmation_required: true,
        service: executionTarget,
        environment: editedPlan?.environment || selectedApplicationConnection.environment,
        remediation_target: executionTarget,
        connection_profile: {
          application: selectedApplicationConnection.application !== "-" ? selectedApplicationConnection.application : undefined,
          service: executionTarget,
          environment: editedPlan?.environment || selectedApplicationConnection.environment,
          namespace: String(remediationPlanEditor.namespace || selectedApplicationConnection.namespace || "").trim(),
          endpoint_url: String(remediationPlanEditor.connection_url || "").trim(),
          connection_type: String(remediationPlanEditor.connection_type || selectedApplicationConnection.connection_type || "").trim(),
          executor_type: String(remediationPlanEditor.executor_type || "").trim(),
          job_name: String(remediationPlanEditor.job_name || "").trim(),
          timeout_seconds: 1200,
          allowed_operations: ["rollback_deployment", "restart_pod", "scale_deployment", "restart_service", "clear_cache", "failover_database", "terraform_rollback"],
          source: selectedApplicationConnection.source,
          credential_ref: String(remediationPlanEditor.credential_ref || selectedApplicationConnection.credential_ref || "").trim() || undefined,
        },
        ui_edited: false,
        plan_source: "approved_catalog",
      },
    };
  }

  async function postRemediationExecution(payload, incidentId, comment) {
    const response = await fetchJson("/api-gateway/remediation/execute", authenticatedOptions({
      method: "POST",
      body: JSON.stringify(payload),
    }));
    const action = unwrap(response);
    const status = String(action?.status || "").toLowerCase();
    const terminal = ["succeeded", "failed", "skipped", "completed", "closed", "resolved"].includes(status);
    // Submission acknowledgement is not an execution result. Keep the gate
    // locked until a terminal action status is observed from the backend.
    setRemediationExecutionState({ loading: !terminal, result: response, error: "" });
    applyApprovalResolutionToUi(
      incidentId,
      status === "succeeded" ? "validating" : status === "failed" || status === "skipped" ? "failed" : "remediating",
      comment
    );
    await refreshApprovalDrivenViews(incidentId);
    void pollIncidentTerminalStatus(incidentId);
    return response;
  }

  async function requestEmergencyStop(actionId) {
    const reason = String(emergencyStopState.reason || "").trim();
    if (!looksLikeUuid(String(actionId || ""))) {
      setEmergencyStopState((current) => ({ ...current, error: "A persisted remediation action is required before emergency stop is available." }));
      return;
    }
    if (reason.length < 8) {
      setEmergencyStopState((current) => ({ ...current, error: "Add a clear emergency-stop reason of at least 8 characters." }));
      return;
    }
    setEmergencyStopState((current) => ({ ...current, loading: true, error: "", message: "" }));
    try {
      const response = await fetchJson(`/api-gateway/remediation/actions/${encodeURIComponent(actionId)}/emergency-stop`, authenticatedOptions({ method: "POST", body: JSON.stringify({ reason }) }));
      setRemediationExecutionState({ loading: false, result: response, error: "" });
      setEmergencyStopState({ reason: "", loading: false, error: "", message: "Emergency stop accepted. The executor and durable workflow were cancelled." });
      await refreshApprovalDrivenViews(selectedIncidentId);
      if (selectedAlertId) await loadAlertDetails(selectedAlertId, selectedAlertRow, { background: true });
    } catch (error) {
      setEmergencyStopState((current) => ({ ...current, loading: false, error: String(error?.message || "Emergency stop failed."), message: "" }));
    }
  }

  async function approveEvidenceDraft() {
    const draft = evidenceDraftReview.draft; if (!draft?.draft_id) return;
    setEvidenceDraftReview((current) => ({ ...current, loading: true, error: "", message: "" }));
    try {
      const reviewed = unwrap(await evidenceDraftApi.review(draft, evidenceDraftReview.content, evidenceDraftReview.notes))?.draft;
      const response = await evidenceDraftApi.approve(reviewed); const next = unwrap(response)?.draft || reviewed;
      setEvidenceDraftReview((current) => ({ ...current, loading: false, draft: next, message: "Approved — indexing pending." }));
      await Promise.allSettled([loadRagDocs(), loadSelectedAlertDocumentLinks(selectedAlertId)]);
    } catch (error) {
      if (isEvidenceDraftConflict(error)) {
        const latest = await evidenceDraftApi.load(String(selectedAlertId)); const next = latest.find((item) => item.draft_id === draft.draft_id) || latest[0] || draft;
        setEvidenceDraftReview((current) => ({ ...current, loading: false, drafts: latest, draft: next, content: next.content || "", error: evidenceDraftApi.conflictMessage }));
      } else setEvidenceDraftReview((current) => ({ ...current, loading: false, error: String(error?.message || error) }));
    }
  }
  async function saveEvidenceDraft() {
    const draft = evidenceDraftReview.draft; if (!draft?.draft_id) return;
    setEvidenceDraftReview((current) => ({ ...current, loading: true, error: "", message: "" }));
    try {
      const response = await evidenceDraftApi.review(draft, evidenceDraftReview.content, evidenceDraftReview.notes); setEvidenceDraftReview((current) => ({ ...current, loading: false, draft: unwrap(response)?.draft || { ...draft, status: "reviewed" }, message: "Draft saved. It remains blocked from reusable knowledge until an authorized user approves it." }));
    } catch (error) {
      if (isEvidenceDraftConflict(error)) {
        const latest = await evidenceDraftApi.load(String(selectedAlertId)); const next = latest.find((item) => item.draft_id === draft.draft_id) || latest[0] || draft;
        setEvidenceDraftReview((current) => ({ ...current, loading: false, drafts: latest, draft: next, content: next.content || "", error: evidenceDraftApi.conflictMessage }));
      } else setEvidenceDraftReview((current) => ({ ...current, loading: false, error: String(error?.message || error) }));
    }
  }
  async function approveExecutionOutcomeForReuse() {
    if (!selectedRemediationOutcome) return;
    setExecutionOutcomeReview((current) => ({ ...current, loading: true, error: "", message: "" }));
    try {
      const plan = remediationPlanEditor.scripts || remediationPlanEditor.commands;
      const reviewer = adminSession?.user?.username || "operator";
      const content = [`# Validated remediation: ${selectedAlertRow?.name || "incident"}`, "", `Service: ${selectedApplicationConnection.service}`, `Environment: ${selectedApplicationConnection.environment}`, `Outcome: ${executionOutcomeReview.outcome}`, `Reviewed by: ${reviewer}`, "", "## Approved execution plan", plan || "No reusable execution command supplied.", "", "## Validation", ...editedExecutionPlan.queries, "", "## Rollback", executionRollbackPlan || "Not supplied", "", "## Operator review", executionOutcomeReview.notes || "No additional notes."].join("\n");
      if (executionOutcomeReview.reusable && plan) {
        await fetchJson("/api-gateway/rag/knowledge-drafts", authenticatedOptions({ method: "POST", body: JSON.stringify({ kind: "remediation", alert_id: selectedAlertId, alert_type: selectedAlertRow?.name || selectedAlertRow?.alert_name, severity: selectedAlertRow?.severity, title: `Validated remediation for ${selectedAlertRow?.name || selectedApplicationConnection.service}`, summary: "Operator-reviewed remediation outcome awaiting governed review.", content, services: [selectedApplicationConnection.service], source_system: "kaims-execution-review", source_ref: `execution-review://${selectedAlertId}`, resolved_by: reviewer, metadata: { approval_status: "pending_review", execution_outcome: String(executionOutcomeReview.outcome), reusable: "false" } }) }));
      }
      if (selectedAlertRecommendationId) await fetchJson(`/api-gateway/evaluations/by-recommendation/${encodeURIComponent(selectedAlertRecommendationId)}/feedback`, authenticatedOptions({ method: "POST", body: JSON.stringify({ decision: executionOutcomeReview.outcome === "successful" ? "approve" : "reject", approver: reviewer, comment: executionOutcomeReview.notes || `Execution outcome: ${executionOutcomeReview.outcome}` }) })).catch(() => null);
      setExecutionOutcomeReview((current) => ({ ...current, loading: false, reviewedAlertId: String(selectedAlertId || ""), message: current.reusable && plan ? "Outcome reviewed. The approved script is now reusable knowledge." : "Outcome review recorded without publishing a reusable script." }));
      const incidentId = String(selectedIncidentId || selectedApprovalIncidentId || approvalForm.incident_id || "").trim();
      await Promise.allSettled([
        loadRagDocs(),
        loadSelectedAlertDocumentLinks(selectedAlertId, selectedAlertRow),
        loadAlertDetails(selectedAlertId, selectedAlertRow, { background: true }),
        incidentId ? loadIncidentStageCompleteness(incidentId, { background: true }) : Promise.resolve(),
      ]);
      setHomeDetailTab("audit");
    } catch (error) {
      setExecutionOutcomeReview((current) => ({ ...current, loading: false, error: String(error?.message || error) }));
    }
  }

  async function approveIncidentRow(row, authorizationScope = "execution") {
    const incidentId = approvalIncidentId(row);
    const rowRecommendationId = approvalRecommendationId(row);
    setSelectedApprovalIncidentId(incidentId);
    setApprovalForm((current) => ({
      ...current,
      action: "approve",
      incident_id: incidentId || current.incident_id,
      recommendation_id: rowRecommendationId || current.recommendation_id,
    }));
    setApprovalState({ loading: true, result: null, error: "" });

    try {
      const recommendationId = await resolveRecommendationIdForIncident(incidentId, rowRecommendationId);
      const response = await executeApprovalAction({
        incidentId,
        recommendationId,
        action: "approve",
        approver: approvalForm.approver,
        channel: approvalForm.channel,
        comment: approvalForm.comment,
        authorizationScope,
      });
      setRemediationExecutionState({ loading: true, result: null, error: "" });
      const remediationResponse = authorizationScope === "dry_run"
        ? await fetchJson("/api-gateway/remediation/dry-run", authenticatedOptions({ method: "POST", body: JSON.stringify(unwrap(response)) }))
        : await postRemediationExecution(unwrap(response), incidentId, approvalForm.comment);
      const remediationStatus = String(unwrap(remediationResponse)?.status || "").toLowerCase();
      setApprovalForm((current) => ({
        ...current,
        action: "approve",
        incident_id: incidentId || current.incident_id,
        recommendation_id: recommendationId || current.recommendation_id,
      }));
      applyApprovalResolutionToUi(
        incidentId,
        remediationStatus === "succeeded" ? "validating" : remediationStatus === "failed" || remediationStatus === "skipped" ? "failed" : "remediating",
        approvalForm.comment
      );
      setApprovalState({ loading: false, result: { approval: response, remediation: remediationResponse }, error: "" });
      loadApprovalIncidentContext(incidentId, { force: true });
      await refreshApprovalDrivenViews(incidentId);
    } catch (error) {
      const raw = String(error?.message || "");
      const concise = raw.includes("HTTP 422")
        ? "Inline approve could not submit because this incident has no linked remediation recommendation yet. Re-run the incident workflow to generate a recommendation."
        : raw;
      setApprovalState({ loading: false, result: null, error: concise });
      setRemediationExecutionState((current) => current.loading ? { loading: false, result: null, error: concise } : current);
    }
  }

  async function requestMoreEvidence(row, reason) {
    const incidentId = approvalIncidentId(row);
    const recommendationId = await resolveRecommendationIdForIncident(incidentId, approvalRecommendationId(row));
    setApprovalState({ loading: true, result: null, error: "" });
    try {
      const response = await executeApprovalAction({
        incidentId,
        recommendationId,
        action: "request-evidence",
        approver: approvalForm.approver,
        channel: approvalForm.channel,
        comment: reason,
      });
      applyApprovalResolutionToUi(incidentId, "investigating", reason);
      setApprovalState({ loading: false, result: response, error: "" });
      await refreshApprovalDrivenViews(incidentId);
    } catch (error) {
      setApprovalState({ loading: false, result: null, error: String(error?.message || error) });
    }
  }

  async function rejectIncidentRow(row) {
    const incidentId = approvalIncidentId(row);
    const rowRecommendationId = approvalRecommendationId(row);
    setSelectedApprovalIncidentId(incidentId);
    setApprovalForm((current) => ({
      ...current,
      action: "reject",
      incident_id: incidentId || current.incident_id,
      recommendation_id: rowRecommendationId || current.recommendation_id,
    }));
    setApprovalState({ loading: true, result: null, error: "" });

    try {
      const recommendationId = await resolveRecommendationIdForIncident(incidentId, rowRecommendationId);
      const response = await executeApprovalAction({
        incidentId,
        recommendationId,
        action: "reject",
        approver: approvalForm.approver,
        channel: approvalForm.channel,
        comment: inlineRejectState.comment,
      });
      setApprovalForm((current) => ({
        ...current,
        action: "reject",
        incident_id: incidentId || current.incident_id,
        recommendation_id: recommendationId || current.recommendation_id,
        comment: inlineRejectState.comment || current.comment,
      }));
      applyApprovalResolutionToUi(incidentId, "failed", inlineRejectState.comment);
      setInlineRejectState({ incidentId: "", comment: "" });
      setApprovalState({ loading: false, result: response, error: "" });
      loadApprovalIncidentContext(incidentId, { force: true });
      await refreshApprovalDrivenViews(incidentId);
    } catch (error) {
      const raw = String(error?.message || "");
      const concise = raw.includes("HTTP 422")
        ? "Inline reject could not submit because this incident has no linked remediation recommendation yet. Re-run the incident workflow to generate a recommendation."
        : raw;
      setApprovalState({ loading: false, result: null, error: concise });
    }
  }

  async function submitApproval(event) {
    event.preventDefault();
    setApprovalState({ loading: true, result: null, error: "" });
    try {
      const cockpitIncidentId = activeTab === "home" && ["approval", "execution"].includes(homeDetailTab) ? selectedIncidentId : "";
      const incidentId = String(cockpitIncidentId || approvalForm.incident_id || selectedApprovalIncidentId || "").trim();
      const approver = String(approvalForm.approver || adminSession?.user?.username || "admin").trim();
      if (!looksLikeUuid(incidentId)) {
        throw new Error("Select a valid incident first from the approval queue.");
      }
      if (!approver) {
        throw new Error("Approver is required.");
      }
      if (["high", "critical"].includes(String(selectedExecutionPlan.riskTier || selectedAlertRow?.severity || "").toLowerCase())
        && ["approve", "modify"].includes(approvalForm.action)
        && !String(approvalForm.comment || "").trim()) {
        throw new Error("A reason is required for high-risk approval or override.");
      }
      const recommendationIdCandidate = String(
        (cockpitIncidentId ? selectedAlertRecommendationId : "")
        || approvalForm.recommendation_id
        || selectedApprovalRecommendationId
        || approvalRecommendationFromPayload(approvalIncidentContext.payload)
        || ""
      ).trim();
      const recommendationId = await resolveRecommendationIdForIncident(incidentId, recommendationIdCandidate);
      const response = await executeApprovalAction({
        incidentId,
        recommendationId,
        action: approvalForm.action,
        approver,
        channel: approvalForm.channel,
        comment: approvalForm.comment,
        modifiedAction: approvalForm.modified_action,
      });
      let remediationResponse = null;
      let actionStatus = approvalForm.action === "reject" ? "failed" : "remediating";
      if (approvalForm.action === "approve" || approvalForm.action === "modify") {
        const editedPlan = buildEditedRemediationPlan();
        const hasPlan = editedPlan.commands.length || editedPlan.scripts.length || editedPlan.queries.length;
        if (hasPlan) {
          setRemediationExecutionState({ loading: true, result: null, error: "" });
          const executionPayload = buildRemediationExecutionPayload({
            incidentId,
            recommendationId,
            approvalId: String(unwrap(response)?.id || ""),
            approver,
            action: approvalForm.action,
            comment: approvalForm.comment,
            editedPlan,
          });
          remediationResponse = await postRemediationExecution(executionPayload, incidentId, approvalForm.comment);
          const remediationStatus = String(unwrap(remediationResponse)?.status || "").toLowerCase();
          actionStatus = remediationStatus === "succeeded"
            ? "validating"
            : remediationStatus === "failed" || remediationStatus === "skipped"
              ? "failed"
              : "remediating";
        } else {
          setRemediationExecutionState({
            loading: false,
            result: null,
            error: "Approval was recorded, but no remediation commands, script, or validation query were available to execute.",
          });
        }
      }
      applyApprovalResolutionToUi(incidentId, actionStatus, approvalForm.comment);
      setApprovalState({ loading: false, result: remediationResponse ? { approval: response, remediation: remediationResponse } : response, error: "" });
      loadApprovalIncidentContext(incidentId, { force: true });
      await refreshApprovalDrivenViews(incidentId);
    } catch (error) {
      const raw = String(error?.message || "");
      const concise = raw.includes("HTTP 422")
        ? "Approval was rejected because this incident has no linked remediation recommendation yet. Re-run the incident workflow to generate one."
        : raw;
      setApprovalState({ loading: false, result: null, error: concise });
      setRemediationExecutionState((current) => current.loading ? { loading: false, result: null, error: concise } : current);
    }
  }

  async function executeApprovedRemediationPlan() {
    const incidentId = String(approvalForm.incident_id || selectedIncidentId || selectedApprovalIncidentId || "").trim();
    const recommendationIdCandidate = String(
      approvalForm.recommendation_id
      || selectedApprovalRecommendationId
      || approvalRecommendationFromPayload(approvalIncidentContext.payload)
      || selectedAlertWorkflow?.recommendation?.id
      || ""
    ).trim();
    const approver = String(adminSession?.user?.username || "").trim();
    const approvalStatus = normalizeApprovalStatus(selectedExecutionPlan.approvalStatus || approvalForm.action);
    const editedPlan = buildEditedRemediationPlan();
    const hasPlan = editedPlan.commands.length || editedPlan.scripts.length || editedPlan.queries.length;

    setRemediationExecutionState({ loading: true, result: null, error: "" });
    try {
      if (!looksLikeUuid(incidentId)) {
        throw new Error("Remediation execution requires a valid incident_id. Select an alert with an incident or sync approval context.");
      }
      const recommendationId = await resolveRecommendationIdForIncident(incidentId, recommendationIdCandidate);
      if (!looksLikeUuid(recommendationId)) {
        throw new Error("Remediation execution requires a valid recommendation_id from the approved incident.");
      }
      if (!hasPlan) {
        throw new Error("Add at least one command, script, or validation query before executing.");
      }
      const liveTarget = [editedPlan?.remediation_target, editedPlan?.actions?.[0]?.target_resource_id]
        .map((value) => String(value || "").trim())
        .find((value) => value && value !== "-" && !looksLikeUuid(value));
      if (!liveTarget) {
        throw new Error("Execution requires an approved service or resource target. Add the application/service mapping before running this plan.");
      }
      if (executionIsReadOnly || editedPlan.execution_ready === false) {
        throw new Error("Execution unavailable: this plan is diagnostic-only and has no reviewed corrective capability.");
      }
      if (!approver) {
        throw new Error("An authenticated operator identity is required for execution.");
      }
      if (approvalStatus !== "approved" && approvalForm.action !== "approve") {
        throw new Error("Approve the immutable remediation plan before execution.");
      }

      const approvalAction = "approve";
      if (approvedExecutionSignature !== executionPlanSignature) {
        throw new Error("This plan has changed since approval. Review and approve the current plan once before execution.");
      }

      const payload = buildRemediationExecutionPayload({
        incidentId,
        recommendationId,
        approvalId: approvedExecutionApprovalId,
        action: approvalAction,
        approver,
        comment: String(approvalForm.comment || remediationPlanEditor.notes || "approved remediation execution").trim(),
        editedPlan,
      });
      await postRemediationExecution(payload, incidentId, approvalForm.comment);
    } catch (error) {
      setRemediationExecutionState({ loading: false, result: null, error: String(error?.message || error) });
    }
  }



  async function approveCockpitRemediationPlan(actionOverride = "") {
    const incidentId = String(approvalForm.incident_id || selectedIncidentId || selectedApprovalIncidentId || "").trim();
    const recommendationIdCandidate = String(approvalForm.recommendation_id || selectedApprovalRecommendationId || selectedAlertRecommendationId || "").trim();
    const approver = String(adminSession?.user?.username || "").trim();
    setApprovalState({ loading: true, result: null, error: "" });
    try {
      if (!looksLikeUuid(incidentId)) throw new Error("A valid incident is required before this plan can be approved.");
      if (!approver) throw new Error("An authenticated operator identity is required for approval.");
      const requestedAction = actionOverride === "reject" || approvalForm.action === "reject" ? "reject" : "approve";
      if (requestedAction !== "reject" && !editedExecutionPlan.commands.length && !editedExecutionPlan.scripts.length) throw new Error("Review or add an executable command or script before approval.");
      if (requestedAction !== "reject" && (executionIsReadOnly || editedExecutionPlan.execution_ready === false)) throw new Error("A diagnostic-only plan cannot be approved for execution. Reject automation and escalate it for manual remediation instead.");
      if ((requestedAction === "reject" || ["high", "critical"].includes(String(selectedExecutionPlan.riskTier || selectedAlertRow?.severity || "").toLowerCase())) && !String(approvalForm.comment || "").trim()) throw new Error(requestedAction === "reject" ? "Add an escalation reason before rejecting automation." : "Add an approval reason for this high-risk plan.");
      const recommendationId = await resolveRecommendationIdForIncident(incidentId, recommendationIdCandidate);
      const action = requestedAction;
      const response = await executeApprovalAction({ incidentId, recommendationId, action, approver, channel: approvalForm.channel, comment: approvalForm.comment, modifiedAction: "" });
      let escalationResponse = null;
      if (action === "reject") {
        escalationResponse = await fetchJson(
          `/api-gateway/incidents/${encodeURIComponent(incidentId)}/escalate`,
          authenticatedOptions({
            method: "POST",
            body: JSON.stringify({
              comment: String(approvalForm.comment || "").trim(),
              service: String(selectedAlertRow?.service || selectedAlertWorkflow?.incident?.service || "unknown"),
              severity: String(selectedAlertRow?.severity || selectedAlertWorkflow?.incident?.severity || "medium"),
              resource_names: [String(selectedAlertRow?.service || "").trim()].filter(Boolean),
            }),
          }),
        );
      }
      setApprovalForm((current) => ({ ...current, action, incident_id: incidentId, recommendation_id: recommendationId, approver }));
      applyApprovalResolutionToUi(incidentId, action === "reject" ? "closed" : "approved", approvalForm.comment);
      setApprovedExecutionSignature(executionPlanSignature);
      const approvalId = String(unwrap(response)?.id || "");
      setApprovedExecutionApprovalId(approvalId);
      setExecutionApprovalRequiresRenewal(false);
      const riskTier = String(selectedExecutionPlan.riskTier || selectedAlertRow?.severity || "").toLowerCase();
      const autoDispatchAfterApproval = action === "approve"
        && !dangerousProductionAction
        && !["high", "critical"].includes(riskTier)
        && liveExecutionPlanAvailable
        && blockingPreflightFailures.length === 0;
      let remediationResponse = null;
      if (autoDispatchAfterApproval) {
        setRemediationExecutionState({ loading: true, result: null, error: "" });
        try {
          const payload = buildRemediationExecutionPayload({
            incidentId,
            recommendationId,
            approvalId,
            approver,
            action,
            comment: approvalForm.comment,
            editedPlan: buildEditedRemediationPlan(),
          });
          remediationResponse = await postRemediationExecution(payload, incidentId, approvalForm.comment);
        } catch (executionError) {
          const message = String(executionError?.message || executionError);
          setRemediationExecutionState({ loading: false, result: null, error: `Approval was recorded, but execution could not start: ${message}` });
          setApprovalState({ loading: false, result: response, error: "Approval recorded. Review the execution blocker below and retry without approving again." });
          await refreshApprovalDrivenViews(incidentId);
          return;
        }
      }
      setApprovalState({ loading: false, result: escalationResponse ? { approval: response, escalation: escalationResponse } : remediationResponse ? { approval: response, remediation: remediationResponse } : response, error: "" });
      await refreshApprovalDrivenViews(incidentId);
    } catch (error) {
      setApprovalState({ loading: false, result: null, error: String(error?.message || error) });
    }
  }

  function confirmAndExecuteRemediationPlan() {
    const target = `${selectedGovernedExecutionTarget || "no governed target"} (${selectedApplicationConnection.environment})`;
    if (!window.confirm(`Execute the approved remediation plan against ${target}? This action is recorded in the audit trail.`)) {
      return;
    }
    executeApprovedRemediationPlan();
  }

  function buildRequiredExecutor() {
    const service = String(selectedGovernedExecutionTarget || "service").trim();
    const environment = String(selectedApplicationConnection.environment || "prod").trim();
    setRemediationPlanEditor((current) => ({
      ...current,
      executor_type: "jenkins",
      connection_type: "jenkins",
      connection_url: current.connection_type === "jenkins" && current.connection_url ? current.connection_url : LOCAL_JENKINS_ENDPOINT,
      job_name: current.job_name || LOCAL_JENKINS_JOB,
      namespace: current.namespace || environment,
      credential_ref: current.credential_ref || LOCAL_JENKINS_CREDENTIAL_REF,
      credential_store: current.credential_store || "hashicorp_vault",
      queries: current.queries || `max_over_time(up{job='${service}'}[5m])`,
    }));
    setShowExecutionCredential(true);
    setExecutionPreflightState({ signature: "", checkedAt: "", passed: false });
    setApprovedExecutionSignature("");
    setApprovedExecutionApprovalId("");
    setExecutionApprovalRequiresRenewal(true);
    setExecutionConfirmationText("");
  }

  const currentRole = useMemo(() => normalizeRoleName(adminSession?.user?.role_name), [adminSession?.user?.role_name]);
  const navigationGroups = useMemo(() => groupedNavigationForRole(currentRole), [currentRole]);
  const currentNavigationItem = useMemo(() => navigationItemForPath(currentPath), [currentPath]);
  const currentBreadcrumb = useMemo(() => breadcrumbForPath(currentPath), [currentPath]);
  const restrictedDestination = useMemo(() => new URLSearchParams(currentSearch).get("destination") || "", [currentSearch]);
  const kaiStateSummary = useMemo(() => {
    const rows = monitorScopedIncidentMetadata || [];
    const statusIncludes = (row, values) => values.some((value) => String(row?.status || row?.state || row?.remediation_status || "").toLowerCase().includes(value));
    const terminal = (row) => statusIncludes(row, ["closed", "resolved", "cancelled"]);
    const resolving = rows.filter((row) => statusIncludes(row, ["execut", "remediat", "rollback"])).length;
    const validating = rows.filter((row) => statusIncludes(row, ["validat", "verif"])).length;
    const blocked = rows.filter((row) => statusIncludes(row, ["blocked", "failed", "manual_intervention"])).length;
    const investigating = rows.filter((row) => !terminal(row) && !statusIncludes(row, ["approval", "execut", "remediat", "rollback", "validat", "verif", "blocked", "failed"])).length;
    return [
      { label: "Investigating", value: investigating, tone: "active" },
      { label: "Resolving", value: resolving, tone: "active" },
      { label: "Waiting approval", value: pendingApprovals.length, tone: pendingApprovals.length ? "attention" : "calm" },
      { label: "Validating", value: validating, tone: "active" },
      { label: "Blocked", value: blocked, tone: blocked ? "attention" : "calm" },
    ];
  }, [monitorScopedIncidentMetadata, pendingApprovals]);
  const projectOnboardingRows = useMemo(
    () => (onboardingState.rows || []).filter((row) => String(row?.provider_name || "").trim().toLowerCase() === "project"),
    [onboardingState.rows],
  );
  const onboardingProjectRowOptions = useMemo(() => {
    const names = new Set();
    (onboardingState.rows || []).forEach((row) => {
      const name = extractOnboardingProjectName(row);
      if (name) {
        names.add(name);
      }
    });
    return Array.from(names).sort((a, b) => a.localeCompare(b));
  }, [onboardingState.rows]);
  const monitoringProjectOptions = useMemo(() => {
    const names = new Set();
    (monitoringApps.rows || []).forEach((row) => {
      const name = String(row?.name || "").trim();
      if (name) {
        names.add(name);
      }
    });
    return Array.from(names).sort((a, b) => a.localeCompare(b));
  }, [monitoringApps.rows]);
  const onboardingProjectOptions = useMemo(() => {
    const names = new Set();
    onboardingProjectRowOptions.forEach((name) => names.add(name));
    monitoringProjectOptions.forEach((name) => names.add(name));
    return Array.from(names).sort((a, b) => a.localeCompare(b));
  }, [onboardingProjectRowOptions, monitoringProjectOptions]);
  const ruleOnboardingRows = useMemo(
    () => (onboardingState.rows || []).filter((row) => {
      const provider = String(row?.provider_name || "").trim().toLowerCase();
      return provider === "existing_rule_sync" || provider === "new_rule_onboarding";
    }),
    [onboardingState.rows],
  );
  const allowedTabs = useMemo(() => allowedLegacyTabsForRole(currentRole), [currentRole]);
  const ingestionStreamRows = useMemo(() => {
    const landingRows = (Array.isArray(landingPadRecent.rows) ? landingPadRecent.rows : [])
      .map((row, index) => {
        const mapped = mapLandingPadRowToAlertStreamRow(row, index);
        return {
          ...mapped,
          file: row?.file || "-",
          path: row?.path || "",
          error: row?.error || "",
          source_channel: normalizeAlertChannel(mapped),
        };
      });

    const alertRows = (Array.isArray(alerts.rows) ? alerts.rows : []).map((row, index) => {
      const mapped = mapLandingPadRowToAlertStreamRow({ ...row, _stream_kind: row?._stream_kind || "alerts_api" }, index);
      return {
        ...mapped,
        file: row?.file || "-",
        path: row?.path || "",
        error: row?.error || "",
        source_channel: normalizeAlertChannel(mapped),
      };
    });

    const allStreamRows = [...landingRows, ...alertRows];
    const consolidatedRows = dedupeAndConsolidateAlertRows(allStreamRows, {
        channels: ALERT_SOURCE_CHANNELS,
        preferLatestState: true,
      });
    const incidentByAlertId = new Map();
    (Array.isArray(incidentMetadata.rows) ? incidentMetadata.rows : []).forEach((incident) => {
      const projection = incident?.projection_payload && typeof incident.projection_payload === "object" ? incident.projection_payload : {};
      const eventPayload = projection?.event_payload && typeof projection.event_payload === "object" ? projection.event_payload : {};
      [incident?.alert_id, projection?.alert_id, eventPayload?.alert_id]
        .map((value) => String(value || "").trim())
        .filter(Boolean)
        .forEach((alertId) => incidentByAlertId.set(alertId, incident));
    });
    const enrichedRows = consolidatedRows.map((row) => {
      const alertId = String(row?.alert_id || row?.id || "").trim();
      const incident = incidentByAlertId.get(alertId);
      if (!incident) return row;
      return {
        ...row,
        incident_id: incident?.incident_id || incident?.id || row?.incident_id,
        ticket_id: incident?.ticket_id || incident?.jira_key || row?.ticket_id,
        jira_key: incident?.jira_key || incident?.ticket_id || row?.jira_key,
        jira_url: incident?.jira_url || row?.jira_url,
        incident_projection: incident,
      };
    });
    return capLatestAlertsPerSource(
      ensureMinimumAlertsBySource(enrichedRows, allStreamRows)
    );
  }, [landingPadRecent.rows, alerts.rows, incidentMetadata.rows]);
  // Live Stream is a project workspace: rows and all derived counts must stay
  // within the project selected in the global monitor selector.
  const scopedIngestionStreamRows = ingestionStreamRows;
  const applicationScopedIngestionStreamRows = useMemo(
    () => filterAlertsForMonitor(scopedIngestionStreamRows, applicationToMonitor),
    [applicationToMonitor, scopedIngestionStreamRows],
  );
  const ingestionStreamCounts = useMemo(() => {
    // Source cards describe the currently selected lifecycle section. Counting
    // resolved rows while the Active tab hides them produces a contradictory
    // "3 arrivals / 0 results" view.
    const sectionRows = applicationScopedIngestionStreamRows.filter((row) => {
      const failed = String(row?.status || "").toLowerCase() === "failed" || Boolean(row?.error);
      const status = String(row?.alert_status || row?.status || "").toLowerCase();
      const resolved = ["resolved", "closed", "completed", "inactive"].includes(status);
      const timestamp = alertTimeMs(row);
      if (ingestionStreamSection === "active") return !failed && !resolved;
      if (ingestionStreamSection === "resolved") return resolved;
      if (ingestionStreamSection === "failed") return failed;
      if (ingestionStreamSection === "historical") return Boolean(timestamp && Date.now() - timestamp >= 86400000);
      return true;
    });
    const counts = { all: sectionRows.length, email: 0, log: 0, prometheus: 0, telemetry: 0, ticket: 0, failed: 0 };
    sectionRows.forEach((row) => {
      const channels = Array.isArray(row?.source_channels) && row.source_channels.length
        ? row.source_channels
        : [String(row?.source_channel || "prometheus")];
      Array.from(new Set(channels)).forEach((channel) => {
        counts[channel] = Number(counts[channel] || 0) + 1;
      });
      if (String(row?.status || "").toLowerCase() === "failed" || row?.error) {
        counts.failed += 1;
      }
    });
    return counts;
  }, [applicationScopedIngestionStreamRows, ingestionStreamSection]);
  const visibleIngestionStreamRows = useMemo(() => {
    const query = String(ingestionStreamQuery || "").trim().toLowerCase();
    const now = Date.now();
    const timeWindowMs = { "1h": 3600000, "24h": 86400000, "7d": 604800000 }[ingestionStreamFilters.timeRange] || 0;
    return applicationScopedIngestionStreamRows.filter((row) => {
      const failed = String(row?.status || "").toLowerCase() === "failed" || Boolean(row?.error);
      const status = String(row?.alert_status || row?.status || "").toLowerCase();
      const resolved = ["resolved", "closed", "completed", "inactive"].includes(status);
      const timestamp = alertTimeMs(row);
      if (ingestionStreamSection === "active" && (failed || resolved)) return false;
      if (ingestionStreamSection === "resolved" && !resolved) return false;
      if (ingestionStreamSection === "failed" && !failed) return false;
      if (ingestionStreamSection === "historical" && (!timestamp || now - timestamp < 86400000)) return false;
      if (ingestionStreamChannel === "failed" && !failed) {
        return false;
      }
      const rowChannels = Array.isArray(row?.source_channels) && row.source_channels.length
        ? row.source_channels
        : [row.source_channel];
      if (!["all", "failed"].includes(ingestionStreamChannel) && !rowChannels.includes(ingestionStreamChannel)) {
        return false;
      }
      if (timeWindowMs && (!timestamp || now - timestamp > timeWindowMs)) return false;
      if (ingestionStreamFilters.severity !== "all" && String(row?.severity || "").toLowerCase() !== ingestionStreamFilters.severity) return false;
      if (ingestionStreamFilters.environment !== "all" && String(row?.environment || row?.labels?.environment || "unknown").toLowerCase() !== ingestionStreamFilters.environment) return false;
      if (!query) {
        return true;
      }
      return [
        row.name,
        row.service,
        row.application,
        row.project_name,
        row.source,
        row.file,
        row.status,
        row.error,
      ].map((value) => String(value || "").toLowerCase()).join(" ").includes(query);
    }).slice(0, 50);
  }, [applicationScopedIngestionStreamRows, ingestionStreamChannel, ingestionStreamFilters, ingestionStreamQuery, ingestionStreamSection]);
  const ingestionFilterOptions = useMemo(() => ({
    applications: Array.from(new Set(scopedIngestionStreamRows.map((row) => String(row?.application || row?.project_name || row?.project || "").trim()).filter(Boolean))).sort(),
    environments: Array.from(new Set(applicationScopedIngestionStreamRows.map((row) => String(row?.environment || row?.labels?.environment || "unknown").trim().toLowerCase()).filter(Boolean))).sort(),
  }), [applicationScopedIngestionStreamRows, scopedIngestionStreamRows]);
  const isAuthenticated = Boolean(String(adminSession.accessToken || "").trim());
  const isAdministrator = currentRole === "administrator";
  const canUseApprovalActions = allowedTabs.includes("approval");
  const executionRollbackPlan = String(
    selectedAlertWorkflow?.recommendation?.rollback
    || selectedAlertWorkflow?.recommendation?.rollback_plan
    || (Array.isArray(selectedExecutionPlan.catalogPlan?.rollback_commands) ? selectedExecutionPlan.catalogPlan.rollback_commands.join("\n") : selectedExecutionPlan.catalogPlan?.rollback_commands)
    || (Array.isArray(selectedExecutionPlan.catalogPlan?.rollback) ? selectedExecutionPlan.catalogPlan.rollback.join("\n") : selectedExecutionPlan.catalogPlan?.rollback)
    || selectedExecutionPlan.remediationAction?.rollback
    || selectedExecutionPlan.remediationAction?.parameters?.rollback_plan
    || (Array.isArray(selectedExecutionPlan.remediationAnalysis?.rollback_plan) ? selectedExecutionPlan.remediationAnalysis.rollback_plan.join(" ") : selectedExecutionPlan.remediationAnalysis?.rollback_plan)
    || ""
  ).trim();
  const editedExecutionPlan = buildEditedRemediationPlan();
  const effectiveCredentialRef = String(remediationPlanEditor.credential_ref || selectedApplicationConnection.credential_ref || "").trim();
  const executionPlanSignature = JSON.stringify({
    // Incident/recommendation IDs can be hydrated while the dry-run request is
    // in flight. They identify backend records but do not change the reviewed
    // plan. Use the stable selected alert so hydration cannot invalidate a
    // successful dry run and send the operator back to step 1.
    alert: selectedAlertId || "",
    target_service: selectedGovernedExecutionTarget,
    target_environment: selectedApplicationConnection.environment,
    connection: remediationPlanEditor.connection_url,
    executor_type: remediationPlanEditor.executor_type,
    job_name: remediationPlanEditor.job_name,
    namespace: remediationPlanEditor.namespace,
    credential_ref: effectiveCredentialRef,
    ...editedExecutionPlan,
  });
  const credentialReferenceValid = !executionRequiresCredential || /^(?:vault:\/\/|arn:aws:secretsmanager:|gcp-secret:\/\/|k8s-secret:\/\/)/.test(effectiveCredentialRef) || /^https:\/\/[^/]+\.vault\.azure\.net\/secrets\/[^/]+(?:\/[^/]+)?$/i.test(effectiveCredentialRef);
  const executionPreflightChecks = [
    { id: "incident", label: "Incident identity", detail: "A durable incident ID is attached.", passed: looksLikeUuid(String(approvalForm.incident_id || selectedIncidentId || selectedApprovalIncidentId || "")), blocking: true },
    { id: "approval", label: "Approval state", detail: "Approval is bound to the exact reviewed plan.", passed: selectedExecutionBreakdown.approvalStatus === "approved", blocking: false },
    { id: "role", label: "Operator permission", detail: "The signed-in role can approve and execute remediation.", passed: canUseApprovalActions, blocking: true },
    { id: "target", label: "Execution target", detail: `${selectedGovernedExecutionTarget || "No governed target"} in ${selectedApplicationConnection.environment}.`, passed: Boolean(selectedGovernedExecutionTarget && !looksLikeUuid(selectedGovernedExecutionTarget)), blocking: true },
    { id: "plan", label: "Corrective capability", detail: executionIsReadOnly ? "This plan collects evidence but does not change the target." : `${editedExecutionPlan.commands.length} command(s), ${editedExecutionPlan.scripts.length} script(s).`, passed: Boolean((editedExecutionPlan.commands.length || editedExecutionPlan.scripts.length) && !executionIsReadOnly && editedExecutionPlan.execution_ready !== false), blocking: true },
    { id: "connection", label: "Connector endpoint", detail: executionEndpointValid ? "Endpoint format is valid." : "Use an http:// or https:// endpoint; deployment names are not URLs.", passed: executionEndpointValid, blocking: Boolean(executionEndpoint) },
    { id: "executor", label: "Governed executor", detail: jenkinsExecutorSelected ? remediationPlanEditor.job_name && executionEndpoint ? `Jenkins job ${remediationPlanEditor.job_name} is configured.` : "Add the Jenkins URL and job path." : executionIsReadOnly ? "Read-only validation does not require a live executor." : "Build a connector for this live action.", passed: executionIsReadOnly || (jenkinsExecutorSelected && Boolean(remediationPlanEditor.job_name) && Boolean(executionEndpoint)), blocking: !executionIsReadOnly },
    { id: "emergency-stop", label: "Emergency stop", detail: executionIsReadOnly ? "Not required for a read-only plan." : jenkinsExecutorSelected ? "Queued and running Jenkins actions can be cancelled and audited." : "The selected executor has no implemented emergency-stop adapter.", passed: executionIsReadOnly || jenkinsExecutorSelected, blocking: !executionIsReadOnly },
    { id: "credential", label: "Credential reference", detail: !executionRequiresCredential ? "Not required for this read-only plan." : credentialReferenceValid ? "A valid enterprise secret-manager URI is attached." : "Use an Azure Key Vault, HashiCorp Vault, AWS Secrets Manager, or Kubernetes Secret URI.", passed: credentialReferenceValid, blocking: executionRequiresCredential },
    { id: "rollback", label: "Rollback coverage", detail: executionRollbackPlan || "No explicit rollback plan is attached.", passed: Boolean(executionRollbackPlan), blocking: !executionIsReadOnly },
    { id: "validation", label: "Recovery validation", detail: editedExecutionPlan.queries.length ? `${editedExecutionPlan.queries.length} post-check(s) supplied.` : "No explicit validation query is attached.", passed: editedExecutionPlan.queries.length > 0, blocking: !executionIsReadOnly },
  ];
  const blockingPreflightFailures = executionPreflightChecks.filter((check) => check.blocking && !check.passed);
  const approvalWillAutoExecute = !dangerousProductionAction
    && !["high", "critical"].includes(String(selectedExecutionPlan.riskTier || selectedAlertRow?.severity || "").toLowerCase())
    && liveExecutionPlanAvailable
    && blockingPreflightFailures.length === 0;
  const executionAwaitingTerminalResult = remediationExecutionState.loading && Boolean(remediationExecutionState.result);
  const executionSetupBlocked = !executionAwaitingTerminalResult && blockingPreflightFailures.length > 0;
  const cockpitApprovalAccepted = executionAwaitingTerminalResult || (!executionApprovalRequiresRenewal && selectedExecutionBreakdown.approvalStatus === "approved")
    || approvedExecutionSignature === executionPlanSignature;
  const executionAllowed = !remediationExecutionState.loading
    && cockpitApprovalAccepted
    && executionConfirmationValid
    && liveExecutionPlanAvailable
    && blockingPreflightFailures.length === 0;
  const executionCapabilityBlocked = !executionAwaitingTerminalResult
    && cockpitApprovalAccepted
    && executionConfirmationValid
    && !liveExecutionPlanAvailable;
  const executionActivationMessage = remediationExecutionState.loading
    ? "Execution submitted — waiting for the terminal run status"
    : executionAllowed
      ? "Ready for guarded execution"
      : !cockpitApprovalAccepted
          ? executionIsReadOnly ? "Choose manual escalation or regenerate a reviewed corrective plan" : "Approve the reviewed plan"
      : blockingPreflightFailures.length
        ? `Complete: ${blockingPreflightFailures.map((check) => check.label).join(", ")}`
          : !liveExecutionPlanAvailable
            ? "Validation-only plan: attach a governed live executor before execution"
          : !executionConfirmationValid
            ? `Type ${executionConfirmationPhrase} in the production confirmation field`
            : "Execution is temporarily unavailable";
  const cockpitApprovalComplete = ["approved", "rejected"].includes(selectedExecutionBreakdown.approvalStatus);
  const manualEscalationRecorded = approvalForm.action === "reject" && (
    ["rejected", "failed"].includes(selectedExecutionBreakdown.approvalStatus)
    || Boolean(approvalState.result && !approvalState.error)
  );
  const activeEmergencyStopStatuses = ["pending", "policy_checked", "approved", "dispatching", "executor_accepted", "running", "verifying"];
  const responseAction = unwrap(remediationExecutionState.result);
  const emergencyStopAction = responseAction?.id ? responseAction : selectedExecutionPlan.remediationAction;
  const emergencyStopAvailable = looksLikeUuid(String(emergencyStopAction?.id || "")) && activeEmergencyStopStatuses.includes(String(emergencyStopAction?.status || "").toLowerCase());
  const blockedRecommendationId = String(
    selectedExecutionPlan.remediationAction?.metadata?.recommendation_id
    || selectedExecutionPlan.remediationAction?.parameters?.recommendation_id
    || "",
  ).trim();
  const policyBlockBelongsToOlderPlan = Boolean(
    blockedRecommendationId
    && selectedExecutionPlan.recommendationId
    && blockedRecommendationId !== selectedExecutionPlan.recommendationId,
  );
  const blockedActionStatus = String(selectedExecutionPlan.remediationAction?.status || "").trim().toLowerCase();
  const rawExecutionPolicyBlock = (
    String(selectedExecutionPlan.remediationAction?.action_type || "").trim().toLowerCase() === "policy-blocked"
    || blockedActionStatus === "policy_blocked"
    || selectedExecutionPlan.remediationAction?.metadata?.policy_blocked === true
  );
  // Automatic policy evaluation records an audit action with action_type
  // policy-blocked and status awaiting_approval when HITL may continue. That
  // is a handoff to an operator, not a permanent execution terminal state.
  const policyBlockAwaitingHumanReview = rawExecutionPolicyBlock
    && (
      ["awaiting_approval", "pending", "pending_approval"].includes(blockedActionStatus)
      || ["awaiting_approval", "pending", "pending_approval"].includes(selectedCanonicalIncidentStatus)
      || ["awaiting_approval", "pending", "pending_approval"].includes(selectedExecutionBreakdown.approvalStatus)
    );
  const executionPolicyBlocked = rawExecutionPolicyBlock
    && !policyBlockBelongsToOlderPlan
    && !policyBlockAwaitingHumanReview;
  const persistedDiagnosticCompletion = String(selectedExecutionPlan.remediationAction?.action_type || "").trim().toLowerCase() === "diagnostic_completion"
    && selectedExecutionPlan.remediationAction?.parameters?.diagnostic_closure === true;
  const recordedExecutionStatus = persistedDiagnosticCompletion
    ? "diagnostic_completed"
    : executionAutoCloses
      ? ""
    : policyBlockBelongsToOlderPlan || policyBlockAwaitingHumanReview
    ? ""
    : blockedActionStatus;
  const terminalIncidentStatus = String(selectedExecutionBreakdown.incidentStatus || "").trim().toLowerCase();
  const cockpitExecutionStatus = effectiveExecutionStatus(
    terminalIncidentStatus,
    recordedExecutionStatus,
    selectedExecutionTechnicalResponse?.queue_url,
  );
  const resolveStageDescription = (() => {
    if (executionAutoCloses) {
      return ["closed", "resolved"].includes(selectedCanonicalIncidentStatus)
        ? "Watch-only closed"
        : "Watch-only auto-closing";
    }
    if (executionIsDiagnosticOnly) return "Investigation requires action";
    if (executionPolicyBlocked) return "Execution blocked — action required";
    if (
      ["awaiting_approval", "pending", "pending_approval"].includes(cockpitExecutionStatus)
      || ["awaiting_approval", "pending", "pending_approval"].includes(selectedCanonicalIncidentStatus)
      || ["awaiting_approval", "pending", "pending_approval"].includes(selectedExecutionBreakdown.approvalStatus)
    ) return "Waiting for approval";
    if (selectedExecutionBreakdown.approvalStatus === "approved" && !cockpitExecutionStatus) return "Approved — ready to execute";
    const labels = {
      dispatching: "Starting remediation",
      executor_accepted: "Queued for execution",
      running: "Remediation running",
      verifying: "Validating recovery",
      succeeded: "Remediation completed",
      execution_failed: "Execution failed",
      validation_failed: "Recovery validation failed",
      failed: "Execution failed",
    };
    return labels[cockpitExecutionStatus] || cockpitExecutionStatus || "Plan, approve, execute";
  })();
  const cockpitAnalysis = canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow);
  const executionOutcomeReviewed = String(executionOutcomeReview.reviewedAlertId || "") === String(selectedAlertId || "")
    || selectedAlertRagDocuments.some((document) => String(document?.source_system || document?.metadata?.source_system || "").toLowerCase() === "kaims-execution-review");
  const incidentCockpitStages = [
    { id: "overview", short: "01", label: "Orient", accessibleLabel: "Overview", description: "Identity and lifecycle", complete: Boolean(selectedAlertId) },
    { id: "evidence", short: "02", label: "Evidence & Understanding", accessibleLabel: "Evidence, RCA, and impact", description: `${selectedAiTrust.evidence.length} linked record(s) · RCA and impact`, complete: selectedAiTrust.evidence.length > 0 && Boolean(cockpitAnalysis.rootCause && cockpitAnalysis.rootCause !== "-") },
    { id: "execution", short: "03", label: "Resolve", accessibleLabel: "Resolve incident", description: resolveStageDescription, complete: persistedDiagnosticCompletion || (["closed", "resolved"].includes(selectedCanonicalIncidentStatus) && executionAutoCloses) || (!executionPolicyBlocked && !executionAutoCloses && ["succeeded", "skipped", "failed", "dispatch_failed", "execution_failed", "validation_failed", "rolled_back", "rollback_failed", "timed_out", "cancelled", "manual_intervention_required"].includes(cockpitExecutionStatus)) },
    { id: "audit", short: "04", label: "Validate", accessibleLabel: "Audit Trail", description: selectedCanonicalIncidentStatus === "closed" ? "closed" : executionOutcomeReviewed ? "outcome reviewed" : "audit and recovery", complete: selectedCanonicalIncidentStatus === "closed" || executionOutcomeReviewed },
  ];
  const cockpitRecommendedStage = (() => {
    if (!incidentCockpitStages.find((stage) => stage.id === "evidence")?.complete || selectedAlertEvaluation.requiresReview) return "evidence";
    if (!cockpitAnalysis.action || cockpitAnalysis.action === "-") return "execution";
    if (!cockpitApprovalComplete || !cockpitExecutionStatus) return "execution";
    return "audit";
  })();
  const cockpitRecommended = incidentCockpitStages.find((stage) => stage.id === cockpitRecommendedStage) || incidentCockpitStages[0];

  useEffect(() => {
    if (!isAuthenticated || canAccessDestination(currentRole, currentNavigationItem.id)) {
      return;
    }
    skipNextActiveTabNavigationRef.current = true;
    setActiveTab("home");
    if (typeof onNavigatePath === "function") {
      onNavigatePath(`/?access=restricted&destination=${encodeURIComponent(currentNavigationItem.label)}`);
    }
  }, [currentNavigationItem.id, currentNavigationItem.label, currentRole, isAuthenticated, onNavigatePath]);
  const canManageSeverityOverride = ["administrator", "l2_engineer", "l3_engineer", "p2", "p3"].includes(currentRole);
  const canProvideAlertDocuments = DOCUMENT_PROVIDER_ROLES.has(currentRole);
  const onboardingSourceDocRows = useMemo(
    () => (Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : []).filter((row) => {
      const text = String(row?.text || "").trim();
      const warning = String(row?.warning || "").trim();
      return Boolean(text) && !warning;
    }),
    [onboardingSourceDocs.rows],
  );
  const selectedJenkinsProcess = useMemo(() => {
    const response = selectedExecutionTechnicalResponse && typeof selectedExecutionTechnicalResponse === "object" ? selectedExecutionTechnicalResponse : {};
    const submitted = response.submitted_parameters && typeof response.submitted_parameters === "object" ? response.submitted_parameters : {};
    const executor = String(response.executor || remediationPlanEditor.executor_type || remediationPlanEditor.connection_type || "").toLowerCase();
    const resolutionId = String(submitted.KAI_OPS_RESOLUTION_ID || response.resolution_id || selectedExecutionPlan.remediationAction?.parameters?.resolution_id || selectedExecutionPlan.remediationAction?.action_type || "").trim();
    const submittedDryRun = submitted.KAI_OPS_DRY_RUN ?? response.dry_run ?? selectedExecutionPlan.remediationAction?.parameters?.dry_run;
    const presentation = executionProcessPresentation(cockpitExecutionStatus, submittedDryRun, executor === "jenkins");
    return {
      ...presentation,
      configured: executor === "jenkins",
      jobName: String(response.job_name || remediationPlanEditor.job_name || ""),
      queueUrl: String(response.queue_url || ""),
      resolutionId: resolutionId || "Not selected",
      hasResolution: Boolean(resolutionId),
      applicationId: String(submitted.KAI_OPS_APPLICATION_ID || selectedExecutionPlan.remediationAction?.parameters?.application_id || selectedApplicationConnection.application || "Not recorded"),
    };
  }, [selectedExecutionTechnicalResponse, cockpitExecutionStatus, selectedExecutionPlan, remediationPlanEditor, selectedApplicationConnection]);
  const onboardingSourceDocCount = onboardingSourceDocRows.length;
  const severityOverrideByKey = useMemo(() => {
    const map = new Map();
    (alertSeverityOverrides.rows || []).forEach((row) => {
      const key = severityOverrideKey(row?.name, row?.service, row?.environment);
      if (key) {
        map.set(key, row);
      }
    });
    return map;
  }, [alertSeverityOverrides.rows]);
  const selectedAlertActionContext = useMemo(() => {
    if (!selectedAlertRow) {
      return null;
    }
    const status = selectedCanonicalIncidentStatus;
    const alertName = String(selectedAlertRow?.name || selectedAlertRow?.alert_name || "").trim();
    const service = String(selectedAlertRow?.service || "").trim();
    const environment = String(selectedAlertRow?.environment || "").trim();
    const overrideKey = severityOverrideKey(alertName, service, environment);
    const overrideRow = severityOverrideByKey.get(overrideKey);
    return {
      status,
      alertName,
      overrideKey,
      overrideRow,
      documentAvailable: hasAlertDocuments(selectedAlertRow),
      alertClosed: isApprovalResolvedStatus(status),
      draftSeverity: String(
        alertSeverityDrafts[overrideKey]
          || overrideRow?.severity
          || String(selectedAlertRow?.severity || "warning").toLowerCase()
      ).toLowerCase(),
      overrideSaving: alertSeverityOverrides.savingKey === overrideKey,
    };
  }, [selectedAlertRow, selectedCanonicalIncidentStatus, severityOverrideByKey, alertSeverityDrafts, alertSeverityOverrides.savingKey]);
  const selectedAlertRuleSummary = useMemo(
    () => summarizeAlertRuleContext(selectedAlertRow, selectedAlertWorkflow),
    [selectedAlertRow, selectedAlertWorkflow],
  );
  const onboardingValidationErrors = useMemo(() => {
    const errors = [];
    if (!String(onboardingForm.name || "").trim()) {
      errors.push("Project name is required.");
    }
    if (!String(onboardingForm.owner_team || "").trim()) {
      errors.push("Owner team is required.");
    }
    if (!String(onboardingForm.region || "").trim()) {
      errors.push("Region is required.");
    }
    if (String(onboardingForm.deployment_mode || "").trim() === "azure_cloud") {
      if (!String(onboardingForm.azure_subscription_id || "").trim()) {
        errors.push("Azure Subscription ID is required for Azure Cloud deployment.");
      }
      if (!String(onboardingForm.azure_service_bus_namespace || "").trim()) {
        errors.push("Azure Service Bus Namespace is required for Azure Cloud deployment.");
      }
      if (!String(onboardingForm.azure_service_bus_topic || "").trim()) {
        errors.push("Azure Service Bus Topic is required for Azure Cloud deployment.");
      }
      if (!String(onboardingForm.azure_service_bus_subscription || "").trim()) {
        errors.push("Azure Service Bus Subscription is required for Azure Cloud deployment.");
      }
    }
    const isSetupMonitoringPath = String(onboardingForm.onboarding_path || "setup_monitoring").trim() === "setup_monitoring";
    const derivedRequirementCount = (Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : []).reduce(
      (count, row) => count + (Array.isArray(row?.derived_requirements) ? row.derived_requirements.length : 0),
      0,
    );
    if (isSetupMonitoringPath && !String(onboardingForm.rule_onboarding_plain_language || "").trim() && derivedRequirementCount === 0) {
      errors.push("Add plain-English rule intent or upload one Service Knowledge file that produces derived requirements.");
    }
    if (isSetupMonitoringPath && !String(onboardingForm.monitoring_url || "").trim()) {
      errors.push("Prometheus endpoint URL is required for Configure Prometheus Monitoring path.");
    }
    if (String(onboardingForm.connection_auth_type || "none") !== "none" && !String(onboardingForm.connection_secret_ref || "").trim()) {
      errors.push("A secret reference is required when monitoring authentication is enabled. Do not enter the secret value.");
    }
    return errors;
  }, [
    onboardingForm.name,
    onboardingForm.owner_team,
    onboardingForm.region,
    onboardingForm.deployment_mode,
    onboardingForm.azure_subscription_id,
    onboardingForm.azure_service_bus_namespace,
    onboardingForm.azure_service_bus_topic,
    onboardingForm.azure_service_bus_subscription,
    onboardingForm.onboarding_path,
    onboardingForm.monitoring_url,
    onboardingForm.rule_onboarding_plain_language,
    onboardingForm.connection_auth_type,
    onboardingForm.connection_secret_ref,
    onboardingSourceDocs.rows,
    onboardingSourceDocCount,
  ]);
  const onboardingAdvisory = useMemo(() => {
    const onboardingPath = String(onboardingForm.onboarding_path || "setup_monitoring").trim();
    if (onboardingPath === "existing_monitoring") {
      return "Existing monitoring path: upload one Service Knowledge file, save project, then send alerts to /alerts/alertmanager to trigger workflow.";
    }
    if (String(onboardingForm.deployment_mode || "").trim() !== "on_prem") {
      return "";
    }
    if (String(onboardingForm.monitoring_url || "").trim()) {
      return "";
    }
    return "Tool endpoint URL is optional now, but recommended for connectivity and rule simulation quality.";
  }, [onboardingForm.deployment_mode, onboardingForm.monitoring_url, onboardingForm.onboarding_path]);
  const onboardingLandingPadDetails = useMemo(() => {
    const summary = onboardingLandingPadSummary && typeof onboardingLandingPadSummary === "object" ? onboardingLandingPadSummary : {};
    const landingPadPath = String(summary?.landing_pad_endpoint || "/alerts/alertmanager").trim() || "/alerts/alertmanager";
    const selectedTool = String(summary?.selected_monitoring_tool || onboardingForm.monitoring_tool || "prometheus").trim().toLowerCase();
    const configuredEndpoint = String(summary?.configured_monitoring_endpoint || onboardingForm.monitoring_url || "").trim();
    const projectName = String(summary?.project_name || onboardingForm.name || "").trim() || "<project-name>";
    const browserOrigin = typeof window !== "undefined" && window?.location?.origin ? window.location.origin : "http://localhost:8501";
    const onboardingPath = String(onboardingForm.onboarding_path || "setup_monitoring").trim().toLowerCase();
    const routeMessage = String(summary?.message || "").trim() || "Send alerts from your monitoring platform to this landing pad endpoint to trigger workflow execution.";

    const samplePayload = {
      receiver: "kaiops",
      status: "firing",
      alerts: [
        {
          status: "firing",
          labels: {
            alertname: `${projectName}-high-latency`,
            severity: "critical",
            service: projectName,
          },
          annotations: {
            summary: "P95 latency exceeded threshold",
            description: "Checkout latency above 2s for 5 minutes",
          },
          startsAt: "2026-01-01T00:00:00Z",
        },
      ],
    };

    return {
      onboardingPath,
      routeMessage,
      selectedTool,
      configuredEndpoint: configuredEndpoint || "Not set",
      externalIngestionEndpoint: `${browserOrigin}/api-gateway${landingPadPath}`,
      internalIngestionEndpoint: `http://monitoring-adapter:8000${landingPadPath}`,
      method: "POST",
      contentType: "application/json",
      traceHeader: "x-trace-id (optional)",
      samplePayload: JSON.stringify(samplePayload, null, 2),
    };
  }, [onboardingLandingPadSummary, onboardingForm.monitoring_tool, onboardingForm.monitoring_url, onboardingForm.name, onboardingForm.onboarding_path]);
  const onboardingHasPendingDocumentApproval = useMemo(
    () => onboardingGeneratedDocs.length > 0 && !onboardingDocApprovalState.approved,
    [onboardingGeneratedDocs.length, onboardingDocApprovalState.approved],
  );
  const onboardingDocumentSummary = useMemo(
    () => ({
      total: onboardingGeneratedDocs.length,
      approved: onboardingDocApprovalState.approved,
    }),
    [onboardingGeneratedDocs.length, onboardingDocApprovalState.approved],
  );
  const onboardingWizardSteps = useMemo(() => {
    const docsUploaded = onboardingSourceDocCount > 0;
    const requirementsDerived = onboardingDerivedRequirements.length > 0
      || String(onboardingForm.rule_onboarding_plain_language || "").trim().length > 0;
    const ruleGenerated = Boolean(
      onboardingRuleRunState?.result
      || onboardingRuleLookup?.result
      || String(onboardingRuleLookup?.workflow_id || "").trim(),
    );
    const docsApproved = Boolean(onboardingDocApprovalState.approved);
    const metadataStored = String(onboardingState.success || "").toLowerCase().includes("saved")
      || projectOnboardingRows.some((row) => {
        const name = String(row?.project_name || "").trim();
        return name && name === String(selectedOnboardingProject || onboardingForm.name || "").trim();
      });

    return [
      { id: "docs_uploaded", label: "Docs Uploaded", complete: docsUploaded },
      { id: "requirements", label: "Requirements Derived", complete: requirementsDerived },
      { id: "rules", label: "Rules Generated", complete: ruleGenerated },
      { id: "docs_approved", label: "Docs Approved", complete: docsApproved },
      { id: "metadata", label: "Metadata Stored", complete: metadataStored },
    ];
  }, [
    onboardingSourceDocCount,
    onboardingDerivedRequirements.length,
    onboardingForm.rule_onboarding_plain_language,
    onboardingRuleRunState?.result,
    onboardingRuleLookup?.result,
    onboardingRuleLookup?.workflow_id,
    onboardingDocApprovalState.approved,
    onboardingState.success,
    projectOnboardingRows,
    selectedOnboardingProject,
    onboardingForm.name,
  ]);
  const onboardingGeneratedRuleRows = useMemo(() => {
    const primary = normalizeGeneratedRuleRows(onboardingRuleRunState?.result);
    if (primary.length) {
      return primary;
    }
    return normalizeGeneratedRuleRows(onboardingRuleLookup?.result);
  }, [onboardingRuleRunState?.result, onboardingRuleLookup?.result]);
  const onboardingRulePromptLines = useMemo(
    () => String(onboardingForm.rule_onboarding_plain_language || "")
      .split(/\r?\n/)
      .map(cleanRuleIntentLine)
      .filter(Boolean),
    [onboardingForm.rule_onboarding_plain_language],
  );
  const onboardingPrometheusRulePreview = useMemo(() => buildPrometheusRulePreview({
    projectName: onboardingForm.name || selectedOnboardingProject,
    serviceName: onboardingForm.name || selectedOnboardingProject || "kaiops-service",
    environment: onboardingForm.environment || "prod",
    requirements: onboardingRulePromptLines,
  }), [
    onboardingForm.name,
    selectedOnboardingProject,
    onboardingForm.environment,
    onboardingRulePromptLines,
  ]);
  const onboardingRulePromptVisible = onboardingSourceDocCount > 0 || onboardingRulePromptLines.length > 0 || onboardingGeneratedRuleRows.length > 0;
  const onboardingMetadataRows = useMemo(() => {
    const currentProject = String(selectedOnboardingProject || onboardingForm.name || "").trim();
    const rows = Array.isArray(onboardingState.rows) ? onboardingState.rows : [];
    return rows
      .filter((row) => {
        const projectName = String(row?.project_name || "").trim();
        return currentProject ? projectName === currentProject : true;
      })
      .map((row, index) => ({
        id: `${String(row?.provider_name || "provider")}-${index}`,
        provider: String(row?.provider_name || "-").trim(),
        project: String(row?.project_name || "-").trim(),
        status: String(row?.test_status || row?.status || "-").trim(),
        updated_at: String(row?.updated_at || row?.created_at || "-").trim(),
      }));
  }, [onboardingState.rows, selectedOnboardingProject, onboardingForm.name]);
  const onboardingReviewGate = useMemo(() => {
    const needsRules = onboardingGeneratedRuleRows.length > 0;
    const needsDocs = onboardingGeneratedDocs.length > 0;
    const needsMetadata = onboardingMetadataRows.length > 0;
    const rulesOk = !needsRules || onboardingReviewAck.rules;
    const docsOk = !needsDocs || onboardingReviewAck.docs;
    const metadataOk = !needsMetadata || onboardingReviewAck.metadata;
    return {
      needsRules,
      needsDocs,
      needsMetadata,
      allReviewed: rulesOk && docsOk && metadataOk,
    };
  }, [
    onboardingGeneratedRuleRows.length,
    onboardingGeneratedDocs.length,
    onboardingMetadataRows.length,
    onboardingReviewAck.rules,
    onboardingReviewAck.docs,
    onboardingReviewAck.metadata,
  ]);
  const onboardingNextAction = useMemo(() => {
    const onboardingPath = String(onboardingForm.onboarding_path || "setup_monitoring").trim();
    if (onboardingState.loading) {
      return "Saving setup and generating onboarding artifacts...";
    }
    if (onboardingHasPendingDocumentApproval) {
      return "Review generated documents below, then click Approve Documents.";
    }
    if (onboardingDocumentSummary.approved) {
      return "Documents approved. You can continue with another update or proceed to advanced workflow management.";
    }
    return onboardingPath === "setup_monitoring"
      ? "Step 1: save monitoring setup. Step 2: add Service Knowledge and generate rules."
      : "Step 1: save monitoring setup and landing pad. Step 2: add Service Knowledge and generate documents.";
  }, [
    onboardingState.loading,
    onboardingHasPendingDocumentApproval,
    onboardingDocumentSummary.approved,
    onboardingForm.onboarding_path,
  ]);

  const adminWorkspaceCaptions = useMemo(() => ({
    users: "Manage users, roles, and credentials.",
    monitoring: "Setup monitoring foundations, landing pad routing, and rule/doc generation.",
    project: "Two-step setup: connect monitoring first, then add documents and rules.",
    alerts: "Alert knowledge onboarding and bulk document ingestion.",
  }), []);
  const adminJourneyStep = useMemo(() => {
    if (adminWorkspace === "users") {
      return "access";
    }
    if (adminWorkspace === "alerts" || (adminWorkspace === "project" && projectSetupStep === "knowledge")) {
      return "knowledge";
    }
    return "setup";
  }, [adminWorkspace, projectSetupStep]);
  const adminJourneyCards = useMemo(() => {
    const setupSaved = Boolean(String(onboardingState.success || "").trim()) && !onboardingState.loading && !onboardingState.error;
    const setupComplete = Boolean(onboardingDocumentSummary.approved) || setupSaved || onboardingWorkflowSteps.length > 0;
    const knowledgeComplete = Boolean(alertOnboardingState.result);
    const setupTone = onboardingState.error
      ? "error"
      : onboardingHasPendingDocumentApproval
          ? "warning"
          : setupComplete
            ? "success"
            : "info";
    const knowledgeHasError = Boolean(alertOnboardingState.error);
    const knowledgeTone = knowledgeHasError
      ? "error"
      : knowledgeComplete
        ? "success"
        : "info";
    return [
      {
        id: "access",
        title: "1. Access",
        hint: "Users, roles, session security",
        status: adminUsers.loading
          ? "Loading users and roles..."
          : adminUsers.error
            ? "Unable to load users"
            : adminUsers.rows.length
              ? `${adminUsers.rows.length} users loaded`
              : "No users returned yet. Click Refresh.",
        complete: Boolean(adminUsers.rows.length),
        tone: adminUsers.error ? "error" : adminUsers.rows.length ? "success" : adminUsers.loading ? "warning" : "info",
        cta: "Open access controls",
      },
      {
        id: "setup",
        title: "2. Guided Setup",
        hint: "Prompt, auto-complete, score, validate",
        status: onboardingHasPendingDocumentApproval
          ? "Setup saved. Review generated documents to finalize."
          : onboardingDocumentSummary.approved
            ? "Project docs approved"
            : (setupSaved || onboardingWorkflowSteps.length > 0)
              ? "Project setup saved and synced."
              : onboardingNextAction,
        complete: setupComplete,
        tone: setupTone,
        cta: onboardingHasPendingDocumentApproval
          ? "Review generated artifacts"
          : setupComplete
            ? "Open workflow status"
            : "Continue guided setup",
      },
      {
        id: "knowledge",
        title: "3. Knowledge",
        hint: "Alert docs onboarding",
        status: knowledgeComplete ? "Knowledge artifacts created" : "Pending knowledge curation",
        complete: knowledgeComplete,
        tone: knowledgeTone,
        cta: knowledgeComplete ? "Review stored knowledge" : "Open knowledge onboarding",
      },
    ];
  }, [
    adminUsers.rows.length,
    adminUsers.loading,
    adminUsers.error,
    onboardingDocumentSummary.approved,
    onboardingNextAction,
    onboardingState.error,
    onboardingState.loading,
    onboardingState.success,
    onboardingHasPendingDocumentApproval,
    onboardingWorkflowSteps.length,
    alertOnboardingState.result,
    alertOnboardingState.error,
  ]);
  const projectStepCards = useMemo(() => {
    const setupSaved = Boolean(String(onboardingState.success || "").trim()) && !onboardingState.loading && !onboardingState.error;
    const monitoringDone = Boolean(String(onboardingForm.name || "").trim())
      && Boolean(String(onboardingForm.owner_team || "").trim())
      && Boolean(String(onboardingForm.region || "").trim())
      && Boolean(String(onboardingForm.monitoring_url || "").trim());
    const docsRulesDone = Boolean(onboardingSourceDocCount > 0 || onboardingRulePromptLines.length > 0 || onboardingGeneratedDocs.length > 0 || setupSaved);
    return [
      { id: "setup", label: "1. Profile & Sources", hint: "Project, owners, monitoring, connections", complete: monitoringDone },
      { id: "docs_rules", label: "2. Knowledge & Rules", hint: "Context, SLOs, alerts, runbooks", complete: docsRulesDone },
      { id: "review", label: "3. Review & Approve", hint: "Rules, documents, metadata", complete: Boolean(onboardingDocApprovalState.approved) },
      { id: "status", label: "4. Activate & Verify", hint: "Workflow, validation, dashboards", complete: Boolean(setupSaved && (onboardingDocApprovalState.approved || onboardingWorkflowSteps.length > 0)) },
    ];
  }, [
    onboardingForm.name,
    onboardingForm.owner_team,
    onboardingForm.region,
    onboardingSourceDocCount,
    onboardingRulePromptLines.length,
    onboardingState.success,
    onboardingState.loading,
    onboardingState.error,
    onboardingGeneratedDocs.length,
    onboardingDocApprovalState.approved,
    onboardingWorkflowSteps.length,
    onboardingForm.monitoring_url,
  ]);
  const showProjectStep = (stepId) => adminWorkspace !== "project" || projectSetupShowAll || projectSetupStep === stepId;
  const navigateAdminJourney = (stepId) => {
    if (stepId === "access") {
      setAdminWorkspace("users");
      return;
    }
    if (stepId === "knowledge") {
      setAdminWorkspace("alerts");
      setProjectSetupShowAll(false);
      setAlertKnowledgeView("onboarding");
      return;
    }
    setAdminWorkspace("project");
    setProjectSetupShowAll(false);
  };
  const triggerAdminJourneyCta = (stepId) => {
    if (stepId === "setup") {
      setAdminWorkspace("project");
      setProjectSetupShowAll(false);
      if (onboardingHasPendingDocumentApproval) {
        setProjectSetupStep("review");
        return;
      }
      if (onboardingDocumentSummary.approved) {
        setProjectSetupStep("status");
        return;
      }
      setProjectSetupStep("docs_rules");
      return;
    }
    navigateAdminJourney(stepId);
  };

  useEffect(() => {
    if (adminWorkspace !== "project" || projectSetupShowAll) {
      return;
    }
    if (projectSetupStep !== "docs_rules") {
      return;
    }
    if (onboardingState.loading || onboardingState.error) {
      return;
    }
    const success = String(onboardingState.success || "").trim();
    if (!success) {
      return;
    }
    if (success.toLowerCase().includes("documents approved")) {
      return;
    }
    if (onboardingGeneratedDocs.length > 0) {
      setProjectSetupStep("review");
      return;
    }
    if (onboardingSourceDocCount === 0) {
      setProjectSetupStep("docs_rules");
      setAlertKnowledgeView("onboarding");
      alertKnowledgeRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }
    setProjectSetupStep("status");
  }, [
    adminWorkspace,
    projectSetupShowAll,
    projectSetupStep,
    onboardingState.loading,
    onboardingState.error,
    onboardingState.success,
    onboardingGeneratedDocs.length,
    onboardingSourceDocCount,
  ]);

  useEffect(() => {
    if (adminWorkspace !== "project" || projectSetupShowAll) {
      return;
    }
    if (projectSetupStep !== "review") {
      return;
    }
    if (onboardingDocApprovalState.approved) {
      setProjectSetupStep("status");
    }
  }, [adminWorkspace, projectSetupShowAll, projectSetupStep, onboardingDocApprovalState.approved]);

  useEffect(() => {
    if (!isAuthenticated || (adminWorkspace !== "monitoring" && adminWorkspace !== "project")) {
      return;
    }
    loadMonitoringApplications();
  }, [isAuthenticated, adminWorkspace]);

  useEffect(() => {
    if (!selectedMonitoringAppId) {
      return;
    }
    loadMonitoringApplicationDetails(selectedMonitoringAppId);
    loadRagDocs();
  }, [selectedMonitoringAppId]);

  useEffect(() => {
    if (!selectedMonitoringAppId || adminWorkspace !== "monitoring") {
      return;
    }
    if (typeof window === "undefined") {
      return;
    }
    window.requestAnimationFrame(() => {
      monitoringInspectRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [selectedMonitoringAppId, adminWorkspace]);

  useEffect(() => {
    if (activeTab !== "admin" || adminWorkspace !== "alerts") {
      return;
    }
    if (typeof window === "undefined") {
      return;
    }
    window.requestAnimationFrame(() => {
      alertKnowledgeRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [activeTab, adminWorkspace]);

  useEffect(() => {
    if (onboardingProjectMode === "new" || selectedOnboardingProject || !onboardingProjectOptions.length) {
      return;
    }
    const firstProjectName = onboardingProjectRowOptions[0] || onboardingProjectOptions[0];
    const firstProjectRow = (onboardingState.rows || []).find((row) => extractOnboardingProjectName(row) === firstProjectName);
    if (firstProjectRow) {
      applyProjectOnboardingRow(firstProjectRow);
      return;
    }
    setSelectedOnboardingProject(firstProjectName);
    setOnboardingForm((curr) => ({
      ...curr,
      name: firstProjectName,
      assignment_project: firstProjectName,
    }));
  }, [onboardingProjectMode, selectedOnboardingProject, onboardingProjectOptions, onboardingProjectRowOptions, onboardingState.rows]);

  useEffect(() => {
    if (!isAuthenticated) {
      return;
    }
    if (allowedTabs.includes(activeTab)) {
      return;
    }
    setActiveTab(allowedTabs[0] || "approval");
  }, [isAuthenticated, allowedTabs, activeTab]);

  function openSection(tabId) {
    if (!allowedTabs.includes(tabId)) {
      return;
    }
    setActiveTab(tabId);
  }

  function openNavigationItem(item) {
    if (!allowedTabs.includes(item.legacyTab)) {
      return;
    }
    if (typeof onNavigatePath === "function") {
      skipNextActiveTabNavigationRef.current = true;
      setActiveTab(item.legacyTab);
      onNavigatePath(item.path);
      return;
    }
    setActiveTab(item.legacyTab);
  }

  function applyIngestionSavedView(viewId) {
    const view = INGESTION_SAVED_VIEWS.find((candidate) => candidate.id === viewId) || INGESTION_SAVED_VIEWS[0];
    setIngestionStreamView(view.id);
    setIngestionStreamSection(view.section);
    setIngestionStreamChannel(view.channel);
    setIngestionStreamFilters(view.filters);
  }

  function openCopilotWorkspace(workspace) {
    if (workspace === "users" && !isAdministrator) {
      return;
    }
    if (workspace === "users") {
      setAdminWorkspace("users");
      onNavigatePath?.("/admin");
    } else if (workspace === "monitoring") {
      setAdminWorkspace("project");
      onNavigatePath?.("/integrations");
    } else if (workspace === "project") {
      setAdminWorkspace("project");
      onNavigatePath?.("/integrations");
    } else if (workspace === "alerts") {
      setAdminWorkspace("alerts");
      setAlertKnowledgeView("onboarding");
      onNavigatePath?.("/applications?workspace=knowledge");
    }
    setActiveTab("admin");
  }

  const reportConfig = useMemo(() => {
    const config = {
      home: {
        title: "Dashboard",
        caption: "Operational dashboard with alert stream and incident overview.",
        metrics: [
          ["Recent Alerts", monitorScopedAlerts.length],
          ["Flows", flows.rows.length],
          ["Gateway Events", gatewayRecent.rows.length],
          ["Health", health.ok ? "OK" : "CHECK"],
        ],
        refresh: refreshAll,
      },
      copilot: {
        title: "Copilot Studio",
        caption: "Guided workspace for project onboarding, alert docs, and user management.",
        metrics: [
          ["Projects", onboardingState.rows.length],
          ["Alert Docs", ragDocs.rows.length],
          ["Users", adminUsers.rows.length],
          ["Ready", health.ok ? "Yes" : "Check"],
        ],
        refresh: refreshAll,
      },
      executive: {
        title: "Executive Dashboard",
        caption: "Leadership KPIs for reliability posture, risk, and closure outcomes.",
        metrics: [
          ["Open Alerts", monitorScopedAlerts.length],
          [
            "Critical Open",
            monitorScopedAlerts.filter((row) => String(row?.severity || "").toLowerCase() === "critical").length,
          ],
          ["Closed Incidents", closedIncidents.rows.length],
          ["Health Restored", closedIncidents.rows.filter((row) => row?.health_restored === true).length],
          ["SLA At Risk", executiveInsights.slaAtRisk],
          ["Avg Approval Wait", `${executiveInsights.avgApprovalWaitMinutes.toFixed(1)} min`],
          ["Auto Remediation Rate", `${executiveInsights.automationRate.toFixed(1)}%`],
          ["LLM Cost (USD)", executiveMetrics.finopsCost.toFixed(6)],
        ],
        refresh: refreshAll,
      },
      admin: {
        title: "Admin Center",
        caption: "Administrative controls, system health, and approval operations.",
        metrics: [
          ["Pending Approvals", pendingApprovals.length],
          ["Gateway", health.ok ? "Healthy" : "Check"],
          ["Metadata Rows", incidentMetadata.rows.length],
          ["Monitoring Target", selectedMonitorScopeLabel],
        ],
        refresh: async () => {
          await Promise.all([checkHealth(), loadIncidentMetadata(), loadGatewaySummary(), loadGatewayRecent()]);
        },
      },
      summary: {
        title: "Incident Metadata Explorer",
        caption: "Filter the incident projection layer across policy, transport, and operational dimensions.",
        metrics: [
          ["Incidents", incidentMetadata.rows.length],
          ["Human Approval", pendingApprovals.length],
          ["Closed", closedIncidents.rows.length],
          ["Monitoring", selectedMonitorScopeLabel],
        ],
        refresh: loadIncidentMetadata,
      },
      approval: {
        title: "Human Approval & Alerts",
        caption: "Pending approvals, live incident feed, and quick guidance workspace.",
        metrics: [
          ["Recent Alerts", monitorScopedAlerts.length],
          ["Pending", pendingApprovals.length],
          ["Guidance Matches", guidanceState.rows.length],
          ["Last Incident", latestIncidentId || "-"],
        ],
        refresh: async () => {
          await Promise.all([loadIncidentMetadata(), loadGatewayRecent(), loadGatewaySummary()]);
        },
      },
      trace: {
        title: "Agent Flow",
        caption: "Agent execution timeline, decisions, outputs, and handoffs.",
        metrics: [
          ["Workflow Events", workflowEventRows.length],
          ["Gateway Events", gatewayRecent.rows.length],
          ["Latest Incident", latestIncidentId || "-"],
          ["Latest Flow", selectedFlow || "-"],
        ],
        refresh: async () => {
          await Promise.all([loadGatewayRecent(), loadGatewaySummary()]);
        },
      },
      finops: {
        title: "LLM FinOps",
        caption: "Token usage, provider costs, and model-level breakdown.",
        metrics: [
          ["LLM Calls", allUsageRows.length],
          [
            "Total Cost (USD)",
            allUsageRows
              .reduce((sum, row) => sum + Number(row?.total_cost_usd || 0), 0)
              .toFixed(6),
          ],
          ["Providers", new Set(allUsageRows.map((row) => row.provider).filter(Boolean)).size],
          ["Models", new Set(allUsageRows.map((row) => row.model).filter(Boolean)).size],
        ],
        refresh: async () => {
          await Promise.all([loadIncidentMetadata(), loadGatewaySummary(), loadGatewayRecent(), loadClosedIncidents(), loadRecentAlerts()]);
        },
      },
      rag: {
        title: "Message Bus",
        caption: "Configured routing plus latest observed published versus consumed topics.",
        metrics: [
          ["Published Topics", messageBusActual.published.length],
          ["Consumed Topics", messageBusActual.consumed.length],
          ["Observed Provider", observedRouting?.message_bus_provider || "N/A"],
          ["Workflow", observedRouting?.workflow || "N/A"],
        ],
        refresh: () => runWorkflow(selectedFlow),
      },
      safety: {
        title: "Gateway Safety",
        caption: "Review gateway decision, policy reasons, and safety metrics before closure.",
        metrics: [
          ["Events", gatewaySummary.data.total_events || 0],
          ["Allowed", gatewaySummary.data.allowed || 0],
          ["Review", gatewaySummary.data.review || 0],
          ["Blocked", gatewaySummary.data.blocked || 0],
        ],
        refresh: async () => {
          await Promise.all([loadGatewaySummary(), loadGatewayRecent()]);
        },
      },
      closed: {
        title: "Closed Tickets",
        caption: "Closed tickets plus current closure report details.",
        metrics: [
          ["Closed", closedIncidents.rows.length],
          [
            "Health Restored",
            closedIncidents.rows.filter((row) => row?.health_restored === true).length,
          ],
          ["Monitoring", selectedMonitorScopeLabel],
          ["Gateway", health.ok ? "OK" : "CHECK"],
        ],
        refresh: loadClosedIncidents,
      },
    };

    return config[activeTab] || config.home;
  }, [
    activeTab,
    monitorScopedAlerts.length,
    flows.rows.length,
    gatewayRecent.rows,
    health.ok,
    monitorScopedIncidentMetadata.length,
    pendingApprovals.length,
    guidanceState.rows.length,
    closedIncidents.rows,
    applicationToMonitor,
    selectedMonitorScopeLabel,
    latestIncidentId,
    latestRecommendationId,
    approvalForm.action,
    workflowEventRows.length,
    selectedFlow,
    allUsageRows,
    messageBusActual,
    observedRouting,
    gatewaySummary.data,
    executiveMetrics.finopsCost,
    executiveInsights.slaAtRisk,
    executiveInsights.avgApprovalWaitMinutes,
    executiveInsights.automationRate,
  ]);

  const workflowGuide = useMemo(() => {
    const unresolvedAlerts = monitorScopedAlerts.filter((row) => !isApprovalResolvedStatus(row?.status || row?.state));
    const agentNames = new Set(
      (selectedAlertEventsDisplay || []).map((row) => String(row?.agent || "").trim().toLowerCase()).filter(Boolean),
    );
    const resolutionSeen = Array.from(agentNames).some((name) => name.includes("resolution intelligence") || name.includes("resolution-agent"));
    const remediationSeen = Array.from(agentNames).some((name) => name.includes("remediation automation") || name.includes("remediation-engine"));

    const cards = [
      {
        id: "alerts",
        label: "Alert Intake",
        status: unresolvedAlerts.length ? "active" : "idle",
        detail: unresolvedAlerts.length
          ? `${unresolvedAlerts.length} open alerts ready for triage.`
          : "No open alerts in the current monitoring scope.",
      },
      {
        id: "approval",
        label: "Approval Queue",
        status: pendingApprovals.length ? "attention" : "clear",
        detail: pendingApprovals.length
          ? `${pendingApprovals.length} incidents are waiting for a user decision.`
          : "No incidents are waiting for human approval.",
      },
      {
        id: "resolution",
        label: "Resolution Intelligence",
        status: resolutionSeen ? "active" : "attention",
        detail: resolutionSeen
          ? "Root-cause and recommendation evidence found for selected alert."
          : "No resolution trace detected for selected alert yet.",
      },
      {
        id: "remediation",
        label: "Remediation Automation",
        status: remediationSeen ? "active" : "attention",
        detail: remediationSeen
          ? "Remediation execution trace detected in agent timeline."
          : "No remediation execution trace detected yet.",
      },
    ];

    let nextAction = "Open an alert row to inspect timeline, then route to approval if required.";
    if (!unresolvedAlerts.length) {
      nextAction = "Generate or ingest a fresh alert to validate the end-to-end agent workflow.";
    } else if (pendingApprovals.length) {
      nextAction = "Use Human Approval to approve or reject pending recommendations and unblock remediation.";
    } else if (!resolutionSeen) {
      nextAction = "Inspect Cockpit and review Evidence or Timeline for Resolution Intelligence output.";
    } else if (!remediationSeen) {
      nextAction = "Approve the recommendation or verify auto-execution policy to trigger remediation.";
    }

    return { cards, nextAction };
  }, [monitorScopedAlerts, pendingApprovals.length, selectedAlertEventsDisplay]);

  const roleDashboard = useMemo(() => {
    const openAlerts = monitorScopedAlerts.filter((row) => !isApprovalResolvedStatus(row?.status || row?.state));
    const priorityIncidents = monitorScopedIncidentMetadata.filter((row) => ["critical", "high"].includes(String(row?.severity || row?.risk_tier || row?.risk || "").toLowerCase()));
    const failedAutomation = selectedAlertEventsDisplay.filter((row) => [row?.status, row?.detail, row?.message].some((value) => /failed|error/i.test(String(value || "")))).length;
    const connectorRows = (Array.isArray(monitoringApps.rows) ? monitoringApps.rows : []).filter((row) => {
      const name = String(row?.name || row?.application || "").trim().toLowerCase();
      return !applicationToMonitor || name === String(applicationToMonitor).trim().toLowerCase();
    });
    const unhealthyConnectors = connectorRows.filter((row) => /failed|error|unhealthy|disabled/i.test(String(row?.status || ""))).length;
    const hasScopedAlertSelection = Boolean(selectedAlertRow);
    const isManagedPlatformScope = ["kaims", "telemetry"].includes(String(applicationToMonitor || "").trim().toLowerCase());
    const shared = {
      period: "Current operational window",
      timezone: "Asia/Kolkata (IST)",
      partial: Boolean(alerts.error || incidentMetadata.error || approvalState.error || monitoringApps.error),
      refreshing: Boolean(alerts.loading || incidentMetadata.loading || approvalState.loading || monitoringApps.loading),
    };
    if (currentRole === "executive") {
      return { ...shared, kind: "Executive", title: "Business reliability attention", description: "Service health, response speed, automation, and impact for the current window.", cards: [
        { label: "Service Health", value: health.ok ? "Healthy" : "Check", detail: "API gateway health probe status.", tone: health.ok ? "clear" : "attention", tab: "executive" },
        { label: "MTTA", value: `${executiveInsights.avgApprovalWaitMinutes.toFixed(1)} min`, detail: "Proxy: mean current approval wait; dedicated acknowledgement timestamps are not available.", tone: "info", tab: "executive" },
        { label: "MTTR", value: "Partial", detail: "Closure durations are incomplete in the current response contract.", tone: "attention", tab: "closed" },
        { label: "Automation Rate", value: `${executiveInsights.automationRate.toFixed(1)}%`, detail: "Automatically executed closures / all closed incidents.", tone: "clear", tab: "executive" },
        { label: "Business Impact", value: executiveInsights.slaAtRisk, detail: "Open high-risk or manual-mode incidents currently at SLA risk.", tone: executiveInsights.slaAtRisk ? "attention" : "clear", tab: "summary" },
      ] };
    }
    if (["l2_engineer", "l3_engineer"].includes(currentRole)) {
      return { ...shared, kind: "Approver", title: "Decisions requiring review", description: "Pending gates with risk, evidence, and execution readiness.", cards: [
        { label: "Pending Approvals", value: pendingApprovals.length, detail: "Approval records whose status is not resolved.", tone: pendingApprovals.length ? "attention" : "clear", tab: "approval" },
        { label: "High-Risk Incidents", value: priorityIncidents.length, detail: "Open incident projections classified high or critical.", tone: priorityIncidents.length ? "attention" : "clear", tab: "summary" },
        { label: "Planned Commands", value: selectedExecutionBreakdown.commands.length, detail: "Guarded execution commands for the selected incident.", tone: "info", tab: "home" },
        { label: "Rollback Readiness", value: selectedExecutionBreakdown.scripts.length ? "Review" : "Missing", detail: "A script exists for review; explicit rollback metadata is not available.", tone: selectedExecutionBreakdown.scripts.length ? "info" : "attention", tab: "home" },
        { label: "Approval SLA", value: `${executiveInsights.avgApprovalWaitMinutes.toFixed(1)} min`, detail: "Mean age of pending approval records.", tone: "info", tab: "approval" },
      ] };
    }
    if (currentRole === "administrator") {
      return { ...shared, kind: "Administrator", title: `${selectedMonitorScopeLabel} operations`, description: "Application health and activity, with platform-wide infrastructure clearly identified.", cards: [
        { label: "Application Connector", value: isManagedPlatformScope && !connectorRows.length ? "Managed" : !connectorRows.length ? "Not configured" : unhealthyConnectors ? "Attention" : "Healthy", detail: isManagedPlatformScope && !connectorRows.length ? `${selectedMonitorScopeLabel} uses KaiMS-managed platform monitoring; no separate onboarding record is required.` : !connectorRows.length ? `${selectedMonitorScopeLabel} has no registered monitoring connector.` : `${connectorRows.length} connector record(s) scoped to ${selectedMonitorScopeLabel}; ${unhealthyConnectors} unhealthy.`, tone: isManagedPlatformScope && !connectorRows.length ? "info" : !connectorRows.length || unhealthyConnectors ? "attention" : "clear", tab: "admin" },
        { label: "Queue Health", value: queueHealth.loading ? "Checking" : queueHealth.healthy ? "Healthy" : queueHealth.status === "attention" ? "Attention" : "Unavailable", detail: queueHealth.loading ? "Reading live broker telemetry." : `${String(queueHealth.provider || "rabbitmq").toUpperCase()} · ${queueHealth.queues || 0} queues · ${queueHealth.ready || 0} ready · ${queueHealth.unacknowledged || 0} in flight.`, tone: queueHealth.healthy ? "clear" : "attention", tab: "rag" },
        { label: "Selected Incident Activity", value: hasScopedAlertSelection ? selectedAlertEventsDisplay.length : "No selection", detail: hasScopedAlertSelection ? `Persisted agent or trace events for the selected ${selectedMonitorScopeLabel} incident.` : `Open a ${selectedMonitorScopeLabel} alert to inspect agent activity.`, tone: hasScopedAlertSelection && selectedAlertEventsDisplay.length ? "clear" : "info", tab: "trace" },
        { label: "Selected Workflow", value: !hasScopedAlertSelection ? "No selection" : failedAutomation ? `${failedAutomation} failed` : "No failures", detail: hasScopedAlertSelection ? "Failure state for the selected in-scope incident workflow." : "Workflow status is shown only after an in-scope alert is selected.", tone: failedAutomation ? "attention" : "info", tab: "trace" },
        { label: "Telemetry", value: gatewayRecent.rows.length, detail: "API gateway telemetry events in the current loaded window.", tone: gatewayRecent.rows.length ? "info" : "attention", tab: "safety" },
      ] };
    }
    return { ...shared, kind: "Operator", title: "What requires attention now?", description: "Active signals, priority incidents, failed automation, and SLA risk.", cards: [
      { label: "Active Alerts", value: openAlerts.length, detail: "Current alerts not in a resolved or closed state.", tone: openAlerts.length ? "attention" : "clear", tab: "stream" },
      { label: "Priority Incidents", value: priorityIncidents.length, detail: "Open high or critical incident projections.", tone: priorityIncidents.length ? "attention" : "clear", tab: "summary" },
      { label: "Failed Automation", value: failedAutomation, detail: "Selected workflow events reporting failed or error state.", tone: failedAutomation ? "attention" : "clear", tab: "home" },
      { label: "Assigned Work", value: "Partial", detail: "Assignment data is not exposed by the current dashboard contract.", tone: "info", tab: "home" },
      { label: "SLA Risks", value: executiveInsights.slaAtRisk, detail: "Open high-risk or manual-mode incidents.", tone: executiveInsights.slaAtRisk ? "attention" : "clear", tab: "home" },
    ] };
  }, [alerts.error, alerts.loading, approvalState.error, approvalState.loading, applicationToMonitor, currentRole, executiveInsights, gatewayRecent.rows.length, health.ok, incidentMetadata.error, incidentMetadata.loading, monitorScopedAlerts, monitorScopedIncidentMetadata, monitoringApps.error, monitoringApps.loading, monitoringApps.rows, pendingApprovals.length, queueHealth, selectedAlertEventsDisplay, selectedAlertRow, selectedExecutionBreakdown.commands.length, selectedExecutionBreakdown.scripts.length, selectedMonitorScopeLabel]);



  if (adminSession.loading || authConfig.loading) return <main className="app-route-loading" aria-busy="true">Restoring authenticated session…</main>;
  if (!isAuthenticated) {
    return (
      <main className={`app-shell auth-shell density-${uiDensity}`}>
        <section className="auth-stage">
          <aside className="auth-brand-story">
            <KaiMSBrand inverse />
            <div className="auth-story-copy">
              <span className="auth-kicker auth-kicker-live"><i aria-hidden="true" /> Autonomous operations workspace</span>
              <h1>From first signal to <em>verified recovery.</em></h1>
              <p>KaiMS connects evidence, human judgment, and guarded action in one accountable incident workflow.</p>
              <div className="auth-signal-chain" aria-label="KaiMS operating model">
                <span><b>01</b><strong>Observe</strong><small>Unify operational signals</small></span>
                <i aria-hidden="true">→</i>
                <span><b>02</b><strong>Understand</strong><small>Explain cause and impact</small></span>
                <i aria-hidden="true">→</i>
                <span><b>03</b><strong>Resolve</strong><small>Act safely and verify</small></span>
              </div>
              <div className="auth-live-assurance"><i aria-hidden="true" /><span><strong>Operations fabric online</strong><small>Evidence, approvals, and recovery controls connected</small></span></div>
            </div>
            <div className="auth-proof-grid" aria-label="KaiMS platform capabilities">
              <span><strong>Evidence first</strong><small>Every conclusion retains its source</small></span>
              <span><strong>Human governed</strong><small>Operators stay in control of action</small></span>
              <span><strong>Recovery verified</strong><small>Closure follows measured health</small></span>
            </div>
          </aside>
          <article className="panel auth-card">
            <div className="auth-card-toolbar">
              <KaiMSBrand compact />
              <div className="auth-theme-switch" role="group" aria-label="Login theme">
                {[
                  ["auto", "Auto"],
                  ["light", "Light"],
                  ["dark", "Dark"],
                ].map(([value, label]) => (
                  <button
                    key={value}
                    type="button"
                    className={uiTheme === value ? "active" : ""}
                    aria-pressed={uiTheme === value}
                    onClick={() => setUiTheme(value)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
            <div className="panel-head">
              <div>
                <span className="auth-kicker">Protected access</span>
                <h2>Welcome back</h2>
                <p>Sign in to your operational command center.</p>
              </div>
            </div>
            <label className="auth-application-select"><span>Application workspace</span><select aria-label="Application workspace" value={applicationToMonitor} onChange={(event) => setApplicationToMonitor(event.target.value)} disabled={!monitorApplications.length}>{!monitorApplications.length ? <option value="">No onboarded projects available</option> : null}{monitorApplications.map((name) => <option key={name} value={name}>{name}</option>)}</select><small>{monitorApplications.length ? "Your session opens scoped to this onboarded application." : "Sign in to configure an application workspace. Your account permissions still apply."}</small></label>
            {authConfig.mode === "oidc" ? (
              <div className="form auth-login-form">
                <p className="auth-sso-note">Enterprise single sign-on is required. Your identity-provider role controls KaiMS access.</p>
                <button className="button-primary auth-submit" type="button" onClick={oidcLogin} disabled={adminSession.loading || authConfig.loading}>{adminSession.loading ? "Redirecting..." : <><span>Continue with SSO</span><b aria-hidden="true">→</b></>}</button>
              </div>
            ) : (
              <form className="form auth-login-form" onSubmit={adminLogin}>
                <div className="auth-access-mode"><span><i aria-hidden="true" /> Secure local access</span><small>Development environment</small></div>
                <label className="auth-field"><span>Username</span><div className="auth-input-frame"><b aria-hidden="true">@</b><input autoComplete="username" value={adminAuthForm.username} onChange={(e) => setAdminAuthForm((curr) => ({ ...curr, username: e.target.value }))} /></div></label>
                <label className="auth-field"><span>Password</span><div className="auth-input-frame"><b className="auth-lock-mark" aria-hidden="true" /><input type={loginPasswordVisible ? "text" : "password"} autoComplete="current-password" value={adminAuthForm.password} onChange={(e) => setAdminAuthForm((curr) => ({ ...curr, password: e.target.value }))} /><button type="button" className="auth-password-toggle" aria-label={loginPasswordVisible ? "Conceal entered value" : "Reveal entered value"} aria-pressed={loginPasswordVisible} onClick={() => setLoginPasswordVisible((visible) => !visible)}>{loginPasswordVisible ? "Hide" : "Show"}</button></div></label>
                <div className="auth-session-meta"><span><i aria-hidden="true" /> Encrypted session</span><span>Role-scoped access</span></div>
                <button className="button-primary auth-submit" type="submit" aria-label="Sign In" disabled={adminSession.loading}>{adminSession.loading ? <><i className="auth-submit-spinner" aria-hidden="true" /> Signing in...</> : <><span>Sign in securely</span><b aria-hidden="true">→</b></>}</button>
              </form>
            )}
            {adminSession.error ? <p className="error auth-login-error" role="alert">{adminSession.error}</p> : null}
            {authConfig.error ? <p className="error auth-login-error" role="alert">{authConfig.error}</p> : null}
            <div className="auth-security-note"><span aria-hidden="true">✓</span><div><strong>Accountable by design</strong><small>{authConfig.mode === "local" ? "Local access is enabled for this development environment." : "Session tokens remain in memory and are never written to local storage."}</small></div></div>
            <p className="auth-role-note">Your navigation, decisions, and available actions adapt automatically to your assigned role.</p>
          </article>
        </section>
      </main>
    );
  }

  return (
    <div className={`app-shell density-${uiDensity} ${routeOutlet ? "app-shell-routed" : ""}`}>
      <a className="skip-link" href="#workspace-content">Skip to workspace content</a>
      {!isBrowserOnline ? (
        <aside className="connectivity-banner" role="alert" aria-live="assertive">
          <div><strong>Connection lost</strong><span>Live updates are paused. Existing information remains visible and may be stale.</span></div>
          <button type="button" className="button-secondary" onClick={() => { if (navigator.onLine) { setIsBrowserOnline(true); refreshAll(); } }}>Retry connection</button>
        </aside>
      ) : null}
      <KaiOperationsShell
        navigationGroups={navigationGroups}
        currentItem={currentNavigationItem}
        currentPath={currentPath}
        role={currentRole}
        onNavigate={openNavigationItem}
        projects={monitorApplications}
        project={applicationToMonitor}
        onProjectChange={setApplicationToMonitor}
        environment={selectedApplicationConnection.environment}
        health={health}
        aiCapability={aiCapabilityStatus}
        autonomyMode={selectedAlertRouting?.execution_mode || observedRouting?.execution_mode || ""}
        approvalCount={pendingApprovals.length}
        notificationCount={globalOperationalData.notifications.length}
        operationalQuery={globalOperationsQuery}
        onOperationalQueryChange={setGlobalOperationsQuery}
        operationalResults={globalOperationalData.results}
        notifications={globalOperationalData.notifications}
        onOpenOperationalItem={openGlobalOperationalItem}
        onOpenNotifications={() => { setGlobalOperationsView("notifications"); setGlobalOperationsOpen(true); }}
        onAskKai={() => setIsCopilotOpen(true)}
        user={adminSession?.user}
        density={uiDensity}
        theme={uiTheme}
        onDensityChange={setUiDensity}
        onThemeChange={setUiTheme}
        onLogout={adminLogout}
        kaiStates={kaiStateSummary}
        restrictedDestination={restrictedDestination}
      >
      <div className={`app-layout kai-legacy-frame ${routeOutlet ? "kai-routed-frame" : ""}`}>
        {null}

        <section className="content-area" id="legacy-workspace-content" tabIndex={-1}>
          {/* KaiOperationsShell (the wrapping topbar) already renders this page's breadcrumb,
              title, health badge, user menu with logout, command palette, and Ask Kai action.
              Render the legacy hero header only when no modern shell is wrapping this view
              (e.g. an unrouted/storybook mount), so routed sessions don't show it twice. */}
          {null}

          <details className="global-operations-bar panel" aria-label="Global operational capabilities">
            <summary className="global-operations-summary"><span>Search &amp; personal work</span><small>Find records, assignments, and notifications</small></summary>
            <div className="global-operations-body">
            <div className="global-operations-tabs" role="tablist" aria-label="Global operations">
              {[['search', 'Search'], ['work', `My Work (${globalOperationalData.myWork.length})`], ['notifications', `Notifications (${globalOperationalData.notifications.length})`]].map(([id, label]) => (
                <button key={id} type="button" role="tab" aria-selected={globalOperationsView === id} className={globalOperationsView === id ? "active" : ""} onClick={() => setGlobalOperationsView(id)}>{label}</button>
              ))}
            </div>
            {globalOperationsView === "search" ? <div className="global-search-workspace">
              <label><span>Global search</span><input type="search" value={globalOperationsQuery} onChange={(event) => setGlobalOperationsQuery(event.target.value)} placeholder="Alert, incident, application, service, or ticket ID" /></label>
              {globalOperationsQuery ? <div className="global-operations-results" role="list" aria-label="Global search results">
                {globalOperationalData.results.length ? globalOperationalData.results.map((item, index) => <button type="button" role="listitem" key={`${item.kind}-${item.label}-${index}`} onClick={() => openGlobalOperationalItem(item)}><strong>{item.kind}: {item.label}</strong><span>{item.meta}</span></button>) : <p>No matching loaded operational records.</p>}
              </div> : <p className="subtitle">Searches currently loaded, role-authorized operational records.</p>}
            </div> : null}
            {globalOperationsView === "work" ? <div className="global-work-list">
              {globalOperationalData.myWork.length ? globalOperationalData.myWork.slice(0, 12).map((item, index) => <button type="button" key={`${item.kind}-${item.label}-${index}`} onClick={() => openGlobalOperationalItem(item)}><span className="workflow-pill workflow-pill-idle">{item.kind}</span><strong>{item.label}</strong><small>{item.meta}</small></button>) : <p>No assigned incidents, pending approvals, or failed actions in the loaded scope.</p>}
              <aside className="unsupported-collaboration"><strong>Collaboration unavailable</strong><span>Notes, mentions, and watchers need an authenticated backend collaboration contract. No local-only success is shown.</span><button type="button" disabled title="Backend collaboration API is not available">Add note / watcher unavailable</button></aside>
            </div> : null}
            {globalOperationsView === "notifications" ? <div className="global-notification-workspace">
              <p className="subtitle">Operational signals derived from current alerts and incidents; this is not a delivery receipt inbox.</p>
              <div className="global-work-list">{globalOperationalData.notifications.length ? globalOperationalData.notifications.map((item, index) => <button type="button" key={`${item.kind}-${item.label}-${index}`} onClick={() => openGlobalOperationalItem(item)}><span className="workflow-pill workflow-pill-idle">{item.kind}</span><strong>{item.label}</strong><small>{item.meta}</small></button>) : <p>No current operational signals.</p>}</div>
              <aside className="unsupported-collaboration"><strong>Delivery preferences unavailable</strong><span>Severity/application subscriptions, email, Slack/Teams, quiet hours, maintenance windows, grouping, and reminder preferences need durable per-user backend contracts.</span><button type="button" disabled title="Notification preference API is not available">Configure delivery unavailable</button></aside>
            </div> : null}
            </div>
          </details>

          {null}

          <RouteRuntimeProvider value={{
            session: { accessToken: String(adminSession.accessToken || ""), username: String(adminSession?.user?.username || "operator") },
            dashboard: {
              processing: queueHealth,
              role: roleDashboard,
              allowedTabs,
              projects: monitoringApps.rows || [],
              observedProjects: monitorApplications,
              selectedProject: String(applicationToMonitor || ""),
              workflow: workflowGuide,
              openSection,
              refreshProjects: async () => {
                await Promise.all([
                  queryClient.invalidateQueries({ queryKey: ["route-api"], refetchType: "none" }),
                  queryClient.invalidateQueries({ queryKey: ["alerts"], refetchType: "none" }),
                ]);
                await Promise.allSettled([
                  loadMonitorApplications(), loadMonitoringApplications(), checkQueueHealth(),
                  loadIncidentMetadata({ ignoreFilters: true, limit: 100 }), loadRecentAlerts(),
                  loadClosedIncidents(), loadGatewaySummary(), loadGatewayRecent(),
                ]);
              },
              selectProject: setApplicationToMonitor,
            },
            copilot: {
              isAdministrator,
              role: currentRole,
              projectCount: onboardingState.rows.length,
              alertDocumentCount: ragDocs.rows.length,
              userCount: adminUsers.rows.length,
              platformReady: health.ok,
              openWorkspace: openCopilotWorkspace,
              openIncidentMetadata: () => {
                setActiveTab("summary");
                onNavigatePath?.("/incidents");
              },
              refresh: refreshAll,
            },
            closed: {
              rows: filteredClosedRows,
              risk: closedFilters.risk,
              mode: closedFilters.mode,
              riskOptions: closedRiskOptions,
              modeOptions: closedModeOptions,
              loading: closedIncidents.loading,
              error: closedIncidents.error || "",
              refresh: loadClosedIncidents,
              hasMore: closedIncidents.nextOffset != null,
              loadMore: () => loadClosedIncidents({ append: true }),
              setRisk: (risk) => setClosedFilters((current) => ({ ...current, risk })),
              setMode: (mode) => setClosedFilters((current) => ({ ...current, mode })),
            },
            agentFlow: {
              workflowRows: workflowEventRows,
              gatewayRows: gatewayRecent.rows,
              gatewayLoading: gatewayRecent.loading,
              gatewayError: gatewayRecent.error || "",
              workflowResult: workflowState.result,
            },
            safety: {
              summary: gatewaySummary.data,
              summaryError: gatewaySummary.error || "",
              events: gatewayRecent.rows,
              landingRows: landingPadRecent.rows,
              landingError: landingPadRecent.error || "",
              refresh: () => { loadGatewaySummary(); loadGatewayRecent(); loadLandingPadRecent(); },
            },
            knowledge: {
              actual: messageBusActual,
              configuredRows: messageBusTopicRows,
              routing: observedRouting,
              primaryTopic: onboardingForm.azure_service_bus_topic,
              application: applicationToMonitor,
              providers: selectedModelProviderRows,
              providersLoading: modelProviderStatus.loading,
              providersError: modelProviderStatus.error || "",
              refreshProviders: loadModelProviderStatus,
              refresh: () => Promise.allSettled([
                loadGatewayRecent(),
                selectedAlertId
                  ? loadAlertDetails(selectedAlertId, selectedAlertRow, { background: true })
                  : loadRecentAlerts({ background: true }),
              ]),
            },
            incidents: {
              // Keep the inbox aligned with the same production/test and
              // application scope used by Live Alerts.
              rows: monitorScopedIncidentMetadata,
              page: incidentMetadata.page || {},
              loading: incidentMetadata.loading,
              error: incidentMetadata.error || "",
              application: applicationToMonitor,
              filters: metadataFilters,
              refresh: loadIncidentMetadata,
              loadPage: (cursor = "") => loadIncidentMetadata({ cursor, limit: 10 }),
              updateFilter: (name, value) => setMetadataFilters((current) => ({ ...current, [name]: value })),
              open: (row) => openAlertDetailsFromIncident(row, "rca"),
              openTechnical: (row) => openAlertDetailsFromIncident(row, "rca"),
            },
            alerts: {
              loading: landingPadRecent.loading,
              error: landingPadRecent.error || "",
              paused: ingestionStreamPaused,
              liveState: liveEvents.state,
              lastEventAt: liveEvents.lastEventAt,
              rows: visibleIngestionStreamRows, inboxRows: applicationScopedIngestionStreamRows,
              totalRows: applicationScopedIngestionStreamRows.length,
              project: selectedMonitorScopeLabel,
              updatedAt: ingestionStreamUpdatedAt,
              section: ingestionStreamSection,
              view: ingestionStreamView,
              savedViews: INGESTION_SAVED_VIEWS,
              filters: ingestionStreamFilters,
              filterOptions: ingestionFilterOptions,
              density: uiDensity,
              counts: ingestionStreamCounts,
              channel: ingestionStreamChannel,
              query: ingestionStreamQuery,
              refresh: () => { loadRecentAlerts({ background: true }); loadLandingPadRecent(); },
              open: openAlertDetails,
              openIncident: (row) => openAlertDetailsFromIncident(row, "rca"),
              togglePaused: () => setIngestionStreamPaused((current) => !current),
              setSection: setIngestionStreamSection,
              setView: setIngestionStreamView,
              applyView: applyIngestionSavedView,
              updateFilter: (name, value) => setIngestionStreamFilters((current) => ({ ...current, [name]: value })),
              setDensity: setUiDensity,
              setChannel: setIngestionStreamChannel,
              setQuery: setIngestionStreamQuery,
            },
            executive: {
              statCards: [
                { label: "Open Alerts", value: monitorScopedAlerts.length },
                { label: "Total Requests", value: executiveMetrics.totalRequests },
                { label: "Failures", value: executiveMetrics.failedRequests },
                { label: "P95 Latency", value: `${executiveMetrics.p95LatencyMs.toFixed(1)} ms` },
                { label: "Closed Tickets", value: executiveClosedSummary.total },
                { label: "Closure Rate", value: `${executiveClosedSummary.closureRate.toFixed(1)}%` },
                { label: "Pending Approvals", value: pendingApprovals.length },
                { label: "SLA At Risk", value: executiveInsights.slaAtRisk },
                { label: "Avg Approval Wait", value: `${executiveInsights.avgApprovalWaitMinutes.toFixed(1)} min` },
                { label: "Auto Remediation", value: `${executiveInsights.automationRate.toFixed(1)}%` },
                { label: "LLM Cost", value: `$${executiveMetrics.finopsCost.toFixed(6)}` },
              ],
              requestChart: [{ label: "Total", value: executiveMetrics.totalRequests, tone: "meta" }, { label: "Success", value: executiveMetrics.successRequests, tone: "ops" }, { label: "Failure", value: executiveMetrics.failedRequests, tone: "risk" }],
              successRequests: executiveMetrics.successRequests,
              failedRequests: executiveMetrics.failedRequests,
              latencyChart: executiveMetrics.latencyTrend,
              latencySubtitle: `Avg ${executiveMetrics.avgLatencyMs.toFixed(1)} ms | P95 ${executiveMetrics.p95LatencyMs.toFixed(1)} ms`,
              finopsChart: [{ label: "Model Calls", value: executiveMetrics.finopsCalls, tone: "meta" }, { label: "Tokens", value: executiveMetrics.finopsTokens, tone: "cost" }, { label: "Cost USD", value: executiveMetrics.finopsCost, displayValue: `$${executiveMetrics.finopsCost.toFixed(6)}`, tone: "bus" }],
              riskChart: executiveClosedSummary.riskItems,
              modeChart: executiveClosedSummary.modeItems,
              weeklyOpenChart: executiveInsights.weeklyOpenTrend,
              weeklyClosedChart: executiveInsights.weeklyClosedTrend,
              workflowStages: selectedWorkflowFlowStages,
              serviceFlow: SERVICE_TOPIC_FLOW,
              finopsRows: finopsByProvider,
              slaAtRisk: executiveInsights.slaAtRisk,
              approvalWaitMinutes: executiveInsights.avgApprovalWaitMinutes,
              automationRate: executiveInsights.automationRate,
              incidents: monitorScopedIncidentMetadata,
              recentlyClosed: executiveClosedSummary.recentRows,
              application: applicationToMonitor,
              openIncident: (row) => openAlertDetailsFromIncident(row, "rca"),
            },
            approvals: {
              guidanceQuery,
              guidanceRows: guidanceState.rows,
              guidanceLoading: guidanceState.loading,
              guidanceError: guidanceState.error || "",
              filter: approvalFilter,
              rows: filteredPendingApprovals,
              selectedIncidentId: selectedApprovalIncidentId,
              selectedRecommendationId: selectedApprovalRecommendationId,
              selectedFlowContext: selectedApprovalFlowContext,
              latestIncidentId,
              contextLoading: approvalIncidentContext.loading,
              contextError: approvalIncidentContext.error || "",
              contextPayload: approvalIncidentContext.incident_id === selectedApprovalIncidentId
                ? approvalIncidentContext.payload
                : null,
              showAdvanced: showAdvancedApprovalForm,
              form: approvalForm,
              ready: approvalReady,
              actionLoading: approvalState.loading,
              actionError: approvalState.error || "",
              actionResult: approvalState.result,
              inlineReject: inlineRejectState,
              setGuidanceQuery,
              searchGuidance: searchGuidanceDocs,
              setFilter: setApprovalFilter,
              incidentId: approvalIncidentId,
              recommendationId: approvalRecommendationId,
              select: selectApprovalIncident,
              open: openAlertDetailsFromIncident,
              approve: (row) => approveIncidentRow(row, "dry_run"),
              approveDryRun: (row) => approveIncidentRow(row, "dry_run"),
              approveExecution: (row) => approveIncidentRow(row, "execution"),
              requestEvidence: requestMoreEvidence,
              toggleReject: (incidentId) => { setApprovalState({ loading: false, result: null, error: "" }); setInlineRejectState((current) => current.incidentId === incidentId ? { incidentId: "", comment: "" } : { incidentId, comment: "" }); },
              setRejectComment: (incidentId, comment) => setInlineRejectState({ incidentId, comment }),
              reject: rejectIncidentRow,
              refresh: () => loadIncidentMetadata({ background: true, ignoreFilters: true }),
              openIncidents: () => setActiveTab("summary"),
              openAgentFlow: () => setActiveTab("trace"),
              sync: () => selectedApprovalIncidentId && loadApprovalIncidentContext(selectedApprovalIncidentId, { force: true }),
              toggleAdvanced: () => setShowAdvancedApprovalForm((current) => !current),
              updateForm: (name, value) => setApprovalForm((current) => ({ ...current, [name]: value })),
              submit: submitApproval,
            },
            admin: {
              sessionUser: adminSession.user,
              sessionError: adminSession.error || "",
              authenticated: Boolean(adminSession.accessToken),
              users: adminUsers.rows,
              roles: adminRoles,
              loading: adminUsers.loading,
              error: adminUsers.error || "",
              createForm: adminCreateUser,
              editForm: adminEditUser,
              resetUserId: adminResetPasswordForm.user_id,
              resetPassword: adminResetPasswordForm.new_password,
              refresh: loadAdminUsersAndRoles,
              selectUser: selectAdminUserForEdit,
              updateCreate: (name, value) => setAdminCreateUser((current) => ({ ...current, [name]: value })),
              updateEdit: (name, value) => setAdminEditUser((current) => ({ ...current, [name]: value })),
              setResetPassword: (new_password) => setAdminResetPasswordForm((current) => ({ ...current, new_password })),
              create: createAdminUser,
              update: updateAdminUser,
              reset: resetAdminUserPassword,
            },
          }}>
            <div className={`workspace-with-copilot ${isCopilotOpen ? "copilot-open" : ""}`}>
              <div className="workspace-main-content">
                {currentSearch.includes("workspace=alert") ? null : routeOutlet}
                {activeTab === "home" && (!routeOutlet || currentSearch.includes("workspace=alert")) ? (
                  <section className={`grid single-col ${routeOutlet ? "legacy-dashboard-cockpit" : ""}`}>
                    <article className={`panel role-dashboard role-dashboard-${roleDashboard.kind.toLowerCase()}`}>
                <div className="panel-head role-dashboard-header">
                  <div>
                    <span className="discovery-eyebrow">{roleDashboard.kind} dashboard</span>
                    <h2>{roleDashboard.title}</h2>
                    <p>{roleDashboard.description}</p>
                  </div>
                  <div className="role-dashboard-window">
                    <span>{roleDashboard.period}</span>
                    <strong>{roleDashboard.timezone}</strong>
                    <span className={`workflow-pill ${roleDashboard.partial ? "workflow-pill-idle" : roleDashboard.refreshing ? "workflow-pill-active" : "workflow-pill-clear"}`}>
                      {roleDashboard.partial ? "partial data" : roleDashboard.refreshing ? "refreshing" : "current data"}
                    </span>
                  </div>
                </div>
                <div className="role-dashboard-grid">
                  {roleDashboard.cards.map((card) => {
                    const accessible = allowedTabs.includes(card.tab);
                    return <article className={`role-attention-card is-${card.tone}`} key={`${roleDashboard.kind}-${card.label}`}>
                      <span>{card.label}</span>
                      <strong>{card.value}</strong>
                      <p>{card.detail}</p>
                      <button type="button" className="button-secondary" disabled={!accessible} title={accessible ? `Open ${card.label}` : "This destination is not available to your role"} onClick={() => accessible && openSection(card.tab)}>View records</button>
                    </article>;
                  })}
                </div>
                <details className="role-dashboard-definitions">
                  <summary>Metric definitions and data quality</summary>
                  <ul>{roleDashboard.cards.map((card) => <li key={`definition-${card.label}`}><strong>{card.label}:</strong> {card.detail}</li>)}</ul>
                  <p>Counts distinguish currently loaded alerts, incident projections, approval records, workflow events, and closures. They are not interchangeable totals.</p>
                </details>
              </article>
              <article className="panel workflow-guide-panel">
                <div className="panel-head">
                  <h2>Workflow Health & Next Action</h2>
                </div>
                <p className="subtitle">Fast status across intake, resolution, approval, and remediation.</p>
                <div className="workflow-guide-grid">
                  {workflowGuide.cards.map((card) => (
                    <div className="workflow-guide-card" key={card.id}>
                      <strong>{card.label}</strong>
                      <span className={`workflow-pill workflow-pill-${card.status}`}>{card.status.toUpperCase()}</span>
                      <p>{card.detail}</p>
                    </div>
                  ))}
                </div>
                <p className="scope-note">Recommended next step: {workflowGuide.nextAction}</p>
              </article>

              <article className="panel">
                <div className="panel-head">
                  <h2>Alert Stream</h2>
                  <label className="alerts-limit-select">
                    Show
                    <select
                      value={alertsLimit}
                      disabled={alerts.loading}
                      onChange={(event) => setAlertsLimit(Number(event.target.value))}
                    >
                      <option value={25}>25</option>
                      <option value={50}>50</option>
                      <option value={100}>100</option>
                      {/* Fetch is hard-capped at 200 (sourceBalancedFetchLimit
                          in loadRecentAlerts) regardless of this selection —
                          don't offer a value the backend call can't honor. */}
                      <option value={200}>200</option>
                    </select>
                    alerts
                  </label>
                  <button className="button-secondary" onClick={loadRecentAlerts} disabled={alerts.loading}>
                    {alerts.loading ? "Loading..." : "Refresh"}
                  </button>
                </div>
                {alerts.error ? <p className="error">{alerts.error}</p> : null}
                {alertSeverityOverrides.error ? <p className="error">{alertSeverityOverrides.error}</p> : null}
                <div className="dashboard-alert-toolbar">
                  <div className="dashboard-alert-focus" role="group" aria-label="Alert triage focus">
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "ops" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("ops")}>Ops {dashboardAlertSummary.ops}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "all" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("all")}>All {dashboardAlertSummary.total}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "critical" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("critical")}>Critical {dashboardAlertSummary.critical}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "high" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("high")}>High {dashboardAlertSummary.high}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "awaiting" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("awaiting")}>Awaiting {dashboardAlertSummary.awaiting}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "active" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("active")}>Active {dashboardAlertSummary.active}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "closed" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("closed")}>Closed {dashboardAlertSummary.closed}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "test" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("test")}>Test {dashboardAlertSummary.test}</button>
                  </div>
                  <div className="dashboard-alert-search">
                    <input
                      value={dashboardAlertQuery}
                      onChange={(event) => setDashboardAlertQuery(event.target.value)}
                      placeholder="Search alert name, service, app, id"
                    />
                    {dashboardAlertQuery ? (
                      <button type="button" className="button-secondary" onClick={() => setDashboardAlertQuery("")}>Clear</button>
                    ) : null}
                  </div>
                </div>
                <p className="subtitle">
                  Showing {dashboardVisibleAlerts.length} of {visibleAlerts.length} alerts for {selectedMonitorScopeLabel}.
                  {dashboardAlertSource !== "all" ? ` Source filter: ${sourceChannelLabel(dashboardAlertSource)}.` : ""}
                  {dashboardAlertFocus === "ops" && dashboardAlertSummary.test > 0 ? ` ${dashboardAlertSummary.test} smoke/stress alerts are hidden in Ops view.` : ""}
                  {monitorScopedRecentClosedAlerts.length > 0 ? ` Includes ${monitorScopedRecentClosedAlerts.length} recent closed incident(s).` : ""}
                </p>
                <div className="alert-source-breakdown" role="group" aria-label="Filter dashboard alerts by source">
                  {[
                    ["all", "All", visibleAlerts.length],
                    ["prometheus", "Prometheus", visibleAlertSourceSummary.prometheus],
                    ["telemetry", "Telemetry", visibleAlertSourceSummary.telemetry],
                    ["email", "Email", visibleAlertSourceSummary.email],
                    ["ticket", "Ticket", visibleAlertSourceSummary.ticket],
                    ["log", "Logs", visibleAlertSourceSummary.log],
                  ].map(([channel, label, count]) => (
                    <button
                      type="button"
                      key={`dashboard-source-${channel}`}
                      className={`source-badge source-filter source-${channel} ${dashboardAlertSource === channel ? "is-active" : ""}`}
                      onClick={() => setDashboardAlertSource((current) => current === channel && channel !== "all" ? "all" : channel)}
                      aria-pressed={dashboardAlertSource === channel}
                    >
                      {label} {count}
                    </button>
                  ))}
                </div>
                {canManageSeverityOverride ? (
                  <p className="subtitle">L2/L3/Admin can set future severity overrides by alert name + service + environment.</p>
                ) : null}
                <AlertStreamTable
                  rows={dashboardVisibleAlerts}
                  loading={alerts.loading}
                  selectedAlertId={selectedAlertId}
                  onSelectAlert={openAlertDetails}
                  scopeLabel={selectedMonitorScopeLabel}
                />
              </article>

              {null}

              {docPromptAlert && canProvideAlertDocuments ? (
                <article className="panel document-prompt-dialog" role="dialog" aria-modal="true" aria-labelledby="document-prompt-title" ref={docPromptRef}>
                  <div className="panel-head">
                    <h3 id="document-prompt-title">Provide Documents</h3>
                    <button type="button" className="button-secondary" onClick={closeDocumentPrompt}>Close</button>
                  </div>
                  <p className="subtitle">
                    Configure documentation for alert{" "}
                    <strong>{String(docPromptAlert.name || docPromptAlert.alert_name || docPromptAlert.alert_id || docPromptAlert.id || "-")}</strong>.
                    All document types are available as tabs below.
                  </p>
                  <div className="detail-tabs sticky-controls" style={{ marginBottom: 10 }}>
                    {ALERT_DOC_KIND_OPTIONS.map((kind) => {
                      const existing = docPromptDocsByKind[kind];
                      const selected = docPromptKind === kind;
                      const label = existing?.path ? `${kind} *` : kind;
                      return (
                        <button
                          key={`doc-kind-${kind}`}
                          type="button"
                          className={selected ? "button-primary" : "button-secondary"}
                          onClick={() => setDocPromptDraftForKind(docPromptAlert, kind)}
                        >
                          {label}
                        </button>
                      );
                    })}
                  </div>
                  <div className="filter-grid">
                    <label>
                      Mode
                      <select value={docPromptMode} onChange={(e) => setDocPromptMode(e.target.value)}>
                        <option value="create">Create New</option>
                        <option value="update" disabled={!docPromptExistingDoc?.path}>Update Existing</option>
                      </select>
                    </label>
                    <div style={{ display: "flex", alignItems: "end", gap: 8 }}>
                      <button
                        type="button"
                        className="button-secondary"
                        onClick={async () => {
                          const draft = await buildAlertDocumentDraftWithAnalysis(docPromptAlert, docPromptKind);
                          setAlertOnboarding((curr) => ({
                            ...curr,
                            kind: draft.kind,
                            title: draft.title,
                            summary: draft.summary,
                            content: draft.content,
                            services: draft.services,
                            severity: draft.severity,
                            alert_type: draft.alert_type,
                            alert_id: draft.alert_id,
                            execution_plan: String(draft.execution_plan || "").trim(),
                            remediation_commands_text: Array.isArray(draft.commands) ? draft.commands.join("\n") : "",
                            remediation_scripts_text: Array.isArray(draft.scripts) ? draft.scripts.join("\n") : "",
                            remediation_queries_text: Array.isArray(draft.queries) ? draft.queries.join("\n") : "",
                          }));
                        }}
                        disabled={alertOnboardingState.loading}
                      >
                        Re-Analyze Alert
                      </button>
                      <button
                        type="button"
                        className="button-secondary"
                        onClick={() => autoCreateAlertDocument(docPromptAlert, docPromptKind)}
                        disabled={alertOnboardingState.loading}
                      >
                        Create Selected Doc
                      </button>
                      <button
                        type="button"
                        className="button-secondary"
                        onClick={() => autoCreateAllAlertDocuments(docPromptAlert)}
                        disabled={alertOnboardingState.loading}
                      >
                        Create All Docs
                      </button>
                    </div>
                  </div>
                  {docPromptExistingDoc?.path ? <p className="subtitle">Existing document: {docPromptExistingDoc.path}</p> : null}
                  <form className="form" onSubmit={submitAlertOnboarding}>
                    <div className="filter-grid">
                      <label>Kind
                        <select value={alertOnboarding.kind} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, kind: e.target.value }))}>
                          <option value="incident">incident</option>
                          <option value="runbook">runbook</option>
                          <option value="deployment">deployment</option>
                          <option value="change">change</option>
                          <option value="dependency">dependency</option>
                          <option value="remediation">remediation</option>
                        </select>
                      </label>
                      <label>Title<input value={alertOnboarding.title} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, title: e.target.value }))} /></label>
                      <label>Severity<select value={alertOnboarding.severity} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, severity: e.target.value }))}><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option></select></label>
                    </div>
                    <label>Services (comma separated)<input value={alertOnboarding.services} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, services: e.target.value }))} /></label>
                    <label>Summary<textarea rows={2} value={alertOnboarding.summary} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, summary: e.target.value }))} /></label>
                    <label>Content<textarea rows={5} value={alertOnboarding.content} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, content: e.target.value }))} /></label>
                    {String(alertOnboarding.kind || "").trim().toLowerCase() === "remediation" ? (
                      <>
                        <div style={{ display: "flex", alignItems: "end", gap: 8 }}>
                          <button
                            type="button"
                            className="button-secondary"
                            onClick={() => autoGenerateRemediationPlan(docPromptAlert)}
                            disabled={alertOnboardingState.loading}
                          >
                            Auto-Generate Commands/Scripts/Queries
                          </button>
                        </div>
                        <label>Execution Plan<textarea rows={4} value={alertOnboarding.execution_plan} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, execution_plan: e.target.value }))} /></label>
                        <div className="filter-grid">
                          <label>Additional Commands<textarea rows={5} value={alertOnboarding.remediation_commands_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_commands_text: e.target.value }))} /></label>
                          <label>Single Remediation Script<textarea rows={5} value={alertOnboarding.remediation_scripts_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_scripts_text: e.target.value }))} /></label>
                          <label>Additional Validation Queries<textarea rows={5} value={alertOnboarding.remediation_queries_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_queries_text: e.target.value }))} /></label>
                        </div>
                      </>
                    ) : null}
                    <button className="button-primary" type="submit" disabled={alertOnboardingState.loading}>
                      {alertOnboardingState.loading ? "Saving..." : docPromptMode === "update" && docPromptExistingDoc?.path ? "Update Document" : "Upload Document"}
                    </button>
                  </form>
                  {alertOnboardingState.error ? <p className="error">{alertOnboardingState.error}</p> : null}
                  {alertOnboardingState.result ? <p className="subtitle">{alertOnboardingState.result?.message || "Document saved."}</p> : null}

                  <article className="panel" style={{ marginTop: 10 }}>
                    <div className="panel-head">
                      <h3>Add Rule From Alert</h3>
                    </div>
                    <p className="subtitle">Use plain language like earlier flow; the system generates and stores a rule workflow.</p>
                    <div className="filter-grid">
                      <label>
                        Monitoring Platform
                        <select value={alertRuleDraft.platform} onChange={(e) => setAlertRuleDraft((curr) => ({ ...curr, platform: e.target.value }))}>
                          <option value="prometheus">prometheus</option>
                          <option value="new_relic">new_relic</option>
                          <option value="datadog">datadog</option>
                        </select>
                      </label>
                    </div>
                    <label>
                      Rule Requirement (Plain English)
                      <textarea rows={3} value={alertRuleDraft.requirement} onChange={(e) => setAlertRuleDraft((curr) => ({ ...curr, requirement: e.target.value }))} />
                    </label>
                    <button type="button" className="button-primary" onClick={addRuleFromAlertPrompt} disabled={alertRuleState.loading}>
                      {alertRuleState.loading ? "Creating Rule..." : "Add Rule"}
                    </button>
                    {alertRuleState.error ? <p className="error">{alertRuleState.error}</p> : null}
                    {alertRuleState.result?.workflow_id ? <p className="subtitle">Rule workflow created: {alertRuleState.result.workflow_id}</p> : null}
                  </article>
                </article>
              ) : null}

              {selectedAlertRow ? (
                <article className="panel alert-details-cockpit" ref={alertDetailsRef} tabIndex={-1}>
                  <div className="panel-head incident-sticky-header">
                    <div>
                      <span className="discovery-eyebrow">Guided Incident Cockpit</span>
                      <h2>Incident Response</h2>
                      <h3>{selectedAlertRow?.service || "Incident"}: {selectedAlertRow?.name || selectedAlertRow?.alert_name || "Alert investigation"}</h3>
                      <p>Work one guided path from combined evidence, RCA, and impact through execution and verified recovery. Current task: <strong>{incidentCockpitStages.find((stage) => stage.id === homeDetailTab)?.label || "Investigate"}</strong>. Recommended next: <strong>{cockpitRecommended.label}</strong>.</p>
                    </div>
                    <div className="incident-record-navigation" aria-label="Incident record navigation">
                      <button type="button" className="button-secondary" disabled={!selectedAlertNavigation.previous} onClick={() => {
                        if (selectedAlertNavigation.previous) {
                          const section = homeDetailTab;
                          openAlertDetails(selectedAlertNavigation.previous);
                          setHomeDetailTab(section);
                        }
                      }}>Previous</button>
                      <span>{selectedAlertNavigation.index >= 0 ? selectedAlertNavigation.index + 1 : "-"} of {selectedAlertNavigation.total}</span>
                      <button type="button" className="button-secondary" disabled={!selectedAlertNavigation.next} onClick={() => {
                        if (selectedAlertNavigation.next) {
                          const section = homeDetailTab;
                          openAlertDetails(selectedAlertNavigation.next);
                          setHomeDetailTab(section);
                        }
                      }}>Next</button>
                    </div>
                  </div>
                  <div className="detail-context">
                    <span><strong>ID:</strong> {selectedAlertId}</span>
                    <span><strong>Service:</strong> {selectedAlertRow?.service || "-"}</span>
                    <span><strong>Severity:</strong> {String(selectedAlertRow?.severity || "-").toUpperCase()}</span>
                    <span>
                      <strong>Status:</strong>{" "}
                      <span className={`pill ${statusPillClass(selectedCanonicalIncidentStatus)}`}>
                        {incidentStatusLabel(selectedCanonicalIncidentStatus)}
                      </span>
                    </span>
                  </div>

                  {(() => {
                    const matchedApproval = selectedMatchedApproval;
                    const incidentId = approvalIncidentId(matchedApproval)
                      || selectedAlertWorkflow?.incident?.id
                      || selectedAlertWorkflow?.incident_id
                      || "";
                    const approvalStatus = selectedApprovalStatus;
                    const isResolved = isApprovalResolvedStatus(approvalStatus);
                    const requiresApproval = Boolean(
                      matchedApproval
                      || selectedExecutionPlan?.requiresApproval
                      || selectedAlertRouting?.requires_approval
                      || selectedAlertWorkflow?.approval?.required
                      || selectedAlertWorkflow?.decision?.requires_approval
                      || isApprovalPendingStatus(approvalStatus)
                    );
                    const approvalInvestigationReady = Boolean(
                      selectedAiTrust.contractValid === true
                      && selectedAiTrust.integrityVerified === true
                      && selectedAiTrust.executionReady === true
                      && selectedExecutionPlan?.catalogPlan?.execution_ready === true
                    );
                    const hasUnresolvedApproval = Boolean(matchedApproval && !isResolved);
                    const hasActionableApproval = Boolean(hasUnresolvedApproval && approvalInvestigationReady);
                    const approvalBlocked = Boolean(hasUnresolvedApproval && !approvalInvestigationReady);

                    if (!requiresApproval) {
                      return null;
                    }

                    return (
                      <section className={`incident-decision-strip ${hasActionableApproval ? "is-actionable" : ""}`} aria-label="Incident decision gate">
                        <div className="incident-decision-copy">
                          <span className="discovery-eyebrow">{hasActionableApproval ? "Decision required" : approvalBlocked ? "Decision blocked" : "Decision status"}</span>
                          <strong>{hasActionableApproval ? "Manual approval is ready for review" : approvalBlocked ? "Approval is blocked until investigation is ready" : matchedApproval ? `Approval ${approvalStatus || "resolved"}` : "No active approval is linked"}</strong>
                          <small>
                            {hasActionableApproval
                              ? "Review the proposed change and safety evidence in Resolve. Approval applies to this exact plan."
                              : approvalBlocked
                                ? "The linked approval is retained for audit, but this investigation contract or execution plan is not currently eligible for approval. Run fresh analysis and review the replacement plan."
                              : `Incident ${incidentId || "-"} is ${incidentStatusLabel(selectedCanonicalIncidentStatus).toLowerCase()}.`}
                          </small>
                        </div>
                        <div className="incident-decision-state">
                          <span className={`pill ${statusPillClass(selectedCanonicalIncidentStatus)}`}>{incidentStatusLabel(selectedCanonicalIncidentStatus)}</span>
                          <span className="pill pill-info">Approval: {approvalBlocked ? "blocked" : approvalStatus || (hasActionableApproval ? "pending" : "not active")}</span>
                        </div>
                        {hasActionableApproval ? (
                          <div className="incident-decision-actions">
                          <button
                            type="button"
                            className="button-secondary"
                            onClick={() => {
                              const matched = selectApprovalFromAlertRow(selectedAlertRow);
                              if (matched) {
                              setActiveTab("approval");
                              }
                            }}
                          >
                            Open Queue
                          </button>
                          <button
                            type="button"
                            className="button-primary"
                            onClick={() => setHomeDetailTab("execution")}
                          >
                            Review and approve
                          </button>
                          </div>
                        ) : null}
                      </section>
                    );
                  })()}

                  <div className="detail-tabs incident-section-navigation cockpit-stage-navigation" role="tablist" aria-label="Incident workspace sections">
                    {incidentCockpitStages.map((stage) => (
                      <button
                        key={`detail-${stage.id}`}
                        type="button"
                        className={`detail-tab ${homeDetailTab === stage.id ? "active" : ""} ${stage.complete ? "is-complete" : ""} ${cockpitRecommendedStage === stage.id ? "is-recommended" : ""}`}
                        onClick={() => setHomeDetailTab(stage.id)}
                        role="tab"
                        aria-selected={homeDetailTab === stage.id}
                        aria-label={stage.accessibleLabel || stage.label}
                      >
                        <span>{stage.complete ? <CircleCheckBig size={14} strokeWidth={2.5} aria-hidden="true" /> : stage.short}</span>
                        <strong>{stage.label}</strong>
                        <small>{stage.description}</small>
                      </button>
                    ))}
                  </div>


                  {selectedAlertData.loading ? <p className="subtitle">Loading selected alert details...</p> : null}
                  {selectedAlertData.error ? <p className="error">{selectedAlertData.error}</p> : null}
                  {selectedAlertRegeneration.error ? <p className="error" role="alert">{selectedAlertRegeneration.error}</p> : null}
                  {selectedAlertRegeneration.message ? <p className="subtitle">{selectedAlertRegeneration.message}</p> : null}

                  {homeDetailTab === "evidence" ? (
                    <>
                    <RcaPanel
                      rcaDetailView={rcaDetailView}
                      onSetRcaDetailView={setRcaDetailView}
                      onSetHomeDetailTab={setHomeDetailTab}
                      selectedAlertTimelineRows={selectedAlertTimelineRows}
                      selectedAlertRagDocuments={selectedAlertRagDocuments}
                      selectedAlertEvaluation={selectedAlertEvaluation}
                      selectedAlertRow={selectedAlertRow}
                      selectedRcaDecision={selectedRcaDecision}
                      selectedAiTrust={selectedAiTrust}
                      selectedAlertWorkflow={selectedAlertWorkflow}
                      selectedAlertRegeneration={selectedAlertRegeneration}
                      selectedAlertRecommendationId={selectedAlertRecommendationId}
                      selectedAlertDocumentContract={selectedAlertDocumentContract}
                      selectedAlertId={selectedAlertId}
                      aiFeedbackState={aiFeedbackState}
                      rcaAnalysisMode={rcaAnalysisMode}
                      onSetRcaAnalysisMode={setRcaAnalysisMode}
                      onRerunRca={regenerateSelectedAlertAnalysis}
                      onRefreshSelectedAlert={() => loadAlertDetails(selectedAlertId, selectedAlertRow, { background: true })}
                      onDownloadRagDocument={downloadRagDocument}
                      onLoadRagDocumentContent={loadRagDocumentContent}
                      onSubmitAiRecommendationFeedback={submitAiRecommendationFeedback}
                    /></>
                  ) : null}

                  {homeDetailTab === "overview" ? (
                    <>
                      <header className="incident-workspace-hero" id="incident-workspace-overview">
                        <div>
                          <span className="discovery-eyebrow">Unified response cockpit</span>
                          <h3>Incident Workspace</h3>
                          <p>Follow the incident, verify the evidence, make the decision, and execute recovery without switching tabs.</p>
                        </div>
                        <div className="incident-workspace-kpis">
                          <span><strong>{incidentStatusLabel(selectedCanonicalIncidentStatus)}</strong> lifecycle</span>
                          <span><strong>{selectedAlertTimelineRows.length}</strong> events</span>
                          <span><strong>{selectedAiTrust.evidence.filter((row) => row.accepted).length}</strong> RCA-supporting evidence</span>
                          <span className={Number(selectedRcaDecision.confidence || 0) < 0.5 ? "is-quality-warning" : ""}><strong>{formatQualityPercent(selectedRcaDecision.confidence)}</strong> {selectedRcaDecision.confidenceLabel}</span>
                        </div>
                      </header>
                      <details className="panel incident-workspace-section workspace-collapsible" open>
                      <summary className="panel-head">
                        <div>
                          <span className="workspace-section-number">01</span>
                          <h3>Incident Overview</h3>
                          <p>Alert identity, status, root cause, quality metrics, and stage completeness.</p>
                        </div>
                        <span className="section-toggle-indicator" />
                      </summary>
                      <div className="table-wrap table-wrap-scroll-x incident-overview-table">
                        <table>
                          <tbody>
                            <tr><th>Alert</th><td>{selectedAlertRow?.name || selectedAlertWorkflow?.alert?.name || "-"}</td></tr>
                            <tr><th>Details Source</th><td>{selectedAlertDetailsSource}</td></tr>
                            <tr><th>Incident</th><td>{selectedAlertWorkflow?.incident?.id || selectedAlertWorkflow?.incident_id || "-"}</td></tr>
                            <tr>
                              <th>Persisted Incident Status</th>
                              <td>
                                <span className={`pill ${statusPillClass(selectedCanonicalIncidentStatus)}`}>
                                  {incidentStatusLabel(selectedCanonicalIncidentStatus)}
                                </span>
                              </td>
                            </tr>
                            <tr>
                               <th>Jira Ticket</th>
                               <td>
                                 {(selectedAlertWorkflow?.incident?.ticket_id || selectedAlertWorkflow?.ticket_id) ? (
                                   <a
                                     href={selectedAlertWorkflow?.incident?.jira_link || selectedAlertWorkflow?.jira_link || `https://kaiops-test.atlassian.net/browse/${selectedAlertWorkflow?.incident?.ticket_id || selectedAlertWorkflow?.ticket_id}`}
                                     target="_blank"
                                     rel="noopener noreferrer"
                                     style={{ color: "#22d3ee", textDecoration: "underline", fontWeight: "bold" }}
                                   >
                                     {selectedAlertWorkflow?.incident?.ticket_id || selectedAlertWorkflow?.ticket_id}
                                   </a>
                                 ) : (
                                   "-"
                                 )}
                               </td>
                             </tr>
                             <tr>
                               <th>Jira Status</th>
                               <td>
                                 {(selectedAlertWorkflow?.incident?.ticket_id || selectedAlertWorkflow?.ticket_id) ? (
                                   <span className={`pill ${(selectedAlertWorkflow?.incident?.jira_status || selectedAlertWorkflow?.jira_status) === "Done" ? "status-success" : "status-warning"}`}>
                                     {selectedAlertWorkflow?.incident?.jira_status || selectedAlertWorkflow?.jira_status || "In Progress"}
                                   </span>
                                 ) : (
                                   "-"
                                 )}
                               </td>
                             </tr>
                            <tr><th>Closed At</th><td>{formatIstTimestamp(selectedAlertWorkflow?.incident?.closed_at)}</td></tr>
                            <tr><th>Service</th><td>{selectedAlertRow?.service || selectedAlertWorkflow?.alert?.service || "-"}</td></tr>
                            <tr><th>Analysis Status</th><td>{canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow).status}</td></tr>
                            <tr><th>Root Cause</th><td>{canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow).rootCause}</td></tr>
                            <tr><th>Recommended Action</th><td>{canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow).action}</td></tr>
                            <tr><th>Impact</th><td>{canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow).impact}</td></tr>
                            <tr><th>External Knowledge</th><td>{canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow).externalKnowledgeStatus}</td></tr>
                          </tbody>
                        </table>
                      </div>

                      <h3>AI Evaluation Metrics</h3>
                      <div className="alert-rule-summary-grid">
                        <article className="alert-rule-summary-card">
                          <span>Overall Quality</span>
                          <strong>{selectedAiTrust.evidence.length ? formatQualityPercent(selectedAlertEvaluation.overallScore) : "Unavailable"}</strong>
                          <small>{selectedAiTrust.evidence.length ? selectedAlertEvaluation.available ? `${selectedAlertEvaluation.qualityLabel} | ${selectedAlertEvaluation.provider}` : "No recorded evaluation" : "No linked evidence"}</small>
                        </article>
                        <article className="alert-rule-summary-card">
                          <span>{selectedAiTrust.confidenceLabel}</span>
                          <strong>{selectedAiTrust.evidence.length ? formatQualityPercent(selectedRcaDecision.confidence) : "Unavailable"}</strong>
                          <small>{selectedAiTrust.confidenceActionable ? "Confirmed and evidence-grounded" : "Diagnostic score; not execution permission"}</small>
                        </article>
                        <article className="alert-rule-summary-card">
                          <span>Grounding</span>
                          <strong>{formatQualityPercent(selectedAlertEvaluation.groundingScore)}</strong>
                          <small>Evidence and context support</small>
                        </article>
                        <article className="alert-rule-summary-card">
                          <span>Hallucination Risk</span>
                          <strong>{formatQualityPercent(selectedAlertEvaluation.hallucinationRisk)}</strong>
                          <small>{selectedAlertEvaluation.requiresReview ? "review recommended" : "within guardrail"}</small>
                        </article>
                        <article className="alert-rule-summary-card">
                          <span>Citation Coverage</span>
                          <strong>{formatQualityPercent(selectedAlertEvaluation.citationCoverage)}</strong>
                          <small>{selectedAlertEvaluation.signals?.citations ?? "-"} citation(s)</small>
                        </article>
                        <article className="alert-rule-summary-card">
                          <span>Evidence Coverage</span>
                          <strong>{formatQualityPercent(selectedAlertEvaluation.evidenceCoverage)}</strong>
                          <small>{selectedAlertEvaluation.signals?.rag_matches ?? selectedAlertRagDocuments.length} RAG match(es)</small>
                        </article>
                      </div>

                      {selectedAlertDocumentContract ? (
                        <>
                          <h3>Enterprise Controls</h3>
                          <div className="alert-rule-summary-grid">
                            <article className="alert-rule-summary-card">
                              <span>Canonical Contract</span>
                              <strong>{selectedAlertDocumentContract.canonical_alert?.schema_version || "-"}</strong>
                              <small>{selectedAlertDocumentContract.canonical_alert?.alert_uid || selectedAlertId}</small>
                            </article>
                            <article className="alert-rule-summary-card">
                              <span>Governance</span>
                              <strong>{selectedAlertDocumentContract.governance?.agent_contract_version || "-"}</strong>
                              <small>Approval gate: {selectedAlertDocumentContract.governance?.approval_gate_required ? "required" : "not required"}</small>
                            </article>
                            <article className="alert-rule-summary-card">
                              <span>RBAC</span>
                              <strong>{selectedAlertDocumentContract.rbac?.risk_tier || "-"}</strong>
                              <small>Tenant: {selectedAlertDocumentContract.rbac?.tenant || "default"} | Env: {selectedAlertDocumentContract.rbac?.environment || "-"}</small>
                            </article>
                            <article className="alert-rule-summary-card">
                              <span>Trace Quality</span>
                              <strong>{selectedAlertDocumentContract.observability?.trace_id || "-"}</strong>
                              <small>{selectedAlertDocumentContract.observability?.quality_gate || "-"}</small>
                            </article>
                            <article className="alert-rule-summary-card">
                              <span>RAG Quality</span>
                              <strong>{selectedAlertDocumentContract.rag_quality?.contract_version || "-"}</strong>
                              <small>Linked docs: {selectedAlertDocumentContract.document_link_summary?.count ?? 0}</small>
                            </article>
                            <article className="alert-rule-summary-card">
                              <span>Remediation Safety</span>
                              <strong>{selectedAlertDocumentContract.remediation_safety?.contract_version || "-"}</strong>
                              <small>Execution safeguards: {selectedAlertDocumentContract.remediation_safety?.dry_run_required ? "enabled" : "standard"}</small>
                            </article>
                          </div>
                        </>
                      ) : null}

                      <h3>Persisted Stage Completeness</h3>
                      <p className="subtitle">A stage is complete only when durable event or relational evidence confirms it. Pending work is never counted as completed.</p>
                      {selectedStageCompleteness.loading ? <p className="subtitle">Loading stage completeness...</p> : null}
                      {selectedStageCompleteness.error ? <p className="error">{selectedStageCompleteness.error}</p> : null}
                      {selectedStageCompleteness.data ? (
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>Stage</th>
                                <th>Status</th>
                                <th>Persisted evidence</th>
                                <th>Required next action</th>
                              </tr>
                            </thead>
                            <tbody>
                              {(selectedStageCompleteness.data?.stages || []).map((row, index) => (
                                <tr key={`stage-${row.stage || index}`}>
                                  <td>{row.label || row.stage || "-"}</td>
                                  <td><span className={`stage-state stage-state-${row.state || (row.persisted ? "complete" : "waiting")}`}>{row.state === "in_progress" ? "In progress" : row.persisted ? "Complete" : "Waiting"}</span></td>
                                  <td>{Array.isArray(row.evidence_sources) && row.evidence_sources.length ? row.evidence_sources.join(" · ") : Array.isArray(row.matched_event_types) && row.matched_event_types.length ? row.matched_event_types.join(" · ") : "No durable evidence yet"}</td>
                                  <td>{row.next_action || (row.persisted ? "Completed." : "Complete the preceding workflow stage.")}</td>
                                </tr>
                              ))}
                              {!Array.isArray(selectedStageCompleteness.data?.stages) || !selectedStageCompleteness.data.stages.length ? (
                                <tr><td colSpan={4}>No persisted stage rows found for incident.</td></tr>
                              ) : null}
                            </tbody>
                          </table>
                        </div>
                      ) : null}

                      {selectedStageCompleteness.data ? (
                        <div className="stage-completion-summary">
                          <progress max={selectedStageCompleteness.data?.stage_completion?.total || 1} value={selectedStageCompleteness.data?.stage_completion?.completed || 0} />
                          <p className="subtitle">
                          Completion: {selectedStageCompleteness.data?.stage_completion?.completed ?? 0}/{selectedStageCompleteness.data?.stage_completion?.total ?? 0}
                          {" "}({selectedStageCompleteness.data?.stage_completion?.percentage ?? 0}%)
                          </p>
                        </div>
                      ) : null}
                      </details>
                    </>
                  ) : null}

                  {homeDetailTab === "evidence" ? (
                    <details className="panel incident-workspace-section workspace-collapsible evidence-workspace">
                      <summary className="panel-head">
                        <div>
                          <span className="workspace-section-number">02</span>
                          <h3>Evidence & Trust</h3>
                          <p>Canonical identity, traceability, linked knowledge, and evaluation quality.</p>
                        </div>
                        <span className="section-toggle-indicator" />
                      </summary>
                      <div className="table-wrap table-wrap-scroll-x">
                        <table>
                          <tbody>
                            <tr><th>Canonical Alert UID</th><td>{selectedAlertDocumentContract?.canonical_alert?.alert_uid || selectedAlertId || "-"}</td></tr>
                            <tr><th>Alert Type</th><td>{selectedAlertDocumentContract?.canonical_alert?.alert_type || selectedAlertRow?.name || "-"}</td></tr>
                            <tr><th>Service</th><td>{selectedAlertDocumentContract?.canonical_alert?.service || selectedAlertRow?.service || "-"}</td></tr>
                            <tr><th>Tenant / Environment</th><td>{selectedAlertDocumentContract?.canonical_alert?.tenant || "default"} / {selectedAlertDocumentContract?.canonical_alert?.environment || selectedAlertRow?.environment || "-"}</td></tr>
                            <tr><th>Trace ID</th><td>{selectedAlertDocumentContract?.observability?.trace_id || selectedAlertRow?.trace_id || "-"}</td></tr>
                            <tr><th>Correlation ID</th><td>{selectedAlertDocumentContract?.canonical_alert?.correlation_id || selectedAlertRow?.correlation_id || "-"}</td></tr>
                            <tr><th>Document Link Contract</th><td>{selectedAlertDocumentContract?.document_link_summary?.contract_version || "-"}</td></tr>
                            <tr><th>Linked Document Count</th><td>{selectedAlertRagDocuments.length}</td></tr>
                            <tr><th>Evaluation Contract</th><td>{selectedAlertEvaluation.contractVersion}</td></tr>
                            <tr><th>Overall Evaluation</th><td>{formatQualityPercent(selectedAlertEvaluation.overallScore)} ({selectedAlertEvaluation.qualityLabel})</td></tr>
                            <tr><th>Confidence Score</th><td>{formatQualityPercent(selectedAlertEvaluation.confidenceScore)}</td></tr>
                            <tr><th>Grounding Score</th><td>{formatQualityPercent(selectedAlertEvaluation.groundingScore)}</td></tr>
                            <tr><th>Hallucination Risk</th><td>{formatQualityPercent(selectedAlertEvaluation.hallucinationRisk)}</td></tr>
                            <tr><th>Citation Coverage</th><td>{formatQualityPercent(selectedAlertEvaluation.citationCoverage)}</td></tr>
                            <tr><th>Evidence Coverage</th><td>{formatQualityPercent(selectedAlertEvaluation.evidenceCoverage)}</td></tr>
                            <tr><th>External Judge</th><td>{selectedAlertEvaluation.externalJudge?.metric ? `${selectedAlertEvaluation.externalJudge.metric}: ${formatQualityPercent(selectedAlertEvaluation.externalJudge.score)}` : "not configured"}</td></tr>
                          </tbody>
                        </table>
                      </div>
                    </details>
                  ) : null}


                  {homeDetailTab === "evidence" ? (
                    <details className="panel alert-documents-panel incident-workspace-section workspace-collapsible">
                      <summary className="panel-head">
                        <div>
                          <h3>Alert Documents</h3>
                          <p>Download backend-linked documents for the selected alert.</p>
                        </div>
                        <span className="section-toggle-indicator" />
                      </summary>
                      {ragDocs.error ? <p className="error">{ragDocs.error}</p> : null}
                      {selectedAlertDocumentLinks.error ? (
                        <p className="subtitle">Backend document-link contract unavailable; using local fallback matcher. {selectedAlertDocumentLinks.error}</p>
                      ) : null}
                      {selectedAlertDocumentLinks.loading ? <p className="subtitle">Resolving linked documents from backend contract...</p> : null}
                      {selectedAlertDocumentContract?.document_link_summary ? (
                        <p className="subtitle">
                          Source: {selectedAlertDocumentContract.document_link_summary.source}
                          {" | "}Matches: {selectedAlertRagDocuments.length}
                          {" | "}Reasons: {(selectedAlertDocumentContract.document_link_summary.match_reasons || []).join(", ") || "-"}
                        </p>
                      ) : null}
                      {selectedAlertKnowledgeDocument ? (
                        <article className="alert-document-download-card alert-document-download-card-single">
                          <div>
                            <span className="workflow-pill workflow-pill-clear">knowledge document</span>
                            <span className="workflow-pill workflow-pill-idle" style={{ marginLeft: 6 }}>
                              {selectedAlertKnowledgeDocument.docs.length} source{selectedAlertKnowledgeDocument.docs.length === 1 ? "" : "s"}
                            </span>
                            <h4>{selectedAlertKnowledgeDocument.title}</h4>
                            <p>{selectedAlertKnowledgeDocument.summary}</p>
                          </div>
                          <div className="alert-document-meta">
                            <span>Alert: {selectedAlertId || "-"}</span>
                            <span>Service: {selectedAlertKnowledgeDocument.service || "-"}</span>
                            <span>Severity: {selectedAlertKnowledgeDocument.severity !== "-" ? selectedAlertKnowledgeDocument.severity : "-"}</span>
                            <span>Types: {selectedAlertKnowledgeDocument.kinds.join(", ") || "document"}</span>
                            <span>Match: {selectedAlertKnowledgeDocument.reasons.join(", ") || "backend-linked"} {selectedAlertKnowledgeDocument.confidence ? `(${Math.round(Number(selectedAlertKnowledgeDocument.confidence) * 100)}%)` : ""}</span>
                          </div>
                          <details className="alert-document-source-list">
                            <summary>Included backend document metadata</summary>
                            <div className="table-wrap" style={{ marginTop: 8 }}>
                              <table>
                                <thead>
                                  <tr><th>Type</th><th>Title</th><th>Path</th></tr>
                                </thead>
                                <tbody>
                                  {selectedAlertKnowledgeDocument.docs.map((doc, index) => (
                                    <tr key={`${doc?.path || doc?.title || "doc"}-${index}`}>
                                      <td>{doc?.kind || doc?.document_kind || "document"}</td>
                                      <td>{doc?.title || "-"}</td>
                                      <td>{doc?.path || "-"}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </details>
                          <button
                            type="button"
                            className="button-primary"
                            onClick={() => downloadConsolidatedAlertDocument(selectedAlertKnowledgeDocument.docs)}
                          >
                            Download Single Document
                          </button>
                        </article>
                      ) : (
                        <div className="alert-documents-empty">
                          <div>
                            <strong>{evidenceDraftReview.draft ? "KaiMS prepared the missing alert document" : "Preparing the missing alert document"}</strong>
                            <p className="subtitle">
                              RCA, impact, diagnostics, resolution, validation, rollback, and cited evidence are assembled automatically. Review and edit the draft before approval.
                            </p>
                          </div>
                          <div className="alert-documents-kind-row">
                            {ALERT_DOC_KIND_OPTIONS.map((kind) => (
                              <button type="button" key={`empty-doc-kind-${kind}`} className={(evidenceDraftReview.draft?.document_kind || "incident") === kind ? "active" : ""} disabled={!evidenceDraftReview.drafts?.some((item) => (item.document_kind || "incident") === kind)} onClick={() => { const next = evidenceDraftReview.drafts?.find((item) => (item.document_kind || "incident") === kind); if (next) setEvidenceDraftReview((current) => ({ ...current, draft: next, content: String(next.content || ""), notes: String(next.review_notes || ""), error: "", message: "" })); }}>{kind === "jira" ? "Jira ticket" : kind}</button>
                            ))}
                          </div>
                          {evidenceDraftReview.loading && !evidenceDraftReview.draft ? <div className="alert-document-generation-state"><span className="spinner" aria-hidden="true" /><span>Completing the RCA-derived document draft…</span></div> : null}
                          {canProvideAlertDocuments && evidenceDraftReview.draft ? <div className="alert-document-draft-editor">
                            <div className="alert-document-draft-heading"><div><span className="eyebrow">{evidenceDraftReview.draft.document_kind || "incident"} · version {evidenceDraftReview.draft.document_version || 1}</span><h4>{evidenceDraftReview.draft.title || "Incident knowledge document"}</h4><small>Reviewer: {evidenceDraftReview.draft.reviewed_by || "Not reviewed"}</small></div><span className={`workflow-pill ${evidenceDraftReview.draft.status === "reviewed" || evidenceDraftReview.draft.status === "approved" ? "workflow-pill-clear" : "workflow-pill-attention"}`}>{evidenceDraftReview.draft.status === "approved_pending_index" ? "Approved — indexing pending" : evidenceDraftReview.draft.status || "draft"}</span></div>
                            <div className="report-view-switch" role="tablist" aria-label="Incident report detail"><button type="button" role="tab" aria-selected={incidentReportView === "simple"} className={incidentReportView === "simple" ? "active" : ""} onClick={() => setIncidentReportView("simple")}>Simple</button><button type="button" role="tab" aria-selected={incidentReportView === "detailed"} className={incidentReportView === "detailed" ? "active" : ""} onClick={() => setIncidentReportView("detailed")}>Detailed</button></div>
                            {incidentReportView === "simple" ? <pre className="simple-incident-report">{simpleIncidentReport(evidenceDraftReview.content)}</pre> : <><label>Document content<textarea rows={18} value={evidenceDraftReview.content} onChange={(event) => setEvidenceDraftReview((current) => ({ ...current, content: event.target.value }))} disabled={evidenceDraftReview.loading || ["approved", "approved_pending_index"].includes(evidenceDraftReview.draft.status)} /></label><label>Reviewer notes<textarea rows={3} value={evidenceDraftReview.notes} onChange={(event) => setEvidenceDraftReview((current) => ({ ...current, notes: event.target.value }))} placeholder="Record corrections, exclusions, and evidence that still needs confirmation." disabled={evidenceDraftReview.loading || ["approved", "approved_pending_index"].includes(evidenceDraftReview.draft.status)} /></label></>}
                            {selectedRcaDecision.reviewRequired ? <p className="subtitle" role="status">The current RCA remains inconclusive. You may still correct and publish verified historical facts for future investigations; publication does not increase this incident's confidence or authorize execution.</p> : null}
                            <div className="alert-documents-empty-actions"><button type="button" className="button-secondary" onClick={saveEvidenceDraft} disabled={evidenceDraftReview.loading || evidenceDraftReview.content.trim().length < 20 || ["approved", "approved_pending_index"].includes(evidenceDraftReview.draft.status)}>Save review</button><button type="button" className="button-primary" onClick={approveEvidenceDraft} disabled={evidenceDraftReview.loading || evidenceDraftReview.draft.status !== "reviewed" || !evidenceDraftReview.draft.evidence_ids?.length || !evidenceDraftReview.draft.source_uris?.length}>Approve reviewed version</button><button type="button" className="button-ghost" onClick={() => selectedAlertRow && openDocumentPrompt(selectedAlertRow)}>Add source document</button></div>
                          </div> : null}
                          <div className="alert-documents-empty-actions">
                            {!canProvideAlertDocuments ? (
                              <button type="button" className="button-secondary" onClick={() => setHomeDetailTab("audit")}>
                                Escalate To L2/L3
                              </button>
                            ) : !evidenceDraftReview.draft && !evidenceDraftReview.loading ? <button type="button" className="button-secondary" onClick={() => selectedAlertRow && openDocumentPrompt(selectedAlertRow)}>Add supporting document</button> : null}
                          </div>
                          {evidenceDraftReview.error ? <p className="error">{evidenceDraftReview.error}</p> : null}
                          {evidenceDraftReview.message ? <p className="status-message">{evidenceDraftReview.message}</p> : null}
                          {selectedAlertActionContext?.alertClosed ? (
                            <p className="subtitle">This alert is closed, so document creation is disabled.</p>
                          ) : null}
                          {!canProvideAlertDocuments ? (
                            <p className="subtitle">L1 operators can monitor and escalate this alert. L2, L3, and Admin users can provide alert documents.</p>
                          ) : null}
                        </div>
                      )}
                    </details>
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "pipeline" ? (
                    <ApplicationSankeyFlow
                      workflow={selectedAlertWorkflow}
                      timelineRows={selectedAlertTimelineRows}
                      routing={selectedAlertRouting}
                      alertRows={monitorScopedAlerts}
                      selectedAlert={selectedAlertRow}
                      selectedAlertId={selectedAlertId}
                      onDrillTimeline={() => setDiagnosticsDetailTab("timeline")}
                    />
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "processing" ? (
                    <ProcessingFlowMap
                      workflow={selectedAlertWorkflow}
                      timelineRows={selectedAlertTimelineRows}
                      routing={selectedAlertRouting}
                      selectedAlert={selectedAlertRow}
                      selectedAlertId={selectedAlertId}
                      onDrillTimeline={() => setDiagnosticsDetailTab("timeline")}
                    />
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "timeline" ? (
                    <FlowTimelineGraph rows={selectedAlertTimelineRows} />
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "context" ? (
                    <ContextRetrievalGraph
                      workflow={selectedAlertWorkflow}
                      timelineRows={selectedAlertTimelineRows}
                      documents={selectedAlertRagDocuments}
                      evaluation={selectedAlertEvaluation}
                      documentContract={selectedAlertDocumentContract}
                      onLoadDocumentContent={loadRagDocumentContent}
                      onDownloadDocument={downloadRagDocument}
                    />
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "events" ? (
                    <AgentEventsGraph rows={selectedAlertEventsDisplay} />
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "finops" ? (
                    <>
                      <div className="metric-grid">
                        <div className="metric-card">
                          <span>Selected Router</span>
                          <strong>{modelProviderStatus?.data?.selected?.default || "-"}</strong>
                          <small>Default provider for new calls</small>
                        </div>
                        <div className="metric-card">
                          <span>Critical Provider</span>
                          <strong>{modelProviderStatus?.data?.selected?.critical || "-"}</strong>
                          <small>Used for critical incidents</small>
                        </div>
                        <div className="metric-card">
                          <span>Provider Health</span>
                          <strong>
                            {selectedModelProviderRows.filter((row) => row.configured && row.healthy && !row.circuitOpen).length}
                            /
                            {selectedModelProviderRows.filter((row) => row.configured).length}
                          </strong>
                          <small>{modelProviderStatus.error || "configured providers available"}</small>
                        </div>
                        <div className="metric-card">
                          <span>Fallback Rows</span>
                          <strong>{selectedFinopsDiagnostics.fallbackRows}</strong>
                          <small>Historical or deterministic fallback calls</small>
                        </div>
                      </div>
                      <div className="chip-row" style={{ margin: "10px 0 12px" }}>
                        {selectedModelProviderRows.map((row) => {
                          const ok = row.configured && row.healthy && !row.circuitOpen;
                          const label = ok ? "ready" : row.configured ? "degraded" : "not configured";
                          return (
                            <span
                              className={`workflow-pill ${ok ? "workflow-pill-active" : "workflow-pill-idle"}`}
                              key={`provider-${row.name}`}
                              title={row.reason || `${row.model}; failures=${row.failures}`}
                            >
                              {row.name}: {label}
                            </span>
                          );
                        })}
                      </div>
                      <div className="table-wrap table-wrap-scroll-x">
                        <table>
                          <thead>
                            <tr>
                              <th>Task</th>
                              <th>Provider</th>
                              <th>Model</th>
                              <th>Status</th>
                              <th>Input</th>
                              <th>Output</th>
                              <th>Cost USD</th>
                              <th>Notes</th>
                            </tr>
                          </thead>
                          <tbody>
                            {selectedAlertUsage.map((row, index) => (
                              <tr key={`usage-${index}`}>
                                <td>{row.task || "-"}</td>
                                <td>{row.provider || "-"}</td>
                                <td>{row.model || "-"}</td>
                                <td>
                                  <span className={`pill ${row.fallback ? "status-failed" : "status-approved"}`}>
                                    {row.fallback ? "fallback" : row.estimated ? "estimated" : "live"}
                                  </span>
                                </td>
                                <td>{row.input_tokens || "-"}</td>
                                <td>{row.output_tokens || "-"}</td>
                                <td>{row.total_cost_usd || "-"}</td>
                                <td>{compactText(row.note || (row.estimated ? "estimated usage" : ""), 140) || "-"}</td>
                              </tr>
                            ))}
                            {!selectedAlertUsage.length ? (
                              <tr>
                                <td colSpan={8}>No FinOps usage rows rendered for selected alert.</td>
                              </tr>
                            ) : null}
                          </tbody>
                        </table>
                      </div>
                      <p className="subtitle">
                        FinOps diagnostics: rendered={selectedFinopsDiagnostics.usageRows}, fallback_rows={selectedFinopsDiagnostics.fallbackRows}, workflow_calls={selectedFinopsDiagnostics.workflowCalls}, workflow_errors={selectedFinopsDiagnostics.workflowErrors}, recommendation_usage={selectedFinopsDiagnostics.recommendationUsage}, trace_calls={selectedFinopsDiagnostics.traceCalls}, trace_errors={selectedFinopsDiagnostics.traceErrors}
                      </p>
                      {!selectedAlertUsage.length ? (
                        <p className="subtitle">No usage rows means upstream services did not persist model usage/cost entries for this alert payload.</p>
                      ) : null}
                    </>
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "api" ? (
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Time</th>
                            <th>Path</th>
                            <th>Status</th>
                            <th>Decision</th>
                            <th>Trace</th>
                          </tr>
                        </thead>
                        <tbody>
                          {gatewayRecent.rows.slice(0, 20).map((row, index) => (
                            <tr key={`api-${index}`}>
                              <td>{formatIstTimestamp(row.created_at)}</td>
                              <td>{row.path || "-"}</td>
                              <td>{row.status_code || "-"}</td>
                              <td>{row?.safety?.decision || "-"}</td>
                              <td>{row.trace_id || "-"}</td>
                            </tr>
                          ))}
                          {!gatewayRecent.rows.length ? (
                            <tr>
                              <td colSpan={5}>No API gateway events found. Refresh or invoke a gateway endpoint.</td>
                            </tr>
                          ) : null}
                        </tbody>
                      </table>
                    </div>
                  ) : null}

                  {homeDetailTab === "execution" ? (
                    <>
                      <ResolutionPanel
                        workflow={selectedAlertWorkflow}
                        alertRow={selectedAlertRow}
                        confidenceScore={Number(selectedAlertEvaluation.confidenceScore || 0)}
                        executionPlan={selectedExecutionPlan}
                        readinessChecks={[
                          { id: "citations", label: "Traceable evidence", detail: Number(selectedAlertEvaluation.citationCoverage || 0) > 0 ? `${formatQualityPercent(selectedAlertEvaluation.citationCoverage)} citation coverage.` : "No supporting citations are attached.", passed: Number(selectedAlertEvaluation.citationCoverage || 0) > 0, action: "review and attach supporting evidence" },
                          { id: "investigation", label: "Iterative investigation", detail: selectedInvestigationConclusive ? "A corroborated conclusion was reached." : "The investigation is missing or inconclusive.", passed: selectedInvestigationConclusive, action: "continue read-only investigation" },
                          { id: "confidence", label: "Evidence confidence", detail: `${formatQualityPercent(selectedInvestigationConfidence)} investigation confidence.`, passed: selectedInvestigationConfidence >= 0.85, action: "raise evidence-derived confidence to at least 85%" },
                          { id: "grounding", label: "Evidence coverage", detail: `${formatQualityPercent(selectedAlertEvaluation.groundingScore)} grounding coverage.`, passed: Number(selectedAlertEvaluation.groundingScore || 0) >= 0.85, action: "raise grounding coverage to at least 85%" },
                          { id: "freshness", label: "Fresh context", detail: selectedAiTrust.evidence.some((row) => !row.cached) ? "Live incident evidence is linked." : "Only cached or unknown evidence is available.", passed: selectedAiTrust.evidence.some((row) => !row.cached), action: "refresh incident context" },
                          { id: "conflicts", label: "Conflicts resolved", detail: selectedAiTrust.conflicting.length ? `${selectedAiTrust.conflicting.length} conflict(s) remain.` : "No conflicts were declared.", passed: selectedAiTrust.conflicting.length === 0, action: "resolve conflicting evidence" },
                          { id: "runbook", label: "Corrective capability", detail: editedExecutionPlan.commands.length || editedExecutionPlan.scripts.length ? "An executable command or playbook is attached." : "No executable corrective plan is attached.", passed: Boolean((editedExecutionPlan.commands.length || editedExecutionPlan.scripts.length) && editedExecutionPlan.execution_ready !== false), action: "attach an approved corrective playbook" },
                          { id: "preflight", label: "Preflight readiness", detail: blockingPreflightFailures.length ? `${blockingPreflightFailures.length} blocking preflight check(s) remain.` : "All blocking preflight checks pass.", passed: blockingPreflightFailures.length === 0, action: "complete blocking preflight checks" },
                          { id: "rollback", label: "Rollback readiness", detail: executionRollbackPlan || "No rollback instructions are attached.", passed: Boolean(executionRollbackPlan), action: "attach rollback instructions" },
                          { id: "validation", label: "Recovery validation", detail: editedExecutionPlan.queries.length ? `${editedExecutionPlan.queries.length} recovery check(s) supplied.` : "No recovery validation is attached.", passed: editedExecutionPlan.queries.length > 0, action: "add recovery validation checks" },
                        ]}
                        onNavigateTab={setHomeDetailTab}
                        embedded
                      />
                      <details className="panel remediation-workspace incident-workspace-section workspace-collapsible" open>
                        <summary className="panel-head">
                          <div>
                            <span className="workspace-section-number">04</span>
                            <h3>Resolution command center</h3>
                            <p>Complete the one current action. Plan, safety, connector, and audit details stay available below.</p>
                          </div>
                          <span className="section-toggle-indicator" />
                        </summary>
                        {executionIsDiagnosticOnly && !executionAutoCloses ? <div className="production-action-banner is-nonproduction">
                          <strong>Investigation remains open</strong>
                          <span>No corrective execution or verified recovery has been recorded.</span>
                          <span>Regenerate a corrective plan or escalate for manual remediation; viewing this workspace will not close the incident.</span>
                        </div> : <div className={`production-action-banner ${dangerousProductionAction ? "is-production" : "is-nonproduction"}`}>
                          <strong>{dangerousProductionAction ? "Dangerous production action" : "Non-production or lower-risk action"}</strong>
                          <span>Action: {selectedExecutionPlan.action === "-" ? selectedRcaDecision.action : selectedExecutionPlan.action}</span>
                          <span>Target: {selectedGovernedExecutionTarget || "Not governed"} · {selectedApplicationConnection.environment} · Risk: {selectedExecutionPlan.riskTier || "unknown"}</span>
                          <span>Duplicate execution is guarded by the remediation idempotency contract; repeated clicks are disabled while a request is active.</span>
                        </div>}
                        {!executionIsDiagnosticOnly ? <details className="resolution-configuration-details">
                          <summary><div><strong>Automation and plan setup</strong><small>{jenkinsExecutorSelected ? `${remediationPlanEditor.job_name || "Jenkins job required"} · ${executionPreflightChecks.filter((check) => check.passed).length}/${executionPreflightChecks.length} checks ready` : "Connector setup required"}</small></div><span>Review setup</span></summary>
                        {jenkinsExecutorSelected && !executionIsDiagnosticOnly ? <section className={`jenkins-process-panel ${selectedJenkinsProcess.configured ? "is-configured" : "is-pending"}`} aria-labelledby="jenkins-process-heading">
                          <header><div><span className="eyebrow">Application automation</span><h3 id="jenkins-process-heading">Jenkins Resolution Process</h3><p>Governed execution from resolution selection through recovery validation.</p></div><span className={`pill ${selectedJenkinsProcess.badgeClass}`}>{selectedJenkinsProcess.badgeLabel}</span></header>
                          <dl className="jenkins-process-summary"><div><dt>Application</dt><dd>{selectedJenkinsProcess.applicationId}</dd></div><div><dt>Jenkins job</dt><dd>{selectedJenkinsProcess.jobName || "Job path required"}</dd></div><div><dt>Resolution</dt><dd>{selectedJenkinsProcess.resolutionId}</dd></div><div><dt>Execution</dt><dd>{selectedJenkinsProcess.executionMode}</dd></div></dl>
                          <ol className="jenkins-process-flow" aria-label="Jenkins resolution progress">
                            <li className={selectedJenkinsProcess.hasResolution ? "is-complete" : "is-current"}><span>1</span><div><strong>Resolution selected</strong><small>{selectedJenkinsProcess.resolutionId}</small></div></li>
                            <li className={cockpitApprovalAccepted ? "is-complete" : "is-current"}><span>2</span><div><strong>Approval</strong><small>{cockpitApprovalAccepted ? "Recorded" : "Pending"}</small></div></li>
                            <li className={selectedJenkinsProcess.succeeded ? "is-complete" : selectedJenkinsProcess.submitted ? "is-current" : cockpitApprovalAccepted ? "is-current" : ""}><span>3</span><div><strong>Jenkins execution</strong><small>{selectedJenkinsProcess.executionStageLabel}</small></div></li>
                            <li className={selectedJenkinsProcess.succeeded ? "is-complete" : ""}><span>4</span><div><strong>Validate and close</strong><small>{selectedJenkinsProcess.succeeded ? `${editedExecutionPlan.queries.length} check(s)` : selectedJenkinsProcess.validationStageLabel}</small></div></li>
                          </ol>
                          <footer><div><strong>Rollback</strong><span>{executionRollbackPlan || "Rollback instructions are required before live execution."}</span></div>{selectedJenkinsProcess.queueUrl ? <a className="button-secondary" href={selectedJenkinsProcess.queueUrl} target="_blank" rel="noreferrer">Open Jenkins build</a> : <button type="button" className="button-secondary" onClick={() => document.querySelector(".remediation-connection-panel")?.scrollIntoView({ behavior: "smooth", block: "start" })}>{selectedJenkinsProcess.configured ? "Review Jenkins setup" : "Configure Jenkins"}</button>}</footer>
                        </section> : null}
                        {!executionIsDiagnosticOnly ? <details className="execution-safety-details">
                          <summary>Safety checks <span>{executionPreflightChecks.filter((check) => check.passed).length}/{executionPreflightChecks.length} ready</span></summary>
                          <div className="execution-decision-grid">
                          <section className={`execution-readiness ${blockingPreflightFailures.length ? "is-blocked" : "is-ready"}`} aria-labelledby="execution-readiness-heading">
                            <div className="panel-head">
                              <div>
                                <span className="eyebrow">Execution readiness</span>
                                <h3 id="execution-readiness-heading">{blockingPreflightFailures.length ? "Complete required setup" : "Required checks ready"}</h3>
                              </div>
                              <strong>{executionPreflightChecks.filter((check) => check.passed).length}/{executionPreflightChecks.length}</strong>
                            </div>
                            <p>{blockingPreflightFailures.length ? `${blockingPreflightFailures.length} blocking issue(s) must be resolved.` : "Policy, target, approval, identity, and idempotency are enforced when execution is submitted."}</p>
                          </section>
                          </div>
                          <div className="execution-checklist" aria-label="Execution readiness checks">
                          {executionPreflightChecks.map((check) => (
                            <article className={`execution-check ${check.passed ? "is-pass" : check.blocking ? "is-block" : "is-warn"}`} key={check.id}>
                              <span aria-hidden="true">{check.passed ? "✓" : check.blocking ? "×" : "!"}</span>
                              <div><strong>{check.label}</strong><p>{check.detail}</p></div>
                              <small>{check.passed ? "Ready" : check.blocking ? "Required" : "Recommended"}</small>
                            </article>
                          ))}
                          </div>
                        </details> : null}
                        {!executionIsDiagnosticOnly ? <details className="panel remediation-connection-panel">
                          <summary className="panel-head"><div><h3>Connection details</h3><p>{selectedApplicationConnection.service} · {selectedApplicationConnection.environment} · {selectedApplicationConnection.source}</p></div><span className="section-toggle-indicator" /></summary>
                          <div className="filter-grid">
                            <label>Application<input value={selectedApplicationConnection.application} readOnly /></label>
                            <label>Service<input value={selectedApplicationConnection.service} readOnly /></label>
                            <label>Environment<input value={selectedApplicationConnection.environment} readOnly /></label>
                            <label>Source<input value={selectedApplicationConnection.source} readOnly /></label>
                            <label>Connection Type<input value={remediationPlanEditor.connection_type} onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, connection_type: e.target.value }))} /></label>
                            <label>Executor<select value={remediationPlanEditor.executor_type} onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, executor_type: e.target.value, connection_type: e.target.value || curr.connection_type }))}><option value="">Validation only</option><option value="jenkins">Jenkins</option></select></label>
                            <label>Endpoint URL<input className={executionEndpoint && !executionEndpointValid ? "input-invalid" : ""} aria-invalid={Boolean(executionEndpoint && !executionEndpointValid)} value={remediationPlanEditor.connection_url} placeholder="https://app-or-metrics-endpoint" onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, connection_url: e.target.value }))} /><span className="field-hint">{executionEndpoint && !executionEndpointValid ? "Enter an HTTP(S) endpoint, not a deployment or release name." : "Optional connector endpoint used for validation and execution."}</span></label>
                            {jenkinsExecutorSelected ? <label>Jenkins Job Path<input value={remediationPlanEditor.job_name} placeholder="service/rollback" onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, job_name: e.target.value }))} /><span className="field-hint">Folders are supported. KaiMS triggers this job only after approval and confirmation.</span></label> : null}
                            <label>Namespace / Runtime<input value={remediationPlanEditor.namespace} placeholder="prod / namespace / resource group" onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, namespace: e.target.value }))} /></label>
                          </div>
                        </details> : null}
                        {!executionIsDiagnosticOnly ? <details className="panel remediation-editor-panel">
                          <summary>Execution plan <span>{editedExecutionPlan.commands.length + editedExecutionPlan.scripts.length} executable step(s) · {editedExecutionPlan.queries.length} validation check(s)</span></summary>
                          <div className="panel-head remediation-editor-actions">
                            <div><h3>Governed execution plan</h3><p>This versioned catalog plan is immutable in the standard workflow. Request a new plan version when the action or checks must change.</p></div>
                          </div>
                          <div className="remediation-editor-grid compact-plan-editor governed-plan-view">
                            <section><span>Remediation playbook</span><small>{editedExecutionPlan.scripts.length ? `${editedExecutionPlan.scripts.length} step(s)` : "No script artifact"}</small><pre>{editedExecutionPlan.scripts.join("\n") || "No reviewed remediation playbook supplied."}</pre></section>
                            <section><span>Execution commands</span><small>{editedExecutionPlan.commands.length} command(s)</small><pre>{editedExecutionPlan.commands.join("\n") || "No approved execution commands supplied."}</pre></section>
                            <section><span>Recovery validation</span><small>{editedExecutionPlan.queries.length} check(s)</small><pre>{editedExecutionPlan.queries.join("\n") || "No recovery validation supplied."}</pre></section>
                          </div>
                        </details> : null}
                        </details> : null}
                        <section className="execution-guided-flow" aria-labelledby="guided-execution-heading">
                          <div className="execution-guided-head"><div><span className="discovery-eyebrow">Guarded execution</span><h3 id="guided-execution-heading">{executionAutoCloses ? "Watch-only completion" : manualEscalationRecorded ? "Manual remediation requested" : "Complete the current step"}</h3><p>{executionAutoCloses ? "This alert is explicitly watch-only. KaiOps is recording the observation and closing it without execution." : manualEscalationRecorded ? "Automation remains safely locked while an operator handles the incident manually." : executionActivationMessage}</p></div><span className={`pill ${executionAllowed || manualEscalationRecorded || (executionAutoCloses && ["closed", "resolved"].includes(selectedCanonicalIncidentStatus)) ? "pill-success" : "pill-warning"}`}>{executionAutoCloses ? (["closed", "resolved"].includes(selectedCanonicalIncidentStatus) ? "Closed" : "Auto-closing") : manualEscalationRecorded ? "Escalated" : executionAllowed ? "Ready" : !cockpitApprovalAccepted ? "Decision required" : executionSetupBlocked || executionCapabilityBlocked ? "Blocked" : "In progress"}</span></div>
                          {executionAutoCloses ? <ol className="execution-stepper" aria-label="Watch-only completion progress"><li className={["closed", "resolved"].includes(selectedCanonicalIncidentStatus) ? "is-complete" : "is-current"}><span>✓</span><div><strong>Record observation and close</strong><small>{["closed", "resolved"].includes(selectedCanonicalIncidentStatus) ? "Completed" : "In progress"}</small></div></li></ol> : !liveExecutionPlanAvailable ? <ol className="execution-stepper" aria-label="Automated plan development"><li className={catalogCandidateAvailable ? "is-complete" : "is-current"}><span>{catalogCandidateAvailable ? "✓" : "1"}</span><div><strong>Collect and verify evidence</strong><small>{catalogCandidateAvailable ? `${Number(selectedCatalogStatus.data?.evidence_sources || 0)} independent sources collected` : "Automated evidence work active"}</small></div></li><li className={catalogReviewRequired ? "is-current" : ""}><span>2</span><div><strong>Compile governed plan</strong><small>{catalogReviewRequired ? "Candidate ready for catalog review" : "Waiting for sufficient evidence"}</small></div></li><li><span>3</span><div><strong>Review and execute</strong><small>Safety locked</small></div></li></ol> : <ol className="execution-stepper" aria-label="Execution progress">
                            <li className={cockpitApprovalAccepted ? "is-complete" : "is-current"}><span>1</span><div><strong>Approve</strong><small>{cockpitApprovalAccepted ? "Recorded" : "Pending"}</small></div></li>
                            <li className={cockpitApprovalAccepted && executionConfirmationValid ? "is-complete" : cockpitApprovalAccepted ? "is-current" : ""}><span>2</span><div><strong>Confirm</strong><small>{cockpitApprovalAccepted && executionConfirmationValid ? "Complete" : "Pending"}</small></div></li>
                            <li className={remediationExecutionState.loading || executionAllowed ? "is-current" : ""}><span>3</span><div><strong>Execute</strong><small>{remediationExecutionState.loading ? "Running" : executionAllowed ? "Ready" : executionCapabilityBlocked ? "Executor required" : "Locked"}</small></div></li>
                          </ol>}
                          <div className="execution-current-step">
                            {manualEscalationRecorded ? <div className="execution-step-form" role="status"><div><strong>Escalation recorded</strong><p>The incident remains open for manual remediation. Automated execution stays locked because no reviewed corrective action or recovery check is available.</p></div><button type="button" className="button-secondary" onClick={regenerateSelectedAlertAnalysis} disabled={selectedAlertRegeneration.loading}>{selectedAlertRegeneration.loading ? "Regenerating…" : "Generate a corrective plan instead"}</button></div> : <>
                            {executionAutoCloses ? <div className="execution-step-form"><div><strong>{["closed", "resolved"].includes(selectedCanonicalIncidentStatus) ? "Watch-only observation recorded — incident closed" : "Automatic watch-only closure in progress"}</strong><p>No approval or execution is required because the resolution explicitly classified this alert as watch-only.</p></div></div> : !liveExecutionPlanAvailable ? <div className="execution-step-form"><div><strong>{catalogReviewRequired ? "A catalog candidate is ready for review" : "KaiMS is developing the governed resolution plan"}</strong><p>{catalogReviewRequired ? `KaiMS collected ${Number(selectedCatalogStatus.data?.evidence_sources || 0)} independent sources and compiled a ${catalogStage.replaceAll("_", " ")}. Review and complete its corrective action, validation, and rollback before it can become executable.` : "Evidence collection and runbook development started automatically. Execution stays locked until the plan contains a verified target, corrective action, recovery validation, rollback, and the required approval."}</p>{selectedAlertRegeneration.message ? <p role="status">{selectedAlertRegeneration.message}</p> : null}{selectedAlertRegeneration.error ? <p className="error" role="alert">{selectedAlertRegeneration.error}</p> : null}</div><div className="button-row">{catalogReviewRequired ? <button type="button" className="button-primary" onClick={() => setActiveTab("knowledge")}>Review catalog candidate</button> : null}<button type="button" className={catalogReviewRequired ? "button-secondary" : "button-primary"} onClick={regenerateSelectedAlertAnalysis} disabled={selectedAlertRegeneration.loading}>{selectedAlertRegeneration.loading ? "Refreshing evidence and analysis…" : "Refresh automated investigation"}</button></div><details><summary>Manual fallback</summary><label>Escalation reason<textarea rows={2} value={approvalForm.comment} placeholder="Explain why automated investigation cannot continue." onChange={(event) => setApprovalForm((current) => ({ ...current, action: "reject", comment: event.target.value }))} /></label><button type="button" className="button-secondary" onClick={() => void approveCockpitRemediationPlan("reject")} disabled={approvalState.loading}>{approvalState.loading ? "Recording escalation…" : "Escalate for manual remediation"}</button></details></div> : !cockpitApprovalAccepted ? <div className="execution-step-form"><div className="credential-method-grid"><label>Decision<select value={approvalForm.action} onChange={(event) => setApprovalForm((current) => ({ ...current, action: event.target.value }))}><option value="approve">Approve immutable plan</option><option value="reject">Reject automation and escalate</option></select></label><label>Approver<input value={adminSession?.user?.username || "Authenticated operator"} readOnly /></label></div><label>Decision reason<textarea rows={2} value={approvalForm.comment} placeholder={approvalForm.action === "reject" ? "Why must this incident be escalated for manual remediation?" : "Why is this plan safe and appropriate?"} onChange={(event) => setApprovalForm((current) => ({ ...current, comment: event.target.value }))} /></label><button type="button" className="button-primary" onClick={() => void approveCockpitRemediationPlan()} disabled={approvalState.loading}>{approvalState.loading ? (approvalWillAutoExecute ? "Approving and starting…" : "Recording decision…") : approvalForm.action === "reject" ? "Reject and escalate" : approvalWillAutoExecute ? "Approve and start remediation" : "Approve and continue"}</button><small className="execution-action-explainer">{approvalWillAutoExecute ? "This lower-risk non-production plan starts immediately after approval." : dangerousProductionAction ? "Production execution requires a separate typed confirmation after approval." : "Approval is recorded first; any missing executor setup is shown next."}</small></div> : executionSetupBlocked ? <div className="execution-step-form"><div><strong>Approval recorded — complete required setup</strong><p>{blockingPreflightFailures.map((check) => check.label).join(", ")}</p></div>{!jenkinsExecutorSelected ? <button type="button" className="button-primary" onClick={buildRequiredExecutor}>Build required process</button> : null}</div> : dangerousProductionAction && !executionConfirmationValid ? <div className="execution-step-form"><label className="typed-execution-confirmation">Approval recorded. Type <code>{executionConfirmationPhrase}</code> to confirm production execution<input value={executionConfirmationText} autoComplete="off" autoFocus onChange={(event) => setExecutionConfirmationText(event.target.value)} /></label></div> : executionCapabilityBlocked ? <div className="execution-step-form"><div><strong>Approval recorded — live execution is not configured</strong><p>This plan has no reviewed corrective capability. Regenerate it after adding a matching catalog playbook.</p></div></div> : <><div><strong>Approval and all safety gates passed</strong><p>{selectedGovernedExecutionTarget} · {selectedApplicationConnection.environment} · {selectedExecutionPlan.riskTier || "unknown risk"}</p></div><button type="button" className="button-primary execution-primary-action" onClick={confirmAndExecuteRemediationPlan} disabled={!executionAllowed}>{remediationExecutionState.loading ? "Executing…" : "Execute approved plan"}</button></>}
                            </>}
                          </div>
                          {remediationExecutionState.error ? <p className="error">{remediationExecutionState.error}</p> : null}
                          {approvalState.error ? <p className="error" role="alert">{approvalState.error}</p> : null}
                          {emergencyStopAvailable ? <section className="execution-emergency-stop" aria-labelledby="emergency-stop-title"><div><span className="eyebrow">Emergency control</span><h4 id="emergency-stop-title">Stop active remediation</h4><p>Stops the queued or running executor job, cancels durable orchestration, and records the authenticated operator and reason.</p></div><label>Required stop reason<textarea rows={2} value={emergencyStopState.reason} placeholder="Describe the unsafe condition or unexpected impact" onChange={(event) => setEmergencyStopState((current) => ({ ...current, reason: event.target.value, error: "" }))} /></label><button type="button" className="button-danger" disabled={emergencyStopState.loading || emergencyStopState.reason.trim().length < 8} onClick={() => requestEmergencyStop(emergencyStopAction.id)}>{emergencyStopState.loading ? "Stopping remediation…" : "Emergency stop"}</button></section> : null}
                          {emergencyStopState.error ? <p className="error" role="alert">{emergencyStopState.error}</p> : null}
                          {emergencyStopState.message ? <p className="status-message" role="status">{emergencyStopState.message}</p> : null}
                        </section>
                        <section className="execution-recovery-grid">
                          <article className={`execution-recovery-card ${executionRollbackPlan ? "is-ready" : "is-missing"}`}>
                            <span className="eyebrow">Rollback</span>
                            <h3>{executionRollbackPlan ? "Rollback plan available" : "Rollback plan missing"}</h3>
                            <p>{executionRollbackPlan || "Attach rollback instructions before treating this plan as production-ready."}</p>
                          </article>
                          <article className={`execution-recovery-card ${editedExecutionPlan.queries.length ? "is-ready" : "is-missing"}`}>
                            <span className="eyebrow">Recovery validation</span>
                            <h3>{editedExecutionPlan.queries.length ? `${editedExecutionPlan.queries.length} post-check(s)` : "Validation missing"}</h3>
                            <p>{editedExecutionPlan.queries[0] || "Add a health, metrics, or data-integrity check to prove recovery."}</p>
                          </article>
                        </section>
                        {selectedRemediationOutcome ? (
                          <section className={`execution-result-card remediation-outcome-${selectedRemediationOutcome.status}`} aria-live="polite">
                            <div className="panel-head"><div><span className="eyebrow">Execution result</span><h3>{selectedRemediationOutcome.title}</h3></div><span className={`pill ${statusPillClass(selectedRemediationOutcome.status)}`}>{selectedRemediationOutcome.status}</span></div>
                            <p>{selectedRemediationOutcome.detail}</p>
                            <dl><dt>Action</dt><dd>{selectedRemediationOutcome.actionType}</dd><dt>Target</dt><dd>{selectedRemediationOutcome.target}</dd></dl>
                            <details className="k-technical-details"><summary>Technical response</summary><pre className="result">{JSON.stringify(selectedExecutionTechnicalResponse, null, 2)}</pre></details>
                            {selectedRemediationOutcome.status === "succeeded" ? <section className="execution-outcome-review"><span className="eyebrow">Required human review</span><h4>Was this remediation effective?</h4><div className="outcome-choice" role="group" aria-label="Execution outcome">{[['successful','Successful'],['partial','Partially successful'],['failed','Failed']] .map(([value,label])=><button type="button" key={value} className={executionOutcomeReview.outcome===value?'active':''} onClick={()=>setExecutionOutcomeReview((current)=>({...current,outcome:value}))}>{label}</button>)}</div><label>Operator findings<textarea rows={3} value={executionOutcomeReview.notes} placeholder="What changed, what was validated, and any side effects." onChange={(e)=>setExecutionOutcomeReview((current)=>({...current,notes:e.target.value}))}/></label><label className="checkbox-row"><input type="checkbox" checked={executionOutcomeReview.reusable} onChange={(e)=>setExecutionOutcomeReview((current)=>({...current,reusable:e.target.checked}))}/>Approve this reviewed script for future matching incidents</label><button type="button" className="button-primary" onClick={approveExecutionOutcomeForReuse} disabled={executionOutcomeReview.loading||!executionOutcomeReview.notes.trim()}>{executionOutcomeReview.loading?'Saving review…':'Submit review and learning'}</button>{executionOutcomeReview.error?<p className="error">{executionOutcomeReview.error}</p>:null}{executionOutcomeReview.message?<p className="status-message">{executionOutcomeReview.message}</p>:null}</section> : null}
                          </section>
                        ) : null}
                        <details className="k-technical-details execution-technical-details">
                          <summary>Workflow and backend routing details</summary>
                          <div className="workflow-guide-grid remediation-flow-grid">
                            {selectedWorkflowFlowStages.map((stage) => (
                              <div className="workflow-guide-card remediation-flow-card" key={stage.id}><strong>{stage.label}</strong><span className={`workflow-pill workflow-pill-${stage.status}`}>{stage.status.toUpperCase()}</span><p>{stage.detail}</p></div>
                            ))}
                          </div>
                          <div className="table-wrap table-wrap-scroll-x remediation-service-flow"><table><thead><tr><th>Backend Service</th><th>Consumes</th><th>Publishes</th><th>Processing Agent</th></tr></thead><tbody>{SERVICE_TOPIC_FLOW.map((stage) => <tr key={`service-flow-${stage.service}`}><td>{stage.service}</td><td>{stage.consumes}</td><td>{stage.publishes}</td><td>{stage.agent}</td></tr>)}</tbody></table></div>
                          <ExecutionPlanGraph plan={selectedExecutionPlan} />
                        </details>
                      </details>
                    </>
                  ) : null}

                  {homeDetailTab === "audit" ? (
                    <section className="incident-audit-section" role="tabpanel">
                      <VerifyWorkspace
                        incidentId={selectedIncidentId}
                        incidentStatus={selectedCanonicalIncidentStatus}
                        workflow={selectedAlertWorkflow}
                        executionPlan={selectedExecutionPlan}
                        remediationOutcome={selectedRemediationOutcome}
                        timelineRows={selectedAlertTimelineRows}
                        documentCount={selectedAlertRagDocuments.length}
                      />
                      <UnifiedIncidentTimeline workflow={selectedAlertWorkflow} rows={selectedAlertTimelineRows} documents={selectedAlertRagDocuments} />
                      <details className="k-technical-details incident-raw-details">
                        <summary>Technical details and raw workflow payload</summary>
                        <pre className="result">{JSON.stringify(selectedAlertData.payload || {}, null, 2)}</pre>
                      </details>
                    </section>
                  ) : null}
                </article>
              ) : selectedAlertId ? (
                <article className="panel alert-details-cockpit" ref={alertDetailsRef} tabIndex={-1} aria-busy={selectedAlertData.loading}>
                  <div className="panel-head incident-sticky-header">
                    <div>
                      <span className="discovery-eyebrow">Guided Incident Cockpit</span>
                      <h2>Alert Details Cockpit</h2>
                      <p>{selectedAlertData.error ? "The alert details could not be loaded." : "Loading the selected alert and incident context..."}</p>
                    </div>
                    <span className={`pill ${selectedAlertData.error ? "pill-danger" : "pill-info"}`}>
                      {selectedAlertData.error ? "Load failed" : "Loading"}
                    </span>
                  </div>
                  {selectedAlertData.error ? (
                    <div>
                      <p className="error" role="alert">{selectedAlertData.error}</p>
                      <button type="button" className="button-primary" onClick={() => loadAlertDetails(selectedAlertId)} disabled={selectedAlertData.loading}>
                        {selectedAlertData.loading ? "Retrying..." : "Retry loading details"}
                      </button>
                    </div>
                  ) : (
                    <p className="subtitle" role="status">Retrieving processing history, Jira ticket, context, and RCA evidence.</p>
                  )}
                </article>
              ) : (
                <article className="panel">
                  <p className="subtitle">Select an alert in Alert Stream to open the detail tabs workspace.</p>
                </article>
              )}
            </section>
          ) : null}

          {activeTab === "admin" && isAdministrator && (!routeOutlet || currentSearch.includes("workspace=knowledge")) ? (
            <section className="grid single-col">
              <article className="panel admin-center-panel">
                <div className="panel-head">
                  <h2>Admin Center</h2>
                  <p>Three-step workspace for access, setup, and alert knowledge.</p>
                </div>

                <div className="admin-journey-grid">
                  {adminJourneyCards.map((step) => (
                    <article
                      key={`admin-journey-${step.id}`}
                      className={`admin-journey-card ${adminJourneyStep === step.id ? "active" : ""}`}
                    >
                      <strong>{step.title}</strong>
                      <span>{step.hint}</span>
                      <small>{step.status}</small>
                      <div className="admin-journey-meta">
                        <span className={`admin-journey-chip admin-journey-chip-${step.tone || "info"}`}>{step.tone || "info"}</span>
                        <span className={`workflow-pill ${step.complete ? "workflow-pill-active" : "workflow-pill-idle"}`}>
                          {step.complete ? "done" : "pending"}
                        </span>
                      </div>
                      <button
                        type="button"
                        className="button-secondary admin-journey-cta"
                        onClick={() => triggerAdminJourneyCta(step.id)}
                      >
                        {step.cta}
                      </button>
                    </article>
                  ))}
                </div>

                <p className="subtitle">Navigate by stage: Access handles identity, Setup covers landing pad and approvals, Knowledge stores alert intelligence.</p>
                <p className="subtitle"><strong>Current Stage:</strong> {adminWorkspaceCaptions[adminWorkspace] || "Administrative workspace controls."}</p>
              </article>

              {adminWorkspace === "users" ? (
                  <div className="grid single-col">
                    <article className="panel">
                      <h3>Session</h3>
                      {adminSession.user ? <p className="subtitle">Signed in as {adminSession.user.username} ({adminSession.user.role_name})</p> : null}
                      {adminSession.error ? <p className="error">{adminSession.error}</p> : null}
                    </article>

                    <article className="panel">
                      <div className="panel-head">
                        <h3>Users</h3>
                        <button className="button-secondary" type="button" onClick={loadAdminUsersAndRoles} disabled={!adminSession.accessToken || adminUsers.loading}>Refresh</button>
                      </div>
                      {adminUsers.error ? <p className="error">{adminUsers.error}</p> : null}
                      {adminUsers.loading ? <p className="subtitle">Loading users and roles...</p> : null}
                      {!adminUsers.loading && !adminUsers.error && !adminUsers.rows.length ? (
                        <div className="empty-state-panel">
                          <strong>No users are shown yet</strong>
                          <span>Refresh access controls to load seeded users, or create a new user below.</span>
                          <button className="button-secondary" type="button" onClick={loadAdminUsersAndRoles} disabled={!adminSession.accessToken}>
                            Refresh Users
                          </button>
                        </div>
                      ) : null}
                      <div className="table-wrap table-wrap-scroll-x">
                        <table>
                          <thead>
                            <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Active</th><th>Actions</th></tr>
                          </thead>
                          <tbody>
                            {adminUsers.rows.map((row, index) => (
                              <tr key={`admin-user-${row.id || index}`}>
                                <td>{row.id || "-"}</td><td>{row.username || "-"}</td><td>{row.email || "-"}</td><td>{row.role_name || row.role_id || "-"}</td><td>{row.status || "-"}</td><td>{row.is_active ? "yes" : "no"}</td>
                                <td><button type="button" className="button-secondary" onClick={() => selectAdminUserForEdit(row)}>Edit</button></td>
                              </tr>
                            ))}
                            {!adminUsers.rows.length && adminUsers.loading ? <tr><td colSpan={7}>Loading users...</td></tr> : null}
                            {!adminUsers.rows.length && !adminUsers.loading && adminUsers.error ? <tr><td colSpan={7}>Unable to load users. Review the error above.</td></tr> : null}
                            {!adminUsers.rows.length && !adminUsers.loading && !adminUsers.error ? <tr><td colSpan={7}>No users returned yet. Use Refresh Users or create a user.</td></tr> : null}
                          </tbody>
                        </table>
                      </div>
                    </article>

                    <article className="panel">
                      <h3>Create User</h3>
                      <details className="admin-collapsible" open>
                        <summary>Create New User</summary>
                        <form className="form" onSubmit={createAdminUser}>
                          <div className="filter-grid">
                            <label>Username<input value={adminCreateUser.username} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, username: e.target.value }))} /></label>
                            <label>Email<input value={adminCreateUser.email} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, email: e.target.value }))} /></label>
                            <label>First Name<input value={adminCreateUser.first_name} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, first_name: e.target.value }))} /></label>
                            <label>Last Name<input value={adminCreateUser.last_name} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, last_name: e.target.value }))} /></label>
                          </div>
                          <div className="filter-grid">
                            <label>Password<input type="password" value={adminCreateUser.password} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, password: e.target.value }))} /></label>
                            <label>Role
                              <select value={adminCreateUser.role_id} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, role_id: Number(e.target.value) }))}>
                                {(adminRoles.length ? adminRoles : [{ id: 1, name: "administrator" }]).map((role) => (
                                  <option key={`role-${role.id}`} value={role.id}>{role.name}</option>
                                ))}
                              </select>
                            </label>
                            <label>Status<input value={adminCreateUser.status} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, status: e.target.value }))} /></label>
                            <label>Active
                              <select value={String(adminCreateUser.is_active)} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, is_active: e.target.value === "true" }))}>
                                <option value="true">true</option><option value="false">false</option>
                              </select>
                            </label>
                          </div>
                          <button className="button-primary" type="submit" disabled={!adminSession.accessToken || adminUsers.loading}>Create User</button>
                        </form>
                      </details>
                    </article>

                    <article className="panel">
                      <h3>Modify User</h3>
                      <details className="admin-collapsible" open={adminEditPanelOpen} onToggle={(event) => setAdminEditPanelOpen(event.currentTarget.open)}>
                        <summary>Edit Existing User</summary>
                        <form className="form" onSubmit={updateAdminUser}>
                          <div className="filter-grid">
                            <label>User ID<input value={adminEditUser.id || ""} readOnly /></label>
                            <label>Username<input value={adminEditUser.username} readOnly /></label>
                            <label>Email<input value={adminEditUser.email} onChange={(e) => setAdminEditUser((curr) => ({ ...curr, email: e.target.value }))} /></label>
                            <label>Role
                              <select value={adminEditUser.role_id} onChange={(e) => setAdminEditUser((curr) => ({ ...curr, role_id: Number(e.target.value) }))}>
                                {(adminRoles.length ? adminRoles : [{ id: 1, name: "Administrator" }]).map((role) => (
                                  <option key={`edit-role-${role.id}`} value={role.id}>{role.name}</option>
                                ))}
                              </select>
                            </label>
                          </div>
                          <div className="filter-grid">
                            <label>First Name<input value={adminEditUser.first_name} onChange={(e) => setAdminEditUser((curr) => ({ ...curr, first_name: e.target.value }))} /></label>
                            <label>Last Name<input value={adminEditUser.last_name} onChange={(e) => setAdminEditUser((curr) => ({ ...curr, last_name: e.target.value }))} /></label>
                            <label>Status
                              <select value={adminEditUser.status} onChange={(e) => setAdminEditUser((curr) => ({ ...curr, status: e.target.value, is_active: e.target.value === "active" }))}>
                                <option value="active">active</option>
                                <option value="inactive">inactive</option>
                                <option value="suspended">suspended</option>
                              </select>
                            </label>
                            <label>Active
                              <select value={String(adminEditUser.is_active)} onChange={(e) => {
                                const isActive = e.target.value === "true";
                                setAdminEditUser((curr) => ({ ...curr, is_active: isActive, status: isActive ? "active" : "inactive" }));
                              }}>
                                <option value="true">true</option><option value="false">false</option>
                              </select>
                            </label>
                          </div>
                          <button className="button-primary" type="submit" disabled={!adminSession.accessToken || adminUsers.loading || !adminEditUser.id}>Update User</button>
                        </form>
                      </details>
                    </article>

                    <article className="panel">
                      <h3>Reset Password</h3>
                      <details className="admin-collapsible">
                        <summary>Reset User Password</summary>
                        <form className="form" onSubmit={resetAdminUserPassword}>
                          <div className="filter-grid">
                            <label>User ID<input value={adminResetPasswordForm.user_id || ""} readOnly /></label>
                            <label>New Password<input type="password" value={adminResetPasswordForm.new_password} onChange={(e) => setAdminResetPasswordForm((curr) => ({ ...curr, new_password: e.target.value }))} /></label>
                          </div>
                          <button className="button-primary" type="submit" disabled={!adminSession.accessToken || adminUsers.loading || !adminResetPasswordForm.user_id || !String(adminResetPasswordForm.new_password || "").trim()}>Reset Password</button>
                        </form>
                      </details>
                    </article>
                  </div>

                ) : null}

                {adminWorkspace === "project" ? (
                  <div className="grid single-col admin-flow-section admin-flow-project">
                    <section className="panel operating-mode-flow" aria-labelledby="operating-mode-title">
                      <div className="panel-head"><div><span className="discovery-eyebrow">Incident operating model</span><h3 id="operating-mode-title">Immediate response, continuously improving context</h3><p>Both modes remain active. Continuous knowledge is the default context strategy for every newly onboarded application.</p></div><span className="workflow-pill workflow-pill-active">Continuous default</span></div>
                      <div className="operating-mode-grid">
                        <article className="operating-mode-card is-immediate">
                          <header><span>01</span><div><small>Immediate</small><h3>Real-time Response</h3></div></header>
                          <ol><li><strong>Process the alert</strong><span>Start as soon as an alert reaches the landing pad.</span></li><li><strong>Reuse known context</strong><span>Apply the latest validated knowledge before discovering missing evidence.</span></li><li><strong>Control the action</strong><span>Review, approve, remediate, validate, and close with a full audit trail.</span></li></ol>
                        </article>
                        <div className="operating-mode-loop" aria-label="AI learning feedback loop"><span>AI</span><strong>Context in</strong><i>↔</i><strong>Outcome back</strong></div>
                        <article className="operating-mode-card is-continuous">
                          <header><span>02</span><div><small>Continuous</small><h3>Proactive & Knowledge</h3></div></header>
                          <ol><li><strong>Monitor all alert sources</strong><span>Aggregate new alert families and schedule recurring analysis.</span></li><li><strong>Curate understanding</strong><span>Persist context, RCA, impact, dependencies, and resolution guidance.</span></li><li><strong>Learn from outcomes</strong><span>Feed validated incident results back into the repository for future response.</span></li></ol>
                        </article>
                      </div>
                      <div className="operating-mode-policy"><div><strong>New application context policy</strong><span>Choose when KaiMS may reuse periodic context and when it must query live systems.</span></div><select aria-label="Default context strategy" value={onboardingForm.context_strategy} onChange={(event) => setOnboardingForm((current) => ({ ...current, context_strategy: event.target.value }))}><option value="auto">Auto: reuse complete context</option><option value="historical">Historical snapshots only</option><option value="realtime">Real-time collection</option></select></div>
                    </section>
                    <article className="panel project-stepper-panel">
                      <div className="panel-head">
                        <div>
                          <h3>Setup Wizard</h3>
                          <p>Start with one plain-English setup prompt. KaiMS auto-completes details, scores the document, asks for missing values, then validates and updates knowledge/rules.</p>
                        </div>
                        <button
                          type="button"
                          className={`setup-section-icon-button ${projectSetupShowAll ? "active" : ""}`}
                          aria-label={projectSetupShowAll ? "Focus current setup step" : "Show full setup"}
                          title={projectSetupShowAll ? "Focus current step" : "Show full setup"}
                          onClick={() => setProjectSetupShowAll((current) => !current)}
                        />
                      </div>
                      <div className="setup-wizard-summary">
                        <div>
                          <span>Project</span>
                          <strong>{String(onboardingForm.name || selectedOnboardingProject || "Not selected")}</strong>
                        </div>
                        <div>
                          <span>Path</span>
                          <strong>{onboardingForm.onboarding_path === "setup_monitoring" ? "Prometheus setup" : "Existing monitoring"}</strong>
                        </div>
                        <div>
                          <span>Service Knowledge</span>
                          <strong>{knowledgePackState.approved ? "approved" : onboardingKnowledgePack?.status || (onboardingSourceDocCount > 0 ? "added" : "missing")}</strong>
                        </div>
                        <div>
                          <span>Generated Rules</span>
                          <strong>{onboardingGeneratedRuleRows.length}</strong>
                        </div>
                      </div>
                      <div className="project-stepper-grid">
                        {projectStepCards.map((card) => (
                          <button
                            key={`project-step-${card.id}`}
                            type="button"
                            className={`project-step-card ${projectSetupStep === card.id ? "active" : ""}`}
                            onClick={() => {
                              setProjectSetupStep(card.id);
                              setProjectSetupShowAll(false);
                              if (card.id === "knowledge") {
                                setAlertKnowledgeView("onboarding");
                              }
                            }}
                          >
                            <strong>{card.label}</strong>
                            <span>{card.hint}</span>
                            <span className={`workflow-pill ${card.complete ? "workflow-pill-active" : "workflow-pill-idle"}`}>
                              {card.complete ? "done" : "pending"}
                            </span>
                          </button>
                        ))}
                      </div>
                    </article>
                    {showProjectStep("setup") ? (
                    <article className="panel">
                      <div className="panel-head">
                        <div>
                          <h3>Setup Monitoring</h3>
                          <p>Choose the monitoring path, enter the tool endpoint, and save the landing-pad setup.</p>
                        </div>
                        <div style={{ display: "flex", gap: 8 }}>
                          <button type="button" className="button-secondary" onClick={loadOnboardingAdminData}>Refresh</button>
                          <button
                            type="button"
                            className="button-secondary"
                            onClick={() => deleteProjectOnboarding(selectedOnboardingProject || onboardingForm.name)}
                            disabled={onboardingProjectMode === "new" || onboardingState.loading || !String(selectedOnboardingProject || onboardingForm.name || "").trim()}
                          >
                            Delete Project
                          </button>
                        </div>
                      </div>
                      <div className="filter-grid">
                        <label>
                          Project Mode
                          <select
                            value={onboardingProjectMode}
                            onChange={(e) => {
                              const nextMode = e.target.value;
                              setOnboardingProjectMode(nextMode);
                              if (nextMode === "new") {
                                resetNewProjectOnboardingDraft();
                              }
                            }}
                          >
                            <option value="existing">Update Existing Project</option>
                            <option value="new">Create New Project</option>
                          </select>
                        </label>
                        <div style={{ display: "flex", alignItems: "end" }}>
                          <button type="button" className="button-secondary" onClick={resetNewProjectOnboardingDraft}>
                            Clear Form
                          </button>
                        </div>
                      </div>
                      <p className="subtitle"><strong>Next:</strong> Save monitoring, then add Service Knowledge in Documents & Rules.</p>
                      {onboardingDocumentSummary.total > 0 ? <p className="subtitle"><strong>Docs:</strong> {onboardingDocumentSummary.total} generated ({onboardingDocumentSummary.approved ? "approved" : "pending"}).</p> : null}
                      {onboardingProjectMode === "existing" ? (
                        <div className="filter-grid">
                        <label>
                          Select Existing Project
                          <select
                            value={selectedOnboardingProject}
                            onChange={(e) => {
                              const nextProjectName = e.target.value;
                              setSelectedOnboardingProject(nextProjectName);
                              const row = (onboardingState.rows || []).find((item) => extractOnboardingProjectName(item) === nextProjectName);
                              if (row) {
                                applyProjectOnboardingRow(row);
                                return;
                              }
                              setOnboardingForm((curr) => ({
                                ...curr,
                                name: nextProjectName,
                                assignment_project: nextProjectName,
                              }));
                            }}
                          >
                            <option value="">Select project</option>
                            {onboardingProjectOptions.map((name, index) => (
                              <option key={`project-select-${name}-${index}`} value={name}>{name}</option>
                            ))}
                          </select>
                        </label>
                        </div>
                      ) : null}
                      <form className="form" onSubmit={saveOnboardingConnectivity}>
                        {onboardingValidationErrors.length ? (
                          <div>
                            {onboardingValidationErrors.map((msg, index) => <p key={`onboarding-error-${index}`} className="error">{msg}</p>)}
                          </div>
                        ) : null}
                        {onboardingHasPendingDocumentApproval ? (
                          <p className="error">Approve pending generated documents before submitting another Create/Update.</p>
                        ) : null}
                        {onboardingAdvisory ? <p className="subtitle">{onboardingAdvisory}</p> : null}
                        <details className="setup-form-section" open>
                          <summary>
                            <span>Project Details</span>
                            <small>Required identity fields</small>
                          </summary>
                        <div className="filter-grid">
                          <label>Project Name *<input placeholder="example-payments" value={onboardingForm.name} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, name: e.target.value, assignment_project: e.target.value }))} /></label>
                          <label>Business Service<input placeholder="Payments checkout" value={onboardingForm.business_service} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, business_service: e.target.value }))} /></label>
                          <label>Owner Team *<input placeholder="sre-platform" value={onboardingForm.owner_team} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, owner_team: e.target.value }))} /></label>
                          <label>Owner Email<input type="email" placeholder="payments-sre@example.com" value={onboardingForm.owner_email} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, owner_email: e.target.value }))} /></label>
                          <label>Environment<select value={onboardingForm.environment} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, environment: e.target.value }))}><option value="dev">dev</option><option value="staging">staging</option><option value="prod">prod</option></select></label>
                          <label>Region *<input placeholder="ap-south-1" value={onboardingForm.region} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, region: e.target.value }))} /></label>
                          <label>Business Criticality<select value={onboardingForm.criticality} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, criticality: e.target.value }))}><option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option></select></label>
                          <label>Cost Center<input placeholder="CC-PLATFORM-01" value={onboardingForm.cost_center} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, cost_center: e.target.value }))} /></label>
                          <label>Source Repository<input type="url" placeholder="https://github.com/org/service" value={onboardingForm.repository_url} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, repository_url: e.target.value }))} /></label>
                        </div>
                        <label>Application Description<textarea rows={3} placeholder="Purpose, customers, dependencies, SLOs, and operational boundaries." value={onboardingForm.description} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, description: e.target.value }))} /></label>
                        <details className="setup-nested-details">
                          <summary>Advanced Settings (Optional)</summary>
                          <div className="filter-grid" style={{ marginTop: 10 }}>
                            <label>Deployment
                              <select value={onboardingForm.deployment_mode} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, deployment_mode: e.target.value }))}>
                                <option value="cloud_neutral">Cloud neutral / portable</option>
                                <option value="on_prem">On-premises</option>
                                <option value="private_cloud">Private cloud</option>
                                <option value="aws_cloud">AWS</option>
                                <option value="azure_cloud">Azure</option>
                                <option value="gcp_cloud">Google Cloud</option>
                              </select>
                            </label>
                            <label>Assign User (optional)<input placeholder="username" value={onboardingForm.assignment_username} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, assignment_username: e.target.value }))} /></label>
                          </div>
                          {onboardingForm.deployment_mode === "azure_cloud" ? (
                            <div className="filter-grid" style={{ marginTop: 10 }}>
                              <label>Azure Subscription ID<input value={onboardingForm.azure_subscription_id} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_subscription_id: e.target.value }))} /></label>
                              <label>Azure Resource Group<input value={onboardingForm.azure_resource_group} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_resource_group: e.target.value }))} /></label>
                              <label>Service Bus Namespace<input value={onboardingForm.azure_service_bus_namespace} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_service_bus_namespace: e.target.value }))} /></label>
                              <label>Service Bus Topic<input value={onboardingForm.azure_service_bus_topic} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_service_bus_topic: e.target.value }))} /></label>
                              <label>Service Bus Subscription<input value={onboardingForm.azure_service_bus_subscription} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_service_bus_subscription: e.target.value }))} /></label>
                            </div>
                          ) : null}
                          {onboardingForm.deployment_mode === "azure_cloud" ? (
                            <div className="filter-grid" style={{ marginTop: 10 }}>
                              <label>Azure Content Safety
                                <select value={String(onboardingForm.azure_content_safety_enabled)} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_content_safety_enabled: e.target.value === "true" }))}>
                                  <option value="false">disabled</option>
                                  <option value="true">enabled</option>
                                </select>
                              </label>
                              <label>Content Safety Endpoint<input value={onboardingForm.azure_content_safety_endpoint} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_content_safety_endpoint: e.target.value }))} /></label>
                            </div>
                          ) : null}
                        </details>
                        </details>
                        <details className="setup-form-section" open>
                          <summary>
                            <span>Monitoring Option</span>
                            <small>Choose one</small>
                          </summary>
                          <div className="panel-head">
                            <h3>Monitoring Option</h3>
                          </div>
                          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                            <button
                              type="button"
                              className={onboardingForm.onboarding_path === "setup_monitoring" ? "button-primary" : "button-secondary"}
                              onClick={() => {
                                setOnboardingForm((curr) => ({
                                  ...curr,
                                  onboarding_path: "setup_monitoring",
                                  start_rule_onboarding: true,
                                  monitoring_tool: "prometheus",
                                  prometheus_url: curr.monitoring_url,
                                }));
                                setNewRulePipelineForm((curr) => ({ ...curr, selected_tool: "prometheus" }));
                                setExistingRulePipelineForm((curr) => ({ ...curr, platform: "prometheus" }));
                              }}
                            >
                              Configure Prometheus Rules
                            </button>
                            <button
                              type="button"
                              className={onboardingForm.onboarding_path === "existing_monitoring" ? "button-primary" : "button-secondary"}
                              onClick={() => setOnboardingForm((curr) => ({ ...curr, onboarding_path: "existing_monitoring", start_rule_onboarding: false }))}
                            >
                              Use Existing Monitoring Tool
                            </button>
                          </div>
                          <p className="subtitle" style={{ marginTop: 8 }}>
                            {onboardingForm.onboarding_path === "setup_monitoring"
                              ? "KaiMS will generate Prometheus rules from the Documents & Rules step."
                              : "Keep your current monitoring tool and send alert webhooks to the KaiMS landing pad."}
                          </p>
                          <div className="setup-message-bus-preview">
                            <div className="setup-route-strip" aria-label="Landing pad event route">
                              <span>Monitoring Tool</span>
                              <i />
                              <span>Landing Pad</span>
                              <i />
                              <span>Alert Workflow</span>
                              <i />
                              <span>Workers</span>
                            </div>
                            <p className="subtitle">
                              Routing is configured after this setup is saved.
                            </p>
                            <details className="setup-bus-details">
                              <summary>Event Bus Topology</summary>
                              <MessageBusTopology
                                actual={messageBusActual}
                                configuredRows={messageBusTopicRows}
                                routing={observedRouting}
                                primaryTopic={onboardingForm.azure_service_bus_topic || "raw-alerts"}
                                compact
                              />
                            </details>
                            <details className="setup-bus-details">
                              <summary>Scale And VM Config</summary>
                              <div className="scale-current-config">
                                <strong>Current Compose Default</strong>
                                <span>1 orchestrator/master container with <code>MESSAGE_BUS_WORKER_COUNT=1</code> per service. The scale overlay raises service worker counts without changing onboarding flow.</span>
                              </div>
                              <div className="scale-guide-grid">
                                {SCALE_CAPACITY_GUIDE.map((row) => (
                                  <div className="scale-guide-card" key={row.rate}>
                                    <div className="scale-guide-rate">
                                      <strong>{row.rate}</strong>
                                      <span>{row.perSecond}</span>
                                    </div>
                                    <dl>
                                      <div>
                                        <dt>Masters</dt>
                                        <dd>{row.masters}</dd>
                                      </div>
                                      <div>
                                        <dt>Workers</dt>
                                        <dd>{row.workers}</dd>
                                      </div>
                                      <div>
                                        <dt>VM Config</dt>
                                        <dd>{row.vm}</dd>
                                      </div>
                                      <div>
                                        <dt>Runtime Config</dt>
                                        <dd><code>{row.config}</code></dd>
                                      </div>
                                      <div>
                                        <dt>State Services</dt>
                                        <dd>{row.state}</dd>
                                      </div>
                                    </dl>
                                  </div>
                                ))}
                              </div>
                              <div className="scale-guide-command">
                                <strong>Compose overlay</strong>
                                <code>docker compose --env-file .env -f docker-compose.yml -f docker-compose.external-state.yml -f docker-compose.scale.yml up -d --build</code>
                              </div>
                            </details>
                          </div>
                        </details>
                        <details className="setup-form-section">
                          <summary>
                            <span>Landing Pad Details</span>
                            <small>Endpoint and sample payload for alert ingestion</small>
                          </summary>
                          <div className="panel-head">
                            <h3>Landing Pad Details</h3>
                            <p>Endpoint and payload guidance for alert ingestion into the KaiMS workflow. Troubleshooting runbooks for ingested alerts are managed under Alert Knowledge.</p>
                          </div>
                          <div className="filter-grid">
                            <label>Ingestion Endpoint (UI/Gateway)
                              <input value={onboardingLandingPadDetails.externalIngestionEndpoint} readOnly />
                            </label>
                            <label>Ingestion Endpoint (Container Network)
                              <input value={onboardingLandingPadDetails.internalIngestionEndpoint} readOnly />
                            </label>
                            <label>Method
                              <input value={onboardingLandingPadDetails.method} readOnly />
                            </label>
                            <label>Content Type
                              <input value={onboardingLandingPadDetails.contentType} readOnly />
                            </label>
                            {onboardingForm.onboarding_path === "existing_monitoring" ? (
                              <>
                                <label>Selected Monitoring Tool
                                  <input value={onboardingLandingPadDetails.selectedTool} readOnly />
                                </label>
                                <label>Configured Tool Endpoint
                                  <input value={onboardingLandingPadDetails.configuredEndpoint} readOnly />
                                </label>
                              </>
                            ) : null}
                          </div>
                          <p className="subtitle"><strong>Optional Header:</strong> {onboardingLandingPadDetails.traceHeader}</p>
                          <p className="subtitle"><strong>Required Body:</strong> JSON payload with an alerts array.</p>
                          <p className="subtitle"><strong>Flow Note:</strong> {onboardingLandingPadDetails.routeMessage}</p>
                          {onboardingLandingPadDetails.onboardingPath === "existing_monitoring" ? (
                            <p className="subtitle">Use this endpoint from your monitoring platform webhook to start landing-pad ingestion.</p>
                          ) : (
                            <p className="subtitle">Rule setup path is selected; this endpoint becomes active after rule and monitoring setup are completed.</p>
                          )}
                          <pre className="result">{onboardingLandingPadDetails.samplePayload}</pre>
                        </details>
                        <details className="setup-form-section">
                          <summary>
                            <span>Connection Details</span>
                            <small>Endpoint metadata</small>
                          </summary>
                        <div className="filter-grid">
                          {onboardingForm.onboarding_path === "existing_monitoring" ? (
                            <label>
                              Monitoring Tool
                              <select
                                value={onboardingForm.monitoring_tool}
                                onChange={(e) => {
                                  const nextTool = e.target.value;
                                  setOnboardingForm((curr) => ({
                                    ...curr,
                                    monitoring_tool: nextTool,
                                    prometheus_url: nextTool === "prometheus" ? curr.monitoring_url : "",
                                    new_relic_url: nextTool === "new_relic" ? curr.monitoring_url : "",
                                    datadog_url: nextTool === "datadog" ? curr.monitoring_url : "",
                                  }));
                                  setNewRulePipelineForm((curr) => ({ ...curr, selected_tool: nextTool }));
                                  setExistingRulePipelineForm((curr) => ({ ...curr, platform: nextTool }));
                                }}
                              >
                                <option value="prometheus">Prometheus</option>
                                <option value="new_relic">New Relic</option>
                                <option value="datadog">Datadog</option>
                              </select>
                            </label>
                          ) : (
                            <label>
                              Monitoring Tool
                              <input value="prometheus" readOnly />
                            </label>
                          )}
                          <label>
                            {onboardingForm.onboarding_path === "setup_monitoring" ? "Prometheus Endpoint URL" : "Tool Endpoint URL (optional)"}
                            <input
                              value={onboardingForm.monitoring_url}
                              placeholder="http://prometheus:9090"
                              onBlur={(e) => {
                                const normalized = simplifyMonitoringUrl(e.target.value);
                                setOnboardingForm((curr) => ({
                                  ...curr,
                                  monitoring_url: normalized,
                                  prometheus_url: curr.monitoring_tool === "prometheus" ? normalized : "",
                                  new_relic_url: curr.monitoring_tool === "new_relic" ? normalized : "",
                                  datadog_url: curr.monitoring_tool === "datadog" ? normalized : "",
                                }));
                                setExistingRulePipelineForm((curr) => ({ ...curr, connection_url: normalized }));
                              }}
                              onChange={(e) => setOnboardingForm((curr) => ({ ...curr, monitoring_url: e.target.value }))}
                            />
                            <span className="field-hint">
                              {onboardingForm.onboarding_path === "setup_monitoring"
                                ? "Required for Prometheus rule setup. In Docker Compose, use http://prometheus:9090."
                                : "Optional. If provided, KaiMS stores endpoint metadata for your existing monitoring tool."}
                            </span>
                          </label>
                          <section className="credential-config" aria-labelledby="credential-config-title">
                            <header>
                              <div><span className="discovery-eyebrow">Secure connection</span><h4 id="credential-config-title">Authentication &amp; credentials</h4><p>Connect using an identity or a reference to an existing secret. KaiMS never asks for or displays the secret value.</p></div>
                              <span className={`credential-security-state ${onboardingForm.connection_auth_type === "none" ? "is-neutral" : "is-secure"}`}>{onboardingForm.connection_auth_type === "none" ? "No authentication" : "Reference only"}</span>
                            </header>
                            <div className="credential-method-grid">
                              <label>Authentication method<select value={onboardingForm.connection_auth_type} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, connection_auth_type: e.target.value, connection_secret_ref: e.target.value === "none" || e.target.value === "managed_identity" ? "" : curr.connection_secret_ref }))}><option value="none">No authentication</option><option value="managed_identity">Azure managed identity</option><option value="bearer">Bearer token</option><option value="api_key">API key</option><option value="basic">Username and password</option><option value="oauth2">OAuth 2 client credentials</option></select><span className="field-hint">Choose the method required by the monitoring endpoint.</span></label>
                              {!['none', 'managed_identity'].includes(onboardingForm.connection_auth_type) ? <label>Secret manager<select value={onboardingForm.connection_secret_store || "azure_key_vault"} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, connection_secret_store: e.target.value, connection_secret_ref: "" }))}><option value="azure_key_vault">Azure Key Vault</option><option value="hashicorp_vault">HashiCorp Vault</option><option value="aws_secrets_manager">AWS Secrets Manager</option><option value="kubernetes_secret">Kubernetes Secret</option></select><span className="field-hint">The runtime identity must have read access to this reference.</span></label> : null}
                            </div>
                            {onboardingForm.connection_auth_type === "managed_identity" ? <div className="credential-managed-identity"><strong>Managed identity selected</strong><span>KaiMS will use the workload identity assigned to the runtime. No stored secret is required.</span></div> : null}
                            {!['none', 'managed_identity'].includes(onboardingForm.connection_auth_type) ? <label className="credential-reference-field">Secret reference<input spellCheck="false" autoComplete="off" placeholder={onboardingForm.connection_secret_store === "hashicorp_vault" ? "vault://kv/data/observability/prometheus#token" : onboardingForm.connection_secret_store === "aws_secrets_manager" ? "aws-sm://prod/observability/prometheus#api-key" : onboardingForm.connection_secret_store === "kubernetes_secret" ? "k8s-secret://monitoring/prometheus-credentials#token" : "azure-kv://kaims-prod/observability-prometheus/token"} value={onboardingForm.connection_secret_ref} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, connection_secret_ref: e.target.value }))} /><span className="field-hint">Paste the secret URI, not its value. Expected format includes the vault or namespace, secret name, and optional key/version.</span></label> : null}
                            <footer><span aria-hidden="true"><CircleCheckBig size={16} strokeWidth={2.5} /></span><p><strong>Secrets stay outside KaiMS.</strong> Only this reference is saved with the application configuration and passed to authorized runtime connectors.</p></footer>
                          </section>
                          <label>Network Zone<input placeholder="prod-private / vnet name" value={onboardingForm.network_zone} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, network_zone: e.target.value }))} /></label>
                          <label>Health Check URL<input type="url" placeholder="https://service/health" value={onboardingForm.healthcheck_url} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, healthcheck_url: e.target.value }))} /></label>
                        </div>
                        <div className="onboarding-source-grid">
                          <label>Logs Source<input type="url" placeholder="https://opensearch.example.com" value={onboardingForm.logs_url} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, logs_url: e.target.value }))} /><span>OpenSearch, Loki, Splunk, or compatible endpoint</span></label>
                          <label>Trace Source<input type="url" placeholder="https://jaeger.example.com" value={onboardingForm.traces_url} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, traces_url: e.target.value }))} /><span>Jaeger, Tempo, or tracing gateway</span></label>
                          <label>Telemetry / OTLP<input type="url" placeholder="https://otel-collector:4318" value={onboardingForm.telemetry_url} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, telemetry_url: e.target.value }))} /><span>OpenTelemetry collector or observability gateway</span></label>
                          <label>Ticketing / Change Source<input type="url" placeholder="https://jira.example.com" value={onboardingForm.ticketing_url} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, ticketing_url: e.target.value }))} /><span>Incident, change, and historical outcome source</span></label>
                          <label>Email Alert Source<input placeholder="imaps://mail.example.com/INBOX" value={onboardingForm.email_url} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, email_url: e.target.value }))} /><span>IMAP/IMAPS mailbox or HTTPS email webhook; credentials remain secret references</span></label>
                        </div>
                        {onboardingForm.onboarding_path !== "setup_monitoring" ? (
                          <p className="subtitle">Alerts from your configured monitoring tool can be ingested into landing pad to trigger the remaining workflow.</p>
                        ) : null}
                        </details>
                        <button className="button-primary" type="submit" disabled={onboardingState.loading || onboardingValidationErrors.length > 0 || onboardingHasPendingDocumentApproval}>
                          {onboardingState.loading ? "Saving..." : onboardingProjectMode === "new" ? "Create Monitoring Setup" : "Save Monitoring Setup"}
                        </button>
                      </form>
                      {onboardingState.error ? <p className="error">{onboardingState.error}</p> : null}
                      {onboardingState.success ? <p className="subtitle">{onboardingState.success}</p> : null}
                    </article>
                    ) : null}

                    {showProjectStep("docs_rules") ? (
                    <article className="panel">
                      <div className="panel-head">
                        <div>
                          <h3>Guided Setup</h3>
                          <p>Enter the service details once. KaiMS extracts project, monitoring, alert, remediation, rollback, and validation facts.</p>
                        </div>
                        <button type="button" className="button-secondary" onClick={() => setProjectSetupStep("setup")}>Connection Setup</button>
                      </div>
                      <form className="form" onSubmit={saveOnboardingConnectivity}>
                        {onboardingValidationErrors.length ? (
                          <div>
                            {onboardingValidationErrors.map((msg, index) => <p key={`docs-rules-error-${index}`} className="error">{msg}</p>)}
                          </div>
                        ) : null}
                        {onboardingHasPendingDocumentApproval ? (
                          <p className="error">Approve pending generated documents before submitting another update.</p>
                        ) : null}
                        <section className="panel guided-setup-project-panel">
                          <div className="panel-head">
                            <div>
                              <h3>Project & Connection</h3>
                              <p>Select an existing project or create a new one. Prometheus is used when KaiMS creates monitoring rules.</p>
                            </div>
                            <span className={`workflow-pill ${onboardingProjectMode === "new" ? "workflow-pill-active" : "workflow-pill-idle"}`}>
                              {onboardingProjectMode === "new" ? "new project" : "existing project"}
                            </span>
                          </div>
                          <div className="filter-grid">
                            <label>
                              Project Mode
                              <select
                                value={onboardingProjectMode}
                                onChange={(e) => {
                                  const nextMode = e.target.value;
                                  setOnboardingProjectMode(nextMode);
                                  if (nextMode === "new") {
                                    resetNewProjectOnboardingDraft();
                                  }
                                }}
                              >
                                <option value="existing">Update Existing Project</option>
                                <option value="new">Create New Project</option>
                              </select>
                            </label>
                            {onboardingProjectMode === "existing" ? (
                              <label>
                                Select Project
                                <select
                                  value={selectedOnboardingProject}
                                  onChange={(e) => {
                                    const nextProjectName = e.target.value;
                                    setSelectedOnboardingProject(nextProjectName);
                                    const row = (onboardingState.rows || []).find((item) => extractOnboardingProjectName(item) === nextProjectName);
                                    if (row) {
                                      applyProjectOnboardingRow(row);
                                      return;
                                    }
                                    setOnboardingForm((curr) => ({
                                      ...curr,
                                      name: nextProjectName,
                                      assignment_project: nextProjectName,
                                    }));
                                  }}
                                >
                                  <option value="">Select project</option>
                                  {onboardingProjectOptions.map((name, index) => (
                                    <option key={`guided-project-select-${name}-${index}`} value={name}>{name}</option>
                                  ))}
                                </select>
                              </label>
                            ) : null}
                            <label>Project Name *<input placeholder="mysql-exporter" value={onboardingForm.name} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, name: e.target.value, assignment_project: e.target.value }))} /></label>
                            <label>Owner Team *<input placeholder="data-platform" value={onboardingForm.owner_team} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, owner_team: e.target.value }))} /></label>
                            <label>Environment<select value={onboardingForm.environment} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, environment: e.target.value }))}><option value="dev">dev</option><option value="staging">staging</option><option value="prod">prod</option></select></label>
                            <label>Region *<input placeholder="ap-south-1" value={onboardingForm.region} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, region: e.target.value }))} /></label>
                            <label>
                              Setup Path
                              <select
                                value={onboardingForm.onboarding_path}
                                onChange={(e) => {
                                  const nextPath = e.target.value;
                                  const defaultUrl = nextPath === "setup_monitoring" ? "http://prometheus:9090" : onboardingForm.monitoring_url;
                                  setOnboardingForm((curr) => ({
                                    ...curr,
                                    onboarding_path: nextPath,
                                    start_rule_onboarding: nextPath === "setup_monitoring",
                                    monitoring_tool: nextPath === "setup_monitoring" ? "prometheus" : curr.monitoring_tool,
                                    monitoring_url: simplifyMonitoringUrl(defaultUrl || curr.monitoring_url),
                                    prometheus_url: nextPath === "setup_monitoring" ? simplifyMonitoringUrl(defaultUrl || curr.monitoring_url) : curr.prometheus_url,
                                  }));
                                  if (nextPath === "setup_monitoring") {
                                    setNewRulePipelineForm((curr) => ({ ...curr, selected_tool: "prometheus" }));
                                    setExistingRulePipelineForm((curr) => ({ ...curr, platform: "prometheus", connection_url: simplifyMonitoringUrl(defaultUrl || "") }));
                                  }
                                }}
                              >
                                <option value="setup_monitoring">Create Prometheus Rules</option>
                                <option value="existing_monitoring">Use Existing Monitoring Webhook</option>
                              </select>
                            </label>
                            {onboardingForm.onboarding_path === "existing_monitoring" ? (
                              <label>
                                Monitoring Tool
                                <select
                                  value={onboardingForm.monitoring_tool}
                                  onChange={(e) => {
                                    const nextTool = e.target.value;
                                    setOnboardingForm((curr) => ({
                                      ...curr,
                                      monitoring_tool: nextTool,
                                      prometheus_url: nextTool === "prometheus" ? curr.monitoring_url : "",
                                      new_relic_url: nextTool === "new_relic" ? curr.monitoring_url : "",
                                      datadog_url: nextTool === "datadog" ? curr.monitoring_url : "",
                                    }));
                                    setNewRulePipelineForm((curr) => ({ ...curr, selected_tool: nextTool }));
                                    setExistingRulePipelineForm((curr) => ({ ...curr, platform: nextTool }));
                                  }}
                                >
                                  <option value="prometheus">Prometheus</option>
                                  <option value="new_relic">New Relic</option>
                                  <option value="datadog">Datadog</option>
                                </select>
                              </label>
                            ) : (
                              <label>Monitoring Tool<input value="Prometheus" readOnly /></label>
                            )}
                            <label>
                              Prometheus / Tool URL
                              <input
                                value={onboardingForm.monitoring_url}
                                placeholder="http://prometheus:9090"
                                onBlur={(e) => {
                                  const normalized = simplifyMonitoringUrl(e.target.value || (onboardingForm.onboarding_path === "setup_monitoring" ? "http://prometheus:9090" : ""));
                                  setOnboardingForm((curr) => ({
                                    ...curr,
                                    monitoring_url: normalized,
                                    prometheus_url: curr.monitoring_tool === "prometheus" ? normalized : "",
                                    new_relic_url: curr.monitoring_tool === "new_relic" ? normalized : "",
                                    datadog_url: curr.monitoring_tool === "datadog" ? normalized : "",
                                  }));
                                  setExistingRulePipelineForm((curr) => ({ ...curr, connection_url: normalized }));
                                }}
                                onChange={(e) => setOnboardingForm((curr) => ({ ...curr, monitoring_url: e.target.value }))}
                              />
                            </label>
                          </div>
                        </section>
                        <details className="setup-form-section setup-source-doc-panel knowledge-guided-panel" open>
                          <summary>
                            <span>Setup Prompt</span>
                            <small>Describe, auto-complete, score, validate</small>
                          </summary>
                          <div className="panel-head">
                            <div>
                              <h3>Tell KaiMS What To Set Up</h3>
                              <p>Paste a short description or runbook notes. KaiMS will complete the setup form and ask only for missing or low-confidence fields.</p>
                            </div>
                            <button
                              type="button"
                              className="button-secondary"
                              onClick={applyUploadedDocumentsToRuleIntent}
                              disabled={!onboardingDerivedRequirements.length}
                            >
                              Apply To Rules
                            </button>
                          </div>
                          <div className="setup-flow-rail">
                            <div className={`setup-flow-node ${onboardingSourceDocCount > 0 ? "complete" : "active"}`}>
                              <strong>Describe</strong>
                              <span>{onboardingSourceDocCount > 0 ? "Input captured" : "Prompt or file"}</span>
                            </div>
                            <div className={`setup-flow-node ${onboardingKnowledgePack ? "complete" : ""}`}>
                              <strong>Score</strong>
                              <span>{onboardingKnowledgePack ? `${Math.round(Number(correctedKnowledgeConfidence || 0) * 100)}% document score` : "Waiting"}</span>
                            </div>
                            <div className={`setup-flow-node ${knowledgePackState.approved ? "complete" : ""}`}>
                              <strong>Update</strong>
                              <span>{knowledgePackState.approved ? "Knowledge updated" : knowledgeReviewReady ? "Ready to validate" : "Needs placeholders"}</span>
                            </div>
                          </div>
                          <div className="knowledge-guided-prompt">
                            <label>
                              Setup Details
                              <textarea
                                rows={7}
                                placeholder="Example: Set up monitoring for mysql-exporter in prod. Owner is data-platform. Prometheus URL is http://prometheus:9090. Alert when exporter is down for 5 minutes or table rows grow unexpectedly. Dependencies are MySQL, Prometheus, and Grafana. Validate /metrics, Prometheus target up, DB connectivity, and row-count query. Rollback by restoring previous exporter config and restarting exporter."
                                value={onboardingForm.service_knowledge_prompt}
                                onChange={(event) => setOnboardingForm((curr) => ({ ...curr, service_knowledge_prompt: event.target.value }))}
                              />
                              <span className="field-hint">Use plain English. KaiMS extracts setup fields, creates placeholders for missing values, and prepares rules from this prompt.</span>
                            </label>
                            <button
                              type="button"
                              className="button-primary"
                              onClick={draftKnowledgePackFromPrompt}
                              disabled={knowledgePackState.loading || !String(onboardingForm.service_knowledge_prompt || "").trim()}
                            >
                              {knowledgePackState.loading ? "Extracting..." : "Auto-Complete Setup"}
                            </button>
                          </div>
                          <p className="knowledge-review-status">{knowledgeReviewSummary}</p>
                          {onboardingKnowledgePack ? (
                            <div className="alert-rule-summary-grid">
                              <article className="alert-rule-summary-card">
                                <span>Document Score</span>
                                <strong>{Math.round(Number(correctedKnowledgeConfidence || 0) * 100)}%</strong>
                                <small>{knowledgeReviewReady ? "ready to validate" : `${knowledgeReviewFields.length} placeholder(s) need input`}</small>
                              </article>
                              <article className="alert-rule-summary-card">
                                <span>Setup Identity</span>
                                <strong>{onboardingForm.name || "-"}</strong>
                                <small>{onboardingForm.owner_team || "-"} | {onboardingForm.environment || "-"}</small>
                              </article>
                              <article className="alert-rule-summary-card">
                                <span>Rules Draft</span>
                                <strong>{onboardingRulePromptLines.length}</strong>
                                <small>plain-English rule intent(s)</small>
                              </article>
                            </div>
                          ) : null}
                          <details className="admin-collapsible knowledge-supporting-docs">
                            <summary>Optional supporting file</summary>
                            <div className="knowledge-pack-panel">
                              <div className="knowledge-pack-upload">
                              <label className="source-doc-upload-card source-doc-upload-card-wide">
                                <span>Add a runbook, ticket export, or notes file</span>
                                <input
                                  type="file"
                                  accept=".txt,.md,.markdown,.json,.csv,.log,.yaml,.yml"
                                  onChange={(e) => handleOnboardingSourceDocuments(e.target.files, "knowledge_pack")}
                                />
                                <small>Optional. Use this only when the prompt does not contain enough detail.</small>
                              </label>
                              <div className="knowledge-pack-samples">
                                <a className="source-doc-download" href={ONBOARDING_SOURCE_DOC_SAMPLE_FILES.troubleshooting.href} download>
                                  Download sample file
                                </a>
                              </div>
                            </div>
                            <div className="knowledge-pack-status">
                              <span className={`workflow-pill ${onboardingKnowledgePack?.status === "ready" || knowledgePackState.approved ? "workflow-pill-active" : "workflow-pill-idle"}`}>
                                {knowledgePackState.approved ? "approved" : onboardingKnowledgePack?.status || "waiting"}
                              </span>
                              <strong>{onboardingSourceDocCount > 0 ? "Input ready" : "No supporting file"}</strong>
                              <small>Confidence {Math.round(Number(correctedKnowledgeConfidence || 0) * 100)}%</small>
                            </div>
                            </div>
                          </details>
                          {onboardingSourceDocs.loading ? <p className="subtitle">Reading uploaded file...</p> : null}
                          {onboardingSourceDocs.error ? <p className="error">{onboardingSourceDocs.error}</p> : null}
                          {knowledgePackState.loading ? <p className="subtitle">Validating Service Knowledge...</p> : null}
                          {knowledgePackState.error ? <p className="error">{knowledgePackState.error}</p> : null}
                          {knowledgePackState.success ? <p className="subtitle">{knowledgePackState.success}</p> : null}
                          {onboardingKnowledgePack ? (
                            <div className="knowledge-pack-review">
                              <div className="panel-head">
                                <div>
                                  <h3>Review Extracted Details</h3>
                                  <p>Fill placeholders or correct extracted details. Validation updates trusted Alert Knowledge and unlocks document/rule generation.</p>
                                </div>
                                <button
                                  type="button"
                                  className="button-secondary"
                                  onClick={revalidateKnowledgeCorrections}
                                  disabled={knowledgePackRevalidation.loading || !Object.keys(knowledgePackCorrections).length}
                                  title="Re-check your manual edits against the uploaded documents before approving."
                                >
                                  {knowledgePackRevalidation.loading ? "Checking against document..." : "Check Edits Against Document"}
                                </button>
                                <button
                                  type="button"
                                  className="button-primary"
                                  onClick={approveKnowledgePack}
                                  disabled={knowledgePackState.loading || !onboardingSourceDocCount || !knowledgeReviewReady}
                                  title={!knowledgeReviewReady ? "Fill the requested missing details, then Check Edits Against Document before approving." : ""}
                                >
                                  Validate & Update Knowledge
                                </button>
                              </div>
                              {knowledgePackRevalidation.error ? (
                                <p className="error">{knowledgePackRevalidation.error}</p>
                              ) : null}
                              {knowledgeReviewFields.length ? (
                                <div className="knowledge-pack-fix-panel">
                                  <div>
                                    <strong>Questions To Complete Validation</strong>
                                    <span>Complete these placeholders so the saved document has enough evidence and operator-safe remediation context.</span>
                                  </div>
                                  <div className="knowledge-pack-fix-grid">
                                    {knowledgeReviewFields.map(([key, fact]) => (
                                      <label key={`docs-rules-fix-${key}`}>
                                        {KNOWLEDGE_FACT_QUESTIONS[key] || `Provide ${KNOWLEDGE_FACT_LABELS[key] || key.replaceAll("_", " ")}`}
                                        <textarea
                                          rows={KNOWLEDGE_LIST_FACTS.has(key) ? 3 : 2}
                                          placeholder={KNOWLEDGE_FACT_HINTS[key] || "Provide the correct value"}
                                          value={knowledgeFactEditValue(key, fact)}
                                          onChange={(event) => updateKnowledgeFactCorrection(key, event.target.value)}
                                        />
                                        <small>Extracted: {knowledgeFactDisplayValue(fact)} | confidence {Math.round(Number(fact?.confidence || 0) * 100)}%</small>
                                      </label>
                                    ))}
                                  </div>
                                </div>
                              ) : (
                                <p className="subtitle">All required details are accepted. You can approve Service Knowledge.</p>
                              )}
                              <div className="table-wrap">
                                <table>
                                  <thead>
                                    <tr><th>Detail</th><th>Editable Value</th><th>Confidence</th><th>Status</th></tr>
                                  </thead>
                                  <tbody>
                                    {Object.entries(correctedKnowledgeFacts).map(([key, fact]) => (
                                      <tr key={`docs-rules-fact-${key}`}>
                                        <td>{key.replaceAll("_", " ")}</td>
                                        <td>
                                          <textarea
                                            className="inline-table-editor"
                                            rows={KNOWLEDGE_LIST_FACTS.has(key) ? 3 : 1}
                                            placeholder={KNOWLEDGE_FACT_HINTS[key] || "Provide the correct value"}
                                            value={knowledgeFactEditValue(key, fact)}
                                            onChange={(event) => updateKnowledgeFactCorrection(key, event.target.value)}
                                          />
                                        </td>
                                        <td>{Math.round(Number(fact?.confidence || 0) * 100)}%</td>
                                        <td>{String(fact?.status || "needs_review").replaceAll("_", " ")}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            </div>
                          ) : null}
                        </details>
                        <details className={`setup-form-section rule-prompt-panel ${onboardingRulePromptVisible ? "ready" : "locked"}`} open={onboardingRulePromptVisible}>
                          <summary>
                            <span>Rules</span>
                            <small>{onboardingRulePromptVisible ? "Review and edit before generating" : "Upload Service Knowledge or type rule intent"}</small>
                          </summary>
                          <div className="panel-head">
                            <div>
                              <h3>Rule Intent</h3>
                              <p>Use extracted hints or type plain-English rules. KaiMS previews the Prometheus format before generation.</p>
                            </div>
                            <span className={`workflow-pill ${onboardingRulePromptVisible ? "workflow-pill-active" : "workflow-pill-idle"}`}>
                              {onboardingRulePromptVisible ? "ready" : "optional"}
                            </span>
                          </div>
                          {onboardingRulePromptLines.length ? (
                            <div className="generated-rule-preview">
                              {onboardingRulePromptLines.slice(0, 4).map((line, index) => (
                                <span key={`docs-rules-prompt-line-${index}`}>{line}</span>
                              ))}
                            </div>
                          ) : null}
                          <label>
                            Rule Intent
                            <textarea
                              rows={5}
                              placeholder="Example: Alert when mysql exporter is down for 5 minutes."
                              value={onboardingForm.rule_onboarding_plain_language}
                              onChange={(e) => {
                                const nextText = e.target.value;
                                setOnboardingForm((curr) => ({ ...curr, rule_onboarding_plain_language: nextText }));
                                setNewRulePipelineForm((curr) => ({ ...curr, requirements_text: nextText }));
                              }}
                            />
                          </label>
                          {onboardingForm.onboarding_path === "setup_monitoring" ? (
                            <div className="knowledge-pack-review">
                              <div className="panel-head">
                                <div>
                                  <h3>Prometheus Rule Preview</h3>
                                  <p>Final rules are validated by the backend and written to the Prometheus rules workspace.</p>
                                </div>
                                <span className="workflow-pill workflow-pill-active">yaml</span>
                              </div>
                              <pre className="result">{onboardingPrometheusRulePreview}</pre>
                            </div>
                          ) : null}
                        </details>
                        <button
                          className="button-primary"
                          type="submit"
                          disabled={onboardingState.loading || onboardingValidationErrors.length > 0 || onboardingHasPendingDocumentApproval || knowledgeHasUnvalidatedInput}
                          title={knowledgeHasUnvalidatedInput ? "Validate and save extracted Alert Knowledge first." : ""}
                        >
                          {onboardingState.loading ? "Generating..." : "Generate Documents & Rules"}
                        </button>
                        {knowledgeHasUnvalidatedInput ? (
                          <p className="subtitle onboarding-review-warning">Validation required: answer the questions above and click Validate & Save Knowledge before generating artifacts.</p>
                        ) : null}
                        {!knowledgeHasUnvalidatedInput && onboardingValidationErrors.length > 0 ? (
                          <p className="subtitle onboarding-review-warning">{onboardingValidationErrors[0]}</p>
                        ) : null}
                      </form>
                      {onboardingState.error ? <p className="error">{onboardingState.error}</p> : null}
                      {onboardingState.success ? <p className="subtitle">{onboardingState.success}</p> : null}
                    </article>
                    ) : null}

                    {(showProjectStep("review") || (adminWorkspace === "project" && projectSetupStep === "docs_rules" && onboardingGeneratedDocs.length > 0)) ? (
                    <article className="panel onboarding-review-panel">
                      <div className="panel-head">
                        <h3>Generated Rules, Docs, and Metadata Review (Required)</h3>
                        <div style={{ display: "flex", gap: 8 }}>
                          <button
                            type="button"
                            className="button-secondary"
                            onClick={() => {
                              setOnboardingGeneratedDocs([]);
                              setOnboardingDocApprovalState({ loading: false, error: "", success: "", approved: false });
                            }}
                            disabled={!onboardingGeneratedDocs.length || onboardingDocApprovalState.loading}
                          >
                            Clear
                          </button>
                          <button
                            type="button"
                            className="button-primary"
                            onClick={approveGeneratedOnboardingDocuments}
                            disabled={!onboardingGeneratedDocs.length || onboardingDocApprovalState.loading || onboardingDocApprovalState.approved || !onboardingReviewGate.allReviewed}
                          >
                            {onboardingDocApprovalState.loading ? "Approving..." : onboardingDocApprovalState.approved ? "Approved" : "Approve Documents"}
                          </button>
                        </div>
                      </div>
                      <p className="subtitle">After Create/Update Project: review generated artifacts, confirm each checklist item, then click Approve Documents.</p>
                      <section className="onboarding-activation-summary" aria-label="Application configuration review">
                        <div><span>Application</span><strong>{onboardingForm.name || "Not supplied"}</strong><small>{onboardingForm.business_service || onboardingForm.description || "Business context not supplied"}</small></div>
                        <div><span>Ownership</span><strong>{onboardingForm.owner_team || "Not supplied"}</strong><small>{onboardingForm.owner_email || "Owner email not supplied"}</small></div>
                        <div><span>Runtime</span><strong>{onboardingForm.environment} · {onboardingForm.region}</strong><small>{onboardingForm.network_zone || onboardingForm.deployment_mode}</small></div>
                        <div><span>Monitoring</span><strong>{onboardingForm.monitoring_tool}</strong><small>{[onboardingForm.logs_url && "logs", onboardingForm.traces_url && "traces", onboardingForm.telemetry_url && "telemetry", onboardingForm.ticketing_url && "ITSM/Jira", onboardingForm.email_url && "email"].filter(Boolean).join(", ") || "primary source only"}</small></div>
                        <div><span>Context policy</span><strong>{onboardingForm.context_strategy}</strong><small>{onboardingForm.context_strategy === "realtime" ? "Collect fresh context for every alert" : onboardingForm.context_strategy === "historical" ? "Use periodic historical snapshots only" : "Reuse complete context; refresh only when needed"}</small></div>
                        <div><span>Credentials</span><strong>{onboardingForm.connection_auth_type}</strong><small>{onboardingForm.connection_secret_ref || "No secret reference required"}</small></div>
                      </section>
                      <div className="filter-grid onboarding-review-checklist" style={{ marginBottom: 8 }}>
                        <label>
                          <input
                            type="checkbox"
                            checked={onboardingReviewAck.rules}
                            onChange={(e) => setOnboardingReviewAck((current) => ({ ...current, rules: e.target.checked }))}
                            disabled={!onboardingGeneratedRuleRows.length}
                          />
                          I reviewed generated rules
                        </label>
                        <label>
                          <input
                            type="checkbox"
                            checked={onboardingReviewAck.docs}
                            onChange={(e) => setOnboardingReviewAck((current) => ({ ...current, docs: e.target.checked }))}
                            disabled={!onboardingGeneratedDocs.length}
                          />
                          I reviewed generated docs
                        </label>
                        <label>
                          <input
                            type="checkbox"
                            checked={onboardingReviewAck.metadata}
                            onChange={(e) => setOnboardingReviewAck((current) => ({ ...current, metadata: e.target.checked }))}
                            disabled={!onboardingMetadataRows.length}
                          />
                          I reviewed generated metadata
                        </label>
                      </div>
                      {!onboardingReviewGate.allReviewed ? <p className="subtitle onboarding-review-warning">Approval is locked until all available review checkboxes are confirmed.</p> : null}
                      {onboardingDocApprovalState.error ? <p className="error">{onboardingDocApprovalState.error}</p> : null}
                      {onboardingDocApprovalState.success ? <p className="subtitle">{onboardingDocApprovalState.success}</p> : null}
                      {!onboardingGeneratedDocs.length ? (
                        <p className="subtitle">No documents pending review.</p>
                      ) : (
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>Kind</th>
                                <th>Title</th>
                                <th>Summary</th>
                              </tr>
                            </thead>
                            <tbody>
                              {onboardingGeneratedDocs.map((doc, index) => (
                                <tr key={`onboarding-doc-${index}`}>
                                  <td>{String(doc?.kind || "-")}</td>
                                  <td>{String(doc?.title || "-")}</td>
                                  <td>{String(doc?.summary || "-")}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                      {onboardingGeneratedDocs.length ? (
                        <details style={{ marginTop: 12 }}>
                          <summary style={{ cursor: "pointer" }}>View Full Documents JSON</summary>
                          <pre className="result">{JSON.stringify(onboardingGeneratedDocs, null, 2)}</pre>
                        </details>
                      ) : null}
                      <details className="onboarding-review-details" style={{ marginTop: 12 }}>
                        <summary style={{ cursor: "pointer" }}>Generated Rules Review ({onboardingGeneratedRuleRows.length})</summary>
                        <div className="table-wrap" style={{ marginTop: 8 }}>
                          <table>
                            <thead>
                              <tr>
                                <th>Name</th>
                                <th>Platform</th>
                                <th>Adapter</th>
                                <th>Severity</th>
                                <th>Status</th>
                                <th>Expression / Query</th>
                              </tr>
                            </thead>
                            <tbody>
                              {onboardingGeneratedRuleRows.map((row) => (
                                <tr key={`generated-rule-${row.id}`}>
                                  <td>{row.name}</td>
                                  <td>{row.platform}</td>
                                  <td>{row.contractMode !== "-" ? `${row.contractMode} / ${row.contractStatus}` : "-"}</td>
                                  <td>{row.severity}</td>
                                  <td>{row.status}</td>
                                  <td>{row.expression || "-"}</td>
                                </tr>
                              ))}
                              {!onboardingGeneratedRuleRows.length ? <tr><td colSpan={6}>No generated rule rows found in latest workflow payload.</td></tr> : null}
                            </tbody>
                          </table>
                        </div>
                      </details>
                      <details className="onboarding-review-details" style={{ marginTop: 12 }}>
                        <summary style={{ cursor: "pointer" }}>Generated Metadata Review ({onboardingMetadataRows.length})</summary>
                        <div className="table-wrap" style={{ marginTop: 8 }}>
                          <table>
                            <thead>
                              <tr>
                                <th>Provider</th>
                                <th>Project</th>
                                <th>Status</th>
                                <th>Updated</th>
                              </tr>
                            </thead>
                            <tbody>
                              {onboardingMetadataRows.map((row) => (
                                <tr key={`generated-meta-${row.id}`}>
                                  <td>{row.provider}</td>
                                  <td>{row.project}</td>
                                  <td>{row.status}</td>
                                  <td>{formatIstTimestamp(row.updated_at)}</td>
                                </tr>
                              ))}
                              {!onboardingMetadataRows.length ? <tr><td colSpan={4}>No metadata rows found for selected project yet.</td></tr> : null}
                            </tbody>
                          </table>
                        </div>
                      </details>
                      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
                        <button type="button" className="button-secondary" onClick={() => setProjectSetupStep("status")}>Next: Workflow Status</button>
                      </div>
                    </article>
                    ) : null}

                    {showProjectStep("status") ? (
                    <article className="panel">
                      <h3>Rule Onboarding Status</h3>
                      <p className="subtitle">Rule onboarding is optional. If enabled above, plain-language requirements are converted into tool-specific rules and documentation automatically.</p>
                      {onboardingDocApprovalState.approved || knowledgePackState.approved || onboardingWorkflowSteps.length > 0 ? (
                        <div className="setup-complete-panel">
                          <div>
                            <span className="workflow-pill workflow-pill-active">ready</span>
                            <h3>{currentOnboardedApplicationName() || "Application"} setup is ready</h3>
                            <p>
                              Monitoring setup, Service Knowledge, generated rules, and approved documents are now connected to the selected application workspace.
                            </p>
                          </div>
                          <div className="setup-complete-actions">
                            <button type="button" className="button-primary" onClick={() => openOnboardedApplicationDashboard()}>
                              Open Application Dashboard
                            </button>
                            <button type="button" className="button-secondary" onClick={() => setProjectSetupStep("docs_rules")}>
                              Back To Documents & Rules
                            </button>
                          </div>
                        </div>
                      ) : null}
                      <HistoricalTicketDiscoveryPanel
                        applicationId={selectedMonitoringAppId}
                        applicationName={currentOnboardedApplicationName() || onboardingForm.name}
                        documents={ragDocs.rows}
                        loading={ragDocs.loading}
                      />
                      <h3>Step-by-Step Workflow Progress</h3>
                      <div className="monitoring-dashboard-cards">
                        {monitoringAppDetails.dashboards.map((row, index) => (
                          <article className="monitoring-dashboard-card" key={`monitoring-dashboard-card-${row.id || index}`}>
                            <span>Generated Dashboard</span>
                            <strong>{row.title || row.dashboard_uid || "Dashboard"}</strong>
                            <small>UID: {row.dashboard_uid || "-"}</small>
                            <small>Updated: {formatIstTimestamp(row.updated_at)}</small>
                            {row.url ? (
                              <button type="button" className="button-secondary" onClick={() => openOnboardedApplicationDashboard(row.url)}>Open Dashboard</button>
                            ) : (
                              <button type="button" className="button-secondary" onClick={() => openOnboardedApplicationDashboard()}>Open Dashboard</button>
                            )}
                          </article>
                        ))}
                        {!monitoringAppDetails.dashboards.length ? (
                          <article className="monitoring-dashboard-card empty">
                            <span>Dashboard Status</span>
                            <strong>No dashboards generated yet</strong>
                            <small>Register an application and validate metrics to generate dashboard references.</small>
                            <button type="button" className="button-secondary" onClick={() => openOnboardedApplicationDashboard()}>Open Application Dashboard</button>
                          </article>
                        ) : null}
                      </div>
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>Step</th>
                              <th>Status</th>
                              <th>What Happened</th>
                              <th>Background</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(() => {
                              const isSetupMonitoring = String(onboardingForm.onboarding_path || "setup_monitoring").trim() === "setup_monitoring";
                              const selectedName = currentOnboardedApplicationName() || onboardingForm.name;
                              const discoveryDoc = findHistoricalTicketDiscoveryDocument(ragDocs.rows, selectedMonitoringAppId, selectedName);
                              const discoveredCount = Number(discoveryDoc?.metadata?.historical_ticket_count || 0);
                              const rows = [];
                              onboardingWorkflowSteps.forEach((row) => rows.push({
                                ...row,
                                source: "workflow",
                                background: explainOnboardingStepBackground(row.step, isSetupMonitoring),
                              }));
                              monitoringAppDetails.history.forEach((row) => {
                                const output = row?.output && typeof row.output === "object" ? row.output : {};
                                rows.push({
                                  step: rows.length + 1,
                                  title: row.event_type || row.agent || "Application audit event",
                                  status: row.status || row.decision || "completed",
                                  source: "audit",
                                  timestamp: row.created_at,
                                  details: {
                                    message: output.message || output.status || `${row.agent || "backend"} recorded ${row.event_type || "an event"}.`,
                                  },
                                  background: `Live application audit event from ${row.agent || "backend"}${row.created_at ? ` at ${formatIstTimestamp(row.created_at)}` : ""}.`,
                                });
                              });
                              if (monitoringAppDetails.validations.length) {
                                const latestValidation = monitoringAppDetails.validations[0];
                                rows.push({
                                  step: rows.length + 1,
                                  title: "Monitoring Validation",
                                  status: latestValidation.metrics_available && latestValidation.target_up ? "completed" : "needs_attention",
                                  source: "validation",
                                  details: {
                                    message: `Target up: ${Boolean(latestValidation.target_up)}; metrics: ${Boolean(latestValidation.metrics_available)}; service discovery: ${Boolean(latestValidation.service_discovery_ok)}.`,
                                  },
                                  background: "Live validation result loaded from the selected application's validation endpoint.",
                                });
                              }
                              if (discoveryDoc) {
                                rows.push({
                                  step: rows.length + 1,
                                  title: "Discover Similar Historical Tickets",
                                  status: "completed",
                                  source: "rag",
                                  details: { message: `${discoveredCount} similar incident match${discoveredCount === 1 ? "" : "es"} used before runbook generation.` },
                                  background: `Dynamic RAG metadata from ${discoveryDoc.title || "the generated runbook"}; strategy: similar-historical-tickets-first.`,
                                });
                                rows.push({
                                  step: rows.length + 1,
                                  title: "Generate Ticket-Grounded Runbook",
                                  status: "completed",
                                  source: "rag",
                                  details: { message: discoveryDoc.title || "Historical-ticket-grounded runbook generated." },
                                  background: "The runbook was generated after incident-only similarity search and context extraction.",
                                });
                              }
                              monitoringAppDetails.dashboards.forEach((row) => rows.push({
                                step: rows.length + 1,
                                title: "Dashboard Generated",
                                status: "completed",
                                source: "dashboard",
                                details: { message: row.title || row.dashboard_uid || "Dashboard reference generated." },
                                background: `Live dashboard record${row.updated_at ? ` updated ${formatIstTimestamp(row.updated_at)}` : ""}.`,
                              }));
                              const dedupedRows = rows.filter((row, index, allRows) => {
                                const identity = `${String(row.title || "").toLowerCase()}|${String(row.timestamp || row?.details?.workflow_id || "")}`;
                                return allRows.findIndex((candidate) => `${String(candidate.title || "").toLowerCase()}|${String(candidate.timestamp || candidate?.details?.workflow_id || "")}` === identity) === index;
                              });
                              if (!dedupedRows.length) {
                                return <tr><td colSpan={4}>No backend workflow activity is available for this project yet.</td></tr>;
                              }
                              return dedupedRows.map((row, index) => {
                                const message = row?.details?.message
                                  || row?.details?.summary
                                  || row?.details?.choice
                                  || row?.details?.path
                                  || row?.details?.workflow_id
                                  || `Requirements: ${Number(row?.details?.requirements_count || 0)}`;
                                return (
                                  <tr key={`workflow-step-${row.step || index}-${row.title}`}>
                                    <td>{index + 1}. {row.title}</td>
                                    <td>{row.status || "pending"}</td>
                                    <td>{String(message || "-")}</td>
                                    <td>
                                      <details>
                                        <summary>How This Worked In Background</summary>
                                        <pre className="result">{row.background || explainOnboardingStepBackground(row.step, isSetupMonitoring)}</pre>
                                      </details>
                                    </td>
                                  </tr>
                                );
                              });
                            })()}
                          </tbody>
                        </table>
                      </div>
                      <div className="filter-grid">
                        <label>
                          Current Project
                          <input value={onboardingForm.name} readOnly />
                        </label>
                        <label>
                          Monitoring Tool
                          <input value={onboardingForm.monitoring_tool} readOnly />
                        </label>
                        <label>
                          Last Workflow ID
                          <input value={String(onboardingRuleLookup.workflow_id || onboardingRuleRunState?.result?.workflow_id || "").trim()} readOnly />
                        </label>
                      </div>
                      {onboardingRuleRunState.error ? <p className="error">{onboardingRuleRunState.error}</p> : null}
                      {onboardingRuleRunState.result?.knowledge_documents?.length ? (
                        <div className="table-wrap">
                          <h4>Documents Saved To System</h4>
                          <p className="subtitle">For transparency: every knowledge document persisted by this run, with its metadata.</p>
                          <table>
                            <thead>
                              <tr>
                                <th>Title</th>
                                <th>Project</th>
                                <th>Platform</th>
                                <th>Owner</th>
                                <th>Created</th>
                                <th>Document ID</th>
                              </tr>
                            </thead>
                            <tbody>
                              {onboardingRuleRunState.result.knowledge_documents.map((doc) => (
                                <tr key={doc.document_id || doc.title}>
                                  <td>{doc.title || "-"}</td>
                                  <td>{doc.project || "-"}</td>
                                  <td>{doc.platform || "-"}</td>
                                  <td>{doc.owner || "-"}</td>
                                  <td>{formatIstTimestamp(doc.created_at)}</td>
                                  <td>{doc.document_id || "-"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : null}
                      {onboardingRuleRunState.result ? <pre className="result">{JSON.stringify(onboardingRuleRunState.result, null, 2)}</pre> : null}
                      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
                        <button type="button" className="button-secondary" onClick={() => setProjectSetupStep("advanced")}>Next: Advanced Tools</button>
                      </div>
                    </article>
                    ) : null}

                    {showProjectStep("advanced") ? (
                    <article className="panel">
                      <h3>Advanced Rule Workflow Management</h3>
                      <details>
                        <summary style={{ cursor: "pointer", marginBottom: 12 }}>Open Advanced Tools</summary>

                        <form className="form" onSubmit={lookupOnboardingRuleWorkflow}>
                          <div className="filter-grid">
                            <label>
                              Workflow ID
                              <input
                                value={onboardingRuleLookup.workflow_id}
                                placeholder="Paste workflow id"
                                onChange={(e) => setOnboardingRuleLookup((curr) => ({ ...curr, workflow_id: e.target.value }))}
                              />
                            </label>
                          </div>
                          <button className="button-secondary" type="submit" disabled={onboardingRuleLookup.loading}>
                            {onboardingRuleLookup.loading ? "Fetching..." : "Lookup Workflow"}
                          </button>
                        </form>
                        {onboardingRuleLookup.error ? <p className="error">{onboardingRuleLookup.error}</p> : null}
                        {onboardingRuleLookup.result ? <pre className="result">{JSON.stringify(onboardingRuleLookup.result, null, 2)}</pre> : null}
                        <div className="table-wrap" style={{ marginTop: 12 }}>
                          <table>
                            <thead>
                              <tr>
                                <th>Project</th>
                                <th>Pipeline</th>
                                <th>Workflow ID</th>
                                <th>Status</th>
                                <th>Updated</th>
                                <th>Action</th>
                              </tr>
                            </thead>
                            <tbody>
                              {ruleOnboardingRows.slice(0, 100).map((row, index) => {
                                const payload = row.connectivity_payload && typeof row.connectivity_payload === "object" ? row.connectivity_payload : {};
                                const workflowId = String(payload.workflow_id || "").trim();
                                return (
                                  <tr key={`rule-workflow-row-${index}`}>
                                    <td>{row.project_name || "-"}</td>
                                    <td>{row.provider_name || payload.pipeline || "-"}</td>
                                    <td>{workflowId || "-"}</td>
                                    <td>{payload.status || row.test_status || "-"}</td>
                                    <td>{formatIstTimestamp(row.updated_at || row.created_at)}</td>
                                    <td>
                                      <div style={{ display: "flex", gap: 8 }}>
                                        <button type="button" className="button-secondary" onClick={() => openRuleWorkflowEditor(row)} disabled={!workflowId}>
                                          Edit
                                        </button>
                                        <button type="button" className="button-secondary" onClick={() => deleteRuleWorkflow(workflowId)} disabled={!workflowId || onboardingRuleEditorState.loading}>
                                          Delete
                                        </button>
                                      </div>
                                    </td>
                                  </tr>
                                );
                              })}
                              {!ruleOnboardingRows.length ? (
                                <tr>
                                  <td colSpan={6}>No saved rule workflows available.</td>
                                </tr>
                              ) : null}
                            </tbody>
                          </table>
                        </div>

                        <h3>Edit Rule Workflow Result</h3>
                        <form className="form" onSubmit={saveRuleWorkflowEditor}>
                          <div className="filter-grid">
                            <label>
                              Workflow ID
                              <input
                                value={onboardingRuleEditor.workflow_id}
                                onChange={(e) => setOnboardingRuleEditor((current) => ({ ...current, workflow_id: e.target.value }))}
                                placeholder="Workflow ID"
                              />
                            </label>
                            <label>
                              Project Name
                              <input
                                value={onboardingRuleEditor.project_name}
                                onChange={(e) => setOnboardingRuleEditor((current) => ({ ...current, project_name: e.target.value }))}
                                placeholder="Project name"
                              />
                            </label>
                          </div>
                          <label>
                            Workflow Result JSON
                            <textarea
                              rows={10}
                              value={onboardingRuleEditor.payload_json}
                              onChange={(e) => setOnboardingRuleEditor((current) => ({ ...current, payload_json: e.target.value }))}
                              placeholder="Paste workflow result JSON"
                            />
                          </label>
                          <button className="button-primary" type="submit" disabled={onboardingRuleEditorState.loading}>
                            {onboardingRuleEditorState.loading ? "Saving..." : "Save Workflow Changes"}
                          </button>
                        </form>
                        {onboardingRuleEditorState.error ? <p className="error">{onboardingRuleEditorState.error}</p> : null}
                        {onboardingRuleEditorState.success ? <p className="subtitle">{onboardingRuleEditorState.success}</p> : null}

                        <div className="panel-head" style={{ marginTop: 12 }}>
                          <h3>Monitoring Platform Capabilities</h3>
                          <button type="button" className="button-secondary" onClick={loadOnboardingRuleCapabilities}>
                            Refresh
                          </button>
                        </div>
                        {onboardingRuleCapabilities.error ? <p className="error">{onboardingRuleCapabilities.error}</p> : null}
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>Platform</th>
                                <th>Pull Rules</th>
                                <th>Push Rules</th>
                                <th>Adapter</th>
                                <th>Simulation</th>
                                <th>Dashboards</th>
                              </tr>
                            </thead>
                            <tbody>
                              {onboardingRuleCapabilities.rows.map((row, index) => (
                                <tr key={`capability-${row.platform || index}`}>
                                  <td>{row.platform || "-"}</td>
                                  <td>{String(Boolean(row.can_pull_rules))}</td>
                                  <td>{String(Boolean(row.can_push_rules))}</td>
                                  <td title={row.contract_label || ""}>{row.contract_mode || "-"} / {row.contract_status || "-"}</td>
                                  <td>{String(Boolean(row.supports_simulation))}</td>
                                  <td>{String(Boolean(row.supports_dashboard_refs))}</td>
                                </tr>
                              ))}
                              {!onboardingRuleCapabilities.rows.length && !onboardingRuleCapabilities.loading ? (
                                <tr>
                                  <td colSpan={6}>No capabilities loaded yet.</td>
                                </tr>
                              ) : null}
                            </tbody>
                          </table>
                        </div>
                      </details>
                    </article>
                    ) : null}
                  </div>

                ) : null}

                {adminWorkspace === "monitoring" ? (
                  <div className="grid single-col admin-flow-section admin-flow-monitoring">
                    <article className="panel">
                      <div className="panel-head">
                        <h3>Setup Monitoring</h3>
                        <button className="button-secondary" type="button" onClick={loadMonitoringApplications} disabled={monitoringApps.loading}>Refresh</button>
                      </div>
                      <p className="subtitle">Start here. Register an application and inspect the end-to-end onboarding chain (discovery, validation, rules, Prometheus update, dashboard).</p>
                      <p className="subtitle"><strong>Alert Knowledge:</strong> Included in Setup Monitoring + Landing Pad. Use the unified setup tab for one continuous workflow.</p>
                      <form className="form" onSubmit={submitMonitoringApplication}>
                        <div className="filter-grid">
                          <label>Tenant<input value={monitoringAppForm.tenant_id} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, tenant_id: e.target.value }))} /></label>
                          <label>Application Name<input value={monitoringAppForm.name} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, name: e.target.value }))} /></label>
                          <label>Owner Team<input value={monitoringAppForm.owner_team} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, owner_team: e.target.value }))} /></label>
                          <label>Owner Email<input value={monitoringAppForm.owner_email} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, owner_email: e.target.value }))} /></label>
                        </div>
                        <div className="filter-grid">
                          <label>Environment<select value={monitoringAppForm.environment} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, environment: e.target.value }))}><option value="dev">dev</option><option value="staging">staging</option><option value="prod">prod</option></select></label>
                          <label>Namespace<input value={monitoringAppForm.namespace} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, namespace: e.target.value }))} /></label>
                          <label>Region<input value={monitoringAppForm.region} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, region: e.target.value }))} /></label>
                          <label>Technology<input value={monitoringAppForm.technology} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, technology: e.target.value }))} /></label>
                        </div>
                        <label>Metrics Endpoint<input placeholder="http://api-gateway:8000/metrics" value={monitoringAppForm.metrics_endpoint} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, metrics_endpoint: e.target.value }))} /></label>
                        <label>Labels (comma-separated key=value)<input value={monitoringAppForm.labels_text} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, labels_text: e.target.value }))} /></label>
                        <button className="button-primary" type="submit" disabled={monitoringAppSubmit.loading}>{monitoringAppSubmit.loading ? "Submitting..." : "Register Application"}</button>
                      </form>
                      {monitoringAppSubmit.error ? <p className="error">{monitoringAppSubmit.error}</p> : null}
                      {monitoringAppSubmit.success ? <p className="subtitle">{monitoringAppSubmit.success}</p> : null}
                      <article className="panel monitoring-doc-gate" style={{ marginTop: 10, borderStyle: "dashed" }}>
                        <div className="panel-head">
                          <h3>Service Knowledge Status</h3>
                          <button type="button" className="button-secondary" onClick={applyUploadedDocumentsToRuleIntent} disabled={!onboardingDerivedRequirements.length}>Apply To Rules</button>
                        </div>
                        <p className="subtitle">Use the Service Knowledge upload above. KaiMS extracts and validates the important details in one flow.</p>
                        <div className="approval-steps" style={{ marginTop: 10 }}>
                          <div className="approval-step">
                            <strong>Extract</strong>
                            <span>Service, owner, environment, dependencies, alerts, commands, rollback, and validation checks.</span>
                          </div>
                          <div className="approval-step">
                            <strong>Validate</strong>
                            <span>Flags missing or low-confidence fields before the details are trusted.</span>
                          </div>
                          <div className="approval-step">
                            <strong>Approve</strong>
                            <span>Stores the reviewed pack in Alert Knowledge for RAG and future incidents.</span>
                          </div>
                        </div>
                        {onboardingSourceDocs.loading ? <p className="subtitle">Reading uploaded file...</p> : null}
                        {onboardingSourceDocs.error ? <p className="error">{onboardingSourceDocs.error}</p> : null}
                        <p className="subtitle monitoring-doc-gate-count">
                          Uploaded file: <strong>{onboardingSourceDocCount > 0 ? "yes" : "no"}</strong> | Service Knowledge: <strong>{knowledgePackState.approved ? "approved" : onboardingKnowledgePack?.status || "waiting"}</strong>
                        </p>
                      </article>
                    </article>

                    <article className="panel">
                      <h3>Applications</h3>
                      {monitoringApps.error ? <p className="error">{monitoringApps.error}</p> : null}
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr><th>Name</th><th>Tenant</th><th>Namespace</th><th>Environment</th><th>Technology</th><th>Status</th><th>Metrics Endpoint</th><th>Action</th></tr>
                          </thead>
                          <tbody>
                            {monitoringApps.rows.map((row, index) => (
                              <tr key={`monitoring-app-${row.id || index}`}>
                                <td>{row.name || "-"}</td>
                                <td>{row.tenant_id || "default"}</td>
                                <td>{row.namespace || "-"}</td>
                                <td>{row.environment || "-"}</td>
                                <td>{row.technology || "-"}</td>
                                <td><span className={`pill ${String(row.status || "").includes("failed") ? "status-failed" : "status-closed"}`}>{row.status || "-"}</span></td>
                                <td>{row.metrics_endpoint || "-"}</td>
                                <td><button type="button" className="button-secondary" onClick={() => setSelectedMonitoringAppId(String(row.id || ""))}>Inspect</button></td>
                              </tr>
                            ))}
                            {!monitoringApps.rows.length ? <tr><td colSpan={8}>No monitoring applications registered yet.</td></tr> : null}
                          </tbody>
                        </table>
                      </div>
                    </article>

                    <article className="panel" ref={monitoringInspectRef}>
                      <div className="panel-head">
                        <h3>Selected Application Timeline</h3>
                        <p className="subtitle">{selectedMonitoringAppId || "Select an application to inspect stage history, validations, and dashboards."}</p>
                      </div>
                      {monitoringAppDetails.error ? <p className="error">{monitoringAppDetails.error}</p> : null}
                      <HistoricalTicketDiscoveryPanel
                        applicationId={selectedMonitoringAppId}
                        applicationName={monitoringApps.rows.find((row) => String(row?.id || "").trim() === String(selectedMonitoringAppId || "").trim())?.name}
                        documents={ragDocs.rows}
                        loading={ragDocs.loading}
                      />
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr><th>Event</th><th>Agent</th><th>Decision</th><th>Status</th><th>Execution (ms)</th><th>Timestamp</th></tr>
                          </thead>
                          <tbody>
                            {monitoringAppDetails.history.map((row, index) => (
                              <tr key={`monitoring-history-${row.id || index}`}>
                                <td>{row.event_type || "-"}</td>
                                <td>{row.agent || "-"}</td>
                                <td>{row.decision || "-"}</td>
                                <td>{row.status || "-"}</td>
                                <td>{asDisplayValue(row.execution_time_ms)}</td>
                                <td>{formatIstTimestamp(row.created_at)}</td>
                              </tr>
                            ))}
                            {!monitoringAppDetails.history.length ? <tr><td colSpan={6}>No stage history available yet.</td></tr> : null}
                          </tbody>
                        </table>
                      </div>
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr><th>Target Up</th><th>Metrics</th><th>Alerts Loaded</th><th>Recording Rules</th><th>Service Discovery</th><th>Timestamp</th></tr>
                          </thead>
                          <tbody>
                            {monitoringAppDetails.validations.map((row, index) => (
                              <tr key={`monitoring-validation-${row.id || index}`}>
                                <td>{String(Boolean(row.target_up))}</td>
                                <td>{String(Boolean(row.metrics_available))}</td>
                                <td>{String(Boolean(row.alerts_loaded))}</td>
                                <td>{String(Boolean(row.recording_rules_loaded))}</td>
                                <td>{String(Boolean(row.service_discovery_ok))}</td>
                                <td>{formatIstTimestamp(row.created_at)}</td>
                              </tr>
                            ))}
                            {!monitoringAppDetails.validations.length ? <tr><td colSpan={6}>No validation records available yet.</td></tr> : null}
                          </tbody>
                        </table>
                      </div>
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr><th>Dashboard UID</th><th>Title</th><th>URL</th><th>Updated</th></tr>
                          </thead>
                          <tbody>
                            {monitoringAppDetails.dashboards.map((row, index) => (
                              <tr key={`monitoring-dashboard-${row.id || index}`}>
                                <td>{row.dashboard_uid || "-"}</td>
                                <td>{row.title || "-"}</td>
                                <td>{row.url || "-"}</td>
                                <td>{formatIstTimestamp(row.updated_at)}</td>
                              </tr>
                            ))}
                            {!monitoringAppDetails.dashboards.length ? <tr><td colSpan={4}>No dashboards generated yet.</td></tr> : null}
                          </tbody>
                        </table>
                      </div>
                    </article>
                  </div>
                ) : null}

                {(adminWorkspace === "alerts" || (adminWorkspace === "project" && showProjectStep("knowledge"))) ? (
                  <div className="grid single-col admin-flow-section admin-flow-knowledge">
                    <article className="panel">
                      <div className="panel-head">
                        <h3>{adminWorkspace === "project" ? "Knowledge: Alert Documents" : "Alert Knowledge Onboarding"}</h3>
                        <p>{adminWorkspace === "project" ? "Create and review alert knowledge here in the same setup workspace." : "Standalone alert knowledge workspace for focused onboarding and review."}</p>
                      </div>
                      <div className="detail-tabs" style={{ marginBottom: 0 }}>
                        <button
                          type="button"
                          className={alertKnowledgeView === "onboarding" ? "button-primary" : "button-secondary"}
                          onClick={() => setAlertKnowledgeView("onboarding")}
                        >
                          Guided Onboarding
                        </button>
                        <button
                          type="button"
                          className={alertKnowledgeView === "backend" ? "button-primary" : "button-secondary"}
                          onClick={() => setAlertKnowledgeView("backend")}
                        >
                          Stored Docs & Metadata
                        </button>
                      </div>
                    </article>

                    {alertKnowledgeView === "onboarding" ? (
                    <article className="panel" ref={alertKnowledgeRef}>
                      <h3>Alert Knowledge Onboarding</h3>
                      <p className="subtitle">Add monitoring/troubleshooting knowledge as part of the same onboarding flow.</p>
                      <form className="form" onSubmit={submitAlertOnboarding}>
                        <label>
                          Prompt For Document Generation
                          <textarea
                            rows={4}
                            placeholder="Describe the alert scenario, triage steps, impact, and expected remediation. Optional prefixes: cmd:, script:, query:."
                            value={alertKnowledgePrompt}
                            onChange={(e) => setAlertKnowledgePrompt(e.target.value)}
                          />
                        </label>
                        <div className="alert-knowledge-source">
                          <label>
                            Supporting Document
                            <input
                              type="file"
                              accept=".md,.markdown,.txt,.json,.csv,.yaml,.yml,.log"
                              onChange={(e) => handleAlertKnowledgeSourceDocument(e.target.files)}
                            />
                          </label>
                          <div className="alert-knowledge-source-status">
                            {alertKnowledgeSourceDoc.loading ? <span>Reading document...</span> : null}
                            {alertKnowledgeSourceDoc.error ? <span className="error">{alertKnowledgeSourceDoc.error}</span> : null}
                            {alertKnowledgeSourceDoc.name && !alertKnowledgeSourceDoc.error ? (
                              <>
                                <div>
                                  <strong>{alertKnowledgeSourceDoc.name}</strong>
                                  <small>{alertKnowledgeSourceDoc.size ? `${Math.ceil(alertKnowledgeSourceDoc.size / 1024)} KB` : "uploaded"}</small>
                                </div>
                                {alertKnowledgeSourceDoc.excerpt ? <p>{alertKnowledgeSourceDoc.excerpt}</p> : null}
                                <button type="button" className="button-secondary" onClick={clearAlertKnowledgeSourceDocument}>
                                  Clear Document
                                </button>
                              </>
                            ) : !alertKnowledgeSourceDoc.loading && !alertKnowledgeSourceDoc.error ? (
                              <span>Upload runbook, RCA, logs, support notes, or troubleshooting docs. The draft uses this together with the prompt.</span>
                            ) : null}
                          </div>
                        </div>
                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                          <button
                            type="button"
                            className="button-secondary"
                            onClick={generateAlertKnowledgeDraftFromPrompt}
                            disabled={alertOnboardingState.loading}
                          >
                            Generate Draft From Prompt + Document
                          </button>
                        </div>
                        <div className="detail-tabs" style={{ marginBottom: 10 }}>
                          {ALERT_DOC_KIND_OPTIONS.map((kind) => (
                            <button
                              key={`onboard-kind-${kind}`}
                              type="button"
                              className={String(alertOnboarding.kind || "").trim().toLowerCase() === kind ? "button-primary" : "button-secondary"}
                              onClick={() => setAlertOnboarding((curr) => ({ ...curr, kind }))}
                            >
                              {kind}
                            </button>
                          ))}
                        </div>
                        <div className="filter-grid">
                          <label>Kind
                            <select value={alertOnboarding.kind} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, kind: e.target.value }))}>
                              <option value="incident">incident</option>
                              <option value="runbook">runbook</option>
                              <option value="deployment">deployment</option>
                              <option value="change">change</option>
                              <option value="dependency">dependency</option>
                              <option value="remediation">remediation</option>
                            </select>
                          </label>
                          <label>Title<input value={alertOnboarding.title} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, title: e.target.value }))} /></label>
                          <label>Alert Type<input value={alertOnboarding.alert_type} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, alert_type: e.target.value }))} /></label>
                          <label>Severity<select value={alertOnboarding.severity} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, severity: e.target.value }))}><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option></select></label>
                        </div>
                        <label>Services (comma separated)<input value={alertOnboarding.services} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, services: e.target.value }))} /></label>
                        <label>Summary<textarea rows={2} value={alertOnboarding.summary} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, summary: e.target.value }))} /></label>
                        <label>Content<textarea rows={5} value={alertOnboarding.content} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, content: e.target.value }))} /></label>
                        {String(alertOnboarding.kind || "").trim().toLowerCase() === "remediation" ? (
                          <>
                            <div style={{ display: "flex", alignItems: "end", gap: 8 }}>
                              <button
                                type="button"
                                className="button-secondary"
                                onClick={() => autoGenerateRemediationPlan()}
                                disabled={alertOnboardingState.loading}
                              >
                                Auto-Generate Commands/Scripts/Queries
                              </button>
                            </div>
                            <label>Execution Plan<textarea rows={4} value={alertOnboarding.execution_plan} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, execution_plan: e.target.value }))} /></label>
                            <div className="filter-grid">
                              <label>Additional Commands<textarea rows={5} value={alertOnboarding.remediation_commands_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_commands_text: e.target.value }))} /></label>
                              <label>Single Remediation Script<textarea rows={5} value={alertOnboarding.remediation_scripts_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_scripts_text: e.target.value }))} /></label>
                              <label>Additional Validation Queries<textarea rows={5} value={alertOnboarding.remediation_queries_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_queries_text: e.target.value }))} /></label>
                            </div>
                          </>
                        ) : null}
                        <button className="button-primary" type="submit" disabled={alertOnboardingState.loading}>{alertOnboardingState.loading ? "Saving..." : "Create Alert Onboarding Doc"}</button>
                      </form>
                      {alertOnboardingState.error ? <p className="error">{alertOnboardingState.error}</p> : null}
                      {alertOnboardingState.result ? <pre className="result">{JSON.stringify(alertOnboardingState.result, null, 2)}</pre> : null}
                    </article>
                    ) : null}

                    {alertKnowledgeView === "backend" ? (
                      <article className="panel">
                        <div className="panel-head">
                          <h3>Stored Backend Documents</h3>
                          <button className="button-secondary" type="button" onClick={loadRagDocs}>Refresh</button>
                        </div>
                        <p className="subtitle">Documents currently stored in backend with metadata details.</p>
                        {ragDocs.error ? <p className="error">{ragDocs.error}</p> : null}
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>Title</th>
                                <th>Kind</th>
                                <th>Alert Type</th>
                                <th>Severity</th>
                                <th>Services</th>
                                <th>Document View</th>
                                <th>Updated</th>
                                <th>Metadata</th>
                              </tr>
                            </thead>
                            <tbody>
                              {ragDocs.rows.map((doc, index) => (
                                <tr key={`backend-doc-${doc.path || doc.title || index}`}>
                                  <td>{doc.title || "-"}</td>
                                  <td>{doc.kind || doc.document_kind || "-"}</td>
                                  <td>{doc.alert_type || "-"}</td>
                                  <td>{doc.severity || "-"}</td>
                                  <td>{Array.isArray(doc.services) ? doc.services.join(", ") : (doc.services || "-")}</td>
                                  <td>
                                    <details className="backend-document-view">
                                      <summary>
                                        <span>{backendDocumentPreview(doc)}</span>
                                      </summary>
                                      <div>
                                        <p>{doc.summary || doc.recommended_action || "Document details are available from backend metadata."}</p>
                                        {doc.root_cause ? <p><strong>Root cause:</strong> {doc.root_cause}</p> : null}
                                        {doc.impact ? <p><strong>Impact:</strong> {doc.impact}</p> : null}
                                        {doc.execution_plan ? <pre className="result">{String(doc.execution_plan)}</pre> : null}
                                        <div className="backend-document-actions">
                                          <button
                                            type="button"
                                            className="button-secondary"
                                            onClick={() => downloadRagDocument(doc)}
                                            disabled={!doc.path}
                                          >
                                            Download
                                          </button>
                                        </div>
                                      </div>
                                    </details>
                                  </td>
                                  <td>{formatIstTimestamp(doc.updated_at || doc.modified_at || doc.created_at)}</td>
                                  <td>
                                    <details>
                                      <summary style={{ cursor: "pointer" }}>view</summary>
                                      <pre className="result" style={{ marginTop: 8 }}>{JSON.stringify({
                                        path: doc.path || null,
                                        alert_id: doc.alert_id || null,
                                        root_cause: doc.root_cause || null,
                                        impact: doc.impact || null,
                                        execution_plan: doc.execution_plan || null,
                                        recommended_action: doc.recommended_action || null,
                                        source_system: doc.source_system || null,
                                        source_ref: doc.source_ref || null,
                                        tags: doc.tags || null,
                                        metadata: doc.metadata || null,
                                      }, null, 2)}</pre>
                                    </details>
                                  </td>
                                </tr>
                              ))}
                              {!ragDocs.rows.length && !ragDocs.loading ? <tr><td colSpan={8}>No documents found in backend.</td></tr> : null}
                            </tbody>
                          </table>
                        </div>
                      </article>
                    ) : null}
                  </div>
                ) : null}
                </section>
              ) : null}
              </div>
              <aside className={`global-copilot-drawer ${isCopilotOpen ? "open" : ""}`}>
                <div className="global-copilot-drawer-header">
                  <h3><Bot size={18} /> Ask KAI</h3>
                  <button className="button-secondary" onClick={() => setIsCopilotOpen(false)}>Close</button>
                </div>
                <div className="global-copilot-drawer-body">
                  <CopilotRoute />
                </div>
              </aside>
            </div>
          </RouteRuntimeProvider>

        </section>
      </div>
      </KaiOperationsShell>
    </div>
  );
}
