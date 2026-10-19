import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Activity,
  Bell,
  BookOpen,
  Bot,
  Boxes,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  CircleUserRound,
  Command,
  FileCheck2,
  FileSearch,
  Gauge,
  LayoutDashboard,
  Menu,
  PlugZap,
  Search,
  Settings,
  ShieldCheck,
  Siren,
  SlidersHorizontal,
  Users,
  X,
  Zap,
} from "lucide-react";

import { searchNavigation, type NavigationIcon, type NavigationItem } from "../../app/navigation";
import "./KaiOperationsShell.css";
import "./OperationsDesign.css";

type NavigationGroupView = { id: string; label: string; items: readonly NavigationItem[] };
type OperationalItem = { kind?: string; label?: string | number; meta?: string; row?: unknown };
type KaiStateItem = { label: string; value: number; tone?: "attention" | "active" | "calm" };

const PAGE_STEPS: Partial<Record<NavigationIcon, readonly string[]>> = {
  dashboard: ["Review items marked Attention", "Open the highest-priority incident", "Check pending approvals"],
  incidents: ["Choose an active incident", "Review evidence and the RCA gate", "Complete the requested next action"],
  approvals: ["Open a decision assigned to you", "Verify evidence, scope, and rollback", "Approve or reject with a reason"],
  copilot: ["Ask one operational question", "Check the cited sources", "Open the related incident or service"],
  knowledge: ["Review documents awaiting approval", "Verify ownership and applicability", "Approve only trustworthy production guidance"],
  applications: ["Select an application", "Confirm ownership and services", "Complete missing monitoring setup"],
  cloudResources: ["Filter to the service or provider", "Open the affected resource", "Verify owner and relationships"],
  operationsCockpit: ["Find a blocked capability", "Review missing configuration", "Run a safe readiness check"],
  cloudConnections: ["Add or select a connection", "Validate credentials and reachability", "Run discovery and review results"],
  platformOverview: ["Review degraded components", "Open the reported dependency", "Confirm recovery after correction"],
  settings: ["Choose the setting to manage", "Review its security impact", "Save and verify the result"],
  audit: ["Filter by incident, actor, or action", "Open the relevant event", "Export evidence when needed"],
};

const ICONS: Record<NavigationIcon, typeof Activity> = {
  dashboard: LayoutDashboard,
  alerts: Activity,
  incidents: Siren,
  approvals: FileCheck2,
  evidenceRequests: FileSearch,
  copilot: Bot,
  agentFlow: Zap,
  knowledge: BookOpen,
  safety: ShieldCheck,
  audit: Gauge,
  closed: CheckCircle2,
  applications: Boxes,
  operationsCockpit: Zap,
  cloudConnections: PlugZap,
  cloudResources: Boxes,
  serviceOnboarding: Settings,
  services: Activity,
  integrations: PlugZap,
  platformOverview: Gauge,
  admin: Users,
  settings: Settings,
  executive: Gauge,
};

export interface KaiOperationsShellProps {
  children: ReactNode;
  navigationGroups: readonly NavigationGroupView[];
  currentItem: NavigationItem;
  currentPath: string;
  role: string;
  onNavigate: (item: NavigationItem) => void;
  projects: readonly string[];
  project: string;
  onProjectChange: (project: string) => void;
  environment: string;
  health: { ok?: boolean; loading?: boolean; message?: string };
  aiCapability?: { degraded?: boolean; loading?: boolean; message?: string };
  autonomyMode?: string;
  approvalCount: number;
  notificationCount: number;
  operationalQuery: string;
  onOperationalQueryChange: (query: string) => void;
  operationalResults: readonly OperationalItem[];
  notifications: readonly OperationalItem[];
  onOpenOperationalItem: (item: OperationalItem) => void;
  onOpenNotifications: () => void;
  onAskKai: () => void;
  user?: { username?: string; role_name?: string } | null;
  density: string;
  theme: string;
  onDensityChange: (density: string) => void;
  onThemeChange: (theme: string) => void;
  onLogout: () => void;
  kaiStates?: readonly KaiStateItem[];
  restrictedDestination?: string;
}

function humanize(value: string | undefined, fallback: string) {
  const text = String(value || "").trim();
  return text && text !== "-" ? text.replaceAll("_", " ").replaceAll("-", " ") : fallback;
}

export function KaiOperationsShell({
  children,
  navigationGroups,
  currentItem,
  currentPath,
  role,
  onNavigate,
  project,
  environment,
  health,
  aiCapability,
  autonomyMode,
  approvalCount,
  notificationCount,
  operationalQuery,
  onOperationalQueryChange,
  operationalResults,
  notifications,
  onOpenOperationalItem,
  onOpenNotifications,
  onAskKai,
  user,
  density,
  theme,
  onDensityChange,
  onThemeChange,
  onLogout,
  kaiStates = [],
  restrictedDestination,
}: KaiOperationsShellProps) {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteView, setPaletteView] = useState<"search" | "notifications">("search");
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const navigationMatches = useMemo(() => searchNavigation(operationalQuery, role).slice(0, 6), [operationalQuery, role]);
  const hasQuery = Boolean(operationalQuery.trim());
  const currentGroup = navigationGroups.find((group) => group.items.some((item) => item.id === currentItem.id));
  const pageSteps = PAGE_STEPS[currentItem.id] || ["Review the current status", "Open the item requiring attention", "Complete the suggested next action"];
  const relatedItems = (currentItem.related || []).map((id) => navigationGroups.flatMap((group) => group.items).find((item) => item.id === id)).filter(Boolean) as NavigationItem[];

  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteView("search");
        setPaletteOpen((open) => !open);
      }
      if (event.key === "Escape") setPaletteOpen(false);
    };
    window.addEventListener("keydown", handleShortcut);
    return () => window.removeEventListener("keydown", handleShortcut);
  }, []);

  useEffect(() => {
    if (!paletteOpen) return;
    const frame = window.requestAnimationFrame(() => searchRef.current?.focus());
    return () => window.cancelAnimationFrame(frame);
  }, [paletteOpen]);

  const selectNavigation = (item: NavigationItem) => {
    onNavigate(item);
    setPaletteOpen(false);
    setMobileNavigationOpen(false);
    onOperationalQueryChange("");
  };

  return (
    <div className="kai-shell">
      <aside className={`kai-navigation ${mobileNavigationOpen ? "is-open" : ""}`} aria-label="Primary navigation">
        <div className="kai-brand-lockup">
          <button type="button" onClick={() => selectNavigation(navigationGroups[0]?.items[0] ?? currentItem)} aria-label="KaiMS operations overview">
            <span className="kai-brand-mark" aria-hidden="true">K</span>
            <span><strong>KaiMS</strong><small>AI Operations Command Center</small></span>
          </button>
          <button className="kai-mobile-close" type="button" aria-label="Close navigation" onClick={() => setMobileNavigationOpen(false)}><X /></button>
        </div>

        <nav className="kai-navigation-groups" aria-label="Primary navigation">
          {navigationGroups.map((group) => (
            <section key={group.id} aria-labelledby={`kai-nav-${group.id}`}>
              <h2 id={`kai-nav-${group.id}`}>{group.label}</h2>
              {group.items.map((item) => {
                const Icon = ICONS[item.icon];
                const active = item.path === "/" ? currentPath === "/" : currentPath === item.path || currentPath.startsWith(`${item.path}/`);
                return (
                  <button key={item.id} type="button" className={active ? "is-active" : ""} aria-current={active ? "page" : undefined} onClick={() => selectNavigation(item)}>
                    <Icon aria-hidden="true" /><span>{item.label}</span>
                    {item.id === "approvals" && approvalCount > 0 ? <em>{approvalCount}</em> : null}
                  </button>
                );
              })}
            </section>
          ))}
        </nav>

        <section className="kai-brain-status" aria-label="Kai operations brain">
          <header><span><Bot aria-hidden="true" />Kai Operations Brain</span><i>Live</i></header>
          <div>
            {kaiStates.length ? kaiStates.map((state) => (
              <span key={state.label} className={state.tone ? `is-${state.tone}` : ""}><small>{state.label}</small><strong>{state.value}</strong></span>
            )) : <p>Kai activity will appear as operational records arrive.</p>}
          </div>
          <button type="button" onClick={onAskKai}><Bot aria-hidden="true" /> Ask Kai</button>
        </section>
      </aside>

      <div className="kai-workspace-frame">
        <header className="kai-operations-bar">
          <button className="kai-mobile-menu" type="button" aria-label="Open navigation" onClick={() => setMobileNavigationOpen(true)}><Menu /></button>
          <div className="kai-context-selectors">
            <span className="kai-environment"><small>Project</small><strong>{project || "No project selected"}</strong></span>
            <span className={`kai-environment ${["prod", "production"].includes(environment.toLowerCase()) ? "is-production" : ""}`}><small>Connection env.</small><strong>{humanize(environment, "Unknown")}</strong></span>
          </div>

          <button className="kai-search-trigger" type="button" onClick={() => { setPaletteView("search"); setPaletteOpen(true); }}>
            <Search aria-hidden="true" /><span>{operationalQuery || "Search or ask Kai..."}</span><kbd><Command aria-hidden="true" /> K</kbd>
          </button>

          <div className="kai-global-actions">
            <span className={`kai-health ${health.ok ? "is-healthy" : "is-degraded"}`} title={health.message || "Platform health unavailable"}><i aria-hidden="true" /><span>Platform</span><strong>{health.loading ? "Checking" : health.ok ? "Healthy" : "Attention"}</strong></span>
            <span className="kai-autonomy"><ShieldCheck aria-hidden="true" /><span>Autonomy</span><strong>{humanize(autonomyMode, "Policy managed")}</strong></span>
            <button type="button" className="kai-count-action" onClick={() => {
              const item = navigationGroups.flatMap((group) => group.items).find((candidate) => candidate.id === "approvals");
              if (item) selectNavigation(item);
            }}><FileCheck2 aria-hidden="true" /><span>Approvals</span>{approvalCount > 0 ? <em>{approvalCount}</em> : null}</button>
            <button type="button" className="kai-icon-action" aria-label={`${notificationCount} operational notifications`} onClick={() => { onOpenNotifications(); setPaletteView("notifications"); setPaletteOpen(true); }}><Bell aria-hidden="true" />{notificationCount > 0 ? <em>{notificationCount}</em> : null}</button>
            <details className="kai-user-menu">
              <summary aria-label="User and display preferences"><CircleUserRound aria-hidden="true" /><span>{user?.username || "User"}</span><ChevronDown aria-hidden="true" /></summary>
              <div>
                <header><strong>{user?.username || "Signed-in user"}</strong><span>{humanize(user?.role_name, "Role unavailable")}</span></header>
                <fieldset><legend>Density</legend>{["comfortable", "compact"].map((value) => <button key={value} type="button" className={density === value ? "is-active" : ""} onClick={() => onDensityChange(value)}>{humanize(value, value)}</button>)}</fieldset>
                <fieldset><legend>Theme</legend>{["auto", "light", "dark"].map((value) => <button key={value} type="button" className={theme === value ? "is-active" : ""} onClick={() => onThemeChange(value)}>{humanize(value, value)}</button>)}</fieldset>
                <button className="kai-logout" type="button" onClick={onLogout}>Sign out</button>
              </div>
            </details>
          </div>
        </header>

        <main className="kai-route-content" id="workspace-content" tabIndex={-1}>
          {aiCapability?.degraded ? <div className="kai-ai-degraded" role="status"><Bot aria-hidden="true" /><span><strong>AI capability degraded.</strong> {aiCapability.message || "AI investigation may be delayed; deterministic monitoring remains active and execution stays governed by backend policy."}</span></div> : null}
          <header className="kai-route-context">
            <div><span>{currentGroup?.label || "KaiMS"} / {currentItem.label}</span><h1>{currentItem.pageTitle}</h1><p>{currentItem.description}</p></div>
            <details className="kai-page-guide"><summary>How to use this page</summary><div><ol>{pageSteps.map((step) => <li key={step}>{step}</li>)}</ol>{relatedItems.length ? <nav aria-label="Related pages"><span>Related</span>{relatedItems.map((item) => <button type="button" key={item.id} onClick={() => selectNavigation(item)}>{item.label}</button>)}</nav> : null}</div></details>
          </header>
          {restrictedDestination ? <div className="kai-permission-notice" role="status"><CircleAlert aria-hidden="true" /><span><strong>Access is restricted.</strong> {restrictedDestination} is not available to your role.</span></div> : null}
          {children}
        </main>
      </div>

      {paletteOpen ? (
        <div className="kai-command-overlay" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) setPaletteOpen(false); }}>
          <section className="kai-command-palette" role="dialog" aria-modal="true" aria-label="Search, navigate, or ask Kai">
            <label>{paletteView === "notifications" ? <Bell aria-hidden="true" /> : <Search aria-hidden="true" />}<input ref={searchRef} value={operationalQuery} onChange={(event) => { setPaletteView("search"); onOperationalQueryChange(event.target.value); }} placeholder={paletteView === "notifications" ? "Filter notifications or start a new search..." : "Search incidents, services, commands, or ask Kai..."} /><kbd>ESC</kbd></label>
            <div className="kai-command-results">
              {paletteView === "notifications" ? <section><h2><Bell aria-hidden="true" /> Meaningful operational changes</h2>{notifications.length ? notifications.map((item, index) => <button type="button" key={`${item.kind}-${item.label}-${index}`} onClick={() => { onOpenOperationalItem(item); setPaletteOpen(false); }}><CircleAlert aria-hidden="true" /><span><strong>{item.kind}: {item.label}</strong><small>{item.meta || "Operational state changed"}</small></span><kbd>Open</kbd></button>) : <p>No approval, critical-alert, recovery, or reopening notifications are present.</p>}</section> : <><section><h2><SlidersHorizontal aria-hidden="true" /> Destinations</h2>{navigationMatches.length ? navigationMatches.map((item) => {
                const Icon = ICONS[item.icon];
                return <button type="button" key={item.id} onClick={() => selectNavigation(item)}><Icon aria-hidden="true" /><span><strong>{item.label}</strong><small>{item.pageTitle}</small></span><kbd>Open</kbd></button>;
              }) : <p>No permitted destination matches.</p>}</section>
              {hasQuery ? <section><h2><Activity aria-hidden="true" /> Operational records</h2>{operationalResults.length ? operationalResults.map((item, index) => <button type="button" key={`${item.kind}-${item.label}-${index}`} onClick={() => { onOpenOperationalItem(item); setPaletteOpen(false); }}><Siren aria-hidden="true" /><span><strong>{item.kind}: {item.label}</strong><small>{item.meta || "Loaded operational record"}</small></span><kbd>Open</kbd></button>) : <p>No matching loaded, role-authorized records.</p>}</section> : null}
              </>}
            </div>
            <footer><span><kbd>↑</kbd><kbd>↓</kbd> browse</span><span><kbd>Enter</kbd> open</span><button type="button" onClick={() => { setPaletteOpen(false); onAskKai(); }}><Bot aria-hidden="true" /> Ask Kai with context</button></footer>
          </section>
        </div>
      ) : null}
      {mobileNavigationOpen ? <button type="button" className="kai-mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNavigationOpen(false)} /> : null}
    </div>
  );
}
