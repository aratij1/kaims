import { useRef } from "react";
import { Activity, BookOpen, FileSearch, GitBranch, LayoutDashboard, RefreshCw, ShieldCheck } from "lucide-react";

export const INCIDENT_VIEWS = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "evidence", label: "Evidence", icon: FileSearch },
  { id: "analysis", label: "Cause & impact", icon: GitBranch },
  { id: "resolution", label: "Resolution", icon: BookOpen },
  { id: "recovery", label: "Recovery", icon: ShieldCheck },
  { id: "activity", label: "Activity", icon: Activity },
] as const;
export type IncidentView = typeof INCIDENT_VIEWS[number]["id"];
export function incidentView(value: string | null): IncidentView {
  return INCIDENT_VIEWS.some(view => view.id === value) ? value as IncidentView : "overview";
}

export default function IncidentWorkspaceNav({ active, onChange, onRefresh, refreshing }: {
  active: IncidentView; onChange: (view: IncidentView) => void; onRefresh: () => void; refreshing: boolean;
}) {
  const tabs = useRef<Array<HTMLButtonElement | null>>([]);
  return <div className="incident-workspace-navigation">
    <div role="tablist" aria-label="Incident details" className="incident-workspace-tabs">
      {INCIDENT_VIEWS.map((view, index) => {
        const Icon = view.icon;
        return <button key={view.id} ref={element => { tabs.current[index] = element; }} type="button"
          id={`incident-tab-${view.id}`} role="tab" aria-selected={active === view.id}
          aria-controls={`incident-panel-${view.id}`} tabIndex={active === view.id ? 0 : -1}
          onClick={() => onChange(view.id)} onKeyDown={event => {
            let next = index;
            if (event.key === "ArrowRight") next = (index + 1) % INCIDENT_VIEWS.length;
            else if (event.key === "ArrowLeft") next = (index + INCIDENT_VIEWS.length - 1) % INCIDENT_VIEWS.length;
            else if (event.key === "Home") next = 0;
            else if (event.key === "End") next = INCIDENT_VIEWS.length - 1;
            else return;
            event.preventDefault();
            onChange(INCIDENT_VIEWS[next].id);
            tabs.current[next]?.focus();
          }}><Icon size={16} aria-hidden="true" /><span>{view.label}</span></button>;
      })}
    </div>
    <button className="incident-workspace-refresh button-secondary" type="button" disabled={refreshing}
      onClick={onRefresh}><RefreshCw size={15} aria-hidden="true" />{refreshing ? "Refreshing..." : "Refresh"}</button>
  </div>;
}
