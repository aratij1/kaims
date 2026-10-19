import { Link } from "react-router-dom";
import type { AlertStreamRow } from "../../app/routeRuntime";
import { alertHandoff } from "../../domain/alertIncidentLink";

export function AlertIncidentHandoff({ row }: { row: AlertStreamRow }) {
  const handoff = alertHandoff(row);
  return <section className="alert-incident-handoff" aria-label="Alert to incident handoff">
    <div><small>Live alert ? Incident</small><strong>{handoff.label}</strong><span>{handoff.detail}</span></div>
    {handoff.id ? <Link className="button-primary" to={`/incidents/${encodeURIComponent(handoff.id)}`}>Open incident ?</Link> : null}
  </section>;
}
