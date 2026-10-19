import type { AlertStreamRow } from "../app/routeRuntime";

/** Only persisted relationships may join an alert to an incident. */
export function alertIncidentId(row: AlertStreamRow): string {
  const projection = row.incident_projection;
  const candidate = String(row.incident_id || projection?.incident_id || projection?.id || "").trim();
  const alertId = String(row.alert_id || row.id || "").trim();
  return candidate && candidate !== alertId ? candidate : "";
}

export function alertHandoff(row: AlertStreamRow) {
  const id = alertIncidentId(row);
  const disposition = String(row.incident_disposition || "").toLowerCase();
  if (id) return { id, label: disposition === "duplicate" ? "Merged into incident" : "Incident linked", detail: id };
  if (["noise", "suppressed", "ignored", "non_actionable"].includes(disposition)) return { id: "", label: "No incident required", detail: row.suppression_reason || "Suppressed by the recorded intake decision." };
  if (disposition === "duplicate") return { id: "", label: "Duplicate recorded", detail: "The canonical incident link has not been supplied." };
  if (row.error || row.status === "failed") return { id: "", label: "Intake failed", detail: "Review the intake error; no incident link is recorded." };
  if (["queued", "backlog", "pending"].includes(String(row.status || "").toLowerCase())) return { id: "", label: "Queued for processing", detail: "No incident link has been recorded yet." };
  return { id: "", label: "Incident link pending", detail: "This alert has no recorded incident relationship yet." };
}
