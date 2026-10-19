export type IncidentIdentitySource = {
  canonical_incident_id?: unknown;
  incident_id?: unknown;
  id?: unknown;
  incident_projection?: { incident_id?: unknown; id?: unknown } | null;
};

export function durableIncidentId(source: IncidentIdentitySource | null | undefined): string {
  const projection = source?.incident_projection;
  return [source?.canonical_incident_id, source?.incident_id, projection?.incident_id, projection?.id, source?.id]
    .map((value) => String(value ?? "").trim()).find(Boolean) || "";
}

export function durableIncidentPath(source: IncidentIdentitySource | null | undefined): string | null {
  const incidentId = durableIncidentId(source);
  return incidentId ? `/incidents/${encodeURIComponent(incidentId)}` : null;
}

