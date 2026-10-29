export type IncidentGroupFilters = {
  risk_tier?: string;
  execution_mode?: string;
  transport_provider?: string;
  status?: string;
  service?: string;
};

export type IncidentGroupPageOptions = {
  cursor?: string;
  limit?: number;
};

const UNFILTERED = "all";

export function buildIncidentGroupQuery(
  options: IncidentGroupPageOptions,
  filters: IncidentGroupFilters,
): string {
  const params = new URLSearchParams({ limit: String(options.limit || 50) });
  const cursor = String(options.cursor || "").trim();
  if (cursor) params.set("cursor", cursor);
  for (const key of ["risk_tier", "execution_mode", "transport_provider", "status"] as const) {
    const value = String(filters[key] || UNFILTERED);
    if (value !== UNFILTERED) params.set(key, value);
  }
  const service = String(filters.service || "").trim();
  if (service) params.set("service", service);
  return params.toString();
}
