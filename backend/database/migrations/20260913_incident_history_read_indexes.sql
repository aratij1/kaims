-- Narrow indexes for live context history and projection-repair reads.
CREATE INDEX idx_context_enrichment_incident ON context_enrichment_jobs (tenant_id, incident_id, created_at, job_id);
CREATE INDEX idx_human_evidence_incident ON human_evidence_requests (tenant_id, incident_id, created_at, request_id);
CREATE INDEX idx_incident_events_created ON incident_events (created_at, id);
