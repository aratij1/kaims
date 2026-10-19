-- Cover the service fallback and severity filter as well as indexed generated scope.
-- Otherwise MySQL fetches the large alert JSON row for every candidate.
ALTER TABLE alerts ADD INDEX idx_alerts_inbox_cover
    (tenant_id, inbox_canonical_incident_id, inbox_project, service, severity, created_at),
    ALGORITHM=INPLACE, LOCK=NONE;
