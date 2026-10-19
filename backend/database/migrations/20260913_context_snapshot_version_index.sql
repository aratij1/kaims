-- Cover latest-version reads and locking lookups without sorting JSON payloads.
SET SESSION lock_wait_timeout = 10;
SET @has_context_version_index := (
    SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'context_snapshots'
      AND index_name = 'idx_context_snapshots_incident_version'
);
SET @context_version_index_sql := IF(@has_context_version_index = 0,
    'ALTER TABLE context_snapshots ADD INDEX idx_context_snapshots_incident_version (tenant_id, incident_id, snapshot_version, collected_at), ALGORITHM=INPLACE, LOCK=NONE',
    'SELECT 1');
PREPARE context_version_index_stmt FROM @context_version_index_sql;
EXECUTE context_version_index_stmt;
DEALLOCATE PREPARE context_version_index_stmt;
