-- Indexed alert identity for reference-safe retention on large snapshot tables.
SET SESSION lock_wait_timeout = 120;
SET @snapshot_alert_column_exists := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='context_snapshots' AND column_name='retention_alert_id');
SET @snapshot_alert_sql := IF(@snapshot_alert_column_exists=0, 'ALTER TABLE context_snapshots ADD COLUMN retention_alert_id VARCHAR(64) GENERATED ALWAYS AS (REPLACE(JSON_UNQUOTE(JSON_EXTRACT(payload, ''$.alert.id'')), ''-'', '''')) VIRTUAL, ALGORITHM=INPLACE, LOCK=NONE', 'SELECT 1');
PREPARE snapshot_alert_stmt FROM @snapshot_alert_sql;
EXECUTE snapshot_alert_stmt;
DEALLOCATE PREPARE snapshot_alert_stmt;
SET @snapshot_alert_index_exists := (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='context_snapshots' AND index_name='idx_context_snapshots_retention_alert');
SET @snapshot_alert_sql := IF(@snapshot_alert_index_exists=0, 'ALTER TABLE context_snapshots ADD INDEX idx_context_snapshots_retention_alert (tenant_id, retention_alert_id), ALGORITHM=INPLACE, LOCK=NONE', 'SELECT 1');
PREPARE snapshot_alert_stmt FROM @snapshot_alert_sql;
EXECUTE snapshot_alert_stmt;
DEALLOCATE PREPARE snapshot_alert_stmt;
