-- Age-first indexes for bounded cleanup; safe after an online manual rollout.
SET SESSION lock_wait_timeout = 10;
SET @retention_index_exists := (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='context_snapshots' AND index_name='idx_context_snapshots_retention');
SET @retention_index_sql := IF(@retention_index_exists=0, 'ALTER TABLE context_snapshots ADD INDEX idx_context_snapshots_retention (collected_at, expires_at, snapshot_id), ALGORITHM=INPLACE, LOCK=NONE', 'SELECT 1');
PREPARE retention_index_stmt FROM @retention_index_sql;
EXECUTE retention_index_stmt;
DEALLOCATE PREPARE retention_index_stmt;
SET @retention_index_exists := (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='resolution_outbox' AND index_name='idx_resolution_outbox_retention');
SET @retention_index_sql := IF(@retention_index_exists=0, 'ALTER TABLE resolution_outbox ADD INDEX idx_resolution_outbox_retention (status, published_at, event_id), ALGORITHM=INPLACE, LOCK=NONE', 'SELECT 1');
PREPARE retention_index_stmt FROM @retention_index_sql;
EXECUTE retention_index_stmt;
DEALLOCATE PREPARE retention_index_stmt;
