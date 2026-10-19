-- RCA commits schedule evidence jobs while holding incident projection locks.
-- Match the lookup so scheduling does not scan/sort JSON-bearing job history.
SET SESSION lock_wait_timeout = 10;
SET @has_enrichment_requirement_index := (
    SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'context_enrichment_jobs'
      AND index_name = 'idx_context_enrichment_job_requirement'
);
SET @enrichment_requirement_index_sql := IF(
    @has_enrichment_requirement_index = 0,
    'ALTER TABLE context_enrichment_jobs ADD INDEX idx_context_enrichment_job_requirement (tenant_id, requirement_id, connector_id, created_at), ALGORITHM=INPLACE, LOCK=NONE',
    'SELECT 1'
);
PREPARE enrichment_requirement_index_stmt FROM @enrichment_requirement_index_sql;
EXECUTE enrichment_requirement_index_stmt;
DEALLOCATE PREPARE enrichment_requirement_index_stmt;
