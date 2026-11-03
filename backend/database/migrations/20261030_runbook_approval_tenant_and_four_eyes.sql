SET @has_approval_tenant := (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'runbook_approvals'
      AND column_name = 'tenant_id'
);
SET @sql := IF(@has_approval_tenant = 0,
    'ALTER TABLE runbook_approvals ADD COLUMN tenant_id VARCHAR(128) NULL',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_approval_reviewer := (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'runbook_approvals'
      AND column_name = 'reviewer'
);
SET @sql := IF(@has_approval_reviewer = 0,
    'ALTER TABLE runbook_approvals ADD COLUMN reviewer VARCHAR(255) NULL',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_approval_checksum := (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'runbook_approvals'
      AND column_name = 'content_sha256'
);
SET @sql := IF(@has_approval_checksum = 0,
    'ALTER TABLE runbook_approvals ADD COLUMN content_sha256 VARCHAR(64) NULL',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_approval_tenant_index := (
    SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'runbook_approvals'
      AND index_name = 'ix_runbook_approvals_tenant_id'
);
SET @sql := IF(@has_approval_tenant_index = 0,
    'CREATE INDEX ix_runbook_approvals_tenant_id ON runbook_approvals (tenant_id)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

UPDATE runbook_approvals AS approvals
JOIN runbook_versions AS versions
  ON versions.runbook_id = approvals.runbook_id
 AND versions.version = approvals.version
SET approvals.tenant_id = versions.tenant_id
WHERE approvals.tenant_id IS NULL;
