-- Enforce the tenant/incident relationship for approvals and physical actions.
-- Existing single-ID foreign keys remain in place. No rows are deleted or repaired.
-- Run the read-only ownership preflight before applying on an existing database.
-- MySQL validates existing rows when adding each foreign key; a mismatch fails closed.
SET SESSION lock_wait_timeout = 10;

SET @present := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema=DATABASE() AND table_name='incidents' AND index_name='uq_incidents_tenant_id');
SET @ddl := IF(@present=0, 'ALTER TABLE incidents ADD UNIQUE KEY uq_incidents_tenant_id (tenant_id, id)', 'SELECT 1');
PREPARE tenant_binding_stmt FROM @ddl;
EXECUTE tenant_binding_stmt;
DEALLOCATE PREPARE tenant_binding_stmt;

SET @present := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema=DATABASE() AND table_name='approvals' AND index_name='idx_approvals_tenant_incident');
SET @ddl := IF(@present=0, 'ALTER TABLE approvals ADD INDEX idx_approvals_tenant_incident (tenant_id, incident_id)', 'SELECT 1');
PREPARE tenant_binding_stmt FROM @ddl;
EXECUTE tenant_binding_stmt;
DEALLOCATE PREPARE tenant_binding_stmt;

SET @present := (SELECT COUNT(*) FROM information_schema.table_constraints
    WHERE table_schema=DATABASE() AND table_name='actions' AND constraint_name='fk_actions_tenant_incident');
SET @ddl := IF(@present=0, 'ALTER TABLE actions ADD CONSTRAINT fk_actions_tenant_incident FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id)', 'SELECT 1');
PREPARE tenant_binding_stmt FROM @ddl;
EXECUTE tenant_binding_stmt;
DEALLOCATE PREPARE tenant_binding_stmt;

SET @present := (SELECT COUNT(*) FROM information_schema.table_constraints
    WHERE table_schema=DATABASE() AND table_name='approvals' AND constraint_name='fk_approvals_tenant_incident');
SET @ddl := IF(@present=0, 'ALTER TABLE approvals ADD CONSTRAINT fk_approvals_tenant_incident FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id)', 'SELECT 1');
PREPARE tenant_binding_stmt FROM @ddl;
EXECUTE tenant_binding_stmt;
DEALLOCATE PREPARE tenant_binding_stmt;
