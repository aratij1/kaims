alert_id: MYSQL-EXPORTER-PRIVILEGE-DENIED
alert_name: mysql-exporter Error from scraper
alert_type: exporter_scrape_privilege_denied
service: mysql-exporter
severity: warning
source_system: internal
source_ref: INC-MYSQL-EXPORTER-001
summary: mysqld_exporter scraper fails with "Access denied; you need (at least one of) the SUPER or REPLICATION CLIENT privilege(s)".
root_cause: The MySQL account mysqld_exporter authenticates with lacks the global PROCESS and REPLICATION CLIENT privileges its default scrapers (slave_status, global_status, global_variables) require. Reusing the application's database user for the exporter is the most common way this happens, since that user is typically scoped to GRANT ALL PRIVILEGES ON <app_db>.* only — full rights on the application schema, but no global/server-level rights at all.
impact: mysqld_exporter's slave_status (and related) scrapers fail every scrape interval; MySQL-related Prometheus metrics for replication/server status are missing or stale, degrading downstream dashboards and alerting for database health.
execution_plan: 1. Identify which MySQL user mysqld_exporter is configured with (--mysqld.username / MYSQLD_EXPORTER_PASSWORD or the DSN).
2. Confirm the privilege gap: SHOW GRANTS FOR '<user>'@'<host>'.
3. Create (or fix) a dedicated low-privilege monitoring user rather than granting these rights to the application user.
4. Grant PROCESS and REPLICATION CLIENT (global scope, no data access) to that dedicated user.
5. Point the exporter at the dedicated user's credentials and restart it.
6. Confirm the scraper errors stop and the Prometheus target is healthy.
recommended_action: Create a dedicated mysql_exporter MySQL user and grant it PROCESS, REPLICATION CLIENT only — do not use root or the application's database user in production.
resolved_by: platform-ops
closed_at: 2026-07-27

# mysql-exporter Error from scraper — Access denied (missing privileges)

## Summary
mysqld_exporter's `slave_status` scraper (and other default scrapers) return
`Error 1227 (42000): Access denied; you need (at least one of) the SUPER,
REPLICATION CLIENT privilege(s) for this operation` because the MySQL account
it authenticates as does not hold those global privileges.

## Description
mysqld_exporter's default collector set issues `SHOW SLAVE STATUS` /
`SHOW REPLICA STATUS` and reads `information_schema`/`performance_schema`
global state. These require `REPLICATION CLIENT` (or `SUPER`) and `PROCESS`
at the global (`*.*`) scope — privileges an application database user
normally never has, since that user is intentionally scoped to
`GRANT ALL PRIVILEGES ON <app_database>.*` only (full rights on its own
schema, nothing server-wide). Pointing the exporter at that application user
is what produces this alert.

## Root Cause
The MySQL user configured for mysqld_exporter lacks the global `PROCESS` and
`REPLICATION CLIENT` privileges. Confirmed via `SHOW GRANTS FOR '<user>'@'%'`
showing only `GRANT ALL PRIVILEGES ON <app_db>.*` (schema-scoped) and no
global grants.

## Diagnosis steps
```sql
-- Identify current grants for the exporter's configured user
SHOW GRANTS FOR '<exporter_user>'@'%';
-- Expect to see ALL PRIVILEGES on one schema only, no global PROCESS/REPLICATION CLIENT
```

## Impact
Prometheus loses MySQL replication/server-status metrics; the `mysql-exporter`
scrape target itself stays reachable (`mysql_up 1`), but specific scrapers
(`slave_status`) log errors every interval and their metrics are absent —
downstream database-health dashboards and alert rules relying on them are
degraded or blind.

## Execution Plan
1. Identify which MySQL user mysqld_exporter is configured with.
2. Confirm the privilege gap with `SHOW GRANTS`.
3. Create a dedicated, least-privilege monitoring user (do not reuse the
   application's database user, and do not use `root` outside of a one-time
   diagnostic test — root satisfies every privilege check trivially, which
   confirms the hypothesis but is never the production fix).
4. Grant only `PROCESS, REPLICATION CLIENT` at global scope.
5. Reconfigure the exporter to use the dedicated user and restart it.
6. Confirm scrape errors stop and the Prometheus target reports healthy.

## Remediation

```sql
CREATE USER IF NOT EXISTS 'mysql_exporter'@'%' IDENTIFIED BY '<strong-password>'
  WITH MAX_USER_CONNECTIONS 3;
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'mysql_exporter'@'%';
FLUSH PRIVILEGES;
```

Then point mysqld_exporter's `--mysqld.username` / `MYSQLD_EXPORTER_PASSWORD`
(or DSN) at `mysql_exporter` instead of the application user or `root`, and
restart the exporter container. Verify with:

```sql
SHOW GRANTS FOR 'mysql_exporter'@'%';
-- Expect exactly: GRANT PROCESS, REPLICATION CLIENT ON *.* TO `mysql_exporter`@`%`
```

No `SELECT`/`INSERT`/`UPDATE`/`DELETE` on any schema is required — the
exporter never reads application data, only server/replication status.
