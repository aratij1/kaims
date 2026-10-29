kind: runbook
title: mysql-exporter privilege denied response runbook
services: mysql-exporter, mysql
owner_team: platform-ops
last_reviewed: 2026-07-27
source_system: internal
source_ref: INC-MYSQL-EXPORTER-001

# mysql-exporter privilege denied response runbook

## Triage
1. Confirm the exact error in exporter logs: `Access denied; you need (at
   least one of) the SUPER, REPLICATION CLIENT privilege(s)`.
2. Identify the MySQL user the exporter is configured with (`--mysqld.username`
   / `MYSQLD_EXPORTER_PASSWORD` or its DSN).
3. Run `SHOW GRANTS FOR '<user>'@'<host>';` — a privilege-denied scraper error
   means that user has no global `PROCESS`/`REPLICATION CLIENT` grant, most
   commonly because it's the application's own database user (scoped only to
   `ALL PRIVILEGES` on the app schema, not globally).
4. Optional one-time diagnostic only: temporarily point the exporter at
   `root` to confirm the hypothesis (root satisfies every privilege trivially).
   Never leave root configured — it is not the fix, only confirmation.

## Remediation
1. Execute:
```sql
CREATE USER IF NOT EXISTS 'mysql_exporter'@'%' IDENTIFIED BY '<strong-password>'
  WITH MAX_USER_CONNECTIONS 3;
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'mysql_exporter'@'%';
FLUSH PRIVILEGES;
```
2. Reconfigure mysqld_exporter to authenticate as `mysql_exporter` instead of
   the application user or `root`, then restart the exporter.
3. Validate service recovery: exporter logs show no further "Access denied"
   errors, `mysql_up == 1`, and the Prometheus target for the exporter
   reports `health: up`.
4. Record root cause and prevention notes: exporter credentials must always
   be a dedicated least-privilege user, never the application DB user or
   root, to avoid both this failure mode and over-privileging application
   code.
