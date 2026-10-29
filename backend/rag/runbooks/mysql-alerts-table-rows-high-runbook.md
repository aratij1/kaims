---
title: KaiOps MySQL Alerts Table Rows High Runbook
kind: runbook
alert_type: KaiOpsMySQLAlertsTableRowsHigh
service: mysql
environment: prod
severity: high
metric: kaiops_mysql_alerts_table_rows
connector: kaiops-mysql
owner_team: platform-ops
---

# KaiOpsMySQLAlertsTableRowsHigh Runbook

## Signal
The Prometheus alert `KaiOpsMySQLAlertsTableRowsHigh` fires when metric
`kaiops_mysql_alerts_table_rows{database="kaiops",table="alerts"}` is above the configured threshold.
This means the KaiOps MySQL `alerts` table is growing and may affect alert list latency,
deduplication, incident projection updates, and dashboard responsiveness.

## Scope
- Service: `mysql`
- Database: `kaiops`
- Table: `alerts`
- Connector: `kaiops-mysql`
- Prometheus: `http://prometheus:9090`
- API Gateway: `http://api-gateway:8000`

## Investigation
1. Confirm the live Prometheus alert is `KaiOpsMySQLAlertsTableRowsHigh`.
2. Confirm the service label is `mysql` and environment is `prod`.
3. Query current row count:
   `SELECT COUNT(*) AS alert_rows FROM alerts;`
4. Check recent growth:
   `SELECT DATE(created_at) AS day, COUNT(*) AS rows_added FROM alerts GROUP BY DATE(created_at) ORDER BY day DESC LIMIT 7;`
5. Check whether file watcher, Alertmanager replay, or test alerts are generating repeated duplicate rows.

## Approved Remediation Script
Use one guarded script, not loose commands:

```bash
sh scripts/remediation/kaiops_alert_health_triage.sh --service mysql --environment prod --api-gateway-url http://api-gateway:8000 --prometheus-url http://prometheus:9090 --mysql-host mysql --mysql-database kaiops --mysql-user kaiops --alerts-table alerts --dry-run true
```

This script validates:
- API gateway health
- Prometheus alert visibility
- MySQL `alerts` table row count when database credentials are available

## Live Remediation Policy
Do not delete rows directly from the UI-generated command. If retention cleanup is approved,
run an explicit archive/delete operation through the `kaiops-mysql` connector after dry-run evidence is reviewed.
The dry-run script must complete successfully before any mutating archive action is allowed.

## Rollback
If a retention or archive action causes missing alert evidence, restore from the latest MySQL backup
or retained archive table, then reload affected incident projections.

## Validation Checks
- `kaiops_mysql_alerts_table_rows` falls below the configured threshold.
- `SELECT COUNT(*) AS alert_rows FROM alerts;` returns the expected post-cleanup count.
- Alert stream no longer creates duplicate `KaiOpsMySQLAlertsTableRowsHigh` incidents.
- Incident timeline shows `script_execution` succeeded and closure validation starts.
