kind: runbook
title: Prometheus and MySQL landing pad triage
services: api-gateway, monitoring-adapter, mysql
owner_team: platform-ops
last_reviewed: 2026-07-10
source_system: internal
source_ref: RUNBOOK-PROMETHEUS-MYSQL-LANDING-PAD

# Prometheus and MySQL landing pad triage

Use this runbook when Prometheus or MySQL alerts are pushed to KaiOps landing pad through Alertmanager.

## Trigger signals

- Alert name: `KaiOpsServiceDown`
- Alert name: `KaiOpsHighLatencyP95`
- Alert name: `MySQLExporterDown`
- Alert name: `MySQLTooManyConnections`

## First response

1. Confirm alert is still firing in Prometheus alerts page.
2. Open KaiOps Dashboard -> Alert Stream and locate the same alert by name/service.
3. Validate alert labels include service, severity, and alert_status=firing.

## Diagnostics

1. Service health:
   - `GET /healthz` for impacted service.
   - Review `docker compose ps` for container status.
2. Latency alerts:
   - Query p95 with PromQL using `kaiops_request_latency_seconds` buckets.
3. MySQL connection alerts:
   - Check `mysql_global_status_threads_connected` in Prometheus.
   - Check app connection pools and long-running queries.

## Remediation guidance

1. For service down:
   - Restart impacted service container.
   - Validate dependencies (mysql, redis, kafka, rabbitmq).
2. For high latency:
   - Identify hot endpoint and rollback recent risky deployment if needed.
   - Scale service replicas or reduce expensive query paths.
3. For high MySQL connections:
   - Remove leaked idle connections.
   - Tune pool size and query timeout.

## Validation

- Alert clears from Prometheus and Alertmanager.
- New incoming alerts continue reaching KaiOps landing pad.
- No error spikes in gateway or monitoring-adapter logs.
