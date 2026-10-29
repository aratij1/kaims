kind: runbook

title: Data Warehouse Incident Response Runbook

services: data-warehouse

owner_team: platform-ops

last_reviewed: 2026-07-08

source_system: internal

source_ref: RUNBOOK-DATA-WAREHOUSE-INCIDENT-RESPONSE



# Data Warehouse Incident Response Runbook



This runbook is derived from RAG_doc.docx and covers the standard operating procedures for incident triage,

investigation, remediation, and escalation across ETL, ingestion, warehouse, streaming, and reporting alerts.



## Standard Operating Procedure

1. Identify the alert id, service, severity, and affected data domain.

2. Check the orchestration layer first: Airflow, CDC, streaming consumers, and downstream dependencies.

3. Validate freshness, counts, and the latest successful pipeline execution.

4. Use safe remediation first: retry, backfill, restart, or scale depending on the alert type.

5. Confirm recovery with data validation, record counts, and dashboard refresh.

6. Capture the resolution and update the incident knowledge base.



## Cross-Alert Response Matrix

- DW-1001 ETL Job Failure | airflow | CRITICAL | etl_failure

- DW-1002 Data Load Delay | data-ingestion | HIGH | sla_breach

- DW-1003 Source System Unavailable | oracle-source | CRITICAL | source_connectivity

- DW-1004 Kafka Consumer Lag High | kafka-ingestion | HIGH | streaming

- DW-1005 Data Quality Check Failed | dq-framework | CRITICAL | data_quality

- DW-1006 Missing Daily Partition | sales-fact-table | HIGH | partition_missing

- DW-1007 Warehouse Storage Usage High | snowflake | MEDIUM | capacity

- DW-1008 Query Performance Degradation | data-warehouse | HIGH | performance

- DW-1009 Replication Lag Exceeded Threshold | replication-service | HIGH | replication

- DW-1010 Schema Drift Detected | customer-ingestion | CRITICAL | schema_change

- DW-1011 Late Arriving Data | transaction-feed | MEDIUM | data_latency

- DW-1012 Dimension Load Failure | customer-dimension | HIGH | etl_failure

- DW-1013 Fact Table Record Count Mismatch | sales-fact | CRITICAL | reconciliation

- DW-1014 Airflow Scheduler Down | airflow | CRITICAL | scheduler

- DW-1015 Spark Executor Memory Exhausted | spark-cluster | HIGH | resource_utilization

- DW-1016 Failed CDC Processing | cdc-pipeline | CRITICAL | change_data_capture

- DW-1017 Business SLA Missed | daily-sales-report | CRITICAL | sla_breach

- DW-1018 Data Pipeline Backlog Growing | data-pipeline | HIGH | backlog

- DW-1019 Unauthorized Data Access Attempt | data-warehouse | CRITICAL | security

- DW-1020 Dashboard Refresh Failure | powerbi-reporting | HIGH | reporting





## Investigation Checklist

- Inspect Airflow DAG and scheduler health.

- Validate source connectivity and replication health.

- Review data quality checks, schema drift, and partition completeness.

- Check consumer lag, backlog growth, and warehouse performance.

- Review audit logs for any security or permission anomalies.



## Remediation Principles

- Prefer reversible actions first.

- Backfill or reprocess when data correctness is impacted.

- Scale or restart when infrastructure is saturated or unhealthy.

- Escalate immediately for security-related alerts.



## Automation Examples

- airflow dags trigger <dag_name>

- systemctl restart airflow-scheduler

- kubectl scale deployment kafka-consumer --replicas=5

- Restart refresh or replication jobs after validation.

## Purpose
Clarify when this runbook should be used and what incident outcome it targets.

## Preconditions
- Required access level and tooling
- Any approvals required before taking action
- Safety constraints for production changes

## Triage Signals
- Confirm impacted service and severity
- Verify alert freshness and blast radius
- Identify whether this is likely change-related

## Investigation Steps
1. Capture current symptoms, metrics, and logs.
2. Check recent deploy/change events and dependency health.
3. Isolate probable fault domain before remediation.

## Troubleshooting Steps
1. Run the top 3 service-specific diagnostics for this alert.
2. Compare current telemetry against known-good baseline.
3. Confirm if issue is transient, recurring, or systemic.
4. Decide: remediate now, escalate, or monitor with guardrails.

## Remediation Steps
1. Apply the safest reversible action first.
2. If unresolved, proceed to deeper corrective action.
3. Record what changed and expected recovery signal.

## Validation
- Alert state transitions to healthy/suppressed as expected
- Key SLO/SLI metrics recover to threshold
- No collateral degradation in dependent services

## Rollback
1. Revert the last remediation action if validation fails.
2. Restore prior known-good configuration or release.

## Escalation
- Escalate to owner team if unresolved after first response cycle
- Escalate immediately for data loss, security risk, or expanding blast radius

## Notes
- Capture root cause hypothesis and final confirmed cause
- Add follow-up prevention tasks and owners
