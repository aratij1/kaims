alert_id: DW-1014
alert_name: Airflow Scheduler Down
service: airflow
severity: critical
alert_type: scheduler
source_system: internal
source_ref: DW-1014
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: systemctl restart airflow-scheduler

# Airflow Scheduler Down (DW-1014)

Service: airflow
Severity: CRITICAL
Alert type: scheduler

## Summary
Workflow scheduler is unavailable and orchestration is paused.

## Symptoms
- No DAG scheduling
- Pending jobs not starting
- Scheduler alerts

## Root Cause
- Scheduler process crash
- Resource exhaustion

## Impact
- Service: airflow Severity: CRITICAL Alert type: scheduler

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- systemctl restart airflow-scheduler

## Investigation Timeline
1. Check scheduler process status
2. Inspect resource usage
3. Review scheduler logs

## Remediation
- Restart scheduler
- Verify scheduler health

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
