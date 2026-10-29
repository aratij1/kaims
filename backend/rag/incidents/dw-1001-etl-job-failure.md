alert_id: DW-1001
alert_name: ETL Job Failure
service: airflow
severity: critical
alert_type: etl_failure
source_system: internal
source_ref: DW-1001
dependencies: Source database availability, Downstream jobs and consumers, Credential validity, Network connectivity between Airflow and the source system
deployment: ETL workflow / DAG changes for sales_etl
execution_plan: airflow dags trigger sales_etl; validate DAG logs; re-run workflow if safe

# ETL Job Failure (DW-1001)

Service: airflow
Severity: CRITICAL
Alert type: etl_failure

## Summary
Scheduled ETL workflow failed before successful completion.

## Symptoms
- DAG failed
- Downstream jobs not triggered
- Missing daily data load

## Root Cause
- Source database unavailable
- SQL query failure
- Network timeout
- Invalid credentials

## Impact
- Service: airflow Severity: CRITICAL Alert type: etl_failure

## Dependencies
- Source database availability
- Downstream jobs and consumers
- Credential validity
- Network connectivity between Airflow and the source system

## Deployment Context
- Recent DAG or workflow changes for `sales_etl`
- Potential code, configuration, or credential updates affecting task execution

## Execution Plan
- Review the Airflow DAG logs for the failing task and exact error.
- Verify source connectivity and credential validity.
- Confirm whether a deployment or configuration change preceded the failure.
- Execute `airflow dags trigger sales_etl` if the workflow is safe to rerun.
- Validate downstream jobs and the daily data load after rerun.

## Investigation Timeline
1. Check Airflow DAG logs
2. Verify source connectivity
3. Validate credentials
4. Review recent code changes

## Remediation
- Retry failed task
- Fix source connectivity
- Correct SQL logic
- Re-run workflow

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
- It intentionally consolidates dependencies, deployment context, and execution guidance into one incident record for faster retrieval and operator use.
