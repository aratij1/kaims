alert_id: DW-1005
alert_name: Data Quality Check Failed
service: dq-framework
severity: critical
alert_type: data_quality
source_system: internal
source_ref: DW-1005
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Run dq validation job

# Data Quality Check Failed (DW-1005)

Service: dq-framework
Severity: CRITICAL
Alert type: data_quality

## Summary
Data quality rules failed on the latest batch or ingestion pass.

## Symptoms
- Validation errors
- Unexpected nulls or duplicates
- Transformation mismatches

## Root Cause
- Null values
- Duplicate records
- Invalid transformations

## Impact
- Service: dq-framework Severity: CRITICAL Alert type: data_quality

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Run dq validation job

## Investigation Timeline
1. Identify bad records
2. Run validation scripts
3. Trace transformation outputs

## Remediation
- Identify bad records
- Run validation scripts
- Reprocess dataset

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
