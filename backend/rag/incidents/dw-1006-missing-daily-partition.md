alert_id: DW-1006
alert_name: Missing Daily Partition
service: sales-fact-table
severity: high
alert_type: partition_missing
source_system: internal
source_ref: DW-1006
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Backfill partition script

# Missing Daily Partition (DW-1006)

Service: sales-fact-table
Severity: HIGH
Alert type: partition_missing

## Summary
Expected daily partition is missing from the warehouse table.

## Symptoms
- Partition absent
- Queries missing latest day
- Fresh load not visible

## Root Cause
- ETL failure
- Partition creation job failed

## Impact
- Service: sales-fact-table Severity: HIGH Alert type: partition_missing

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Backfill partition script

## Investigation Timeline
1. Check partition creation workflow
2. Verify ingest completion
3. Inspect orchestration logs

## Remediation
- Backfill partition
- Re-run ingestion workflow

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
