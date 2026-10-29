alert_id: DW-1013
alert_name: Fact Table Record Count Mismatch
service: sales-fact
severity: critical
alert_type: reconciliation
source_system: internal
source_ref: DW-1013
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Reload affected partition

# Fact Table Record Count Mismatch (DW-1013)

Service: sales-fact
Severity: CRITICAL
Alert type: reconciliation

## Summary
Fact table counts do not match the expected source totals.

## Symptoms
- Count mismatch
- Reconciliation failures
- Partial load indicators

## Root Cause
- Partial load
- Duplicate processing
- Source extraction issue

## Impact
- Service: sales-fact Severity: CRITICAL Alert type: reconciliation

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Reload affected partition

## Investigation Timeline
1. Perform reconciliation
2. Review source extraction
3. Identify duplicates or skipped partitions

## Remediation
- Perform reconciliation
- Reload affected partition

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
