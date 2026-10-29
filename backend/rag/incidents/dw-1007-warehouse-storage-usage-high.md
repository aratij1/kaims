alert_id: DW-1007
alert_name: Warehouse Storage Usage High
service: snowflake
severity: high
alert_type: capacity
source_system: internal
source_ref: DW-1007
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Archive old partitions job

# Warehouse Storage Usage High (DW-1007)

Service: snowflake
Severity: HIGH
Alert type: capacity

## Summary
Warehouse storage usage is approaching or above capacity thresholds.

## Symptoms
- Storage alerts firing
- Slower maintenance operations

## Root Cause
- Data growth
- Stale historical data

## Impact
- Service: snowflake Severity: MEDIUM Alert type: capacity

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Archive old partitions job

## Investigation Timeline
1. Review storage trends
2. Find stale tables and partitions
3. Check retention policy

## Remediation
- Purge unused tables
- Archive old partitions
- Increase storage quota

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
