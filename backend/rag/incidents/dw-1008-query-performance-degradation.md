alert_id: DW-1008
alert_name: Query Performance Degradation
service: data-warehouse
severity: high
alert_type: performance
source_system: internal
source_ref: DW-1008
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Refresh warehouse stats

# Query Performance Degradation (DW-1008)

Service: data-warehouse
Severity: HIGH
Alert type: performance

## Summary
Query execution time has degraded in the warehouse or reporting layer.

## Symptoms
- Longer dashboard load times
- Slow query execution
- Higher CPU/IO usage

## Root Cause
- Missing indexes
- Poor execution plan
- Large table scans

## Impact
- Service: data-warehouse Severity: HIGH Alert type: performance

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Refresh warehouse stats

## Investigation Timeline
1. Analyze query plan
2. Refresh statistics
3. Identify scans and joins

## Remediation
- Analyze query plan
- Refresh statistics
- Optimize SQL

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
