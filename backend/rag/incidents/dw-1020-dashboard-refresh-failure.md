alert_id: DW-1020
alert_name: Dashboard Refresh Failure
service: powerbi-reporting
severity: high
alert_type: reporting
source_system: internal
source_ref: DW-1020
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Restart refresh job

# Dashboard Refresh Failure (DW-1020)

Service: powerbi-reporting
Severity: HIGH
Alert type: reporting

## Summary
Dashboard refresh failed and reporting data is stale.

## Symptoms
- Refresh job failures
- Stale dashboard visuals
- Dataset timeout errors

## Root Cause
- Warehouse unavailable
- Dataset refresh timeout

## Impact
- Service: powerbi-reporting Severity: HIGH Alert type: reporting

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Restart refresh job

## Investigation Timeline
1. Check refresh job logs
2. Validate source connectivity
3. Review dataset timeout settings

## Remediation
- Restart refresh job
- Validate data source connectivity
- Re-run dashboard refresh

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
