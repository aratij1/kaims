alert_id: DW-1003
alert_name: Source System Unavailable
service: oracle-source
severity: critical
alert_type: source_connectivity
source_system: internal
source_ref: DW-1003
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Run source connectivity probe

# Source System Unavailable (DW-1003)

Service: oracle-source
Severity: CRITICAL
Alert type: source_connectivity

## Summary
Source system is unavailable or cannot be reached from the ingestion layer.

## Symptoms
- Connection errors
- No new source records
- Repeated retry failures

## Root Cause
- Oracle outage
- Network issue
- Firewall blockage

## Impact
- Service: oracle-source Severity: CRITICAL Alert type: source_connectivity

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Run source connectivity probe

## Investigation Timeline
1. Verify source status page
2. Check listener/service health
3. Confirm firewall and routing rules

## Remediation
- Verify database status
- Restart listener
- Restore connectivity

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
