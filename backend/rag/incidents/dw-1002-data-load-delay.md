alert_id: DW-1002
alert_name: Data Load Delay
service: data-ingestion
severity: high
alert_type: sla_breach
source_system: internal
source_ref: DW-1002
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Trigger delayed pipeline job; Scale workers if backlog continues

# Data Load Delay (DW-1002)

Service: data-ingestion
Severity: HIGH
Alert type: sla_breach

## Summary
Data was not delivered within the agreed SLA window.

## Symptoms
- Delivery delayed beyond SLA threshold
- Downstream consumers waiting on data

## Root Cause
- Upstream delay
- Resource contention
- Failed dependency job

## Impact
- Service: data-ingestion Severity: HIGH Alert type: sla_breach

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Trigger delayed pipeline job
- Scale workers if backlog continues

## Investigation Timeline
1. Review upstream job status
2. Check queue depth and worker utilization
3. Inspect dependency failures

## Remediation
- Trigger delayed pipeline
- Increase compute resources
- Escalate SLA breach

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
