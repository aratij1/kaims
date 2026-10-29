alert_id: DW-1018
alert_name: Data Pipeline Backlog Growing
service: data-pipeline
severity: high
alert_type: backlog
source_system: internal
source_ref: DW-1018
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Scale processing cluster

# Data Pipeline Backlog Growing (DW-1018)

Service: data-pipeline
Severity: HIGH
Alert type: backlog

## Summary
Data pipeline backlog is growing and records are not being processed quickly enough.

## Symptoms
- Queue depth increasing
- Lagging freshness
- Worker saturation

## Root Cause
- Slow processing
- Increased ingestion volume

## Impact
- Service: data-pipeline Severity: HIGH Alert type: backlog

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Scale processing cluster

## Investigation Timeline
1. Check backlog growth rate
2. Inspect worker throughput
3. Review ingestion spikes

## Remediation
- Scale processing cluster
- Increase worker nodes

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
