alert_id: DW-1004
alert_name: Kafka Consumer Lag High
service: kafka-ingestion
severity: high
alert_type: streaming
source_system: internal
source_ref: DW-1004
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: kubectl scale deployment kafka-consumer --replicas=5

# Kafka Consumer Lag High (DW-1004)

Service: kafka-ingestion
Severity: HIGH
Alert type: streaming

## Summary
Streaming consumer lag is increasing and records are not being processed in time.

## Symptoms
- Consumer lag rising
- Records accumulating in queue
- Throughput decreasing

## Root Cause
- Slow consumers
- High message volume
- Consumer crash

## Impact
- Service: kafka-ingestion Severity: HIGH Alert type: streaming

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- kubectl scale deployment kafka-consumer --replicas=5

## Investigation Timeline
1. Inspect consumer lag metrics
2. Check consumer logs
3. Review partition balance

## Remediation
- Scale consumer group
- Restart consumers
- Increase partitions

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
