alert_id: INC-9011
alert_name: INC-9011 orders database replica lag
service: orders-db
severity: high
alert_type: replication
source_system: internal
source_ref: INC-9011
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Not explicitly documented.

# INC-9011 orders database replica lag (INC-9011)

Service: orders-db
Severity: HIGH
Alert type: replication

## Summary
Orders read replicas lagged behind the primary after a write-heavy campaign. Failover and read traffic shaping restored order reads. The impact was stale order status in customer support and checkout confirmation flows.

## Symptoms
- Orders read replicas lagged behind the primary after a write-heavy campaign. Failover and read traffic shaping restored order reads. The impact was stale order status in customer support and checkout confirmation flows.

## Root Cause
- Not explicitly documented.

## Impact
- Orders read replicas lagged behind the primary after a write-heavy campaign. Failover and read traffic shaping restored order reads. The impact was stale order status in customer support and checkout confirmation flows.

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Not explicitly documented.

## Investigation Timeline
1. Not explicitly documented.

## Remediation
- Not explicitly documented.

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from inc-9011-database-lag.md and is intended for retrieval, SOPs, and runbook-driven operations.
