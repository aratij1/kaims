alert_id: ORDERS-REPLICA-LAG
alert_name: Orders database replica lag
service: orders-db
severity: critical
alert_type: incident
source_system: internal
source_ref: INC-NEW
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Failover database
resolved_by: platform-ops
closed_at: 2026-07-08

# Orders database replica lag (ORDERS-REPLICA-LAG)

Service: orders-db
Severity: CRITICAL
Alert type: incident

## Summary
Replica lag above threshold for 10 minutes

## Symptoms
- Not explicitly documented.

## Root Cause
- Primary write saturation

## Impact
- Stale reads on order queries

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Failover database

## Investigation Timeline
1. Failover database

## Remediation
- Failover database

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from orders-replica-lag-incident.md and is intended for retrieval, SOPs, and runbook-driven operations.
