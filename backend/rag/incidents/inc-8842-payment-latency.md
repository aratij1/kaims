alert_id: INC-8842
alert_name: INC-8842 payment latency after Deployment 2.5
service: payments
severity: high
alert_type: latency
source_system: internal
source_ref: INC-8842
dependencies: checkout, ledger, fraud, postgres-primary
deployment: Deployment 2.5
execution_plan: Confirm checkout latency regression; Roll back deployment; Validate SLO recovery

# INC-8842 payment latency after Deployment 2.5 (INC-8842)

Service: payments
Severity: HIGH
Alert type: latency

## Summary
Deployment 2.5 increased checkout p95 latency for payments. Rollback restored service health within minutes. The incident impacted payment authorization and checkout completion latency.

## Symptoms
- Deployment 2.5 increased checkout p95 latency for payments. Rollback restored service health within minutes. The incident impacted payment authorization and checkout completion latency.

## Root Cause
- Deployment 2.5.

## Impact
- Payment latency.

## Dependencies
- checkout
- ledger
- fraud
- postgres-primary

## Deployment Context
- Deployment 2.5 changed payment timeout handling and checkout retry behavior.
- The deployment touched `payments-api`, downstream `checkout`, and ledger authorization paths.

## Execution Plan
1. Confirm checkout latency regression.
2. Roll back deployment.
3. Validate SLO recovery.

## Investigation Timeline
1. Tie the alert onset to the Deployment 2.5 window.
2. Compare checkout p95 latency against the SLO threshold.
3. Confirm rollback restored service health.

## Remediation
- Roll back deployment.
- Restore payment service health.

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from inc-8842-payment-latency.md and is intended for retrieval, SOPs, and runbook-driven operations.
