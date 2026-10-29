kind: sop
title: Payments webhook retry storm operational SOP
services: payments-webhook
owner_team: payments-ops
last_reviewed: 2026-07-08
source_system: internal
source_ref: INC-PAY-002

# Payments webhook retry storm SOP

## Objective
Standardize operator response for Payments webhook retry storm.

## Trigger Conditions
- Alert payments-webhook-retry-storm is active in prod.
- Severity is CRITICAL.

## Procedure
1. Verify incident context and impacted dependencies.
2. Apply approved action: Throttle retries and enable exponential backoff.
3. Confirm closure criteria and document evidence.
