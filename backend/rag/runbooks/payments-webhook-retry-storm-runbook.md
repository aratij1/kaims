kind: runbook
title: Payments webhook retry storm response runbook
services: payments-webhook
owner_team: payments-ops
last_reviewed: 2026-07-08
source_system: internal
source_ref: INC-PAY-002

# Payments webhook retry storm response runbook

## Triage
1. Confirm alert severity CRITICAL and impacted service payments-webhook.
2. Check metrics, logs, and dependencies for anomaly start time.
3. Validate whether recent deployment/change windows overlap incident start.

## Remediation
1. Execute: Throttle retries and enable exponential backoff.
2. Validate service recovery and alert stabilization.
3. Record root cause and prevention notes.
