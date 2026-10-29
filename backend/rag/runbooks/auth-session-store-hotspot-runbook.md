kind: runbook
title: Auth session store hotspot response runbook
services: auth-session
owner_team: identity-ops
last_reviewed: 2026-07-08
source_system: internal
source_ref: INC-AUTH-003

# Auth session store hotspot response runbook

## Triage
1. Confirm alert severity CRITICAL and impacted service auth-session.
2. Check metrics, logs, and dependencies for anomaly start time.
3. Validate whether recent deployment/change windows overlap incident start.

## Remediation
1. Execute: Rebalance shards and redirect session writes.
2. Validate service recovery and alert stabilization.
3. Record root cause and prevention notes.
