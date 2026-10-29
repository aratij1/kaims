kind: runbook
title: Catalog cache stale reads response runbook
services: catalog-api
owner_team: commerce-ops
last_reviewed: 2026-07-08
source_system: internal
source_ref: INC-CAT-001

# Catalog cache stale reads response runbook

## Triage
1. Confirm alert severity CRITICAL and impacted service catalog-api.
2. Check metrics, logs, and dependencies for anomaly start time.
3. Validate whether recent deployment/change windows overlap incident start.

## Remediation
1. Execute: Drain invalidation backlog and flush affected cache keys.
2. Validate service recovery and alert stabilization.
3. Record root cause and prevention notes.
