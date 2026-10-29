kind: sop
title: Orders database replica lag operational SOP
services: orders-db
owner_team: platform-ops
last_reviewed: 2026-07-08
source_system: internal
source_ref: INC-NEW

# Orders database replica lag SOP

## Objective
Standardize operator response for Orders database replica lag.

## Trigger Conditions
- Alert orders-replica-lag is active in prod.
- Severity is CRITICAL.

## Procedure
1. Verify incident context and impacted dependencies.
2. Apply approved action: Failover database.
3. Confirm closure criteria and document evidence.
