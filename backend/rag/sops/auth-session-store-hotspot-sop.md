kind: sop
title: Auth session store hotspot operational SOP
services: auth-session
owner_team: identity-ops
last_reviewed: 2026-07-08
source_system: internal
source_ref: INC-AUTH-003

# Auth session store hotspot SOP

## Objective
Standardize operator response for Auth session store hotspot.

## Trigger Conditions
- Alert auth-session-store-hotspot is active in prod.
- Severity is CRITICAL.

## Procedure
1. Verify incident context and impacted dependencies.
2. Apply approved action: Rebalance shards and redirect session writes.
3. Confirm closure criteria and document evidence.
