kind: sop
title: Catalog cache stale reads operational SOP
services: catalog-api
owner_team: commerce-ops
last_reviewed: 2026-07-08
source_system: internal
source_ref: INC-CAT-001

# Catalog cache stale reads SOP

## Objective
Standardize operator response for Catalog cache stale reads.

## Trigger Conditions
- Alert catalog-cache-stale is active in prod.
- Severity is CRITICAL.

## Procedure
1. Verify incident context and impacted dependencies.
2. Apply approved action: Drain invalidation backlog and flush affected cache keys.
3. Confirm closure criteria and document evidence.
