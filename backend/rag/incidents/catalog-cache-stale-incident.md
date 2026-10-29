alert_id: CATALOG-CACHE-STALE
alert_name: Catalog cache stale reads
alert_type: cache
service: catalog-api
severity: critical
source_system: internal
source_ref: INC-CAT-001
summary: Catalog API served stale cache entries after invalidation lag.
root_cause: Redis invalidation consumer lag
impact: Customers saw outdated product availability
execution_plan: 1. Check Redis consumer lag
2. Drain backlog
3. Flush affected cache namespace
4. Validate fresh reads
recommended_action: Drain invalidation backlog and flush affected cache keys
resolved_by: commerce-ops
closed_at: 2026-07-08

# Catalog cache stale reads

## Summary
Catalog API served stale cache entries after invalidation lag.

## Description
Cache hit ratio collapsed and stale catalog data persisted for 15 minutes

## Root Cause
Redis invalidation consumer lag

## Impact
Customers saw outdated product availability

## Execution Plan
1. Check Redis consumer lag
2. Drain backlog
3. Flush affected cache namespace
4. Validate fresh reads

## Remediation
Drain invalidation backlog and flush affected cache keys
