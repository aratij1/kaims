alert_id: AUTH-SESSION-STORE-HOTSPOT
alert_name: Auth session store hotspot
alert_type: datastore_hotspot
service: auth-session
severity: critical
source_system: internal
source_ref: INC-AUTH-003
summary: Authentication sessions concentrated on a hot shard and increased login latency.
root_cause: Uneven shard key distribution in session persistence layer
impact: Intermittent login slowdowns and token refresh failures
execution_plan: 1. Identify hot shard
2. Shift affected traffic
3. Rebalance shard mapping
4. Validate auth latency and refresh success
recommended_action: Rebalance shards and redirect session writes
resolved_by: identity-ops
closed_at: 2026-07-08

# Auth session store hotspot

## Summary
Authentication sessions concentrated on a hot shard and increased login latency.

## Description
Session store write latency exceeded SLO after one shard absorbed disproportionate traffic

## Root Cause
Uneven shard key distribution in session persistence layer

## Impact
Intermittent login slowdowns and token refresh failures

## Execution Plan
1. Identify hot shard
2. Shift affected traffic
3. Rebalance shard mapping
4. Validate auth latency and refresh success

## Remediation
Rebalance shards and redirect session writes
