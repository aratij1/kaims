alert_id: PAYMENTS-WEBHOOK-RETRY-STORM
alert_name: Payments webhook retry storm
alert_type: retry_storm
service: payments-webhook
severity: critical
source_system: internal
source_ref: INC-PAY-002
summary: Payments webhooks retried aggressively after downstream 429 responses.
root_cause: Missing exponential backoff on webhook dispatcher
impact: Delayed merchant notifications and elevated queue depth
execution_plan: 1. Inspect retry queue depth
2. Apply dispatcher throttle
3. Enable backoff configuration
4. Validate delivery latency
recommended_action: Throttle retries and enable exponential backoff
resolved_by: payments-ops
closed_at: 2026-07-08

# Payments webhook retry storm

## Summary
Payments webhooks retried aggressively after downstream 429 responses.

## Description
Webhook delivery retries spiked 8x and saturated outbound workers for 12 minutes

## Root Cause
Missing exponential backoff on webhook dispatcher

## Impact
Delayed merchant notifications and elevated queue depth

## Execution Plan
1. Inspect retry queue depth
2. Apply dispatcher throttle
3. Enable backoff configuration
4. Validate delivery latency

## Remediation
Throttle retries and enable exponential backoff
