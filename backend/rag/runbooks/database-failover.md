kind: runbook

title: Orders database failover

services: orders-db, orders

owner_team: platform-ops

last_reviewed: 2026-07-08

source_system: internal

source_ref: RUNBOOK-DATABASE-FAILOVER



# Orders database failover



If orders database replica lag exceeds the read consistency threshold, reduce

traffic to lagging replicas and prepare failover when the primary is saturated.



Recommended remediation:



1. Confirm replica lag and write saturation.

2. Put read replicas in degraded mode.

3. Fail over to a healthy database node when approved.

4. Validate stale reads are resolved and alerts clear.

## Purpose
Clarify when this runbook should be used and what incident outcome it targets.

## Preconditions
- Required access level and tooling
- Any approvals required before taking action
- Safety constraints for production changes

## Triage Signals
- Confirm impacted service and severity
- Verify alert freshness and blast radius
- Identify whether this is likely change-related

## Investigation Steps
1. Capture current symptoms, metrics, and logs.
2. Check recent deploy/change events and dependency health.
3. Isolate probable fault domain before remediation.

## Troubleshooting Steps
1. Run the top 3 service-specific diagnostics for this alert.
2. Compare current telemetry against known-good baseline.
3. Confirm if issue is transient, recurring, or systemic.
4. Decide: remediate now, escalate, or monitor with guardrails.

## Remediation Steps
1. Apply the safest reversible action first.
2. If unresolved, proceed to deeper corrective action.
3. Record what changed and expected recovery signal.

## Validation
- Alert state transitions to healthy/suppressed as expected
- Key SLO/SLI metrics recover to threshold
- No collateral degradation in dependent services

## Rollback
1. Revert the last remediation action if validation fails.
2. Restore prior known-good configuration or release.

## Escalation
- Escalate to owner team if unresolved after first response cycle
- Escalate immediately for data loss, security risk, or expanding blast radius

## Notes
- Capture root cause hypothesis and final confirmed cause
- Add follow-up prevention tasks and owners
