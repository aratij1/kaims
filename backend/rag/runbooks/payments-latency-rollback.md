kind: runbook

title: Payments latency rollback

services: payments, checkout

owner_team: platform-ops

last_reviewed: 2026-07-08

source_system: internal

source_ref: RUNBOOK-PAYMENTS-LATENCY-ROLLBACK

deployment: Deployment 2.5



# Payments latency rollback



If payment checkout latency increases immediately after Deployment 2.5, compare

the alert start time with the deployment window. Prefer rollback of

`payments-api` before risky configuration changes.



Recommended remediation:



1. Confirm p95 latency and error-rate regression in Prometheus.

2. Notify payments-sre in the incident channel.

3. Roll back `payments-api` to the previous stable release.

4. Validate latency, CPU, and error-rate recovery.

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
