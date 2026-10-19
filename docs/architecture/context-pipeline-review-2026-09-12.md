# Context and RCA pipeline review ? 12 September 2026

The previous UI loading fix did not resolve stalled RCA synthesis. This review traced the stored snapshot, iterative investigation, synthesis model call, recommendation binding, requirement planning, canonical API, and incident view.

## Reproduced failures

1. Incident 4c340f46-785c-4f1c-acfc-3a06166cfdd8 retained 105 records. Its synthesis used heuristic-fallback, generated zero citations, and published no missing evidence. A separate iterative stage claimed conclusive with two trace IDs. Those IDs were not citations from the failed synthesis and must not be silently promoted into an accepted RCA.
2. The recorded synthesis request was 67,783 bytes despite a 48,000-byte configured budget. Compaction only removed several top-level keys and could leave large nested reports over budget. Removing whole evidence arrays also deprived the model of source references.
3. Evidence planning discarded prose or unknown category codes. Structured requirements were stringified during handoff, losing question and connector scope. Explicit empty connector lists were replaced by default connectors.
4. Previously collected questions suppressed the same explicit unresolved question in later RCA versions. Active work should be reused; historical collection is not proof that a new RCA gap is satisfied.
5. Canonical display hid model fallback and read quality_gate.blocking_reasons even though the producer writes blockers. Text causal chains were converted into lists of individual characters.
6. Evidence was collapsed, and the canonical incident page lacked a direct governed retry action.

## Shared changes

- Enforce model payload bounds recursively while retaining arrays of attributable evidence; reject a still oversized request explicitly rather than sending it over budget.
- Preserve structured and prose gaps. Unknown questions become explicit unbound review requests, rather than guessed automatic collection that can falsely satisfy them.
- Publish a review gap when synthesis returns no validated citations, including when a separate iterative report says conclusive.
- Make question deduplication RCA-version aware while keeping initial probes one-time and reusing active collection.
- Explain fallback on existing canonical read models; expose quality blockers and normalize textual explanations.
- Show evidence immediately and provide Rerun investigation through the existing tenant-scoped, durable fresh-analysis endpoint. The button reports pending/failure states and does not approve remediation.

## Live verification

A small model-router health check returned a real model response without fallback. Read-only synthesis replay used two retained incident contexts through the deployed resolution agent and model router:

| Incident | Original request | Sent request | Model fallback | Citations | Explicit gaps |
| --- | ---: | ---: | --- | ---: | ---: |
| 4c340f46-785c-4f1c-acfc-3a06166cfdd8 (KaiMS) | 136938 | 34125 | No | 2 | 1 |
| 32f77019-ab6b-4945-8942-4b305022b18d (Telemetry) | 168596 | 33474 | No | 0 | 5 |

Both were below the 48000-byte budget. Replay did not persist recommendations, publish remediation, or change tickets. Two citations do not by themselves establish causality; the Telemetry evidence remained insufficient. The old 67783-byte request and replay input differ, so this is evidence of corrected budget enforcement, not a controlled measurement attributing the earlier provider fallback solely to size.

Post-deployment reads checked four KaiMS/Telemetry incidents: 105, 151, 159, and 151 retained evidence records. The screenshot incident now explicitly exposes the synthesis fallback and missing citation review gap. Stored historic recommendations are retained until governed reanalysis publishes a replacement.

## Validation and limits

140 backend tests and 45 UI tests passed. Backend regression coverage includes model payload budgets, structured/prose gaps, RCA propagation, iterative investigation, enrichment lifecycle, canonical bindings and command contracts. UI coverage includes context refresh/navigation, evidence visibility/pagination, retry submission and errors, and incident entry routes. Typecheck and production bundle budgets passed.

The deployment uses fresh application code on the existing local runtime images. Rollback tags are kaims-context-agent:before-pipeline-context-fix, kaims-resolution-agent:before-pipeline-context-fix, and kaims-ui:before-pipeline-context-fix.

This is not proof of a full authenticated browser-to-remediation-to-recovery cycle. The model replay intentionally did not overwrite historical results. Existing evidence gaps, unbound capabilities, and absent recovery validation remain explicit. No external Jira issue was created or linked in this review.
