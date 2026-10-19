# Incident section audit: 936b3ba6-759f-4fb2-ba86-12954a2302ea

## Findings

| Section | Assessment | Correction or limitation |
|---|---|---|
| Header / current state | Persisted waiting-for-human status is real; ?Kai is working? implies activity not established by it. | Describe waiting for human evidence or an open investigation. |
| Resolution journey | Non-empty JSON observation advanced the view to root cause. | Causal progress now requires a confirmed claim, not just non-empty text. Earlier checkmarks still represent lifecycle stages, not proof of impact. |
| Observed state | ?Impact not established? is appropriately cautious. | Retained. An alert does not establish customer impact or packet loss. |
| Working hypothesis | Source JSON is an observation, not a causal explanation. | Show no explanatory causal hypothesis; retain original text in expandable recorded observation. |
| Citation count | Traceability was labelled validation. | Label traceable citations. References do not establish correctness or causality. |
| Confidence | Recommendation-level percentage was attached to the leading claim without binding. | Only display a numeric 0?1 confidence explicitly present on that claim; otherwise unavailable. No calibrated probability is inferred. |
| Supporting rationale | Empty rationale is real missing information. | Label recorded supporting rationale; do not invent supporting reasons. |
| Ruled-out causes | Contradictions, evidence IDs and alternatives were combined and labelled ruled out. | Label contradictions and alternatives recorded; do not claim elimination. |
| Resolution gate | No executable plan and blocked prerequisites are backed by the stored operation state. | Retained; the absence of a plan is not a diagnosis. |
| Investigation records | Counts represent attached and RCA-linked records, not independent corroborations. | Retained with traceability wording; no claims that record count proves cause. |
| Evidence collection | Human request was obscured by a previous dead-letter job; generic collection claims overstate source availability. | Current request status first, prior job shown separately; explain that requests do not establish source availability. |
| Trace failure | TRACE_NOT_FOUND_OR_EXPIRED cannot prove a trace once existed or expired. | Say no matching trace retrieved; confirm a trace source exists before requesting it. |
| Trace requirement / why needed | Generic span/causal-chain request is stored backend text, but applicability to external httpbin is not established. | Backend requirement remains unresolved; not silently cancelled. Requires collector/planner correction or authorized evidence review. |
| AI-generated evidence draft | Suggested text is a request/template, not an observation. | Existing editable-draft label retained; it must not be submitted as verified evidence without a source. |
| Causal chain | Repeating raw observation as a cause was misleading. | Uses the corrected causal presentation; remains incomplete. |
| Recovery validation | No report exists. ?Waiting for execution? incorrectly assumes execution is required before every recovery assessment. | Say no recovery validation recorded; require actual observations. |
| Timeline | created_at and updated_at are record timestamps, not a complete state-transition history. | Label recorded history and record update; explicitly identify incomplete event coverage. |
| Evidence provenance | Alert ID is not a canonical evidence ID; context quality is not causal confidence. | Label source alert ID and recorded context score. |
| Human handoff | Existing endpoint assigns a responder and administratively closes automation. | UI accurately discloses this; it is not technical recovery. |
| Human control | No active executable control is available. | Disabled controls retained; no rollback capability claimed. |
| Administrative closure | Explicitly distinguishes disposition from recovery. | Retained. No closure executed in this audit. |

## Scope

These changes correct presentation and preserve stored records. They do not
publish the operator RCA as an accepted backend RCA, manufacture distributed
traces, establish customer impact, or close the incident. The prior operator RCA
and paired probe observations remain separate artifacts. The stored generic
trace requirement and generation of observation-only RCA text are backend gaps
that remain visible, rather than being disguised by the UI.

Validation: eight focused claim/collection tests, TypeScript, build and bundle
budgets. Exact-incident browser verification passed: observation-only text, unavailable
claim confidence, traceability labelling and neutral trace failure wording.
Screenshot: incident-truth-audit-936b3ba6.png.


## Shared backend correction

The resolution agent no longer emits typed causal claims from derived observations or legacy observation-only fallback statements. Alert names containing latency plus arbitrary telemetry/log rows no longer establish impact. External blackbox/public-internet first-wave evidence requests now ask for timestamped HTTP status, probe success, DNS and TLS diagnostics instead of mandatory distributed traces. Internal first-wave requirements are unchanged.

Validation: 120 focused backend investigation, enrichment, contract and repository tests passed. Deployed locally to resolution-agent. Existing stored RCA snapshots and historical evidence requests were not rewritten; existing trace requests can therefore remain open pending reassessment. This change does not establish root cause, authorize remediation, or prove recovery for any existing incident.


## Live reassessment follow-up

The earlier deployment did not repair persisted RCA v1 or its generic trace requirement. A fresh analysis was requested through the authenticated regeneration API (request ef4bf175-7ae3-4001-a402-6be339bbce55), producing RCA v2. The reconciliation path now cancels only the exact obsolete generic trace question for external probes; specific trace questions remain unchanged.

The replacement metrics job initially failed with PROMETHEUS_SERIES_INCOMPLETE: the aggregate alert expression discarded metric names and covered multiple endpoints. Targeted blackbox metrics collection now requests named probe measurements with an exact instance matcher. A read-only live check retrieved five named series. The single failed job was retried with an audit record preserving prior failure and attempt count; it subsequently reached collected, with its requirement marked collected.

The shared UI now presents causal candidates with no resolved supporting evidence as untested diagnostic candidates rather than the main explanation. Live browser verification confirmed the unavailable explanatory-cause heading, Understanding stage, and absence of the obsolete generic trace request. No incident was closed or marked recovered by this repair.

Validation: 35 collector/enrichment tests, 9 UI tests, TypeScript checking, and bundle-budget checking passed. Context agent, resolution agent, and UI were deployed locally. Existing incidents were not bulk reassessed; confirmed root cause and recovery remain separate outstanding work.

Final live check: enrichment triggered RCA v3. The canonical workspace has no active requirements, two traceable citations, and REVIEW_RCA as the next action; the incident remains investigating. Its conclusion is inconclusive. The UI now also excludes inconclusive status sentences from causal-hypothesis presentation. Ten UI tests passed, and the final browser check passed against RCA v3. Archived requirements remain available in collapsed history.
