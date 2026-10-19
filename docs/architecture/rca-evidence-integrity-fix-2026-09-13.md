# RCA and impact evidence corrections

## Findings
- Alert transport files under landing/ingested_alerts were admissible as application log evidence, including historical snapshots.
- Missing source timestamps were replaced with collection/window time and could appear current.
- Dependency attribution allowed a slow parent span or unrelated unhealthy container to support a dependency cause.
- The running configuration disables deep analysis, which also disabled the impact model step. Stored impact statements inspected had no supporting citations and zero confidence.

## Changes
Collectors and normalization reject alert transport artifacts as operational logs. The RCA compiler also rejects them from old snapshots. Real log event timestamps are preserved; undated records remain non-current. Dependency support requires an identified relationship and the slow downstream service. The UI keeps historical alert artifacts in a separate audit section. Impact summaries no longer become observed-impact claims automatically.

An independent RESOLUTION_IMPACT_ANALYSIS_ENABLED switch is implemented and tested with a mocked router. It preserves the existing deep-analysis default; the deployment overlay explicitly sets it false. Remediation policy is unchanged.

## Validation
Broad backend regression run: 158 passed, one outdated fallback assertion identified and corrected; affected tests rerun separately: 44 passed (rca-evidence-recheck.log). UI evidence component: five tests and TypeScript check passed; targeted ESLint passed. All four images built. Resolution image import and disabled impact gate verified without a model call.

## Remaining qualification
These corrections do not rewrite stored RCA/impact conclusions. Fresh collection and analysis are still required to qualify affected incidents. The screenshot's exact incident ID has been requested.

Automatic approval review rejected enabling new impact model calls because they transmit incident evidence to a remote provider and incur usage costs. The configured remote reasoning provider was verified read-only as Azure OpenAI GPT-4o at truesdlc-test.openai.azure.com. No new impact model calls have been enabled. Explicit approval is required for that step.

## Local rollout
The corrected context-agent, discovery-mcp, resolution-agent and UI images were deployed with docker compose. Existing persisted findings were not regenerated. The impact model switch remains false.
