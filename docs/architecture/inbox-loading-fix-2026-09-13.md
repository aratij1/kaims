# Inbox loading and human-wait correction

The local Unified Inbox backend and UI have been updated and are healthy.

Changes:
- Evidence progress reads are scoped to current incident ownership in the selected workspace before loading requirement and job history.
- Automated collection takes precedence over a pending human evidence request when that request explicitly permits investigation to continue. Blocking requests still take precedence. Assignment failures are classified as collection blocked, not as an assigned human wait.
- The incident detail and inbox use the same progress priority. Actual human waits now belong to the Needs me view in the frontend.
- The page explicitly displays loading progress instead of presenting a blank record area.
- The rollout also activates existing workspace improvements to alert index usage and compact projection loading. Prior workspace edits were preserved.

Validation:
- 31 backend tests passed, including six new parameterized cases covering blocking requests, nonblocking requests, retries, failed assignments, workspace isolation, and inbox/detail parity.
- 22 frontend inbox tests passed; TypeScript and patch whitespace checks passed.
- Browser: 10 records visible, all actively collecting at the time of verification; first feed response 3.466 seconds, refresh 2.241 seconds, both HTTP 200.
- Separate direct endpoint probes after restart: 10.432, 2.243, and 0.096 seconds. Cold-start and concurrent host load still affect latency.
- A pre-change diagnostic with a larger 100-record limit took 41.687 seconds; this is not a like-for-like comparison to the browser's 10-record page.

Browser evidence: `inbox-loading-verification-2026-09-13.json` and matching PNG.
Reproduce the browser check from frontend/react with `node scripts/verify-inbox-loading.mjs`.

Deployment:
The full workspace backend build encountered pre-existing pending migrations.
The running monitoring-adapter instead uses the previously working runtime image
with only `backend/src/common/common/repository.py` overlaid. The migration
compatibility gate remains enabled and the existing migration manifest is intact.
The local base tag is `kaims-inbox-working-base:20260913`; the focused Dockerfile
is `.tmp/Dockerfile.inbox-fix`. Only monitoring-adapter and ui were recreated.
No incident statuses, approval decisions, or human requests were rewritten in the database.
Real human-blocked incidents remain waiting. Changes are local and uncommitted.
