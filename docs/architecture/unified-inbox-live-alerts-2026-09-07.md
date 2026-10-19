# Unified inbox and live alert alignment

The incident UI initialized its record mode to incidents and hard-coded
`record_type=incidents` in every inbox request. Existing combined signal rendering
was therefore unreachable. The inbox also did not subscribe to the operational
updates already driving live alerts.

The default is now the combined backend feed, with an explicit Incidents only
option. Requests retain the login project and attention filters; changing record
mode resets the cursor. The backend represents unlinked alerts as signals and
linked occurrences through their canonical incident. Resolved recently and the
closed history remain available. History was not deleted.

The shared authenticated SSE client now publishes a browser notification for
validated operational events. The inbox coalesces updates for 250 ms, prevents
overlapping fetches, preserves trailing updates during a pending fetch, and keeps
its visibility-aware 30-second fallback. No second SSE connection is opened.

Validation: 16 backend persistence/inbox tests, five hook tests, TypeScript,
production build and bundle budgets passed. A browser test against the deployed
UI used intercepted fixture responses to verify signal -> incident -> closed,
project scope, immediate event refresh, and incident-only selection. It created
no production alerts. This validates UI behavior; it is not new recovery evidence.

Docker Hub DNS prevented the normal image build. Deployment used locally built
assets layered onto the existing local UI image. A Windows path issue in the
bundle checker was corrected by passing file URLs directly to readFileSync.

This patch does not add the previously discussed future test/demo ingestion
exclusion policy; provenance filtering remains a separate outstanding change.
