# Incident detail cleanup ? 2026-09-13

## Deployed changes

- Removed unused IncidentDecisionWorkspace component, its stylesheet, and tests exclusively for that retired component.
- Removed four unreachable standalone UI branches (243 lines): sidebar, hero, report banner, and alternate cockpit launcher.
- Restored recommendation.impact to the canonical investigation workspace projection. Previously only customer_impact/business_impact were read.
- A plain impact statement now defaults to unconfirmed rather than established. Existing typed claim status remains authoritative.
- Show recorded impact assessments even when impact is unconfirmed or not established.
- Display unsupported diagnostic candidates openly rather than inside a collapsed details element. No causal confirmation or execution permission is fabricated.

## Validation

- Backend persistence and command contract: 17 passed.
- Frontend quality: 246 passed, one optional live-fixture test skipped. Lint, types, architecture passed; final markup removal also passed lint and production build/bundle budget.
- Authenticated deployed Chromium test: three real incidents, all HTTP 200; canonical RCA, limitations and impact text matched rendered detail pages. No page errors. See ui-detail-live-browser-2026-09-13.log.
- The first synthetic Chromium test failed because its application registry fixture was empty, disabling login. Fixture corrected and rerun; see ui-detail-browser-tests-2026-09-13.log for final result.
- localhost:8501 index serves /assets/index-DM7qvLVk.js, matching the locally built index.
- ui, context-agent and api-gateway running healthy. Previous UI retained as kaims-ui:before-detail-cleanup-20260913.

## Remaining scope

This is not a complete visual redesign or complete legacy runtime removal. App.jsx still supplies authentication, application scope, runtime state and the old alert/knowledge workspaces. Removing it requires migrating those active responsibilities, not deleting their imports. The overview layout is unchanged. Old alert-workspace navigation still needs consolidation with the canonical incident route.

- Fixed login resetting an explicit incident URL to Overview. Canonical incident links now survive sign-in.

- Final synthetic Chromium regression passed (7.8 seconds): direct incident login, canonical analysis rendering, reload/token refresh, and retained analysis after HTTP 503. Application registry, timestamp, and refresh fixtures were corrected; no schema validation was bypassed.
