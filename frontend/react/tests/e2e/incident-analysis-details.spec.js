import { expect, test } from "@playwright/test";

const id = "34343434-3434-4434-8434-343434343434";
function command() {
  return {
    schema_version: "kaiops.incident-command.v2", incident_id: id, revision: "a".repeat(64),
    incident: { incident_id: id, title: "Recorded assessment incident", service: "api-gateway", status: "investigating", context: { logs: Array.from({ length: 12 }, (_, index) => ({ message: `Database timeout sample ${index + 1}`, source: "collector" })), telemetry: { latency_p95_ms: 725 } } },
    operations: {
      schema_version: "kaiops.operations-state.v1", incident_id: id, lifecycle_state: "INVESTIGATING", updated_at: "2026-09-13T06:00:00Z",
      context: {}, investigation: {}, requirements: [], requirement_history: [], resolution: {}, approval: {},
      investigation_workspace: {
        schema_version: "kaiops.investigation-workspace.v1", binding: { rca_version: 3 },
        impact: { status: "unconfirmed", statement: "Checkout requests may time out." },
        rca: { status: "insufficient_evidence", hypothesis: "Connection pool exhaustion needs verification.", resolved_evidence_ids: [], grounding_notes: "Historical pool metrics are missing." },
        evidence: [], requirements: [], resolution: { status: "blocked" }, operator_review: {},
      },
    },
    evidence: {
      latest_snapshot_id: null, bound_snapshot_id: null, binding_consistent: true,
      counts: { latest_context_records: 0, bound_snapshot_records: 0, rca_bound_records: 0, traceable_citations: 0, unresolved_bindings: 0, open_requirements: 0, pending_requirements: 0, exhausted_requirements: 0, open_conflicts: 0 },
      evidence_collection_exhausted: false, scores: [], blockers: [],
    },
  };
}

async function signIn(page) {
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("fixture-password");
  await page.getByRole("button", { name: /sign in/i }).click();
}

test("canonical details retain unconfirmed RCA and impact across reload and show refresh failures", async ({ page }) => {
  test.setTimeout(120_000);
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  let fail = false;
  await page.route("**/api-gateway/**", async route => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api-gateway/, "");
    if (path === `/incidents/${id}/command`) {
      if (!fail) await new Promise(resolve => setTimeout(resolve, 8_000));
      return route.fulfill({ status: fail ? 503 : 200, contentType: "application/json", body: JSON.stringify(fail ? { detail: "Context service temporarily unavailable" } : command()) });
    }
    const body = path === "/auth/config" ? { mode: "local", local_development_only: true }
      : ["/auth/login", "/auth/refresh"].includes(path) ? { access_token: "fixture-token", refresh_token: "fixture-refresh", user: { id: 1, username: "admin", role_name: "Administrator" } }
      : path === "/applications" ? { data: { rows: [{ id: "kaims", name: "KaiMS", status: "active" }] } }
      : path === "/healthz" ? { status: "ok" } : { data: { rows: [] }, rows: [] };
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.goto(`/incidents/${id}`);
  await signIn(page);
  for (let load = 0; load < 2; load += 1) {
    await expect(page.getByRole("heading", { name: "Recorded assessment incident" })).toBeVisible({ timeout: 20_000 });
    await page.getByRole("link", { name: "Detailed context", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Detailed context", exact: true })).toBeVisible();
    await page.getByLabel("Context section").selectOption("logs");
    await expect(page.getByText("Database timeout sample 1", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Next records", exact: true }).click();
    await expect(page.getByText("Database timeout sample 11", { exact: true })).toBeVisible();
    await page.getByLabel("Context section").selectOption("telemetry");
    await expect(page.getByText("725", { exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Recorded impact assessment" })).toBeVisible();
    await expect(page.getByText("Checkout requests may time out.", { exact: true })).toBeVisible();
    await expect(page.getByText("Connection pool exhaustion needs verification.", { exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Impact has not been established" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Verified impact" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "No execution to control" })).toBeDisabled();
    if (load === 0) {
      await page.reload();
      if (await page.getByLabel("Username").isVisible()) await signIn(page);
    }
  }
  fail = true;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.getByText(/Context refresh failed/)).toBeVisible();
  await expect(page.getByText("Checkout requests may time out.", { exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});
