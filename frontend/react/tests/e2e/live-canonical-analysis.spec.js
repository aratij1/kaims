import { expect, test } from "@playwright/test";
const ids = String(process.env.KAIOPS_LIVE_INCIDENT_IDS || "").split(",").filter(Boolean);
test.skip(!process.env.KAIOPS_LIVE_E2E || !ids.length, "Explicit incident IDs and live mode are required");
test("deployed detail pages display the persisted canonical analysis", async ({ page }) => {
  test.setTimeout(240_000);
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("/incidents");
  await page.getByLabel("Username").fill(process.env.KAIOPS_E2E_USERNAME || "admin");
  await page.getByLabel("Password").fill(process.env.KAIOPS_E2E_PASSWORD || "Admin@123456");
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.locator(".kai-shell")).toBeVisible({ timeout: 45_000 });
  for (const id of ids) {
    const responsePromise = page.waitForResponse(response => response.url().includes(`/incidents/${id}/command`) && response.status() === 200, { timeout: 90_000 });
    await page.goto(`/incidents/${id}`);
    const response = await responsePromise;
    const payload = await response.json();
    const workspace = payload.data || payload;
    expect(workspace.incident_id).toBe(id);
    await expect(page.locator(".incident-command")).toBeVisible({ timeout: 30_000 });
    await page.getByRole("link", { name: "Detailed context", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Detailed context", exact: true })).toBeVisible();
    const context = workspace.incident.context || workspace.incident.projection_payload?.context || {};
    const buckets = context.metadata?.context_evidence || context.context_evidence || {};
    const evidenceCounts = {};
    for (const [category, records] of Object.entries(buckets)) {
      if (!Array.isArray(records) || !records.length) continue;
      const key = `${category}_evidence`;
      await page.getByLabel("Context section").selectOption(key);
      await expect(page.locator(".ic-context-content > ol, .ic-context-content ol").first()).toBeVisible();
      const first = records[0];
      const scalar = Object.values(first || {}).find(value => typeof value === "string" && value.trim() && value.length < 200);
      if (scalar) await expect(page.locator(".ic-context-content")).toContainText(scalar);
      evidenceCounts[category] = records.length;
    }
    if (context.cloud && Object.keys(context.cloud).length === 0) {
      await expect(page.locator('select option[value="cloud"]')).toHaveCount(0);
      await expect(page.locator(".ic-context-unavailable")).toContainText("Cloud");
    }
    await page.screenshot({ path: `../../docs/architecture/context-detail-${id}-2026-09-13.png` });
    const details = workspace.operations.investigation_workspace;
    if (details.impact.statement) await expect(page.locator(".ic-impact")).toContainText(details.impact.statement);
    if (details.rca.hypothesis) await expect(page.locator(".incident-command")).toContainText(details.rca.hypothesis);
    if (details.rca.grounding_notes) await expect(page.locator(".incident-command")).toContainText(details.rca.grounding_notes);
    await expect(page.getByText("Workspace could not be displayed", { exact: true })).toHaveCount(0);
    console.log(JSON.stringify({ incident_id: id, http: response.status(), rca_status: details.rca.status, impact_status: details.impact.status, impact_visible: Boolean(details.impact.statement), evidence_counts: evidenceCounts }));
  }
  expect(errors).toEqual([]);
});
