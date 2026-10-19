import { expect, test } from "@playwright/test";
test.skip(!process.env.KAIOPS_LIVE_E2E, "Live backend required");
test("deployed inbox counts and lifecycle agree with canonical incident details", async ({ page }) => {
  test.setTimeout(240000);
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("/incidents");
  await page.getByLabel("Username").fill(process.env.KAIOPS_E2E_USERNAME || "admin");
  await page.getByLabel("Password").fill(process.env.KAIOPS_E2E_PASSWORD || "Admin@123456");
  const response = page.waitForResponse(r => r.url().includes("/incidents/inbox/feed") && r.status() === 200, { timeout: 90000 });
  await page.getByRole("button", { name: /sign in/i }).click();
  const initial = await response;
  const auth = await initial.request().headerValue("authorization");
  const checks = [];
  for (const view of ["all", "needs_me", "kai_handling"]) {
    const url = new URL(initial.url()); url.searchParams.set("inbox_view", view); url.searchParams.set("limit", "100"); url.searchParams.delete("cursor");
    const started = Date.now();
    const result = await page.request.get(url.toString(), { headers: { Authorization: auth }, timeout: 45000 })
      .catch(() => { throw new Error(`Inbox ${view} did not respond within 45 seconds`); });
    const feedElapsed = Date.now() - started;
    expect(result.status()).toBe(200);
    const payload = await result.json(); const feed = payload.data || payload;
    expect(feed.filtered_count).toBe(feed.view_counts[view]);
    if (!feed.next_cursor) expect(feed.rows.length).toBe(feed.filtered_count);
    for (const item of feed.rows) expect(["warning", "warn"]).not.toContain(String(item.row.severity).toLowerCase());
    const statuses = [];
    if (view === "all") for (const item of feed.rows.filter(row => row.record_type === "incident").slice(0, 5)) {
      const id = item.row.incident_id || item.row.id;
      const result = await page.request.get(new URL(`/api-gateway/incidents/${id}/command`, page.url()).toString(), { headers: { Authorization: auth }, timeout: 60000 });
      expect(result.status()).toBe(200);
      const payload = await result.json(); const command = payload.data || payload;
      statuses.push({ id, inbox: item.row.status, detail: command.operations.lifecycle_state.toLowerCase() });
    }
    console.log(JSON.stringify({ view, count: feed.filtered_count, elapsed_ms: feedElapsed, statuses }));
    checks.push(...statuses);
  }
  expect(checks.length).toBeGreaterThan(0);
  for (const row of checks) expect(row.inbox, row.id).toBe(row.detail);
  expect(errors).toEqual([]);
});
