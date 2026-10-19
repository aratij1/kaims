import { expect, test } from "@playwright/test";
test.skip(!process.env.KAIOPS_LIVE_E2E, "Live backend required");
test("unified inbox excludes warning signals and incidents", async ({ page }) => {
  test.setTimeout(120000);
  await page.goto("/incidents");
  await page.getByLabel("Username").fill(process.env.KAIOPS_E2E_USERNAME || "admin");
  await page.getByLabel("Password").fill(process.env.KAIOPS_E2E_PASSWORD || "Admin@123456");
  const received = page.waitForResponse(r => r.url().includes("/incidents/inbox/feed") && r.status() === 200, { timeout: 90000 });
  await page.getByRole("button", { name: /sign in/i }).click();
  const response = await received;
  const payload = await response.json();
  const feed = payload.data || payload;
  expect(feed.rows.length).toBeGreaterThan(0);
  for (const item of feed.rows) expect(["warning","warn"]).not.toContain(String(item.row.severity || "").toLowerCase());
  await expect(page.locator(".unified-inbox-card").first()).toBeVisible({timeout:30000});
  await expect(page.locator(".unified-inbox-card.severity-warning")).toHaveCount(0);
  console.log(JSON.stringify({ checked_rows: feed.rows.length, warning_rows: 0 }));
});
