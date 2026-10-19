import { expect, test } from "@playwright/test";

const liveAlertId = String(process.env.KAIOPS_LIVE_ALERT_ID || "").trim();

test.skip(!process.env.KAIOPS_LIVE_E2E || !liveAlertId, "Set KAIOPS_LIVE_E2E=1 and KAIOPS_LIVE_ALERT_ID to verify a persisted live RCA");

test("completed live analysis renders its persisted RCA", async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto(`/?workspace=alert&alert_id=${encodeURIComponent(liveAlertId)}`);
  await page.getByLabel("Username").fill(process.env.KAIOPS_E2E_USERNAME || "admin");
  await page.getByLabel("Password").fill(process.env.KAIOPS_E2E_PASSWORD || "Admin@123456");
  await page.getByRole("button", { name: /sign in/i }).click();

  await expect(page.locator(".alert-details-cockpit")).toBeVisible({ timeout: 45_000 });
  const sections = page.getByRole("tablist", { name: "Incident workspace sections" });
  await sections.getByRole("tab", { name: "Evidence, RCA, and impact" }).click();
  await page.getByRole("tab", { name: /Summary/ }).click();

  await expect(page.getByText("Decision brief", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Explainability trace", { exact: true })).toHaveCount(0);
  const workspace = page.locator(".canonical-investigation-hero");
  await expect(workspace).toBeVisible({ timeout: 45_000 });
  await expect(workspace).not.toContainText("RCA pending");
  await expect(page.getByText(/HTTP 401|Not authenticated/)).toHaveCount(0);
  await expect(page.getByText(/HTTP 502|All connection attempts failed/)).toHaveCount(0);

  const review = page.getByRole("button", { name: "Review missing evidence" }).first();
  if (await review.count()) {
    await review.click();
    const response = page.locator("[data-requirement-response]:focus");
    await expect(response).toBeVisible();
    await expect(response).toBeFocused();
    await expect(response).toHaveValue(/Evidence requirement:/);
  }
});
