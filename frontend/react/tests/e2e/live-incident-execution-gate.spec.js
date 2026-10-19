import { expect, test } from "@playwright/test";

const incidentId = String(process.env.KAIOPS_LIVE_INCIDENT_ID || "").trim();

test.skip(
  !process.env.KAIOPS_LIVE_E2E || !incidentId,
  "Set KAIOPS_LIVE_E2E=1 and KAIOPS_LIVE_INCIDENT_ID to verify a live diagnostic execution gate",
);

test("live diagnostic incident does not expose execution controls", async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto(`/incidents/${encodeURIComponent(incidentId)}`);
  await page.getByLabel("Username").fill(process.env.KAIOPS_E2E_USERNAME || "admin");
  await page.getByLabel("Password").fill(process.env.KAIOPS_E2E_PASSWORD || "Admin@123456");
  await page.getByRole("button", { name: /sign in/i }).click();

  await expect(page.locator(".incident-command")).toBeVisible({ timeout: 45_000 });
  await expect(page.locator(".ic-command-header")).toContainText(/collecting|investigating|collection.blocked/i);
  await expect(page.getByRole("button", { name: /Open technical execution workspace|Approve & let Kai resolve|Take control in governed workspace/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "No execution to control" })).toBeDisabled();
  await expect(page.getByRole("button", { name: /Approve & let Kai resolve/ })).toHaveCount(0);
});
