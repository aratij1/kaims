import { chromium, expect } from "@playwright/test";
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
const key = "kaiops.ui.preferences.v1";
await context.addInitScript((key) => {
  if (!localStorage.getItem(key)) localStorage.setItem(key, JSON.stringify({ applicationToMonitor: "Telemetry" }));
}, key);
const page = await context.newPage();
let failRegistry = false;
await page.route("**/api-gateway/applications", async (route) => {
  await new Promise((resolve) => setTimeout(resolve, 1200));
  if (failRegistry) return route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "Test registry outage" }) });
  return route.continue();
});
try {
  await page.goto("http://localhost:8501/", { waitUntil: "domcontentloaded" });
  const selector = page.getByRole("combobox", { name: "Application workspace" });
  await expect(selector).toHaveValue("Telemetry", { timeout: 30000 });
  await selector.selectOption("KaiMS");
  await expect.poll(() => page.evaluate((key) => JSON.parse(localStorage.getItem(key)).applicationToMonitor, key)).toBe("KaiMS");
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(selector).toHaveValue("KaiMS", { timeout: 30000 });
  failRegistry = true;
  await page.reload({ waitUntil: "networkidle" });
  await expect.poll(() => page.evaluate((key) => JSON.parse(localStorage.getItem(key)).applicationToMonitor, key)).toBe("KaiMS");
  failRegistry = false;
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(selector).toHaveValue("KaiMS", { timeout: 30000 });
  console.log(JSON.stringify({ savedTelemetryRestored: true, explicitSelectionRetainedAfterReload: true, registryFailurePreservesPreference: true, registryRecoveryPreservesPreference: true }));
} finally { await browser.close(); }
