import { chromium } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";

// Credentials stay in process memory; report only response timings and statuses.
const python = `import json
from common.config import get_settings
print(json.dumps({"password":get_settings().admin_user_password}))`;
const session = JSON.parse(execFileSync("docker", ["exec", "-i", "kaims-api-gateway-1", "python", "-"], { input: python, encoding: "utf8", windowsHide: true }));
const browser = await chromium.launch({headless: true});
const page = await browser.newPage({viewport: {width: 1517, height: 1000}});
const feeds = [];
page.on("response", async response => {
  if (!response.url().includes("/incidents/inbox/feed")) return;
  try {
    const payload = await response.json();
    const data = payload.data || payload;
    const timing = response.request().timing();
    const statuses = {};
    for (const record of data.rows || []) {
      const status = record.row?.status || record.record_type;
      statuses[status] = (statuses[status] || 0) + 1;
    }
    feeds.push({status: response.status(), milliseconds: Math.round(timing.responseEnd), rows: data.rows?.length || 0, statuses});
  } catch { feeds.push({status: response.status()}); }
});
try {
  await page.goto("http://127.0.0.1:8501/incidents", {waitUntil: "domcontentloaded"});
  await page.locator('input[autocomplete="username"]').fill("admin");
  await page.locator('input[autocomplete="current-password"]').fill(session.password);
  await page.getByRole("combobox", {name: "Application workspace"}).selectOption("KaiMS", {timeout: 60_000});
  await page.getByRole("button", {name: /sign in/i}).click();
  await page.locator(".incident-list-heading").waitFor({timeout: 60_000});
  await page.locator(".incident-summary-list article").first().waitFor({timeout: 60_000});
  const refresh = page.waitForResponse(response => response.url().includes("/incidents/inbox/feed") && response.ok(), {timeout: 60_000});
  await page.getByRole("button", {name: "Refresh queue", exact: true}).click();
  await refresh;
  await page.locator('.incident-summary-list[aria-busy="false"]').waitFor({timeout:60_000});
  const report = {url: page.url(), visibleRecords: await page.locator(".incident-summary-list article").count(), feeds};
  writeFileSync("../../docs/architecture/inbox-loading-verification-2026-09-13.json", JSON.stringify(report, null, 2));
  await page.screenshot({path: "../../docs/architecture/inbox-loading-verification-2026-09-13.png", fullPage: true});
  console.log(JSON.stringify(report));
} finally { await browser.close(); }
