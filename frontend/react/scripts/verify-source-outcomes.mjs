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
try {
  await page.goto("http://127.0.0.1:8501/incidents", {waitUntil:"domcontentloaded"});
  await page.locator('input[autocomplete="username"]').fill("admin");
  await page.locator('input[autocomplete="current-password"]').fill(session.password);
  await page.getByRole("combobox",{name:"Application workspace"}).selectOption("KaiMS",{timeout:60000});
  await page.getByRole("button",{name:/sign in/i}).click();
  await page.locator(".incident-list-heading").waitFor({timeout:60000});
  await page.goto("http://127.0.0.1:8501/incidents/07bdb64c-e021-482c-ad39-be40dbd27ead",{waitUntil:"domcontentloaded"});
  const context=page.getByRole("region",{name:"Detailed context",exact:true});
  await context.getByLabel("Context section").waitFor({timeout:60000});
  if ((await context.innerText()).includes("No data returned:")) throw new Error("Blanket no-data warning remains");
  const options=await context.locator("option").allTextContents();
  for (const name of ["Database Evidence", "Changes Evidence", "Dependency Evidence", "Deployment Evidence"]) {
    if (!options.some(text=>text.startsWith(name))) throw new Error(`Missing populated section: ${name}`);
  }
  await context.locator(".ic-context-unavailable > summary").click();
  const outcomes=await context.locator(".ic-context-unavailable").innerText();
  if (outcomes.includes("Recent Changes") || outcomes.includes("Dependency Services") || outcomes.includes("Deployment")) throw new Error("Populated source still listed as missing");
  if (!outcomes.includes("Search completed with no matching records")) throw new Error("RAG no-match outcome missing");
  const report={incidentId:"07bdb64c-e021-482c-ad39-be40dbd27ead",options,outcomes,blanketNoDataWarning:false};
  writeFileSync(new URL("../../../docs/architecture/source-outcomes-verification-2026-09-13.json",import.meta.url),JSON.stringify(report,null,2));
  console.log(JSON.stringify(report));
} finally {await browser.close();}
