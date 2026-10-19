import { chromium } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
const python = `import json,urllib.request
from common.config import get_settings
r=urllib.request.Request('http://localhost:8000/auth/login',data=json.dumps({'username':'admin','password':get_settings().admin_user_password}).encode(),headers={'Content-Type':'application/json'})
a=json.load(urllib.request.urlopen(r)); print(json.dumps({'accessToken':a['access_token'],'refreshToken':a.get('refresh_token',''),'username':'admin','password':get_settings().admin_user_password}))`;
const session = JSON.parse(execFileSync("docker", ["exec", "-i", "kaims-api-gateway-1", "python", "-"], { input: python, encoding: "utf8", windowsHide: true }));
const browser = await chromium.launch({headless:true});
const page = await browser.newPage({ viewport: { width: 1500, height: 1100 } });
try {
  await page.goto("http://localhost:8501/",{waitUntil:"domcontentloaded"});
  const registry=await page.request.get("http://localhost:8501/api-gateway/applications");
  const payload=await registry.json(); const data=payload.data || payload;
  const registered=new Set((data.rows || []).map(r=>r.name || r.application));
  const selector=page.getByRole("combobox",{name:"Application workspace"});
  const selected=[...registered][0];
  if(!selected) throw new Error("No onboarded project available for live login verification");
  await selector.selectOption(selected,{timeout:30000});
  const options=await selector.locator("option").allTextContents();
  if(options.some(o=>!registered.has(o))) throw new Error("Login contains a project absent from the onboarding registry");
  await page.locator('input[autocomplete="username"]').fill("admin");
  await page.locator('input[autocomplete="current-password"]').fill(session.password);
  await page.getByRole("button",{name:/sign in/i}).click();
  await page.locator(".kai-operations-bar").waitFor({timeout:30000});
  if(await page.locator(".kai-context-selectors select, .oh-scope select").count()) throw new Error("Post-login project selector remains");
  const projectText=await page.locator(".kai-context-selectors").innerText();
  if(!projectText.toLowerCase().includes(selected.toLowerCase())) throw new Error(`Login selection lost: ${projectText}; expected ${selected}`);
  await page.reload({waitUntil:"domcontentloaded"});
  await page.locator(".kai-operations-bar").waitFor({timeout:30000});
  if(!(await page.locator(".kai-context-selectors").innerText()).toLowerCase().includes(selected.toLowerCase())) throw new Error("Project not retained after reload");
  console.log(JSON.stringify({onboardedLoginOptions:options,postLoginSelectors:0,selectedProject:selected,scopeRetainedAfterReload:true}));
} finally { await browser.close(); }
