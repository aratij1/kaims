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
 await page.getByRole("combobox",{name:"Application workspace"}).selectOption("checkout-api");
 await page.locator('input[autocomplete="username"]').fill("admin");
 await page.locator('input[autocomplete="current-password"]').fill(session.password);
 await page.getByRole("button",{name:/sign in/i}).click();
 await page.locator(".kai-operations-bar").waitFor();
 await page.goto("http://localhost:8501/incidents/936b3ba6-759f-4fb2-ba86-12954a2302ea",{waitUntil:"domcontentloaded"});
 await page.getByRole("heading",{name:"No explanatory causal hypothesis recorded",exact:true}).waitFor({timeout:30000});
 const decision=await page.locator(".ic-decision-evidence").innerText();
 if(!decision.includes("traceable") || decision.includes("69%")) throw new Error("Unbound confidence or citation label still shown");
 if(await page.getByText("What Kai ruled out",{exact:true}).count()) throw new Error("Unsupported ruled-out label remains");
 const stage=await page.locator(".ic-journey li.is-current span").innerText();
 if(stage==="Root cause") throw new Error("Observation promoted to causal progress");
 await page.getByText(/Untested diagnostic candidate|Recorded observation \(not a causal explanation\)/).waitFor({timeout:30000});
 for (const item of await page.getByText("Collect fresh distributed traces for the affected service and incident window.",{exact:true}).all()) {
  if(await item.isVisible()) throw new Error("Obsolete generic trace request still shown as active work");
 }
 await page.screenshot({path:"docs/architecture/incident-truth-audit-936b3ba6.png",fullPage:true});
 console.log(JSON.stringify({incidentId:"936b3ba6-759f-4fb2-ba86-12954a2302ea",rawJsonNotHypothesis:true,claimConfidenceUnavailable:true,traceabilityLabel:true,currentJourneyStage:stage,traceExpiryClaimRemoved:true}));
} finally { await browser.close(); }
