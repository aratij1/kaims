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
  let stage="alert"; const requests=[];
  await page.route("**/api-gateway/incidents/inbox/feed?*",route=>{
    const url=new URL(route.request().url()); requests.push(url.searchParams.toString());
    const incident={incident_id:"browser-fixture-incident",title:"Browser fixture incident",service:"checkout-api",status:stage==="closed"?"closed":"investigating",created_at:new Date().toISOString(),updated_at:new Date().toISOString()};
    const row=stage==="alert"?{record_type:"alert",score:75,row:{id:"browser-fixture-alert",name:"Browser fixture alert",service:"checkout-api",severity:"high",created_at:new Date().toISOString()}}:{record_type:"incident",score:100,row:incident};
    return route.fulfill({status:200,contentType:"application/json",body:JSON.stringify({rows:[row],total_count:1,filtered_count:1,next_cursor:null,previous_cursor:null,record_counts:{incidents:stage==="alert"?0:1,alerts:stage==="alert"?1:0},view_counts:{all:1,resolved:stage==="closed"?1:0}})});
  });
  await page.goto("http://localhost:8501/incidents",{waitUntil:"domcontentloaded"});
  await page.getByRole("combobox",{name:"Application workspace"}).selectOption("checkout-api");
  await page.locator('input[autocomplete="username"]').fill("admin");
  await page.locator('input[autocomplete="current-password"]').fill(session.password);
  await page.getByRole("button",{name:/sign in/i}).click();
  await page.getByRole("button",{name:"Incidents",exact:true}).first().click();
  await page.locator(".unified-inbox-card.is-signal").waitFor({timeout:30000});
  if(!requests.some(q=>q.includes("record_type=all")&&q.includes("project_id=checkout-api"))) throw new Error("Wrong feed scope");
  stage="incident";
  await page.evaluate(()=>window.dispatchEvent(new CustomEvent("kaiops:operational-update",{detail:{type:"incident.status"}})));
  await page.locator(".unified-inbox-card.is-incident").waitFor({timeout:5000});
  if(await page.locator(".unified-inbox-card.is-signal").count()) throw new Error("Linked signal duplicated");
  stage="closed";
  await page.evaluate(()=>window.dispatchEvent(new CustomEvent("kaiops:operational-update",{detail:{type:"incident.status"}})));
  await page.locator(".unified-inbox-card .status-closed").waitFor({timeout:5000});
  await page.getByRole("combobox",{name:"Inbox records"}).selectOption("incidents");
  await page.waitForResponse(r=>r.url().includes("record_type=incidents")&&r.status()===200);
  console.log(JSON.stringify({fixtureOnly:true,unlinkedAlertVisible:true,incidentLinked:true,closureVisible:true,liveRefresh:true,projectScope:"checkout-api",incidentOnlyView:true,realAlertsCreated:0}));
} finally { await browser.close(); }
