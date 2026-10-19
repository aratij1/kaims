import { chromium } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
const mode=process.argv[2]||"review";
const out="../../artifacts/lightweight-review";
mkdirSync(out,{recursive:true});
const password=execFileSync("docker",["exec","kaims-api-gateway-1","python","-c","from common.config import get_settings;print(get_settings().admin_user_password)"],{encoding:"utf8",windowsHide:true}).trim();
const browser=await chromium.launch({headless:true});
const context=await browser.newContext({viewport:{width:1500,height:1080}});
const page=await context.newPage();
const errors=[];
let results={mode,errors};
page.on("pageerror",error=>errors.push(error.message));
try {
 await page.goto("http://localhost:8501/",{waitUntil:"domcontentloaded"});
 await page.locator('input[autocomplete="username"]').fill("admin");
 await page.locator('input[autocomplete="current-password"]').fill(password);
 const workspace=page.getByRole("combobox",{name:"Application workspace"});
 if(await workspace.count()) {
   const options=await workspace.locator("option").evaluateAll(nodes=>nodes.map(n=>({value:n.value,label:n.textContent,disabled:n.disabled})));
   const preferred=options.find(n=>n.label?.toLowerCase().includes("kaiops")&&!n.disabled)||options.find(n=>n.value&&!n.disabled);
   if(preferred) await workspace.selectOption(preferred.value);
 }
 await page.getByRole("button",{name:/sign in/i}).click();
 await page.locator(".kai-navigation").waitFor({timeout:60000});
 await page.screenshot({path:`${out}/${mode}-overview.png`,fullPage:true});
 const cohort=JSON.parse(readFileSync("../../artifacts/last50-e2e-20261019/results.json","utf8"));
 const ids=[...new Set(cohort.map(row=>row.submission?.incident_id||row.incident_id).filter(Boolean).map(id=>id.replace(/^([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{12})$/i,"$1-$2-$3-$4-$5")))];
 const checks=[];
 for(const id of ids.filter(id=>["210ac91e-6c5b-4ecf-9cbe-7c098caf8f56","e22f2252-922d-465d-84fd-af18773a41e6","abc2a6b3-9cc1-40c3-a4e5-fb1a1755f7ac"].includes(id))){
  const check={incident:id,tabs:[],error:null};
  try {
   const responsePromise = page.waitForResponse(r=>r.url().includes(`/incidents/${id}/command?`) && r.request().method()==="GET",{timeout:60000});
   await page.goto(`http://localhost:8501/incidents/${id}`,{waitUntil:"domcontentloaded"});
   const response=await responsePromise;
   if(response.status()!==200) throw new Error(`Command returned ${response.status()}`);
   const command=await response.json();
   check.revision=command.revision;
   check.recommendation=command.operations.investigation_workspace?.binding?.recommendation_id;
   check.rcaStatus=command.operations.investigation_workspace?.rca?.status;
   await page.locator(".ic-command-header").waitFor({timeout:45000});
   const metrics=page.locator("#incident-panel-overview .ic-metric");
   await metrics.first().waitFor();
   check.summary=await metrics.allTextContents();
   const n=command.evidence.counts.latest_context_records;
   if(!check.summary[0].includes(`${n} records`)) throw new Error("Overview evidence total differs from command revision");
   for(const name of ["Evidence","Cause & impact","Resolution","Recovery"]){
    await page.getByRole("tab",{name,exact:true}).click();
    await page.locator('[role="tabpanel"]:visible').waitFor({timeout:10000});
    check.tabs.push(name);
    if(name==="Cause & impact") {
      check.analysisHeading=await page.locator("#incident-rca h3").innerText();
      const root=check.summary[1];
      if(root.includes("Working hypothesis") && !root.includes(check.analysisHeading)) throw new Error("Overview hypothesis differs from detail");
      if(root.includes("Inconclusive") && check.analysisHeading!=="Cause not established") throw new Error("Overview inconclusive status differs from detail");
    }
   }
   if(checks.length<3) await page.screenshot({path:`${out}/browser-${id}.png`,fullPage:true});
  }catch(error){check.error=String(error).slice(0,350);}
  checks.push(check);
  writeFileSync(`${out}/browser.json`,JSON.stringify({checks,pageErrors:errors},null,2));
 }
 console.log(JSON.stringify({incidents:checks.length,passed:checks.filter(c=>!c.error).length,pageErrors:errors}));
}finally{await browser.close();}
