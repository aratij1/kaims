import { chromium } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
const mode=process.argv[2]||"review";
const out="../../artifacts/last25-e2e-20261019";
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
 const cohort=JSON.parse(readFileSync(`${out}/results.json`,"utf8"));
 const ids=[...new Set(cohort.map(row=>row.submission?.incident_id||row.incident_id).filter(Boolean))];
 const checks=[];
 for(const id of ids){
  const check={incident:id,tabs:[],error:null};
  try {
   await page.goto(`http://localhost:8501/incidents/${id}`,{waitUntil:"domcontentloaded"});
   await page.locator(".ic-command-header").waitFor({timeout:45000});
   for(const name of ["Evidence","Cause & impact","Resolution","Recovery"]){
    await page.getByRole("tab",{name,exact:true}).click();
    await page.locator('[role="tabpanel"]:visible').waitFor({timeout:10000});
    check.tabs.push(name);
   }
   if(checks.length<3) await page.screenshot({path:`${out}/browser-${id}.png`,fullPage:true});
  }catch(error){check.error=String(error).slice(0,350);}
  checks.push(check);
  writeFileSync(`${out}/browser.json`,JSON.stringify({checks,pageErrors:errors},null,2));
 }
 console.log(JSON.stringify({incidents:checks.length,passed:checks.filter(c=>!c.error).length,pageErrors:errors}));
}finally{await browser.close();}
