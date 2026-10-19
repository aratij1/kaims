import { chromium } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
const mode=process.argv[2]||"review";
const out="../../artifacts/resolution-gate-review";
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
 const id="210ac91e-6c5b-4ecf-9cbe-7c098caf8f56";
 await page.goto(`http://localhost:8501/incidents/${id}`,{waitUntil:"domcontentloaded"});
 await page.locator(".ic-command-header").waitFor({timeout:60000});
 await page.screenshot({path:`${out}/${mode}-incident.png`,fullPage:true});
 results={mode,errors,incident:id};

 await page.getByRole("tab",{name:"Resolution",exact:true}).click();
 await page.getByText("Confirm the cause before choosing a remedy",{exact:true}).waitFor();
 await page.screenshot({path:`${out}/resolution-browser.png`,fullPage:true});
 results.resolutionText=await page.getByRole("tabpanel").innerText();
 await page.getByRole("button",{name:"Review evidence gaps",exact:true}).click();
 await page.locator('#incident-tab-evidence[aria-selected="true"]').waitFor();
 results.evidenceSelected=await page.getByRole("tab",{name:"Evidence",exact:true}).getAttribute("aria-selected");
 if(results.evidenceSelected!=="true" || errors.length) throw new Error(JSON.stringify({selected:results.evidenceSelected,errors}));
 writeFileSync(`${out}/browser.json`,JSON.stringify(results,null,2));
 console.log(JSON.stringify({incident:id,evidenceSelected:results.evidenceSelected,pageErrors:errors}));
} finally {await browser.close();}
