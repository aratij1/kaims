import { chromium } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
const mode=process.argv[2]||"review";
const out="../../artifacts/latency-chain-review";
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
 const id="09ccf7e2-3592-4c33-a05f-8e963a04cbb0";
 await page.goto(`http://localhost:8501/incidents/${id}`,{waitUntil:"domcontentloaded"});
 await page.locator(".ic-command-header").waitFor({timeout:60000});
 await page.screenshot({path:`${out}/${mode}-incident.png`,fullPage:true});
 results={mode,errors,incident:id};

 await page.getByRole("tab",{name:"Cause & impact",exact:true}).click();
 await page.getByRole("tabpanel").waitFor();
 await page.screenshot({path:`${out}/analysis-browser.png`,fullPage:true});
 results.analysisText=await page.getByRole("tabpanel").innerText();
 results.url=page.url();
 results.specificGapVisible=await page.getByRole("heading",{name:"Why this path is incomplete"}).count()===1;
 if(!results.specificGapVisible) throw new Error("Specific causal gap missing");
 writeFileSync(`${out}/browser.json`,JSON.stringify(results,null,2));
 console.log(JSON.stringify({incident:id,opened:true,pageErrors:errors,url:page.url()}));
} finally {await browser.close();}
