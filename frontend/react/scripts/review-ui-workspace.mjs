import AxeBuilder from "@axe-core/playwright";
import { chromium, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
const mode=process.argv[2]||"review";
const out="../../artifacts/ui-redesign";
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
   const preferred=options.find(n=>n.label?.toLowerCase().includes("telemetry")&&!n.disabled)||options.find(n=>n.value&&!n.disabled);
   if(preferred) await workspace.selectOption(preferred.value);
 }
 await page.getByRole("button",{name:/sign in/i}).click();
 await page.locator(".kai-navigation").waitFor({timeout:60000});
 await page.screenshot({path:`${out}/${mode}-overview.png`,fullPage:true});
 const id="656817b7-7932-4c0c-8218-30e50bfbf0d9";
 await page.goto(`http://localhost:8501/incidents/${id}`,{waitUntil:"domcontentloaded"});
 await page.locator(".ic-command-header").waitFor({timeout:60000});
 await page.screenshot({path:`${out}/${mode}-incident.png`,fullPage:true});
 results={mode,errors,incident:id};
 if(mode!=="before") {
   results.tabs=[];
   results.accessibility=[];
   for(const name of ["Overview","Evidence","Cause & impact","Resolution","Recovery","Activity"]) {
     await page.getByRole("tab",{name,exact:true}).click();
     await page.getByRole("tabpanel").waitFor();
     if(await page.getByRole("tabpanel").count()!==1) throw new Error("Expected exactly one visible workspace panel");
     const slug=name.toLowerCase().replace(/[^a-z]+/g,"-");
     await page.screenshot({path:`${out}/desktop-${slug}.png`,fullPage:true});
     results.tabs.push({name,url:page.url(),visiblePanels:await page.getByRole("tabpanel").count()});
     if(name==="Recovery") {
       await page.getByText("6 recorded checks / 66 samples",{exact:true}).waitFor();
       if(await page.locator(".recovery-evidence article").count()!==6) throw new Error("Recovery checks missing");
       results.recovery={validators:6,samples:66,window:await page.locator(".ic-validation").innerText().then(t=>t.includes("338.818s / 300s"))};
       if(!results.recovery.window) throw new Error("Recovery stability window missing");
     }
     const audit=await new AxeBuilder({page}).include(".incident-command").withTags(["wcag2a","wcag2aa","wcag21aa"]).analyze();
     results.accessibility.push({name,violations:audit.violations.map(v=>({id:v.id,impact:v.impact,targets:v.nodes.map(n=>n.target)}))});
   }
   await page.getByRole("tab",{name:"Evidence",exact:true}).click();
   await page.reload({waitUntil:"domcontentloaded"});
   await page.getByRole("tab",{name:"Evidence",exact:true}).waitFor({timeout:60000});
   if(await page.getByRole("tab",{name:"Evidence",exact:true}).getAttribute("aria-selected")!=="true") throw new Error("Deep link lost on reload");
   results.deepLinkReload=true;
   await page.getByRole("tab",{name:"Evidence",exact:true}).focus();
   await page.keyboard.press("ArrowRight");
   await expect(page.getByRole("tab",{name:"Cause & impact",exact:true})).toHaveAttribute("aria-selected","true");
   results.keyboardNavigation=true;
   await page.locator(".kai-user-menu>summary").click();
   await page.getByRole("button",{name:"dark",exact:true}).click();
   await page.locator(".kai-user-menu>summary").click();
   await page.screenshot({path:`${out}/desktop-dark-analysis.png`,fullPage:true});
   const darkAudit=await new AxeBuilder({page}).include(".incident-command").withTags(["wcag2a","wcag2aa","wcag21aa"]).analyze();
   results.accessibility.push({name:"Dark analysis",violations:darkAudit.violations.map(v=>({id:v.id,impact:v.impact,targets:v.nodes.map(n=>n.target)}))});
   await page.locator(".kai-user-menu>summary").click();
   await page.getByRole("button",{name:"light",exact:true}).click();
   await page.locator(".kai-user-menu>summary").click();
   await page.setViewportSize({width:390,height:844});
   await page.getByRole("tab",{name:"Overview",exact:true}).click();
   await expect(page.getByRole("tab",{name:"Overview",exact:true})).toHaveAttribute("aria-selected","true");
   await page.evaluate(async()=>{window.scrollTo(0,0);await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));});
   await page.screenshot({path:`${out}/mobile-incident.png`,fullPage:true});
   results.mobileOverflow=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth);
   if(results.mobileOverflow) throw new Error("Mobile horizontal page overflow");
   await page.setViewportSize({width:1500,height:1080});
   for(const [path,label] of [["/incidents","inbox"],["/alerts","alerts"],["/knowledge","knowledge"]]) {
     await page.goto("http://localhost:8501"+path,{waitUntil:"domcontentloaded"});
     await page.locator(".kai-route-content").waitFor();
     await page.screenshot({path:`${out}/desktop-${label}.png`,fullPage:true});
   }
 }
 if(errors.length) throw new Error(errors.join("; "));
 writeFileSync(`${out}/${mode}-browser.json`,JSON.stringify(results,null,2));
 console.log(JSON.stringify(results));
 if(results.accessibility?.some(audit=>audit.violations.some(issue=>["serious","critical"].includes(issue.impact)))) throw new Error("Accessibility audit has serious violations");
} catch(error) {writeFileSync(`${out}/${mode}-diagnostic.json`,JSON.stringify({...results,error:String(error),url:page.url()},null,2));throw error;} finally {await browser.close();}
