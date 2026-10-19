import {chromium} from '@playwright/test';
import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
const root=resolve('../..'),out=resolve(root,'artifacts/azure-ui-repair');
const buffer=readFileSync(resolve(root,'.tmp/azure-ssh/connection.json'));
const connection=JSON.parse(buffer.toString(buffer[0]===255?'utf16le':'utf8').replace(/^\uFEFF/,''));
const login=JSON.parse(execFileSync(resolve(root,'.venv/Scripts/python.exe'),[resolve(root,'.tmp/azure_exec.py'),resolve(root,'.tmp/azure_browser_credentials_remote.py')],{cwd:root,encoding:'utf8',windowsHide:true}).trim());
const browser=await chromium.launch({headless:true});const errors=[],serverErrors=[];
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});page.setDefaultTimeout(15000);
 page.on('pageerror',e=>errors.push(e.message));
 page.on('response',r=>{if(r.status()>=500)serverErrors.push({path:new URL(r.url()).pathname,status:r.status()});});
 const apiResponses=[]; page.on('response',r=>{if(r.url().includes('/api-gateway/'))apiResponses.push({path:new URL(r.url()).pathname,status:r.status()});});
 const queueResponses=[]; page.on('response',r=>{if(r.url().includes('/incidents/metadata')) queueResponses.push({status:r.status(),authenticated:!!r.request().headers()['authorization']});});
 const url=`http://${connection.host}:8501/`;
 const response=await page.goto(url,{waitUntil:'domcontentloaded',timeout:30000});
 await page.getByLabel('Username',{exact:true}).fill(login.username);
 await page.getByLabel('Password',{exact:true}).fill(login.password);
 const workspace=page.getByRole('combobox',{name:'Application workspace'});
 if(await workspace.count()){
  const options=await workspace.locator('option').evaluateAll(nodes=>nodes.map(n=>({value:n.value,label:n.textContent,disabled:n.disabled})));
  const option=options.find(x=>!x.disabled&&/dgsl/i.test(x.label||''))||options.find(x=>!x.disabled&&x.value);
  if(option)await workspace.selectOption(option.value);
 }
 const authPromise=page.waitForResponse(r=>r.url().includes('/auth/login')&&r.request().method()==='POST',{timeout:30000});
 await page.getByRole('button',{name:/sign in/i}).click();const auth=await authPromise;
 await page.waitForFunction(()=>!document.querySelector('input[autocomplete="current-password"]')&&document.querySelector('nav'),{},{timeout:60000});
 const pages=[];
 for(const name of ['Operations Overview','Alert Stream','Incident Queue','My Approvals','Closed Incidents','Projects & Integrations','Knowledge & Runbooks','Users & Access','Platform Health & Audit']){
  const start=apiResponses.length;
  try{await page.locator('nav').getByText(name,{exact:true}).first().click(); await page.waitForTimeout(2500);
   pages.push({name,responses:apiResponses.slice(start),errors:await page.locator('[role="alert"]').allTextContents(),buttons:(await page.locator('main button').allTextContents()).slice(0,30)});
  }catch(e){pages.push({name,failure:e.message.slice(0,180)});}
 }
 await page.locator('nav').getByText('Incident Queue',{exact:true}).first().click();await page.waitForTimeout(2500);
 await page.getByRole('button',{name:'View details',exact:true}).first().click();await page.waitForTimeout(4000);
 pages.push({name:'incident-detail',text:(await page.locator('main').first().innerText()).slice(-18000)});
 pages.push({name:'queue-controls',buttons:await page.locator('button').allTextContents(),links:await page.locator('main a').evaluateAll(nodes=>nodes.map(n=>({text:n.textContent,href:n.getAttribute('href')})))});
 await page.screenshot({path:resolve(out,'azure-e2e-queue.png'),fullPage:true});
 const receipt={url,http_status:response.status(),login_status:auth.status(),authenticated_page_visible:true,page_errors:errors,server_errors:serverErrors,queue_responses:queueResponses,pages,api_responses:apiResponses};
 writeFileSync(resolve(out,'azure-e2e-browser.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));
 if(auth.status()!==200||errors.length||serverErrors.length||!queueResponses.some(r=>r.status===200&&r.authenticated)||queueResponses.some(r=>r.status===401)||apiResponses.some(r=>r.status===401)||pages.some(p=>p.failure))process.exitCode=1;
}finally{await browser.close();}
