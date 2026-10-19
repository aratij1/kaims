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
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('pageerror',e=>errors.push(e.message));
 page.on('response',r=>{if(r.status()>=500)serverErrors.push({path:new URL(r.url()).pathname,status:r.status()});});
 let phase='login'; const checks=[]; const httpErrors=[]; page.on('response',r=>{if(r.url().includes('/api-gateway/')&&r.status()>=400)httpErrors.push({phase,path:new URL(r.url()).pathname,status:r.status(),authenticated:!!r.request().headers()['authorization']});});
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
 await page.locator('nav').getByText('Incident Queue',{exact:true}).first().click();await page.waitForTimeout(2000);
 await page.getByRole('button',{name:'View details',exact:true}).first().click();await page.waitForTimeout(2500);
 for(const name of ['Evidence & Understanding','Resolve','Validate']){
  try{phase=name;await page.getByText(name,{exact:true}).first().click({timeout:10000});await page.waitForTimeout(2000);
   checks.push({name,visible:true,alerts:await page.locator('[role="alert"]').allTextContents()});
  }catch(e){checks.push({name,failure:e.message.slice(0,200)});}
 }
 phase='reload';await page.reload({waitUntil:'domcontentloaded'});
 await page.waitForFunction(()=>!document.querySelector('input[autocomplete="current-password"]')&&document.querySelector('nav'),{},{timeout:30000});
 checks.push({name:'reload-session',passed:true});
 await page.locator('nav').getByText('Incident Queue',{exact:true}).first().click();await page.waitForTimeout(2000);
 checks.push({name:'queue-after-reload',passed:await page.getByRole('button',{name:'View details',exact:true}).count()>0});
 phase='logout';await page.getByRole('button',{name:'Logout',exact:true}).click();
 await page.getByLabel('Password',{exact:true}).waitFor();
 checks.push({name:'logout-clears-session',passed:await page.evaluate(()=>!sessionStorage.getItem('kaims.auth.session.v1'))});
 phase='reload';await page.reload({waitUntil:'domcontentloaded'});await page.getByLabel('Password',{exact:true}).waitFor();
 checks.push({name:'logout-remains-logged-out-after-reload',passed:true});
 const receipt={url,http_status:response.status(),login_status:auth.status(),authenticated_page_visible:true,page_errors:errors,server_errors:serverErrors,queue_responses:queueResponses,checks,http_errors:httpErrors};
 writeFileSync(resolve(out,'e2e-detail-session.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));
 if(auth.status()!==200||errors.length||serverErrors.length||!queueResponses.some(r=>r.status===200&&r.authenticated)||queueResponses.some(r=>r.status===401)||httpErrors.length||checks.some(c=>c.failure||c.passed===false))process.exitCode=1;
}finally{await browser.close();}
