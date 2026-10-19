import fs from 'node:fs';
import { test, expect } from '@playwright/test';
const manifest = process.env.KAIOPS_REVIEW_MANIFEST;
test.skip(!manifest, 'Set KAIOPS_REVIEW_MANIFEST for the pinned live cohort');
test('latest 40 existing incident workspaces load context, impact and RCA', async ({page}, info) => {
 test.setTimeout(1_200_000);
 const rows=fs.readFileSync(manifest,'utf8').trim().split(/\r?\n/).map(x=>JSON.parse(x));
 const results=[];
 let responses=[];let crashes=[];
 page.on('response',r=>{if(r.status()>=500) responses.push({status:r.status(),url:new URL(r.url()).pathname});});
 page.on('pageerror',e=>crashes.push(e.message));
 await page.goto(`/incidents/${rows[0].incident_id}`);
 await page.getByLabel('Username').fill('admin');
 await page.getByLabel('Password').fill(process.env.KAIOPS_E2E_PASSWORD);
 await page.getByRole('button',{name:/sign in/i}).click();
 await expect(page.locator('.incident-command')).toBeVisible({timeout:45_000});
 for(const row of rows){
  responses=[];crashes=[];let error=null;
  try {
   await page.goto(`/incidents/${row.incident_id}`);
   await expect(page.locator('.incident-command')).toBeVisible({timeout:45_000});
   await expect(page.locator('.ic-command-header')).toContainText(row.service);
   for(const name of ['Detailed context','Impact assessment','Root cause analysis']){
    await page.getByRole('link',{name,exact:true}).click();
    await expect(page.locator(name==='Detailed context'?'#incident-detailed-context':name==='Impact assessment'?'#incident-impact':'#incident-rca')).toBeVisible({timeout:15_000});
   }
   await expect(page.getByText(/HTTP 50\d|An unexpected service error occurred|Not authenticated/)).toHaveCount(0);
   expect(responses).toEqual([]);expect(crashes).toEqual([]);
  }catch(e){error=String(e.message).slice(0,1800);await page.screenshot({path:info.outputPath(`${row.ticket}-failure.png`),fullPage:true});}
  results.push({incident_id:row.incident_id,ticket:row.ticket,passed:!error,error,server_errors:responses,page_errors:crashes});
  fs.writeFileSync(process.env.KAIOPS_REVIEW_UI_RESULT,JSON.stringify(results,null,2));
 }
 expect(results.filter(x=>!x.passed)).toEqual([]);
});
