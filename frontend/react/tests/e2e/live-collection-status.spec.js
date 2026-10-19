import fs from 'node:fs';
import {expect,test} from '@playwright/test';
test.skip(!process.env.KAIOPS_LIVE_E2E,'Requires the live local incident stack');
test('real incident labels match the current uncached collection phase',async({page})=>{
 test.setTimeout(120000);
 await page.goto('/');
 await page.getByLabel('Username').fill('admin');
 await page.getByLabel('Password').fill(process.env.KAIOPS_E2E_PASSWORD);
 await page.getByRole('button',{name:/sign in/i}).click();
 await expect(page.locator('.operations-home')).toBeVisible({timeout:45000});
 const results=[];
 for(const id of ['b2306e7f-7319-4302-860d-bf9cbec068f5','51cafc58-9ccb-4718-af02-a72e8dce86b5']){
  const response=page.waitForResponse(r=>r.url().includes(`/incidents/${id}/command`)&&r.status()===200,{timeout:45000});
  await page.goto(`/incidents/${id}`);
  const received=await response;
  const payload=await received.json();const data=payload.data||payload;
  const operations=data.operations;
  const phase=operations.collection?.phase;
  const status=String(operations.lifecycle_state||'').toLowerCase();
  const expected=status==='collecting'&&phase==='queued'?'queued for evidence':status==='collecting'&&phase==='retry_wait'?'waiting to retry evidence':status.replaceAll('_',' ');
  await expect(page.locator('.ic-header-state')).toContainText(expected,{timeout:10000});
  expect(received.headers()['cache-control']).toContain('no-store');
  results.push({incident_id:id,lifecycle:status,phase,displayed:expected,collection:operations.collection});
 }
 fs.mkdirSync('../../artifacts/collecting-stall-review',{recursive:true});
 fs.writeFileSync('../../artifacts/collecting-stall-review/browser-incident-states.json',JSON.stringify(results,null,2));
});
