import fs from 'node:fs';
import {expect,test} from '@playwright/test';

test.skip(!process.env.KAIOPS_LIVE_E2E,'Requires the live local incident stack');
test('RCA sequence, remedy and outcome match retained incident evidence',async({page})=>{
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
  const workspace=data.operations.investigation_workspace;
  expect(workspace.rca.timeline).toBeTruthy();
  for(const event of workspace.rca.timeline.events){
   if(event.kind==='observation') expect(event.rca_cited).toBe(true);
  }
  const section=page.locator('#incident-rca');
  await page.locator('.ic-investigation-history').evaluate(element=>element.setAttribute('open',''));
  for(const heading of ['Sequence of events','How the failure developed','Proposed remedy','Resolution outcome']){
   await expect(section.getByRole('heading',{name:heading,exact:true})).toBeVisible();
  }
  const validation=data.operations.validation||{};
  const verified=validation.health_restored===true&&validation.alerts_cleared===true&&Boolean(validation.report_id&&validation.validation_checksum);
  if(!verified) await expect(section).not.toContainText('Recovery verified by the recorded validation report.');
  if(workspace.resolution.proposed_remedy) await expect(section).toContainText(workspace.resolution.proposed_remedy);
  results.push({incident_id:id,rca_status:workspace.rca.status,timeline:workspace.rca.timeline,proposed_remedy:workspace.resolution.proposed_remedy,verified_recovery:verified});
 }
 fs.mkdirSync('../../artifacts/rca-sequence-review',{recursive:true});
 fs.writeFileSync('../../artifacts/rca-sequence-review/live-incidents.json',JSON.stringify(results,null,2));
});
