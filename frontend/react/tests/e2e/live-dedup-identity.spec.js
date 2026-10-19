import fs from 'node:fs';
import {test,expect} from '@playwright/test';
test.skip(!process.env.KAIOPS_LIVE_E2E,'Live stack only');
test('identical alert names show their distinct affected endpoints',async({page})=>{
 test.setTimeout(90000);await page.goto('/');
 await page.getByLabel('Username').fill('admin');await page.getByLabel('Password').fill(process.env.KAIOPS_E2E_PASSWORD);
 await page.getByRole('button',{name:/sign in/i}).click();
 const home=page.locator('.operations-home');await expect(home).toBeVisible({timeout:45000});
 const refresh=home.getByRole('button',{name:'Refresh',exact:true});await expect(refresh).toBeEnabled({timeout:30000});
 const updated=page.waitForResponse(r=>r.url().includes('/incidents/groups?')&&r.request().method()==='GET');await refresh.click();expect((await updated).status()).toBe(200);
 await expect(home.locator('.oh-scope')).toContainText(/Updated \d/);
 const cards=home.locator('.kai-handling .oh-work-item').filter({hasText:'KaiOpsHighLatencyP99'});
 expect(await cards.count()).toBeGreaterThan(1);
 const operations=[];
 for(const card of await cards.all()){
  await expect(card.locator('.oh-operation')).toBeVisible();
  const operation=await card.locator('.oh-operation').innerText();expect(operation).toContain('/');operations.push(operation);
 }
 expect(new Set(operations).size).toBe(operations.length);
 const target=cards.filter({hasText:'b2306e7f-7319-4302-860d-bf9cbec068f5'});
 await expect(target.locator('.oh-operation')).toContainText('/onboarding/templates');
 fs.mkdirSync('../../artifacts/dedup-review',{recursive:true});fs.writeFileSync('../../artifacts/dedup-review/browser-identities.json',JSON.stringify({operations,displayed:await home.innerText()},null,2));
});
