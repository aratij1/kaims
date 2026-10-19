import fs from 'node:fs';
import {test,expect} from '@playwright/test';
test.skip(!process.env.KAIOPS_LIVE_E2E,'Live stack only');
test('homepage refresh bypasses stale data for every homepage feed',async({page,context},info)=>{
 test.setTimeout(120000);
 const cdp=await context.newCDPSession(page);
 await cdp.send('Network.clearBrowserCache');await cdp.send('Network.setCacheDisabled',{cacheDisabled:true});
 await page.goto('/');
 await page.getByLabel('Username').fill('admin');await page.getByLabel('Password').fill(process.env.KAIOPS_E2E_PASSWORD);
 await page.getByRole('button',{name:/sign in/i}).click();
 const home=page.locator('.operations-home');await expect(home).toBeVisible({timeout:45000});
 const refresh=home.getByRole('button',{name:'Refresh',exact:true});await expect(refresh).toBeEnabled({timeout:30000});
 // Let the initial feeds settle so these responses must come from manual refresh.
 await expect(home.locator('.oh-scope')).not.toContainText('Updating live data');
 const paths=['/alerts/all?','/incidents/groups?','/incidents/closed?'];
 const responses=paths.map(path=>page.waitForResponse(r=>r.url().includes(path)&&r.request().method()==='GET',{timeout:45000}));
 await refresh.click();
 const received=await Promise.all(responses);
 for(const response of received){expect(response.status()).toBe(200);expect(response.headers()['cache-control']).toContain('no-store');}
 await expect(refresh).toBeEnabled({timeout:45000});
 await expect(home.locator('.oh-scope')).toContainText(/Updated \d/);
 const groupsPayload=await received[1].json();const groups=groupsPayload.data||groupsPayload;
 const terminalStates=['closed','resolved','recovered','cancelled'];
 const expectedHandling=new Map((groups.rows||[]).filter(row=>!terminalStates.includes(String(row.status||'').toLowerCase())).map(row=>[row.canonical_incident_id||row.incident_id||row.id,row]));
 // The API window spans projects; the overview applies the selected project.
 const handlingCount=Number(await home.locator('.kai-handling header em').innerText());
 expect(handlingCount).toBeLessThanOrEqual(expectedHandling.size);
 const handlingCards=home.locator('.kai-handling .oh-work-item');
 await expect(handlingCards).toHaveCount(Math.min(handlingCount,6));
 for(const card of await handlingCards.all()){
  const displayed=await card.innerText();
  expect([...expectedHandling.keys()].some(id=>displayed.includes(id))).toBe(true);
 }
 const attentionText=await home.locator('.needs-you').innerText();
 for(const card of await handlingCards.all()){const id=(await card.innerText()).match(/[0-9a-f]{8}-[0-9a-f-]{27,}/i)?.[0];if(id) expect(attentionText).not.toContain(id);}
 const autoRefresh=await page.waitForResponse(r=>r.url().includes('/incidents/groups?')&&r.request().method()==='GET',{timeout:35000});
 expect(autoRefresh.status()).toBe(200);
 const closed=await received[2].json();const data=closed.data||closed;
 const evidence={verified_at:new Date().toISOString(),requests:received.map(r=>({path:new URL(r.url()).pathname,status:r.status(),from_service_worker:r.fromServiceWorker()})),closed_rows:data.rows?.length,latest_closures:(data.rows||[]).slice(0,4).map(r=>({incident_id:r.incident_id||r.id,status:r.status,closed_at:r.closed_at})),displayed:await home.innerText()};
 fs.mkdirSync('../../artifacts/home-cache-review',{recursive:true});fs.writeFileSync('../../artifacts/home-cache-review/latest-homepage.json',JSON.stringify(evidence,null,2));
 await page.screenshot({path:'../../artifacts/home-cache-review/latest-homepage.png',fullPage:true});
});

test('homepage identifies stale results after a failed refresh and recovers on retry',async({page})=>{
 test.setTimeout(120000);
 await page.goto('/');
 await page.getByLabel('Username').fill('admin');
 await page.getByLabel('Password').fill(process.env.KAIOPS_E2E_PASSWORD);
 await page.getByRole('button',{name:/sign in/i}).click();
 const home=page.locator('.operations-home');
 await expect(home).toBeVisible({timeout:45000});
 await expect(home.locator('.oh-scope')).toContainText(/Updated \d/,{timeout:30000});
 const previousCount=await home.locator('.oh-work-item').count();
 await page.route('**/api-gateway/incidents/groups?**',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'Temporary read failure for freshness verification'})}));
 await home.getByRole('button',{name:'Refresh',exact:true}).click();
 const warning=home.getByRole('alert');
 await expect(warning).toContainText('Showing the last successful results',{timeout:30000});
 expect(await home.locator('.oh-work-item').count()).toBe(previousCount);
 await page.unroute('**/api-gateway/incidents/groups?**');
 await warning.getByRole('button',{name:'Retry refresh'}).click();
 await expect(warning).toHaveCount(0,{timeout:30000});
 await expect(home.locator('.oh-truth').filter({hasText:'Evidence jobs:'})).toBeVisible();
 await page.route('**/api-gateway/operations/queue-health',route=>route.fulfill({status:503,contentType:'application/json',body:'{"detail":"Temporary telemetry failure"}'}));
 await home.getByRole('button',{name:'Refresh',exact:true}).click();
 await expect(home.getByRole('status').filter({hasText:'Alert analysis:'})).toContainText('Processing paused: capacity service unavailable',{timeout:30000});
 await expect(home.getByRole('status').filter({hasText:'Alert analysis:'})).toContainText('Evidence job counts unavailable');
});
