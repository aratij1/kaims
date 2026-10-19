import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import { NAVIGATION_ITEMS } from '../../src/app/navigation';
test.skip(!process.env.KAIOPS_LIVE_E2E,'Live local stack required');
test('all canonical local workspaces render and retain bounded mobile layout',async({page},testInfo)=>{
 test.setTimeout(600000);
 const errors=[];const failures=[];let current='login';const rows=[];
 page.on('pageerror',error=>errors.push({route:current,error:error.message}));
 page.on('response',response=>{if(response.status()>=500)failures.push({route:current,path:new URL(response.url()).pathname,status:response.status()});});
 await page.goto('/');await page.getByLabel('Username').fill(process.env.KAIOPS_E2E_USERNAME||'admin');await page.getByLabel('Password').fill(process.env.KAIOPS_E2E_PASSWORD||'Admin@123456');await page.getByRole('button',{name:/sign in/i}).click();
 await expect(page.locator('.kai-shell')).toBeVisible({timeout:45000});
 for(const item of NAVIGATION_ITEMS){
  current=item.path;const started=Date.now();
  await page.evaluate(path=>{history.pushState({},'',path);dispatchEvent(new PopStateEvent('popstate'));},item.path);
  const result={path:item.path,title:item.pageTitle,errors:[]};
  try{
   await expect(page.getByRole('heading',{name:item.pageTitle,level:1,exact:true})).toBeVisible({timeout:20000});
   await page.waitForTimeout(1000);
   const fatal=await page.getByText(/Application error|Something went wrong|Failed to fetch dynamically imported module/).count();
   expect(fatal).toBe(0);
   result.desktopOverflow=await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth);
   await page.setViewportSize({width:390,height:844});await page.waitForTimeout(150);
   result.mobileOverflow=await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth);
   if(result.desktopOverflow>1||result.mobileOverflow>1)result.errors.push('Document horizontal overflow');
   await page.screenshot({path:testInfo.outputPath(`${item.id}-mobile.png`),fullPage:true});
  }catch(error){result.errors.push(error.message.slice(0,500));}
  await page.setViewportSize({width:1440,height:1000});result.elapsedMs=Date.now()-started;rows.push(result);console.log(JSON.stringify(result));
 }
 const report={routes:rows,pageErrors:errors,serverErrors:failures};
 fs.writeFileSync(testInfo.outputPath('local-route-audit.json'),JSON.stringify(report,null,2));
 fs.mkdirSync('../../artifacts/local-deep-review',{recursive:true});fs.writeFileSync('../../artifacts/local-deep-review/routes.json',JSON.stringify(report,null,2));
 expect(errors).toEqual([]);expect(rows.filter(row=>row.errors.length)).toEqual([]);expect(failures).toEqual([]);
});
