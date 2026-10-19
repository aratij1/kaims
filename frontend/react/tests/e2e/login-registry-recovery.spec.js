import { expect, test } from '@playwright/test';
for(const registryFails of [false,true])test(`sign-in stays usable when the application registry ${registryFails?'fails':'is empty'}`,async({page})=>{
 await page.route('**/api-gateway/**',async route=>{
  const path=new URL(route.request().url()).pathname.replace(/^\/api-gateway/,'');
  if(path==='/applications'&&registryFails)return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'Registry temporarily unavailable'})});
  const body=path==='/auth/config'?{mode:'local',local_development_only:true}:path==='/auth/login'?{access_token:'login-regression',refresh_token:'refresh-regression',user:{id:1,username:'admin',role_name:'Administrator'}}:path==='/healthz'?{status:'ok'}:{data:{rows:[]},rows:[]};
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(body)});
 });
 await page.goto('/');await page.getByLabel('Username').fill('admin');await page.getByLabel('Password').fill('fixture-password');
 const button=page.getByRole('button',{name:/sign in/i});await expect(button).toBeEnabled();
 await button.click();await expect(page.locator('.kai-shell')).toBeVisible();
 await expect(page.getByRole('heading',{name:'Welcome back'})).toHaveCount(0);
});
