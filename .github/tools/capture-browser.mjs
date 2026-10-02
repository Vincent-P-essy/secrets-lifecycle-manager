import fs from 'node:fs';
import {createRequire} from 'node:module';
const require=createRequire(process.env.CAPTURE_BROWSER_ROOT+'/package.json');
const {chromium}=require('playwright');
const [url,out,raw]=process.argv.slice(2);
const browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--enable-unsafe-swiftshader']});
try {
 const page=await browser.newPage({viewport:{width:1440,height:960}}),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto(url,{waitUntil:'domcontentloaded'});await page.waitForTimeout(2000);
 for(const a of JSON.parse(raw)){
  if(a.type==='fill')await page.locator(a.selector).fill(a.value);
  else if(a.type==='key')await page.locator(a.selector).press(a.key);
  else if(a.type==='click')await page.getByRole('button',{name:a.name}).first().click();
  else if(a.type==='selector')await page.locator(a.selector).first().click();
  else if(a.type==='wait')await page.waitForTimeout(a.ms);
  await page.waitForTimeout(500);
 }
 await page.waitForTimeout(2000);await page.screenshot({path:out});
 fs.writeFileSync(out+'.json',JSON.stringify({url,title:await page.title(),errors,text:(await page.locator('body').innerText()).slice(0,6000)},null,2)+'\n');
}finally{await browser.close();}
