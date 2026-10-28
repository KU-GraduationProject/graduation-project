const {chromium}=require(process.env.TEMP+'/leafy-grafana-browser/node_modules/playwright-core');
const fs=require('fs');
const path=require('path');
const root=path.resolve(__dirname,'..','..','graduation-project');
const env=Object.fromEntries(fs.readFileSync(path.join(root,'.env'),'utf8').replace(/^\uFEFF/,'').split(/\r?\n/).filter(l=>!l.startsWith('#')&&l.includes('=')).map(l=>[l.slice(0,l.indexOf('=')),l.slice(l.indexOf('=')+1).trim().replace(/^['"]|['"]$/g,'')]));
const summary=JSON.parse(fs.readFileSync(path.join(__dirname,'summary.json'),'utf8'));
const preflight=JSON.parse(fs.readFileSync(path.join(__dirname,'preflight.json'),'utf8'));
const snapshotEnd=Date.parse(summary.panel_snapshot_at);
(async()=>{
 const browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 let page;
 try {
  const context=await browser.newContext({viewport:{width:1700,height:1150}});
  const auth=await context.request.post('http://localhost:3000/login',{data:{user:'admin',password:env.GRAFANA_PASSWORD||'admin'}});
  if(!auth.ok())throw new Error('Grafana login failed');
  page=await context.newPage();
  const errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  const base='http://localhost:3000/d/aiops-main?orgId=1&timezone=Asia%2FSeoul';
  await page.goto(base+'&from='+(snapshotEnd-900000)+'&to='+snapshotEnd+'&viewPanel=panel-63',{waitUntil:'domcontentloaded'});
  await page.waitForTimeout(6000);
  await page.getByText('✅ 인가 목적지 누적 전송 (5m)',{exact:true}).scrollIntoViewIfNeeded({timeout:20000});
  await page.waitForTimeout(2500);
  fs.writeFileSync(path.join(__dirname,'browser-network.txt'),await page.locator('body').innerText());
  await page.screenshot({path:path.join(__dirname,'grafana-ca-network.png')});
  await page.goto(base+'&from='+preflight.window_start_ms+'&to='+snapshotEnd,{waitUntil:'domcontentloaded'});
  await page.waitForTimeout(5000);
  await page.evaluate(()=>{for(const e of document.querySelectorAll('*'))if(e.scrollHeight>e.clientHeight+500)e.scrollTop=e.scrollHeight;});
  await page.getByText('평균 탐지 시간 (MTTD) · 표본 수',{exact:true}).scrollIntoViewIfNeeded({timeout:20000});
  await page.getByText(summary.experiment_id,{exact:true}).first().waitFor({timeout:20000});
  await page.getByText('네트워크 경보 상세',{exact:true}).scrollIntoViewIfNeeded();
  await page.waitForTimeout(2500);
  let text=await page.locator('body').innerText();
  if(!text.includes('C-a')||!text.includes('not_detected'))throw new Error('C-a result row missing');
  if(!text.includes('미측정'))throw new Error('Null latency is not visibly represented');
  fs.writeFileSync(path.join(__dirname,'browser-overview.txt'),text);
  await page.screenshot({path:path.join(__dirname,'grafana-ca-overview.png')});
  await page.goto(base+'&from='+preflight.window_start_ms+'&to='+snapshotEnd+'&var-experiment_id='+summary.experiment_id,{waitUntil:'domcontentloaded'});
  await page.waitForTimeout(5000);
  await page.evaluate(()=>{for(const e of document.querySelectorAll('*'))if(e.scrollHeight>e.clientHeight+500)e.scrollTop=e.scrollHeight;});
  await page.getByText('평균 탐지 시간 (MTTD) · 표본 수',{exact:true}).scrollIntoViewIfNeeded({timeout:20000});
  await page.waitForTimeout(2500);
  text=await page.locator('body').innerText();
  const measured=text.slice(text.indexOf('탐지 시간 및 수신 경보'));
  if(!measured.includes('not_detected')||!measured.includes('미측정')||!measured.match(/표본 수\s+0/))throw new Error('Filtered C-a measurement state missing');
  fs.writeFileSync(path.join(__dirname,'browser-ca-only.txt'),measured);
  await page.screenshot({path:path.join(__dirname,'grafana-ca-only.png')});
  const result={checked_at:new Date().toISOString(),page_errors:errors,overview_null_rendered:true,ca_only_no_mttd:true,experiment_id:summary.experiment_id};
  if(errors.length)throw new Error('Browser page errors: '+JSON.stringify(errors));
  fs.writeFileSync(path.join(__dirname,'browser-verification.json'),JSON.stringify(result,null,2));
  console.log(JSON.stringify(result));
  console.log(measured);
 }catch(e){
  if(page){await page.screenshot({path:path.join(__dirname,'browser-failure.png')});console.log((await page.locator('body').innerText()).slice(-3500));}
  throw e;
 }finally{await browser.close();}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
