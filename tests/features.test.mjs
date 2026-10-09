import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { scan } from '../dist/scanner.js';
import { renderMarkdown } from '../dist/report.js';
const response=data=>new Response(JSON.stringify(data),{status:200});
const fakeOSV=async(url,init)=>{
 if(url.endsWith('/querybatch')){
  const {queries}=JSON.parse(init.body);
  return response({results:queries.map(q=>({vulns:[{id:q.package.name==='prod'?'OSV-PROD':'OSV-DEV'}]}))});
 }
 return response({id:url.split('/').at(-1),summary:'Mocked report',database_specific:{severity:'HIGH'}});
};
async function fixture(fn){
 const dir=await mkdtemp(join(tmpdir(),'guardian-test-'));
 try{
  await writeFile(join(dir,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'':{dependencies:{prod:'1.0.0'},devDependencies:{devtool:'1.0.0'}},'node_modules/prod':{version:'1.0.0'},'node_modules/devtool':{version:'1.0.0',dev:true}}}));
  return await fn(dir);
 }finally{await rm(dir,{recursive:true,force:true});}
}
test('exclude-dev filters dev dependencies',async()=>fixture(async dir=>{
 const report=await scan(dir,fakeOSV,{excludeDev:true});
 assert.equal(report.dependencyCount,1);
 assert.equal(report.findings.length,1);
 assert.equal(report.findings[0].packageName,'prod');
}));
test('ignore advisory IDs case-insensitively',async()=>fixture(async dir=>{
 const report=await scan(dir,fakeOSV,{ignoreIds:['osv-prod','OSV-DEV']});
 assert.equal(report.complete,true);
 assert.equal(report.findings.length,0);
}));
test('markdown escapes pipe characters',async()=>fixture(async dir=>{
 const report=await scan(dir,fakeOSV);
 report.findings[0].packageName='evil|name';
 const markdown=renderMarkdown(report);
 assert.match(markdown,/\| Severity \| Package/);
 assert.ok(markdown.includes('evil\\|name'));
}));
test('invalid CLI parameters return code 2',()=>{
 for(const args of [['scan','.','--ignore'],['scan','.','--severity','BAD'],['scan','.','--output'],['scan','.','--unknown']]){
  const result=spawnSync(process.execPath,['dist/cli.js',...args],{encoding:'utf8'});
  assert.equal(result.status,2,`Unexpected exit for ${args.join(' ')}: ${result.stderr}`);
 }
});
