import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchAdvisories } from '../dist/osv.js';
import { scan, severityOf } from '../dist/scanner.js';
const makeResponse=data=>new Response(JSON.stringify(data),{status:200,headers:{'content-type':'application/json'}});
const mock=async(url,options)=>{
 if(url.endsWith('/querybatch')){
  const{queries}=JSON.parse(options.body);
  return makeResponse({results:queries.map(q=>q.package.name==='lodash'?{vulns:[{id:'GHSA-test-123'}]}:{vulns:[]})});
 }
 if(url.endsWith('/GHSA-test-123'))return makeResponse({id:'GHSA-test-123',summary:'Test vulnerability',database_specific:{severity:'HIGH'},references:[{url:'https://osv.dev/GHSA-test-123'}]});
 throw new Error(`Unexpected mock URL: ${url}`);
};
test('OSV IDs hydrated and shared across alias installs',async()=>{
 const report=await scan('tests/fixtures',mock);
 assert.equal(report.complete,true);
 assert.equal(report.findings.length,1);
 assert.equal(report.findings[0].severity,'HIGH');
 assert.equal(report.findings[0].paths.length,2);
});
test('partial network failure is never silently marked clean',async()=>{
 const report=await scan('tests/fixtures',async()=>{throw new Error('offline');});
 assert.equal(report.complete,false);
 assert.match(report.warnings[0],/offline/);
});
test('CVSS v3 vector correctly scored',()=>{
 assert.equal(severityOf({id:'test',severity:[{type:'CVSS_V3',score:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]}),'CRITICAL');
});
test('paginated OSV batch results preserve all advisory IDs',async()=>{
 let seen=0;
 const result=await fetchAdvisories([{name:'pkg',version:'1.0.0',path:'node_modules/pkg',direct:true,dev:false,optional:false,dependencies:[]}],async(url,options)=>{
  if(url.endsWith('/querybatch')){
   const query=JSON.parse(options.body).queries[0];
   return makeResponse({results:[query.page_token?{vulns:[{id:'OSV-SECOND'}]}:{vulns:[{id:'OSV-FIRST'}],next_page_token:'page2'}]});
  }
  seen++;
  return makeResponse({id:url.split('/').at(-1)});
 });
 assert.equal(result.get('pkg\u00001.0.0').length,2);
 assert.equal(seen,2);
});
