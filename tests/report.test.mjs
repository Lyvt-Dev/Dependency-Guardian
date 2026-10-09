import test from 'node:test';
import assert from 'node:assert/strict';
import { renderSarif, renderTerminal } from '../dist/report.js';
const report={schemaVersion:1,project:'/tmp/example',scannedAt:'2026-10-09T00:00:00Z',complete:true,dependencyCount:1,uniquePackages:1,warnings:[],source:'OSV',findings:[{id:'GHSA-example',aliases:[],packageName:'demo',installedVersion:'1.0.0',paths:['node_modules/demo'],severity:'HIGH',summary:'Example vulnerability',references:[],category:'VULNERABILITY'}]};
test('SARIF report includes rules and findings',()=>{
 const value=renderSarif(report);assert.equal(value.version,'2.1.0');assert.equal(value.runs[0].tool.driver.rules[0].id,'GHSA-example');assert.equal(value.runs[0].results[0].level,'error');
});
test('Terminal displays severity, package and advisory',()=>{
 const value=renderTerminal(report);assert.match(value,/\[HIGH\] demo@1\.0\.0/);assert.match(value,/GHSA-example/);
});
