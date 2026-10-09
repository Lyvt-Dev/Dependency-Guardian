import test from 'node:test';
import assert from 'node:assert/strict';
import { parseNpmLockfile, packageNameFromPath } from '../dist/parser.js';
test('package names resolve with nested scoped packages',()=>{
 assert.equal(packageNameFromPath('node_modules/@types/node'),'@types/node');
 assert.equal(packageNameFromPath('node_modules/foo/node_modules/@abc/tool'),'@abc/tool');
});
test('lockfile v3 includes nested packages and excludes workspace symlinks',async()=>{
 const packages=await parseNpmLockfile('tests/fixtures');
 assert.equal(packages.length,4);
 assert.deepEqual(packages.filter(p=>p.name==='lodash').map(p=>p.version),['4.17.20','4.17.20']);
 assert.equal(packages.find(p=>p.name==='foo').direct,true);
 assert.equal(packages.find(p=>p.name==='bar').direct,false);
});
