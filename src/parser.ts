import { readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import type { PackageInstance } from './types.js';

const MAX_LOCKFILE_BYTES = 25 * 1024 * 1024;
type LockPackage = { name?: unknown; version?: unknown; link?: unknown; dev?: unknown; optional?: unknown; dependencies?: unknown; optionalDependencies?: unknown };
const dict = (v:unknown):Record<string,unknown> => v && typeof v==='object' && !Array.isArray(v) ? v as Record<string,unknown> : {};
export function packageNameFromPath(path:string):string {
 const marker='/node_modules/';
 const at=path.lastIndexOf(marker);
 const tail=at>=0?path.slice(at+marker.length):path.startsWith('node_modules/')?path.slice('node_modules/'.length):'';
 if(!tail)throw new Error(`Not a node_modules entry: ${path}`);
 const segments=tail.split('/');
 return segments[0]!.startsWith('@')?`${segments[0]}/${segments[1]??''}`:segments[0]!;
}
export async function parseNpmLockfile(directory:string):Promise<PackageInstance[]> {
 const filename=join(resolve(directory),'package-lock.json');
 const bytes=await readFile(filename);
 if(bytes.byteLength>MAX_LOCKFILE_BYTES)throw new Error('Lockfile exceeds 25 MiB safety limit');
 let raw:unknown;try{raw=JSON.parse(bytes.toString('utf8'));}catch{throw new Error('Invalid JSON in package-lock.json');}
 const lock=dict(raw);
 if(![2,3].includes(Number(lock.lockfileVersion)))throw new Error('Only npm package-lock v2 and v3 are supported');
 const rawPackages=dict(lock.packages);
 if(!Object.hasOwn(rawPackages,''))throw new Error('Lockfile missing root package entry');
 if(Object.keys(rawPackages).length>100_000)throw new Error('Lockfile exceeds package count limit');
 const root=dict(rawPackages['']);
 const directNames=new Set([...Object.keys(dict(root.dependencies)),...Object.keys(dict(root.devDependencies)),...Object.keys(dict(root.optionalDependencies))]);
 const result:PackageInstance[]=[];
 for(const [path,data] of Object.entries(rawPackages)){
  if(!path||!(path.startsWith('node_modules/')||path.includes('/node_modules/')))continue;
  const entry=dict(data) as LockPackage;
  if(entry.link===true)continue;
  if(typeof entry.version!=='string'||!entry.version.trim())continue;
  const installName=packageNameFromPath(path);
  const actualName=typeof entry.name==='string'&&entry.name.length?entry.name:installName;
  const dependencies=[...Object.keys(dict(entry.dependencies)),...Object.keys(dict(entry.optionalDependencies))];
  result.push({name:actualName,version:entry.version,path,direct:path===`node_modules/${installName}`&&directNames.has(installName),dev:entry.dev===true,optional:entry.optional===true,dependencies});
 }
 return result.sort((a,b)=>a.path.localeCompare(b.path));
}
