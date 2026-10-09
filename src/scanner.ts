import { resolve } from 'node:path';
import { parseNpmLockfile } from './parser.js';
import { fetchAdvisories, type Transport } from './osv.js';
import type { Advisory, Finding, ScanReport, Severity } from './types.js';

function cvssV3(vector:string):number|null {
 const parts=vector.split('/');
 if(!['CVSS:3.0','CVSS:3.1'].includes(parts[0]??''))return null;
 const m=Object.fromEntries(parts.slice(1).map(p=>p.split(':')));
 const weights={AV:{N:.85,A:.62,L:.55,P:.2},AC:{L:.77,H:.44},UI:{N:.85,R:.62},C:{H:.56,L:.22,N:0},I:{H:.56,L:.22,N:0},A:{H:.56,L:.22,N:0}} as const;
 const av=weights.AV[m.AV as keyof typeof weights.AV],ac=weights.AC[m.AC as keyof typeof weights.AC],ui=weights.UI[m.UI as keyof typeof weights.UI];
 const c=weights.C[m.C as keyof typeof weights.C],i=weights.I[m.I as keyof typeof weights.I],a=weights.A[m.A as keyof typeof weights.A];
 const pr=m.S==='C'?({N:.85,L:.68,H:.5} as Record<string,number>)[m.PR]:({N:.85,L:.62,H:.27} as Record<string,number>)[m.PR];
 if([av,ac,ui,c,i,a,pr].some(v=>v===undefined)||!['U','C'].includes(m.S))return null;
 const iss=1-(1-c!)*(1-i!)*(1-a!);
 const impact=m.S==='U'?6.42*iss:7.52*(iss-.029)-3.25*Math.pow(iss-.02,15);
 const exploit=8.22*av!*ac!*pr!*ui!;
 if(impact<=0)return 0;
 const base=m.S==='U'?Math.min(impact+exploit,10):Math.min(1.08*(impact+exploit),10);
 return Math.ceil((base-1e-10)*10)/10;
}
export function severityOf(advisory:Advisory):Severity{
 const direct=advisory.database_specific?.severity?.toUpperCase();
 for(const item of advisory.severity??[]){
  const n=Number(item.score);
  const score=Number.isFinite(n)&&n>=0&&n<=10?n:cvssV3(item.score);
  if(score!==null&&score!==undefined){
   if(score>=9)return'CRITICAL';if(score>=7)return'HIGH';if(score>=4)return'MEDIUM';return'LOW';
  }
 }
 if(direct&&['LOW','MEDIUM','HIGH','CRITICAL'].includes(direct))return direct as Severity;
 return'UNKNOWN';
}
export interface ScanOptions{excludeDev?:boolean;ignoreIds?:string[]}
export async function scan(directory:string,transport?:Transport,options:ScanOptions={}):Promise<ScanReport>{
 const allPackages=await parseNpmLockfile(directory);
 const packages=options.excludeDev?allPackages.filter(p=>!p.dev):allPackages;
 const ignored=new Set((options.ignoreIds??[]).map(x=>x.toUpperCase()));
 const warnings:string[]=[];
 const base:ScanReport={schemaVersion:1,project:resolve(directory),scannedAt:new Date().toISOString(),complete:true,dependencyCount:packages.length,uniquePackages:new Set(packages.map(p=>`${p.name}\0${p.version}`)).size,findings:[],warnings,source:'OSV'};
 try{
  const data=await fetchAdvisories(packages,transport);
  const merged=new Map<string,Finding>();
  for(const pkg of packages)for(const advisory of data.get(`${pkg.name}\0${pkg.version}`)??[]){
   if([advisory.id,...(advisory.aliases??[])].some(id=>ignored.has(id.toUpperCase())))continue;
   const key=`${pkg.name}\0${pkg.version}\0${advisory.id}`;
   if(merged.has(key)){merged.get(key)!.paths.push(pkg.path);continue;}
   merged.set(key,{id:advisory.id,aliases:advisory.aliases??[],packageName:pkg.name,installedVersion:pkg.version,paths:[pkg.path],severity:severityOf(advisory),summary:advisory.summary??'No advisory summary provided',category:'VULNERABILITY',references:(advisory.references??[]).map(r=>r.url).filter(u=>u.startsWith('https://')).slice(0,20)});
  }
  base.findings=[...merged.values()].sort((a,b)=>a.packageName.localeCompare(b.packageName)||a.id.localeCompare(b.id));
 }catch(error){base.complete=false;warnings.push(`OSV lookup failed: ${error instanceof Error?error.message:String(error)}`);}
 return base;
}
