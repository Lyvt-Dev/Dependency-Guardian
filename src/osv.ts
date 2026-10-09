import type { Advisory, PackageInstance } from './types.js';
const API='https://api.osv.dev';
export interface Transport {(url:string,init?:RequestInit):Promise<Response>}
const MAX_BATCH=100;
async function jsonRequest<T>(url:string,init:RequestInit,transport:Transport,retries=2):Promise<T>{
 for(let attempt=0;;attempt++){
  try{
   const response=await transport(url,{...init,signal:AbortSignal.timeout(12000)});
   if(!response.ok){
    if((response.status===429||response.status>=500)&&attempt<retries){await new Promise(r=>setTimeout(r,300*(attempt+1)));continue;}
    throw new Error(`OSV returned HTTP ${response.status}`);
   }
   return await response.json() as T;
  }catch(error){if(attempt>=retries)throw error;await new Promise(r=>setTimeout(r,300*(attempt+1)));}
 }
}
interface Query{package:{name:string;ecosystem:'npm'};version:string;page_token?:string}
interface QueryResult{vulns?:Array<{id:string}>;next_page_token?:string}
export async function fetchAdvisories(packages:PackageInstance[],transport:Transport=fetch):Promise<Map<string,Advisory[]>>{
 const keys=[...new Set(packages.map(p=>`${p.name}\0${p.version}`))];
 const results=new Map<string,Advisory[]>(),idsByKey=new Map<string,Set<string>>();
 for(const key of keys){results.set(key,[]);idsByKey.set(key,new Set());}
 for(let offset=0;offset<keys.length;offset+=MAX_BATCH){
  const chunk=keys.slice(offset,offset+MAX_BATCH);
  let pending=chunk.map(key=>({key,token:undefined as string|undefined}));
  for(let page=0;pending.length>0;page++){
   if(page>30)throw new Error('OSV query pagination exceeded safety limit');
   const queries:Query[]=pending.map(({key,token})=>{const[name,version]=key.split('\0');return{package:{name:name!,ecosystem:'npm'},version:version!,...(token?{page_token:token}:{})};});
   const data=await jsonRequest<{results:QueryResult[]}>(`${API}/v1/querybatch`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({queries})},transport);
   if(!Array.isArray(data.results)||data.results.length!==pending.length)throw new Error('Unexpected OSV batch response');
   const next:typeof pending=[];
   data.results.forEach((item,i)=>{
    if(!Array.isArray(item.vulns)&&item.vulns!==undefined)throw new Error('Unexpected OSV vulnerability list');
    const key=pending[i]!.key;
    for(const vuln of item.vulns??[])if(typeof vuln.id==='string')idsByKey.get(key)!.add(vuln.id);
    if(item.next_page_token)next.push({key,token:item.next_page_token});
   });
   pending=next;
  }
 }
 const details=new Map<string,Advisory>();
 const ids=[...new Set([...idsByKey.values()].flatMap(set=>[...set]))];
 for(let i=0;i<ids.length;i+=8)await Promise.all(ids.slice(i,i+8).map(async id=>{
  const item=await jsonRequest<Advisory>(`${API}/v1/vulns/${encodeURIComponent(id)}`,{method:'GET'},transport);
  if(item.id!==id)throw new Error(`Unexpected OSV advisory ID for ${id}`);
  details.set(id,item);
 }));
 for(const[key,ids]of idsByKey)results.set(key,[...ids].map(id=>details.get(id)!));
 return results;
}
