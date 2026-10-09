import type { ScanReport } from './types.js';
import { severityRank } from './types.js';
export function renderTerminal(report:ScanReport):string {
 const lines=['Dependency Guardian 0.2.0',`Project: ${report.project}`,`Packages: ${report.dependencyCount} installations (${report.uniquePackages} unique name/version pairs)`,`Lookup: ${report.complete?'complete':'INCOMPLETE'}`,`Findings: ${report.findings.length}`,''];
 for(const finding of [...report.findings].sort((a,b)=>severityRank[b.severity]-severityRank[a.severity])){
  lines.push(`[${finding.severity}] ${finding.packageName}@${finding.installedVersion} — ${finding.id}`,`  ${finding.summary.replace(/\s+/g,' ').slice(0,200)}`,`  at ${finding.paths.join(', ')}`,`  https://osv.dev/vulnerability/${encodeURIComponent(finding.id)}`);
 }
 if(report.warnings.length)lines.push('',...report.warnings.map(x=>`WARNING: ${x}`));
 return lines.join('\n');
}
export function renderSarif(report:ScanReport):object {
 const rules=new Map(report.findings.map(f=>[f.id,{id:f.id,name:f.id,shortDescription:{text:f.summary},helpUri:`https://osv.dev/vulnerability/${encodeURIComponent(f.id)}`}]));
 return {version:'2.1.0',$schema:'https://json.schemastore.org/sarif-2.1.0.json',
  runs:[{tool:{driver:{name:'Dependency Guardian',version:'0.2.0',informationUri:'https://github.com/Lyvt-Dev/Dependency-Guardian',rules:[...rules.values()]}},
   results:report.findings.map(f=>({ruleId:f.id,level:['CRITICAL','HIGH'].includes(f.severity)?'error':f.severity==='MEDIUM'?'warning':'note',message:{text:`${f.packageName}@${f.installedVersion}: ${f.summary}`},locations:[{physicalLocation:{artifactLocation:{uri:'package-lock.json'},region:{startLine:1}}}],properties:{severity:f.severity,package:f.packageName,version:f.installedVersion,paths:f.paths}}))}]};
}
export function renderMarkdown(report:ScanReport):string{
 const esc=(value:string)=>value.replace(/\|/g,'\\|').replace(/[\r\n]+/g,' ').replace(/`/g,"'");
 const counts=Object.fromEntries(['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].map(k=>[k,report.findings.filter(f=>f.severity===k).length]));
 const lines=['# Dependency Guardian — Security Report','',`- **Scan complete:** ${report.complete?'Yes':'No — results incomplete'}`,`- **Dependencies analyzed:** ${report.dependencyCount}`,`- **Findings:** ${report.findings.length}`,`- **By severity:** ${Object.entries(counts).map(([k,v])=>`${k}: ${v}`).join(' · ')}`,'','| Severity | Package | Advisory | Locations |','| --- | --- | --- | --- |'];
 for(const f of [...report.findings].sort((a,b)=>severityRank[b.severity]-severityRank[a.severity]))lines.push(`| ${f.severity} | ${esc(f.packageName)}@${esc(f.installedVersion)} | [${esc(f.id)}](https://osv.dev/vulnerability/${encodeURIComponent(f.id)}) | ${f.paths.map(esc).join(', ')} |`);
 if(report.warnings.length)lines.push('','## Warnings','',...report.warnings.map(w=>`- ${esc(w)}`));
 return lines.join('\n');
}
