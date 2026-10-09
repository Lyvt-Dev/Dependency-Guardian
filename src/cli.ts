#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { scan } from './scanner.js';
import { renderSarif, renderTerminal, renderMarkdown } from './report.js';
import { severityRank, type Severity } from './types.js';
function usage():string{return `Dependency Guardian — npm dependency security scanner

Usage:
  guardian scan [directory] [--json | --sarif | --markdown] [--output filename] [--severity low|medium|high|critical] [--exclude-dev] [--ignore OSV-ID] [--fail-on-unknown]
  guardian explain <OSV-ID>
  guardian doctor
  guardian --help

Exit codes: 0 = policy passed, 1 = findings at threshold, 2 = error/incomplete scan`;}
export async function main(argv:string[]):Promise<number>{
 if(!argv.length||argv.includes('--help')||argv[0]==='help'){console.log(usage());return 0;}
 if(argv[0]==='doctor'){console.log(`Node: ${process.version}\nOSV endpoint: https://api.osv.dev\nNode >=22: ${Number(process.versions.node.split('.')[0])>=22}`);return Number(process.versions.node.split('.')[0])>=22?0:2;}
 if(argv[0]==='explain'){if(!argv[1]||!/^[\w.-]{3,100}$/.test(argv[1])){console.error('Expected an OSV ID');return 2;}console.log(`https://osv.dev/vulnerability/${encodeURIComponent(argv[1])}`);return 0;}
 if(argv[0]!=='scan'){console.error(usage());return 2;}
 const args=argv.slice(1);let directory='.';let format:'json'|'sarif'|'markdown'|'terminal'='terminal';let output:string|undefined;let threshold:Severity='HIGH';let excludeDev=false;let failOnUnknown=false;const ignoreIds:string[]=[];
 for(let i=0;i<args.length;i++){
  const arg=args[i]!;
  if(arg==='--json')format='json';else if(arg==='--sarif')format='sarif';else if(arg==='--markdown')format='markdown';
  else if(arg==='--exclude-dev')excludeDev=true;
  else if(arg==='--fail-on-unknown')failOnUnknown=true;
  else if(arg==='--ignore'){const id=args[++i];if(!id||!/^[\w.-]{3,100}$/.test(id))throw new Error('Invalid --ignore ID');ignoreIds.push(id);}
  else if(arg==='--output'){output=args[++i];if(!output)throw new Error('Missing --output filename');}
  else if(arg==='--severity'){const v=args[++i]?.toUpperCase();if(!v||!['LOW','MEDIUM','HIGH','CRITICAL'].includes(v))throw new Error('Invalid --severity threshold');threshold=v as Severity;}
  else if(arg.startsWith('-'))throw new Error(`Unknown option: ${arg}`);
  else if(directory==='.')directory=arg;else throw new Error('Too many positional arguments');
 }
 const report=await scan(directory,undefined,{excludeDev,ignoreIds});
 const content=format==='json'?JSON.stringify(report,null,2):format==='sarif'?JSON.stringify(renderSarif(report),null,2):format==='markdown'?renderMarkdown(report):renderTerminal(report);
 if(output){await writeFile(output,content+'\n','utf8');console.error(`Report written to ${output}`);}else console.log(content);
 if(!report.complete)return 2;
 return report.findings.some(f=>severityRank[f.severity]>=severityRank[threshold]||(failOnUnknown&&f.severity==='UNKNOWN'))?1:0;
}
main(process.argv.slice(2)).then(code=>{process.exitCode=code;}).catch(error=>{console.error(`Guardian error: ${error instanceof Error?error.message:String(error)}`);process.exitCode=2;});
