export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
export interface PackageInstance { name:string; version:string; path:string; direct:boolean; dev:boolean; optional:boolean; dependencies:string[] }
export interface Advisory { id:string; aliases?:string[]; summary?:string; details?:string; severity?:Array<{type:string;score:string}>; database_specific?:{severity?:string}; affected?:Array<{package?:{ecosystem?:string;name?:string};ranges?:Array<{type:string;events:Array<Record<string,string>>}>}>; references?:Array<{type?:string;url:string}>; modified?:string }
export interface Finding { id:string; aliases:string[]; packageName:string; installedVersion:string; paths:string[]; severity:Severity; summary:string; references:string[]; category:'VULNERABILITY' }
export interface ScanReport { schemaVersion:1; project:string; scannedAt:string; complete:boolean; dependencyCount:number; uniquePackages:number; findings:Finding[]; warnings:string[]; source:'OSV' }
export const severityRank:Record<Severity,number>={UNKNOWN:-1,LOW:0,MEDIUM:1,HIGH:2,CRITICAL:3};
