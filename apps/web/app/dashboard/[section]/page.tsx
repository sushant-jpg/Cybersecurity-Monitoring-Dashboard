"use client";

import { use, useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { BellRing, CheckCheck, ChevronRight, CirclePlus, Database, ExternalLink, KeyRound, Search, Server, ShieldCheck, ToggleLeft, ToggleRight } from "lucide-react";
import type { Severity } from "@securewatch/shared";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";

type Row = Record<string, unknown>;
const configs: Record<string,{title:string;eyebrow:string;description:string;endpoint:string;columns:Array<[string,string]>}> = {
  alerts:{title:"Security alerts",eyebrow:"Detection queue",description:"Prioritized findings created by enabled detection rules.",endpoint:"/api/v1/alerts",columns:[["severity","Severity"],["title","Alert"],["status","Status"],["riskScore","Risk"],["affectedUser","Affected user"],["ipAddress","Source IP"],["createdAt","Detected"]]},
  incidents:{title:"Incident management",eyebrow:"Case workflow",description:"Coordinate investigation, containment, recovery, and evidence.",endpoint:"/api/v1/incidents",columns:[["severity","Severity"],["title","Incident"],["status","Status"],["assignedAnalyst","Assigned analyst"],["createdAt","Created"]]},
  users:{title:"Users & behavior",eyebrow:"Identity security",description:"Organization members, roles, sessions, and identity posture.",endpoint:"/api/v1/users",columns:[["name","Name"],["email","Email"],["role","Role"],["lastLoginAt","Last login"],["lockedUntil","Lock status"]]},
  applications:{title:"Monitored applications",eyebrow:"Data sources",description:"Register trusted telemetry sources and rotate ingestion credentials.",endpoint:"/api/v1/applications",columns:[["name","Application"],["environment","Environment"],["type","Type"],["_count","Events"],["apiKeys","API keys"],["createdAt","Registered"]]},
  rules:{title:"Detection rules",eyebrow:"Detection engineering",description:"Tune thresholds, windows, severities, and rule availability.",endpoint:"/api/v1/rules",columns:[["enabled","Enabled"],["name","Rule"],["severity","Severity"],["threshold","Threshold"],["timeWindowSec","Window"],["baseRiskScore","Base risk"]]},
  audit:{title:"Audit log",eyebrow:"Accountability",description:"Immutable trace of security-sensitive platform actions.",endpoint:"/api/v1/audit",columns:[["timestamp","Time"],["action","Action"],["actor","Actor"],["actorRole","Role"],["targetType","Target"],["requestId","Request ID"]]},
  notifications:{title:"Notifications",eyebrow:"Attention center",description:"High-priority alerts, incidents, lockouts, and security changes.",endpoint:"/api/v1/notifications",columns:[["readAt","State"],["type","Type"],["title","Notification"],["message","Details"],["createdAt","Received"]]}
};

export default function SectionPage({params}:{params:Promise<{section:string}>}) {
  const {section}=use(params);
  if(section==="system-health") return <SystemHealth/>;
  if(section==="threat-intelligence") return <ThreatIntelligence/>;
  if(section==="analytics") return <AnalyticsSummary/>;
  if(section==="settings") return <Settings/>;
  const config=configs[section];
  if(!config) return <EmptyState title="Page not found" description="This security workspace section does not exist."/>;
  return <ResourceTable section={section} config={config}/>;
}

function ResourceTable({section,config}:{section:string;config:typeof configs[string]}) {
  const [rows,setRows]=useState<Row[]>([]);const [error,setError]=useState("");const [loading,setLoading]=useState(true);const [search,setSearch]=useState("");const [showCreate,setShowCreate]=useState(false);const [secret,setSecret]=useState("");
  const load=useCallback(async()=>{setLoading(true);setError("");try{const result=await api<Row[]|{items:Row[]}>(config.endpoint);setRows(Array.isArray(result)?result:result.items);}catch(e){setError(e instanceof Error?e.message:"Unable to load records");}finally{setLoading(false);}},[config.endpoint]);
  useEffect(()=>{const initial=setTimeout(()=>void load(),0);return()=>clearTimeout(initial);},[load]);
  const filtered=useMemo(()=>rows.filter((row)=>!search||JSON.stringify(row).toLowerCase().includes(search.toLowerCase())),[rows,search]);
  const toggleRule=async(row:Row)=>{await api(`/api/v1/rules/${String(row.id)}`,{method:"PATCH",body:JSON.stringify({enabled:!row.enabled})});await load();};
  const createApp=async(event:FormEvent<HTMLFormElement>)=>{event.preventDefault();const form=new FormData(event.currentTarget);const app=await api<{id:string}>("/api/v1/applications",{method:"POST",body:JSON.stringify({name:form.get("name"),environment:form.get("environment"),type:form.get("type")})});const key=await api<{apiKey:string}>(`/api/v1/applications/${app.id}/keys`,{method:"POST",body:JSON.stringify({name:"Primary ingestion key"})});setSecret(key.apiKey);setShowCreate(false);await load();};
  const markAll=async()=>{await api("/api/v1/notifications/read-all",{method:"PATCH",body:"{}"});await load();};
  return <><PageHeader eyebrow={config.eyebrow} title={config.title} description={config.description} action={<div className="flex gap-2">{section==="notifications"&&<Button variant="outline" onClick={markAll}><CheckCheck className="h-4 w-4"/>Mark all read</Button>}{section==="applications"&&<Button onClick={()=>setShowCreate(!showCreate)}><CirclePlus className="h-4 w-4"/>Register application</Button>}</div>}/>
    {showCreate&&<form onSubmit={createApp} className="panel mb-4 grid gap-3 p-5 md:grid-cols-[1fr_180px_200px_auto]"><input name="name" required placeholder="Application name" className="h-10 rounded-lg border border-white/10 bg-black/10 px-3 text-sm outline-none"/><input name="environment" required defaultValue="Production" placeholder="Environment" className="h-10 rounded-lg border border-white/10 bg-black/10 px-3 text-sm outline-none"/><input name="type" required defaultValue="Node.js API" placeholder="Application type" className="h-10 rounded-lg border border-white/10 bg-black/10 px-3 text-sm outline-none"/><Button type="submit">Create & issue key</Button></form>}
    {secret&&<div className="mb-4 rounded-xl border border-amber-400/20 bg-amber-400/[.06] p-5"><div className="flex items-center gap-2 text-sm font-semibold text-amber-200"><KeyRound className="h-4 w-4"/>Copy this ingestion key now</div><code className="mt-3 block overflow-x-auto rounded-lg bg-black/30 p-3 text-xs text-amber-100">{secret}</code><p className="mt-2 text-xs text-amber-200/60">Only its SHA-256 hash is stored. SecureWatch cannot show this key again.</p></div>}
    <div className="panel mb-4 flex items-center gap-2 p-3"><Search className="ml-1 h-4 w-4 text-slate-600"/><input className="h-9 flex-1 bg-transparent text-sm outline-none placeholder:text-slate-600" placeholder={`Search ${config.title.toLowerCase()}…`} value={search} onChange={(e)=>setSearch(e.target.value)}/><span className="text-xs text-slate-600">{filtered.length} records</span></div>
    {loading?<LoadingState/>:error?<ErrorState message={error} retry={load}/>:filtered.length===0?<EmptyState title={`No ${config.title.toLowerCase()} found`} description="There are no records in this organization matching the current view."/>:<div className="panel overflow-hidden"><div className="overflow-x-auto"><table className="w-full min-w-[850px] text-left"><thead className="border-b border-white/[.06] bg-white/[.018] text-[10px] uppercase tracking-wider text-slate-500"><tr>{config.columns.map(([,label])=><th key={label} className="px-4 py-3 font-semibold">{label}</th>)}<th className="px-4 py-3"/></tr></thead><tbody className="divide-y divide-white/[.05]">{filtered.map((row)=><tr key={String(row.id)} className="hover:bg-white/[.018]">{config.columns.map(([key])=><td key={key} className="max-w-xs px-4 py-3 text-xs text-slate-400">{renderCell(key,row[key],row,section,toggleRule)}</td>)}<td className="px-4 py-3 text-right">{["alerts","incidents"].includes(section)&&<Link href={`/dashboard/${section}/${String(row.id)}`} className="inline-flex h-8 w-8 items-center justify-center rounded-lg hover:bg-white/[.05]"><ChevronRight className="h-4 w-4"/></Link>}</td></tr>)}</tbody></table></div></div>}
  </>;
}

function renderCell(key:string,value:unknown,row:Row,section:string,toggleRule:(row:Row)=>void):React.ReactNode {
  if(key==="severity"&&typeof value==="string")return <SeverityBadge severity={value as Severity}/>;
  if(key==="enabled")return <button onClick={()=>toggleRule(row)} className={value?"text-emerald-300":"text-slate-600"}>{value?<ToggleRight className="h-6 w-6"/>:<ToggleLeft className="h-6 w-6"/>}</button>;
  if(key==="readAt")return value?<span className="text-slate-600">Read</span>:<span className="inline-flex items-center gap-1 text-cyan-300"><BellRing className="h-3 w-3"/>Unread</span>;
  if(key==="lockedUntil")return value?<span className="text-red-300">Locked until {formatDate(String(value))}</span>:<span className="text-emerald-300">Active</span>;
  if(key==="_count"&&value&&typeof value==="object")return String((value as Row).events??0);
  if(key==="apiKeys"&&Array.isArray(value))return `${value.filter((v)=>!(v as Row).revokedAt).length} active`;
  if(key==="assignedAnalyst"||key==="actor")return value&&typeof value==="object"?String((value as Row).name??"—"):"—";
  if(["createdAt","timestamp","lastLoginAt"].includes(key))return value?formatDate(String(value)):"—";
  if(key==="timeWindowSec")return `${Number(value)/60} min`;
  if(key==="riskScore"||key==="baseRiskScore")return <span className="font-mono font-semibold text-slate-200">{String(value)}/100</span>;
  if(key==="title")return <span className="font-medium text-slate-200">{String(value??"—")}</span>;
  if(typeof value==="boolean")return value?"Yes":"No";
  if(value==null)return "—";
  if(typeof value==="object")return JSON.stringify(value);
  return String(value).replaceAll("_"," ");
}

function SystemHealth(){const [data,setData]=useState<{services:Record<string,{status:string;detail?:string}>;checkedAt:string}|null>(null);const [error,setError]=useState("");const load=useCallback(async()=>{try{setData(await api("/api/v1/system/status"));}catch(e){setError(e instanceof Error?e.message:"Health check failed");}},[]);useEffect(()=>{const initial=setTimeout(()=>void load(),0);const timer=setInterval(()=>void load(),15000);return()=>{clearTimeout(initial);clearInterval(timer);};},[load]);return <><PageHeader eyebrow="Platform" title="System health" description="Live dependency checks for the monitoring control plane."/>{error?<ErrorState message={error} retry={load}/>:!data?<LoadingState/>:<div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{Object.entries(data.services).map(([name,service])=><div key={name} className="panel p-5"><div className="flex items-center justify-between"><div className="grid h-9 w-9 place-items-center rounded-lg bg-white/[.04]">{name==="postgresql"?<Database className="h-4 w-4"/>:<Server className="h-4 w-4"/>}</div><span className={`rounded-full border px-2 py-1 text-[10px] font-semibold ${service.status==="HEALTHY"?"border-emerald-400/20 bg-emerald-400/10 text-emerald-300":service.status==="DEGRADED"?"border-amber-400/20 bg-amber-400/10 text-amber-300":"border-red-400/20 bg-red-400/10 text-red-300"}`}>{service.status}</span></div><h2 className="mt-5 capitalize font-medium">{name.replace(/([A-Z])/g," $1")}</h2><p className="mt-2 text-xs text-slate-500">{service.detail??"Dependency responded successfully."}</p></div>)}</div>}</>}

function ThreatIntelligence(){const [ip,setIp]=useState("203.0.113.10");const [data,setData]=useState<Row|null>(null);const [error,setError]=useState("");const search=async(e:FormEvent)=>{e.preventDefault();setError("");try{setData(await api(`/api/v1/threat-intelligence/ip/${ip}`));}catch(x){setError(x instanceof Error?x.message:"Lookup failed");}};return <><PageHeader eyebrow="Enrichment" title="IP intelligence" description="Investigate observed addresses with internal evidence and clearly labeled reputation sources."/><form onSubmit={search} className="panel flex gap-3 p-4"><input value={ip} onChange={(e)=>setIp(e.target.value)} className="h-10 flex-1 rounded-lg border border-white/10 bg-black/10 px-3 font-mono text-sm outline-none" placeholder="IPv4 or IPv6 address"/><Button><Search className="h-4 w-4"/>Investigate</Button></form>{error&&<div className="mt-4"><ErrorState message={error} retry={()=>setError("")}/></div>}{data&&<div className="mt-4 grid gap-4 md:grid-cols-3"><div className="panel p-5 md:col-span-2"><p className="text-xs text-muted">Observed address</p><p className="mt-2 font-mono text-2xl">{String(data.ipAddress)}</p><div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4">{[["Risk",data.riskScore],["Events",data.eventsGenerated],["Failed logins",data.failedLogins],["Affected users",Array.isArray(data.affectedUsers)?data.affectedUsers.length:0]].map(([l,v])=><div key={String(l)}><p className="text-xs text-slate-500">{String(l)}</p><p className="mt-1 font-mono text-xl font-semibold">{String(v)}</p></div>)}</div></div><div className="panel p-5"><div className="flex items-center justify-between"><ShieldCheck className="h-5 w-5 text-cyan-300"/><span className="rounded-full bg-amber-400/10 px-2 py-1 text-[10px] text-amber-300">{(data.reputation as Row)?.isDemo?"DEMO DATA":"EXTERNAL"}</span></div><p className="mt-5 text-xs text-slate-500">Reputation</p><p className="mt-1 text-lg font-semibold">{String((data.reputation as Row)?.reputation??"UNKNOWN")}</p><p className="mt-3 text-xs leading-5 text-slate-500">{String(data.accuracyNotice)}</p></div></div>}</>}

function AnalyticsSummary(){const router=useRouter();return <><PageHeader eyebrow="Analysis" title="Security analytics" description="Aggregated telemetry is available on the overview, with category, source, identity, location, and risk breakdowns."/><div className="panel flex min-h-72 flex-col items-center justify-center text-center"><ExternalLink className="h-9 w-9 text-cyan-300"/><h2 className="mt-4 font-semibold">Unified analytics workspace</h2><p className="mt-2 max-w-md text-sm text-muted">Open the command center to explore live, backend-aggregated charts and security metrics.</p><Button className="mt-5" onClick={()=>router.push("/dashboard")}>Open overview</Button></div></>}

function Settings(){return <><PageHeader eyebrow="Administration" title="Security settings" description="Organization-wide retention and integration settings are controlled by privileged API operations."/><div className="grid gap-4 md:grid-cols-2"><div className="panel p-6"><h2 className="font-semibold">Data retention</h2><p className="mt-2 text-sm text-muted">Security events: 90 days<br/>Audit records: 365 days</p></div><div className="panel p-6"><h2 className="font-semibold">Threat provider</h2><p className="mt-2 text-sm text-muted">Demo provider is used unless an external provider and credential are configured. Demo results are never presented as verified intelligence.</p></div></div></>}
