"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Activity, ArrowRight, Eye, EyeOff, LockKeyhole, Radar, ShieldCheck } from "lucide-react";
import { api, setAccessToken } from "@/lib/api";
import { Button } from "@/components/ui/button";

interface LoginResult { accessToken: string; user: { name: string; role: string }; organization: { name: string } }

export default function LoginPage() {
  const router = useRouter();
  const [organizationSlug, setOrganizationSlug] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setLoading(true); setError("");
    try {
      const data = await api<LoginResult>("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ organizationSlug, email, password }) });
      setAccessToken(data.accessToken);
      router.replace("/dashboard/applications");
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Sign in failed"); }
    finally { setLoading(false); }
  }
  return <main className="subtle-grid flex min-h-screen items-center justify-center p-5">
    <div className="grid w-full max-w-6xl overflow-hidden rounded-2xl border border-white/[.08] bg-[#0c121e]/95 shadow-2xl lg:grid-cols-[1.15fr_.85fr]">
      <section className="relative hidden min-h-[680px] overflow-hidden border-r border-white/[.07] p-12 lg:flex lg:flex-col lg:justify-between">
        <div className="absolute -right-24 -top-28 h-96 w-96 rounded-full bg-cyan-400/[.08] blur-3xl"/>
        <div className="relative flex items-center gap-3"><div className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-300/20 bg-cyan-300/10"><Radar className="h-5 w-5 text-cyan-300"/></div><div><p className="font-semibold tracking-wide">SecureWatch</p><p className="text-xs text-muted">Threat detection platform</p></div></div>
        <div className="relative max-w-lg"><div className="mb-7 inline-flex items-center gap-2 rounded-full border border-cyan-300/15 bg-cyan-300/[.06] px-3 py-1.5 text-xs text-cyan-200"><Activity className="h-3.5 w-3.5"/>Security operations, in focus</div><h1 className="text-5xl font-semibold leading-[1.08] tracking-tight">See the signals.<br/><span className="text-cyan-300">Stop the threat.</span></h1><p className="mt-6 text-base leading-7 text-slate-400">Consolidate application telemetry, surface correlated threats, and move from alert to incident with evidence intact.</p></div>
        <div className="relative grid grid-cols-3 gap-3">{[["24/7","Monitoring"],["<1s","Live feed"],["100%","Tenant scoped"]].map(([value,label])=><div key={label} className="rounded-xl border border-white/[.06] bg-white/[.025] p-4"><p className="font-mono text-lg font-semibold text-slate-100">{value}</p><p className="mt-1 text-xs text-slate-500">{label}</p></div>)}</div>
      </section>
      <section className="flex min-h-[680px] items-center p-7 sm:p-12">
        <div className="mx-auto w-full max-w-sm">
          <div className="mb-9 lg:hidden"><div className="flex items-center gap-2 text-lg font-semibold"><ShieldCheck className="h-6 w-6 text-cyan-300"/>SecureWatch</div></div>
          <p className="text-xs font-semibold uppercase tracking-[.2em] text-cyan-300">Secure access</p><h2 className="mt-3 text-3xl font-semibold tracking-tight">Welcome back</h2><p className="mt-2 text-sm text-slate-400">Sign in to your security operations workspace.</p>
          <form className="mt-8 space-y-5" onSubmit={submit}>
            <label className="block text-sm text-slate-300">Organization slug<input className="mt-2 h-11 w-full rounded-lg border border-white/10 bg-slate-950/40 px-3 text-sm outline-none transition focus:border-cyan-400/60" value={organizationSlug} onChange={(e)=>setOrganizationSlug(e.target.value)} autoComplete="organization" required/></label>
            <label className="block text-sm text-slate-300">Email address<input className="mt-2 h-11 w-full rounded-lg border border-white/10 bg-slate-950/40 px-3 text-sm outline-none transition focus:border-cyan-400/60" type="email" value={email} onChange={(e)=>setEmail(e.target.value)} autoComplete="email" required/></label>
            <label className="block text-sm text-slate-300">Password<div className="relative mt-2"><input className="h-11 w-full rounded-lg border border-white/10 bg-slate-950/40 px-3 pr-10 text-sm outline-none transition focus:border-cyan-400/60" type={show?"text":"password"} value={password} onChange={(e)=>setPassword(e.target.value)} autoComplete="current-password" required/><button type="button" onClick={()=>setShow(!show)} className="absolute right-3 top-3 text-slate-500 hover:text-slate-300" aria-label={show?"Hide password":"Show password"}>{show?<EyeOff className="h-4 w-4"/>:<Eye className="h-4 w-4"/>}</button></div></label>
            {error && <div role="alert" className="rounded-lg border border-red-400/20 bg-red-400/[.07] p-3 text-sm text-red-300">{error}</div>}
            <Button className="w-full" size="lg" disabled={loading}>{loading?"Authenticating…":<>Open security console <ArrowRight className="h-4 w-4"/></>}</Button>
          </form>
          <div className="mt-8 flex items-start gap-3 rounded-lg border border-white/[.06] bg-white/[.025] p-4"><LockKeyhole className="mt-0.5 h-4 w-4 shrink-0 text-slate-500"/><p className="text-xs leading-5 text-slate-500">Use your organization credentials. Sessions use rotating refresh tokens and HTTP-only cookies.</p></div>
        </div>
      </section>
    </div>
  </main>;
}
