"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { io, type Socket } from "socket.io-client";
import { AppWindow, Bell, ChevronDown, CircleUserRound, FileClock, Menu, Radar, Search, Users, Wifi, WifiOff, X } from "lucide-react";
import { API_URL, api, getAccessToken, refreshAccessToken, setAccessToken } from "@/lib/api";
import { cn } from "@/lib/utils";
import { PageSkeleton } from "./states";

const navigation = [
  ["Applications", "/dashboard/applications", AppWindow],
  ["Users", "/dashboard/users", Users],
  ["Audit Logs", "/dashboard/audit", FileClock]
] as const;

interface Me { id: string; name: string; email: string; role: string; organization: { name: string; slug: string } }

export function DashboardShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname(); const router = useRouter();
  const [me, setMe] = useState<Me | null>(null); const [loading, setLoading] = useState(true); const [mobile, setMobile] = useState(false);
  const [connected, setConnected] = useState(false); const [unread, setUnread] = useState(0);
  useEffect(() => {
    let active = true; let socket: Socket | undefined;
    const start = async () => {
      try {
        let user: Me;
        try { user = await api<Me>("/api/v1/auth/me"); }
        catch { if (!(await refreshAccessToken())) throw new Error("Session expired"); user = await api<Me>("/api/v1/auth/me"); }
        if (!active) return; setMe(user);
        const notifications = await api<{ unread: number }>("/api/v1/notifications").catch(() => ({ unread: 0 }));
        if (active) setUnread(notifications.unread);
        socket = io(API_URL, { auth: { token: getAccessToken() }, transports: ["websocket", "polling"] });
        socket.on("connect", () => setConnected(true)); socket.on("disconnect", () => setConnected(false));
        socket.on("alert.created", () => setUnread((value) => value + 1));
      } catch { setAccessToken(null); router.replace("/login"); }
      finally { if (active) setLoading(false); }
    };
    void start(); return () => { active = false; socket?.disconnect(); };
  }, [router]);
  if (loading) return <main className="p-8"><PageSkeleton/></main>;
  if (!me) return null;
  return <div className="min-h-screen lg:grid lg:grid-cols-[248px_1fr]">
    {mobile && <button className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={()=>setMobile(false)} aria-label="Close navigation"/>}
    <aside className={cn("fixed inset-y-0 left-0 z-50 flex w-[248px] flex-col border-r border-white/[.06] bg-[#090f19]/98 transition-transform lg:sticky lg:top-0 lg:h-screen lg:translate-x-0", mobile?"translate-x-0":"-translate-x-full")}>
      <div className="flex h-20 items-center justify-between border-b border-white/[.06] px-5"><Link href="/dashboard" className="flex items-center gap-3"><div className="grid h-9 w-9 place-items-center rounded-lg border border-cyan-300/20 bg-cyan-300/10"><Radar className="h-5 w-5 text-cyan-300"/></div><div><p className="text-sm font-semibold tracking-wide">SecureWatch</p><p className="text-[10px] uppercase tracking-[.18em] text-slate-500">Security Ops</p></div></Link><button className="lg:hidden" onClick={()=>setMobile(false)}><X className="h-5 w-5"/></button></div>
      <nav className="scrollbar-thin flex-1 overflow-y-auto px-3 py-5"><p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[.18em] text-slate-600">Workspace</p><div className="space-y-1">{navigation.filter(([label]) => label !== "Users" || me.role !== "VIEWER").filter(([label]) => label !== "Audit Logs" || me.role === "SUPER_ADMIN").map(([label,href,Icon])=>{const active=pathname.startsWith(href);return <Link key={href} href={href} onClick={()=>setMobile(false)} className={cn("flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition",active?"bg-cyan-300/[.09] text-cyan-200":"text-slate-400 hover:bg-white/[.04] hover:text-slate-200")}><Icon className={cn("h-[17px] w-[17px]",active?"text-cyan-300":"text-slate-500")}/>{label}</Link>})}</div></nav>
      <div className="border-t border-white/[.06] p-4"><div className="flex items-center gap-3 rounded-lg bg-white/[.025] p-3"><div className="grid h-8 w-8 place-items-center rounded-full bg-slate-700 text-xs font-semibold">{me.name.split(" ").map((v)=>v[0]).slice(0,2).join("")}</div><div className="min-w-0 flex-1"><p className="truncate text-xs font-medium">{me.name}</p><p className="truncate text-[10px] text-slate-500">{me.role.replaceAll("_"," ")}</p></div><ChevronDown className="h-4 w-4 text-slate-600"/></div></div>
    </aside>
    <div className="min-w-0">
      <header className="sticky top-0 z-30 flex h-20 items-center gap-4 border-b border-white/[.06] bg-[#080e18]/85 px-5 backdrop-blur-xl lg:px-8"><button className="lg:hidden" onClick={()=>setMobile(true)}><Menu className="h-5 w-5"/></button><div className="hidden items-center gap-2 text-sm sm:flex"><span className="text-slate-500">Workspace</span><span className="text-slate-700">/</span><span className="font-medium">{me.organization.name}</span></div><div className="ml-auto flex items-center gap-2 sm:gap-4"><button className="hidden h-9 w-64 items-center gap-2 rounded-lg border border-white/[.07] bg-white/[.025] px-3 text-xs text-slate-500 md:flex"><Search className="h-4 w-4"/>Search events, IPs, users <kbd className="ml-auto text-[10px]">⌘ K</kbd></button><div className={cn("flex items-center gap-2 rounded-full border px-2.5 py-1.5 text-[11px]",connected?"border-emerald-400/15 bg-emerald-400/[.06] text-emerald-300":"border-amber-400/15 bg-amber-400/[.06] text-amber-300")}>{connected?<Wifi className="h-3 w-3"/>:<WifiOff className="h-3 w-3"/>}<span className="hidden sm:inline">{connected?"Live":"Reconnecting"}</span></div><Link href="/dashboard/notifications" className="relative grid h-9 w-9 place-items-center rounded-lg border border-white/[.07] bg-white/[.025]"><Bell className="h-4 w-4 text-slate-400"/>{unread>0&&<span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-red-400"/>}</Link><CircleUserRound className="h-7 w-7 text-slate-500"/></div></header>
      <main className="mx-auto max-w-[1600px] p-5 lg:p-8">{children}</main>
    </div>
  </div>;
}
