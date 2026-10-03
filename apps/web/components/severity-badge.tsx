import { AlertCircle, AlertTriangle, Info, ShieldAlert } from "lucide-react";
import type { Severity } from "@securewatch/shared";
import { cn } from "@/lib/utils";

const styles: Record<Severity, string> = {
  LOW: "border-sky-400/20 bg-sky-400/10 text-sky-300", INFORMATIONAL: "border-slate-400/20 bg-slate-400/10 text-slate-300",
  MEDIUM: "border-amber-400/20 bg-amber-400/10 text-amber-300", HIGH: "border-orange-400/20 bg-orange-400/10 text-orange-300",
  CRITICAL: "border-red-400/20 bg-red-400/10 text-red-300"
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const Icon = severity === "CRITICAL" ? ShieldAlert : severity === "HIGH" || severity === "MEDIUM" ? AlertTriangle : severity === "LOW" ? Info : AlertCircle;
  return <span className={cn("inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-[11px] font-semibold tracking-wide", styles[severity], className)}><Icon className="h-3 w-3" aria-hidden />{severity}</span>;
}
