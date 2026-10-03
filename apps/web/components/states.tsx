import { AlertTriangle, Inbox, LoaderCircle, RefreshCw } from "lucide-react";
import { Button } from "./ui/button";

export function PageSkeleton() {
  return <div className="space-y-4 animate-pulse"><div className="h-20 rounded-xl bg-white/[.04]"/><div className="grid gap-4 md:grid-cols-3">{[1,2,3].map((i)=><div key={i} className="h-36 rounded-xl bg-white/[.04]"/>)}</div><div className="h-80 rounded-xl bg-white/[.04]"/></div>;
}
export function LoadingState({ label = "Loading security data" }: { label?: string }) { return <div className="panel flex min-h-64 items-center justify-center gap-3 text-sm text-muted"><LoaderCircle className="h-5 w-5 animate-spin"/>{label}</div>; }
export function EmptyState({ title = "No security activity", description = "No records match the current view." }: { title?: string; description?: string }) { return <div className="panel flex min-h-64 flex-col items-center justify-center px-6 text-center"><Inbox className="mb-4 h-10 w-10 text-slate-600"/><h3 className="font-semibold">{title}</h3><p className="mt-2 max-w-md text-sm text-muted">{description}</p></div>; }
export function ErrorState({ message, retry }: { message: string; retry: () => void }) { return <div className="panel flex min-h-64 flex-col items-center justify-center px-6 text-center"><AlertTriangle className="mb-4 h-10 w-10 text-red-400"/><h3 className="font-semibold">Unable to load this view</h3><p className="mt-2 max-w-md text-sm text-muted">{message}</p><Button variant="outline" className="mt-5" onClick={retry}><RefreshCw className="h-4 w-4"/>Retry</Button></div>; }
