export function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description: string; action?: React.ReactNode }) {
  return <header className="mb-7 flex flex-col justify-between gap-4 sm:flex-row sm:items-end"><div>{eyebrow&&<p className="mb-2 text-[10px] font-semibold uppercase tracking-[.22em] text-cyan-300">{eyebrow}</p>}<h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h1><p className="mt-2 max-w-2xl text-sm text-slate-400">{description}</p></div>{action}</header>;
}
