"use client";

import type { Compare } from "@/lib/types";

const fmt = (n: number) => n.toLocaleString("en-US");

function Bar({ value, max, tone }: { value: number; max: number; tone: "naive" | "rung" }) {
  const pct = max > 0 && value > 0 ? Math.max(3, Math.round((value / max) * 100)) : 0;
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-white/10">
      <div
        className={`h-full rounded-full ${
          tone === "naive" ? "bg-rose-400/80" : "bg-emerald-400/90"
        }`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

function Column({
  tone,
  label,
  blurb,
  reachable,
  tokenEdges,
  total,
}: {
  tone: "naive" | "rung";
  label: string;
  blurb: string;
  reachable: number;
  tokenEdges: number;
  total: number;
}) {
  const naive = tone === "naive";
  return (
    <div
      className={`rounded-2xl border p-4 ${
        naive ? "border-rose-400/25 bg-rose-500/5" : "border-emerald-400/25 bg-emerald-500/5"
      }`}
    >
      <div className="flex items-baseline justify-between gap-3">
        <h4 className={`text-sm font-semibold ${naive ? "text-rose-200" : "text-emerald-200"}`}>
          {label}
        </h4>
        <span className="text-[10px] uppercase tracking-wide text-white/40">
          {naive ? "other tools" : "rung"}
        </span>
      </div>
      <p className="mt-1 text-[11px] leading-snug text-white/45">{blurb}</p>

      <p className="mt-3 text-3xl font-bold tabular-nums">
        {fmt(reachable)}
        {total > 0 && <span className="ml-1 text-sm font-medium text-white/40">of {fmt(total)}</span>}
      </p>
      <p className="text-[11px] text-white/45">workloads reach cluster-admin</p>
      <div className="mt-2">
        <Bar value={reachable} max={total} tone={tone} />
      </div>

      <p className="mt-3 text-lg font-semibold tabular-nums">{fmt(tokenEdges)}</p>
      <p className="text-[11px] text-white/45">TOKEN_LIST edges assumed</p>
    </div>
  );
}

export default function ComparePanel({ compare }: { compare: Compare | null }) {
  if (!compare) {
    return (
      <section className="glass space-y-1 rounded-3xl p-5">
        <h3 className="text-lg font-semibold">Why a graph, done right</h3>
        <p className="text-xs text-white/40">
          Waiting on <span className="font-mono">/compare</span> — the count of this graph taken
          naively and precondition-gated.
        </p>
      </section>
    );
  }

  const {
    naive_reachable,
    rung_reachable,
    naive_token_list_edges,
    rung_token_list_edges,
  } = compare;
  // Naive counts every workload as reachable, so it is also the denominator of the question.
  const total = naive_reachable;
  const blocked = Math.max(0, naive_token_list_edges - rung_token_list_edges);

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <h3 className="text-lg font-semibold">Why a graph, done right</h3>
        <span className="text-xs text-white/40">same graph, two answers</span>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <Column
          tone="naive"
          label="Every permission is a capability"
          blurb="Ignore the preconditions and let each grant do what it looks like it can do."
          reachable={naive_reachable}
          tokenEdges={naive_token_list_edges}
          total={total}
        />
        <Column
          tone="rung"
          label="Preconditions checked"
          blurb="An edge exists only when the cluster fact that justifies it is present."
          reachable={rung_reachable}
          tokenEdges={rung_token_list_edges}
          total={total}
        />
      </div>

      <p className="text-xs text-white/45">
        The gap is <span className="font-semibold text-white/70">{fmt(blocked)}</span> assumed
        TOKEN_LIST edges the cluster&rsquo;s controls never allow — PSA on pod create, projected
        Secrets, <span className="font-mono text-white/60">bind</span> on role binding, and{" "}
        <span className="font-mono text-white/60">hostPID</span> for a node escape.
      </p>
    </section>
  );
}
