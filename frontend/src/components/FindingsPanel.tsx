"use client";

import { useMemo, useState } from "react";
import StatusBadge from "./StatusBadge";
import type { Finding, Mitre } from "@/lib/types";

/**
 * The regression detector's tracked routes. Grouped by status, filterable, sorted by severity
 * score within each group — so a judge opening the panel on a cluster with 73 findings doesn't
 * see a wall of NEW rows but can zoom in on what matters (REGRESSED → critical NEW → high NEW).
 */
type Filter = "all" | "REGRESSED" | "NEW" | "ACCEPTED" | "RESOLVED";

const STATUS_ORDER: Finding["status"][] = ["REGRESSED", "NEW", "ACCEPTED", "RESOLVED"];
const FILTERS: { key: Filter; label: string }[] = [
  { key: "all", label: "all" },
  { key: "REGRESSED", label: "regressed" },
  { key: "NEW", label: "new" },
  { key: "ACCEPTED", label: "accepted" },
  { key: "RESOLVED", label: "resolved" },
];

const SEV_COLORS: Record<string, string> = {
  critical: "bg-rose-500/20 text-rose-200 border-rose-500/40",
  high: "bg-amber-500/20 text-amber-200 border-amber-500/40",
  medium: "bg-cyan-500/20 text-cyan-200 border-cyan-500/40",
  low: "bg-white/10 text-white/60 border-white/15",
};

export default function FindingsPanel({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState<Filter>("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  const { counts, filtered, groups } = useMemo(() => {
    const counts: Record<string, number> = { all: findings.length };
    for (const f of findings) counts[f.status] = (counts[f.status] ?? 0) + 1;

    const filtered = filter === "all" ? findings : findings.filter((f) => f.status === filter);

    // group by status in the desired order, sort each group by score desc
    const groups: { status: string; items: Finding[] }[] = [];
    for (const status of STATUS_ORDER) {
      const items = filtered
        .filter((f) => f.status === status)
        .sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
      if (items.length) groups.push({ status, items });
    }
    return { counts, filtered, groups };
  }, [findings, filter]);

  return (
    <section className="glass flex max-h-[60vh] flex-col rounded-3xl p-4">
      <div className="mb-3 flex items-baseline justify-between">
        <h3 className="text-xs font-medium uppercase tracking-wide text-white/50">Findings</h3>
        <span className="font-mono text-[10px] text-white/30">
          {filtered.length}
          {filtered.length !== findings.length ? ` / ${findings.length}` : ""}
        </span>
      </div>

      {/* filter chips — stay fixed, don't scroll with the list */}
      <div className="mb-3 flex flex-wrap gap-1.5">
        {FILTERS.map(({ key, label }) => {
          const count = counts[key] ?? 0;
          const active = filter === key;
          const dim = count === 0 && key !== "all";
          return (
            <button
              key={key}
              onClick={() => setFilter(key)}
              disabled={dim}
              className={`rounded-full border px-2.5 py-0.5 text-[10px] font-medium uppercase tracking-wide transition
                ${active
                  ? "border-cyan-400/60 bg-cyan-400/10 text-cyan-200"
                  : dim
                    ? "border-white/10 text-white/20"
                    : "border-white/10 text-white/50 hover:border-white/25 hover:text-white/70"}`}
            >
              {label} <span className="ml-1 opacity-60">{count}</span>
            </button>
          );
        })}
      </div>

      {filtered.length === 0 ? (
        <p className="text-xs text-white/40">
          {findings.length === 0
            ? "The detector reports nothing for this tenant."
            : `No ${filter.toLowerCase()} findings — try another filter.`}
        </p>
      ) : (
        <div className="scroll-y fade-bottom -mr-2 flex-1 space-y-3 pr-2">
          {groups.map((group) => (
            <div key={group.status} className="space-y-2">
              <div className="flex items-center gap-2 text-[10px] uppercase tracking-wide text-white/40">
                <span>{group.status}</span>
                <span className="font-mono">{group.items.length}</span>
                <span className="h-px flex-1 bg-white/10" />
              </div>
              <ul className="space-y-1.5">
                {group.items.map((f, i) => (
                  <FindingRow
                    key={f.id ?? `${group.status}-${i}`}
                    f={f}
                    expanded={expanded === (f.id ?? `${group.status}-${i}`)}
                    onToggle={() =>
                      setExpanded(
                        expanded === (f.id ?? `${group.status}-${i}`)
                          ? null
                          : (f.id ?? `${group.status}-${i}`),
                      )
                    }
                  />
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function FindingRow({
  f,
  expanded,
  onToggle,
}: {
  f: Finding;
  expanded: boolean;
  onToggle: () => void;
}) {
  const sevClass = SEV_COLORS[f.severity ?? "medium"] ?? SEV_COLORS.medium;
  const title = f.title ?? f.target ?? "(no title)";
  const isRegressed = f.status === "REGRESSED";
  const mitre: Mitre[] = Array.isArray(f.mitre) ? f.mitre : [];

  return (
    <li
      className={`overflow-hidden rounded-xl border transition ${
        isRegressed
          ? "border-rose-500/40 bg-rose-500/5"
          : "border-white/10 bg-white/5 hover:border-white/20"
      }`}
    >
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-start gap-2 px-3 py-2 text-left"
        aria-expanded={expanded}
      >
        <span className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase ${sevClass}`}>
          {f.severity ?? "med"} {typeof f.score === "number" ? `· ${f.score.toFixed(1)}` : ""}
        </span>
        <div className="flex-1 min-w-0">
          <p className="truncate text-xs leading-snug text-white/85">{title}</p>
          {f.target && f.target !== title && (
            <p className="truncate font-mono text-[10px] text-white/40">→ {f.target}</p>
          )}
        </div>
        <StatusBadge status={f.status} />
      </button>

      {expanded && (
        <div className="space-y-2 border-t border-white/10 bg-black/20 px-3 py-2.5">
          {f.route && (
            <div>
              <div className="mb-0.5 text-[9px] uppercase tracking-wide text-white/40">chain</div>
              <code className="block break-words font-mono text-[10px] text-cyan-200/90">{f.route}</code>
            </div>
          )}
          {mitre.length > 0 && (
            <div>
              <div className="mb-1 text-[9px] uppercase tracking-wide text-white/40">MITRE ATT&amp;CK</div>
              <div className="flex flex-wrap gap-1">
                {mitre.map((m) => (
                  <a
                    key={m.id}
                    href={m.url || `https://attack.mitre.org/techniques/${m.id}/`}
                    target="_blank"
                    rel="noreferrer"
                    className="rounded border border-fuchsia-400/30 bg-fuchsia-500/10 px-1.5 py-0.5 font-mono text-[9px] text-fuchsia-200 hover:bg-fuchsia-500/20"
                    title={m.tactic ? `${m.name} · ${m.tactic}` : m.name}
                  >
                    {m.id} · {m.name}
                  </a>
                ))}
              </div>
            </div>
          )}
          {f.previous_status && (
            <div className="text-[10px] text-white/50">
              previous status: <span className="font-mono text-white/70">{f.previous_status}</span>
            </div>
          )}
          {(f.owning_app || f.deployed_from) && (
            <div className="text-[10px] text-white/50">
              {f.owning_app ? (
                <>
                  owned by <span className="font-mono text-white/70">{f.owning_app}</span>
                </>
              ) : (
                "owner unknown"
              )}
              {f.deployed_from ? (
                <>
                  {" "}
                  · deployed from <span className="font-mono text-white/70">{f.deployed_from}</span>
                </>
              ) : null}
            </div>
          )}
          {f.first_seen && (
            <div className="text-[10px] text-white/40">
              first seen {f.first_seen}
              {f.last_seen && f.last_seen !== f.first_seen ? ` · last seen ${f.last_seen}` : ""}
            </div>
          )}
          {f.note && !f.route && <p className="text-[11px] text-white/60">{f.note}</p>}
        </div>
      )}
    </li>
  );
}
