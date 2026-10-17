"use client";

import StatusBadge from "./StatusBadge";
import type { Finding } from "@/lib/types";

/** What the regression detector knows about this tenant — one row per tracked route, badges visible. */
export default function FindingsPanel({ findings }: { findings: Finding[] }) {
  return (
    <section className="glass space-y-3 rounded-3xl p-4">
      <div className="flex items-baseline justify-between">
        <h3 className="text-xs font-medium uppercase tracking-wide text-white/50">Findings</h3>
        <span className="font-mono text-[10px] text-white/30">{findings.length}</span>
      </div>

      {findings.length === 0 ? (
        <p className="text-xs text-white/40">The detector reports nothing for this tenant.</p>
      ) : (
        <ul className="space-y-2">
          {findings.map((f, i) => (
            <li
              key={f.id ?? i}
              className={`rounded-2xl border px-3 py-2 ${
                f.status === "REGRESSED"
                  ? "border-rose-500/40 bg-rose-500/5"
                  : "border-white/10 bg-white/5"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <StatusBadge status={f.status} />
                {f.previous_status && (
                  <span className="text-[10px] text-white/40">was {f.previous_status}</span>
                )}
              </div>
              {(f.title || f.target) && (
                <p className="mt-1.5 text-sm leading-snug text-white/80">
                  {f.title ?? f.target}
                </p>
              )}
              {(f.route || f.target) && (
                <p className="mt-0.5 break-words font-mono text-[10px] text-white/40">
                  {[f.route, f.target].filter(Boolean).join(" → ")}
                </p>
              )}
              {f.note && <p className="mt-1 text-[11px] text-white/50">{f.note}</p>}
              {(f.owning_app || f.deployed_from) && (
                <p className="mt-1 text-[10px] text-white/40">
                  {f.owning_app ? `owned by ${f.owning_app}` : "owner unknown"}
                  {f.deployed_from ? ` · deployed from ${f.deployed_from}` : ""}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
