"use client";

import StatusBadge from "./StatusBadge";
import type { Finding } from "@/lib/types";

/**
 * The money shot: a route the team closed is walkable again. Deliberately loud — rose, oversized
 * label, and it sits above the stage rather than inside a panel where it could be scrolled past.
 */
export default function RegressionBanner({ finding }: { finding: Finding }) {
  const chain = [finding.route, finding.target].filter(Boolean).join("  →  ");
  const owner = finding.owning_app;
  const from = finding.deployed_from;
  return (
    <div
      id="regression-banner"
      role="status"
      aria-live="polite"
      className="flex items-start gap-3 rounded-2xl border border-rose-500/50 bg-rose-500/10 px-4 py-3 shadow-[0_0_35px_-12px_rgba(244,63,94,0.75)]"
    >
      <span aria-hidden className="mt-0.5 text-lg leading-none text-rose-300">
        ⚠
      </span>
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status="REGRESSED" size="lg" />
          <p className="text-sm font-semibold text-rose-100 sm:text-base">
            {finding.title ?? "A closed route is walkable again"}
          </p>
        </div>
        {chain && <p className="break-words font-mono text-[11px] text-rose-200/80">{chain}</p>}
        {/* Who owns the workload this route starts from (T3.4). Both fields are often null. */}
        {(owner || from) && (
          <p className="text-xs text-rose-200/80">
            {owner ? (
              <>
                Owned by <span className="font-medium text-rose-100">{owner}</span>
              </>
            ) : (
              "Owner unknown"
            )}
            {from ? (
              <>
                {owner ? ", " : " "}deployed from{" "}
                <span className="font-mono text-rose-100/90">{from}</span>
              </>
            ) : null}
            .
          </p>
        )}
        <p className="text-xs text-rose-200/70">
          {finding.previous_status
            ? `Was ${finding.previous_status} — reachable again in this snapshot.`
            : "Reachable again in this snapshot."}
          {finding.note ? ` ${finding.note}` : ""}
        </p>
      </div>
    </div>
  );
}
