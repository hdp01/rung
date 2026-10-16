"use client";

import { FINDING_STATUSES, type FindingStatus } from "@/lib/types";

/**
 * Colours are the detector's own vocabulary, not graph semantics: emerald closed, amber accepted,
 * rose for the one that must not be missed. An unknown status stays neutral rather than guessing.
 */
const STYLE: Record<FindingStatus, string> = {
  NEW: "bg-sky-500/15 text-sky-200 ring-sky-400/40",
  RESOLVED: "bg-emerald-500/15 text-emerald-200 ring-emerald-400/40",
  ACCEPTED: "bg-amber-500/15 text-amber-200 ring-amber-400/40",
  REGRESSED: "bg-rose-500/25 text-rose-200 ring-rose-400/60",
};
const GLYPH: Record<FindingStatus, string> = {
  NEW: "+",
  RESOLVED: "✓",
  ACCEPTED: "≈",
  REGRESSED: "!",
};
const UNKNOWN = "bg-white/10 text-white/60 ring-white/20";

const known = (status: string): status is FindingStatus =>
  (FINDING_STATUSES as readonly string[]).includes(status);

export default function StatusBadge({
  status,
  size = "sm",
}: {
  status: string;
  size?: "sm" | "lg";
}) {
  return (
    <span
      aria-label={`finding status: ${status}`}
      className={`inline-flex shrink-0 items-center gap-1 rounded-full font-semibold uppercase tracking-wide ring-1 ${
        size === "lg" ? "px-2.5 py-1 text-xs" : "px-2 py-0.5 text-[10px]"
      } ${known(status) ? STYLE[status] : UNKNOWN} ${
        status === "REGRESSED" ? "animate-pulse" : ""
      }`}
    >
      <span aria-hidden className="leading-none">
        {known(status) ? GLYPH[status] : "•"}
      </span>
      {status}
    </span>
  );
}
