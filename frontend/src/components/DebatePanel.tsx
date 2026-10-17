"use client";

import type { DebateTurn } from "@/lib/types";

/**
 * Two speaker bubbles — red attacker, blue defender — with per-side evidence
 * and a verdict line underneath. Rendered inline inside a chat turn when the
 * `red_blue_debate` tool emits a `debate` event; falls back silently to the
 * normal answer prose if the payload is missing.
 */
export default function DebatePanel({
  topic,
  red,
  blue,
  verdict,
  mode,
}: {
  topic?: string;
  red: DebateTurn;
  blue: DebateTurn;
  verdict?: string;
  mode?: string;
}) {
  return (
    <div className="mt-3 space-y-2 rounded-xl border border-white/10 bg-black/30 p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] uppercase tracking-wide text-white/40">
          red/blue debate{topic ? ` · ${topic}` : ""}
        </span>
        {mode && (
          <span className="font-mono text-[9px] text-white/30">
            {mode === "llm-voiced" ? "LLM-voiced" : "templated"}
          </span>
        )}
      </div>

      <Bubble turn={red} />
      <Bubble turn={blue} />

      {verdict && (
        <div className="mt-2 border-t border-white/10 pt-2">
          <span className="mr-1 font-mono text-[10px] uppercase tracking-wide text-emerald-300/80">
            verdict
          </span>
          <span className="text-[11px] leading-relaxed text-white/70">{verdict}</span>
        </div>
      )}
    </div>
  );
}

function Bubble({ turn }: { turn: DebateTurn }) {
  const isRed = turn.voice === "red";
  const palette = isRed
    ? { bg: "bg-rose-500/10", border: "border-rose-400/30", label: "text-rose-300", chip: "bg-rose-400/15 text-rose-200" }
    : { bg: "bg-cyan-500/10", border: "border-cyan-400/30", label: "text-cyan-300", chip: "bg-cyan-400/15 text-cyan-200" };

  const evidence = turn.evidence ?? {};
  const evidenceEntries = Object.entries(evidence).filter(
    ([, v]) => v !== null && v !== undefined && v !== "",
  );

  return (
    <div className={`rounded-lg border ${palette.border} ${palette.bg} p-2.5`}>
      <div className={`mb-1 font-mono text-[10px] uppercase tracking-wide ${palette.label}`}>
        {isRed ? "red · attacker" : "blue · defender"}
      </div>
      <p className="whitespace-pre-wrap text-[12px] leading-relaxed text-white/85">
        {turn.text}
      </p>
      {evidenceEntries.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {evidenceEntries.map(([k, v]) => (
            <span
              key={k}
              className={`rounded px-1.5 py-0.5 font-mono text-[9px] ${palette.chip}`}
              title={`${k}: ${formatEvidence(v)}`}
            >
              {k}: {formatEvidence(v)}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function formatEvidence(v: unknown): string {
  if (Array.isArray(v)) return v.length <= 3 ? v.join(" › ") : `${v.length} items`;
  if (typeof v === "object" && v !== null) return "{…}";
  const s = String(v);
  return s.length > 60 ? s.slice(0, 57) + "…" : s;
}
