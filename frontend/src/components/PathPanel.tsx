"use client";

import type { ElementSelection, PathStep } from "@/lib/types";

const CONFIDENCE_STYLE: Record<string, string> = {
  high: "bg-emerald-400/15 text-emerald-300",
  medium: "bg-amber-400/15 text-amber-300",
  low: "bg-rose-400/15 text-rose-300",
};

function Confidence({ value }: { value?: string }) {
  if (!value) return null;
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
        CONFIDENCE_STYLE[value] ?? "bg-white/10 text-white/60"
      }`}
    >
      {value} confidence
    </span>
  );
}

/**
 * The ATT&CK technique for a hop, with its CIS section when the technique has one.
 *
 * The backend nests the technique under `mitre` and publishes `cis_section` as a sibling that
 * already reads "CIS Kubernetes Benchmark §5.2 (…)" — so the raw value is shown, not "CIS " + it.
 */
function MitreLine({
  mitre,
  cisSection,
}: {
  mitre?: { id: string; name: string; url?: string } | null;
  cisSection?: string | null;
}) {
  if (!mitre && !cisSection) return null;
  return (
    <p className="text-[11px] leading-snug text-white/60">
      <span className="text-white/40">MITRE: </span>
      {mitre ? (
        <>
          {mitre.url ? (
            <a
              href={mitre.url}
              target="_blank"
              rel="noreferrer"
              className="text-cyan-300 underline decoration-dotted underline-offset-2 hover:text-cyan-200"
            >
              {mitre.id}
            </a>
          ) : (
            <span className="text-cyan-300">{mitre.id}</span>
          )}{" "}
          {mitre.name}
        </>
      ) : (
        <span className="text-white/40">—</span>
      )}
      {cisSection ? <span className="text-white/40"> · {cisSection}</span> : null}
    </p>
  );
}

function Detail({ selection, steps }: { selection: ElementSelection; steps: PathStep[] }) {
  if (selection.type === "node") {
    const props = Object.entries(selection.props);
    return (
      <div className="space-y-2">
        <p className="font-mono text-[11px] text-white/50">{selection.id}</p>
        <p className="text-sm font-semibold">{selection.kind}</p>
        {props.length > 0 && (
          <dl className="space-y-1">
            {props.map(([k, v]) => (
              <div key={k} className="flex gap-2 text-[11px]">
                <dt className="w-24 shrink-0 text-white/40">{k}</dt>
                <dd className="break-all text-white/70">
                  {Array.isArray(v) ? v.join(", ") : String(v)}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </div>
    );
  }

  const step = steps.find(
    (s) => s.from === selection.source && s.to === selection.target && s.edge === selection.edgeType,
  );

  return (
    <div className="space-y-2">
      <p className="font-mono text-[11px] text-cyan-300">{selection.edgeType}</p>
      <p className="text-[11px] text-white/60">
        {selection.source} <span className="text-white/30">→</span> {selection.target}
      </p>
      <span
        className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-medium ${
          selection.attackPath ? "bg-cyan-400/15 text-cyan-300" : "bg-white/10 text-white/60"
        }`}
      >
        {selection.attackPath ? "attack step" : "display only — never an attack step"}
      </span>
      {step?.why && <p className="text-[11px] leading-snug text-white/60">{step.why}</p>}
      <MitreLine
        mitre={selection.mitre ?? step?.mitre ?? null}
        cisSection={selection.cisSection ?? step?.cis_section ?? null}
      />
      <Confidence value={step?.confidence} />
    </div>
  );
}

export default function PathPanel({
  steps,
  selection,
  onSelectEdge,
}: {
  steps: PathStep[];
  selection: ElementSelection | null;
  onSelectEdge?: (step: PathStep) => void;
}) {
  return (
    <aside className="glass flex h-full flex-col gap-4 overflow-y-auto rounded-3xl p-4">
      <div>
        <div className="flex items-baseline justify-between">
          <h4 className="text-xs uppercase tracking-wide text-white/40">The chain</h4>
          <span className="text-[10px] text-white/30">
            {steps.length} {steps.length === 1 ? "step" : "steps"}
          </span>
        </div>
        {steps.length === 0 ? (
          <p className="mt-2 text-[11px] leading-snug text-white/40">
            Ask a question — the path the agent walks lights up on the graph, and every hop explains
            itself here.
          </p>
        ) : (
          <ol className="mt-3 space-y-2">
            {steps.map((s, i) => {
              const active =
                selection?.type === "edge" &&
                selection.source === s.from &&
                selection.target === s.to &&
                selection.edgeType === s.edge;
              return (
                <li key={`${s.from}-${s.edge}-${s.to}-${i}`}>
                  <button
                    type="button"
                    onClick={() => onSelectEdge?.(s)}
                    className={`w-full rounded-xl border p-2.5 text-left transition ${
                      active
                        ? "border-cyan-400/60 bg-cyan-400/10"
                        : "border-white/10 bg-white/5 hover:border-cyan-400/40"
                    }`}
                  >
                    <span className="font-mono text-[10px] text-cyan-300">
                      {i + 1}. {s.edge}
                    </span>
                    <span className="mt-1 block truncate text-[11px] text-white/60">{s.to}</span>
                    {s.why && (
                      <span className="mt-1 block text-[10px] leading-snug text-white/40">
                        {s.why}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ol>
        )}
      </div>

      {selection && (
        <div className="border-t border-white/10 pt-4">
          <h4 className="mb-2 text-xs uppercase tracking-wide text-white/40">
            {selection.type === "node" ? "Node" : "Why this edge exists"}
          </h4>
          <Detail selection={selection} steps={steps} />
        </div>
      )}
    </aside>
  );
}
