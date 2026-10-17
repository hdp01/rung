"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import StatusBadge from "./StatusBadge";
import type { AskEvent, Finding, PathStep } from "@/lib/types";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

type Turn = {
  role: "user" | "assistant";
  text: string;
  tools: string[];
  citations: string[];
  done: boolean;
  /** Set when this answer is about a tracked finding. */
  status?: string;
  finding?: Finding;
  /** Kyverno ClusterPolicy YAML the agent proposed for this answer (W1.2). */
  proposed_policy?: string;
};

/**
 * Copy-to-clipboard for the proposed policy. `navigator.clipboard` is only available in a secure
 * context, so a failure leaves the label alone rather than pretending it copied.
 */
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          /* clipboard blocked (http on a non-localhost origin) — leave it */
        }
      }}
      aria-label="Copy proposed policy"
      className="rounded-md border border-white/10 bg-white/5 px-2 py-0.5 text-[10px] text-white/60 transition hover:border-cyan-400/40 hover:text-white"
    >
      {copied ? "copied ✓" : "copy"}
    </button>
  );
}

export default function Chat({
  tenant,
  onPath,
  onFinding,
}: {
  tenant?: string;
  onPath?: (steps: PathStep[]) => void;
  onFinding?: (finding: Finding | null) => void;
}) {
  const [turns, setTurns] = useState<Turn[]>([]);
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [turns]);

  const patchLast = (fn: (last: Turn) => Turn) =>
    setTurns((t) => t.map((turn, i) => (i === t.length - 1 ? fn(turn) : turn)));

  function handleEvent(ev: AskEvent) {
    switch (ev.type) {
      case "token": {
        const text = ev.text;
        patchLast((t) => ({ ...t, text: t.text + text }));
        break;
      }
      case "tool": {
        const name = ev.name;
        patchLast((t) => ({ ...t, tools: [...t.tools, name] }));
        break;
      }
      case "path":
        onPath?.(ev.steps);
        break;
      case "final": {
        const { answer, citations = [], status, finding, proposed_policy } = ev;
        patchLast((t) => ({
          ...t,
          text: t.text || answer,
          citations,
          status: status ?? finding?.status,
          finding,
          proposed_policy: proposed_policy ?? t.proposed_policy,
          done: true,
        }));
        // hand the finding up so the page can raise the regression banner
        onFinding?.(finding ?? (status ? { status } : null));
        break;
      }
    }
  }

  const SUGGESTIONS: string[] = [
    "Which pods can reach cluster-admin?",
    "ci-runner is compromised — what can it reach, grouped by namespace?",
    "What should I fix first for the highest leverage?",
    "Show me an attacker playbook for the highest-risk chain",
    "Run a red/blue debate over this cluster",
    "Is the cluster getting better or worse — show the trend",
  ];

  async function askText(q: string) {
    if (!q || busy) return;
    setQuestion("");
    setError(null);
    setBusy(true);
    onPath?.([]); // a new question starts with no chain; the answer lights one up if it has one
    onFinding?.(null); // and with no finding; the answer (or the tenant's list) supplies one
    setTurns((t) => [
      ...t,
      { role: "user", text: q, tools: [], citations: [], done: true },
      { role: "assistant", text: "", tools: [], citations: [], done: false },
    ]);

    try {
      const res = await fetch(`${API}/ask`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ question: q, tenant }),
      });
      if (!res.ok || !res.body) {
        const detail = await res.text();
        throw new Error(detail || `ask failed (${res.status})`);
      }

      // SSE: events arrive as `data: {json}` lines, possibly split across chunks.
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data:")) continue;
          const raw = line.slice(5).trim();
          if (!raw) continue;
          let event: AskEvent;
          try {
            event = JSON.parse(raw) as AskEvent;
          } catch {
            continue;
          }
          handleEvent(event);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "ask failed");
    } finally {
      setBusy(false);
      setTurns((t) => t.map((turn) => ({ ...turn, done: true })));
    }
  }

  async function ask(e: FormEvent) {
    e.preventDefault();
    await askText(question.trim());
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex-1 space-y-3 overflow-y-auto p-4">
        {turns.length === 0 && (
          <div className="space-y-3">
            <p className="text-sm text-white/40">
              Ask about the cluster, or try one of these:
            </p>
            <div className="flex flex-col gap-2">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => askText(s)}
                  disabled={busy}
                  className="group rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-left text-xs text-white/70 transition hover:border-cyan-400/40 hover:bg-cyan-400/5 hover:text-white disabled:opacity-40"
                >
                  <span className="mr-2 font-mono text-[10px] text-cyan-300/70 group-hover:text-cyan-300">
                    ask →
                  </span>
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}
        {turns.map((turn, i) => (
          <div key={i} className={turn.role === "user" ? "flex justify-end" : "flex justify-start"}>
            <div
              className={`max-w-[85%] rounded-2xl px-4 py-2.5 text-sm leading-relaxed ${
                turn.role === "user"
                  ? "bg-indigo-500/80 text-white"
                  : "glass text-white/80"
              }`}
            >
              {turn.tools.length > 0 && (
                <div className="mb-2 flex flex-wrap gap-1.5">
                  {turn.tools.map((name, ti) => (
                    <span
                      key={`${name}-${ti}`}
                      className="rounded-full bg-black/40 px-2 py-0.5 font-mono text-[10px] text-cyan-300"
                    >
                      tool: {name}
                    </span>
                  ))}
                </div>
              )}
              <p className="whitespace-pre-wrap">
                {turn.text}
                {turn.role === "assistant" && !turn.done && (
                  <span className="ml-0.5 inline-block h-3.5 w-1.5 animate-pulse bg-cyan-300 align-middle" />
                )}
              </p>
              {turn.status && (
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <StatusBadge status={turn.status} />
                  {turn.finding?.target && (
                    <span className="font-mono text-[10px] text-white/40">
                      {turn.finding.target}
                    </span>
                  )}
                </div>
              )}
              {turn.citations.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5 border-t border-white/10 pt-2">
                  {turn.citations.map((c) => (
                    <span key={c} className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-white/50">
                      {c}
                    </span>
                  ))}
                </div>
              )}
              {turn.proposed_policy && (
                <div className="mt-2 border-t border-white/10 pt-2">
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <span className="text-[10px] uppercase tracking-wide text-white/40">
                      proposed policy
                    </span>
                    <CopyButton text={turn.proposed_policy} />
                  </div>
                  <pre className="max-h-72 overflow-auto rounded-lg border border-white/10 bg-black/50 p-2.5 text-[10px] leading-relaxed text-cyan-100">
                    {turn.proposed_policy}
                  </pre>
                </div>
              )}
            </div>
          </div>
        ))}
        <div ref={endRef} />
      </div>

      {error && <p className="px-4 pb-2 text-xs text-rose-300">{error}</p>}

      <form onSubmit={ask} className="flex gap-2 border-t border-white/10 p-3">
        <input
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="ask…"
          aria-label="Ask about the cluster"
          className="flex-1 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm outline-none placeholder:text-white/30 focus:border-indigo-400/50"
        />
        <button
          type="submit"
          disabled={busy || question.trim() === ""}
          className="rounded-xl bg-gradient-to-r from-indigo-500 to-cyan-400 px-4 py-2 text-sm font-semibold text-white disabled:opacity-40"
        >
          {busy ? "…" : "send"}
        </button>
      </form>
    </div>
  );
}
