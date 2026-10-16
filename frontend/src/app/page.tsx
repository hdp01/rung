"use client";

import { ChangeEvent, FormEvent, useEffect, useState } from "react";
import dynamic from "next/dynamic";
import type { Graph, Health, Stats } from "@/lib/types";

// Cytoscape touches window/document — keep it out of SSR (see next/dynamic docs).
const GraphView = dynamic(() => import("@/components/GraphView"), {
  ssr: false,
  loading: () => <p className="text-sm text-white/40">Loading graph…</p>,
});

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function Home() {
  const [health, setHealth] = useState<Health | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      const h = await fetch(`${API}/health`);
      setHealth(await h.json());
      const s = await fetch(`${API}/stats`);
      setStats(await s.json());
      const g = await fetch(`${API}/graph`);
      if (g.ok) setGraph(await g.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "backend unreachable");
    }
  }

  useEffect(() => {
    // Initial load: the snapshot of backend state is fetched from outside React
    // (not derived from render), so setting it here is intended.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refresh();
  }, []);

  async function onUpload(e: FormEvent) {
    e.preventDefault();
    if (!file) return;
    setUploading(true);
    setMessage(null);
    setError(null);
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await fetch(`${API}/ingest`, { method: "POST", body: form });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "ingest failed");
      setMessage(`Ingested: ${JSON.stringify(data.counts)}`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "upload failed");
    } finally {
      setUploading(false);
    }
  }

  const online = health?.falkordb === "connected";

  return (
    <main className="min-h-screen px-6 py-10 md:px-12">
      <div className="mx-auto max-w-6xl space-y-8">
        {/* Top bar */}
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-2xl bg-gradient-to-br from-indigo-500 via-fuchsia-500 to-cyan-400 glow float" />
            <div>
              <h1 className="text-2xl font-bold tracking-tight">
                Rung <span className="text-white/40">/ graph atlas</span>
              </h1>
              <p className="text-xs text-white/50">Kubernetes privilege-escalation, made visible</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span
              className={`flex items-center gap-2 rounded-full px-4 py-2 text-xs font-medium glass ${
                online ? "text-emerald-300" : "text-rose-300"
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${online ? "bg-emerald-400 animate-pulse" : "bg-rose-400"}`}
              />
              FalkorDB {online ? "connected" : "offline"}
            </span>
            <button
              onClick={refresh}
              className="rounded-full glass px-4 py-2 text-xs text-white/70 hover:text-white"
            >
              Refresh
            </button>
          </div>
        </header>

        {/* Hero */}
        <section className="glass rounded-3xl p-8 md:p-12">
          <div className="grid gap-8 md:grid-cols-2 md:items-center">
            <div>
              <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-indigo-400/30 bg-indigo-400/10 px-3 py-1 text-xs text-indigo-300">
                <span className="h-1.5 w-1.5 rounded-full bg-indigo-400" />
                live graph
              </div>
              <h2 className="text-4xl font-extrabold leading-tight md:text-5xl">
                See the chains
                <span className="block bg-gradient-to-r from-indigo-400 via-fuchsia-400 to-cyan-300 bg-clip-text text-transparent">
                  nobody reviews.
                </span>
              </h2>
              <p className="mt-4 max-w-md text-sm leading-relaxed text-white/60">
                Load a cluster snapshot into FalkorDB and watch entities, permissions and attack
                paths resolve into a traversable graph. Upload a snapshot to get started.
              </p>
            </div>
            <form onSubmit={onUpload} className="space-y-4 rounded-2xl glass p-6">
              <label className="block text-xs font-medium uppercase tracking-wide text-white/50">
                snapshot.json
              </label>
              <input
                type="file"
                accept="application/json,.json"
                onChange={(e: ChangeEvent<HTMLInputElement>) => setFile(e.target.files?.[0] ?? null)}
                className="block w-full cursor-pointer rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm file:mr-3 file:rounded-md file:border-0 file:bg-indigo-500 file:px-3 file:py-1.5 file:text-xs file:font-semibold file:text-white"
              />
              <button
                type="submit"
                disabled={!file || uploading}
                className="w-full rounded-xl bg-gradient-to-r from-indigo-500 via-fuchsia-500 to-cyan-400 px-4 py-3 text-sm font-semibold text-white shadow-lg transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {uploading ? "Ingesting…" : "Upload & ingest"}
              </button>
              {message && <p className="text-xs text-emerald-300 break-all">{message}</p>}
              {error && <p className="text-xs text-rose-300 break-all">{error}</p>}
            </form>
          </div>
        </section>

        {/* Graph pane */}
        <section className="space-y-3">
          <div className="flex items-end justify-between">
            <h3 className="text-lg font-semibold">Attack surface</h3>
            <span className="text-xs text-white/40">
              {graph ? `${graph.nodes.length} nodes · ${graph.edges.length} edges` : ""}
            </span>
          </div>
          <div className="glass h-[62vh] min-h-[360px] overflow-hidden rounded-3xl">
            <GraphView graph={graph} />
          </div>
        </section>

        {/* Stats */}
        <section className="space-y-3">
          <div className="flex items-end justify-between">
            <h3 className="text-lg font-semibold">Graph composition</h3>
            <span className="text-xs text-white/40">{health?.graph}</span>
          </div>
          {stats ? (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4">
              {Object.entries(stats).map(([k, v]) => (
                <div key={k} className="glass rounded-2xl p-4 transition hover:scale-[1.02]">
                  <p className="text-2xl font-bold">{v}</p>
                  <p className="mt-1 text-xs text-white/50">{k}</p>
                  <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/5">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-cyan-400"
                      style={{ width: `${Math.min(100, (v as number) * 10 + 8)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-white/40">Loading graph…</p>
          )}
        </section>

        <footer className="pt-6 text-center text-xs text-white/30">
          powered by FalkorDB · Rung · Graph Hacks 2026
        </footer>
      </div>
    </main>
  );
}
