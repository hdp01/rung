"use client";

import { ChangeEvent, FormEvent, useEffect, useState } from "react";
import dynamic from "next/dynamic";
import Chat from "@/components/Chat";
import ComparePanel from "@/components/ComparePanel";
import FindingsPanel from "@/components/FindingsPanel";
import PathPanel from "@/components/PathPanel";
import RegressionBanner from "@/components/RegressionBanner";
import { edgeIdFor, edgeMetaFor } from "@/lib/graph-utils";
import type {
  Compare,
  ElementSelection,
  Finding,
  Graph,
  Health,
  PathStep,
  Stats,
  Tenant,
} from "@/lib/types";

// Cytoscape touches window/document — keep it out of SSR (see next/dynamic docs).
const GraphView = dynamic(() => import("@/components/GraphView"), {
  ssr: false,
  loading: () => <p className="text-sm text-white/40">Loading graph…</p>,
});

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function Home() {
  const [health, setHealth] = useState<Health | null>(null);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenant, setTenant] = useState("");
  const [stats, setStats] = useState<Stats | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [path, setPath] = useState<PathStep[]>([]);
  const [selection, setSelection] = useState<ElementSelection | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [latestFinding, setLatestFinding] = useState<Finding | null>(null);
  const [compare, setCompare] = useState<Compare | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const [graphMode, setGraphMode] = useState<"attack" | "all">("attack");

  async function loadHealth() {
    try {
      const h = await fetch(`${API}/health`, { cache: "no-store" });
      setHealth(await h.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "backend unreachable");
    }
  }

  async function loadTenants() {
    try {
      const r = await fetch(`${API}/tenants`, { cache: "no-store" });
      const list: Tenant[] = await r.json();
      setTenants(list);
      // keep the current selection if it still exists, else ?tenant= from the URL, else the first
      setTenant((cur) => {
        const wanted = cur || new URLSearchParams(window.location.search).get("tenant") || "";
        return list.some((t) => t.tenant === wanted) ? wanted : (list[0]?.tenant ?? "");
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "backend unreachable");
    }
  }

  // One graph per tenant: /graph and /stats are both scoped by ?tenant=
  async function loadTenantData(name: string) {
    try {
      const q = `tenant=${encodeURIComponent(name)}`;
      const [s, g, f, c] = await Promise.all([
        fetch(`${API}/stats?${q}`, { cache: "no-store" }),
        fetch(`${API}/graph?${q}`, { cache: "no-store" }),
        fetch(`${API}/findings?${q}`, { cache: "no-store" }),
        fetch(`${API}/compare?${q}`, { cache: "no-store" }),
      ]);
      if (s.ok) setStats(await s.json());
      if (g.ok) setGraph(await g.json());
      if (f.ok) setFindings((await f.json()).findings ?? []);
      // /compare is new (Stream B): until it answers, say so rather than leaving the other
      // tenant's proof on screen.
      setCompare(c.ok ? await c.json() : null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "backend unreachable");
    }
  }

  function refresh() {
    setReload((n) => n + 1);
    loadHealth();
    loadTenants();
  }

  useEffect(() => {
    // Initial load: cluster health and the tenant list live outside React, so setting
    // that loaded state here is the point of the effect, not a render-derived update.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadHealth();
    loadTenants();
  }, []);

  useEffect(() => {
    if (!tenant) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadTenantData(tenant);
  }, [tenant, reload]);

  function switchTenant(name: string) {
    setTenant(name);
    setPath([]); // a chain or finding from the other cluster must not stay lit
    setSelection(null);
    setLatestFinding(null);
    // keep the URL shareable: /?tenant=<name>
    const url = new URL(window.location.href);
    url.searchParams.set("tenant", name);
    window.history.replaceState(null, "", url);
  }

  async function onUpload(e: FormEvent) {
    e.preventDefault();
    if (!file || !tenant) return;
    setUploading(true);
    setMessage(null);
    setError(null);
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await fetch(`${API}/ingest?tenant=${encodeURIComponent(tenant)}`, {
        method: "POST",
        body: form,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "ingest failed");
      setMessage(`Ingested: ${JSON.stringify(data.counts)}`);
      await loadTenantData(tenant);
    } catch (e) {
      setError(e instanceof Error ? e.message : "upload failed");
    } finally {
      setUploading(false);
    }
  }

  const online = health?.falkordb === "connected";

  // The finding the last answer was about, or the tenant's own list: either way, a route that is
  // walkable again is the thing a reviewer must not scroll past.
  // Prefer a regression whose owning workload we can name: "a risk you accepted, walking again" is
  // a stronger banner than an anonymous route. Both fallbacks are needed — ownership is often null.
  const regressed =
    (latestFinding?.status === "REGRESSED" ? latestFinding : undefined) ??
    findings.find((f) => f.status === "REGRESSED" && f.owning_app) ??
    findings.find((f) => f.status === "REGRESSED");

  return (
    <main className="min-h-screen px-4 py-6 sm:px-6 md:px-10">
      <div className="mx-auto max-w-7xl space-y-6">
        {/* Top bar */}
        <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-2xl bg-gradient-to-br from-indigo-500 via-fuchsia-500 to-cyan-400 glow float" />
            <div>
              <h1 className="text-2xl font-bold tracking-tight">
                Rung <span className="text-white/40">/ graph atlas</span>
              </h1>
              <p className="text-xs text-white/50">Kubernetes privilege-escalation, made visible</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-2 rounded-full glass px-3 py-1.5 text-xs text-white/50">
              <span>tenant</span>
              <select
                aria-label="Tenant"
                value={tenant}
                onChange={(e) => switchTenant(e.target.value)}
                disabled={tenants.length === 0}
                className="cursor-pointer rounded-lg border border-white/10 bg-slate-900 px-2 py-1 text-xs font-medium text-white/90 outline-none focus:border-indigo-400/50 disabled:opacity-50"
              >
                {tenants.length === 0 && <option value="">loading…</option>}
                {tenants.map((t) => (
                  <option key={t.tenant} value={t.tenant}>
                    {t.tenant}
                  </option>
                ))}
              </select>
            </label>
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

        {regressed && <RegressionBanner finding={regressed} />}

        {/* Stage: chat + snapshot sidebar on the left, graph on the right */}
        <section className="grid gap-4 lg:grid-cols-[minmax(0,380px)_minmax(0,1fr)] lg:items-start">
          <div className="space-y-4">
            <div className="glass flex h-[54vh] min-h-[340px] flex-col overflow-hidden rounded-3xl">
              <Chat
                tenant={tenant || undefined}
                onPath={(steps) => {
                  setPath(steps);
                  setSelection(null);
                }}
                onFinding={setLatestFinding}
              />
            </div>

            <FindingsPanel findings={findings} />

            <form onSubmit={onUpload} className="glass space-y-3 rounded-3xl p-5">
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
                disabled={!file || uploading || !tenant}
                className="w-full rounded-xl bg-gradient-to-r from-indigo-500 via-fuchsia-500 to-cyan-400 px-4 py-3 text-sm font-semibold text-white shadow-lg transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {uploading ? "Ingesting…" : "Upload & ingest"}
              </button>
              <p className="text-[11px] text-white/40">
                Loads into <span className="font-mono text-white/60">{`rung:${tenant}`}</span>. Entities,
                permissions and attack paths resolve into a traversable graph.
              </p>
              {message && <p className="text-xs text-emerald-300 break-all">{message}</p>}
              {error && <p className="text-xs text-rose-300 break-all">{error}</p>}
            </form>
          </div>

          {/* Graph pane + chain detail */}
          <section className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-lg font-semibold">Attack surface</h3>
              <div className="flex items-center gap-2">
                <div className="flex overflow-hidden rounded-full border border-white/10 text-[10px] font-medium uppercase tracking-wide">
                  <button
                    onClick={() => setGraphMode("attack")}
                    className={`px-3 py-1 transition ${
                      graphMode === "attack"
                        ? "bg-cyan-400/20 text-cyan-200"
                        : "text-white/50 hover:text-white/80"
                    }`}
                    title="Only edges with attack_path:1 and the nodes they touch"
                  >
                    attack subgraph
                  </button>
                  <button
                    onClick={() => setGraphMode("all")}
                    className={`px-3 py-1 transition ${
                      graphMode === "all"
                        ? "bg-cyan-400/20 text-cyan-200"
                        : "text-white/50 hover:text-white/80"
                    }`}
                    title="Full cluster graph — includes every structural edge"
                  >
                    show all
                  </button>
                </div>
                <span className="font-mono text-[10px] text-white/40">
                  {graph ? `${graph.nodes.length} nodes · ${graph.edges.length} edges` : ""}
                </span>
              </div>
            </div>
            <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_300px]">
              {/* No `glass` on the graph pane — backdrop-blur underneath a
                  constantly-repainting canvas burns ~30% CPU on scroll/pan.
                  Flat solid background keeps the canvas smooth. */}
              <div className="h-[55vh] min-h-[380px] overflow-hidden rounded-3xl border border-white/10 bg-black/40">
                <GraphView
                  graph={graph}
                  path={path}
                  selectedId={selection?.id ?? null}
                  onSelect={setSelection}
                  mode={graphMode}
                />
              </div>
              <PathPanel
                steps={path}
                selection={selection}
                onSelectEdge={(step) => {
                  if (!graph) return;
                  const id = edgeIdFor(graph, step.from, step.edge, step.to);
                  if (!id) return;
                  // /ask steps do not carry the ATT&CK tag today, so resolve it from /graph —
                  // the same edge the graph pane would hand us on a click.
                  const meta = edgeMetaFor(graph, step.from, step.edge, step.to);
                  setSelection({
                    type: "edge",
                    id,
                    source: step.from,
                    target: step.to,
                    edgeType: step.edge,
                    attackPath: true,
                    mitre: step.mitre ?? meta.mitre,
                    cisSection: step.cis_section ?? meta.cis_section,
                  });
                }}
              />
            </div>
          </section>
        </section>

        {/* The proof: one graph, counted naively and precondition-gated (Stream B owns /compare) */}
        <ComparePanel compare={compare} />

        {/* Stats */}
        <section className="space-y-3">
          <div className="flex items-end justify-between">
            <h3 className="text-lg font-semibold">Graph composition</h3>
            <span className="font-mono text-xs text-white/40">{`rung:${tenant}`}</span>
          </div>
          {stats ? (
            (() => {
              // Scale every bar relative to the largest count in the current stats, not a
              // fixed /10 that under-weighted every count > 10 (so e.g. "76 containers" and
              // "6 nodes" both filled the bar). Max of 1 avoids divide-by-zero on an empty graph.
              const maxCount = Math.max(1, ...Object.values(stats).map((n) => Number(n) || 0));
              return (
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6">
                  {Object.entries(stats).map(([k, v]) => (
                    <div key={k} className="glass rounded-2xl p-4 transition hover:scale-[1.02]">
                      <p className="text-2xl font-bold">{v}</p>
                      <p className="mt-1 text-xs text-white/50">{k}</p>
                      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/5">
                        <div
                          className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-cyan-400"
                          style={{ width: `${Math.max(4, (Number(v) / maxCount) * 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              );
            })()
          ) : (
            <p className="text-sm text-white/40">No counts yet.</p>
          )}
        </section>

        <footer className="pb-4 text-center text-xs text-white/40">
          powered by FalkorDB · Rung · Graph Hacks 2026
        </footer>
      </div>
    </main>
  );
}
