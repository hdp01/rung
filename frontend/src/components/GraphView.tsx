"use client";

import { useEffect, useRef, useState } from "react";
import cytoscape, { type Core, type StylesheetJson } from "cytoscape";
import { edgeIdFor, KIND_COLOR, LAYOUT, toElements } from "@/lib/graph-utils";
import type { ElementSelection, Graph, PathStep } from "@/lib/types";

const ACCENT = "#22d3ee";

const STYLE: StylesheetJson = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      "text-wrap": "wrap",
      "text-valign": "center",
      "text-halign": "center",
      "text-max-width": "96px",
      color: "#e6e9f2",
      "font-size": 10,
      shape: "round-rectangle",
      width: 112,
      height: 48,
      "background-color": (n) => KIND_COLOR[n.data("kind")] ?? "#5d646e",
      "border-width": 1.5,
      "border-color": "rgba(255,255,255,0.28)",
    },
  },
  {
    selector: "edge",
    style: {
      label: "data(label)",
      "font-size": 9,
      color: "#9aa3ad",
      "curve-style": "bezier",
      "target-arrow-shape": "triangle",
      "line-color": "#6b7688",
      "target-arrow-color": "#6b7688",
      width: 2,
      "text-background-color": "#0b0e14",
      "text-background-opacity": 1,
      "text-background-padding": "3px",
    },
  },
  // Non-walkable / structural edges stay muted and dashed — never an attack step.
  {
    selector: 'edge[attack_path = 0], edge[type = "SCHEDULED_ON"]',
    style: {
      "line-style": "dashed",
      "line-color": "#3a434e",
      "target-arrow-color": "#3a434e",
      color: "#6b7688",
      opacity: 0.85,
    },
  },

  /* --- path highlight (C3) --- */
  { selector: "node.dimmed", style: { opacity: 0.2 } },
  { selector: "edge.dimmed", style: { opacity: 0.08 } },
  {
    selector: "node.path-node",
    style: { "border-color": ACCENT, "border-width": 3, "z-index": 500 },
  },
  {
    selector: "edge.path-edge",
    style: {
      "line-style": "solid",
      "line-color": ACCENT,
      "target-arrow-color": ACCENT,
      color: "#67e8f9",
      width: 3.5,
      "z-index": 900,
      "text-background-color": "#082f3a",
    },
  },

  /* --- click selection --- */
  { selector: "node.selected", style: { "border-color": "#ffffff", "border-width": 3.5 } },
  { selector: "edge.selected", style: { "line-color": "#ffffff", "target-arrow-color": "#ffffff", width: 4 } },
];

/**
 * The "route spine" — the edge types that actually form cluster-admin escalation chains.
 * We deliberately EXCLUDE the RBAC mesh edges (IMPERSONATE, ROLE_ESCALATE, ROLE_BIND,
 * TOKEN_CREATE, POD_*) from the default view: they're real attack primitives but they form
 * a near-complete graph among the 105 identities (851+ edges), which renders as an
 * unreadable hairball and buries the actual story. They're all still visible in "show all".
 */
const SPINE_EDGES = new Set([
  "IDENTITY_ASSUME",
  "CE_PRIV_MOUNT",
  "CE_NSENTER",
  "CE_MODULE_LOAD",
  "EXPLOIT_HOST_TRAVERSE",
  "EXPLOIT_CONTAINERD_SOCK",
  "TOKEN_STEAL",
  "TOKEN_LIST",
  "PERMISSION_DISCOVER",
  "ADMIN_OF",
]);

/**
 * Narrow the graph to the route spine: pods → (escape/token) → identities →
 * permsets → cluster. Keeps only spine edges and the nodes they touch. On the demo
 * cluster this is ~15-25 nodes forming clean chains, instead of the 231-node mesh.
 */
function attackSubgraph(graph: Graph): Graph {
  const edges = graph.edges.filter(
    (e) => e.attack_path === 1 && SPINE_EDGES.has(e.type),
  );
  const kept = new Set<string>();
  for (const e of edges) {
    kept.add(e.source);
    kept.add(e.target);
  }
  return {
    nodes: graph.nodes.filter((n) => kept.has(n.id)),
    edges,
  };
}

/**
 * Hard-cap any view to the most-connected N nodes. 280 unlabelled dots is unreadable
 * at any zoom level; 80 nodes grouped by degree tells the real story. We score each
 * node by how many edges it touches, keep the top N, and drop any edges whose endpoints
 * aren't both kept.
 */
function capByDegree(graph: Graph, maxNodes: number): Graph {
  if (graph.nodes.length <= maxNodes) return graph;
  const degree: Record<string, number> = {};
  for (const n of graph.nodes) degree[n.id] = 0;
  for (const e of graph.edges) {
    degree[e.source] = (degree[e.source] ?? 0) + 1;
    degree[e.target] = (degree[e.target] ?? 0) + 1;
  }
  // Always keep the semantic endpoints — attack-source pods and the cluster node. Capping
  // purely by degree would drop the pods (they have 1-2 edges each) and keep RBAC hubs,
  // leaving the tree rootless. Force the endpoints, then fill the rest by degree.
  const forced = new Set(
    graph.nodes.filter((n) => n.kind === "Pod" || n.kind === "Cluster").map((n) => n.id),
  );
  const kept = new Set(forced);
  for (const n of [...graph.nodes].sort((a, b) => (degree[b.id] ?? 0) - (degree[a.id] ?? 0))) {
    if (kept.size >= maxNodes) break;
    kept.add(n.id);
  }
  return {
    nodes: graph.nodes.filter((n) => kept.has(n.id)),
    edges: graph.edges.filter((e) => kept.has(e.source) && kept.has(e.target)),
  };
}

const MAX_NODES: Record<"attack" | "all", number> = {
  attack: 25,   // the attack core: 6 pods + ~5 admin permsets + their identities + the cluster node
  all: 40,      // show-all is already noisy — more nodes just adds hairball
};

/**
 * In the "show all" view we don't actually render every edge — a 2192-edge rendering is a
 * dot-cloud regardless of layout. Keep attack edges plus the minimum structural scaffolding
 * (BELONGS_TO, IDENTITY_ASSUME, SCHEDULED_ON) that lets a reader trace back to a workload.
 */
const SHOW_ALL_STRUCTURAL_KEEP = new Set(["BELONGS_TO", "IDENTITY_ASSUME", "SCHEDULED_ON", "CONTAINED_IN"]);

function pruneForShowAll(graph: Graph): Graph {
  return {
    nodes: graph.nodes,
    edges: graph.edges.filter(
      (e) => e.attack_path === 1 || SHOW_ALL_STRUCTURAL_KEEP.has(e.type),
    ),
  };
}

export default function GraphView({
  graph,
  path,
  selectedId,
  onSelect,
  mode = "attack",
}: {
  graph: Graph | null;
  path?: PathStep[];
  selectedId?: string | null;
  onSelect?: (selection: ElementSelection | null) => void;
  /** "attack" (default) = only attack-walkable subgraph; "all" = everything. */
  mode?: "attack" | "all";
}) {
  const box = useRef<HTMLDivElement | null>(null);
  const cy = useRef<Core | null>(null);
  const onSelectRef = useRef(onSelect);
  const [truncated, setTruncated] = useState<{ shown: number; total: number } | null>(null);

  useEffect(() => {
    onSelectRef.current = onSelect;
  }, [onSelect]);

  useEffect(() => {
    if (!box.current) return;
    const inst = cytoscape({
      container: box.current,
      elements: [],
      style: STYLE,
      layout: { ...LAYOUT },
      // Zoom bounds + lower wheel sensitivity: without these, a scroll gesture rockets
      // the graph into "one giant node fills the pane" or "nodes become 1px dots" and
      // the user has to double-click to re-fit. 0.3 slows the wheel; 0.3-3 bounds stop
      // the extremes.
      minZoom: 0.3,
      maxZoom: 3,
      wheelSensitivity: 0.3,
    });
    inst.on("tap", "edge", (evt) => {
      const d = evt.target.data();
      onSelectRef.current?.({
        type: "edge",
        id: String(d.id),
        source: String(d.source),
        target: String(d.target),
        edgeType: String(d.type),
        attackPath: Number(d.attack_path) === 1,
        step: d.step === undefined ? undefined : Number(d.step),
        mitre: d.mitre ?? null,
        cisSection: d.cis_section ?? null,
      });
    });
    inst.on("tap", "node", (evt) => {
      const d = evt.target.data();
      onSelectRef.current?.({
        type: "node",
        id: String(d.id),
        kind: String(d.kind),
        props: (d.props ?? {}) as Record<string, unknown>,
      });
    });
    inst.on("tap", (evt) => {
      if (evt.target === inst) onSelectRef.current?.(null); // clicked empty space
    });
    cy.current = inst;
    return () => {
      inst.destroy();
      cy.current = null;
    };
  }, []);

  // THE empty-pane fix: Cytoscape captures the container size at init and renders into a
  // fixed canvas. When the container's width changes (the PathPanel column appearing or
  // disappearing, a window resize, the pane first becoming visible), the canvas keeps the
  // old dimensions and the graph is drawn off-screen — a black pane. Observe the box and
  // resize + refit on every real size change. rAF-debounced so a burst of resize events
  // during a layout transition collapses into one refit.
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    let raf = 0;
    const ro = new ResizeObserver(() => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const inst = cy.current;
        if (!inst || inst.elements().length === 0) return;
        inst.resize();
        inst.fit(undefined, 50);
      });
    });
    ro.observe(el);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, []);

  const zoomBy = (factor: number) => {
    const inst = cy.current;
    if (!inst) return;
    const next = Math.max(0.3, Math.min(3, inst.zoom() * factor));
    inst.zoom({
      level: next,
      renderedPosition: { x: inst.width() / 2, y: inst.height() / 2 },
    });
  };

  useEffect(() => {
    const inst = cy.current;
    if (!inst || !graph) return;
    inst.elements().remove();
    const scoped = mode === "all" ? pruneForShowAll(graph) : attackSubgraph(graph);
    const view = capByDegree(scoped, MAX_NODES[mode]);
    if (view.nodes.length === 0) {
      setTruncated(null);
      return;
    }
    setTruncated(
      view.nodes.length < scoped.nodes.length
        ? { shown: view.nodes.length, total: scoped.nodes.length }
        : null,
    );
    inst.add(toElements(view));
    // Breadthfirst with EXPLICIT roots = the Pod (attack-source) nodes. Without roots,
    // cytoscape auto-picked poorly and laid every node in one horizontal line floating in
    // the vertical center — the "what is this empty space" bug. Rooted at the pods, the graph
    // flows as a real hierarchy (pods → identities → permsets → cluster) and fills the pane.
    const roots = inst.nodes().filter((n) => n.data("kind") === "Pod");
    const layout = {
      name: "breadthfirst",
      directed: true,
      roots: roots.length ? roots : undefined,
      spacingFactor: mode === "all" ? 1.0 : 1.3,
      padding: 30,
      grid: true,       // align nodes to a grid within each depth — tidier than the default
      avoidOverlap: true,
    };
    inst.layout(layout).run();
    inst.fit(undefined, 40);
  }, [graph, mode]);

  // Light the chain, dim everything else.
  useEffect(() => {
    const inst = cy.current;
    if (!inst || !graph) return;
    const steps = path ?? [];
    inst.batch(() => {
      inst.elements().removeClass("dimmed path-node path-edge");
      inst.edges().removeData("step");
      if (steps.length === 0) return;
      inst.elements().addClass("dimmed");
      // Direct id-lookup per step is O(path) instead of O(path × edges).
      // On the full 2192-edge graph this used to walk ~10k iterations per highlight
      // and was the hot path when a user clicked a chip.
      steps.forEach((s, i) => {
        inst.getElementById(s.from).removeClass("dimmed").addClass("path-node");
        inst.getElementById(s.to).removeClass("dimmed").addClass("path-node");
        const edgeId = edgeIdFor(graph, s.from, s.edge, s.to);
        if (!edgeId) return;
        const edge = inst.getElementById(edgeId);
        if (edge.nonempty()) {
          edge.removeClass("dimmed").addClass("path-edge").data("step", i + 1);
        }
      });
    });
    if (steps.length > 0) {
      const els = inst.elements(".path-node, .path-edge");
      if (els.length > 0) inst.fit(els, 90);
    } else {
      inst.fit(undefined, 40);
    }
  }, [path, graph, mode]);

  useEffect(() => {
    const inst = cy.current;
    if (!inst) return;
    inst.elements().removeClass("selected");
    if (selectedId) inst.getElementById(selectedId).addClass("selected");
  }, [selectedId]);

  const empty = !graph || graph.nodes.length === 0;

  return (
    <div className="relative h-full w-full">
      <div ref={box} className="h-full w-full" />
      {/* legend sits at the bottom-left, out of the way of graph content and the truncation badge */}
      <div className="pointer-events-none absolute bottom-3 left-3 flex flex-wrap gap-1.5">
        {Object.entries(KIND_COLOR).map(([kind, color]) => (
          <span
            key={kind}
            className="flex items-center gap-1.5 rounded-full bg-black/50 px-2 py-0.5 text-[10px] text-white/70"
          >
            <span className="h-2 w-2 rounded-sm" style={{ background: color }} />
            {kind}
          </span>
        ))}
      </div>
      {/* zoom controls — big/small view on demand, plus one-click fit when the view drifts */}
      <div className="absolute right-3 top-3 flex items-center gap-1">
        <button
          onClick={() => zoomBy(1 / 1.4)}
          className="flex h-7 w-7 items-center justify-center rounded-lg border border-white/15 bg-black/60 text-sm font-semibold text-white/70 transition hover:border-cyan-400/40 hover:text-cyan-200"
          title="Zoom out"
        >
          −
        </button>
        <button
          onClick={() => cy.current?.fit(undefined, 50)}
          className="flex h-7 items-center justify-center rounded-lg border border-white/15 bg-black/60 px-2.5 text-[11px] font-medium text-white/70 transition hover:border-cyan-400/40 hover:text-cyan-200"
          title="Fit to view"
        >
          ⤢ fit
        </button>
        <button
          onClick={() => zoomBy(1.4)}
          className="flex h-7 w-7 items-center justify-center rounded-lg border border-white/15 bg-black/60 text-sm font-semibold text-white/70 transition hover:border-cyan-400/40 hover:text-cyan-200"
          title="Zoom in"
        >
          +
        </button>
      </div>
      {truncated && (
        <span className="pointer-events-none absolute bottom-3 right-3 rounded-full bg-amber-500/15 px-3 py-1 text-[10px] font-medium text-amber-200">
          top {truncated.shown} of {truncated.total} nodes
        </span>
      )}
      {empty && (
        <p className="pointer-events-none absolute inset-0 flex items-center justify-center text-sm text-white/40">
          No graph loaded — upload a snapshot or check the backend.
        </p>
      )}
    </div>
  );
}
