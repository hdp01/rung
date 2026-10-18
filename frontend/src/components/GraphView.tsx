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
 * Narrow the graph to the attack-walkable subgraph: keep only edges with
 * attack_path:1 (plus any structural edges that start from one of those nodes
 * so chains stay readable), and only nodes that are endpoints of a kept edge.
 */
function attackSubgraph(graph: Graph): Graph {
  const kept = new Set<string>();
  const edges = graph.edges.filter((e) => e.attack_path === 1);
  for (const e of edges) {
    kept.add(e.source);
    kept.add(e.target);
  }
  const context = graph.edges.filter(
    (e) => e.attack_path === 0 && kept.has(e.source) && kept.has(e.target),
  );
  return {
    nodes: graph.nodes.filter((n) => kept.has(n.id)),
    edges: [...edges, ...context],
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
  const kept = new Set(
    [...graph.nodes]
      .sort((a, b) => (degree[b.id] ?? 0) - (degree[a.id] ?? 0))
      .slice(0, maxNodes)
      .map((n) => n.id),
  );
  return {
    nodes: graph.nodes.filter((n) => kept.has(n.id)),
    edges: graph.edges.filter((e) => kept.has(e.source) && kept.has(e.target)),
  };
}

const MAX_NODES: Record<"attack" | "all", number> = {
  attack: 60,   // chains fit comfortably; most clusters are < 60 attack-involved nodes anyway
  all: 80,      // enough to see cluster structure, few enough to label every node
};

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

  useEffect(() => {
    const inst = cy.current;
    if (!inst || !graph) return;
    inst.elements().remove();
    const scoped = mode === "all" ? graph : attackSubgraph(graph);
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
    // Dense full-view uses "concentric" — 280 nodes with cose froze the main thread for
    // 5-10s. Concentric groups by node degree (hubs in center, leaves outward), runs in O(n),
    // and never blocks the UI. Attack subgraph is small + chain-shaped, so breadthfirst
    // reads better there.
    const layout = mode === "all"
      ? {
          name: "concentric",
          concentric: (n: cytoscape.NodeSingular) => n.degree(false),
          levelWidth: () => 1,
          minNodeSpacing: 20,
          animate: false,
          padding: 24,
          fit: true,
        }
      : { ...LAYOUT };
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
      <div className="pointer-events-none absolute left-3 top-3 flex flex-wrap gap-2">
        {Object.entries(KIND_COLOR).map(([kind, color]) => (
          <span
            key={kind}
            className="flex items-center gap-1.5 rounded-full bg-black/40 px-2 py-1 text-[10px] text-white/70 backdrop-blur"
          >
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: color }} />
            {kind}
          </span>
        ))}
      </div>
      {truncated && (
        <span className="pointer-events-none absolute right-3 top-3 rounded-full bg-amber-500/15 px-3 py-1 text-[10px] font-medium text-amber-200 backdrop-blur">
          showing top {truncated.shown} of {truncated.total} nodes by connectivity
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
