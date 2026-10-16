"use client";

import { useEffect, useRef } from "react";
import cytoscape, { type Core, type ElementDefinition, type StylesheetJson } from "cytoscape";
import type { Graph } from "@/lib/types";

/**
 * Kind → colour. Taken from the scaffold's map (backend/web/index.html); `Pod`
 * was missing there and takes the app accent.
 */
export const KIND_COLOR: Record<string, string> = {
  Pod: "#6366f1",
  Container: "#8a3324",
  Identity: "#7a5c2e",
  PermSet: "#6b4a6b",
  Node: "#44506b",
  Volume: "#5d7a52",
  Cluster: "#15181d",
};

const LAYOUT = { name: "breadthfirst", directed: true, spacingFactor: 1.25, padding: 28 } as const;

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
];

export function toElements(graph: Graph): ElementDefinition[] {
  return [
    ...graph.nodes.map((n) => ({
      data: { id: n.id, label: n.label || n.id, kind: n.kind },
    })),
    ...graph.edges.map((e, i) => ({
      data: {
        id: `e${i}`,
        source: e.source,
        target: e.target,
        label: e.type,
        type: e.type,
        attack_path: e.attack_path ?? 1,
      },
    })),
  ];
}

export default function GraphView({ graph }: { graph: Graph | null }) {
  const box = useRef<HTMLDivElement | null>(null);
  const cy = useRef<Core | null>(null);

  useEffect(() => {
    if (!box.current) return;
    const inst = cytoscape({
      container: box.current,
      elements: [],
      style: STYLE,
      layout: { ...LAYOUT },
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
    if (graph.nodes.length === 0) return;
    inst.add(toElements(graph));
    inst.layout({ ...LAYOUT }).run();
    inst.fit(undefined, 40);
  }, [graph]);

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
      {empty && (
        <p className="pointer-events-none absolute inset-0 flex items-center justify-center text-sm text-white/40">
          No graph loaded — upload a snapshot or check the backend.
        </p>
      )}
    </div>
  );
}
