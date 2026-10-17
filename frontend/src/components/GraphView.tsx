"use client";

import { useEffect, useRef } from "react";
import cytoscape, { type Core, type StylesheetJson } from "cytoscape";
import { KIND_COLOR, LAYOUT, toElements } from "@/lib/graph-utils";
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

export default function GraphView({
  graph,
  path,
  selectedId,
  onSelect,
}: {
  graph: Graph | null;
  path?: PathStep[];
  selectedId?: string | null;
  onSelect?: (selection: ElementSelection | null) => void;
}) {
  const box = useRef<HTMLDivElement | null>(null);
  const cy = useRef<Core | null>(null);
  const onSelectRef = useRef(onSelect);

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
    if (graph.nodes.length === 0) return;
    inst.add(toElements(graph));
    inst.layout({ ...LAYOUT }).run();
    inst.fit(undefined, 40);
  }, [graph]);

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
      steps.forEach((s, i) => {
        inst.getElementById(s.from).removeClass("dimmed").addClass("path-node");
        inst.getElementById(s.to).removeClass("dimmed").addClass("path-node");
        inst.edges().forEach((edge) => {
          const d = edge.data();
          if (d.source === s.from && d.target === s.to && d.type === s.edge) {
            edge.removeClass("dimmed").addClass("path-edge").data("step", i + 1);
          }
        });
      });
    });
    if (steps.length > 0) {
      const els = inst.elements(".path-node, .path-edge");
      if (els.length > 0) inst.fit(els, 90);
    } else {
      inst.fit(undefined, 40);
    }
  }, [path, graph]);

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
      {empty && (
        <p className="pointer-events-none absolute inset-0 flex items-center justify-center text-sm text-white/40">
          No graph loaded — upload a snapshot or check the backend.
        </p>
      )}
    </div>
  );
}
