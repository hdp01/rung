import type { ElementDefinition } from "cytoscape";
import type { Graph } from "@/lib/types";

/** Kind → colour, reused from the old scaffold (backend/web/index.html). */
export const KIND_COLOR: Record<string, string> = {
  Pod: "#6366f1",
  Container: "#8a3324",
  Identity: "#7a5c2e",
  PermSet: "#6b4a6b",
  Node: "#44506b",
  Volume: "#5d7a52",
  Cluster: "#15181d",
};

export const LAYOUT = {
  name: "breadthfirst",
  directed: true,
  spacingFactor: 1.25,
  padding: 28,
} as const;

export function toElements(graph: Graph): ElementDefinition[] {
  return [
    ...graph.nodes.map((n) => ({
      data: { id: n.id, label: n.label || n.id, kind: n.kind, props: n.props ?? {} },
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

/** The cytoscape edge id for a step, matching the ids built in toElements. */
export function edgeIdFor(
  graph: Graph,
  source: string,
  edgeType: string,
  target: string,
): string | null {
  const i = graph.edges.findIndex(
    (e) => e.source === source && e.target === target && e.type === edgeType,
  );
  return i === -1 ? null : `e${i}`;
}
