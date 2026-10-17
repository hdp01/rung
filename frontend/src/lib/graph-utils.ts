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
  const nodeIds = new Set(graph.nodes.map((n) => n.id));
  return [
    ...graph.nodes.map((n) => ({
      data: { id: n.id, label: n.label || n.id, kind: n.kind, props: n.props ?? {} },
    })),
    // Skip an edge whose endpoints are not both nodes. `/graph` can carry a RELIES_ON edge from
    // an Exception it never lists as a node (the accept-risk path), and cytoscape throws on an
    // edge with a missing end — which blanks the whole pane. The id keeps the original edge index
    // so edgeIdFor() still resolves a path step to the same edge.
    ...graph.edges
      .map((e, i) => ({ e, i }))
      .filter(({ e }) => nodeIds.has(e.source) && nodeIds.has(e.target))
      .map(({ e, i }) => ({
        data: {
          id: `e${i}`,
          source: e.source,
          target: e.target,
          label: e.type,
          type: e.type,
          attack_path: e.attack_path ?? 1,
          // Carry the ATT&CK tag through so a click can explain the hop (C/O2c).
          mitre: e.mitre ?? null,
          cis_section: e.cis_section ?? null,
        },
      })),
  ];
}

/** The ATT&CK/CIS metadata for an edge, found by its (source, type, target) triple. */
export function edgeMetaFor(
  graph: Graph,
  source: string,
  edgeType: string,
  target: string,
): { mitre: Graph["edges"][number]["mitre"] | null; cis_section: string | null } {
  const edge = graph.edges.find(
    (e) => e.source === source && e.target === target && e.type === edgeType,
  );
  return { mitre: edge?.mitre ?? null, cis_section: edge?.cis_section ?? null };
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
