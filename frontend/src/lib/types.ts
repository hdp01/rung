// Shapes from the API contract (TEAM_PLAN.md §5) — do not invent fields here.

export type GraphNode = {
  id: string;
  label: string;
  kind: string;
  props?: Record<string, unknown>;
};

export type GraphEdge = {
  source: string;
  target: string;
  type: string;
  /** 1 = walkable attack step, 0 = display only (never an attack step). */
  attack_path?: number;
};

export type Graph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

export type PathStep = {
  from: string;
  edge: string;
  to: string;
  why?: string;
  confidence?: string;
};

export type AttackPath = {
  id?: string;
  source?: string;
  target?: string;
  steps: PathStep[];
};

export type Tenant = {
  tenant: string;
  counts: Record<string, number>;
};

export type Health = {
  status: string;
  falkordb: string;
  graph: string;
};

export type Stats = Record<string, number>;

/** What the graph pane reports when the user clicks a node or an edge. */
export type ElementSelection =
  | { type: "node"; id: string; kind: string; props: Record<string, unknown> }
  | {
      type: "edge";
      id: string;
      source: string;
      target: string;
      edgeType: string;
      /** true when the edge is a walkable attack step (attack_path: 1). */
      attackPath: boolean;
      /** 1-based position in the highlighted chain, when this edge is part of it. */
      step?: number;
    };

/** Events streamed by POST /ask. */
export type AskEvent =
  | { type: "tool"; name: string; args?: Record<string, unknown> }
  | { type: "token"; text: string }
  | { type: "path"; steps: PathStep[] }
  | { type: "final"; answer: string; citations?: string[] };
