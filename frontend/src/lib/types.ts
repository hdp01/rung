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

/** Events streamed by POST /ask. */
export type AskEvent =
  | { type: "tool"; name: string; args?: Record<string, unknown> }
  | { type: "token"; text: string }
  | { type: "path"; steps: PathStep[] }
  | { type: "final"; answer: string; citations?: string[] };
