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

/**
 * GET /compare?tenant= — the same graph counted two ways. Stream B computes both numbers; the UI
 * only renders them. This is the thesis in four fields, so it stays stable.
 */
export type Compare = {
  /** Workloads reaching cluster-admin when every permission is treated as a capability. */
  naive_reachable: number;
  /** Workloads reaching it through precondition-gated edges — Rung's answer. */
  rung_reachable: number;
  /** TOKEN_LIST edges the naive model assumes. */
  naive_token_list_edges: number;
  /** TOKEN_LIST edges that survive the preconditions. */
  rung_token_list_edges: number;
};

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

/**
 * Regression detector vocabulary (TEAM_PLAN §4): a route is NEW when first seen, RESOLVED or
 * ACCEPTED once it is dealt with, and REGRESSED when a closed route walks again.
 *
 * Stub shape — A ships the real findings on the 17th (docs/stream-c-frontend.md §C5). `status` is a
 * plain string, and every other field is optional, so a payload this shape does not know about
 * renders a neutral badge instead of throwing. `GET /findings?tenant=` returns `{findings: [...]}`.
 */
export const FINDING_STATUSES = ["NEW", "RESOLVED", "ACCEPTED", "REGRESSED"] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export type Finding = {
  id?: string;
  status: string;
  /** Route fingerprint: the steps taken to reach it. */
  route?: string;
  /** Target fingerprint: what the route lands on. */
  target?: string;
  title?: string;
  note?: string;
  /** What the detector recorded before this status — lets a REGRESSED finding say "was RESOLVED". */
  previous_status?: string;
  first_seen?: string;
  last_seen?: string;
};

/** Events streamed by POST /ask. */
export type AskEvent =
  | { type: "tool"; name: string; args?: Record<string, unknown> }
  | { type: "token"; text: string }
  | { type: "path"; steps: PathStep[] }
  | {
      type: "final";
      answer: string;
      citations?: string[];
      /** Present when this answer is about a tracked finding. */
      status?: string;
      finding?: Finding;
      /** Kyverno ClusterPolicy YAML when the agent called propose_policy. */
      proposed_policy?: string;
    };

/** POST /ask request body. */
export type AskRequest = {
  question: string;
  tenant?: string;
  /** Active reasoning persona: redteam | defender | auditor. */
  persona?: "redteam" | "defender" | "auditor";
};
