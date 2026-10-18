// Shapes from the API contract (TEAM_PLAN.md §5) — do not invent fields here.

export type GraphNode = {
  id: string;
  label: string;
  kind: string;
  props?: Record<string, unknown>;
};

/**
 * An ATT&CK technique the backend tags attack edges with (`backend/rung/attck.py`).
 *
 * It arrives as one nested object on the edge, `mitre: {id, name, tactic, url}` — not as the flat
 * `mitre_id`/`mitre_name`/`mitre_url` fields the task list assumed. `url` is the technique page.
 */
export type Mitre = {
  id: string;
  name: string;
  tactic?: string;
  url?: string;
};

export type GraphEdge = {
  source: string;
  target: string;
  type: string;
  /** 1 = walkable attack step, 0 = display only (never an attack step). */
  attack_path?: number;
  /** Present on attack edges only — structural edges carry no technique. */
  mitre?: Mitre;
  /**
   * CIS Kubernetes Benchmark section, present only when the edge's technique has one
   * (`CE_PRIV_MOUNT` → §5.2, `ROLE_BIND` → §5.1). The value already reads
   * "CIS Kubernetes Benchmark §5.2 (…)", so the UI must not prefix it with "CIS" again.
   */
  cis_section?: string | null;
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
  /** ATT&CK tag for this hop, when the backend sends one; the UI also resolves it from /graph. */
  mitre?: Mitre | null;
  /** CIS section for this hop, when the backend sends one; likewise resolvable from /graph. */
  cis_section?: string | null;
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
      /** ATT&CK technique for this edge, when /graph tagged it. */
      mitre?: Mitre | null;
      /** CIS section for this edge, when its technique has one. */
      cisSection?: string | null;
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
  /** Helm release / Argo app that owns the workload the route starts from (T3.4). Often null. */
  owning_app?: string | null;
  /** Where that owner deploys from — e.g. "helm:jenkins". Often null. */
  deployed_from?: string | null;
  /** ATT&CK techniques the route walks, one entry per distinct edge type. */
  mitre?: Mitre[];
  /** 0-10 risk score derived from route edges + status (REGRESSED and CE_* push higher). */
  score?: number;
  /** Human-readable severity bucket derived from score. */
  severity?: "critical" | "high" | "medium" | "low";
};

/**
 * A single speaker's turn in a red/blue debate — the `red_blue_debate` tool's
 * per-side output. `text` is the voice (LLM-generated or templated fallback);
 * `evidence` is the tool-result data the backend used to ground that voice.
 */
export type DebateTurn = {
  voice: "red" | "blue";
  text: string;
  evidence?: Record<string, unknown>;
};

/** Events streamed by POST /ask. */
export type AskEvent =
  | { type: "tool"; name: string; args?: Record<string, unknown> }
  | { type: "token"; text: string }
  | { type: "path"; steps: PathStep[] }
  | {
      type: "debate";
      topic?: string;
      red_turn: DebateTurn;
      blue_turn: DebateTurn;
      verdict?: string;
      /** "llm-voiced" when a model synthesised the voices, "templated" when the fallback did. */
      mode?: string;
    }
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
