"""The real agent — Claude Opus 5.5 over the graph, via the tool-use loop.

Streams events in the shape the frontend's chat panel already consumes
(see `frontend/src/lib/types.ts :: AskEvent`): `tool` while the agent is
working, `token` as the final answer is typed, `path` to light up a chain
on the graph, `final` when it's done. This replaces `ask.py`'s keyword
router with real multi-tool reasoning — same event vocabulary, so the
frontend code does not change.

Falls back cleanly: if ANTHROPIC_API_KEY is not set, callers get a
`RuntimeError` and `app.main` keeps serving the keyword stand-in. That
way a teammate who hasn't set a key still sees the UI work end to end.
"""
from __future__ import annotations

import json
import os
from typing import Any, Callable, Iterator

from . import graph as graph_logic
from . import paths as paths_logic
from . import sim as sim_logic

# `claude-opus-5-5` is the current Opus; adaptive thinking + effort=high is
# the right default for pick-the-right-tool reasoning. Overridable from env
# so a teammate can downgrade to Sonnet if the Opus bill alarms them.
_MODEL = os.getenv("RUNG_AGENT_MODEL", "claude-opus-5-5")
_MAX_TOKENS = int(os.getenv("RUNG_AGENT_MAX_TOKENS", "4096"))
_MAX_STEPS = int(os.getenv("RUNG_AGENT_MAX_STEPS", "12"))

SYSTEM = """\
You are Rung, an agent that reasons about privilege-escalation paths in a
Kubernetes cluster represented as a FalkorDB graph.

Rules you must not break:
- Answer only from tool results. If no path exists, say so plainly;
  never speculate about edges you have not read.
- Always cite the chain. Every claim about reachability names its edges
  in order. Do not just name the destination.
- State confidence. If an edge carries `confidence: 'low'` (POD_PATCH
  does), flag that in the answer.
- A permission is not a capability. Rung's attack edges already encode
  the preconditions (Pod Security Admission for POD_CREATE, real token
  Secrets for TOKEN_LIST, the bind verb for ROLE_BIND, privileged AND
  hostPID for CE_NSENTER). Do not reason around them.
- Prefer `paths_to` or `blast_radius` for "can X reach Y?" questions;
  prefer `choke_points` for "what should I fix first?"; prefer
  `critical_reach` for "who can reach cluster-admin?".
- Keep the final answer short — a lead sentence, then the chain or the
  short list, then the "why it matters" line. No preamble.
"""

TOOLS = [
    {
        "name": "list_entities",
        "description": (
            "List entities of a given kind, optionally filtered by substring. "
            "Use to find an entity id before passing it to another tool. "
            "`kind` is one of Pod, Container, Identity, PermSet, Volume, Node, Cluster."
        ),
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind"],
            "properties": {
                "kind": {"type": "string"},
                "name_contains": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
        },
    },
    {
        "name": "blast_radius",
        "description": (
            "Everything reachable from this entity via attack-walkable edges, "
            "with the shortest-hop count to each. Use for 'this is compromised, "
            "what can it reach?'."
        ),
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["id"],
            "properties": {
                "id": {"type": "string"},
                "max_hops": {"type": "integer", "minimum": 1, "maximum": 8},
            },
        },
    },
    {
        "name": "paths_to",
        "description": (
            "The attack chain(s) from a source to a target. Returns ordered "
            "steps with edge type on each hop. Use for 'how does X reach Y?'. "
            "`target` defaults to the Cluster node (cluster-admin)."
        ),
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["source"],
            "properties": {
                "source": {"type": "string"},
                "target": {"type": "string"},
                "max_hops": {"type": "integer", "minimum": 1, "maximum": 8},
            },
        },
    },
    {
        "name": "critical_reach",
        "description": (
            "Every workload that reaches cluster-admin, with shortest-hop "
            "count. Use for 'who can escalate to admin?'."
        ),
        "input_schema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    {
        "name": "choke_points",
        "description": (
            "Highest-leverage fix: nodes with the greatest betweenness over the "
            "attack-walkable subgraph. Removing one closes the most chains."
        ),
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"top_n": {"type": "integer", "minimum": 1, "maximum": 10}},
        },
    },
    {
        "name": "simulate_remove",
        "description": (
            "Change-simulation: 'if I remove these role bindings, what closes "
            "and what still gets to cluster-admin by another route?'. Pass a "
            "list of role-ref strings like 'ClusterRole/cluster-admin'."
        ),
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["role_refs"],
            "properties": {
                "role_refs": {"type": "array", "items": {"type": "string"}, "maxItems": 5},
            },
        },
    },
    {
        "name": "list_findings",
        "description": (
            "The regression detector's current findings: route + target + "
            "status (NEW | RESOLVED | ACCEPTED | REGRESSED). Use for 'what's "
            "new since last snapshot?' or 'has anything regressed?'."
        ),
        "input_schema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
]


# ---------- tool implementations (thin wrappers over the real logic) ----------


def _impl_list_entities(g, args: dict) -> dict:
    kind = args.get("kind", "Entity")
    needle = (args.get("name_contains") or "").lower()
    limit = min(int(args.get("limit", 25)), 50)
    cy = f"MATCH (n:{kind}) RETURN n.id AS id ORDER BY n.id"
    rows = g.query(cy).result_set
    ids = [r[0] for r in rows if (not needle) or needle in r[0].lower()][:limit]
    return {"kind": kind, "ids": ids, "returned": len(ids)}


def _impl_blast_radius(g, args: dict) -> dict:
    pod = args["id"]
    hops = min(int(args.get("max_hops", 5)), 6)
    cy = (
        f"MATCH (a {{id:$id}})-[*1..{hops} {{attack_path:1}}]->(t) "
        "WITH t, min(length((a)-[*1..%d {attack_path:1}]->(t))) AS h "
        "RETURN t.id AS id, labels(t)[0] AS kind, h AS hops ORDER BY hops, id LIMIT 20"
    ) % hops
    try:
        rows = g.query(cy, {"id": pod}, timeout=10000).result_set
    except Exception as exc:  # noqa: BLE001
        return {"error": f"query timed out or failed: {exc}", "source": pod}
    return {
        "source": pod,
        "max_hops": hops,
        "reached": [{"id": r[0], "kind": r[1], "hops": r[2]} for r in rows],
    }


def _impl_paths_to(g, args: dict) -> dict:
    source = args["source"]
    target = args.get("target") or "cluster"
    try:
        rows = g.query(
            "MATCH (a {id:$a}), (b {id:$b}) "
            "CALL algo.SPpaths({sourceNode:a, targetNode:b, pathCount:3, "
            "relTypes:['IDENTITY_ASSUME','PERMISSION_DISCOVER','ADMIN_OF',"
            "'POD_EXEC','POD_ATTACH','POD_PATCH','POD_CREATE','TOKEN_LIST',"
            "'TOKEN_BRUTEFORCE','TOKEN_CREATE','TOKEN_STEAL','ROLE_BIND',"
            "'ROLE_ESCALATE','IDENTITY_IMPERSONATE','CE_NSENTER',"
            "'CE_MODULE_LOAD','CE_PRIV_MOUNT','EXPLOIT_HOST_TRAVERSE',"
            "'EXPLOIT_CONTAINERD_SOCK']}) "
            "YIELD path RETURN [n IN nodes(path) | n.id] AS chain, "
            "[r IN relationships(path) | type(r)] AS edges",
            {"a": source, "b": target},
            timeout=10000,
        ).result_set
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "source": source, "target": target}
    paths = []
    for chain, edges in rows:
        steps = []
        for i, node_id in enumerate(chain):
            if i == 0:
                continue
            steps.append({"from": chain[i - 1], "edge": edges[i - 1], "to": node_id})
        paths.append({"steps": steps, "hops": len(edges)})
    return {"source": source, "target": target, "paths": paths}


def _impl_critical_reach(g, _args: dict) -> dict:
    rows = g.query(
        "MATCH (p:Pod)-[*1..6 {attack_path:1}]->(c:Cluster) "
        "WITH p, min(length((p)-[*1..6 {attack_path:1}]->(c))) AS h "
        "RETURN p.id AS id, h ORDER BY h, p.id LIMIT 30",
        timeout=15000,
    ).result_set
    return {"reaching_cluster_admin": [{"id": r[0], "hops": r[1]} for r in rows]}


def _impl_choke_points(g, args: dict) -> dict:
    top = min(int(args.get("top_n", 5)), 10)
    try:
        rows = g.query(
            "CALL algo.betweenness() YIELD node, score "
            "WHERE score > 0 RETURN node.id AS id, labels(node)[0] AS kind, "
            f"score ORDER BY score DESC LIMIT {top}",
            timeout=20000,
        ).result_set
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "top": []}
    return {"top": [{"id": r[0], "kind": r[1], "score": round(float(r[2]), 2)} for r in rows]}


def _impl_simulate_remove(g, snapshot_path, args: dict) -> dict:
    refs = args.get("role_refs") or []
    if not refs:
        return {"error": "role_refs is required (list of 'Kind/name' strings)"}
    try:
        snap = json.loads(open(snapshot_path).read())
    except Exception as exc:  # noqa: BLE001
        return {"error": f"could not read snapshot: {exc}"}
    before = len(sim_logic._identities_reaching(snap, dropped=set()))
    after_total = 0
    details = []
    for ref in refs:
        kind, _, name = ref.partition("/")
        if not kind or not name:
            details.append({"role_ref": ref, "error": "expected 'Kind/name'"})
            continue
        result = sim_logic.simulate(snap, remove_role_ref=ref)
        after_total = result.get("after", {}).get("count", before)
        details.append(
            {
                "role_ref": ref,
                "before": result.get("before", {}).get("count", before),
                "after": after_total,
                "closed": result.get("closed", []),
                "survived": result.get("survived", []),
            }
        )
    return {"removed": refs, "simulations": details, "note": "pod counts refer to identities reaching cluster-admin"}


def _impl_list_findings(g, _args: dict) -> dict:
    findings = paths_logic.findings(g)
    return {"findings": findings[:25], "total": len(findings)}


# ---------- the event stream ----------


def _run_tool(name: str, args: dict, g, snapshot_path: str | None) -> dict:
    try:
        if name == "list_entities":
            return _impl_list_entities(g, args)
        if name == "blast_radius":
            return _impl_blast_radius(g, args)
        if name == "paths_to":
            return _impl_paths_to(g, args)
        if name == "critical_reach":
            return _impl_critical_reach(g, args)
        if name == "choke_points":
            return _impl_choke_points(g, args)
        if name == "simulate_remove":
            if not snapshot_path:
                return {"error": "no snapshot available for simulation"}
            return _impl_simulate_remove(g, snapshot_path, args)
        if name == "list_findings":
            return _impl_list_findings(g, args)
        return {"error": f"unknown tool: {name}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


def _emit_path_from_tool(name: str, result: dict) -> list[dict]:
    """Pull `path` events out of tool results so the UI lights up chains."""
    events = []
    if name == "paths_to":
        for p in result.get("paths") or []:
            steps = p.get("steps") or []
            if steps:
                events.append({"type": "path", "steps": steps})
    return events


def available() -> bool:
    """True when the real agent can run (API key present)."""
    return bool(os.getenv("ANTHROPIC_API_KEY"))


def stream_ask(question: str, tenant: str | None = None) -> Iterator[dict]:
    """Run the agent and yield frontend-shaped events as it works.

    Raises RuntimeError if the API key is missing — the caller should fall
    back to the keyword stand-in in `ask.py` in that case.
    """
    if not available():
        raise RuntimeError("ANTHROPIC_API_KEY not set; agent unavailable")

    # Lazy import so a missing SDK doesn't break the rest of the backend.
    import anthropic

    g = graph_logic.connect_for(tenant)
    snapshot_path = os.getenv("RUNG_SEED_SNAPSHOT")

    client = anthropic.Anthropic()
    messages: list[dict] = [{"role": "user", "content": question}]
    citations: list[str] = []

    for _step in range(_MAX_STEPS):
        resp = client.messages.create(
            model=_MODEL,
            max_tokens=_MAX_TOKENS,
            system=SYSTEM,
            tools=TOOLS,
            messages=messages,
            # adaptive thinking is the default on Opus 5.5; effort=high for
            # multi-tool reasoning. budget_tokens is removed on this family.
            thinking={"type": "adaptive"},
        )

        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        text_blocks = [b for b in resp.content if b.type == "text"]

        # If the model is done thinking, stream its answer and finish.
        if resp.stop_reason != "tool_use" or not tool_uses:
            final_text = "".join(b.text for b in text_blocks).strip()
            for chunk in _tokenize_for_stream(final_text):
                yield {"type": "token", "text": chunk}
            yield {"type": "final", "answer": final_text, "citations": citations}
            return

        # Record the assistant turn before we start answering tool calls —
        # the API requires every tool_use to be paired with a tool_result.
        messages.append({"role": "assistant", "content": resp.content})

        tool_results = []
        for tu in tool_uses:
            yield {"type": "tool", "name": tu.name, "args": dict(tu.input or {})}
            result = _run_tool(tu.name, dict(tu.input or {}), g, snapshot_path)
            citations.extend(_cite_ids(result))
            for ev in _emit_path_from_tool(tu.name, result):
                yield ev
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tu.id,
                    "content": json.dumps(result)[:4000],
                }
            )
        messages.append({"role": "user", "content": tool_results})

    yield {
        "type": "final",
        "answer": "The agent did not converge within its step budget.",
        "citations": citations,
    }


def _tokenize_for_stream(text: str):
    """Chunk the final answer so the UI gets a streamed feel; the model
    isn't a true stream here because we loop over tool_use first."""
    if not text:
        yield ""
        return
    buf = []
    for word in text.split(" "):
        buf.append(word)
        if len(buf) >= 6:
            yield " ".join(buf) + " "
            buf = []
    if buf:
        yield " ".join(buf)


def _cite_ids(result: dict) -> list[str]:
    """Pull entity ids out of a tool result for the `final.citations` list."""
    cited: list[str] = []
    for key in ("id", "source", "target"):
        v = result.get(key)
        if isinstance(v, str) and ("/" in v or v == "cluster"):
            cited.append(v)
    for row in result.get("reached") or []:
        if isinstance(row, dict) and row.get("id"):
            cited.append(row["id"])
    for row in result.get("reaching_cluster_admin") or []:
        if isinstance(row, dict) and row.get("id"):
            cited.append(row["id"])
    for p in result.get("paths") or []:
        for step in p.get("steps") or []:
            for k in ("from", "to"):
                v = step.get(k)
                if isinstance(v, str):
                    cited.append(v)
    # dedupe, preserve order, cap to keep the final event small
    seen = set()
    out = []
    for c in cited:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out[:20]
