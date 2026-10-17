"""Rung MCP server — exposes all graph-agent tools over the MCP protocol.

Run with:
    FALKORDB_GRAPH=rung:kind-graphhacks uv run python -m rung.mcp_server

Or test with Inspector:
    npx @modelcontextprotocol/inspector uv run python -m rung.mcp_server

Tools exposed (19 total, matching agent.py TOOLS):
    list_entities, blast_radius, paths_to, critical_reach, choke_points,
    simulate_remove, list_findings, list_snapshots,
    who_owns, what_belongs_to, who_to_contact, propose_policy,
    compare_baseline, accept_risk, executive_brief,
    attack_trend, attack_rank, snapshot_diff, exploit_poc
"""
from __future__ import annotations

import os

from fastmcp import FastMCP

from . import agent as agent_logic
from . import graph as graph_logic

mcp = FastMCP("rung")


def _g():
    return graph_logic.connect()


def _snap() -> str | None:
    return os.getenv("RUNG_SEED_SNAPSHOT")


# ---------------------------------------------------------------------------
# core graph tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_entities(kind: str, name_contains: str = "", limit: int = 25) -> dict:
    """List entities of a given kind, optionally filtered by name substring.

    kind: one of Pod, Container, Identity, PermSet, Volume, Node, Cluster.
    """
    return agent_logic._run_tool(
        "list_entities",
        {"kind": kind, "name_contains": name_contains, "limit": limit},
        _g(), _snap(),
    )


@mcp.tool()
def blast_radius(id: str, max_hops: int = 5) -> dict:
    """Everything reachable from this entity via attack-walkable edges, with hop count.

    Use for 'this pod is compromised — what can it reach?'.
    """
    return agent_logic._run_tool(
        "blast_radius", {"id": id, "max_hops": max_hops}, _g(), _snap()
    )


@mcp.tool()
def paths_to(source: str, target: str = "cluster", max_hops: int = 8) -> dict:
    """The attack chain(s) from source to target (default: cluster-admin).

    Returns ordered steps with edge type on each hop.
    """
    return agent_logic._run_tool(
        "paths_to",
        {"source": source, "target": target, "max_hops": max_hops},
        _g(), _snap(),
    )


@mcp.tool()
def critical_reach() -> dict:
    """Every pod that reaches cluster-admin, with shortest-hop count."""
    return agent_logic._run_tool("critical_reach", {}, _g(), _snap())


@mcp.tool()
def choke_points(top_n: int = 5) -> dict:
    """Highest-leverage fix: nodes whose removal closes the most attack chains."""
    return agent_logic._run_tool("choke_points", {"top_n": top_n}, _g(), _snap())


@mcp.tool()
def simulate_remove(role_refs: list[str]) -> dict:
    """Simulate removing role bindings: what closes and what survives?

    role_refs: list of 'Kind/name' strings, e.g. ['ClusterRole/cluster-admin'].
    """
    return agent_logic._run_tool(
        "simulate_remove", {"role_refs": role_refs}, _g(), _snap()
    )


# ---------------------------------------------------------------------------
# regression detector tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_findings() -> dict:
    """Regression-detector findings: route + target + status (NEW|RESOLVED|ACCEPTED|REGRESSED)."""
    return agent_logic._run_tool("list_findings", {}, _g(), _snap())


@mcp.tool()
def list_snapshots() -> dict:
    """Snapshot history the detector diffs (newest first) with per-snapshot counts."""
    return agent_logic._run_tool("list_snapshots", {}, _g(), _snap())


# ---------------------------------------------------------------------------
# Track 03 ownership tools
# ---------------------------------------------------------------------------

@mcp.tool()
def who_owns(id: str) -> dict:
    """Attribution for a pod or service-account: returns app, team, Helm release.

    Honest about missing data — returns null fields rather than guessing.
    id: entity id, e.g. 'pod/jenkins/ci-runner' or 'sa/argocd/argocd-application-controller'.
    """
    return agent_logic._run_tool("who_owns", {"id": id}, _g(), _snap())


@mcp.tool()
def what_belongs_to(id: str) -> dict:
    """List every entity (pods, SAs) that belongs to a given app or team.

    id: app id like 'app/jenkins' or team id like 'team/platform'.
    """
    return agent_logic._run_tool("what_belongs_to", {"id": id}, _g(), _snap())


@mcp.tool()
def who_to_contact(id: str) -> dict:
    """Who to contact about a risk: team label or owning app when no team label is present.

    id: entity id, e.g. 'pod/jenkins/ci-runner'.
    """
    return agent_logic._run_tool("who_to_contact", {"id": id}, _g(), _snap())


# ---------------------------------------------------------------------------
# W1 policy proposal tool
# ---------------------------------------------------------------------------

@mcp.tool()
def propose_policy(
    finding_id: str = "",
    path_steps: list[str] | None = None,
) -> dict:
    """Propose a Kyverno ClusterPolicy that closes the deepest attack edge in a chain.

    Pass finding_id (route fingerprint from list_findings) OR
    path_steps (edge type list, e.g. ['CE_MODULE_LOAD', 'TOKEN_STEAL', 'ADMIN_OF']).

    Returns kyverno_yaml (ready-to-apply YAML) and rationale.
    Covered edges: CE_PRIV_MOUNT, CE_NSENTER, CE_MODULE_LOAD, EXPLOIT_CONTAINERD_SOCK.
    """
    return agent_logic._run_tool(
        "propose_policy",
        {"finding_id": finding_id, "path_steps": path_steps or []},
        _g(), _snap(),
    )


# ---------------------------------------------------------------------------
# W6 baseline comparison + accept_risk
# ---------------------------------------------------------------------------

@mcp.tool()
def compare_baseline() -> dict:
    """Compare the current cluster against the hardened secure baseline (rung_reachable=0).

    Returns how many pods are at risk now vs the baseline, which pods they are,
    and concrete remediation hints per attack edge type.
    """
    return agent_logic._run_tool("compare_baseline", {}, _g(), _snap())


@mcp.tool()
def accept_risk(finding_id: str, note: str = "") -> dict:
    """Accept the risk behind a finding — record it as a known, tolerated exposure.

    On the next snapshot ingest, routes still traversing the accepted controls
    stay ACCEPTED; a new route that bypasses them becomes REGRESSED.

    finding_id: route fingerprint from list_findings.
    note: why this risk is accepted, e.g. 'Jenkins needs privileged for Docker builds'.
    """
    return agent_logic._run_tool(
        "accept_risk",
        {"finding_id": finding_id, "note": note},
        _g(), _snap(),
    )


@mcp.tool()
def executive_brief() -> dict:
    """CISO-level security brief: attack surface, highest-leverage fix, open findings.

    Combines critical_reach, choke_points, list_findings, and compare_baseline
    into a three-paragraph summary. No arguments required.
    """
    return agent_logic._run_tool("executive_brief", {}, _g(), _snap())


@mcp.tool()
def attack_trend() -> dict:
    """How the attack surface has changed across every ingested snapshot.

    Returns per-snapshot route counts (new/resolved/accepted/regressed) in
    chronological order and a direction label (increasing/decreasing/stable).
    Use to answer 'is the cluster getting better or worse over time?'
    """
    return agent_logic._run_tool("attack_trend", {}, _g(), _snap())


@mcp.tool()
def attack_rank(top_n: int = 10) -> dict:
    """PageRank over attack-path edges only — which node is most central to all attacks?

    Complements choke_points (betweenness): attack_rank finds the most traversed
    nodes across all chains; choke_points finds the single best removal target.
    top_n: number of top-ranked nodes to return (max 20).
    """
    return agent_logic._run_tool("attack_rank", {"top_n": top_n}, _g(), _snap())


@mcp.tool()
def snapshot_diff() -> dict:
    """Natural-language diff between the two most recent snapshots.

    Returns how many routes appeared, resolved, regressed, or were accepted,
    plus a one-paragraph narrative. Use for 'what changed since the last scan?'
    """
    return agent_logic._run_tool("snapshot_diff", {}, _g(), _snap())


@mcp.tool()
def exploit_poc(finding_id: str = "", path_steps: list | None = None) -> dict:
    """Generate the attacker-command playbook for an attack chain.

    Pass finding_id (from list_findings) OR path_steps (list of {from,edge,to}).
    Returns per-edge kubectl/curl/nsenter commands, the identity each hop needs,
    and the cleanup to undo any artifacts. For authorized defensive testing only.
    """
    return agent_logic._run_tool(
        "exploit_poc",
        {"finding_id": finding_id, "path_steps": path_steps or []},
        _g(), _snap(),
    )


if __name__ == "__main__":
    mcp.run()
