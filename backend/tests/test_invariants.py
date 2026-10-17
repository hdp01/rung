"""The invariant suite — the handful of truths that must hold after EVERY task.

The assertion harness (`test_assertions.py`) proves the derivation rules are
*wired correctly*. This file proves the graph the rules produce still *means
the right thing*: the discriminating reachability band, the two-number thesis,
the hero chain, and the three edges that must never become walkable. It's the
cheap gate we run between every change — if any of these drift, the demo's
whole story is wrong even when every unit test passes.

Hermetic, like the assertion harness: the committed snapshot is ingested into
a dedicated graph (`rung:test-invariants`) that the tenant list filters out,
so a test run never touches the live demo graph.
"""
import os
import pathlib

import pytest
from falkordb import FalkorDB

from rung.compare import compare_thesis
from rung.ingest import ingest

SNAPSHOT = pathlib.Path(__file__).resolve().parents[1] / "data" / "demo-snapshot.json"
TENANT = "test-invariants"
GRAPH = f"rung:{TENANT}"

ATTACK_RELS = [
    "IDENTITY_ASSUME", "PERMISSION_DISCOVER", "ADMIN_OF",
    "POD_EXEC", "POD_ATTACH", "POD_PATCH", "POD_CREATE",
    "TOKEN_LIST", "TOKEN_BRUTEFORCE", "TOKEN_CREATE", "TOKEN_STEAL",
    "ROLE_BIND", "ROLE_ESCALATE", "IDENTITY_IMPERSONATE",
    "CE_NSENTER", "CE_MODULE_LOAD", "CE_PRIV_MOUNT",
    "EXPLOIT_HOST_TRAVERSE", "EXPLOIT_CONTAINERD_SOCK",
]

# Edges that exist for display/structural reasons and must never be walked.
STRUCTURAL_RELS = ["CONTAINED_IN", "SCHEDULED_ON", "MOUNTS"]


@pytest.fixture(scope="module")
def g():
    """Ingest the real snapshot into a dedicated graph and hand out a handle."""
    if not SNAPSHOT.exists():
        pytest.skip(f"snapshot missing: {SNAPSHOT}")
    os.environ["FALKORDB_GRAPH"] = GRAPH
    try:
        ingest(str(SNAPSHOT), stats=False)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"ingest failed, likely no FalkorDB: {exc}")
    host = os.getenv("FALKORDB_HOST", "localhost")
    port = int(os.getenv("FALKORDB_PORT", "6380"))
    yield FalkorDB(host=host, port=port).select_graph(GRAPH)


def _one(g, cypher, timeout=15000):
    rows = g.query(cypher, timeout=timeout).result_set
    return rows[0][0] if rows and rows[0] else 0


# ---------------------------------------------------------------------------
# INV-1 — the headline number stays discriminating.
# ---------------------------------------------------------------------------
def test_inv1_reachability_band(g):
    """If pods reaching cluster-admin via attack_path:1 (<=5 hops) drifts out
    of [6, 9], the demo is lying: near-total means a precondition leaked,
    near-zero means the graph lost its edges."""
    reaching = _one(
        g, "MATCH (p:Pod)-[*1..5 {attack_path:1}]->(c:Cluster) RETURN count(DISTINCT p)"
    )
    assert 6 <= reaching <= 9, (
        f"reachability {reaching} outside the honest band [6, 9] — "
        f"a precondition leaked (too high) or edges were lost (too low)"
    )


# ---------------------------------------------------------------------------
# INV-2 — the two-number thesis, exactly as /compare reports it.
# ---------------------------------------------------------------------------
def test_inv2_thesis_numbers(g):
    """The product is one sentence: '16 pods reach admin if you trust every
    edge; 6 do once you gate it.' These are the numbers a judge sees, computed
    the same way the /compare endpoint computes them (`compare_thesis`)."""
    t = compare_thesis(TENANT)
    assert t["naive_reachable"] == 16, f"naive_reachable drifted: {t['naive_reachable']}"
    assert t["rung_reachable"] in (6, 7), f"rung_reachable drifted: {t['rung_reachable']}"
    assert t["naive_token_list_edges"] >= 1000, (
        f"naive token count collapsed: {t['naive_token_list_edges']} — "
        f"the over-report the demo contrasts against is gone"
    )
    assert t["rung_token_list_edges"] in (15, 16, 17), (
        f"gated token count drifted: {t['rung_token_list_edges']}"
    )


# ---------------------------------------------------------------------------
# INV-3 — the hero chain exists, and it escapes the container.
# ---------------------------------------------------------------------------
def test_inv3_hero_chain(g):
    """ci-runner -> cluster must exist AND pass through a container escape
    (CE_* / EXPLOIT_*). If the escape stops firing, the demo's opening beat
    becomes a boring RBAC chain."""
    rels = ",".join(f"'{r}'" for r in ATTACK_RELS)
    rows = g.query(
        f"""
        MATCH p = (:Pod {{id:'pod/jenkins/ci-runner'}})-[*1..5 {{attack_path:1}}]->(:Cluster)
        WHERE ALL(r IN relationships(p) WHERE type(r) IN [{rels}])
        RETURN [r IN relationships(p) | type(r)] AS edges
        LIMIT 20
        """,
        timeout=15000,
    ).result_set
    assert rows, "ci-runner -> cluster: the signature path is dead"
    assert any(
        any(e.startswith(("CE_", "EXPLOIT_")) for e in row[0]) for row in rows
    ), "hero chain exists but never escapes the container"


# ---------------------------------------------------------------------------
# INV-4 — ownership is context, never an attack edge.
# ---------------------------------------------------------------------------
def test_inv4_ownership_edges_not_walkable(g):
    """Ownership edges (BELONGS_TO / OWNED_BY, added by the attribution work)
    answer 'who owns this', not 'who can reach this'. They must never be
    walkable, or a pod would 'reach' admin merely by being owned by a team.
    Trivially true before attribution lands — that's the point: it's the guard
    that keeps attribution from regressing the thesis when it arrives."""
    walkable = _one(
        g,
        "MATCH ()-[r:BELONGS_TO|OWNED_BY]->() WHERE r.attack_path = 1 RETURN count(r)",
    )
    assert walkable == 0, f"{walkable} ownership edge(s) are attack-walkable"


# ---------------------------------------------------------------------------
# INV-5 — SCHEDULED_ON is never walkable (the spike bug).
# ---------------------------------------------------------------------------
def test_inv5_scheduled_on_never_walkable(g):
    """The original spike walked SCHEDULED_ON and got 16/16 pods to admin by
    inheriting their node's authority. A pod scheduled on a node does not own
    it. This must stay zero forever."""
    walkable = _one(
        g, "MATCH ()-[r:SCHEDULED_ON]->() WHERE r.attack_path = 1 RETURN count(r)"
    )
    assert walkable == 0, "SCHEDULED_ON became walkable — the spike bug is back"


# ---------------------------------------------------------------------------
# INV-6 — no silent downgrade: every attack edge keeps its flag.
# ---------------------------------------------------------------------------
def test_inv6_no_silent_downgrade(g):
    """attack_path on relationships is how the agent and the UI decide what's
    walkable. If any attack edge loses the flag the UI dims it and the agent
    refuses to walk it — a silent product bug that no exception reports.
    Structural edges are the mirror image: they must carry zero."""
    rows = g.query("MATCH ()-[r]->() RETURN type(r), count(r), sum(r.attack_path)").result_set
    seen = {row[0]: (row[1], row[2] or 0) for row in rows}

    downgraded = {
        rel: (total, walkable)
        for rel in ATTACK_RELS
        for total, walkable in [seen.get(rel, (0, 0))]
        if total and walkable != total
    }
    assert not downgraded, f"attack edge types lost attack_path:1: {downgraded}"

    leaked = {
        rel: walkable
        for rel in STRUCTURAL_RELS
        for total, walkable in [seen.get(rel, (0, 0))]
        if walkable
    }
    assert not leaked, f"structural edge types became walkable: {leaked}"
