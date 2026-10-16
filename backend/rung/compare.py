"""Compare the live graph with a snapshot — the `/compare` endpoint.

`compare` ingests a snapshot into a throwaway graph and reports how the
current graph differs from it: node and edge counts per label, plus a
per-type diff. The live graph is never touched.
"""
import os


def compare(current_graph: str, snapshot_path: str) -> dict:
    """Compare the current graph with the snapshot, both fully counted.

    Returns {"current": counts, "compared": counts, "diff": {...}}.
    """
    from falkordb import FalkorDB

    from .ingest import _counts, ingest

    host = os.getenv("FALKORDB_HOST", "localhost")
    port = int(os.getenv("FALKORDB_PORT", "6380"))
    scratch = f"{current_graph}-compare"

    compared = FalkorDB(host=host, port=port).select_graph(scratch)
    ingest(snapshot_path, graph_name=scratch)

    current = _counts(_graph(current_graph))
    other = _counts(compared)
    diff = {}
    for key in sorted(set(current) | set(other)):
        if key == "graph":
            continue
        delta = other.get(key, 0) - current.get(key, 0)
        if delta:
            diff[key] = delta
    return {
        "current": current,
        "compared": other,
        "diff": diff,
    }


def _graph(current_graph: str):
    from falkordb import FalkorDB

    host = os.getenv("FALKORDB_HOST", "localhost")
    port = int(os.getenv("FALKORDB_PORT", "6380"))
    return FalkorDB(host=host, port=port).select_graph(current_graph)


def compare_thesis(tenant: str) -> dict:
    """The thesis-prover: the same graph counted two ways.

    `naive_reachable`: pods that reach cluster-admin treating every edge as
    walkable — the model every other tool uses, where SCHEDULED_ON means
    "owns the node" and permission equals capability.

    `rung_reachable`: pods that reach cluster-admin via `attack_path:1`
    only — Rung's precondition-gated answer.

    Token counts: `naive_token_list_edges` is the number of (identity with
    `secrets:list` discoverable, SA in scope) pairs — what KubeHound-style
    counting produces. `rung_token_list_edges` is the derived TOKEN_LIST
    edges that survive the real-token-Secret precondition.
    """
    g = _graph(f"rung:{tenant}")

    def _one(cypher, timeout=15000):
        rows = g.query(cypher, timeout=timeout).result_set
        return rows[0][0] if rows and rows[0] else 0

    # Naive: every edge walkable, SCHEDULED_ON included.
    naive_reach = _one(
        "MATCH (p:Pod)-[*1..6]->(c:Cluster) RETURN count(DISTINCT p)"
    )
    # Rung: attack_path:1 only.
    rung_reach = _one(
        "MATCH (p:Pod)-[*1..6 {attack_path:1}]->(c:Cluster) RETURN count(DISTINCT p)"
    )

    # Token: the naive count is what a tool without the real-Secret gate
    # would emit — one TOKEN_LIST per (lister, projected SA). Equivalently:
    # how many TOKEN_LIST edges would exist if we dropped the token-Secret
    # precondition. Approximated by counting the full cross-product of
    # (identities with any `secrets:list` grant) and (projected SAs on the
    # cluster), without the real-Secret filter.
    projected_sas = _one("MATCH (i:Identity) WHERE i.id STARTS WITH 'sa/' RETURN count(i)")
    secrets_list_count = _one(
        "MATCH (i:Identity)-[:PERMISSION_DISCOVER]->(p:PermSet) "
        "WHERE p.rules CONTAINS 'secrets' AND p.rules CONTAINS 'list' "
        "RETURN count(DISTINCT i)"
    )
    naive_tokens = secrets_list_count * projected_sas
    rung_tokens = _one("MATCH ()-[r:TOKEN_LIST]->() RETURN count(r)")

    return {
        "naive_reachable": int(naive_reach),
        "rung_reachable": int(rung_reach),
        "naive_token_list_edges": int(naive_tokens),
        "rung_token_list_edges": int(rung_tokens),
    }
