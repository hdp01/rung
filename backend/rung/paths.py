"""Path enumeration and findings — plain functions over the graph.

`paths_to` enumerates the escalation paths that start at an identity and end
at the cluster (the `Cluster` node). `findings` summarises what the graph
says about what an attacker can reach, and returns one entry per tracked
route with a regression-detector status.

Every function works on the graph it is given: the caller selects the
tenant's graph (`graph.connect_for(tenant)`), and everything in that graph —
including the cluster-scoped identities and roles its snapshot references —
is in scope. There is no second, per-node filter to get wrong.
"""
from . import graph

_MAX_PATH_LEN = 12  # safety valve: a path may traverse at most this many edges


def attack_adjacency(g):
    """Map node id -> the attack edges leaving it (only attack_path=1 edges).

    Built once per query so walking many identities scans the graph's edges
    a single time instead of once per identity.
    """
    adjacency = {}
    for edge in graph.edges(g):
        if edge["attack_path"] == 1:
            adjacency.setdefault(edge["from"], []).append(edge)
    return adjacency


def paths_to(g, start_id, adjacency=None):
    """All escalation paths from `start_id` to the cluster, as a list.

    Only edges marked attack_path=1 are walked: SCHEDULED_ON and the other
    display-only structural edges never appear on a path. Each path is
    {"nodes": [...], "edges": [...]} where `nodes` are node ids in order and
    `edges` the typed edges traversed. A path that reaches the Cluster node
    is an escalation; paths are only reported up to _MAX_PATH_LEN edges.

    `adjacency` may be a prebuilt map (see `attack_adjacency`) so callers
    that walk many identities scan the graph's edges only once.
    """
    if adjacency is None:
        adjacency = attack_adjacency(g)

    results = []
    stack = [([start_id], [])]  # path of node ids, list of edges
    while stack:
        node_path, traversed = stack.pop()
        current = node_path[-1]
        if len(traversed) > _MAX_PATH_LEN:
            continue
        if current == "cluster":
            results.append(_path_view(node_path, traversed))
            continue
        for edge in adjacency.get(current, []):
            nxt = edge["to"]
            if nxt in node_path:
                continue
            stack.append((node_path + [nxt], traversed + [edge]))
    results.sort(key=lambda p: len(p["edges"]))
    return results


def identities_reaching_admin(g):
    """Identity ids that can reach the cluster, with a canonical route each.

    One shortest witness per (identity, admin grant) instead of every simple
    path: the attack graph is combinatorial (the demo cluster enumerates
    350k paths to the reach limit), and a caller that needs "who reaches
    admin, and how" wants a route per identity, not the cross-product of
    every interchangeable victim. `findings.canonical_routes` computes the
    witnesses with a single BFS per source.
    """
    from . import findings as detector

    grouped = {}
    for route in detector.canonical_routes(g):
        source = route["source"]
        if source.startswith("pod/"):
            # /paths speaks identity -> cluster; pods are the detector's own
            # sources and would duplicate their service accounts here.
            continue
        entry = grouped.setdefault(source, {"identity": source, "paths": []})
        entry["paths"].append(
            {
                "nodes": route["nodes"],
                "edges": [
                    {
                        "from": edge["from"],
                        "edge": edge["type"],
                        "to": edge["to"],
                        "attack_path": edge["attack_path"],
                    }
                    for edge in route["edges"]
                ],
            }
        )
    return [grouped[key] for key in sorted(grouped)]


def reaching_admin(g):
    """Same as `identities_reaching_admin` — a more compact name."""
    return identities_reaching_admin(g)


def _path_view(node_path, traversed):
    return {
        "nodes": node_path,
        "edges": [
            {
                "from": edge["from"],
                "edge": edge["type"],
                "to": edge["to"],
                "attack_path": edge["attack_path"],
            }
            for edge in traversed
        ],
    }


def findings(g):
    """One entry per tracked route, each carrying a detector status.

    This is the read side of the regression detector: the statuses and
    fingerprints live in `:Finding` nodes written by `rung.findings` on each
    ingest. Graphs ingested before the detector existed have no memory, so
    they fall back to a live NEW-only view instead of an empty panel.
    """
    from . import findings as detector

    tracked = detector.list_findings(g)
    return tracked if tracked else detector.ephemeral_findings(g)


def attack_edge_counts(g):
    """Counts of each derived (attack) edge type in this graph.

    Only the five derived types are reported — structural edges (MOUNTS,
    CONTAINED_IN, ...) are not attack edges and never appear here.
    """
    counts = {
        "POD_EXEC": 0,
        "POD_CREATE": 0,
        "TOKEN_LIST": 0,
        "TOKEN_STEAL": 0,
        "ROLE_BIND": 0,
    }
    for edge in graph.edges(g):
        if edge["type"] in counts:
            counts[edge["type"]] += 1
    return counts
