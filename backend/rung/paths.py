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


def _identity_ids(g):
    """Every identity node id (`sa/...`, `user/...`, `group/...`, ...)."""
    res = g.query("MATCH (n:Identity) RETURN n.id")
    for (node_id,) in res.result_set:
        yield node_id


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
    """Identity ids that can reach the cluster, with their paths."""
    adjacency = attack_adjacency(g)
    out = []
    for node_id in sorted(_identity_ids(g)):
        found = paths_to(g, node_id, adjacency=adjacency)
        if any(_reaches_cluster(path) for path in found):
            out.append(
                {
                    "identity": node_id,
                    "paths": found,
                }
            )
    return out


def reaching_admin(g):
    """Same as `identities_reaching_admin` — a more compact name."""
    return identities_reaching_admin(g)


def _reaches_cluster(path):
    return path["nodes"][-1] == "cluster"


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

    Every route that reaches cluster-admin is reported as `NEW`: Rung computes
    what is walkable *now*, while remembering what was RESOLVED is future
    work (cross-snapshot memory). `status` and the optional fields (`route`,
    `target`, `title`, `note`, `previous_status`, ...) are consumed by the
    frontend's findings panel.
    """
    out = []
    for entry in identities_reaching_admin(g):
        identity = entry["identity"]
        for route_path in entry["paths"]:
            nodes = route_path["nodes"]
            edge_types = ",".join(step["edge"] for step in route_path["edges"])
            out.append(
                {
                    "status": "NEW",
                    "route": " → ".join(nodes),
                    "target": nodes[-1],
                    "title": f"Cluster-admin reachable from {identity}",
                    "note": f"walks {edge_types}",
                }
            )
    return out


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
