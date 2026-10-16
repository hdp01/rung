"""Graph queries as plain functions — the logic `app.main` calls, never HTTP.

`subgraph` collects the part of the graph reachable from a set of start
nodes, across every edge type (structural and attack).
"""
import os


def graph_name():
    return os.getenv("FALKORDB_GRAPH", "rung:kind-graphhacks")


def connect():
    from falkordb import FalkorDB

    return FalkorDB(host=_host(), port=_port()).select_graph(graph_name())


def graph_name_for(tenant: str | None = None) -> str:
    """Graph to read or write: `rung:<tenant>` when a tenant is selected.

    Every graph the API exposes is a slice of the cluster. Without a tenant
    the default graph (`FALKORDB_GRAPH`) is used, which keeps the seeded
    demo and every existing caller working unchanged.
    """
    if tenant:
        return f"rung:{tenant}"
    return graph_name()


def connect_for(tenant: str | None = None):
    """A connection to the graph selected by `tenant` (see `graph_name_for`)."""
    from falkordb import FalkorDB

    return FalkorDB(host=_host(), port=_port()).select_graph(graph_name_for(tenant))


def list_graphs():
    """Every graph this FalkorDB holds (names only), via `GRAPH.LIST`."""
    from falkordb import FalkorDB

    return FalkorDB(host=_host(), port=_port()).list_graphs()


def _host():
    return os.getenv("FALKORDB_HOST", "localhost")


def _port():
    return int(os.getenv("FALKORDB_PORT", "6380"))


def edges(g):
    """Every edge in the graph: (from_id, to_id, type, attack_path)."""
    res = g.query(
        "MATCH (a)-[r]->(b) RETURN a.id AS from_id, b.id AS to_id, "
        "type(r) AS type, r.attack_path AS attack_path"
    )
    for from_id, to_id, rel_type, attack_path in res.result_set:
        yield {
            "from": from_id,
            "to": to_id,
            "type": rel_type,
            "attack_path": attack_path,
        }


def _adjacency(g):
    """Map node id -> [(edge, ...)] following every edge type."""
    out = {}
    for edge in edges(g):
        out.setdefault(edge["from"], []).append(edge)
    return out


def subgraph(g, start_ids):
    """The nodes and edges reachable from `start_ids` (BFS, all edge types)."""
    start = list(start_ids)
    adjacency = _adjacency(g)
    seen = set()
    queue = list(start)
    while queue:
        node_id = queue.pop(0)
        if node_id in seen:
            continue
        seen.add(node_id)
        for edge in adjacency.get(node_id, ()):
            if edge["to"] not in seen:
                queue.append(edge["to"])
    # Collect the edges inside the subgraph.
    inside = []
    for edge in edges(g):
        if edge["from"] in seen and edge["to"] in seen:
            inside.append(edge)
    nodes = [{"id": node_id} for node_id in sorted(seen)]
    return {"nodes": nodes, "edges": inside}


def _specific_label(labels):
    """The concrete type label of an entity node: `Pod`, not `Entity`.

    FalkorDB reports every alias a node carries; `Entity` itself is always
    there, the next alias is the node's own type label.
    """
    for label in labels:
        if label and label != "Entity":
            return label
    return None


def node_view(g):
    """Every entity node as {id, label, kind, props} — what the UI renders."""
    res = g.query("MATCH (n:Entity) RETURN n.id AS node_id, n")
    out = []
    for row in res.result_set:
        node_id, node = row
        label = _specific_label(node.labels)
        if label is None:
            continue
        props = dict(node.properties or {})
        out.append(
            {
                "id": node_id,
                "label": label,
                "kind": label,
                "props": props,
            }
        )
    out.sort(key=lambda n: n["id"])
    return out


def edge_view(g):
    """Every edge as {source, target, type, attack_path} — the UI's edge shape."""
    res = g.query(
        "MATCH (a)-[r]->(b) RETURN a.id AS source, b.id AS target, "
        "type(r) AS type, r.attack_path AS attack_path"
    )
    out = []
    for row in res.result_set:
        source, target, rel_type, attack_path = row
        out.append(
            {
                "source": source,
                "target": target,
                "type": rel_type,
                "attack_path": attack_path,
            }
        )
    out.sort(key=lambda e: (e["source"], e["type"], e["target"]))
    return out
