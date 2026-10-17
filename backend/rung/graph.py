"""Graph queries as plain functions — the logic `app.main` calls, never HTTP.

`subgraph` collects the part of the graph reachable from a set of start
nodes, across every edge type (structural and attack).

Connections are pooled: one FalkorDB client per (host, port) is reused by
every call and every thread (the redis-py pool underneath is thread-safe),
so a request pays for a query, not for a fresh TCP handshake to FalkorDB.
"""
import os
import threading
from collections import deque

_clients = {}
_clients_lock = threading.Lock()


def _client():
    """The shared FalkorDB client for the configured host/port."""
    from falkordb import FalkorDB

    key = (_host(), _port())
    with _clients_lock:
        client = _clients.get(key)
        if client is None:
            client = FalkorDB(host=key[0], port=key[1])
            _clients[key] = client
        return client


def graph_name():
    return os.getenv("FALKORDB_GRAPH", "rung:kind-graphhacks")


def connect():
    """A connection to the default graph (`FALKORDB_GRAPH`)."""
    return connect_to(graph_name())


def connect_to(name: str | None = None):
    """A connection to an explicitly named graph, over the shared client."""
    return _client().select_graph(name or graph_name())


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
    return connect_to(graph_name_for(tenant))


def list_graphs():
    """Every graph this FalkorDB holds (names only), via `GRAPH.LIST`."""
    return _client().list_graphs()


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
    """The nodes and edges reachable from `start_ids` (BFS, all edge types).

    One edge scan: the adjacency built for the walk is reused to collect the
    edges inside the reached set, in a deterministic order.
    """
    adjacency = _adjacency(g)
    seen = set()
    queue = deque(start_ids)
    while queue:
        node_id = queue.popleft()
        if node_id in seen:
            continue
        seen.add(node_id)
        for edge in adjacency.get(node_id, ()):
            if edge["to"] not in seen:
                queue.append(edge["to"])
    inside = [
        edge
        for from_id in sorted(seen)
        for edge in sorted(
            adjacency.get(from_id, ()), key=lambda e: (e["to"], e["type"])
        )
        if edge["to"] in seen
    ]
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
