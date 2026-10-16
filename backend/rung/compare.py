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
