"""Rung backend API — serves graph stats, FalkorDB health, and ingestion.

HTTP is thin: every endpoint delegates to the plain functions in `rung`
(graph, paths, sim, ...), which never see a request.
"""

import json
import logging
import os
import tempfile
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import StreamingResponse

from rung import ask as ask_logic
from rung import attck
from rung import findings as findings_logic
from rung import graph as graph_logic
from rung import paths as paths_logic
from rung.compare import compare, compare_thesis
from rung.ingest import ingest

log = logging.getLogger("rung.api")

# Every edge type `rung ingest` can create: the six structural ones plus the
# five derived attack edges.
EDGE_TYPES = [
    "CONTAINED_IN",
    "SCHEDULED_ON",
    "MOUNTS",
    "IDENTITY_ASSUME",
    "PERMISSION_DISCOVER",
    "ADMIN_OF",
    "POD_EXEC",
    "POD_CREATE",
    "TOKEN_LIST",
    "TOKEN_STEAL",
    "ROLE_BIND",
]

@asynccontextmanager
async def _lifespan(_app):
    """Startup/shutdown: seed the demo graph, then serve.

    `seed_graph` is defined below (module fully loaded before startup runs).
    """
    seed_graph()
    yield


app = FastAPI(title="Rung API", version="0.1.0", lifespan=_lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# The graph payload is ~400 KB of JSON; gzip cuts it by ~10x on the wire.
app.add_middleware(GZipMiddleware, minimum_size=1024)


def _query(g, cypher, params=None):
    return g.query(cypher, params or {})


def _connect(tenant=None):
    """A connection to the graph selected by `tenant`."""
    return graph_logic.connect_for(tenant)


def _counts_graph(tenant=None):
    return graph_logic.connect_to(graph_logic.graph_name_for(tenant))


def _seed_path() -> str | None:
    candidates = [
        os.getenv("RUNG_SEED_SNAPSHOT"),
        "data/demo-snapshot.json",
        "/app/data/demo-snapshot.json",
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


def _graph_name() -> str:
    return os.getenv("FALKORDB_GRAPH", "rung:kind-graphhacks")


def _count_labels(g):
    """Counts per node label in this graph — one grouped query.

    A node can carry several labels (`Entity` plus its own type); the grouped
    query counts each label in a single server-side pass instead of one query
    per label, which matters once every tenant is counted for `/tenants`.
    """
    counts = {
        "Pod": 0,
        "Container": 0,
        "Identity": 0,
        "PermSet": 0,
        "Volume": 0,
        "Node": 0,
        "Cluster": 0,
        # The common `Entity` label counts every node above (see ingest._counts).
        "Entity": 0,
    }
    try:
        res = _query(g, "MATCH (n) UNWIND labels(n) AS label RETURN label, count(*)")
    except Exception:  # noqa: BLE001 — a graph that does not exist yet reads as zero
        return counts
    for label, count in res.result_set:
        if label in counts:
            counts[label] = count
    return counts


def _count_edges(g):
    """Counts per edge type in this graph — one grouped query, not a scan."""
    counts = {edge_type: 0 for edge_type in EDGE_TYPES}
    try:
        res = _query(g, "MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS c")
    except Exception:  # noqa: BLE001 — a graph that does not exist yet reads as zero
        return counts
    for rel_type, count in res.result_set:
        counts[rel_type] = count
    return counts


def _counts(tenant=None):
    """Node and edge counts of the tenant's graph (the default graph without one)."""
    g = _connect(tenant)
    counts = _count_labels(g)
    counts.update(_count_edges(g))
    return counts


def _falkordb_ok() -> bool:
    try:
        g = _counts_graph()
        g.query("RETURN 1")
        return True
    except Exception:  # noqa: BLE001 — any failure means "not connected"
        return False


def seed_graph() -> None:
    """Ingest the bundled demo snapshot on startup (best-effort)."""
    path = _seed_path()
    if path is None:
        return
    try:
        ingest(path, stats=False)
    except Exception as exc:  # noqa: BLE001 — seeding must not take down the API
        log.warning("seed skipped: %s", exc)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "falkordb": "connected" if _falkordb_ok() else "disconnected",
        "graph": _graph_name(),
    }


@app.get("/stats")
def stats(tenant: str | None = None):
    """Counts per label and edge type; scoped to a tenant when one is given."""
    try:
        counts = _counts(tenant)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return counts


_NODE_DESCRIPTIONS = {
    "Pod": "One node per pod collected from the cluster (pod/<ns>/<name>).",
    "Container": "One node per container found inside those pods (container/<ns>/<pod>/<name>).",
    "Identity": "ServiceAccounts (and Users/Groups referenced by bindings) that can act in the cluster (sa/<ns>/<name>, user/<name>, group/<name>).",
    "PermSet": "One node per (role, scope) pair granted by a binding, holding that role's rules (<rolekind>/<name>@<scope>).",
    "Volume": "Host-path volumes mounted by pods (vol/<ns>/<pod>/<name>).",
    "Node": "Kubernetes node a pod is scheduled on (node/<name>).",
    "Cluster": "Single root node for the whole cluster (`cluster`); cluster-admin PermSets connect here.",
    "Entity": "Common label carried by every node above so re-ingest can rebuild them without touching memory nodes.",
}

_EDGE_DESCRIPTIONS = {
    "CONTAINED_IN": "Container → Pod. A container always runs inside its pod. Display + structural (not an attack edge).",
    "SCHEDULED_ON": "Pod → Node. Where the pod runs. Display only; never treated as an attack edge.",
    "MOUNTS": "Container → Volume. The container mounts that host volume, exposing host paths.",
    "IDENTITY_ASSUME": "Pod → Identity. The pod runs as its service account and can use its token.",
    "PERMISSION_DISCOVER": "Identity → PermSet. A binding grants that identity the permissions of that role/scope.",
    "ADMIN_OF": "PermSet → Cluster. The role is cluster-admin-equivalent (* on apiGroups/resources/verbs).",
    "POD_EXEC": "Identity → Pod. The attacker can run a command in this pod (privileged + hostPID).",
    "POD_CREATE": "Identity → Node. The attacker can create pods in this cluster.",
    "TOKEN_LIST": "Identity → Identity. The attacker can list secrets and learn about service-account tokens.",
    "TOKEN_STEAL": "Pod → Identity. The pod runs with a service-account token the attacker can steal.",
    "ROLE_BIND": "Identity → PermSet. The attacker can bind a role to an identity (`bind`/`escalate`).",
}

_NODE_ORDER = ["Pod", "Container", "Identity", "PermSet", "Volume", "Node", "Cluster", "Entity"]
_EDGE_ORDER = list(EDGE_TYPES)


@app.get("/composition")
def composition():
    """The old descriptive view: per-label counts with human-readable notes."""
    try:
        counts = _counts(None)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    nodes = [
        {"label": label, "count": counts.get(label, 0), "description": _NODE_DESCRIPTIONS[label]}
        for label in _NODE_ORDER
    ]
    edges = [
        {
            "type": edge,
            "count": counts.get(edge, 0),
            "description": _EDGE_DESCRIPTIONS[edge],
            # The ATT&CK technique this edge represents, when it is an attack
            # edge (None for the structural ones). See `rung.attck`.
            "mitre": attck.technique_for(edge),
        }
        for edge in _EDGE_ORDER
    ]
    total_nodes = counts.get("Entity", 0)
    total_edges = sum(counts.get(e, 0) for e in _EDGE_ORDER)
    return {
        "graph": _graph_name(),
        "nodes": nodes,
        "edges": edges,
        "totals": {"nodes": total_nodes, "edges": total_edges},
    }


@app.get("/graph")
def graph_view(tenant: str | None = None):
    """The graph itself: entity nodes with their properties, and every edge.

    `nodes` is a list (what the graph canvas renders) and `edges` uses
    `source`/`target` keys, exactly as the frontend expects. A tenant
    selects the graph to read (`rung:<tenant>`); without one, the default
    graph is read.
    """
    try:
        g = _connect(tenant)
        nodes = graph_logic.node_view(g)
        edges = [attck.tag_edge(edge) for edge in graph_logic.edge_view(g)]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "graph": graph_logic.graph_name_for(tenant),
        "nodes": nodes,
        "edges": edges,
        "totals": {"nodes": len(nodes), "edges": len(edges)},
    }


@app.get("/paths")
def paths():
    """Escalation paths: which identities reach cluster-admin, and how."""
    try:
        g = _counts_graph()
        reaching = paths_logic.identities_reaching_admin(g)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "graph": _graph_name(),
        "reaching_admin": reaching,
        "totals": {"identities": len(reaching)},
    }


@app.get("/findings")
def findings_view(tenant: str | None = None):
    """The regression detector's tracked routes, newest state first.

    Reads the `:Finding` memory written on each ingest — statuses
    (NEW / RESOLVED / ACCEPTED / REGRESSED), route + target fingerprints and
    first/last-seen timestamps are persisted, not recomputed. Recomputing the
    live path set here took ~2 minutes on the demo graph; the stored memory
    answers in milliseconds and is what makes cross-snapshot status possible.
    """
    try:
        g = _connect(tenant)
        tracked = paths_logic.findings(g)
        counts = findings_logic.status_counts(tracked)
        attack_edges = paths_logic.attack_edge_counts(g)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "graph": graph_logic.graph_name_for(tenant),
        # Each finding carries the ATT&CK techniques its route uses, derived
        # from the stored route fingerprint (W2, TEAM_PLAN §5c).
        "findings": [attck.tag_finding(finding) for finding in tracked],
        "counts": counts,
        "attack_edge_counts": attack_edges,
    }


@app.get("/snapshots")
def snapshots_view(tenant: str | None = None):
    """The snapshot log the findings are diffed against.

    At least two entries mean the detector has something to compare; each
    one carries what that ingest changed (new/resolved/accepted/regressed).
    """
    try:
        g = _connect(tenant)
        history = findings_logic.snapshot_history(g)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"graph": graph_logic.graph_name_for(tenant), "snapshots": history}


@app.get("/exceptions")
def exceptions_view(tenant: str | None = None):
    """Accepted risks: the controller/operator memory the detector honours."""
    try:
        g = _connect(tenant)
        exceptions = findings_logic.list_exceptions(g)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"graph": graph_logic.graph_name_for(tenant), "exceptions": exceptions}


@app.post("/exceptions")
def accept_exception(body: dict, tenant: str | None = None):
    """Accept the risk behind a finding (Track 02's "remember this").

    Body: `{route_fp, relies_on?, title?, note?}`. `relies_on` defaults to the
    witness route's intermediate entities — the control(s) the acceptance
    trusts. A later route to the same target that traverses none of them is
    reported as REGRESSED.
    """
    route_fp = body.get("route_fp")
    if not route_fp:
        raise HTTPException(status_code=400, detail="{'route_fp': ...} required")
    try:
        g = _connect(tenant)
        exception = findings_logic.accept(
            g,
            route_fp,
            relies_on=body.get("relies_on"),
            title=body.get("title"),
            note=body.get("note"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"status": "accepted", "exception": exception}


def _is_tenant_graph(name):
    """A tenant graph is `rung:<tenant>`; test and compare scratch are not."""
    if not name.startswith("rung:"):
        return False
    tenant = name.removeprefix("rung:")
    return bool(tenant) and not tenant.startswith("test") and not tenant.endswith("-compare")


def _tenant_of_graph(name):
    """`rung:<tenant>` -> `<tenant>` (the name the API and UI speak)."""
    return name.removeprefix("rung:")


@app.get("/tenants")
def tenants():
    """One entry per tenant graph — a flat list of `{tenant, counts}`.

    A tenant is a FalkorDB graph named `rung:<tenant>`, the same name
    `/ingest?tenant=` writes into. Test and compare scratch graphs are left
    out, as is a graph that holds no entities yet; the default graph is
    always listed so the seeded demo shows up on first load.
    """
    try:
        names = set(graph_logic.list_graphs())
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    default = _graph_name()
    names.add(default)
    out = []
    for name in sorted(names):
        if not _is_tenant_graph(name):
            continue
        tenant = _tenant_of_graph(name)
        counts = _counts(tenant)
        if name != default and not counts.get("Entity"):
            continue
        out.append({"tenant": tenant, "counts": counts})
    return out


@app.post("/ingest")
async def ingest_snapshot(
    file: Annotated[UploadFile, File()], tenant: str | None = None
):
    """Ingest an uploaded snapshot, optionally into a tenant's graph."""
    try:
        content = await file.read()
        snapshot = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON: {exc}") from exc

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        json.dump(snapshot, tmp)
        path = tmp.name
    try:
        result = ingest(
            path,
            stats=False,
            graph_name=graph_logic.graph_name_for(tenant),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return {"status": "ingested", "counts": result}


@app.get("/compare")
def compare_naive_vs_rung(tenant: str | None = None):
    """The thesis-prover: the same graph counted two ways (TEAM_PLAN §4 win).

    Shape matches `frontend/src/lib/types.ts::Compare`: four integers,
    `naive_*` vs `rung_*`, so the UI can render them side by side.
    """
    # compare_thesis prefixes `rung:` itself, so hand it the bare tenant.
    bare = tenant or graph_logic.graph_name_for(None).split(":", 1)[-1]
    try:
        return compare_thesis(bare)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/compare")
async def compare_snapshots(file: Annotated[UploadFile, File()]):
    """Compare the live graph with a snapshot: counts, and a per-type diff."""
    try:
        content = await file.read()
        snapshot = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON: {exc}") from exc
    if not isinstance(snapshot, dict) or "pods" not in snapshot:
        raise HTTPException(status_code=400, detail="not a snapshot object")

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        json.dump(snapshot, tmp)
        path = tmp.name
    try:
        result = compare(_graph_name(), path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return {"status": "compared", "result": result}


def _ask_context(tenant=None):
    """The payloads the agent needs about the graph of this tenant."""
    g = _connect(tenant)
    return {
        "reaching_admin": paths_logic.identities_reaching_admin(g),
        "findings": [
            attck.tag_finding(finding) for finding in paths_logic.findings(g)
        ],
        "summary": _counts(tenant),
    }


def _event_lines(events):
    for event in events:
        yield f"data: {json.dumps(event)}\n\n"


@app.post("/ask")
async def ask(question: dict):
    """Answer a natural-language question, streamed as Server-Sent Events.

    Prefers the real Claude Opus 5.5 agent (`rung.agent.stream_ask`) when
    ANTHROPIC_API_KEY is set; falls back to the keyword stand-in in
    `rung.ask` otherwise, so the UI still works without an API key.
    """
    if "question" not in question:
        raise HTTPException(status_code=400, detail="{'question': ...'} required")
    tenant = question.get("tenant")
    q_text = str(question["question"])

    from rung import agent as agent_logic

    if agent_logic.available():
        stream = agent_logic.stream_ask(q_text, tenant)
    else:
        context = _ask_context(tenant)
        stream = ask_logic.events(q_text, context)

    return StreamingResponse(
        _event_lines(_safe_stream(stream)),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _safe_stream(events):
    """Convert an unhandled agent exception into a `final` event instead of
    a mid-stream disconnect — the UI shows the message, nothing crashes."""
    try:
        yield from events
    except Exception as exc:  # noqa: BLE001
        yield {"type": "final", "answer": f"agent error: {exc}", "citations": []}
