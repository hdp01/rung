"""The regression detector — Track 02's cross-snapshot memory.

Findings are *stored*, not recomputed on the fly. Every tracked attack route
(isolated entity → cluster) gets a `:Finding` node carrying its fingerprint,
status and first/last-seen times; each ingest adds a `:Snapshot` node and
diffs the current routes against the stored ones. The status vocabulary is the
frontend's (`frontend/src/lib/types.ts`):

* ``NEW``       — the route was not tracked before this snapshot.
* ``RESOLVED``  — the route walked in an earlier snapshot and no longer does.
* ``ACCEPTED``  — an operator accepted this class of risk (an ``:Exception``
                  covers the target and the route honours the control the
                  exception relies on).
* ``REGRESSED`` — a route that closed walks again, or a *different* route
                  reaches an accepted target without traversing any of the
                  ``RELIED_ON`` entities the exception trusted: the
                  "waived risk is back by a new route" moment.

Why ``:Finding`` is deliberately *not* labelled ``:Entity``: ``rung ingest``
tears the graph down with ``MATCH (n:Entity) DETACH DELETE n``, so memory
nodes must live outside that label or every re-ingest would reset the memory
the detector exists to keep. This is the same contract the tests encode.

Why one canonical witness per (source, target) instead of every path: the
attack graph is combinatorial (one demo cluster enumerates 350k routes to
12 hops; the product needs a list a human can read). A bounded BFS from every
workload/identity keeps the *shortest* route to each cluster-admin grant —
the route the demo lights up — and the fingerprint still changes when the
route's controls change, which is exactly what regression detection needs.
"""
import hashlib
import json
from collections import Counter, deque
from datetime import UTC, datetime

from . import paths as paths_logic

STATUSES = ("NEW", "RESOLVED", "ACCEPTED", "REGRESSED")

_STATUS_ORDER = {"REGRESSED": 0, "NEW": 1, "ACCEPTED": 2, "RESOLVED": 3}

# Entities the detector anchors exceptions on. ``cluster`` is the terminal
# node every route shares, and the target grant is what the exception is
# *about* — neither can be part of "the control we relied on", or no bypass
# could ever fail the test that produces REGRESSED.
_CONTROL_EXCLUDED = {"cluster"}


# ---------------------------------------------------------------------------
# fingerprints
# ---------------------------------------------------------------------------


def _hash(prefix, text):
    return prefix + hashlib.sha1(text.encode("utf-8")).hexdigest()[:12]


def route_fingerprint(nodes, edges):
    """A stable fingerprint of the exact route: source + (edge, target)..."""
    steps = [nodes[0]]
    for edge in edges:
        steps.append(f"{edge['type']}>{edge['to']}")
    return _hash("path:", "|".join(steps))


def target_fingerprint(permset_id):
    """A stable fingerprint of the admin grant a route lands on."""
    return _hash("grant:", permset_id)


def snapshot_fingerprint(snapshot):
    """A stable id for a snapshot's *content plus capture time*.

    Two ingests of the same collected snapshot are the same snapshot (and are
    not diffed twice); a re-collection produces a new ``collected_at`` and so
    a new id even when nothing changed.
    """
    meta = snapshot.get("meta") or {}
    stamped = dict(snapshot)
    stamped.pop("_rung", None)
    blob = json.dumps(stamped, sort_keys=True, default=str)
    return _hash("snap:", f"{meta.get('collected_at', '')}|{blob}")


# ---------------------------------------------------------------------------
# current routes (bounded, canonical)
# ---------------------------------------------------------------------------


def _sources(g):
    """Every node an attack can start from: workloads and identities."""
    out = []
    for label in ("Pod", "Identity"):
        rows = g.query(f"MATCH (n:{label}) RETURN n.id").result_set
        out.extend(row[0] for row in rows if row[0])
    return sorted(set(out))


def _admin_grants(g):
    """Admin PermSets: every (role, scope) with an ADMIN_OF edge to cluster."""
    rows = g.query(
        "MATCH (p:PermSet)-[:ADMIN_OF]->(:Cluster {id:'cluster'}) "
        "RETURN p.id, p.name, p.scope"
    ).result_set
    return {row[0]: {"name": row[1], "scope": row[2]} for row in rows if row[0]}


def _adjacency(g):
    """Attack-walkable edges only, sorted so witnesses are deterministic."""
    adjacency = paths_logic.attack_adjacency(g)
    for edges in adjacency.values():
        edges.sort(key=lambda e: (e["to"], e["type"], e["from"]))
    return adjacency


def _shortest_parents(source, adjacency):
    """BFS parents over attack edges: node -> (previous node, edge used)."""
    parents = {source: (None, None)}
    queue = deque([source])
    while queue:
        current = queue.popleft()
        for edge in adjacency.get(current, ()):
            nxt = edge["to"]
            if nxt not in parents:
                parents[nxt] = (current, edge)
                queue.append(nxt)
    return parents


def _reconstruct(source, target, parents):
    """The nodes and edges from `source` to `target` via BFS parents."""
    nodes, edges = [], []
    node = target
    while node != source:
        previous, edge = parents[node]
        nodes.append(node)
        edges.append(edge)
        node = previous
    nodes.append(source)
    nodes.reverse()
    edges.reverse()
    return nodes, edges


def _ownership_for(g, entity_id):
    """owning_app and deployed_from for an entity, null-safe."""
    try:
        rows = g.query(
            "MATCH (e {id:$id})-[:BELONGS_TO]->(a:App) RETURN a.name, a.source",
            {"id": entity_id},
        ).result_set
    except Exception:  # noqa: BLE001
        return None, None
    if not rows:
        return None, None
    app_name, source = rows[0]
    deployed_from = f"helm:{app_name}" if source == "helm" else (f"argocd:{app_name}" if source == "argocd" else app_name)
    return app_name, deployed_from


def canonical_routes(g):
    """One witness route per (source, admin grant), with fingerprints.

    Each route is a dict: ``source``, ``nodes``, ``edges`` (dicts with
    ``from``/``to``/``type``), ``route_fp``, ``target_fp``, ``route`` (the
    edge chain, the frontend's display form) and ``target`` (the grant).
    """
    adjacency = _adjacency(g)
    grants = _admin_grants(g)
    routes = []
    for source in _sources(g):
        parents = _shortest_parents(source, adjacency)
        for permset_id, props in grants.items():
            if permset_id not in parents:
                continue
            nodes, edges = _reconstruct(source, permset_id, parents)
            route_edges = edges + [
                {
                    "from": permset_id,
                    "to": "cluster",
                    "type": "ADMIN_OF",
                    "attack_path": 1,
                }
            ]
            route_nodes = nodes + ["cluster"]
            route_fp = route_fingerprint(route_nodes, route_edges)
            scope = props.get("scope") or "cluster"
            owning_app, deployed_from = _ownership_for(g, source)
            routes.append(
                {
                    "source": source,
                    "nodes": route_nodes,
                    "edges": route_edges,
                    "route_fp": route_fp,
                    "target_fp": target_fingerprint(permset_id),
                    "route": " › ".join(edge["type"] for edge in route_edges),
                    "target": f"{props.get('name')} @ {'cluster' if scope == '*' else scope}",
                    "title": f"Cluster-admin reachable from {source}",
                    "note": "walks " + " › ".join(edge["type"] for edge in route_edges),
                    "owning_app": owning_app,
                    "deployed_from": deployed_from,
                }
            )
    routes.sort(key=lambda r: (r["source"], r["target_fp"]))
    return routes


def ephemeral_findings(g):
    """Current routes as NEW findings, for graphs without detector memory.

    The API used to answer `/findings` by enumerating live paths; keeping
    that as a fallback means an old graph still reads sensibly until the
    next ingest writes real memory.
    """
    return [
        {
            "id": route["route_fp"],
            "route_fp": route["route_fp"],
            "target_fp": route["target_fp"],
            "status": "NEW",
            "route": route["route"],
            "target": route["target"],
            "title": route["title"],
            "note": route["note"],
            "previous_status": None,
            "first_seen": None,
            "last_seen": None,
            "owning_app": route.get("owning_app"),
            "deployed_from": route.get("deployed_from"),
        }
        for route in canonical_routes(g)
    ]


# ---------------------------------------------------------------------------
# memory: nodes, exceptions, snapshots
# ---------------------------------------------------------------------------


def _now():
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _nodes(g, label):
    rows = g.query(f"MATCH (n:{label}) RETURN n").result_set
    return [dict(row[0].properties or {}) for row in rows]


def _ensure_indexes(g):
    for label, prop in (
        ("Finding", "id"),
        ("Finding", "status"),
        ("Snapshot", "id"),
        ("Exception", "id"),
    ):
        try:
            g.query(f"CREATE INDEX FOR (n:{label}) ON (n.{prop})")
        except Exception:  # noqa: BLE001,S110 — already exists is fine
            pass


def _write(g, label, props):
    g.query(
        f"MERGE (n:{label} {{id:$id}}) SET n = $props",
        {"id": props["id"], "props": props},
    )


def _write_many(g, label, rows):
    """Upsert many nodes of one label in a single round-trip.

    The memory is written on every ingest; batching turns an ingest of a
    large graph from one query per finding into one query per label.
    """
    if not rows:
        return
    g.query(
        f"UNWIND $rows AS row MERGE (n:{label} {{id: row.id}}) SET n = row",
        {"rows": rows},
    )


def _active_exceptions(g):
    out = []
    for props in _nodes(g, "Exception"):
        if str(props.get("active", "true")).lower() in ("true", "1", "yes"):
            props["relies_on"] = json.loads(props.get("relies_on") or "[]")
            out.append(props)
    return out


def _traverses(route, exception):
    """True when the route walks any entity the exception relies on.

    This is the graph test behind REGRESSED: an acceptance is only valid
    while the routes it covers still pass through the control it trusted.
    """
    relied = set(exception.get("relies_on") or ())
    return bool(relied & set(route["nodes"]))


def _matching_exception(exceptions, target_fp):
    for exception in exceptions:
        if exception.get("target_fp") == target_fp:
            return exception
    return None


def _link_exceptions(g):
    """Re-create RELIES_ON edges after an ingest rebuilt the Entity nodes.

    The entity ids are stored on the exception (``relies_on``); the edges are
    a live convenience for queries, the ids are the durable source of truth
    because a re-ingest deletes and recreates every entity.
    """
    pairs = [
        {"e": props["id"], "t": entity_id}
        for props in _nodes(g, "Exception")
        for entity_id in json.loads(props.get("relies_on") or "[]")
    ]
    if not pairs:
        return
    g.query(
        "UNWIND $pairs AS pair "
        "MATCH (e:Exception {id: pair.e}), (t:Entity {id: pair.t}) "
        "MERGE (e)-[:RELIES_ON]->(t)",
        {"pairs": pairs},
    )


def _snapshot_summary(props):
    return {
        "snapshot": props.get("id"),
        "at": props.get("created_at"),
        "new": int(props.get("new") or 0),
        "resolved": int(props.get("resolved") or 0),
        "accepted": int(props.get("accepted") or 0),
        "regressed": int(props.get("regressed") or 0),
        "routes": int(props.get("routes") or 0),
    }


def record_snapshot(g, snapshot):
    """Diff the graph against memory and persist this snapshot's findings.

    Called by ``ingest`` once the entities and edges are rebuilt. Returns a
    summary dict ``{snapshot, at, new, resolved, accepted, regressed, routes}``
    that `/ingest` and `rung ingest` surface.
    """
    _ensure_indexes(g)
    _link_exceptions(g)

    snap_id = snapshot_fingerprint(snapshot)
    known = [
        props
        for props in _nodes(g, "Snapshot")
        if props.get("id") == snap_id
    ]
    if known:
        # Same snapshot content already processed: idempotent re-ingest.
        return _snapshot_summary(known[0])

    meta = snapshot.get("meta") or {}
    seen_at = meta.get("collected_at") or _now()
    routes = canonical_routes(g)
    memories = {props["id"]: props for props in _nodes(g, "Finding")}
    exceptions = _active_exceptions(g)
    counts = Counter()

    seen_fps = set()
    current_rows = []
    for route in routes:
        seen_fps.add(route["route_fp"])
        memory = memories.get(route["route_fp"])
        exception = _matching_exception(exceptions, route["target_fp"])
        first_seen = (memory or {}).get("first_seen") or seen_at
        # A replayed older snapshot must not rewind the clock: last_seen is
        # the newest snapshot in which the route walked, not the newest ingest.
        last_seen = seen_at
        previous_last_seen = (memory or {}).get("last_seen")
        if previous_last_seen and previous_last_seen > seen_at:
            last_seen = previous_last_seen
        status, previous_status, note = _decide(route, memory, exception)
        counts[status] += 1
        current_rows.append(
            {
                "id": route["route_fp"],
                "route_fp": route["route_fp"],
                "target_fp": route["target_fp"],
                "route": route["route"],
                "target": route["target"],
                "title": route["title"],
                "note": note,
                "nodes": json.dumps(route["nodes"]),
                "status": status,
                "previous_status": previous_status,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "snapshot_id": snap_id,
            }
        )

    resolved_rows = []
    for route_fp, memory in memories.items():
        if route_fp in seen_fps or memory.get("status") == "RESOLVED":
            continue
        resolved_rows.append(
            {
                **memory,
                "status": "RESOLVED",
                "previous_status": memory.get("status"),
                "note": f"route no longer walks as of {snap_id}",
                "snapshot_id": snap_id,
            }
        )
        counts["RESOLVED"] += 1

    _write_many(g, "Finding", current_rows)
    _write_many(g, "Finding", resolved_rows)

    summary = {
        "snapshot": snap_id,
        "at": seen_at,
        "new": counts["NEW"],
        "resolved": counts["RESOLVED"],
        "accepted": counts["ACCEPTED"],
        "regressed": counts["REGRESSED"],
        "routes": len(routes),
    }
    _write(
        g,
        "Snapshot",
        {
            "id": snap_id,
            "created_at": seen_at,
            "ingested_at": _now(),
            "context": meta.get("context") or "",
            "routes": summary["routes"],
            "new": summary["new"],
            "resolved": summary["resolved"],
            "accepted": summary["accepted"],
            "regressed": summary["regressed"],
        },
    )
    return summary


def _decide(route, memory, exception):
    """The detector's whole rule set, in priority order.

    Returns ``(status, previous_status, note)`` for one route.
    """
    if exception is not None and _traverses(route, exception):
        previous = None
        if memory:
            previous = (
                memory.get("previous_status")
                if memory.get("status") == "ACCEPTED"
                else memory.get("status")
            )
        elif exception.get("relies_on"):
            previous = "NEW"
        return (
            "ACCEPTED",
            previous,
            f"risk accepted by exception {exception.get('id')}: {exception.get('note') or ''}".strip(),
        )

    if memory is None:
        if exception is not None:
            # A different route to an accepted target that bypasses every
            # entity the acceptance relied on: the waiver is no longer valid.
            return (
                "REGRESSED",
                "ACCEPTED",
                (
                    f"waived risk back: new route to {route['target']} bypasses the "
                    f"control(s) exception {exception.get('id')} relied on"
                ),
            )
        return "NEW", None, route["note"]

    if memory.get("status") == "RESOLVED":
        return (
            "REGRESSED",
            "RESOLVED",
            f"closed route walks again as of {memory.get('snapshot_id')}",
        )

    if exception is not None:
        return (
            "REGRESSED",
            memory.get("status"),
            (
                f"waived risk back: route to {route['target']} no longer traverses "
                f"the control(s) exception {exception.get('id')} relied on"
            ),
        )

    return memory.get("status", "NEW"), memory.get("previous_status"), memory.get("note", "")


# ---------------------------------------------------------------------------
# read side
# ---------------------------------------------------------------------------


def _public(props):
    return {
        "id": props.get("id"),
        "route_fp": props.get("route_fp"),
        "target_fp": props.get("target_fp"),
        "status": props.get("status"),
        "route": props.get("route"),
        "target": props.get("target"),
        "title": props.get("title"),
        "note": props.get("note"),
        "previous_status": props.get("previous_status") or None,
        "first_seen": props.get("first_seen"),
        "last_seen": props.get("last_seen"),
        "owning_app": props.get("owning_app"),
        "deployed_from": props.get("deployed_from"),
    }


def list_findings(g):
    """Every tracked finding, status-ordered for the panel.

    REGRESSED first (the banner), then NEW, ACCEPTED, RESOLVED — the same
    priority the frontend gives them.
    """
    rows = [_public(props) for props in _nodes(g, "Finding")]
    rows.sort(
        key=lambda f: (
            _STATUS_ORDER.get(f["status"], 9),
            f.get("last_seen") or "",
            f.get("route") or "",
        )
    )
    return rows


def status_counts(findings):
    counts = Counter(f.get("status") for f in findings)
    return {status: counts.get(status, 0) for status in STATUSES}


def snapshot_history(g):
    """The snapshot log, newest first — the two points the diff compares."""
    rows = [_snapshot_summary(props) for props in _nodes(g, "Snapshot")]
    rows.sort(key=lambda s: s.get("at") or "", reverse=True)
    return rows


def list_exceptions(g):
    """Active risk acceptances, with the entities they rely on."""
    return [
        {
            "id": props.get("id"),
            "target_fp": props.get("target_fp"),
            "title": props.get("title"),
            "note": props.get("note"),
            "relies_on": props.get("relies_on") or [],
            "active": props.get("active", True),
            "created_at": props.get("created_at"),
        }
        for props in _active_exceptions(g)
    ]


def accept(g, route_fp, relies_on=None, title=None, note=None):
    """Accept the risk behind one finding, recording the control it trusts.

    ``relies_on`` defaults to the witnesses' intermediate entities (the
    source and the target grant are not controls). From the next ingest on,
    routes that still traverse one of them stay ACCEPTED; a different route
    to the same grant that traverses none of them is REGRESSED.
    """
    findings = {props["id"]: props for props in _nodes(g, "Finding")}
    finding = findings.get(route_fp)
    if finding is None:
        raise ValueError(f"unknown finding: {route_fp}")

    nodes = json.loads(finding.get("nodes") or "[]")
    target_id = nodes[-2] if len(nodes) >= 2 else "cluster"
    if relies_on is None:
        relies_on = [
            node for node in nodes if node not in _CONTROL_EXCLUDED and node != nodes[0] and node != target_id
        ]
    exception = {
        "id": _hash("exc:", f"{finding['target_fp']}|{','.join(sorted(relies_on))}"),
        "target_fp": finding["target_fp"],
        "title": title or finding.get("title"),
        "note": note or f"accepted {finding.get('target')}",
        "relies_on": json.dumps(sorted(set(relies_on))),
        "active": "true",
        "created_at": _now(),
    }
    _ensure_indexes(g)
    _write(g, "Exception", exception)
    _link_exceptions(g)

    relied = json.loads(exception["relies_on"])
    accepted_rows = []
    for candidate in findings.values():
        if candidate.get("target_fp") != finding["target_fp"]:
            continue
        route = {"nodes": json.loads(candidate.get("nodes") or "[]")}
        if _traverses(route, {"relies_on": relied}):
            accepted_rows.append(
                {
                    **candidate,
                    "status": "ACCEPTED",
                    "previous_status": (
                        candidate.get("previous_status")
                        if candidate.get("status") == "ACCEPTED"
                        else candidate.get("status")
                    ),
                    "note": exception["note"],
                }
            )
    _write_many(g, "Finding", accepted_rows)
    return {
        "id": exception["id"],
        "target_fp": exception["target_fp"],
        "title": exception["title"],
        "note": exception["note"],
        "relies_on": json.loads(exception["relies_on"]),
        "active": True,
        "created_at": exception["created_at"],
    }


def reset_memory(g):
    """Drop findings and the snapshot log (exceptions stay): demo/test helper."""
    g.query("MATCH (n:Finding) DETACH DELETE n")
    g.query("MATCH (n:Snapshot) DETACH DELETE n")
