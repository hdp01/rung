"""`rung ingest` — build the graph in FalkorDB from a snapshot.

Part 1 (entities + structural edges): entities + the six structural edges.
Part 2 (derived attack edges) is deliberately left out — see HANDOFF.md.
"""
import json
import os

from falkordb import FalkorDB


_LABELS = ["Entity", "Pod", "Container", "Identity", "PermSet", "Volume", "Node", "Cluster"]
_REL_TYPES = [
    "CONTAINED_IN",
    "SCHEDULED_ON",
    "MOUNTS",
    "IDENTITY_ASSUME",
    "PERMISSION_DISCOVER",
    "ADMIN_OF",
]


def _graph():
    host = os.getenv("FALKORDB_HOST", "localhost")
    port = int(os.getenv("FALKORDB_PORT", "6380"))
    name = os.getenv("FALKORDB_GRAPH", "rung:kind-graphhacks")
    return FalkorDB(host=host, port=port).select_graph(name)


def _q(g, cypher, params=None):
    return g.query(cypher, params or {})


def ingest(snapshot_path: str, stats: bool = False) -> None:
    with open(snapshot_path, "r") as f:
        snap = json.load(f)

    g = _graph()

    # 2a. Teardown — only Entity nodes, never memory nodes.
    _q(g, "MATCH (n:Entity) DETACH DELETE n")

    # Indexes (best-effort: ignore "already exists").
    for label in _LABELS:
        try:
            _q(g, f"CREATE INDEX FOR (n:{label}) ON (n.id)")
        except Exception:
            pass

    pods = snap.get("pods", []) or []
    nodes = snap.get("nodes", []) or []
    serviceaccounts = snap.get("serviceaccounts", []) or []
    roles = snap.get("roles", []) or []
    bindings = snap.get("bindings", []) or []

    # Identity set.
    identities = {}  # id -> props
    for sa in serviceaccounts:
        sid = f"sa/{sa['namespace']}/{sa['name']}"
        identities[sid] = {
            "id": sid,
            "kind": "ServiceAccount",
            "name": sa["name"],
            "namespace": sa["namespace"],
            "automount": sa.get("automount"),
        }

    def role_for(role_ref, scope):
        for r in roles:
            if r.get("kind") != role_ref.get("kind"):
                continue
            if r.get("name") != role_ref.get("name"):
                continue
            # Role (namespace-scoped) must match the binding scope.
            if role_ref.get("kind") == "Role" and r.get("namespace") not in (None, scope):
                continue
            return r
        return None

    # PermSets: one per (roleRef, scope) pair seen in bindings.
    permsets = {}  # id -> props
    # identity -> set of permset ids
    identity_permsets = {}
    for b in bindings:
        kind = b.get("kind", "")
        if kind == "ClusterRoleBinding":
            scope = "*"
        else:
            scope = b.get("namespace")
            if scope is None:
                scope = "*"
        role_ref = b.get("roleRef") or {}
        rid = f"{role_ref.get('kind', '').lower()}/{role_ref.get('name')}@{scope}"
        if rid not in permsets:
            role = role_for(role_ref, scope)
            rules = (role or {}).get("rules") or []
            admin = any(
                "*" in (rule.get("apiGroups") or [])
                and "*" in (rule.get("resources") or [])
                and "*" in (rule.get("verbs") or [])
                for rule in rules
            )
            permsets[rid] = {
                "id": rid,
                "kind": role_ref.get("kind"),
                "name": role_ref.get("name"),
                "scope": scope,
                "admin": bool(admin),
                "rules": json.dumps(rules),
            }
        for subj in b.get("subjects", []) or []:
            skind = subj.get("kind")
            sname = subj.get("name")
            s_ns = subj.get("namespace")
            if skind == "ServiceAccount":
                sid = f"sa/{s_ns}/{sname}" if s_ns is not None else None
            elif skind == "User":
                sid = f"user/{sname}"
            elif skind == "Group":
                sid = f"group/{sname}"
            else:
                sid = None
            if sid is None:
                # Fall back to a subject-namespaced id.
                sid = f"subject/{skind or 'unknown'}/{sname}"
            if sid not in identities:
                identities[sid] = {
                    "id": sid,
                    "kind": skind,
                    "name": sname,
                    "namespace": s_ns,
                }
            identity_permsets.setdefault(sid, set()).add(rid)

    # --- create nodes ---

    # Cluster (one, always)
    _q(g, "CREATE (n:Entity:Cluster {id:$id})", {"id": "cluster"})
    # also store nothing else

    # Nodes
    for node in nodes:
        nid = f"node/{node['name']}"
        _q(
            g,
            "CREATE (n:Entity:Node {id:$id, name:$name})",
            {"id": nid, "name": node.get("name")},
        )

    # Identity
    for sid, props in identities.items():
        _q(g, "CREATE (n:Entity:Identity) SET n = $props", {"props": props})

    # PermSet
    for pid, props in permsets.items():
        _q(g, "CREATE (n:Entity:PermSet) SET n = $props", {"props": props})

    # Pods + containers + volumes
    for pod in pods:
        ns = pod["namespace"]
        pname = pod["name"]
        pid = f"pod/{ns}/{pname}"
        pod_props = {
            "id": pid,
            "name": pname,
            "namespace": ns,
            "serviceAccount": pod.get("serviceAccount"),
            "node": pod.get("node"),
            "hostPID": pod.get("hostPID"),
            "hostNetwork": pod.get("hostNetwork"),
            "automount": pod.get("automount"),
        }
        _q(g, "CREATE (n:Entity:Pod) SET n = $props", {"props": pod_props})

        # Volumes
        volume_ids = []
        for vol in pod.get("hostVolumes", []) or []:
            vid = f"vol/{ns}/{pname}/{vol['name']}"
            volume_ids.append(vid)
            vol_props = {
                "id": vid,
                "name": vol.get("name"),
                "namespace": ns,
                "pod": pname,
                "hostPath": vol.get("hostPath"),
                "mountPaths": vol.get("mountPaths"),
            }
            _q(g, "CREATE (n:Entity:Volume) SET n = $props", {"props": vol_props})

        # Containers
        for c in pod.get("containers", []) or []:
            cid = f"container/{ns}/{pname}/{c['name']}"
            cprops = {
                "id": cid,
                "name": c.get("name"),
                "namespace": ns,
                "pod": pname,
                "image": c.get("image"),
                "privileged": c.get("privileged"),
                "caps": c.get("caps"),
                "runAsUser": c.get("runAsUser"),
            }
            _q(g, "CREATE (n:Entity:Container) SET n = $props", {"props": cprops})

    # --- edges ---

    # CONTAINED_IN: Container -> Pod
    for pod in pods:
        ns = pod["namespace"]
        pname = pod["name"]
        pid = f"pod/{ns}/{pname}"
        for c in pod.get("containers", []) or []:
            cid = f"container/{ns}/{pname}/{c['name']}"
            _q(
                g,
                "MATCH (a:Container {id:$a}), (b:Pod {id:$b}) "
                "CREATE (a)-[:CONTAINED_IN {attack_path:0}]->(b)",
                {"a": cid, "b": pid},
            )

    # SCHEDULED_ON: Pod -> Node  (display only)
    for pod in pods:
        if not pod.get("node"):
            continue
        pid = f"pod/{pod['namespace']}/{pod['name']}"
        nid = f"node/{pod['node']}"
        _q(
            g,
            "MATCH (a:Pod {id:$a}), (b:Node {id:$b}) "
            "CREATE (a)-[:SCHEDULED_ON {attack_path:0}]->(b)",
            {"a": pid, "b": nid},
        )

    # MOUNTS: Container -> Volume
    for pod in pods:
        ns = pod["namespace"]
        pname = pod["name"]
        volume_ids = [f"vol/{ns}/{pname}/{v['name']}" for v in pod.get("hostVolumes", []) or []]
        for c in pod.get("containers", []) or []:
            cid = f"container/{ns}/{pname}/{c['name']}"
            for vid in volume_ids:
                _q(
                    g,
                    "MATCH (a:Container {id:$a}), (b:Volume {id:$b}) "
                    "CREATE (a)-[:MOUNTS {attack_path:0}]->(b)",
                    {"a": cid, "b": vid},
                )

    # IDENTITY_ASSUME: Pod -> Identity
    for pod in pods:
        sa_name = pod.get("serviceAccount")
        if not sa_name:
            continue
        ns = pod["namespace"]
        pid = f"pod/{ns}/{pod['name']}"
        sid = f"sa/{ns}/{sa_name}"
        if sid not in identities:
            identities[sid] = {
                "id": sid,
                "kind": "ServiceAccount",
                "name": sa_name,
                "namespace": ns,
                "automount": pod.get("automount"),
            }
            _q(g, "CREATE (n:Entity:Identity) SET n = $props", {"props": identities[sid]})
        _q(
            g,
            "MATCH (a:Pod {id:$a}), (b:Identity {id:$b}) "
            "CREATE (a)-[:IDENTITY_ASSUME {attack_path:1}]->(b)",
            {"a": pid, "b": sid},
        )

    # PERMISSION_DISCOVER: Identity -> PermSet
    for sid, pids in identity_permsets.items():
        for permset_id in pids:
            _q(
                g,
                "MATCH (a:Identity {id:$a}), (b:PermSet {id:$b}) "
                "CREATE (a)-[:PERMISSION_DISCOVER {attack_path:1}]->(b)",
                {"a": sid, "b": permset_id},
            )

    # ADMIN_OF: PermSet -> Cluster
    for pid, props in permsets.items():
        if props.get("admin"):
            _q(
                g,
                "MATCH (a:PermSet {id:$a}), (b:Cluster {id:$b}) "
                "CREATE (a)-[:ADMIN_OF {attack_path:1}]->(b)",
                {"a": pid, "b": "cluster"},
            )

    result = _counts(g)
    if stats:
        _print_stats(g, result)
    return result


def _counts(g) -> dict:
    out = {}
    for label in _LABELS:
        if label == "Entity":
            continue
        try:
            res = _q(g, f"MATCH (n:{label}) RETURN count(n)")
            out[label] = res.result_set[0][0] if res.result_set else 0
        except Exception:
            out[label] = 0
    try:
        res = _q(g, "MATCH (n:Entity) RETURN count(n)")
        out["Entity"] = res.result_set[0][0] if res.result_set else 0
    except Exception:
        out["Entity"] = 0
    for rt in _REL_TYPES:
        try:
            res = _q(g, f"MATCH ()-[r:{rt}]->() RETURN count(r)")
            out[rt] = res.result_set[0][0] if res.result_set else 0
        except Exception:
            out[rt] = 0
    return out


def _print_stats(g, result=None):
    if result is None:
        result = _counts(g)
    for label in _LABELS:
        print(f"{label}: {result.get(label, 0)}")
    for rt in _REL_TYPES:
        print(f"{rt}: {result.get(rt, 0)}")
