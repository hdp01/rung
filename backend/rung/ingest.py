"""`rung ingest` — build the graph in FalkorDB from a snapshot.

Part 1: entities + the six structural edges.
Part 2: derived attack edges, only where a documented precondition holds.
"""
import json
import os

from falkordb import FalkorDB


# The structural edges (part 1). SCHEDULED_ON is display-only, never an
# attack edge — see README.md, "more conservative than its prior art".
_REL_TYPES = [
    "CONTAINED_IN",
    "SCHEDULED_ON",
    "MOUNTS",
    "IDENTITY_ASSUME",
    "PERMISSION_DISCOVER",
    "ADMIN_OF",
]

_LABELS = ["Entity", "Pod", "Container", "Identity", "PermSet", "Volume", "Node", "Cluster"]

# The attack edges (part 2). Each is derived only when its precondition holds;
# an edge without its precondition is not created at all, never with
# attack_path=0.
_ATTACK_REL_TYPES = [
    "POD_EXEC",
    "POD_CREATE",
    "TOKEN_LIST",
    "TOKEN_STEAL",
    "ROLE_BIND",
]


def _graph(graph_name: str | None = None):
    host = os.getenv("FALKORDB_HOST", "localhost")
    port = int(os.getenv("FALKORDB_PORT", "6380"))
    name = graph_name or os.getenv("FALKORDB_GRAPH", "rung:kind-graphhacks")
    return FalkorDB(host=host, port=port).select_graph(name)


def _q(g, cypher, params=None):
    return g.query(cypher, params or {})


def ingest(snapshot_path: str, stats: bool = False, graph_name: str | None = None) -> dict:
    with open(snapshot_path, "r") as f:
        snap = json.load(f)

    g = _graph(graph_name)

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

    # --- part 2: derived attack edges (preconditions checked, never invented) ---

    _attack_edges(g, snap, pods, nodes, identities, identity_permsets, permsets)

    result = _counts(g)
    if stats:
        _print_stats(g, result)
    return result


def _covers(values, wanted):
    """True if this rule list covers everything `wanted` (`*` is the wildcard)."""
    return "*" in values or set(wanted) <= set(values)


def _real_token_identities(secrets):
    """Service-account ids that own a real token Secret in the cluster.

    A token counts only when the cluster really holds a Secret of type
    `kubernetes.io/service-account-token` owned by that service account —
    a Secret's mere existence is not enough.
    """
    out = set()
    for sec in secrets:
        if sec.get("type") != "kubernetes.io/service-account-token":
            continue
        sa_name = sec.get("saName")
        if not sa_name:
            continue
        out.add(f"sa/{sec.get('namespace')}/{sa_name}")
    return out


def _projected_identities(pods):
    """Service-account ids whose token is projected by a running pod.

    Kubernetes >= 1.24 mounts service-account tokens into pods instead of
    storing them as Secret data, so the token a pod runs with exists only
    while that pod uses automount.
    """
    out = set()
    for pod in pods:
        if pod.get("automount") is False:
            continue
        sa_name = pod.get("serviceAccount")
        if not sa_name:
            continue
        out.add(f"sa/{pod['namespace']}/{sa_name}")
    return out


def _attack_edges(g, snap, pods, nodes, identities, identity_permsets, permsets) -> None:
    """Part 2 — derive the attack edges, and only those the cluster allows.

    The preconditions are the four conservative rules documented in
    README.md, "more conservative than its prior art":

    1. a privileged container that shares its host PID offers an escape
       (POD_EXEC);
    2. creating pods is an escalation path only where Pod Security
       Admission is not restricted (POD_CREATE), and only for identities
       that hold the `create` verb;
    3. a service-account token exists only as a projected mount, and only a
       real token Secret makes it listable or stealable (TOKEN_LIST,
       TOKEN_STEAL);
    4. binding a role needs the `bind` and `escalate` verbs (ROLE_BIND).

    Every edge is created only when its precondition holds — none is
    invented, and an attack edge never has attack_path=0.
    """
    namespaces = {n.get("name"): n.get("enforce") for n in snap.get("namespaces", []) or []}
    token_sas = _projected_identities(pods) & _real_token_identities(
        snap.get("secrets", []) or []
    )

    def rules_of(props):
        return json.loads(props.get("rules") or "[]")

    def holds(rulesets, resources, verbs):
        """True if one of these PermSets lets the holder act as required."""
        for props in rulesets:
            for rule in rules_of(props):
                if not _covers(rule.get("resources") or [], resources):
                    continue
                if not _covers(rule.get("verbs") or [], verbs):
                    continue
                return True
        return False

    def attacker_rulesets(attacker):
        """The PermSets this identity can discover (its PERMISSION_DISCOVER edges)."""
        return [permsets[pid] for pid in sorted(identity_permsets.get(attacker, ()))]

    # ---- rule 1: a privileged + hostPID container is an escape hatch ----
    # POD_EXEC: attacker --[POD_EXEC]--> Pod
    escapable = {}  # pod id -> True
    for pod in pods:
        if not pod.get("hostPID"):
            continue
        for c in pod.get("containers") or []:
            if c.get("privileged"):
                escapable[f"pod/{pod['namespace']}/{pod['name']}"] = True
    for attacker in sorted(identities):
        for pod_id in sorted(escapable):
            _q(
                g,
                "MATCH (a:Identity {id:$a}), (b:Pod {id:$b}) "
                "CREATE (a)-[:POD_EXEC {attack_path:1}]->(b)",
                {"a": attacker, "b": pod_id},
            )

    # ---- rule 4: creating pods needs an unrestricted namespace -----
    # POD_CREATE: attacker --[POD_CREATE]--> Node
    restricted = {name for name, enforce in namespaces.items() if enforce == "restricted"}
    node_namespace = {}  # node name -> namespace of the first pod on it
    for pod in pods:
        if pod.get("node"):
            node_namespace.setdefault(pod["node"], pod["namespace"])
    for attacker in sorted(identities):
        if not holds(attacker_rulesets(attacker), ("pods",), ("create",)):
            continue
        if identities[attacker].get("namespace") in restricted:
            continue
        for node_name, node_id in node_ids(nodes):
            if node_namespace.get(node_name, "*") in restricted:
                continue
            _q(
                g,
                "MATCH (a:Identity {id:$a}), (b:Node {id:$b}) "
                "CREATE (a)-[:POD_CREATE {attack_path:1}]->(b)",
                {"a": attacker, "b": node_id},
            )

    # ---- rule 2: tokens are projected, and only real token Secrets ----
    # TOKEN_LIST: attacker --[TOKEN_LIST]--> Identity — they learn which
    # service-account tokens exist and can be stolen.
    for attacker in sorted(identities):
        if not holds(attacker_rulesets(attacker), ("secrets",), ("list",)):
            continue
        for target in sorted(token_sas):
            _q(
                g,
                "MATCH (a:Identity {id:$a}), (b:Identity {id:$b}) "
                "CREATE (a)-[:TOKEN_LIST {attack_path:1}]->(b)",
                {"a": attacker, "b": target},
            )

    # TOKEN_STEAL: the compromised pod uses its service-account token, which
    # the attacker then holds — the edge starts at the pod. The target only
    # exists where automount projects a real token Secret.
    for pod in pods:
        if pod.get("automount") is False:
            continue
        sa_name = pod.get("serviceAccount")
        if not sa_name:
            continue
        target = f"sa/{pod['namespace']}/{sa_name}"
        if target not in token_sas:
            continue
        _q(
            g,
            "MATCH (a:Pod {id:$a}), (b:Identity {id:$b}) "
            "CREATE (a)-[:TOKEN_STEAL {attack_path:1}]->(b)",
            {"a": f"pod/{pod['namespace']}/{pod['name']}", "b": target},
        )

    # ---- rule 3: binding needs bind/escalate -----------------------
    # ROLE_BIND: attacker --[ROLE_BIND]--> PermSet — they can bind an
    # existing role and so gain the permissions of that role/scope.
    for attacker in sorted(identities):
        if not holds(
            attacker_rulesets(attacker),
            ("*",),
            ("bind", "escalate"),
        ):
            continue
        for permset_id in sorted(identity_permsets.get(attacker, ())):
            _q(
                g,
                "MATCH (a:Identity {id:$a}), (b:PermSet {id:$b}) "
                "CREATE (a)-[:ROLE_BIND {attack_path:1}]->(b)",
                {"a": attacker, "b": permset_id},
            )


def node_ids(nodes):
    """Yield (node name, node id) pairs."""
    for node in nodes:
        yield node["name"], f"node/{node['name']}"


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
    for rt in _REL_TYPES + _ATTACK_REL_TYPES:
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
    for rt in _REL_TYPES + _ATTACK_REL_TYPES:
        print(f"{rt}: {result.get(rt, 0)}")
