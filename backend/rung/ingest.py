"""`rung ingest` — build the graph in FalkorDB from a snapshot.

Part 1: entities + the six structural edges.
Part 2: derived attack edges, only where a documented precondition holds.
Part 3: the regression detector — diff this snapshot's routes against the
stored :Finding memory (see `findings.py`).
"""
import json
from datetime import UTC, datetime, timedelta

_STALE_DAYS = 7

from . import findings as findings_logic
from . import graph as graph_logic

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

_LABELS = ["Entity", "Pod", "Container", "Identity", "PermSet", "Volume", "Node", "Cluster", "App", "Team"]

# The attack edges (part 2). Each is derived only when its precondition holds;
# an edge without its precondition is not created at all, never with
# attack_path=0.
_ATTACK_REL_TYPES = [
    # RBAC-granted actions. Each one fires only where the holder actually
    # satisfies the K8s precondition it names, not just the verb.
    "POD_EXEC",
    "POD_ATTACH",
    "POD_PATCH",
    "POD_CREATE",
    "TOKEN_LIST",
    "TOKEN_BRUTEFORCE",
    "TOKEN_CREATE",
    "TOKEN_STEAL",
    "ROLE_BIND",
    "ROLE_ESCALATE",
    "IDENTITY_IMPERSONATE",
    # Container escapes. Pod -> Node when the pod's spec gives it host reach.
    "CE_NSENTER",
    "CE_MODULE_LOAD",
    "CE_PRIV_MOUNT",
    "EXPLOIT_HOST_TRAVERSE",
    "EXPLOIT_CONTAINERD_SOCK",
]


def _graph(graph_name: str | None = None):
    """The graph the caller named, or the default one — over the shared client."""
    return graph_logic.connect_to(graph_name)


def _q(g, cypher, params=None):
    return g.query(cypher, params or {})


def ingest(
    snapshot_path: str,
    stats: bool = False,
    graph_name: str | None = None,
    allow_stale: bool = False,
) -> dict:
    with open(snapshot_path, "r") as f:
        snap = json.load(f)

    # Stale-snapshot guard: refuse snapshots older than _STALE_DAYS unless
    # explicitly overridden. Prevents a re-submitted old snapshot from
    # producing a misleading "no new findings" result.
    if not allow_stale:
        collected_at = (snap.get("meta") or {}).get("collected_at")
        if collected_at:
            try:
                ts = datetime.fromisoformat(collected_at)
                age = datetime.now(UTC) - ts
                if age > timedelta(days=_STALE_DAYS):
                    raise ValueError(
                        f"snapshot is {age.days} days old (collected_at={collected_at}); "
                        f"re-collect or pass allow_stale=True to ingest anyway"
                    )
            except (ValueError, TypeError) as exc:
                if "days old" in str(exc):
                    raise
                # Unparseable timestamp — warn but continue

    g = _graph(graph_name)

    # 2a. Teardown — only Entity nodes, never memory nodes.
    _q(g, "MATCH (n:Entity) DETACH DELETE n")

    # Indexes (best-effort: ignore "already exists").
    for label in _LABELS:
        try:
            _q(g, f"CREATE INDEX FOR (n:{label}) ON (n.id)")
        except Exception:  # noqa: BLE001,S110 — already exists is fine
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

    # --- ownership nodes (T3.2) — structural, NEVER attack ---------------
    # App and Team nodes capture the Helm/ArgoCD/k8s metadata already in the
    # cluster. BELONGS_TO and OWNED_BY are display-only edges: attack_path=0
    # FOREVER. INV-4 guards this.
    _ingest_ownership(g, pods, serviceaccounts, identities)

    # --- part 2: derived attack edges (preconditions checked, never invented) ---

    _attack_edges(g, snap, pods, nodes, identities, identity_permsets, permsets)

    # --- part 3: regression memory ---------------------------------------
    # Diff the rebuilt graph against the findings from the previous snapshot.
    # Finding/Snapshot nodes are not :Entity, so the teardown above — and the
    # next ingest's teardown — cannot touch them.
    result = _counts(g)
    result["findings"] = findings_logic.record_snapshot(g, snap)
    if stats:
        _print_stats(g, result)
        _print_findings(result["findings"])
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


def _projected_identities(pods, serviceaccounts=None):
    """Service-account ids whose token is projected by a running pod.

    Kubernetes >= 1.24 mounts service-account tokens into pods instead of
    storing them as Secret data, so the token a pod runs with exists only
    while automount is enabled. `automountServiceAccountToken: false` on
    either the pod or the ServiceAccount defeats the projection.
    """
    sa_automount = {
        f"sa/{sa['namespace']}/{sa['name']}": sa.get("automount")
        for sa in (serviceaccounts or [])
    }
    out = set()
    for pod in pods:
        if pod.get("automount") is False:
            continue
        sa_name = pod.get("serviceAccount")
        if not sa_name:
            continue
        sa_id = f"sa/{pod['namespace']}/{sa_name}"
        if sa_automount.get(sa_id) is False:
            continue
        out.add(sa_id)
    return out


def _attack_edges(g, snap, pods, nodes, identities, identity_permsets, permsets) -> None:
    """Part 2 — derive the attack edges, and only those the cluster allows.

    Rung's thesis: model the *precondition*, not the permission. An RBAC verb
    without the capability that verb depends on is not an attack path — so
    every edge below is gated on the real-world condition it needs:

    * `POD_EXEC` / `POD_ATTACH` / `POD_PATCH` / `POD_CREATE` — the holder has the
      verb, and (for POD_CREATE) the target namespace doesn't enforce
      restricted/baseline Pod Security Admission.
    * `TOKEN_LIST` / `TOKEN_BRUTEFORCE` — the attacker has `list` or `get` on
      secrets AND a `kubernetes.io/service-account-token` Secret actually
      exists; projected tokens (k8s >= 1.24) are not Secrets.
    * `TOKEN_CREATE` — the attacker has `create` on `serviceaccounts/token`,
      the modern token path.
    * `TOKEN_STEAL` — pods on a node leak their SA tokens to a host-escaped
      attacker, unless `automountServiceAccountToken: false` is set.
    * `ROLE_BIND` — needs `create` on `rolebindings`/`clusterrolebindings` AND
      `bind` on the target role (RBAC escalation prevention blocks it
      otherwise); the target name must be in that `bind` rule's
      `resourceNames`, or `resourceNames` must be empty.
    * `ROLE_ESCALATE` — needs `escalate` on `roles`/`clusterroles`.
    * `IDENTITY_IMPERSONATE` — needs `impersonate` on the subject's kind.
    * `CE_NSENTER` — container is privileged AND the pod sets `hostPID: true`.
    * `CE_MODULE_LOAD` — container holds `CAP_SYS_MODULE` OR is privileged.
    * `CE_PRIV_MOUNT` — container is privileged.
    * `EXPLOIT_HOST_TRAVERSE` — pod mounts `/var/lib/kubelet/pods` (or parent)
      from the host; reaches every token on that node.
    * `EXPLOIT_CONTAINERD_SOCK` — pod mounts a container-runtime socket.
    """
    namespaces = {n.get("name"): n.get("enforce") for n in snap.get("namespaces", []) or []}
    token_sas = _projected_identities(
        pods, snap.get("serviceaccounts", []) or []
    ) & _real_token_identities(snap.get("secrets", []) or [])

    def rules_of(props):
        return json.loads(props.get("rules") or "[]")

    def _rule_grants(rule, resource, verb, resource_name=None):
        """A single rule grants (resource, verb) with optional resourceName gate."""
        resources = rule.get("resources") or []
        verbs = rule.get("verbs") or []
        if resource not in resources and "*" not in resources:
            return False
        if verb not in verbs and "*" not in verbs:
            return False
        if resource_name is not None:
            names = rule.get("resourceNames") or []
            if names and resource_name not in names:
                return False
        return True

    def _rulesets_grant(rulesets, resource, verb, resource_name=None):
        for props in rulesets:
            for rule in rules_of(props):
                if _rule_grants(rule, resource, verb, resource_name):
                    return True
        return False

    def attacker_rulesets(attacker):
        """PermSets this identity can discover (its PERMISSION_DISCOVER edges)."""
        return [permsets[pid] for pid in sorted(identity_permsets.get(attacker, ()))]

    def holds_verb(attacker, resource, verb, resource_name=None):
        return _rulesets_grant(attacker_rulesets(attacker), resource, verb, resource_name)

    def _edge(a_label, a_id, rel, b_label, b_id):
        _q(
            g,
            f"MATCH (a:{a_label} {{id:$a}}), (b:{b_label} {{id:$b}}) "
            f"CREATE (a)-[:{rel} {{attack_path:1}}]->(b)",
            {"a": a_id, "b": b_id},
        )

    # ---------------------------------------------------------------
    # Container escapes: Pod -> Node, per container capability. We fire
    # the pod-level edge whenever any container in the pod meets its gate.
    # ---------------------------------------------------------------
    for pod in pods:
        if not pod.get("node"):
            continue
        pod_id = f"pod/{pod['namespace']}/{pod['name']}"
        node_id = f"node/{pod['node']}"
        containers = pod.get("containers") or []
        privileged = any(c.get("privileged") for c in containers)
        sys_module = any("SYS_MODULE" in (c.get("caps") or []) for c in containers)
        host_pid = bool(pod.get("hostPID"))

        if privileged and host_pid:
            _edge("Pod", pod_id, "CE_NSENTER", "Node", node_id)
        if privileged or sys_module:
            _edge("Pod", pod_id, "CE_MODULE_LOAD", "Node", node_id)
        if privileged:
            _edge("Pod", pod_id, "CE_PRIV_MOUNT", "Node", node_id)

        for v in pod.get("hostVolumes") or []:
            hp = (v.get("hostPath") or "").rstrip("/")
            if not hp:
                continue
            # kubelet traversal: /var/lib/kubelet/pods or any parent dir
            if hp == "/var/lib/kubelet/pods" or _is_parent(hp, "/var/lib/kubelet/pods"):
                _edge("Pod", pod_id, "EXPLOIT_HOST_TRAVERSE", "Node", node_id)
            # runtime socket mount
            lower = hp.lower()
            if any(
                sock in lower
                for sock in ("containerd.sock", "dockershim.sock", "crio.sock", "cri-dockerd.sock")
            ) or lower.endswith(("/run/docker.sock", "/var/run/docker.sock")):
                _edge("Pod", pod_id, "EXPLOIT_CONTAINERD_SOCK", "Node", node_id)

    # ---------------------------------------------------------------
    # TOKEN_STEAL: once the attacker owns the node, every SA of every pod
    # on that node is theirs — unless that pod set automount:false. This
    # is what makes the hero chain (pod -> node -> sa -> admin) possible.
    # ---------------------------------------------------------------
    # automount can be set on the pod OR on the SA; either `false` kills the
    # projected token, so TOKEN_STEAL must honour both. Build an SA-level
    # view from the snapshot.
    sa_automount = {
        f"sa/{sa['namespace']}/{sa['name']}": sa.get("automount")
        for sa in snap.get("serviceaccounts", []) or []
    }
    node_sa_targets = {}  # node name -> set of sa ids
    for pod in pods:
        if not pod.get("node") or pod.get("automount") is False:
            continue
        sa_name = pod.get("serviceAccount")
        if not sa_name:
            continue
        sa_id = f"sa/{pod['namespace']}/{sa_name}"
        if sa_automount.get(sa_id) is False:
            continue
        node_sa_targets.setdefault(pod["node"], set()).add(sa_id)
    for node_name, sa_ids in node_sa_targets.items():
        node_id = f"node/{node_name}"
        for sa_id in sorted(sa_ids):
            if sa_id not in identities:
                continue
            _edge("Node", node_id, "TOKEN_STEAL", "Identity", sa_id)

    # ---------------------------------------------------------------
    # RBAC-granted actions. Verb + target gated by K8s preconditions.
    # ---------------------------------------------------------------
    all_pod_ids = [f"pod/{p['namespace']}/{p['name']}" for p in pods]
    pods_by_ns = {}
    for p in pods:
        pods_by_ns.setdefault(p["namespace"], []).append(f"pod/{p['namespace']}/{p['name']}")
    restricted_ns = {
        name for name, enforce in namespaces.items() if enforce in ("restricted", "baseline")
    }

    def pods_in_attacker_scope(attacker, verb_resource):
        """Which pods a cluster-wide verb can touch — all, or just the ns-scoped set."""
        # If the attacker holds the verb through a ClusterRole-sourced permset, scope is '*'.
        for pid in sorted(identity_permsets.get(attacker, ())):
            props = permsets[pid]
            scope = props.get("scope")
            for rule in rules_of(props):
                if _rule_grants(rule, "pods", verb_resource):
                    if scope == "*":
                        return all_pod_ids
                    return pods_by_ns.get(scope, [])
        return []

    def pods_subres_in_scope(attacker, subresource, verb):
        """Pods reachable via a subresource verb (pods/exec, pods/attach)."""
        touched = []
        seen = set()
        for pid in sorted(identity_permsets.get(attacker, ())):
            props = permsets[pid]
            scope = props.get("scope")
            for rule in rules_of(props):
                if _rule_grants(rule, subresource, verb):
                    targets = all_pod_ids if scope == "*" else pods_by_ns.get(scope, [])
                    for t in targets:
                        if t not in seen:
                            seen.add(t)
                            touched.append(t)
                    break
        return touched

    for attacker in sorted(identities):
        # POD_EXEC / POD_ATTACH — subresource verbs
        for pod_id in pods_subres_in_scope(attacker, "pods/exec", "create"):
            _edge("Identity", attacker, "POD_EXEC", "Pod", pod_id)
        for pod_id in pods_subres_in_scope(attacker, "pods/attach", "create"):
            _edge("Identity", attacker, "POD_ATTACH", "Pod", pod_id)

        # POD_PATCH — low-confidence RBAC path; the attacker patches an existing
        # pod's image/tolerations. We mark it with confidence='low'.
        patch_targets = set(pods_subres_in_scope(attacker, "pods", "patch")) | set(
            pods_subres_in_scope(attacker, "pods", "update")
        )
        for pod_id in sorted(patch_targets):
            _q(
                g,
                "MATCH (a:Identity {id:$a}), (b:Pod {id:$b}) "
                "CREATE (a)-[:POD_PATCH {attack_path:1, confidence:'low'}]->(b)",
                {"a": attacker, "b": pod_id},
            )

        # POD_CREATE — needs `create` on `pods` AND target namespace isn't
        # enforcing baseline/restricted PSA. We fire per-node, filtered by
        # whether any node ns is non-restricted.
        if holds_verb(attacker, "pods", "create"):
            # determine the attacker's scope for pods:create
            scope = _attacker_scope_for(attacker, identity_permsets, permsets, "pods", "create")
            allowed_ns = (
                [ns for ns in namespaces if ns not in restricted_ns]
                if scope == "*"
                else ([scope] if scope and scope not in restricted_ns else [])
            )
            if allowed_ns:
                # the attacker can only reach nodes where a pod from an allowed ns runs
                reachable_nodes = {
                    pod["node"]
                    for pod in pods
                    if pod.get("node") and pod["namespace"] in allowed_ns
                }
                for node_name in sorted(reachable_nodes):
                    _edge("Identity", attacker, "POD_CREATE", "Node", f"node/{node_name}")

        # TOKEN_LIST — list on secrets at a scope that covers the target's
        # namespace, AND a real token Secret actually exists for the target.
        list_scope = _attacker_scope_for(
            attacker, identity_permsets, permsets, "secrets", "list"
        )
        if list_scope is not None:
            for target in sorted(token_sas):
                if target not in identities:
                    continue
                target_ns = identities[target].get("namespace")
                if list_scope != "*" and target_ns != list_scope:
                    continue
                _edge("Identity", attacker, "TOKEN_LIST", "Identity", target)

        # TOKEN_BRUTEFORCE — get (no list) on secrets, same scope + Secret gate
        get_scope = _attacker_scope_for(
            attacker, identity_permsets, permsets, "secrets", "get"
        )
        if get_scope is not None and list_scope is None:
            for target in sorted(token_sas):
                if target not in identities:
                    continue
                target_ns = identities[target].get("namespace")
                if get_scope != "*" and target_ns != get_scope:
                    continue
                _edge("Identity", attacker, "TOKEN_BRUTEFORCE", "Identity", target)

        # TOKEN_CREATE — the modern token path on k8s >= 1.24
        if holds_verb(attacker, "serviceaccounts/token", "create"):
            # In theory any SA; we scope to the attacker's binding scope
            scope = _attacker_scope_for(
                attacker, identity_permsets, permsets, "serviceaccounts/token", "create"
            )
            for target in sorted(identities):
                if not target.startswith("sa/"):
                    continue
                target_ns = identities[target].get("namespace")
                if scope != "*" and target_ns != scope:
                    continue
                _edge("Identity", attacker, "TOKEN_CREATE", "Identity", target)

        # IDENTITY_IMPERSONATE — impersonate verb on users/groups/serviceaccounts
        if any(
            holds_verb(attacker, r, "impersonate")
            for r in ("users", "groups", "serviceaccounts")
        ):
            for target in sorted(identities):
                if target != attacker:
                    _edge("Identity", attacker, "IDENTITY_IMPERSONATE", "Identity", target)

    # ROLE_BIND and ROLE_ESCALATE need to look at each PermSet target
    # explicitly to honour resourceNames.
    for attacker in sorted(identities):
        rsets = attacker_rulesets(attacker)
        has_rb_create = any(
            _rule_grants(r, res, "create")
            for props in rsets
            for r in rules_of(props)
            for res in ("rolebindings", "clusterrolebindings")
        )
        if has_rb_create:
            for permset_id, props in permsets.items():
                target_kind = (props.get("kind") or "").lower()
                target_name = props.get("name")
                want_res = "clusterroles" if target_kind == "clusterrole" else "roles"
                if not any(
                    _rule_grants(r, want_res, "bind", resource_name=target_name)
                    for p in rsets
                    for r in rules_of(p)
                ):
                    continue
                _edge("Identity", attacker, "ROLE_BIND", "PermSet", permset_id)

        for permset_id, props in permsets.items():
            target_kind = (props.get("kind") or "").lower()
            target_name = props.get("name")
            want_res = "clusterroles" if target_kind == "clusterrole" else "roles"
            if not any(
                _rule_grants(r, want_res, "escalate", resource_name=target_name)
                for p in rsets
                for r in rules_of(p)
            ):
                continue
            _edge("Identity", attacker, "ROLE_ESCALATE", "PermSet", permset_id)


def _is_parent(parent, child):
    """True if `parent` is a (strict) ancestor directory of `child`."""
    p = parent.rstrip("/")
    c = child.rstrip("/")
    return c.startswith(p + "/") or p == c


def _attacker_scope_for(attacker, identity_permsets, permsets, resource, verb):
    """Return the broadest scope ('*' or a namespace) at which the attacker
    holds (resource, verb). None if they don't hold it."""
    best = None
    for pid in sorted(identity_permsets.get(attacker, ())):
        props = permsets[pid]
        scope = props.get("scope")
        for rule in json.loads(props.get("rules") or "[]"):
            resources = rule.get("resources") or []
            verbs = rule.get("verbs") or []
            if (resource in resources or "*" in resources) and (
                verb in verbs or "*" in verbs
            ):
                if scope == "*":
                    return "*"
                best = scope
    return best


def _ingest_ownership(g, pods, serviceaccounts, identities):
    """Create App and Team nodes from ownership metadata (T3.2 — Track 03).

    All edges created here carry attack_path=0 FOREVER. INV-4 asserts this.
    No ownership node is created when the metadata is absent — never invented.
    """
    def _app_id(name, source):
        return f"app/{name}"

    def _team_id(name):
        return f"team/{name}"

    def _upsert_app(app_id, name, source):
        _q(g, (
            "MERGE (n:Entity:App {id:$id}) "
            "SET n.name = $name, n.source = $source"
        ), {"id": app_id, "name": name, "source": source})

    def _upsert_team(team_id, name):
        _q(g, (
            "MERGE (n:Entity:Team {id:$id}) SET n.name = $name"
        ), {"id": team_id, "name": name})

    def _belongs_to(entity_id, app_id):
        _q(g, (
            "MATCH (e {id:$eid}), (a:App {id:$aid}) "
            "MERGE (e)-[:BELONGS_TO {attack_path:0}]->(a)"
        ), {"eid": entity_id, "aid": app_id})

    def _owned_by(app_id, team_id):
        _q(g, (
            "MATCH (a:App {id:$aid}), (t:Team {id:$tid}) "
            "MERGE (a)-[:OWNED_BY {attack_path:0}]->(t)"
        ), {"aid": app_id, "tid": team_id})

    def _process_ownership(entity_id, ownership):
        if not ownership:
            return
        # Derive the canonical app name.
        app_name = (
            ownership.get("helm_release")
            or ownership.get("argocd_app")
            or ownership.get("part_of")
            or ownership.get("app_name")
        )
        if not app_name:
            return
        source = (
            "helm" if ownership.get("helm_release")
            else "argocd" if ownership.get("argocd_app")
            else "partOf"
        )
        aid = _app_id(app_name, source)
        _upsert_app(aid, app_name, source)
        _belongs_to(entity_id, aid)

        # Team from team_labels.
        team_labels = ownership.get("team_labels") or {}
        for val in team_labels.values():
            if val:
                tid = _team_id(val)
                _upsert_team(tid, val)
                _owned_by(aid, tid)

    for pod in pods:
        pid = f"pod/{pod['namespace']}/{pod['name']}"
        _process_ownership(pid, pod.get("ownership"))

    for sa in serviceaccounts:
        sid = f"sa/{sa['namespace']}/{sa['name']}"
        if sid in identities:
            _process_ownership(sid, sa.get("ownership"))


def node_ids(nodes):
    """Yield (node name, node id) pairs."""
    for node in nodes:
        yield node["name"], f"node/{node['name']}"


def _counts(g) -> dict:
    """Counts per label and relation — two grouped queries, not one per key.

    The grouped form matters at scale: a cluster with a hundred tenants and a
    dozen edge types would otherwise pay a query per key per request.
    """
    out = {label: 0 for label in _LABELS}
    for rt in _REL_TYPES + _ATTACK_REL_TYPES:
        out[rt] = 0
    try:
        res = _q(g, "MATCH (n) UNWIND labels(n) AS label RETURN label, count(*)")
        for label, count in res.result_set:
            if label in out:
                out[label] = count
    except Exception:  # noqa: BLE001,S110 — a graph that does not exist yet reads as zero
        pass
    try:
        res = _q(g, "MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS c")
        for rel_type, count in res.result_set:
            if rel_type in out:
                out[rel_type] = count
    except Exception:  # noqa: BLE001,S110
        pass
    return out


def _print_stats(g, result=None):
    if result is None:
        result = _counts(g)
    for label in _LABELS:
        print(f"{label}: {result.get(label, 0)}")
    for rt in _REL_TYPES + _ATTACK_REL_TYPES:
        print(f"{rt}: {result.get(rt, 0)}")


def _print_findings(summary):
    """The detector's one-line verdict after an ingest."""
    print(
        "findings: {routes} routes — {new} NEW, {resolved} RESOLVED, "
        "{accepted} ACCEPTED, {regressed} REGRESSED ({snapshot})".format(**summary)
    )
