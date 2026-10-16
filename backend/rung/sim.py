"""Change simulation — plain functions over a snapshot.

`simulate` removes (or adds) permissions and reports who could reach
cluster-admin with the change applied. It never touches FalkorDB; it works
purely on the snapshot dict, so it can be unit-tested without a server.
"""
import copy


def simulate(snapshot, remove_role_ref=None, add_role_ref=None):
    """Hypothetical graph after applying `remove_role_ref` / `add_role_ref`.

    `remove_role_ref` is "Kind/name@scope" (e.g. "ClusterRole/cluster-admin@*"):
    that role's rules are dropped, and every PermSet that binds it loses
    them. `add_role_ref` adds such a role, as if a ClusterRole had just been
    created. Returns {"baseline_reaching": [...], "after_reaching": [...]}.
    """
    baseline = _reaches(snapshot, None, None)
    after = _reaches(snapshot, remove_role_ref, add_role_ref)
    return {
        "baseline_reaching": baseline,
        "after_reaching": after,
    }


def _reaches(snapshot, remove_role_ref, add_role_ref):
    snap = copy.deepcopy(snapshot)
    dropped = set()
    if remove_role_ref:
        dropped.add(_role_key(remove_role_ref))
    if add_role_ref:
        _add_role(snap, add_role_ref)
    return _identities_reaching(snap, dropped)


def _add_role(snap, role_ref):
    kind, name, scope = _split_role_ref(role_ref)
    snap.setdefault("roles", []).append(
        {
            "kind": kind,
            "name": name,
            "namespace": None if scope == "*" else scope,
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"], "resourceNames": []}],
        }
    )


def _role_key(role_ref):
    """The (kind, name) identifying a role, e.g. ("ClusterRole", "cluster-admin")."""
    kind_name = role_ref.split("@", 1)[0]
    kind, name = kind_name.split("/", 1)
    return kind, name


def _add_role(snap, role_ref):
    kind, name, scope = _split_role_ref(role_ref)
    snap.setdefault("roles", []).append(
        {
            "kind": kind,
            "name": name,
            "namespace": None if scope == "*" else scope,
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"], "resourceNames": []}],
        }
    )


def _split_role_ref(role_ref):
    kind_name, scope = role_ref.split("@", 1)
    kind, name = kind_name.split("/", 1)
    return kind, name, scope


def _binding_scope(binding):
    if binding.get("kind") == "ClusterRoleBinding":
        return "*"
    return binding.get("namespace")


def _identities_reaching(snap, dropped):
    bindings = snap.get("bindings", []) or []
    # PermSets: one per (roleRef, scope).
    permsets = {}
    for binding in bindings:
        scope = _binding_scope(binding)
        role_ref = binding.get("roleRef") or {}
        rid = f"{role_ref.get('kind', '').lower()}/{role_ref.get('name', '')}@{scope}"
        if (role_ref.get("kind"), role_ref.get("name")) in dropped:
            continue
        role = _role(snap, role_ref.get("kind"), role_ref.get("name"), scope)
        rules = role.get("rules") or []
        admin = any(
            "*" in (rule.get("apiGroups") or [])
            and "*" in (rule.get("resources") or [])
            and "*" in (rule.get("verbs") or [])
            for rule in rules
        )
        permsets[rid] = {"rules": rules, "admin": bool(admin)}

    # identity -> the PermSets it can discover.
    discovered = {}
    for binding in bindings:
        scope = _binding_scope(binding)
        role_ref = binding.get("roleRef") or {}
        rid = f"{role_ref.get('kind', '').lower()}/{role_ref.get('name', '')}@{scope}"
        if (role_ref.get("kind"), role_ref.get("name")) in dropped:
            continue
        for subject in binding.get("subjects", []) or []:
            sid = _subject_id(subject)
            if sid is not None:
                discovered.setdefault(sid, set()).add(rid)

    reach = set()
    for identity, pids in discovered.items():
        for pid in pids:
            if permsets[pid]["admin"]:
                reach.add(identity)
    return sorted(reach)


def _role(snap, kind, name, scope):
    for role in snap.get("roles", []) or []:
        if role.get("kind") != kind or role.get("name") != name:
            continue
        if kind == "Role" and role.get("namespace") not in (None, scope):
            continue
        return role
    return {"rules": []}


def _subject_id(subject):
    kind = subject.get("kind")
    name = subject.get("name")
    namespace = subject.get("namespace")
    if kind == "ServiceAccount":
        return f"sa/{namespace}/{name}"
    if kind == "User":
        return f"user/{name}"
    if kind == "Group":
        return f"group/{name}"
    return None
