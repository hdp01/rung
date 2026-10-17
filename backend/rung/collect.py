"""`rung collect` — read a cluster (read-only) into the snapshot.json contract.

Implement per HANDOFF.md, Task 1. Writes the exact JSON shape documented there;
it is the only interface to the ingester. Never captures Secret .data.
"""

import json
import os
from datetime import UTC, datetime

from kubernetes import client, config


def _load_context(context: str) -> None:
    try:
        config.load_kube_config(context=context)
    except Exception:  # noqa: BLE001 — no kubeconfig: fall back to in-cluster
        config.load_incluster_config()


def collect(context: str, out: str) -> dict:
    _load_context(context)

    core = client.CoreV1Api()
    rbac = client.RbacAuthorizationV1Api()

    # Namespaces
    namespaces = []
    for ns in sorted(core.list_namespace().items, key=lambda n: n.metadata.name):
        labels = ns.metadata.labels or {}
        namespaces.append(
            {
                "name": ns.metadata.name,
                "enforce": labels.get("pod-security.kubernetes.io/enforce"),
            }
        )

    # Nodes
    nodes = []
    for node in sorted(core.list_node().items, key=lambda n: n.metadata.name):
        nodes.append({"name": node.metadata.name})

    # ServiceAccounts
    serviceaccounts = []
    for sa in sorted(
        core.list_service_account_for_all_namespaces().items,
        key=lambda s: (s.metadata.namespace or "", s.metadata.name or ""),
    ):
        serviceaccounts.append(
            {
                "name": sa.metadata.name,
                "namespace": sa.metadata.namespace,
                "automount": sa.automount_service_account_token,
                "ownership": _ownership(sa.metadata),
            }
        )

    # Secrets — record existence + type + owning SA, never .data.
    secrets = []
    for sec in sorted(
        core.list_secret_for_all_namespaces().items,
        key=lambda s: (s.metadata.namespace or "", s.metadata.name or ""),
    ):
        ann = sec.metadata.annotations or {}
        secrets.append(
            {
                "name": sec.metadata.name,
                "namespace": sec.metadata.namespace,
                "type": sec.type,
                "saName": ann.get("kubernetes.io/service-account.name"),
            }
        )

    # Pods
    pods = []
    for pod in sorted(
        core.list_pod_for_all_namespaces().items,
        key=lambda p: (p.metadata.namespace or "", p.metadata.name or ""),
    ):
        spec = pod.spec or client.V1PodSpec()
        node_name = getattr(spec, "node_name", None)
        containers_out = []
        # map volume name -> list of mount paths across containers
        volume_mountpaths = {}
        for c in spec.containers or []:
            csc = getattr(c, "security_context", None)
            caps = None
            if csc is not None and getattr(csc, "capabilities", None) is not None:
                caps = list(csc.capabilities.add or [])
            else:
                caps = []
            for vm in getattr(c, "volume_mounts", None) or []:
                volume_mountpaths.setdefault(vm.name, []).append(vm.mount_path)
            containers_out.append(
                {
                    "name": c.name,
                    "image": c.image,
                    "privileged": (csc.privileged if csc is not None else None),
                    "caps": caps,
                    "runAsUser": (getattr(csc, "run_as_user", None) if csc is not None else None),
                }
            )

        host_volumes = []
        for v in spec.volumes or []:
            hp = getattr(v, "host_path", None)
            if hp is None:
                continue
            host_volumes.append(
                {
                    "name": v.name,
                    "hostPath": getattr(hp, "path", None),
                    "mountPaths": volume_mountpaths.get(v.name, []),
                }
            )

        pods.append(
            {
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "serviceAccount": getattr(spec, "service_account_name", None) or getattr(spec, "service_account", None),
                "node": node_name,
                "hostPID": getattr(spec, "host_pid", None),
                "hostNetwork": getattr(spec, "host_network", None),
                "automount": getattr(spec, "automount_service_account_token", None),
                "containers": containers_out,
                "hostVolumes": host_volumes,
                "ownership": _ownership(pod.metadata),
            }
        )

    # Roles (namespace-scoped Role) + ClusterRole
    roles = []
    for r in sorted(rbac.list_role_for_all_namespaces().items, key=lambda x: ((x.metadata.namespace or ""), x.metadata.name or "")):
        roles.append(_role_to_dict(r, kind="Role"))
    for r in sorted(rbac.list_cluster_role().items, key=lambda x: x.metadata.name or ""):
        roles.append(_role_to_dict(r, kind="ClusterRole"))

    # Bindings
    bindings = []
    for b in sorted(rbac.list_role_binding_for_all_namespaces().items, key=lambda x: ((x.metadata.namespace or ""), x.metadata.name or "")):
        bindings.append(_binding_to_dict(b, kind="RoleBinding"))
    for b in sorted(rbac.list_cluster_role_binding().items, key=lambda x: x.metadata.name or ""):
        bindings.append(_binding_to_dict(b, kind="ClusterRoleBinding"))

    snapshot = {
        "meta": {
            "collected_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "context": context,
        },
        "namespaces": namespaces,
        "nodes": nodes,
        "serviceaccounts": serviceaccounts,
        "secrets": secrets,
        "pods": pods,
        "roles": roles,
        "bindings": bindings,
    }

    out_dir = os.path.dirname(os.path.abspath(out))
    os.makedirs(out_dir, exist_ok=True)
    with open(out, "w") as f:
        json.dump(snapshot, f, indent=2)
    return snapshot


def _ownership(meta) -> dict | None:
    """Extract ownership metadata from a Kubernetes ObjectMeta.

    Returns null (None) when no ownership signal is present — never invents.
    """
    ann = meta.annotations or {}
    labels = meta.labels or {}
    owner_refs = []
    for ref in meta.owner_references or []:
        owner_refs.append({"kind": ref.kind, "name": ref.name})

    team_labels = {}
    for key in list(labels):
        lower = key.lower()
        if any(seg in lower for seg in ("team", "owner", "contact")):
            team_labels[key] = labels[key]

    result = {
        "helm_release": ann.get("meta.helm.sh/release-name"),
        "argocd_app": ann.get("argocd.argoproj.io/instance"),
        "managed_by": labels.get("app.kubernetes.io/managed-by"),
        "part_of": labels.get("app.kubernetes.io/part-of"),
        "app_name": labels.get("app.kubernetes.io/name"),
        "team_labels": team_labels or None,
        "owner_refs": owner_refs or None,
    }
    # Return None if nothing was found — never store empty ownership dicts.
    if all(v is None for v in result.values()):
        return None
    return result


def _rule_api(rule):
    return {
        "apiGroups": list(rule.api_groups or []),
        "resources": list(rule.resources or []),
        "verbs": list(rule.verbs or []),
        "resourceNames": list(rule.resource_names or []),
    }


def _role_to_dict(role, kind: str) -> dict:
    meta = role.metadata or client.V1ObjectMeta()
    rules = [_rule_api(r) for r in (role.rules or [])]
    return {
        "kind": kind,
        "name": meta.name,
        "namespace": (meta.namespace if kind == "Role" else None),
        "rules": rules,
        "ownership": _ownership(meta),
    }


def _subject_to_dict(s) -> dict:
    return {
        "kind": s.kind,
        "name": s.name,
        "namespace": getattr(s, "namespace", None),
    }


def _binding_to_dict(binding, kind: str) -> dict:
    meta = binding.metadata or client.V1ObjectMeta()
    role_ref = binding.role_ref
    subjects = [_subject_to_dict(s) for s in (binding.subjects or [])]
    return {
        "kind": kind,
        "name": meta.name,
        "namespace": (meta.namespace if kind == "RoleBinding" else None),
        "subjects": subjects,
        "roleRef": {
            "kind": role_ref.kind,
            "name": role_ref.name,
        },
        "ownership": _ownership(meta),
    }
