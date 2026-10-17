#!/usr/bin/env python3
"""Produce data/demo-snapshot-v2.json and data/demo-snapshot-v3.json from a live cluster.

Track 02, task A2. Starting from the committed baseline
(``data/demo-snapshot.json`` — v1, the hero chain's admin grant intact):

1. restore the baseline: the argocd ClusterRoleBinding is present and the
   v3 ClusterRoleBinding does not exist (an interrupted previous run is fixed)
2. **the deliberate change**: delete ClusterRoleBinding/argocd-application-controller
   — the admin grant the hero chain steals a token for — and re-collect
   -> ``data/demo-snapshot-v2.json``  (the fix; every argocd route closes)
3. **the different route**: create ClusterRoleBinding/argocd-jenkins-deploy,
   binding the *same* argocd admin ClusterRole to ServiceAccount
   jenkins/build-deployer — the CI pipeline's deploy identity — and re-collect
   -> ``data/demo-snapshot-v3.json``  (same target, new route; reopens the risk)
4. restore the cluster (delete the new binding, re-create the original one)

The committed triples are then proven before the script exits: each file is
ingested into a scratch graph and the route counts must match the scripted
story (v1: 73 routes; v2: 7 routes, none to the argocd grant; v3: 15 routes,
7 to the argocd grant — including a brand-new one from sa/jenkins/build-deployer).
Run the offline replay any time with ``bash scripts/regression-cycle-demo.sh``.
"""
import argparse
import json
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from rung import findings as detector
from rung import graph as graph_logic
from rung.collect import collect
from rung.ingest import ingest

FIX_BINDING = "argocd-application-controller"
NEW_BINDING = "argocd-jenkins-deploy"
ARGOCD_ROLE = "argocd-application-controller"
JENKINS_SA = ("jenkins", "build-deployer")
SNAPSHOT_KEYS = ("namespaces", "nodes", "serviceaccounts", "secrets", "pods", "roles", "bindings")


def _rbac(context):
    from kubernetes import client, config

    config.load_kube_config(context=context)
    return client.RbacAuthorizationV1Api(), client


def _identity(item):
    return (item.get("kind"), item.get("namespace"), item.get("name"))


def _identity_diff(live, committed):
    """Identities present in only one of the two snapshots, per key."""
    out = {}
    for key in SNAPSHOT_KEYS:
        a = {_identity(x) for x in live.get(key) or []}
        b = {_identity(x) for x in committed.get(key) or []}
        if a != b:
            out[key] = {"live_only": sorted(a - b), "committed_only": sorted(b - a)}
    return out


def _fix_binding_body(client):
    """The original binding as the fixture declares it (restore fallback)."""
    return client.V1ClusterRoleBinding(
        metadata=client.V1ObjectMeta(name=FIX_BINDING),
        role_ref=client.V1RoleRef(
            api_group="rbac.authorization.k8s.io", kind="ClusterRole", name=ARGOCD_ROLE
        ),
        subjects=[
            client.V1Subject(
                kind="ServiceAccount",
                name="argocd-application-controller",
                namespace="argocd",
            )
        ],
    )


def _new_binding_body(client):
    """The v3 change: the same admin role, the CI pipeline's own SA."""
    namespace, name = JENKINS_SA
    return client.V1ClusterRoleBinding(
        metadata=client.V1ObjectMeta(name=NEW_BINDING),
        role_ref=client.V1RoleRef(
            api_group="rbac.authorization.k8s.io", kind="ClusterRole", name=ARGOCD_ROLE
        ),
        subjects=[
            client.RbacV1Subject(kind="ServiceAccount", name=name, namespace=namespace)
        ],
    )


def _delete(rbac, name):
    from kubernetes.client.exceptions import ApiException

    try:
        rbac.delete_cluster_role_binding(name=name)
        return True
    except ApiException as exc:
        if exc.status != 404:
            raise
        return False


def _ensure_fix_binding(rbac, client):
    """The original binding must be live before v2 is collected."""
    from kubernetes.client.exceptions import ApiException

    try:
        return rbac.read_cluster_role_binding(name=FIX_BINDING)
    except ApiException as exc:
        if exc.status != 404:
            raise
        body = _fix_binding_body(client)
        rbac.create_cluster_role_binding(body=body)
        print(f"• {FIX_BINDING} was missing; re-created it before generating")
        return body


def _create_new_binding(rbac, client):
    rbac.create_cluster_role_binding(body=_new_binding_body(client))
    print(f"• different route: created ClusterRoleBinding/{NEW_BINDING} -> "
          f"ClusterRole/{ARGOCD_ROLE} for sa/{JENKINS_SA[0]}/{JENKINS_SA[1]}")


def _verify(files):
    """Ingest the committed triple and prove the scripted numbers."""
    expected = {
        "v1": {"routes": 73, "argocd": 36},
        "v2": {"routes": 7, "argocd": 0},
        "v3": {"routes": 15, "argocd": 7},
    }
    ok = True
    for label, path in files.items():
        graph_name = f"rung:scratch-demo-{label}"
        g = graph_logic.connect_to(graph_name)
        try:
            ingest(str(path), graph_name=graph_name)
            routes = detector.canonical_routes(g)
            argocd = [r for r in routes if r["target"].startswith(ARGOCD_ROLE)]
            want = expected[label]
            count_ok = len(routes) == want["routes"] and len(argocd) == want["argocd"]
            detail = f"{len(routes)} routes, {len(argocd)} to the argocd grant"
            if label == "v3":
                new_route = [
                    r for r in argocd
                    if r["source"] == f"sa/{JENKINS_SA[0]}/{JENKINS_SA[1]}"
                ]
                count_ok = count_ok and len(new_route) == 1
                detail += f", {len(new_route)} from sa/{JENKINS_SA[0]}/{JENKINS_SA[1]}"
            mark = "✔" if count_ok else "✘"
            print(f"  {mark} {label}: {detail} (wanted {want['routes']}/{want['argocd']})")
            ok = ok and count_ok
        finally:
            g.delete()
    return ok


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", default="kind-graphhacks")
    parser.add_argument("--data-dir", default=str(BACKEND / "data"))
    args = parser.parse_args(argv)

    started = time.time()
    data = Path(args.data_dir)
    v1 = data / "demo-snapshot.json"
    v2 = data / "demo-snapshot-v2.json"
    v3 = data / "demo-snapshot-v3.json"

    rbac, client = _rbac(args.context)
    live = _ensure_fix_binding(rbac, client)
    if _delete(rbac, NEW_BINDING):
        print(f"• cleaned up a leftover ClusterRoleBinding/{NEW_BINDING}")

    # Baseline drift check: what does the live cluster hold today vs the
    # committed v1? Anything beyond the known fixture drift is worth seeing.
    baseline_live = data / "demo-snapshot-live.json"
    collect(context=args.context, out=str(baseline_live))
    drift = _identity_diff(
        json.loads(baseline_live.read_text()), json.loads(v1.read_text())
    )
    baseline_live.unlink(missing_ok=True)
    if drift:
        print("• baseline drift vs committed v1 (not produced by this run):")
        for key, delta in drift.items():
            print(f"    {key}: live_only={delta['live_only']} committed_only={delta['committed_only']}")
    else:
        print("• baseline matches committed v1 exactly")

    try:
        _delete(rbac, FIX_BINDING)
        print(f"• deliberate change: deleted ClusterRoleBinding/{FIX_BINDING}")
        collect(context=args.context, out=str(v2))
        print(f"• collected v2 -> {v2}")

        _create_new_binding(rbac, client)
        collect(context=args.context, out=str(v3))
        print(f"• collected v3 -> {v3}")
    finally:
        _delete(rbac, NEW_BINDING)
        if not live:
            live = _fix_binding_body(client)
        metadata = live.metadata
        if metadata is not None:
            metadata.resource_version = None
            metadata.uid = None
            metadata.creation_timestamp = None
            metadata.managed_fields = None
        from kubernetes.client.exceptions import ApiException

        try:
            rbac.create_cluster_role_binding(body=live)
            print(f"• restored ClusterRoleBinding/{FIX_BINDING} (cluster is reusable)")
        except ApiException as exc:
            if exc.status != 409:
                raise
            print(f"• ClusterRoleBinding/{FIX_BINDING} already present")

    print("\nproving the committed triple:")
    ok = _verify({"v1": v1, "v2": v2, "v3": v3})
    if ok:
        print("\n✔ demo snapshots written and verified (v1 → v2 → v3)")
    else:
        print("\n✘ verification failed — do not commit these files")
    print(f"done in {time.time() - started:.1f}s")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
