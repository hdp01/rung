#!/usr/bin/env python3
"""Track 02 demo: two snapshots, one deliberate change, a RESOLVED finding.

Run it via `bash scripts/regression-demo.sh` (which brings FalkorDB up). It
finishes in well under a minute against the bundled kind cluster:

1. reset the detector's memory in the tenant graph (``--keep-history`` skips)
2. collect snapshot A from the live cluster and ingest it — every route is NEW
3. delete the ``argocd-application-controller`` ClusterRoleBinding, the admin
   grant the hero chain steals a token for
4. collect snapshot B and ingest it — the detector diffs the fingerprints and
   reports the routes that no longer walk as RESOLVED
5. verify the same answer through `GET /findings` when the API is running,
   print the transition table, and restore the binding (``--keep-broken``
   leaves the cluster fixed)

Exit status is 0 only when the second ingest emitted at least one RESOLVED
finding — this script is the acceptance test for the regression detector.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from rung import findings as detector
from rung import graph as graph_logic
from rung.collect import collect
from rung.ingest import ingest

BINDING = "argocd-application-controller"


def _rbac(context):
    from kubernetes import client, config

    config.load_kube_config(context=context)
    return client.RbacAuthorizationV1Api(), client


def _binding_body(client):
    """The ClusterRoleBinding as the fixture declares it (fallback restore)."""
    return client.V1ClusterRoleBinding(
        metadata=client.V1ObjectMeta(name=BINDING),
        role_ref=client.V1RoleRef(
            api_group="rbac.authorization.k8s.io",
            kind="ClusterRole",
            name=BINDING,
        ),
        subjects=[
            client.V1Subject(
                kind="ServiceAccount",
                name=BINDING,
                namespace="argocd",
            )
        ],
    )


def _ensure_binding(rbac, client):
    """Return the live binding, re-creating it if a previous run left it out."""
    from kubernetes.client.exceptions import ApiException

    try:
        return rbac.read_cluster_role_binding(name=BINDING)
    except ApiException as exc:
        if exc.status != 404:
            raise
        body = _binding_body(client)
        rbac.create_cluster_role_binding(body=body)
        print(f"• {BINDING} was missing; re-created it before the demo")
        return body


def _delete_binding(rbac):
    rbac.delete_cluster_role_binding(name=BINDING)
    print(f"• deliberate change: deleted ClusterRoleBinding/{BINDING}")


def _restore_binding(rbac, body):
    from kubernetes.client.exceptions import ApiException

    metadata = body.metadata
    if metadata is not None:
        metadata.resource_version = None
        metadata.uid = None
        metadata.creation_timestamp = None
        metadata.managed_fields = None
    try:
        rbac.create_cluster_role_binding(body=body)
        print(f"• restored ClusterRoleBinding/{BINDING} (cluster is reusable)")
    except ApiException as exc:
        if exc.status != 409:
            raise
        print(f"• ClusterRoleBinding/{BINDING} already present")


def _ingest_summary(path, graph_name, label):
    summary = ingest(path, graph_name=graph_name)["findings"]
    print(
        f"• ingest {label}: {summary['routes']} routes — "
        f"{summary['new']} NEW, {summary['resolved']} RESOLVED, "
        f"{summary['accepted']} ACCEPTED, {summary['regressed']} REGRESSED"
    )
    return summary


def _api_findings(api, tenant):
    """The same view the UI reads; None when the API isn't running."""
    url = f"{api.rstrip('/')}/findings?tenant={tenant}"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def _print_transitions(g):
    changed = [
        f
        for f in detector.list_findings(g)
        if f["status"] in ("RESOLVED", "REGRESSED")
    ]
    for finding in changed[:8]:
        was = finding.get("previous_status") or "?"
        print(f"    {finding['status']:<9} was {was:<8} {finding['route']}")
        print(f"              target {finding['target']}  ({finding['route_fp']})")
    if len(changed) > 8:
        print(f"    … and {len(changed) - 8} more")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", default="kind-graphhacks")
    parser.add_argument("--tenant", default="kind-graphhacks")
    parser.add_argument(
        "--api", default="http://localhost:8000", help="verify through this API"
    )
    parser.add_argument(
        "--keep-history",
        action="store_true",
        help="diff against whatever memory already exists",
    )
    parser.add_argument(
        "--keep-broken",
        action="store_true",
        help="leave the ClusterRoleBinding deleted (do not restore)",
    )
    args = parser.parse_args(argv)

    started = time.time()
    graph_name = f"rung:{args.tenant}"
    g = graph_logic.connect_for(args.tenant)
    try:
        g.query("RETURN 1")
    except Exception as exc:  # noqa: BLE001
        print(f"! FalkorDB is not reachable: {exc}")
        return 2

    rbac, client = _rbac(args.context)
    live = _ensure_binding(rbac, client)

    if not args.keep_history:
        detector.reset_memory(g)
        print("• detector memory reset (findings + snapshot log)")

    snapshot_a = str(BACKEND / "data" / "demo-snapshot-a.json")
    snapshot_b = str(BACKEND / "data" / "demo-snapshot-b.json")
    had_routes = False
    try:
        collect(context=args.context, out=snapshot_a)
        print(f"• collected snapshot A -> {snapshot_a}")
        summary_a = _ingest_summary(snapshot_a, graph_name, "A (before)")
        had_routes = summary_a["routes"] > 0

        _delete_binding(rbac)

        collect(context=args.context, out=snapshot_b)
        print(f"• collected snapshot B -> {snapshot_b}")
        summary_b = _ingest_summary(snapshot_b, graph_name, "B (after the fix)")

        print("\ntransitions the detector reported:")
        _print_transitions(g)

        history = detector.snapshot_history(g)
        print(
            f"\nsnapshot history: {len(history)} ingested"
            + "".join(f"\n  {s['at']}  routes={s['routes']} resolved={s['resolved']}" for s in history)
        )

        api = _api_findings(args.api, args.tenant)
        if api is not None:
            counts = api.get("counts") or {}
            print(
                f"API check: GET {args.api}/findings counts = {counts}"
            )
            api_resolved = int(counts.get("RESOLVED") or 0)
        else:
            api_resolved = None
            print("API check: skipped (API not running)")

        ok = summary_b["resolved"] >= 1 and had_routes
        if ok:
            print(
                f"\n✔ regression detection verified: {summary_b['resolved']} route(s) "
                f"RESOLVED after the deliberate change"
            )
        else:
            print(
                "\n✘ the second ingest did not report a RESOLVED route — "
                "the detector or the cluster state is wrong"
            )
        if api_resolved is not None and api_resolved < 1:
            print("✘ the API agrees? no: /findings reports no RESOLVED entries")
            ok = False
        print(f"done in {time.time() - started:.1f}s")
        return 0 if ok else 1
    finally:
        if not args.keep_broken:
            _restore_binding(rbac, live)


if __name__ == "__main__":
    sys.exit(main())
