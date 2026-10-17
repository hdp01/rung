#!/usr/bin/env python3
"""Track 02 demo — the full v1 → v2 → v3 cycle: RESOLVED, then REGRESSED.

Run it via ``bash scripts/regression-cycle-demo.sh``. No cluster is needed:
the three snapshots are committed files, so the whole story replays in
seconds and gives the same answer every time.

1. reset the detector's memory in the tenant graph (``--keep-history`` skips)
2. ingest v1 (``data/demo-snapshot.json``): every route is NEW; then accept
   the risk on the hero chain — ``pod/jenkins/ci-runner`` › CE_MODULE_LOAD ›
   TOKEN_STEAL › PERMISSION_DISCOVER › ADMIN_OF — trusting the host token path
   and the argocd service account (the ``relies_on`` control) while the fix
   lands. Every route the acceptance covers flips to ACCEPTED.
3. ingest v2 (``data/demo-snapshot-v2.json``): the fix deleted the argocd
   admin ClusterRoleBinding, so the accepted argocd routes — and every route
   that only walked through the argocd SA — are reported RESOLVED.
4. ingest v3 (``data/demo-snapshot-v3.json``): an integration binding re-added
   the *same* admin grant to ServiceAccount jenkins/build-deployer by a
   different route that traverses none of the controls the acceptance relied
   on -> REGRESSED findings with ``previous_status = ACCEPTED`` (the new
   bypasses) and REGRESSED "closed route walks again" for the grant's other
   routes the fix had closed.

Exit status is 0 only when all of that held and — when the API is up —
``GET /findings`` agrees. This script is the acceptance test for A2.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from rung import findings as detector
from rung import graph as graph_logic
from rung.ingest import ingest

HERO_SOURCE = "pod/jenkins/ci-runner"
ARGOCD_GRANT = "argocd-application-controller"


def _ingest_summary(path, graph_name, label):
    summary = ingest(str(path), graph_name=graph_name)["findings"]
    print(
        f"• ingest {label}: {summary['routes']} routes — "
        f"{summary['new']} NEW, {summary['resolved']} RESOLVED, "
        f"{summary['accepted']} ACCEPTED, {summary['regressed']} REGRESSED"
    )
    return summary


def _counts(g):
    return detector.status_counts(detector.list_findings(g))


def _print_transitions(g, needles, limit=8):
    changed = [
        f
        for f in detector.list_findings(g)
        if f["status"] in needles and f.get("previous_status")
    ]
    for finding in changed[:limit]:
        print(f"    {finding['status']:<9} was {finding.get('previous_status'):<8} "
              f"{finding['route']}")
        print(f"              target {finding['target']}  ({finding['route_fp']})")
        if finding.get("note"):
            print(f"              {finding['note']}")
    if len(changed) > limit:
        print(f"    … and {len(changed) - limit} more")


def _api_findings(api, tenant):
    """The same view the UI reads; None when the API isn't running."""
    url = f"{api.rstrip('/')}/findings?tenant={tenant}"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", default="kind-graphhacks")
    parser.add_argument(
        "--api", default="http://localhost:8000", help="verify through this API"
    )
    parser.add_argument(
        "--data-dir", default=str(BACKEND / "data"), help="where the snapshots live"
    )
    parser.add_argument(
        "--keep-history",
        action="store_true",
        help="diff against whatever memory already exists",
    )
    args = parser.parse_args(argv)

    started = time.time()
    data = Path(args.data_dir)
    v1 = data / "demo-snapshot.json"
    v2 = data / "demo-snapshot-v2.json"
    v3 = data / "demo-snapshot-v3.json"
    for path in (v1, v2, v3):
        if not path.exists():
            print(f"! missing snapshot {path} — regenerate with "
                  f"scripts/make_demo_snapshots.py")
            return 2

    graph_name = f"rung:{args.tenant}"
    g = graph_logic.connect_for(args.tenant)
    try:
        g.query("RETURN 1")
    except Exception as exc:  # noqa: BLE001
        print(f"! FalkorDB is not reachable: {exc}")
        return 2

    if not args.keep_history:
        detector.reset_memory(g)
        g.query("MATCH (n:Exception) DETACH DELETE n")
        print("• detector memory reset (findings + snapshot log + exceptions)")

    # 1. v1 — the risk is live, and the operator accepts it.
    summary_v1 = _ingest_summary(v1, graph_name, "v1 (risk live)")
    hero = [
        r
        for r in detector.canonical_routes(g)
        if r["source"] == HERO_SOURCE and r["target"].startswith(ARGOCD_GRANT)
    ]
    if not hero:
        print(f"! no hero-chain route ({HERO_SOURCE} → {ARGOCD_GRANT}) in v1")
        return 1
    exception = detector.accept(
        g,
        hero[0]["route_fp"],
        title=f"{HERO_SOURCE}: admin via the argocd binding",
        note="known CI risk while the argocd admin binding is removed",
    )
    print(f"• v1 Exception accepted: {exception['title']}")
    print(f"    relies_on: {', '.join(exception['relies_on'])}")
    accepted_v1 = _counts(g)["ACCEPTED"]
    print(f"• routes covered by the acceptance now: {accepted_v1} ACCEPTED")

    # 2. v2 — the fix; the accepted routes close.
    summary_v2 = _ingest_summary(v2, graph_name, "v2 (the fix)")
    print("  transitions the detector reported:")
    _print_transitions(g, ("RESOLVED", "REGRESSED"))

    # 3. v3 — the risk comes back through a different route.
    summary_v3 = _ingest_summary(v3, graph_name, "v3 (different route)")
    print("  transitions the detector reported:")
    _print_transitions(g, ("REGRESSED",))

    counts = _counts(g)
    print(f"\nfinal /findings statuses: {counts}")
    history = detector.snapshot_history(g)
    print(
        f"snapshot history: {len(history)} ingested"
        + "".join(f"\n  {s['at']}  routes={s['routes']} resolved={s['resolved']}" for s in history)
    )

    api = _api_findings(args.api, args.tenant)
    if api is not None:
        api_counts = api.get("counts") or {}
        print(f"API check: GET {args.api}/findings counts = {api_counts}")
    else:
        api_counts = None
        print("API check: skipped (API not running)")

    checks = [
        (summary_v1["routes"] > 0, "v1 has routes to track"),
        (accepted_v1 > 0, "the v1 acceptance covered at least one route"),
        (summary_v2["resolved"] > 0, "the fix resolved at least one route"),
        (summary_v3["regressed"] > 0, "the different route was flagged REGRESSED"),
        (
            counts["REGRESSED"] > 0,
            "a REGRESSED finding is visible in /findings memory",
        ),
    ]
    if api_counts is not None:
        checks.append((int(api_counts.get("REGRESSED") or 0) > 0, "the API agrees (REGRESSED)"))
        checks.append((int(api_counts.get("RESOLVED") or 0) > 0, "the API agrees (RESOLVED)"))
    failed = [why for ok, why in checks if not ok]
    if failed:
        print("\n✘ the cycle did not hold:")
        for why in failed:
            print(f"    - {why}")
    else:
        print(
            f"\n✔ full cycle verified: v1 {summary_v1['routes']} routes → "
            f"accept {accepted_v1} → v2 {summary_v2['resolved']} RESOLVED → "
            f"v3 {summary_v3['regressed']} REGRESSED (was ACCEPTED)"
        )
        print("  regenerate the snapshots from a live cluster: "
              "python scripts/make_demo_snapshots.py")
    print(f"done in {time.time() - started:.1f}s")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
