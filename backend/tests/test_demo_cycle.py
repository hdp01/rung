"""A2's acceptance test: the committed demo triple replays v1 → v2 → v3.

Hermetic — ingests the three committed snapshots into one scratch graph and
asserts the scripted moments: v1 tracks 73 routes, accepting the hero chain's
argocd route covers 32 findings, v2 (the fix) resolves 68 routes and flags
nothing, and v3 (the same admin grant re-added through a different route for
the jenkins build-deployer SA) produces REGRESSED findings — the brand-new
bypass is `previous_status = ACCEPTED` and traverses none of the controls the
acceptance relied on; the grant's other closed routes "walk again".
"""
import json
import os
from pathlib import Path

import pytest
from falkordb import FalkorDB

from rung import findings as findings_logic
from rung.ingest import ingest

DATA = Path(__file__).resolve().parent.parent / "data"
V1, V2, V3 = (DATA / name for name in (
    "demo-snapshot.json",
    "demo-snapshot-v2.json",
    "demo-snapshot-v3.json",
))
HERO_SOURCE = "pod/jenkins/ci-runner"
DEPLOYER = "sa/jenkins/build-deployer"
ARGOCD_GRANT = "argocd-application-controller"
NEW_BINDING = "argocd-jenkins-deploy"


@pytest.fixture
def env(tmp_path, monkeypatch):
    graph = f"rung:test-demo-cycle-{os.getpid()}-{tmp_path.name}"
    monkeypatch.setenv("FALKORDB_HOST", "localhost")
    monkeypatch.setenv("FALKORDB_PORT", "6380")
    monkeypatch.setenv("FALKORDB_GRAPH", graph)
    g = FalkorDB(host="localhost", port=6380).select_graph(graph)
    g.query("MATCH (n) DETACH DELETE n")
    yield g, graph
    try:
        g.delete()  # drop the whole graph: tests must not accumulate one each
    except Exception:  # noqa: BLE001,S110 — best-effort cleanup
        pass


def _finding_nodes(g, route_fp):
    rows = g.query(
        "MATCH (f:Finding {id:$id}) RETURN f.nodes", {"id": route_fp}
    ).result_set
    return set(json.loads(rows[0][0])) if rows else set()


def _hero_route(g):
    for route in findings_logic.canonical_routes(g):
        if route["source"] == HERO_SOURCE and route["target"].startswith(ARGOCD_GRANT):
            return route
    return None


def test_demo_cycle_resolves_then_regresses(env):
    g, graph = env

    # -- v1: the risk is live ------------------------------------------------
    v1 = ingest(str(V1), graph_name=graph)["findings"]
    assert v1["routes"] == 73, f"v1 should track 73 routes, got {v1['routes']}"

    hero = _hero_route(g)
    assert hero is not None, "v1 lost the hero chain"
    assert "CE_" in hero["route"], "the hero route must go through a container escape"

    exception = findings_logic.accept(
        g, hero["route_fp"], note="known CI risk while the binding is removed"
    )
    assert exception["relies_on"], "the acceptance must trust at least one control"
    accepted = [
        f for f in findings_logic.list_findings(g) if f["status"] == "ACCEPTED"
    ]
    assert len(accepted) == 32, f"the acceptance should cover 32 routes, covered {len(accepted)}"
    assert all(f["target_fp"] == hero["target_fp"] for f in accepted)

    # -- v2: the fix resolves the accepted routes and flags nothing ----------
    v2 = ingest(str(V2), graph_name=graph)["findings"]
    assert v2["routes"] == 7, f"v2 should keep 7 routes, got {v2['routes']}"
    assert v2["resolved"] == 68, f"the fix should resolve 68 routes, got {v2['resolved']}"
    assert v2["regressed"] == 0, "the fix itself must not flag regressions"

    # the hero route the acceptance trusted is now RESOLVED
    hero_after = next(
        f for f in findings_logic.list_findings(g) if f["route_fp"] == hero["route_fp"]
    )
    assert hero_after["status"] == "RESOLVED"
    assert hero_after["previous_status"] == "ACCEPTED"

    # -- v3: the same grant comes back through a different route -------------
    v3 = ingest(str(V3), graph_name=graph)["findings"]
    assert v3["routes"] == 15, f"v3 should expose 15 routes, got {v3['routes']}"
    assert v3["regressed"] == 7, f"seven routes should regress, got {v3['regressed']}"

    findings = findings_logic.list_findings(g)
    regressed = [f for f in findings if f["status"] == "REGRESSED"]
    sources = {
        r["route_fp"]: r["source"] for r in findings_logic.canonical_routes(g)
    }

    # the brand-new bypass: the deployer SA was handed the same admin role
    bypass = [f for f in regressed if sources.get(f["route_fp"]) == DEPLOYER]
    assert len(bypass) == 1, "the deployer's new route must be one REGRESSED finding"
    (bypass,) = bypass
    assert bypass["target_fp"] == hero["target_fp"], "the bypass must hit the accepted grant"
    assert bypass["previous_status"] == "ACCEPTED"
    assert bypass["route"] == "PERMISSION_DISCOVER › ADMIN_OF"
    relied = set(exception["relies_on"])
    assert relied.isdisjoint(_finding_nodes(g, bypass["route_fp"])), (
        "REGRESSED must traverse none of the exception's controls"
    )

    # the grant's other closed routes walk again, and are flagged as such
    walk_again = [f for f in regressed if f["previous_status"] == "RESOLVED"]
    assert walk_again, "re-adding the grant must surface 'closed route walks again'"
    assert all(f["target_fp"] == hero["target_fp"] for f in regressed)


def test_demo_snapshot_files_are_the_scripted_delta():
    """The triple differs by exactly the two changes the demo narrates."""
    v1, v2, v3 = (json.loads(path.read_text()) for path in (V1, V2, V3))

    def identities(snapshot, key):
        return {
            (item.get("kind"), item.get("namespace"), item.get("name"))
            for item in snapshot.get(key) or []
        }

    # v2 = v1 minus the argocd admin ClusterRoleBinding, nothing else.
    removed = identities(v1, "bindings") - identities(v2, "bindings")
    added = identities(v2, "bindings") - identities(v1, "bindings")
    assert removed == {("ClusterRoleBinding", None, "argocd-application-controller")}
    assert added == set()
    for key in ("namespaces", "nodes", "serviceaccounts", "pods", "roles"):
        assert identities(v1, key) == identities(v2, key), f"v2 drifted on {key}"
    # one live-fixture secret (a bootstrap token) expired between collections;
    # it is not a service-account token and cannot change any route.
    assert {s["name"] for s in v1["secrets"]} - {s["name"] for s in v2["secrets"]} == {
        "bootstrap-token-abcdef"
    }

    # v3 = v2 plus the deploy binding that re-adds the grant to the CI SA.
    added = identities(v3, "bindings") - identities(v2, "bindings")
    removed = identities(v2, "bindings") - identities(v3, "bindings")
    assert removed == set()
    assert added == {("ClusterRoleBinding", None, NEW_BINDING)}
    for key in ("namespaces", "nodes", "serviceaccounts", "secrets", "pods", "roles"):
        assert identities(v2, key) == identities(v3, key), f"v3 drifted on {key}"

    (binding,) = [b for b in v3["bindings"] if b["name"] == NEW_BINDING]
    assert binding["roleRef"] == {"kind": "ClusterRole", "name": ARGOCD_GRANT}
    assert binding["subjects"] == [
        {"kind": "ServiceAccount", "name": "build-deployer", "namespace": "jenkins"}
    ]
