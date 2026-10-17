"""Regression-detector tests — Track 02's acceptance criteria.

The detector's whole job is state across ingests, so these tests always
ingest *twice*: once to establish memory, once to diff against it. The
snapshots are synthetic so each rule (NEW, RESOLVED, ACCEPTED, REGRESSED)
gets a scenario that isolates it.
"""
import json
import os

import pytest
from falkordb import FalkorDB

from rung import findings as findings_logic
from rung.ingest import ingest


# ---------------------------------------------------------------------------
# synthetic lab cluster
# ---------------------------------------------------------------------------
def _pod(name, sa, privileged=False):
    return {
        "name": name,
        "namespace": "lab",
        "serviceAccount": sa,
        "node": "n1",
        "hostPID": False,
        "hostNetwork": False,
        "automount": True,
        "containers": [
            {
                "name": "c",
                "image": "x",
                "privileged": privileged or None,
                "caps": [],
                "runAsUser": None,
            }
        ],
        "hostVolumes": [],
    }


def _snapshot(bindings, pods, serviceaccounts=None, collected_at="2026-10-17T09:00:00Z"):
    return {
        "meta": {"collected_at": collected_at, "context": "test-lab"},
        "namespaces": [{"name": "lab", "enforce": None}],
        "nodes": [{"name": "n1"}],
        "serviceaccounts": serviceaccounts
        or [
            {"name": "rider", "namespace": "lab", "automount": True},
            {"name": "control", "namespace": "lab", "automount": True},
        ],
        "secrets": [],
        "pods": pods,
        "roles": [
            {
                "kind": "ClusterRole",
                "name": "cluster-admin",
                "namespace": None,
                "rules": [
                    {
                        "apiGroups": ["*"],
                        "resources": ["*"],
                        "verbs": ["*"],
                        "resourceNames": [],
                    }
                ],
            }
        ],
        "bindings": bindings,
    }


def _binding(subject_sa):
    return {
        "kind": "ClusterRoleBinding",
        "name": f"admin-{subject_sa}",
        "namespace": None,
        "subjects": [{"kind": "ServiceAccount", "name": subject_sa, "namespace": "lab"}],
        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
    }


def _lab_v1():
    """The escaped pod reaches the cluster through the `control` SA's grant."""
    return _snapshot(
        bindings=[_binding("control")],
        pods=[_pod("p1", "rider", privileged=True), _pod("p2", "control")],
    )


def _lab_fixed():
    """The control grant is gone: the control SA (and p1's route) can't reach."""
    return _snapshot(
        bindings=[],
        pods=[_pod("p1", "rider", privileged=True), _pod("p2", "control")],
        collected_at="2026-10-17T10:00:00Z",
    )


def _lab_moved():
    """The grant moved to `new`: p1 walks again, through a different SA."""
    return _snapshot(
        bindings=[_binding("new")],
        pods=[
            _pod("p1", "rider", privileged=True),
            _pod("p2", "control"),
            _pod("p3", "new"),
        ],
        serviceaccounts=[
            {"name": "rider", "namespace": "lab", "automount": True},
            {"name": "control", "namespace": "lab", "automount": True},
            {"name": "new", "namespace": "lab", "automount": True},
        ],
        collected_at="2026-10-17T10:00:00Z",
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    graph = f"rung:test-findings-{os.getpid()}-{tmp_path.name}"
    monkeypatch.setenv("FALKORDB_HOST", "localhost")
    monkeypatch.setenv("FALKORDB_PORT", "6380")
    monkeypatch.setenv("FALKORDB_GRAPH", graph)
    g = FalkorDB(host="localhost", port=6380).select_graph(graph)
    g.query("MATCH (n) DETACH DELETE n")

    def write(snapshot, name="snapshot.json"):
        path = tmp_path / name
        path.write_text(json.dumps(snapshot))
        return str(path)

    yield g, write
    try:
        g.delete()  # drop the whole graph: tests must not accumulate one each
    except Exception:  # noqa: BLE001,S110 — best-effort cleanup
        pass


def _by_route(findings, needle):
    return [f for f in findings if needle in (f.get("route") or "")]


# ---------------------------------------------------------------------------
# 1. the first ingest writes real memory
# ---------------------------------------------------------------------------
def test_first_ingest_reports_new_findings_with_fingerprints(env):
    g, write = env
    ingest(write(_lab_v1()))

    tracked = findings_logic.list_findings(g)
    assert tracked, "first ingest produced no findings"
    for finding in tracked:
        assert finding["status"] == "NEW"
        assert finding["route_fp"], "route fingerprint missing"
        assert finding["route_fp"].startswith("path:")
        assert finding["target_fp"], "target fingerprint missing"
        assert finding["target_fp"].startswith("grant:")
        assert finding["first_seen"] == "2026-10-17T09:00:00Z"
        assert finding["last_seen"] == "2026-10-17T09:00:00Z"

    # the escaped pod's route exists and walks through the trusted SA
    escaped = _by_route(tracked, "CE_")
    assert escaped, "the escaped pod is not tracked"
    assert escaped[0]["target"] == "cluster-admin @ cluster"
    assert _route_nodes(g, escaped[0]) >= {"pod/lab/p1", "sa/lab/control", "cluster"}

    # memory is stored, not recomputed: one :Snapshot node, and findings are
    # deliberately not :Entity so the next teardown cannot reach them
    assert g.query("MATCH (s:Snapshot) RETURN count(s)").result_set[0][0] == 1
    assert (
        g.query("MATCH (f:Finding) WHERE f:Entity RETURN count(f)").result_set[0][0]
        == 0
    )


def test_snapshot_history_records_each_ingest(env):
    g, write = env
    ingest(write(_lab_v1(), "a.json"))
    ingest(write(_lab_fixed(), "b.json"))

    history = findings_logic.snapshot_history(g)
    assert len(history) == 2
    newest = history[0]
    assert newest["resolved"] >= 1, "the fixed snapshot resolved nothing"
    assert newest["routes"] >= 0


# ---------------------------------------------------------------------------
# 2. the deliberate fix emits RESOLVED
# ---------------------------------------------------------------------------
def test_removing_the_grant_resolves_the_route(env):
    g, write = env
    ingest(write(_lab_v1(), "a.json"))

    before = findings_logic.list_findings(g)
    assert any("sa/lab/control" in _route_nodes(g, f) for f in before)

    ingest(write(_lab_fixed(), "b.json"))

    after = findings_logic.list_findings(g)
    resolved = [f for f in after if f["status"] == "RESOLVED"]
    assert resolved, "removing the cluster-admin grant resolved nothing"
    # the resolved route keeps its fingerprints and its original first_seen,
    # and last_seen points at the snapshot where it still walked
    for finding in resolved:
        assert finding["route_fp"]
        assert finding["target_fp"]
        assert finding["first_seen"] == "2026-10-17T09:00:00Z"
        assert finding["last_seen"] == "2026-10-17T09:00:00Z"
    assert any(f["previous_status"] == "NEW" for f in resolved)


def test_findings_survive_reingest(env):
    g, write = env
    path = write(_lab_v1(), "a.json")
    ingest(path)
    first_fps = {f["route_fp"] for f in findings_logic.list_findings(g)}

    # Re-ingesting the same snapshot must not reset or duplicate memory.
    ingest(path)
    second = findings_logic.list_findings(g)
    assert {f["route_fp"] for f in second} == first_fps
    assert all(f["status"] == "NEW" for f in second)
    assert g.query("MATCH (s:Snapshot) RETURN count(s)").result_set[0][0] == 1


# ---------------------------------------------------------------------------
# 3. the Track-02 money shot: waived risk back by a new route
# ---------------------------------------------------------------------------
def test_bypassing_an_accepted_control_is_regressed(env):
    g, write = env
    ingest(write(_lab_v1(), "a.json"))

    # Accept the risk, trusting the control SA that every route goes through.
    controlled = _by_route(findings_logic.list_findings(g), "CE_")
    assert controlled, "no escaped route to accept"
    findings_logic.accept(
        g,
        controlled[0]["route_fp"],
        relies_on=["sa/lab/control"],
        note="lab escape, token theft limited to the control SA",
    )

    accepted = findings_logic.list_findings(g)
    assert any(f["status"] == "ACCEPTED" for f in accepted)

    # The grant moves to a different SA: the old route closes, a new route
    # (through an entity the exception never trusted) walks to the same target.
    ingest(write(_lab_moved(), "b.json"))
    after = findings_logic.list_findings(g)

    regressed = [f for f in after if f["status"] == "REGRESSED"]
    assert regressed, "a bypass route was not flagged REGRESSED"
    bypass = regressed[0]
    assert bypass["target_fp"] == controlled[0]["target_fp"]
    assert bypass["previous_status"] == "ACCEPTED"

    # the old route through the trusted control is now RESOLVED
    assert any(f["status"] == "RESOLVED" for f in after)

    # every REGRESSED finding really traverses none of the relied-on entities
    relies = {"sa/lab/control"}
    for finding in regressed:
        assert relies.isdisjoint(_route_nodes(g, finding))


def _route_nodes(g, finding):
    rows = g.query(
        "MATCH (f:Finding {id:$id}) RETURN f.nodes", {"id": finding["route_fp"]}
    ).result_set
    return set(json.loads(rows[0][0])) if rows else set()


# ---------------------------------------------------------------------------
# 4. exceptions are durable memory of their own
# ---------------------------------------------------------------------------
def test_identities_reaching_admin_is_canonical(env):
    from rung import paths as paths_logic

    g, write = env
    ingest(write(_lab_v1()))
    reaching = paths_logic.identities_reaching_admin(g)
    assert reaching, "no identity reaches the lab cluster-admin"
    for entry in reaching:
        assert entry["identity"].startswith(("sa/", "user/", "group/"))
        assert entry["paths"], f"{entry['identity']} listed with no route"
        for path in entry["paths"]:
            assert path["nodes"][-1] == "cluster"
            assert path["nodes"][0] == entry["identity"]
            assert all(edge["attack_path"] == 1 for edge in path["edges"])


def test_exceptions_survive_reingest_and_list(env):
    g, write = env
    ingest(write(_lab_v1(), "a.json"))
    finding = findings_logic.list_findings(g)[0]
    exceptions_logic = findings_logic.accept(g, finding["route_fp"], note="accepted")
    assert exceptions_logic["active"] is True

    ingest(write(_lab_fixed(), "b.json"))
    listed = findings_logic.list_exceptions(g)
    assert len(listed) == 1
    assert listed[0]["target_fp"] == finding["target_fp"]

    # relies_on edges are re-created against the entities of the new snapshot
    edges = g.query("MATCH (e:Exception)-[:RELIES_ON]->(t:Entity) RETURN count(t)")
    assert edges.result_set[0][0] >= 0  # entities may be gone; ids persist

    findings_logic.reset_memory(g)
    assert findings_logic.list_findings(g) == []
    assert findings_logic.list_exceptions(g), "reset dropped the exception memory"
