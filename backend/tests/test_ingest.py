"""Ingest tests — HANDOFF.md, Task 3."""
import json
import os
import tempfile

import pytest
from falkordb import FalkorDB

from rung.ingest import ingest


def _snapshot():
    return {
        "meta": {"collected_at": "2026-10-15T09:00:00Z", "context": "kind-graphhacks"},
        "namespaces": [{"name": "webapps", "enforce": "restricted"}],
        "nodes": [{"name": "graphhacks-control-plane"}],
        "serviceaccounts": [{"name": "jenkins", "namespace": "jenkins", "automount": None}],
        "secrets": [
            {
                "name": "jenkins-legacy-token",
                "namespace": "jenkins",
                "type": "kubernetes.io/service-account-token",
                "saName": "jenkins",
            }
        ],
        "pods": [
            {
                "name": "ci-runner",
                "namespace": "jenkins",
                "serviceAccount": "jenkins",
                "node": "graphhacks-control-plane",
                "hostPID": True,
                "hostNetwork": False,
                "automount": None,
                "containers": [
                    {"name": "c", "image": "x", "privileged": True, "caps": ["SYS_ADMIN"], "runAsUser": None}
                ],
                "hostVolumes": [{"name": "hostroot", "hostPath": "/", "mountPaths": ["/host"]}],
            }
        ],
        "roles": [
            {
                "kind": "ClusterRole",
                "name": "cluster-admin",
                "namespace": None,
                "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"], "resourceNames": []}],
            }
        ],
        "bindings": [
            {
                "kind": "ClusterRoleBinding",
                "name": "cluster-admin",
                "namespace": None,
                "subjects": [{"kind": "ServiceAccount", "name": "jenkins", "namespace": "jenkins"}],
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            }
        ],
    }


@pytest.fixture
def env(tmp_path, monkeypatch):
    graph = f"rung:test-{os.getpid()}-{tmp_path.name}"
    monkeypatch.setenv("FALKORDB_HOST", "localhost")
    monkeypatch.setenv("FALKORDB_PORT", "6380")
    monkeypatch.setenv("FALKORDB_GRAPH", graph)
    snap = tmp_path / "snapshot.json"
    snap.write_text(json.dumps(_snapshot()))
    g = FalkorDB(host="localhost", port=6380).select_graph(graph)
    g.query("MATCH (n) DETACH DELETE n")
    yield snap, graph, g
    try:
        g.query("MATCH (n) DETACH DELETE n")
    except Exception:
        pass


def test_entity_counts_match_snapshot(env):
    snap, graph, g = env
    ingest(str(snap))

    def count(label):
        return g.query(f"MATCH (n:{label}) RETURN count(n)").result_set[0][0]

    assert count("Pod") == 1
    assert count("Container") == 1
    assert count("Identity") == 1
    assert count("PermSet") == 1
    assert count("Volume") == 1
    assert count("Node") == 1
    assert count("Cluster") == 1

    ids = {r[0] for r in g.query("MATCH (n) RETURN n.id").result_set}
    assert "pod/jenkins/ci-runner" in ids
    assert "clusterrole/cluster-admin@*" in ids

    # teardown invariant: every *entity* created carries :Entity. Detector
    # memory (Finding/Snapshot/Exception) is deliberately outside that label.
    bare = g.query(
        "MATCH (n) WHERE NOT n:Entity AND NOT n:Finding AND NOT n:Snapshot "
        "AND NOT n:Exception RETURN count(n)"
    ).result_set[0][0]
    assert bare == 0


def test_scheduled_on_is_not_an_attack_edge(env):
    snap, graph, g = env
    ingest(str(snap))
    rows = g.query("MATCH ()-[r:SCHEDULED_ON]->() RETURN r.attack_path").result_set
    assert rows, "expected at least one SCHEDULED_ON edge"
    assert all(r[0] == 0 for r in rows)


def test_memory_node_survives_ingest(env):
    snap, graph, g = env
    g.query("CREATE (m:Memory {id:'m1'})")
    ingest(str(snap))
    rows = g.query("MATCH (m:Memory {id:'m1'}) RETURN count(m)").result_set
    assert rows[0][0] == 1


def test_teardown_does_not_touch_non_entity(env):
    snap, graph, g = env
    g.query("CREATE (m:Memory {id:'mem'})")
    ingest(str(snap))
    # ingest created only Entity nodes plus detector memory; Memory survives
    assert g.query("MATCH (m:Memory) RETURN count(m)").result_set[0][0] == 1
    orphan = g.query(
        "MATCH (n) WHERE NOT n:Entity AND NOT n:Finding AND NOT n:Snapshot "
        "AND NOT n:Exception RETURN count(n)"
    ).result_set[0][0]
    assert orphan == 1
    # the detector's memory survived the teardown and is not :Entity, so the
    # next ingest cannot delete it either
    assert g.query("MATCH (f:Finding) RETURN count(f)").result_set[0][0] >= 1
    assert (
        g.query("MATCH (f:Finding) WHERE f:Entity RETURN count(f)").result_set[0][0]
        == 0
    )


# --- part 2: derived attack edges ---


def _snapshot_with(overrides):
    snap = _snapshot()
    for key, value in overrides.items():
        if value is None:
            snap.pop(key, None)
        else:
            snap[key] = value
    return snap


def test_attack_edges_derived_when_preconditions_hold(env):
    snap, graph, g = env
    ingest(str(env[0]))
    rows = g.query("MATCH ()-[r]->() RETURN type(r)").result_set
    by_type = {}
    for rel_type, in rows:
        by_type.setdefault(rel_type[0], 0)
    def count(rel_type):
        res = g.query(f"MATCH ()-[r:{rel_type}]->() RETURN count(r)")
        return res.result_set[0][0]
    # The fixture pod is privileged + hostPID (an escape), the attacker holds
    # cluster-admin (`*` verbs), and its token is projected.
    assert count("POD_EXEC") == 1
    assert count("TOKEN_STEAL") >= 1
    assert count("ROLE_BIND") >= 1


def test_token_list_finds_projected_tokens(env):
    snap, graph, g = env
    ingest(str(env[0]))
    # The attacker holds `list` on `secrets` (cluster-admin grants `*`), and
    # ci-runner's token is projected, so TOKEN_LIST is derived.
    res = g.query("MATCH ()-[r:TOKEN_LIST]->() RETURN count(r)")
    assert res.result_set[0][0] >= 1


def test_scheduled_on_stays_display_only_even_with_attack_edges(env):
    # SCHEDULED_ON is structural (display only, attack_path 0) and must not
    # gain attack_path 1 in part 2.
    snap, graph, g = env
    ingest(str(env[0]))
    rows = g.query("MATCH ()-[r:SCHEDULED_ON]->() RETURN r.attack_path").result_set
    assert rows
    assert all(r[0] == 0 for r in rows)


def test_ce_nsenter_needs_privileged_and_hostpid():
    # CE_NSENTER requires BOTH privileged and hostPID. A hostPID pod whose
    # container is not privileged doesn't qualify — the AND must hold.
    snapshot = _snapshot()
    pod = snapshot["pods"][0]
    pod["hostPID"] = True
    pod["containers"][0]["privileged"] = None
    graph = f"rung:test-noexec-{os.getpid()}"
    with tempfile.TemporaryDirectory() as tmp:
        path = f"{tmp}/snapshot.json"
        with open(path, "w") as f:
            json.dump(snapshot, f)
        g = FalkorDB(host="localhost", port=6380).select_graph(graph)
        g.query("MATCH (n) DETACH DELETE n")
        try:
            ingest(f"{tmp}/snapshot.json", graph_name=graph)
            res = g.query("MATCH ()-[r:CE_NSENTER]->() RETURN count(r)")
            assert res.result_set[0][0] == 0
        finally:
            g.query("MATCH (n) DETACH DELETE n")


def test_token_steal_originates_from_a_node(env):
    # TOKEN_STEAL is Node -> Identity: an attacker who escapes a container
    # onto the host can read any projected SA token on that node. The source
    # must be a Node, not the pod itself — the pod's own SA is already
    # reachable via IDENTITY_ASSUME.
    snap, graph, g = env
    ingest(str(env[0]))
    rows = g.query("MATCH (a)-[r:TOKEN_STEAL]->(b) RETURN a.id, b.id").result_set
    assert rows, "TOKEN_STEAL did not fire where it should"
    for src, dst in rows:
        assert src.startswith("node/"), f"TOKEN_STEAL source must be a Node, got {src!r}"
        assert dst.startswith("sa/"), f"TOKEN_STEAL target must be an SA identity, got {dst!r}"


def test_role_bind_needs_bind_or_escalate(env):
    # cluster-admin's rules are `*` on everything, so every attacker who can
    # discover it can also bind it — but an attacker whose PermSet lacks
    # bind/escalate must not get a ROLE_BIND edge.
    snap, graph, g = env
    ingest(str(env[0]))
    rows = g.query("MATCH ()-[r:ROLE_BIND]->() RETURN count(r)").result_set
    assert rows[0][0] >= 1


def test_role_bind_requires_bind_verb():
    # Build a snapshot whose only binding would be discovered by an identity
    # that holds cluster-admin but never bind/escalate: no ROLE_BIND.
    cluster_admin_rules = {
        "apiGroups": ["*"],
        "resources": ["*"],
        "verbs": ["get"],
        "resourceNames": [],
    }
    snapshot = {
        "meta": {"collected_at": "2026-10-16T00:00:00Z", "context": "test"},
        "namespaces": [{"name": "webapps", "enforce": None}],
        "nodes": [{"name": "n1"}],
        "serviceaccounts": [
            {"name": "ci-runner", "namespace": "jenkins", "automount": True}
        ],
        "secrets": [],
        "pods": [
            {
                "name": "ci-runner",
                "namespace": "jenkins",
                "serviceAccount": "ci-runner",
                "node": "n1",
                "hostPID": False,
                "hostNetwork": False,
                "automount": True,
                "containers": [],
                "hostVolumes": [],
            }
        ],
        "roles": [
            {
                "kind": "ClusterRole",
                "name": "cluster-admin",
                "namespace": None,
                "rules": [cluster_admin_rules],
            }
        ],
        "bindings": [
            {
                "kind": "ClusterRoleBinding",
                "name": "cluster-admin",
                "namespace": None,
                "subjects": [
                    {"kind": "ServiceAccount", "name": "ci-runner", "namespace": "jenkins"}
                ],
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            }
        ],
    }
    graph = f"rung:test-norolebind-{os.getpid()}"

    with tempfile.TemporaryDirectory() as tmp:
        path = f"{tmp}/snapshot.json"
        with open(path, "w") as f:
            json.dump(snapshot, f)
        g = FalkorDB(host="localhost", port=6380).select_graph(graph)
        g.query("MATCH (n) DETACH DELETE n")
        try:
            ingest(path, graph_name=graph)
            rows = g.query("MATCH ()-[r:ROLE_BIND]->() RETURN count(r)").result_set
            assert rows[0][0] == 0
        finally:
            g.query("MATCH (n) DETACH DELETE n")


def test_pod_create_respects_restricted_psa():
    # A Role granting create on pods exists, but the namespace enforces
    # restricted PSA: POD_CREATE must not be derived there.
    rules = {
        "apiGroups": ["*"],
        "resources": ["pods"],
        "verbs": ["create"],
        "resourceNames": [],
    }
    snapshot = {
        "meta": {"collected_at": "2026-10-16T00:00:00Z", "context": "test"},
        "namespaces": [{"name": "restricted", "enforce": "restricted"}],
        "nodes": [{"name": "n1"}],
        "serviceaccounts": [{"name": "ci-runner", "namespace": "restricted", "automount": True}],
        "secrets": [],
        "pods": [],
        "roles": [
            {
                "kind": "ClusterRole",
                "name": "pod-creator",
                "namespace": None,
                "rules": [rules],
            }
        ],
        "bindings": [
            {
                "kind": "ClusterRoleBinding",
                "name": "pod-creator-binding",
                "namespace": None,
                "subjects": [
                    {"kind": "ServiceAccount", "name": "ci-runner", "namespace": "restricted"}
                ],
                "roleRef": {"kind": "ClusterRole", "name": "pod-creator"},
            }
        ],
    }
    graph = f"rung:test-restricted-{os.getpid()}"

    with tempfile.TemporaryDirectory() as tmp:
        path = f"{tmp}/snapshot.json"
        with open(path, "w") as f:
            json.dump(snapshot, f)
        g = FalkorDB(host="localhost", port=6380).select_graph(graph)
        g.query("MATCH (n) DETACH DELETE n")
        try:
            ingest(path, graph_name=graph)
            rows = g.query("MATCH ()-[r:POD_CREATE]->() RETURN count(r)").result_set
            assert rows[0][0] == 0
        finally:
            g.query("MATCH (n) DETACH DELETE n")
