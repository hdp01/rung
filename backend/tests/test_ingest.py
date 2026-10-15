"""Ingest tests — HANDOFF.md, Task 3."""
import json
import os

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

    # teardown invariant: every node created has :Entity
    bare = g.query("MATCH (n) WHERE NOT n:Entity RETURN count(n)").result_set[0][0]
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
    # ingest created only Entity nodes; memory node still present
    assert g.query("MATCH (m:Memory) RETURN count(m)").result_set[0][0] == 1
    # no orphan non-Entity created by ingest
    assert g.query("MATCH (n) WHERE NOT n:Entity RETURN count(n)").result_set[0][0] == 1
