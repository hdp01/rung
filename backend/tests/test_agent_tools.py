"""Agent tool, fallback-answer and count-query tests.

The agent's tools are the backend's public surface for the LLM: they must
treat model output as untrusted input and answer from the same memory the
API reads. These tests cover that, the keyword fallback's answers, and the
grouped attack-edge counts the API serves.
"""
import json
import os

import pytest
from falkordb import FalkorDB

from rung import agent
from rung import ask as ask_logic
from rung import paths as paths_logic
from rung.ingest import ingest


def _snapshot():
    """One escaped pod whose service account holds cluster-admin."""
    return {
        "meta": {"collected_at": "2026-10-17T09:00:00Z", "context": "agent-test"},
        "namespaces": [{"name": "jenkins", "enforce": None}],
        "nodes": [{"name": "n1"}],
        "serviceaccounts": [
            {"name": "jenkins", "namespace": "jenkins", "automount": None}
        ],
        "secrets": [],
        "pods": [
            {
                "name": "ci-runner",
                "namespace": "jenkins",
                "serviceAccount": "jenkins",
                "node": "n1",
                "hostPID": True,
                "hostNetwork": False,
                "automount": None,
                "containers": [
                    {
                        "name": "c",
                        "image": "x",
                        "privileged": True,
                        "caps": ["SYS_ADMIN"],
                        "runAsUser": None,
                    }
                ],
                "hostVolumes": [],
            }
        ],
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
        "bindings": [
            {
                "kind": "ClusterRoleBinding",
                "name": "admin",
                "namespace": None,
                "subjects": [
                    {"kind": "ServiceAccount", "name": "jenkins", "namespace": "jenkins"}
                ],
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
    yield g, str(snap)
    try:
        g.delete()  # drop the whole graph: tests must not accumulate one each
    except Exception:  # noqa: BLE001,S110 — best-effort cleanup
        pass


# ---------------------------------------------------------------------------
# tool input is untrusted: the model can put Cypher in a "kind"
# ---------------------------------------------------------------------------
def test_list_entities_rejects_unknown_kind(env):
    g, snap = env
    ingest(snap)
    before = g.query("MATCH (n) RETURN count(n)").result_set[0][0]
    result = agent._run_tool(
        "list_entities", {"kind": "Pod) DETACH DELETE n //"}, g, None
    )
    assert "error" in result, "an injected kind must not reach Cypher"
    assert g.query("MATCH (n) RETURN count(n)").result_set[0][0] == before


def test_list_entities_resolves_and_filters(env):
    g, snap = env
    ingest(snap)
    result = agent._run_tool(
        "list_entities", {"kind": "Pod", "name_contains": "ci"}, g, None
    )
    assert result["ids"] == ["pod/jenkins/ci-runner"]


def test_unknown_tool_returns_error(env):
    g, _snap = env
    assert "error" in agent._run_tool("nope", {}, g, None)


# ---------------------------------------------------------------------------
# findings/snapshots tools read the same memory the API does
# ---------------------------------------------------------------------------
def test_list_findings_and_snapshots_share_the_detector_memory(env):
    g, snap = env
    ingest(snap)

    found = agent._run_tool("list_findings", {}, g, None)
    assert found["total"] >= 1
    assert found["findings"][0]["route_fp"].startswith("path:")

    history = agent._run_tool("list_snapshots", {}, g, None)
    assert history["total"] == 1
    assert history["snapshots"][0]["routes"] == found["total"]


# ---------------------------------------------------------------------------
# the keyword fallback answers from the same memory
# ---------------------------------------------------------------------------
def test_findings_answer_counts_statuses():
    tracked = [
        {"status": "NEW"},
        {"status": "RESOLVED"},
        {"status": "RESOLVED"},
        {"status": "REGRESSED"},
    ]
    answer = ask_logic.build_answer(
        "any misconfig risks?",
        {"reaching_admin": [], "findings": tracked, "summary": {}},
    )["answer"]
    assert "4 tracked route(s)" in answer
    assert "1 REGRESSED" in answer
    assert "1 NEW" in answer
    assert "2 RESOLVED" in answer


def test_findings_answer_handles_empty_memory():
    answer = ask_logic.build_answer(
        "any risks?",
        {"reaching_admin": [], "findings": [], "summary": {}},
    )["answer"]
    assert "No tracked routes" in answer


# ---------------------------------------------------------------------------
# the grouped count query must agree with the ingest result
# ---------------------------------------------------------------------------
def test_attack_edge_counts_match_ingest(env):
    g, snap = env
    result = ingest(snap)
    counts = paths_logic.attack_edge_counts(g)
    for edge_type in ("POD_EXEC", "POD_CREATE", "TOKEN_LIST", "TOKEN_STEAL", "ROLE_BIND"):
        assert counts[edge_type] == result[edge_type]
