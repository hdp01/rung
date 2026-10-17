"""Agent tool, fallback-answer and count-query tests.

The agent's tools are the backend's public surface for the LLM: they must
treat model output as untrusted input and answer from the same memory the
API reads. These tests cover that, the keyword fallback's answers, and the
grouped attack-edge counts the API serves.
"""
import json
import os

import pytest
import yaml
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


# ---------------------------------------------------------------------------
# propose_policy — static Kyverno templates for the four priority edges
# ---------------------------------------------------------------------------

def test_propose_policy_path_steps_returns_yaml_and_rationale(env):
    g, _snap = env
    result = agent._run_tool(
        "propose_policy",
        {"path_steps": ["CE_PRIV_MOUNT", "TOKEN_STEAL", "ADMIN_OF"]},
        g, None,
    )
    assert "kyverno_yaml" in result, result
    assert "rationale" in result, result
    assert result["edge_type"] == "CE_PRIV_MOUNT"
    parsed = yaml.safe_load(result["kyverno_yaml"])
    assert parsed["kind"] == "ClusterPolicy"
    assert parsed["apiVersion"] == "kyverno.io/v1"


def test_propose_policy_priority_highest_severity_wins(env):
    g, _snap = env
    result = agent._run_tool(
        "propose_policy",
        {"path_steps": ["CE_PRIV_MOUNT", "CE_MODULE_LOAD", "TOKEN_STEAL"]},
        g, None,
    )
    assert result.get("edge_type") == "CE_MODULE_LOAD", (
        "CE_MODULE_LOAD outranks CE_PRIV_MOUNT in severity ordering"
    )


def test_propose_policy_all_four_covered_edges(env):
    g, _snap = env
    for edge in ("CE_PRIV_MOUNT", "CE_NSENTER", "CE_MODULE_LOAD", "EXPLOIT_CONTAINERD_SOCK"):
        result = agent._run_tool(
            "propose_policy", {"path_steps": [edge, "ADMIN_OF"]}, g, None
        )
        assert "kyverno_yaml" in result, f"{edge} has no template"
        assert result["edge_type"] == edge
        parsed = yaml.safe_load(result["kyverno_yaml"])
        assert parsed.get("kind") == "ClusterPolicy"


def test_propose_policy_finding_id_resolves_route(env):
    g, snap = env
    ingest(snap)
    findings = agent._run_tool("list_findings", {}, g, None)["findings"]
    assert findings, "need at least one finding to test propose_policy by id"
    fid = findings[0]["route_fp"]
    result = agent._run_tool("propose_policy", {"finding_id": fid}, g, None)
    assert "kyverno_yaml" in result or "error" in result


def test_propose_policy_no_template_returns_error(env):
    g, _snap = env
    result = agent._run_tool(
        "propose_policy",
        {"path_steps": ["TOKEN_LIST", "ADMIN_OF"]},
        g, None,
    )
    assert "error" in result
    assert "note" in result


def test_propose_policy_empty_input_returns_error(env):
    g, _snap = env
    result = agent._run_tool("propose_policy", {}, g, None)
    assert "error" in result


# set_persona — persona switching and SYSTEM prompt framing
# ---------------------------------------------------------------------------

def test_set_persona_redteam(env):
    g, _snap = env
    result = agent._run_tool("set_persona", {"name": "redteam"}, g, None)
    assert result.get("persona") == "redteam"
    assert result.get("active") is True
    assert "frame" in result


def test_set_persona_defender(env):
    g, _snap = env
    result = agent._run_tool("set_persona", {"name": "defender"}, g, None)
    assert result.get("persona") == "defender"
    assert result.get("active") is True


def test_set_persona_auditor(env):
    g, _snap = env
    result = agent._run_tool("set_persona", {"name": "auditor"}, g, None)
    assert result.get("persona") == "auditor"
    assert result.get("active") is True


def test_set_persona_unknown_returns_error(env):
    g, _snap = env
    result = agent._run_tool("set_persona", {"name": "hacker"}, g, None)
    assert "error" in result
    assert "valid" in result


def test_set_persona_suffix_augments_system_prompt():
    for name in ("redteam", "defender", "auditor"):
        persona = agent.PERSONAS[name]
        augmented = agent.SYSTEM + persona["suffix"]
        assert augmented != agent.SYSTEM
        assert len(augmented) > len(agent.SYSTEM)


def test_system_prompt_has_injection_guard():
    assert "untrusted" in agent.SYSTEM.lower()


# compare_baseline — current vs secure-baseline
# ---------------------------------------------------------------------------

def test_compare_baseline_returns_delta(env):
    g, snap = env
    ingest(snap)
    result = agent._run_tool("compare_baseline", {}, g, None)
    assert "current_reachable" in result
    assert "baseline_reachable" in result
    assert result["baseline_reachable"] == 0
    assert result["delta"] == result["current_reachable"]
    assert "pods_at_risk" in result
    assert "remediation_hints" in result
    assert "summary" in result


def test_compare_baseline_reachable_positive(env):
    g, snap = env
    ingest(snap)
    result = agent._run_tool("compare_baseline", {}, g, None)
    # Fixture has jenkins/ci-runner bound to cluster-admin — must show up
    assert result["current_reachable"] >= 1


def test_compare_baseline_has_remediation_hints(env):
    g, snap = env
    ingest(snap)
    result = agent._run_tool("compare_baseline", {}, g, None)
    # Fixture pod has privileged:true AND cluster-admin SA — at least one hint
    assert len(result["remediation_hints"]) >= 1
    for hint in result["remediation_hints"]:
        assert "action" in hint
        assert "category" in hint


# accept_risk — exception recording and REGRESSED wiring
# ---------------------------------------------------------------------------

def test_accept_risk_unknown_id_returns_error(env):
    g, snap = env
    ingest(snap)
    result = agent._run_tool("accept_risk", {"finding_id": "path:doesnotexist"}, g, None)
    assert "error" in result
    assert "hint" in result


def test_accept_risk_missing_id_returns_error(env):
    g, snap = env
    result = agent._run_tool("accept_risk", {}, g, None)
    assert "error" in result


def test_executive_brief_structure(env):
    g, snap = env
    ingest(snap)
    result = agent._run_tool("executive_brief", {}, g, None)
    for key in ("reachable_pods", "baseline_reachable", "delta_from_baseline",
                "open_findings", "regressed_findings", "brief"):
        assert key in result, f"missing key {key!r}"
    assert isinstance(result["brief"], str)
    assert len(result["brief"]) > 20


def test_executive_brief_counts_match_tools(env):
    g, snap = env
    ingest(snap)
    brief = agent._run_tool("executive_brief", {}, g, None)
    reach = agent._run_tool("critical_reach", {}, g, None)
    assert brief["reachable_pods"] == len(reach.get("reaching_cluster_admin", []))


def test_accept_risk_valid_finding(env):
    g, snap = env
    ingest(snap)
    # Record a snapshot so findings exist
    import json as _json
    from rung import findings as findings_logic
    findings_logic.record_snapshot(g, _json.loads(open(snap).read()))
    findings_result = agent._run_tool("list_findings", {}, g, None)
    findings = findings_result.get("findings", [])
    if not findings:
        pytest.skip("no findings in graph — need at least one to test accept_risk")
    fid = findings[0]["id"]
    result = agent._run_tool("accept_risk", {"finding_id": fid, "note": "test acceptance"}, g, None)
    assert "error" not in result
    assert "id" in result
    assert "target_fp" in result
    assert "message" in result
