"""The assertion harness — hand-written paths that MUST exist and MUST NOT.

This is the project's correctness canary. The derivation rules are tempting
to misread (e.g. "SCHEDULED_ON is reachable", "list on secrets yields a
token"), and a tool that confidently lies is worse than one that doesn't try.
Every assertion here encodes one of the project's four deliberate divergences
from KubeHound (see README.md): PSA gating, real-Secret gating, the `bind`
verb, and `privileged`+`hostPID` together.

The tests run against a committed real-cluster snapshot (`data/demo-snapshot.json`),
so they're hermetic — no live cluster needed. They use a dedicated graph name so
they can't clobber the live demo graph.
"""
import os
import pathlib

import pytest
from falkordb import FalkorDB

from rung.ingest import ingest

SNAPSHOT = pathlib.Path(__file__).resolve().parents[1] / "data" / "demo-snapshot.json"
# Named `test-…` on purpose: `/tenants` hides graphs whose tenant starts with
# "test", so this scratch graph never shows up as a phantom tenant in the demo.
GRAPH = "rung:test-assertions"

ATTACK_RELS = [
    "IDENTITY_ASSUME", "PERMISSION_DISCOVER", "ADMIN_OF",
    "POD_EXEC", "POD_ATTACH", "POD_PATCH", "POD_CREATE",
    "TOKEN_LIST", "TOKEN_BRUTEFORCE", "TOKEN_CREATE", "TOKEN_STEAL",
    "ROLE_BIND", "ROLE_ESCALATE", "IDENTITY_IMPERSONATE",
    "CE_NSENTER", "CE_MODULE_LOAD", "CE_PRIV_MOUNT",
    "EXPLOIT_HOST_TRAVERSE", "EXPLOIT_CONTAINERD_SOCK",
]


@pytest.fixture(scope="module")
def g():
    """Ingest the real snapshot into a dedicated graph and hand out a handle."""
    if not SNAPSHOT.exists():
        pytest.skip(f"snapshot missing: {SNAPSHOT}")
    os.environ["FALKORDB_GRAPH"] = GRAPH
    try:
        ingest(str(SNAPSHOT), stats=False)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"ingest failed, likely no FalkorDB: {exc}")
    host = os.getenv("FALKORDB_HOST", "localhost")
    port = int(os.getenv("FALKORDB_PORT", "6380"))
    yield FalkorDB(host=host, port=port).select_graph(GRAPH)


def _q(g, cypher, timeout=15000):
    return g.query(cypher, timeout=timeout).result_set


# ---------------------------------------------------------------------------
# 1. The headline number — the whole thesis in one assertion.
# ---------------------------------------------------------------------------
def test_reachability_is_discriminating(g):
    """A tool that says 'everything reaches admin' is lying by over-reporting;
    one that says 'nothing' is lying by under-reporting. The honest number for
    the bundled cluster lives in a narrow band, and the band itself is the
    product working."""
    pod_count = _q(g, "MATCH (p:Pod) RETURN count(p)")[0][0]
    reaching = _q(
        g,
        "MATCH (p:Pod)-[*1..5 {attack_path:1}]->(c:Cluster) "
        "RETURN count(DISTINCT p)",
    )[0][0]
    assert pod_count >= 12, f"too few pods in snapshot: {pod_count}"
    assert 3 <= reaching <= pod_count - 3, (
        f"reachability {reaching}/{pod_count} is suspicious — "
        f"either a precondition leaked (near-total) or the graph lost edges (near-zero)"
    )


# ---------------------------------------------------------------------------
# 2. The hero chain — the demo's signature path exists.
# ---------------------------------------------------------------------------
def test_hero_chain_ci_runner_to_cluster(g):
    """ci-runner is privileged → escapes to the host via CE_PRIV_MOUNT →
    steals an argocd token on the node → that SA is bound to a `*`/`*`/`*`
    ClusterRole → cluster-admin. This is the chain the demo opens on."""
    rows = _q(
        g,
        f"""
        MATCH p = (:Pod {{id:'pod/jenkins/ci-runner'}})-[*1..5 {{attack_path:1}}]->(:Cluster)
        WHERE ALL(r IN relationships(p) WHERE type(r) IN [{','.join(f"'{r}'" for r in ATTACK_RELS)}])
        RETURN [r IN relationships(p) | type(r)] AS edges
        LIMIT 20
        """,
    )
    assert rows, "ci-runner → cluster: no path at all (the signature demo is dead)"
    # at least one chain must involve a container escape (CE_* or EXPLOIT_*)
    has_escape = any(
        any(e.startswith(("CE_", "EXPLOIT_")) for e in row[0]) for row in rows
    )
    assert has_escape, "ci-runner → cluster chain exists but doesn't go through a container escape"


# ---------------------------------------------------------------------------
# 3. SCHEDULED_ON is NEVER an attack edge.
# ---------------------------------------------------------------------------
def test_scheduled_on_never_attack_path(g):
    """The whole project rests on this. The spike's original bug was treating
    SCHEDULED_ON as walkable, which made 16/16 pods reach cluster-admin by
    inheriting the node's authority. SCHEDULED_ON exists for display only."""
    rows = _q(
        g, "MATCH ()-[r:SCHEDULED_ON]->() WHERE r.attack_path = 1 RETURN count(r)"
    )
    assert rows[0][0] == 0, "SCHEDULED_ON has an attack-walkable edge — this is the spike bug returning"


# ---------------------------------------------------------------------------
# 4. The four deliberate divergences from KubeHound.
# ---------------------------------------------------------------------------
def test_pod_create_gated_by_pod_security_admission(g):
    """`create` on pods in a `restricted` namespace must not produce POD_CREATE.
    The hardening fixture has webapps/webapp-deployer with exactly this
    permission; the edge must not exist."""
    rows = _q(
        g,
        "MATCH (:Identity {id:'sa/webapps/webapp-deployer'})-[:POD_CREATE]->(n:Node) "
        "RETURN count(n)",
    )
    assert rows[0][0] == 0, (
        "POD_CREATE fired from a restricted-PSA namespace — the PSA precondition leaked"
    )


def test_token_list_requires_real_secret(g):
    """`list` on secrets without a real `kubernetes.io/service-account-token`
    Secret in scope must not produce TOKEN_LIST. staging has no such Secret,
    so the staging secret-reader must have zero TOKEN_LIST edges."""
    rows = _q(
        g,
        "MATCH (:Identity {id:'sa/staging/staging-secret-reader'})-[:TOKEN_LIST]->() "
        "RETURN count(*)",
    )
    assert rows[0][0] == 0, (
        "TOKEN_LIST fired without a real token Secret — the k8s 1.24 precondition leaked"
    )


def test_role_bind_requires_bind_verb(g):
    """`create` on rolebindings alone is not escalation — Kubernetes blocks
    granting rights the subject does not hold. staging/binder-weak has that
    `create` without `bind`, so it must have zero ROLE_BIND edges."""
    rows = _q(
        g,
        "MATCH (:Identity {id:'sa/staging/binder-weak'})-[:ROLE_BIND]->() "
        "RETURN count(*)",
    )
    assert rows[0][0] == 0, (
        "ROLE_BIND fired without the bind verb — RBAC escalation prevention was ignored"
    )


def test_role_bind_fires_with_bind_verb(g):
    """The positive side of the same rule. staging/binder-strong has
    `clusterrolebindings:create` AND `bind` on `cluster-admin` → it MUST have
    a ROLE_BIND edge to the cluster-admin PermSet."""
    rows = _q(
        g,
        "MATCH (:Identity {id:'sa/staging/binder-strong'})-[:ROLE_BIND]"
        "->(p:PermSet {name:'cluster-admin'}) RETURN count(*)",
    )
    assert rows[0][0] >= 1, (
        "ROLE_BIND failed to fire where the bind verb and target role are both present"
    )


def test_ce_nsenter_requires_privileged_and_hostpid(g):
    """CE_NSENTER needs BOTH privileged AND hostPID. ci-runner is privileged
    without hostPID, node-exporter is hostPID without privileged — neither
    satisfies the AND, so CE_NSENTER on the known pods must be 0."""
    for pod_id in ("pod/jenkins/ci-runner", "pod/monitoring/node-exporter"):
        rows = _q(g, f"MATCH (:Pod {{id:'{pod_id}'}})-[:CE_NSENTER]->() RETURN count(*)")
        assert rows[0][0] == 0, f"CE_NSENTER fired on {pod_id} without hostPID AND privileged"


def test_token_steal_defeated_by_automount_false(g):
    """A pod that sets `automountServiceAccountToken: false` must not
    contribute its SA to the Node → Identity TOKEN_STEAL edges.
    monitoring-prometheus-node-exporter and no-automount both set this."""
    for sa_id in (
        "sa/monitoring/monitoring-prometheus-node-exporter",
        "sa/staging/no-automount",
    ):
        rows = _q(g, f"MATCH (:Node)-[:TOKEN_STEAL]->(i:Identity {{id:'{sa_id}'}}) RETURN count(*)")
        assert rows[0][0] == 0, f"TOKEN_STEAL reached {sa_id} despite automount:false"


# ---------------------------------------------------------------------------
# 5. Explainability — every attack edge carries attack_path:1.
# ---------------------------------------------------------------------------
def test_every_attack_edge_type_has_the_flag(g):
    """attack_path on relationships is how the agent and the UI decide what's
    walkable. If any attack edge type is missing the flag, the frontend
    silently dims it and the agent silently refuses to walk it — both are
    product bugs."""
    rows = _q(g, "MATCH ()-[r]->() RETURN type(r), count(r), sum(r.attack_path)")
    seen = {row[0]: (row[1], row[2]) for row in rows}
    structural = {"CONTAINED_IN", "SCHEDULED_ON", "MOUNTS"}
    for rel in ATTACK_RELS:
        total, walkable = seen.get(rel, (0, 0))
        if total == 0:
            continue  # that edge type didn't fire on this snapshot — fine
        assert walkable == total, (
            f"{rel}: {total} edges but only {walkable} have attack_path=1"
        )
    for rel in structural:
        total, walkable = seen.get(rel, (0, 0))
        assert walkable == 0, f"structural edge {rel} has attack_path=1 on {walkable} edges"
