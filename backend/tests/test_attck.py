"""The MITRE coverage guard — every edge type is either tagged or structural.

W2 adds a technique tag to each attack edge. The failure mode of a mapping
table is silent drift: someone derives a new edge type, ships it untagged, and
the UI quietly shows a hop with no technique. These tests make that impossible
— a new edge type must be either mapped in `attck.EDGE_TECHNIQUE` or named in
`attck.STRUCTURAL_EDGES`, and nothing may be both.
"""
import re

from rung import attck, ingest


def test_every_edge_type_is_tagged_or_structural():
    """The completeness guard: no edge type may fall through the cracks."""
    all_types = set(ingest._REL_TYPES) | set(ingest._ATTACK_REL_TYPES)
    tagged = set(attck.EDGE_TECHNIQUE)
    structural = set(attck.STRUCTURAL_EDGES)

    assert tagged | structural == all_types, (
        f"edge types with no decision: {all_types - tagged - structural}"
    )
    assert not (tagged & structural), (
        f"edge types both tagged and structural: {tagged & structural}"
    )


def test_structural_edges_have_no_technique():
    """A scheduling or containment edge is not an attack and must not badge."""
    for edge_type in attck.STRUCTURAL_EDGES:
        assert attck.technique_for(edge_type) is None


def test_every_attack_edge_resolves_to_a_known_technique():
    for edge_type in ingest._ATTACK_REL_TYPES:
        tag = attck.technique_for(edge_type)
        assert tag is not None, f"{edge_type} has no technique"
        assert tag["id"] in attck.TECHNIQUES
        # every tag type carries the same four keys, so the UI can render one shape
        assert set(tag) == {"id", "name", "tactic", "url"}


def test_technique_urls_point_at_their_id():
    """Top-level IDs only: `T1611` -> .../T1611/ — no sub-techniques."""
    for technique_id, tag in attck.TECHNIQUES.items():
        expected = attck.ATTACK_BASE + technique_id.replace(".", "/") + "/"
        assert tag["url"] == expected, f"{technique_id} url is {tag['url']}"
        # Top-level IDs only per spec — no sub-techniques (no dot in ID)
        assert re.fullmatch(r"T\d{4}", technique_id), (
            f"{technique_id} is a sub-technique — spec requires top-level only"
        )


def test_spec_required_techniques_present():
    """The six IDs verified against attack.mitre.org on 2026-10-17 must all resolve."""
    for tid in ("T1611", "T1610", "T1609", "T1552", "T1134", "T1098"):
        assert tid in attck.TECHNIQUES, f"required technique {tid} missing"


def test_spec_edge_mappings():
    """Each mapping from the W2 spec is present and correct."""
    required = {
        "CE_NSENTER": "T1611",
        "CE_PRIV_MOUNT": "T1611",
        "CE_MODULE_LOAD": "T1611",
        "EXPLOIT_HOST_TRAVERSE": "T1611",
        "EXPLOIT_CONTAINERD_SOCK": "T1611",
        "POD_CREATE": "T1610",
        "POD_PATCH": "T1610",
        "POD_EXEC": "T1609",
        "POD_ATTACH": "T1609",
        "TOKEN_LIST": "T1552",
        "TOKEN_BRUTEFORCE": "T1552",
        "TOKEN_STEAL": "T1552",
        "TOKEN_CREATE": "T1134",
        "IDENTITY_IMPERSONATE": "T1134",
        "ROLE_BIND": "T1098",
        "ROLE_ESCALATE": "T1098",
    }
    for edge, expected_tid in required.items():
        tag = attck.technique_for(edge)
        assert tag is not None, f"{edge} has no technique"
        assert tag["id"] == expected_tid, f"{edge}: got {tag['id']}, want {expected_tid}"


def test_cis_sections():
    """RBAC edges → §5.1, Escape edges → §5.2, others → None."""
    for edge in ("ROLE_BIND", "ROLE_ESCALATE"):
        assert "§5.1" in (attck.cis_section_for(edge) or ""), f"{edge} missing §5.1"
    for edge in ("CE_PRIV_MOUNT", "CE_NSENTER", "CE_MODULE_LOAD"):
        assert "§5.2" in (attck.cis_section_for(edge) or ""), f"{edge} missing §5.2"
    assert attck.cis_section_for("TOKEN_LIST") is None


def test_techniques_for_dedupes_and_keeps_order():
    chain = ["POD_EXEC", "POD_EXEC", "CE_PRIV_MOUNT", "ADMIN_OF", "MOUNTS"]
    ids = [tag["id"] for tag in attck.techniques_for(chain)]
    assert ids == ["T1609", "T1611", "T1078"]
    assert attck.summarize(chain) == "T1609, T1611, T1078"


def test_tag_edge_only_tags_attacks():
    tagged = attck.tag_edge({"source": "a", "target": "b", "type": "CE_PRIV_MOUNT"})
    assert tagged["mitre"]["id"] == "T1611"
    assert tagged.get("cis_section") == "CIS Kubernetes Benchmark §5.2 (Pod Security Standards)"
    untagged = attck.tag_edge({"source": "a", "target": "b", "type": "SCHEDULED_ON"})
    assert "mitre" not in untagged


def test_tag_finding_reads_the_route_fingerprint():
    finding = {"status": "NEW", "route": "POD_EXEC › CE_PRIV_MOUNT › ADMIN_OF"}
    tagged = attck.tag_finding(finding)
    assert [t["id"] for t in tagged["mitre"]] == ["T1609", "T1611", "T1078"]
    # an untagged route is returned untouched, not with an empty list
    assert "mitre" not in attck.tag_finding({"status": "NEW", "route": ""})
