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
    """`T1611` -> .../T1611/, `T1552.001` -> .../T1552/001/ — copy-paste safe."""
    for technique_id, tag in attck.TECHNIQUES.items():
        expected = attck.ATTACK_BASE + technique_id.replace(".", "/") + "/"
        assert tag["url"] == expected, f"{technique_id} url is {tag['url']}"
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique_id)


def test_techniques_for_dedupes_and_keeps_order():
    chain = ["POD_EXEC", "POD_EXEC", "CE_PRIV_MOUNT", "ADMIN_OF", "MOUNTS"]
    ids = [tag["id"] for tag in attck.techniques_for(chain)]
    assert ids == ["T1609", "T1611", "T1078"]
    assert attck.summarize(chain) == "T1609, T1611, T1078"


def test_tag_edge_only_tags_attacks():
    tagged = attck.tag_edge({"source": "a", "target": "b", "type": "CE_PRIV_MOUNT"})
    assert tagged["mitre"]["id"] == "T1611"
    untagged = attck.tag_edge({"source": "a", "target": "b", "type": "SCHEDULED_ON"})
    assert "mitre" not in untagged


def test_tag_finding_reads_the_route_fingerprint():
    finding = {"status": "NEW", "route": "POD_EXEC › CE_PRIV_MOUNT › ADMIN_OF"}
    tagged = attck.tag_finding(finding)
    assert [t["id"] for t in tagged["mitre"]] == ["T1609", "T1611", "T1078"]
    # an untagged route is returned untouched, not with an empty list
    assert "mitre" not in attck.tag_finding({"status": "NEW", "route": ""})
