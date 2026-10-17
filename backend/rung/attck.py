"""MITRE ATT&CK tags for Rung's attack edges — W2 (TEAM_PLAN §5c).

Top-level technique IDs only.  Sub-techniques are specific and easy to get
wrong; the six verified IDs below are confirmed live against attack.mitre.org.

CIS sections follow the same discipline: section number only, no sub-control
numbers invented.  Only two sections are stated:
  §5.1 RBAC     — ROLE_BIND, ROLE_ESCALATE
  §5.2 Pod Sec  — CE_* escape edges

All six technique IDs were verified 2026-10-17:
  T1611 OK, T1610 OK, T1609 OK, T1552 OK, T1134 OK, T1098 OK
"""

ATTACK_BASE = "https://attack.mitre.org/techniques/"

TECHNIQUES = {
    "T1098": {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Privilege Escalation",
        "url": f"{ATTACK_BASE}T1098/",
        "cis_section": "CIS Kubernetes Benchmark §5.1 (RBAC)",
    },
    "T1134": {
        "id": "T1134",
        "name": "Access Token Manipulation",
        "tactic": "Privilege Escalation",
        "url": f"{ATTACK_BASE}T1134/",
        "cis_section": None,
    },
    "T1552": {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "url": f"{ATTACK_BASE}T1552/",
        "cis_section": None,
    },
    "T1609": {
        "id": "T1609",
        "name": "Container Administration Command",
        "tactic": "Execution",
        "url": f"{ATTACK_BASE}T1609/",
        "cis_section": None,
    },
    "T1610": {
        "id": "T1610",
        "name": "Deploy Container",
        "tactic": "Execution",
        "url": f"{ATTACK_BASE}T1610/",
        "cis_section": None,
    },
    "T1611": {
        "id": "T1611",
        "name": "Escape to Host",
        "tactic": "Privilege Escalation",
        "url": f"{ATTACK_BASE}T1611/",
        "cis_section": "CIS Kubernetes Benchmark §5.2 (Pod Security Standards)",
    },
    # Supplementary techniques for Rung edges not named in the spec's top-6.
    "T1069": {
        "id": "T1069",
        "name": "Permission Groups Discovery",
        "tactic": "Discovery",
        "url": f"{ATTACK_BASE}T1069/",
        "cis_section": None,
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "url": f"{ATTACK_BASE}T1078/",
        "cis_section": None,
    },
}

EDGE_TECHNIQUE = {
    # Container escapes → T1611 Escape to Host
    "CE_NSENTER": "T1611",
    "CE_PRIV_MOUNT": "T1611",
    "CE_MODULE_LOAD": "T1611",
    "EXPLOIT_HOST_TRAVERSE": "T1611",
    "EXPLOIT_CONTAINERD_SOCK": "T1611",
    # Deploy / run containers → T1610 Deploy Container
    "POD_CREATE": "T1610",
    "POD_PATCH": "T1610",
    # Execute commands in containers → T1609 Container Administration Command
    "POD_EXEC": "T1609",
    "POD_ATTACH": "T1609",
    # Unsecured credentials (service-account tokens) → T1552
    "TOKEN_LIST": "T1552",
    "TOKEN_BRUTEFORCE": "T1552",
    "TOKEN_STEAL": "T1552",
    # Access Token Manipulation (create / impersonate) → T1134
    "TOKEN_CREATE": "T1134",
    "IDENTITY_IMPERSONATE": "T1134",
    # Account Manipulation (grant / escalate roles) → T1098
    "ROLE_BIND": "T1098",
    "ROLE_ESCALATE": "T1098",
    # Supplementary: not in the spec's top-6 but present in the graph
    "IDENTITY_ASSUME": "T1078",
    "ADMIN_OF": "T1078",
    "PERMISSION_DISCOVER": "T1069",
}

STRUCTURAL_EDGES = ("CONTAINED_IN", "SCHEDULED_ON", "MOUNTS")


def technique_for(edge_type: str):
    """The ATT&CK tag for an edge type, or `None` for a structural edge."""
    technique_id = EDGE_TECHNIQUE.get(edge_type)
    if technique_id is None:
        return None
    t = TECHNIQUES[technique_id]
    # Return only the four keys the UI renders; cis_section lives on the edge itself.
    return {"id": t["id"], "name": t["name"], "tactic": t["tactic"], "url": t["url"]}


def cis_section_for(edge_type: str):
    """The CIS Kubernetes Benchmark section for an edge, or None."""
    technique_id = EDGE_TECHNIQUE.get(edge_type)
    if technique_id is None:
        return None
    return TECHNIQUES[technique_id].get("cis_section")


def techniques_for(edge_types):
    """The distinct techniques a chain of edge types uses, in first-seen order."""
    seen = {}
    for edge_type in edge_types:
        tag = technique_for(edge_type)
        if tag and tag["id"] not in seen:
            seen[tag["id"]] = tag
    return list(seen.values())


def summarize(edge_types) -> str:
    """`"T1609, T1611"` — the compact form for a note or a log line."""
    return ", ".join(tag["id"] for tag in techniques_for(edge_types))


def tag_edge(edge: dict) -> dict:
    """Return `edge` with `mitre` + `cis_section` added for attack edges."""
    edge_type = edge.get("type")
    tag = technique_for(edge_type)
    if tag is None:
        return edge
    result = {**edge, "mitre": tag}
    cis = cis_section_for(edge_type)
    if cis:
        result["cis_section"] = cis
    return result


def tag_finding(finding: dict) -> dict:
    """Return `finding` with the techniques its route uses under `mitre`."""
    route = finding.get("route") or ""
    edge_types = [part.strip() for part in route.split("›") if part.strip()]
    tags = techniques_for(edge_types)
    if not tags:
        return finding
    return {**finding, "mitre": tags}
