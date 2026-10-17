"""MITRE ATT&CK tags for Rung's attack edges — W2 (TEAM_PLAN §5c).

Rung already speaks *graph* (nodes, edges, preconditions). This module lets it
speak *threat model* too: every derived attack edge maps to exactly one ATT&CK
technique, so a finding can say why a hop matters in the language the security
team the judge works on already uses.

The mapping is copied from KubeHound's attack reference
(https://kubehound.io/reference/attacks/) so Rung's tags agree with the prior
art it contrasts against. The three edges KubeHound's table doesn't name —
Rung's `ROLE_ESCALATE`, `TOKEN_CREATE`, and the terminal `ADMIN_OF` — are
mapped to the technique whose definition they actually match, each with a
comment saying why.

Structural edges (`CONTAINED_IN`, `SCHEDULED_ON`, `MOUNTS`) deliberately have
no technique: they are not attacks, and returning `None` for them is what
stops the UI from badging "this pod runs on that node" as a technique.
"""

ATTACK_BASE = "https://attack.mitre.org/techniques/"

# technique id -> the tag we attach to an edge (id, name, tactic, url).
# Only the techniques Rung's edges can actually produce.
TECHNIQUES = {
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "url": f"{ATTACK_BASE}T1078/",
    },
    "T1069": {
        "id": "T1069",
        "name": "Permission Groups Discovery",
        "tactic": "Discovery",
        "url": f"{ATTACK_BASE}T1069/",
    },
    "T1098": {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Privilege Escalation",
        "url": f"{ATTACK_BASE}T1098/",
    },
    "T1528": {
        "id": "T1528",
        "name": "Steal Application Access Token",
        "tactic": "Credential Access",
        "url": f"{ATTACK_BASE}T1528/",
    },
    "T1552.001": {
        "id": "T1552.001",
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "url": f"{ATTACK_BASE}T1552/001/",
    },
    "T1609": {
        "id": "T1609",
        "name": "Container Administration Command",
        "tactic": "Execution",
        "url": f"{ATTACK_BASE}T1609/",
    },
    "T1610": {
        "id": "T1610",
        "name": "Deploy Container",
        "tactic": "Execution",
        "url": f"{ATTACK_BASE}T1610/",
    },
    "T1611": {
        "id": "T1611",
        "name": "Escape to Host",
        "tactic": "Privilege Escalation",
        "url": f"{ATTACK_BASE}T1611/",
    },
}

# Rung edge type -> technique id. One entry per derived attack edge
# (`rung.ingest._ATTACK_REL_TYPES` plus the three `_REL_TYPES` that are attacks).
EDGE_TECHNIQUE = {
    # Act as / hold an identity. KubeHound maps IDENTITY_ASSUME,
    # IDENTITY_IMPERSONATE and ROLE_BIND all to Valid Accounts.
    "IDENTITY_ASSUME": "T1078",
    "IDENTITY_IMPERSONATE": "T1078",
    "ROLE_BIND": "T1078",
    # The terminal hop: a PermSet that *is* cluster-admin. Holding it means the
    # attacker now has a valid admin account — Valid Accounts, not a new trick.
    "ADMIN_OF": "T1078",
    "PERMISSION_DISCOVER": "T1069",
    # The `escalate` verb rewrites a role's rules to grant more than you hold.
    "ROLE_ESCALATE": "T1098",
    # Running commands inside someone else's container.
    "POD_EXEC": "T1609",
    "POD_ATTACH": "T1609",
    "POD_PATCH": "T1609",
    "POD_CREATE": "T1610",
    # Obtaining a service-account token three ways.
    "TOKEN_LIST": "T1528",
    "TOKEN_BRUTEFORCE": "T1528",
    "TOKEN_CREATE": "T1528",
    "TOKEN_STEAL": "T1552.001",
    "EXPLOIT_HOST_TRAVERSE": "T1552.001",
    # Container escapes.
    "CE_NSENTER": "T1611",
    "CE_MODULE_LOAD": "T1611",
    "CE_PRIV_MOUNT": "T1611",
    # A mounted runtime socket is used to deploy a container onto the host.
    "EXPLOIT_CONTAINERD_SOCK": "T1610",
}

# Structural edges: displayed, never attacks, never tagged.
STRUCTURAL_EDGES = ("CONTAINED_IN", "SCHEDULED_ON", "MOUNTS")


def technique_for(edge_type: str):
    """The ATT&CK tag for an edge type, or `None` for a structural edge."""
    technique_id = EDGE_TECHNIQUE.get(edge_type)
    if technique_id is None:
        return None
    return dict(TECHNIQUES[technique_id])


def techniques_for(edge_types):
    """The distinct techniques a chain of edge types uses, in first-seen order.

    A route that runs `POD_EXEC › POD_EXEC › CE_PRIV_MOUNT` has two
    techniques, not three — the answer to "what does this chain use".
    """
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
    """Return `edge` with a `mitre` tag added when it is an attack edge."""
    tag = technique_for(edge.get("type"))
    if tag is None:
        return edge
    return {**edge, "mitre": tag}


def tag_finding(finding: dict) -> dict:
    """Return `finding` with the techniques its route uses under `mitre`.

    The route fingerprint is a chain of edge types (`" › ".join(...)`), so the
    tag is derived from the stored fingerprint — no detector memory change.
    """
    route = finding.get("route") or ""
    edge_types = [part.strip() for part in route.split("›") if part.strip()]
    tags = techniques_for(edge_types)
    if not tags:
        return finding
    return {**finding, "mitre": tags}
