# Day 1 handoff — Rung

**For:** the teammate building this morning/afternoon. Assumes you're comfortable in Python
and FastAPI, but new to FalkorDB, Cypher, and this project's internals. Everything you need is
below — you shouldn't have to read anything else to start.

**Context:** the event window opened today (15 Oct 00:01 IST), so writing real code now is both
allowed and the point. Rung turns a Kubernetes cluster into a graph of who-can-reach-what, and
puts an agent on top that explains privilege-escalation paths. You're building the part that
gets the cluster *into* the graph. Harsh takes over this evening to build the attack-path
derivation and the agent.

---

## Rule you must not break

**Do NOT copy `../graphhacks-prep/spike/*.py`.** That was throwaway exploration and it contains
at least four derivation rules we now know are wrong. Write everything fresh. The spec you need
is in this file; the deeper reference is `../graphhacks-prep/DESIGN.md` (read it, don't paste
from it).

Commits: author is **hdp01**, and **no co-author / "Generated with Claude" trailer** — Harsh's
standing rule. Small, frequent commits are better than one big one.

---

## Step 0 — confirm your environment (5 min)

These are already running on this machine; just verify:

```bash
# FalkorDB (graph DB) — should answer PONG
docker exec falkordb redis-cli ping            # -> PONG   (host port is 6380)

# the test cluster — should list 11 namespaces incl. argocd, jenkins, webapps, staging
kubectl --context kind-graphhacks get ns

# Python env
cd rung && uv sync
```

If FalkorDB isn't up: `docker run -d --name falkordb -p 6380:6379 -p 3100:3000 falkordb/falkordb:latest`
If the cluster is gone: `../graphhacks-prep/bootstrap.sh` then re-apply
`../graphhacks-prep/cluster/hardening.yaml`.

FalkorDB Browser (to see your graph visually) is at http://localhost:3100.

---

## The contract — snapshot.json

This is the **only** interface between your work and Harsh's. The collector writes this exact
shape; the ingester reads it. Pin it and don't drift.

```json
{
  "meta":    { "collected_at": "2026-10-15T09:00:00Z", "context": "kind-graphhacks" },
  "namespaces": [ { "name": "webapps", "enforce": "restricted" } ],
  "nodes":      [ { "name": "graphhacks-control-plane" } ],
  "serviceaccounts": [
    { "name": "jenkins", "namespace": "jenkins", "automount": null }
  ],
  "secrets": [
    { "name": "jenkins-legacy-token", "namespace": "jenkins",
      "type": "kubernetes.io/service-account-token", "saName": "jenkins" }
  ],
  "pods": [
    { "name": "ci-runner", "namespace": "jenkins", "serviceAccount": "jenkins",
      "node": "graphhacks-control-plane", "hostPID": true, "hostNetwork": false,
      "automount": null,
      "containers": [
        { "name": "c", "image": "...", "privileged": true,
          "caps": ["SYS_ADMIN"], "runAsUser": null }
      ],
      "hostVolumes": [ { "name": "hostroot", "hostPath": "/", "mountPaths": ["/host"] } ]
    }
  ],
  "roles": [
    { "kind": "ClusterRole", "name": "cluster-admin", "namespace": null,
      "rules": [ { "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"],
                  "resourceNames": [] } ] }
  ],
  "bindings": [
    { "kind": "ClusterRoleBinding", "name": "cluster-admin", "namespace": null,
      "subjects": [ { "kind": "ServiceAccount", "name": "x", "namespace": "y" } ],
      "roleRef": { "kind": "ClusterRole", "name": "cluster-admin" } }
  ]
}
```

**Field rules that matter — the whole project's correctness leans on these:**
- `namespaces[].enforce` = the `pod-security.kubernetes.io/enforce` label value, or `null`.
- `secrets[]` — capture name, type, and `saName` (from the
  `kubernetes.io/service-account.name` annotation). **Never include `.data`.** We record that a
  Secret exists, never its contents.
- `serviceaccounts[].automount` and `pods[].automount` = the `automountServiceAccountToken`
  field (true / false / null).
- `roles[].rules[].resourceNames` — **keep these.** Most RBAC dumps throw them away; we need
  them (a `bind` on `resourceNames: [cluster-admin]` is different from `bind` on anything).
- Capture `verbs` verbatim, including `bind`, `escalate`, `impersonate`.
- Container-level `privileged`, `caps`, `runAsUser` — per container, not per pod.

---

## Your scope today

### Task 1 — `rung collect`  → writes snapshot.json

A CLI that reads the cluster (read-only) via the `kubernetes` Python client and writes the JSON
above. Signature: `rung collect --context kind-graphhacks -o data/snapshot.json`.

Wire it into `src/rung/cli.py` (the `rung` entry point is already declared in pyproject). Put the
logic in `src/rung/collect.py`.

**Done when:** the file validates against the contract and the counts look right —
~84 serviceaccounts, ~101 clusterroles, ~85 clusterrolebindings, 16 pods, 11 namespaces (two of
them with an `enforce` value), and the `jenkins-legacy-token` secret is present with no `data`
field anywhere in the file.

### Task 2 — `rung ingest` **part 1 only**: entities + structural edges

`rung ingest data/snapshot.json` → builds the graph in FalkorDB. Put logic in
`src/rung/ingest.py`. Connect with:

```python
from falkordb import FalkorDB
g = FalkorDB(host="localhost", port=6380).select_graph("rung:kind-graphhacks")
```

**2a. Teardown first (the dangerous line — get it exactly right):**
```cypher
MATCH (n:Entity) DETACH DELETE n
```
Every entity node you create carries the `:Entity` label *and* its type label, e.g.
`(:Entity:Pod)`. Memory nodes (built this evening) never get `:Entity`, so this teardown can
never touch them. Assert that invariant in a test.

**2b. Entity nodes** — give every node an `id` and index each label on `id`:

| Label | id format | from |
|---|---|---|
| `Entity:Pod` | `pod/<ns>/<name>` | pods[] |
| `Entity:Container` | `container/<ns>/<pod>/<name>` | pods[].containers[] |
| `Entity:Identity` | `sa/<ns>/<name>` (+ `user/<name>`, `group/<name>` for binding subjects) | serviceaccounts[] + bindings |
| `Entity:PermSet` | `<rolekind>/<name>@<scope>` | see below |
| `Entity:Volume` | `vol/<ns>/<pod>/<name>` | pods[].hostVolumes[] |
| `Entity:Node` | `node/<name>` | nodes[] |
| `Entity:Cluster` | `cluster` | one, always |

**PermSet is the one non-obvious bit.** Create one PermSet per *(roleRef, scope)* pair seen in
`bindings`: `scope` = the binding's namespace for a RoleBinding, `"*"` for a
ClusterRoleBinding. `id = f"{roleRef.kind.lower()}/{roleRef.name}@{scope}"`. Set
`admin = true` if that role has any rule with `*` in apiGroups AND `*` in resources AND `*` in
verbs. Store the role's rules on the node (as JSON string) — Harsh needs them this evening.

**2c. Structural edges only.** Build exactly these six and no others — the attack-path edges are
Harsh's evening job and depend on precondition logic you don't need to touch:

| Edge | From → To | attack_path | when |
|---|---|---|---|
| `CONTAINED_IN` | Container → Pod | 0 | always |
| `SCHEDULED_ON` | Pod → Node | **0** | pod.node set. **Display only — never an attack edge** |
| `MOUNTS` | Container → Volume | 0 | container mounts that hostVolume |
| `IDENTITY_ASSUME` | Pod → Identity | 1 | pod.serviceAccount |
| `PERMISSION_DISCOVER` | Identity → PermSet | 1 | a binding names this subject → that permset |
| `ADMIN_OF` | PermSet → Cluster | 1 | permset.admin == true |

Every edge gets an `attack_path` property (0 or 1). That property is how the evening traversals
know what's walkable — so `SCHEDULED_ON` being 0 is load-bearing, not cosmetic.

### Task 3 — tests (`tests/test_ingest.py`)

Enough to prove the build is sound and to give Harsh a safety net to extend:
- node count per label equals the count derivable from the snapshot;
- `pod/jenkins/ci-runner` and `clusterrole/cluster-admin@*` both exist;
- every `SCHEDULED_ON` edge has `attack_path = 0`;
- no node that lacks `:Entity` exists after ingest (teardown invariant).

Run with `uv run pytest -q`.

### Stretch (only if all three are solid)
A `rung ingest --stats` flag that prints node/edge counts per label. Harsh will use it.

---

## What you are NOT building (leave it for the evening)

The derived attack edges — `POD_EXEC`, `POD_CREATE`, `TOKEN_LIST`, `TOKEN_STEAL`, `ROLE_BIND`,
`CE_*`, etc. Each needs a precondition check (PSA labels, real token Secrets, the `bind` verb,
`privileged`+`hostPID` together) that is the core of the project and easy to get subtly wrong.
Harsh holds that context. Your structural graph is the foundation it sits on — if entity counts
are right and `SCHEDULED_ON` is non-walkable, the handoff is clean.

---

## Handoff at evening

Commit and push whatever state you're in (even partial). Leave a one-line note in this file under
`## Status` saying what works and what's half-done. Harsh pulls, runs your tests, and builds the
attack layer on top.

## Status
- (friend: fill this in before you stop)
