# Day 1 handoff — Rung

**For:** my teammate, building on your own machine. Assumes you're comfortable in Python and
FastAPI, but new to FalkorDB, Cypher, and this project. Everything you need is in this file —
you shouldn't have to read anything else to start.

**Context:** the event window opened today (15 Oct 00:01 IST), so writing real code now is both
allowed and the point. Rung turns a Kubernetes cluster into a graph of who-can-reach-what, and
puts an agent on top that explains privilege-escalation paths. You build the part that gets the
cluster *into* the graph. Harsh takes over this evening for the attack-path derivation and the
agent.

Commit under **your own name** — you're a teammate, push as yourself. Small, frequent commits.
Write everything fresh against the spec below; don't hunt for old code to paste.

---

## Prerequisites (install on your machine)

- **docker**
- **kind** — v0.33.0 recommended (`go install sigs.k8s.io/kind@v0.33.0`, or grab the binary)
- **kubectl**
- **Python 3.12+** and **uv** (`curl -LsSf https://astral.sh/uv/install.sh | sh`)

No helm needed — the RBAC is bundled as fixtures.

## Step 0 — stand up the environment (~10 min, mostly image pulls)

```bash
git clone <repo-url> && cd rung
bash scripts/bootstrap-cluster.sh        # kind cluster + real RBAC + hardening + pods
docker run -d --name falkordb -p 6380:6379 -p 3100:3000 falkordb/falkordb:latest
uv sync
```

Verify: `kubectl --context kind-graphhacks get ns` shows 11 namespaces (incl. argocd, jenkins,
webapps, staging), and `docker exec falkordb redis-cli ping` returns PONG. FalkorDB Browser —
where you can *see* your graph — is at http://localhost:3100.

This cluster mirrors Harsh's, so the graph you build will line up with the attack-path layer
added this evening.

---

## The contract — snapshot.json

The **only** interface between your work and Harsh's. The collector writes this exact shape; the
ingester reads it. Pin it; don't drift.

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
- `secrets[]` — name, type, and `saName` (from the `kubernetes.io/service-account.name`
  annotation). **Never include `.data`.** We record that a Secret exists, never its contents.
- `serviceaccounts[].automount` and `pods[].automount` = `automountServiceAccountToken`
  (true / false / null).
- `roles[].rules[].resourceNames` — **keep these.** Most RBAC dumps drop them; we need them
  (a `bind` on `resourceNames: [cluster-admin]` differs from `bind` on anything).
- Capture `verbs` verbatim, including `bind`, `escalate`, `impersonate`.
- Container-level `privileged`, `caps`, `runAsUser` — per container, not per pod.

---

## Your scope today

### Task 1 — `rung collect`  → writes snapshot.json
CLI reading the cluster (read-only) via the `kubernetes` Python client, writing the JSON above.
`rung collect --context kind-graphhacks -o data/snapshot.json`. Logic in `src/rung/collect.py`
(stub + entry point already wired).

**Done when:** the file matches the contract and counts look right — ~84 serviceaccounts,
~101 clusterroles, ~85 clusterrolebindings, 16 pods, 11 namespaces (two with an `enforce`
value), and `jenkins-legacy-token` is present with **no `data` field anywhere** in the file.

### Task 2 — `rung ingest` **part 1 only**: entities + structural edges
`rung ingest data/snapshot.json` → builds the graph. Logic in `src/rung/ingest.py`. Connect:
```python
from falkordb import FalkorDB
g = FalkorDB(host="localhost", port=6380).select_graph("rung:kind-graphhacks")
```

**2a. Teardown first (get it exactly right):** `MATCH (n:Entity) DETACH DELETE n`
Every entity node carries `:Entity` *and* its type label, e.g. `(:Entity:Pod)`. Memory nodes
(built this evening) never get `:Entity`, so this can't touch them. Assert that in a test.

**2b. Entity nodes** — every node gets an `id`; index each label on `id`:

| Label | id format | from |
|---|---|---|
| `Entity:Pod` | `pod/<ns>/<name>` | pods[] |
| `Entity:Container` | `container/<ns>/<pod>/<name>` | pods[].containers[] |
| `Entity:Identity` | `sa/<ns>/<name>` (+ `user/<name>`, `group/<name>` for binding subjects) | serviceaccounts[] + bindings |
| `Entity:PermSet` | `<rolekind>/<name>@<scope>` | see below |
| `Entity:Volume` | `vol/<ns>/<pod>/<name>` | pods[].hostVolumes[] |
| `Entity:Node` | `node/<name>` | nodes[] |
| `Entity:Cluster` | `cluster` | one, always |

**PermSet** — one per *(roleRef, scope)* pair seen in `bindings`: `scope` = the binding's
namespace for a RoleBinding, `"*"` for a ClusterRoleBinding.
`id = f"{roleRef.kind.lower()}/{roleRef.name}@{scope}"`. Set `admin = true` if that role has any
rule with `*` in apiGroups AND `*` in resources AND `*` in verbs. Store the role's rules on the
node (JSON string) — Harsh needs them this evening.

**2c. Structural edges only.** Build exactly these six, no others — the attack edges are Harsh's
evening job and need precondition logic you don't have to touch:

| Edge | From → To | attack_path | when |
|---|---|---|---|
| `CONTAINED_IN` | Container → Pod | 0 | always |
| `SCHEDULED_ON` | Pod → Node | **0** | pod.node set. **Display only — never an attack edge** |
| `MOUNTS` | Container → Volume | 0 | container mounts that hostVolume |
| `IDENTITY_ASSUME` | Pod → Identity | 1 | pod.serviceAccount |
| `PERMISSION_DISCOVER` | Identity → PermSet | 1 | a binding names this subject → that permset |
| `ADMIN_OF` | PermSet → Cluster | 1 | permset.admin == true |

Every edge gets an `attack_path` property (0/1) — that's how the evening traversals know what's
walkable, so `SCHEDULED_ON = 0` is load-bearing, not cosmetic.

### Task 3 — tests (`tests/test_ingest.py`, stubs already present)
- node count per label equals what the snapshot implies;
- `pod/jenkins/ci-runner` and `clusterrole/cluster-admin@*` both exist;
- every `SCHEDULED_ON` edge has `attack_path = 0`;
- no node lacking `:Entity` exists after ingest (teardown invariant).

Run: `uv run pytest -q`.

### Stretch (only if 1–3 are solid)
A `rung ingest --stats` flag printing node/edge counts per label (`--stats` is already in the CLI).

---

## What you are NOT building (leave it for the evening)
The derived attack edges — `POD_EXEC`, `POD_CREATE`, `TOKEN_LIST`, `TOKEN_STEAL`, `ROLE_BIND`,
`CE_*`, etc. Each needs a precondition check (PSA labels, real token Secrets, the `bind` verb,
`privileged`+`hostPID` together) that is the core of the project and easy to get subtly wrong.
Harsh holds that context. Your structural graph is the foundation it sits on.

## Handoff at evening
Push whatever state you're in (even partial) and fill in `## Status` below — what works, what's
half-done, anything that surprised you. Harsh pulls, runs your tests, builds the attack layer on
top.

## Status
- (fill this in before you stop)
