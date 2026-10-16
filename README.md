# Rung

**Point it at a Kubernetes cluster. It derives the permission chains that actually work, and answers
your questions about them — with the path, the cluster fact behind every step, and a memory of what
you already decided.**

Built for **Graph Hacks: Context for AI Agents** (FalkorDB), 15–18 October 2026 — Tracks **01**
(Agents That Act on Connected Data) and **02** (Agent Memory and Coordination).

A cluster hands out permissions in small, individually harmless pieces. Chain three of them and you
have cluster-admin. Nobody reviews the chains, because a chain is not what the permission model shows
you: it is spread across four records, and none of them is alarming on its own. Rung loads the cluster
into FalkorDB, derives the edges an attacker can really traverse, and puts an agent on top that
answers in English — with the path.

## Run it

Three commands. You need Docker, and nothing else — FalkorDB, the API and the web UI all build and
start from here.

```bash
git clone https://github.com/hdp01/rung.git && cd rung
docker compose up --build -d                 # FalkorDB + API + web UI, seeded with the demo snapshot
open http://localhost:3000                   # macOS: open · Windows: start · Linux: xdg-open
```

The first build takes a few minutes. After that: FalkorDB on `:6380` (browser on
[localhost:3100](http://localhost:3100)), the API on `:8000`, the UI on `http://localhost:3000`,
seeded from `backend/data/demo-snapshot.json`.

The agent runs on a model key, read from `.env` in the repo root (compose picks it up automatically):

```bash
echo 'ANTHROPIC_API_KEY=sk-ant-…' > .env
docker compose up -d          # restart to pick it up
```

## What you'll see

- **A tenant dropdown.** Two tenants, one graph each, in one FalkorDB. Ask both the same question and
  they answer differently — that is per-tenant isolation, not a filter.
- **Chat on the left, the graph on the right.** Ask *"this pod was just compromised — what can it
  reach?"* and the answer streams while the chain lights up on the graph, step by step.
- **Click any edge → why it exists.** The precondition that justifies it and how confident the
  derivation is. `SCHEDULED_ON` is drawn muted and dashed: it is never an attack step.
- **Regression badges.** Every finding carries NEW / RESOLVED / ACCEPTED / REGRESSED, and a REGRESSED
  route gets a banner across the top. This is our Track-02 money shot: a risk you accepted last week,
  walking again by a route you have not seen.
- **The baseline comparison.** The same graph counted twice — "every permission is a capability"
  against "preconditions checked" — side by side. The gap is the whole point of Rung.

## Why a graph

A permission is not a capability. Four examples, each of which the naive reading gets wrong:

| The rule other tools apply | Why it over-reports |
|---|---|
| scheduled on a node ⇒ can read its tokens | needs a container escape first |
| `secrets: list` ⇒ service-account tokens | not since k8s 1.24 — tokens are projected, not Secrets |
| `create rolebindings` ⇒ grant any role | RBAC escalation prevention blocks it without `bind` |
| `create pods` ⇒ own the node | not in a namespace enforcing restricted Pod Security Admission |

Rung models the **precondition**, not the permission. A chain looks like this — and no single
Kubernetes object in the cluster contains it:

```
pod/jenkins/pwn-pod ──IDENTITY_ASSUME──▶ sa/jenkins/jenkins
   ──PERMISSION_DISCOVER──▶ clusterrole/cluster-admin@* ──ADMIN_OF──▶ cluster
```

Each hop carries the fact that justifies it — *"serviceAccount jenkins is mounted in the pod
(automountServiceAccountToken not disabled)"*, *"bound by ClusterRoleBinding cluster-admin"*, *"\* on \*
on \*"* — which is what the UI shows when you click an edge.

The comparison that follows: counting permissions as capabilities says ~16 of 16 pods in the bundled
cluster reach cluster-admin — roughly 1,500 TOKEN_LIST edges. Counting preconditions says a handful.
The false ones are false for four specific reasons: Pod Security Admission on pod creation, tokens
being projected rather than stored as Secrets, `bind` being required to grant a role, and needing both
`privileged` and `hostPID` to nsenter out of a container.

## Prior art, and what Rung adds

This graph has been built before — Datadog's [KubeHound](https://kubehound.io), WithSecure's IceKube,
and IBM X-Force's BloodHound-Kube. All three proved the attack graph is real; none has an agent. They
require a human who knows Cypher or Gremlin to ask the right question, and they model *permissions* as
capabilities, which over-reports.

Rung adds the agent — which chooses the graph algorithms itself (shortest paths, betweenness) instead
of being handed a query — plus two things none of them do: **change simulation** (remove a grant, see
the blast radius close) and **memory across snapshots** (so "you accepted this risk yesterday" is a
fact Rung holds, not a note you kept).

## Run it against your own cluster

`rung collect` reads your cluster read-only and writes a sanitised snapshot. Nothing leaves your
machine unless you upload it.

```bash
cd backend
uv run rung collect --context <your-context> -o snapshot.json
curl -F file=@snapshot.json http://localhost:8000/ingest
```

## Data

The bundled demo snapshot comes from a disposable local `kind` cluster built for this project — our
own synthetic data, no private, personal or restricted information. Secrets are redacted at
collection: Rung records that a Secret *exists* and its type, never its contents. The
hand-authored JSON in `dataset/` exists only as test fixtures; the demo runs on the collected
snapshot.

## Working on the frontend without the backend

The web UI talks to one base URL (`NEXT_PUBLIC_API_URL`) and is developed against a mock that
implements the same contract, so the two sides move independently.

```bash
cd frontend
npm install
node mock/server.mjs        # terminal 1 — :8000, the contract, canned question-aware answers
npm run dev                 # terminal 2 — :3000
```

Point it at the real API by setting `NEXT_PUBLIC_API_URL` — no code change. To check that an API
conforms to the contract the UI is built on (`frontend/src/lib/types.ts`):

```bash
cd frontend
npm run check:contract -- http://localhost:8000
```

It walks every call the app makes, prints PASS / MISSING / MISMATCH per endpoint, and exits non-zero
on drift — so it can gate a deploy. See `docs/integration-report.md` for the current status.

## Layout

```
backend/     FastAPI service, the ingester, the collector, the seed snapshot
frontend/    Next.js app (chat + Cytoscape graph) and the contract mock
dataset/     hand-authored fixtures (tests only — never the demo data)
docs/        per-stream build guides, integration report, winning strategy
TEAM_PLAN.md the contract, the correctness rules, who owns what
```

## Status

Written inside the event window, 15–18 October 2026. The frontend is complete against the contract
and runs on the mock; the collector, the derived attack edges, the API endpoints and the agent are
landing through the 17th. `docs/integration-report.md` tracks exactly which endpoints are live.

Not doing: real ownership data (Track 03), and any autonomous remediation — Rung recommends and
simulates, it never acts on your cluster.

<!-- TODO(event): demo video link, deployed URL, architecture diagram -->
