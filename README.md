# Rung

**Point it at a Kubernetes cluster. It derives the permission chains that actually work, and answers
your questions about them — with the path, the cluster fact behind every step, and a memory of what
you already decided.**

Built for **Graph Hacks: Context for AI Agents** (FalkorDB), 15–18 October 2026 — Tracks **01**
(Agents That Act on Connected Data) and **02** (Agent Memory and Coordination).

> ### 🔗 Try it now
> | | |
> |---|---|
> | **Live app** | **https://35-154-42-179.sslip.io** |
> | **Demo video** | **https://www.youtube.com/watch?v=j1pQ79dtpwk** *(2:34 walkthrough)* |
> | **Write-up** | [dev.to blog](https://dev.to/hdp01/a-permission-is-not-a-capability-a-kubernetes-attack-path-agent-on-falkordb-208m) |
> | **Tracks entered** | 01 — Agents That Act on Connected Data · 02 — Agent Memory and Coordination |
> | **Graph database** | FalkorDB (the whole product runs on the graph — see [Why a graph](#why-a-graph)) |
>
> The live app is seeded with a real cluster snapshot. Open it and click a suggested question —
> the agent answers from the graph, streaming its tool calls, and lights up the attack chain as it goes.

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

## Deploy it

The whole stack — FalkorDB, API, UI, nginx — packs into **one container**
(`deploy/fly/Dockerfile`): stateless (re-seeded from the demo snapshot on every
boot) and origin-agnostic (the UI's API base is injected at start-up, so the
same image serves from any public URL).

The **live deployment** at **https://35-154-42-179.sslip.io** runs that image on a small
AWS EC2 instance behind **Caddy**, which terminates HTTPS with an auto-renewing Let's Encrypt
certificate (the `*.sslip.io` hostname maps the host's IP, so no domain purchase is needed). The
same image also deploys to Fly.io with the runbook in [`deploy/fly/README.md`](deploy/fly/README.md),
or to a no-account public URL via `deploy/tunnel.sh` (Cloudflare quick-tunnel).

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

## Graph data model

Rung models a Kubernetes cluster as a typed property graph. **Entity nodes** are rebuilt from each
snapshot (`:Entity` is a shared label so one `MATCH (:Entity) DETACH DELETE` resets state); **memory
nodes** (`:Finding`, `:Snapshot`, `:Exception`) are kept outside that label so cross-session memory
survives re-ingest.

```
                           ┌──────────────┐
                           │   Cluster    │
                           └──────▲───────┘
                                  │ ADMIN_OF
                           ┌──────┴───────┐
                           │   PermSet    │  (role × scope, admin:bool)
                           └──────▲───────┘
                                  │ PERMISSION_DISCOVER
      MOUNTS       SCHEDULED_ON   │                       OWNED_BY
   ┌────────┐    ┌─────────┐    ┌─┴────────┐  BELONGS_TO  ┌──────┐  ┌──────┐
   │ Volume │◀───│   Pod   │────│ Identity │              │ App  │─▶│ Team │
   └────────┘    └────┬────┘    └──────────┘              └──▲───┘  └──────┘
                      │ CONTAINED_IN                         │
                 ┌────▼─────┐                                │
                 │ Container│      ────── BELONGS_TO ────────┘
                 └──────────┘
                      │  SCHEDULED_ON
                 ┌────▼───┐
                 │  Node  │
                 └────────┘

   Attack edges (attack_path=1 — all of these fire only when the real precondition holds):
   POD_EXEC, POD_ATTACH, POD_PATCH, POD_CREATE,
   TOKEN_LIST, TOKEN_BRUTEFORCE, TOKEN_CREATE, TOKEN_STEAL,
   ROLE_BIND, ROLE_ESCALATE, IDENTITY_IMPERSONATE,
   CE_NSENTER, CE_MODULE_LOAD, CE_PRIV_MOUNT,
   EXPLOIT_HOST_TRAVERSE, EXPLOIT_CONTAINERD_SOCK

   Memory nodes (NOT labelled :Entity — survive re-ingest):
   :Finding  — one per tracked (route × target) with status NEW|RESOLVED|ACCEPTED|REGRESSED
   :Snapshot — one per ingest with new/resolved/accepted/regressed counts
   :Exception — a human-recorded "we accept this risk" + the entities it relies on
```

Every edge carries `attack_path: 0` (structural / display-only) or `attack_path: 1` (walkable in an
attack chain). The split is the first thing the agent respects — `SCHEDULED_ON` never contributes to a
path, no matter what the model thinks. Edge derivation lives in [`backend/rung/ingest.py`](backend/rung/ingest.py);
precondition rules are in that file's long module docstring.

## Load-bearing Cypher queries

Five queries the product depends on. The attack-adjacency walker (findings.py) is the hot path; the
rest are built-in graph algorithms the agent calls as tools.

**1. Enumerate all walkable attack edges.** The adjacency the detector's BFS walks.

```cypher
MATCH (a)-[r {attack_path: 1}]->(b)
RETURN a.id AS from, type(r) AS type, b.id AS to
```

**2. Shortest attack path from a source to cluster-admin.** The agent's `paths_to` tool, served by
FalkorDB's native `algo.SPpaths` restricted to attack-only relationship types.

```cypher
MATCH (a {id: $source}), (b {id: 'cluster'})
CALL algo.SPpaths({sourceNode: a, targetNode: b, pathCount: 3,
                   relTypes: ['CE_PRIV_MOUNT','CE_NSENTER','CE_MODULE_LOAD',
                              'TOKEN_STEAL','TOKEN_LIST','TOKEN_CREATE',
                              'POD_EXEC','POD_CREATE','POD_PATCH',
                              'ROLE_BIND','ROLE_ESCALATE','IDENTITY_IMPERSONATE',
                              'EXPLOIT_HOST_TRAVERSE','EXPLOIT_CONTAINERD_SOCK',
                              'IDENTITY_ASSUME','PERMISSION_DISCOVER','ADMIN_OF']})
YIELD path
RETURN [n IN nodes(path) | n.id] AS chain,
       [r IN relationships(path) | type(r)] AS edges
```

**3. Betweenness centrality — the single best fix (`choke_points` tool).**

```cypher
CALL algo.betweenness() YIELD node, score
WHERE score > 0
RETURN node.id AS id, labels(node)[0] AS kind, score
ORDER BY score DESC LIMIT 5
```

**4. Blast radius — everything reachable from a compromised entity, with hop count.** The one
query that most-reveals a mis-scoped service account.

```cypher
MATCH p = (a {id: $id})-[*1..5 {attack_path: 1}]->(t)
WITH t, min(length(p)) AS hops
RETURN t.id AS id, labels(t)[0] AS kind, hops
ORDER BY hops, id LIMIT 20
```

**5. Memory lookup — currently tracked findings per status.** The `list_findings` tool, straight
off the `:Finding` nodes the detector writes on each ingest.

```cypher
MATCH (f:Finding)
RETURN f.id, f.status, f.route, f.target, f.first_seen, f.last_seen, f.previous_status
ORDER BY f.last_seen DESC
```

PageRank over the attack-only subgraph (`attack_rank` tool) is computed in Python so it can project
onto the attack-walkable induced subgraph without materialising a separate graph in FalkorDB — see
[`backend/rung/agent.py`](backend/rung/agent.py) `_pagerank_attack`.

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

**Want to try it on different data without a cluster?** [`docs/sample-cluster.json`](docs/sample-cluster.json)
is a synthetic enterprise cluster (9 namespaces, 15 workloads, RBAC, three real container-escape
chains plus plenty of decoys where the preconditions don't hold). Open the live app, pick a tenant
name, and upload it with the **snapshot.json** box in the UI (or `curl -F file=@docs/sample-cluster.json
"<url>/ingest?tenant=acme&allow_stale=true"`). You'll see the same thesis on fresh data: a naive count
of 15 pods reaching cluster-admin collapses to 6 once preconditions are checked.

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
on drift — so it can gate a deploy.

## Layout

```
backend/     FastAPI service, the agent + tools, the ingester, the collector, the seed snapshot
frontend/    Next.js app (chat + Cytoscape graph) and the contract mock
dataset/     hand-authored fixtures (tests only — never the demo data)
deploy/      single-container image (FalkorDB + API + UI + nginx) and deploy runbooks
docs/        the demo video and the write-up (blog-post.md)
```


## Use Rung as an MCP server (Claude Code / Cursor)

Rung exposes all **20 graph-reasoning tools** over MCP so any agent — Claude Code,
Cursor, or your own — can call them directly. A `.claude/mcp.json` is committed
at the repo root; point Claude Code at the running stack with one command:

```bash
# 1. Start the stack
docker compose up -d

# 2. In Claude Code, the MCP server auto-loads from .claude/mcp.json.
#    Or launch the server manually:
FALKORDB_GRAPH=rung:kind-graphhacks uv run --project backend python -m rung.mcp_server
```

Then ask Claude Code: *"Which pods in this cluster can reach cluster-admin?"* —
it calls `critical_reach` from the graph, not from memory.

Tools exposed (grouped by role):
- **Discovery:** `list_entities`, `blast_radius`, `paths_to`, `critical_reach`, `choke_points`, `attack_rank`
- **Change simulation:** `simulate_remove`, `propose_policy`, `exploit_poc`, `red_blue_debate`
- **Memory & regression:** `list_findings`, `list_snapshots`, `snapshot_diff`, `attack_trend`, `accept_risk`
- **Ownership (Track 03):** `who_owns`, `what_belongs_to`, `who_to_contact`
- **Reporting:** `compare_baseline`, `executive_brief`
- **Reasoning overlay:** `set_persona` (redteam/defender/auditor)

## Enabling the real agent

`/ask` picks the best backend available and falls back cleanly if none is set.

**Preference order:**
1. **Bedrock** (Amazon Nova via the Converse API) — set `BEDROCK_API_KEY`.
   Default model is `amazon.nova-lite-v1:0` on `us-east-1` (cheap: $0.06/$0.24
   per MTok; a hackathon's traffic fits in a dollar). Override with
   `BEDROCK_MODEL_ID=amazon.nova-pro-v1:0` for the demo recording, or point
   at a Claude model if you have a Marketplace subscription.
2. **Gemini** (free tier) — set `GEMINI_API_KEY`. Default model
   `gemini-flash-lite-latest`; override via `RUNG_AGENT_MODEL`.
3. **Keyword stand-in** — the default when neither is set. Answers the demo's
   canonical questions from structured tool output; no model call. The graph,
   path view, baseline comparison and regression detector all work either way.

Credentials come from `credentials.env` one directory above the repo (project
convention). The backend auto-loads it on first use — no manual sourcing. All
tests pass with or without a key (CI never needs one).

Both real backends emit the same SSE event vocabulary
(`frontend/src/lib/types.ts :: AskEvent`) as the keyword stand-in, so the
frontend never knows which one is answering.

## FalkorDB does the real work

Remove FalkorDB and nothing functions: the attack-path derivation, the agent's `paths_to` /
`choke_points` / `attack_rank` tools, and the cross-snapshot memory (`:Finding` / `:Snapshot` /
`:Exception` nodes) are all graph operations. There is no second store.

Rung recommends and simulates — it never acts on your cluster. Built inside the event window,
15–18 October 2026; the test suite passes with or without a model key.

## AI assistance disclosure

Per the hackathon rules, AI use is disclosed in full:

- **Coding**: built with AI pair-programming (Claude / Claude Code) alongside the team. Every
  architectural decision, the graph data model, the attack-edge precondition rules, the Cypher
  queries, and the agent tool design were directed, reviewed, and are understood by the team — the
  AI accelerated implementation, it did not define the approach.
- **Demo video**: the screen capture was driven with Playwright (headless Chromium) against the live
  app, and the narration was generated with a neural text-to-speech voice. The on-screen product,
  data, and agent answers are all real.

The team can explain the graph model, the queries, the architecture, and every technical decision on
request.
