# Backend

The FastAPI service, the ingester and the collector. For what Rung is and the three-command
bring-up, see the [project README](../README.md).

| Path | What it is |
|---|---|
| `app/main.py` | the API — `/health`, `/stats`, `/graph`, `/paths`, `/findings`, `/snapshots`, `/exceptions`, `/ingest`, `/compare`, `/ask` |
| `rung/ingest.py` | snapshot → FalkorDB: entities, structural edges, derived attack edges, then the detector's diff |
| `rung/findings.py` | the regression detector — `:Finding` / `:Snapshot` / `:Exception` memory, fingerprints, statuses |
| `rung/collect.py` | `rung collect` — a read-only snapshot of a live cluster |
| `rung/cli.py` | the `rung` CLI — `collect`, `ingest`, `findings`, `snapshots` |
| `data/demo-snapshot.json` | the seed the container ingests on startup |
| `fixtures/cluster/` | manifests for the local `kind` cluster the demo snapshot came from |
| `tests/` | `pytest` |

## Run it

```bash
cd ..                          # repo root — the compose file lives there
docker compose up --build -d    # FalkorDB :6380, API :8000, UI :3000
```

The container seeds `data/demo-snapshot.json` into the `rung:kind-graphhacks` graph on startup.
Without Docker, with FalkorDB already listening on :6380:

```bash
uv run uvicorn app.main:app --reload --port 8000
uv run pytest
```

## Environment

| Variable | Default | |
|---|---|---|
| `FALKORDB_HOST` | `localhost` | `falkordb` inside compose |
| `FALKORDB_PORT` | `6380` | `6379` inside compose |
| `FALKORDB_GRAPH` | `rung:kind-graphhacks` | one graph per tenant |
| `RUNG_SEED_SNAPSHOT` | `data/demo-snapshot.json` | ingested on startup; empty to skip |
| `BEDROCK_API_KEY` | unset | paste it in `.env` at the repo root — the one place model keys live (git-ignored; compose reads the same file) |

Model keys: put `BEDROCK_API_KEY` in the repo-root `.env`, then
`docker compose up -d backend`. Optional `BEDROCK_REGION` / `BEDROCK_MODEL_ID`
override the `us-east-1` / `amazon.nova-lite-v1:0` defaults. Empty keeps the
offline keyword answerer for `/ask`.

## Regression detector — Track 02

Every ingest diffs the routes it just derived against stored memory and writes
`:Finding` nodes (deliberately **not** `:Entity`, so teardown can't delete them),
a `:Snapshot` log entry, and the status of each route:

| Status | Meaning |
|---|---|
| `NEW` | route not tracked before this snapshot |
| `RESOLVED` | route walked earlier and no longer does |
| `ACCEPTED` | an operator accepted this target's risk and the route honours the control the exception relies on |
| `REGRESSED` | a closed route walks again, **or** a different route reaches an accepted target without traversing any `RELIES_ON` entity — the "waived risk back by a new route" moment |

Each finding carries `route_fp` (the exact route), `target_fp` (the admin grant),
and `first_seen` / `last_seen`. The detector uses one canonical witness per
(source → grant) found by BFS: the demo graph's exhaustive path space is 350k
routes, which is unusable in a panel and pointless to diff; the witness answers
`GET /findings` in ~20 ms instead of ~2 minutes.

### Performance & integration

* One shared FalkorDB client per host/port (pooled, thread-safe); every module
  connects through `rung.graph.connect_to`.
* Counts are one grouped server-side query per axis (nodes by label, edges by
  type) instead of one query per key — ingest and `/stats`, `/tenants` and
  `/findings` all reuse them.
* Detector memory is written in batches: one `UNWIND … MERGE` per label, not
  one query per finding; `RELIES_ON` re-links are one round-trip too.
* Responses over 1 KB are gzipped (`/graph` is ~434 KB → ~23 KB on the wire).
* The agent exposes the detector too: `list_findings` and `list_snapshots`
  read the same memory the API does, and unknown node kinds are rejected
  before they reach Cypher. The keyword fallback summarizes findings by status.
* Tests are hermetic: each test drops its graph afterwards, so repeated runs
  leave no scratch graphs behind.

### The 30-second regression demo

```bash
bash scripts/regression-demo.sh     # live kind cluster; restores it afterwards
```

It resets the tenant's detector memory, collects and ingests snapshot **A**
(every route `NEW`), deletes `ClusterRoleBinding/argocd-application-controller`,
collects and ingests snapshot **B**, asserts at least one route is now
**RESOLVED**, verifies that same answer through `GET /findings`, and restores
the binding. The full run (FalkorDB already up) takes **about 3 seconds** and
exits non-zero if the detector misses the resolution. `--keep-history` diffs
against existing memory; `--keep-broken` leaves the cluster fixed.

### The full cycle — v1 → v2 → v3 (RESOLVED, then REGRESSED)

```bash
bash scripts/regression-cycle-demo.sh   # offline replay of the committed snapshots
```

Three committed snapshots script the whole regression story in one command
(~3 s, no cluster needed):

* **v1** — `data/demo-snapshot.json`, the baseline: 73 routes, all `NEW`.
  Accept the hero chain's route (`pod/jenkins/ci-runner › CE_MODULE_LOAD ›
  TOKEN_STEAL › PERMISSION_DISCOVER › ADMIN_OF`, trusting
  `node/graphhacks-control-plane` and `sa/argocd/argocd-application-controller`)
  — 32 findings flip to `ACCEPTED`.
* **v2** — `data/demo-snapshot-v2.json`, the fix: the argocd admin
  ClusterRoleBinding is gone, re-collected from the live cluster.
  **68 `RESOLVED`, 0 `REGRESSED`** — every accepted route closed.
* **v3** — `data/demo-snapshot-v3.json`, the regression: the same argocd admin
  grant re-added through a different route — `ClusterRoleBinding/argocd-jenkins-deploy`
  binds it to `ServiceAccount jenkins/build-deployer`. **7 `REGRESSED`**: the
  deployer's brand-new bypass (`previous_status=ACCEPTED`, traverses none of
  the exception's `RELIES_ON` entities), its two token-pivot siblings
  (`TOKEN_CREATE › PERMISSION_DISCOVER › ADMIN_OF`), and four closed routes
  walking again — plus 8 `NEW`. `GET /findings` agrees.

Regenerate the two files from a live kind cluster (delete the original binding
→ collect v2 → create the deploy binding → collect v3 → restore):

```bash
python scripts/make_demo_snapshots.py
```

### Accepting a risk

`POST /exceptions {"route_fp": "path:…", "note": "…"}` records an exception;
`relies_on` defaults to the witness route's intermediate entities (the control
the acceptance trusts). Findings that still traverse one of them are
`ACCEPTED`; a later route to the same grant that traverses none of them is
`REGRESSED`. `GET /snapshots` lists the ingested snapshot history; the same
memory is readable from the CLI (`rung findings`, `rung snapshots`).

