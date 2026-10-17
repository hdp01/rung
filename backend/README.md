# Backend

The FastAPI service, the ingester and the collector. For what Rung is and the three-command
bring-up, see the [project README](../README.md).

| Path | What it is |
|---|---|
| `app/main.py` | the API — `/health`, `/stats`, `/graph`, `/paths`, `/findings`, `/snapshots`, `/exceptions`, `/ingest`, `/compare`, `/ask` |
| `rung/ingest.py` | snapshot → FalkorDB: entities, structural edges, derived attack edges, then the detector's diff |
| `rung/findings.py` | the regression detector — `:Finding` / `:Snapshot` / `:Exception` memory, fingerprints, statuses |
| `rung/collect.py` | `rung collect` — a read-only snapshot of a live cluster |
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
`GET /findings` in ~50 ms instead of ~2 minutes.

### The 30-second regression demo

```bash
bash scripts/regression-demo.sh     # live kind cluster; restores it afterwards
```

It resets the tenant's detector memory, collects and ingests snapshot **A**
(every route `NEW`), deletes `ClusterRoleBinding/argocd-application-controller`,
collects and ingests snapshot **B**, asserts at least one route is now
**RESOLVED**, verifies that same answer through `GET /findings`, and restores
the binding. The full run (FalkorDB already up) takes **under 3 seconds** and
exits non-zero if the detector misses the resolution. `--keep-history` diffs
against existing memory; `--keep-broken` leaves the cluster fixed.

### Accepting a risk

`POST /exceptions {"route_fp": "path:…", "note": "…"}` records an exception;
`relies_on` defaults to the witness route's intermediate entities (the control
the acceptance trusts). Findings that still traverse one of them are
`ACCEPTED`; a later route to the same grant that traverses none of them is
`REGRESSED`. `GET /snapshots` lists the ingested snapshot history.

