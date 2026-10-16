# Backend

The FastAPI service, the ingester and the collector. For what Rung is and the three-command
bring-up, see the [project README](../README.md).

| Path | What it is |
|---|---|
| `app/main.py` | the API — `/health`, `/stats`, `/ingest` live; the rest of the contract (`TEAM_PLAN.md` §5) is landing |
| `rung/ingest.py` | snapshot → FalkorDB: entities, the six structural edges, and the derived attack edges |
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
