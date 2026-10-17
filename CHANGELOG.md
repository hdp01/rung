# Changelog — 2026-10-17: model keys in one place — `.env`

`BEDROCK_API_KEY` (or `GEMINI_API_KEY`) now lives in a single git-ignored
`.env` at the repo root. `docker compose` substitutes the Bedrock
key/region/model into the backend container, and host runs read the same file
(`rung.agent._load_credentials_env`, which still supports `credentials.env`).
Empty is fine — `/ask` falls back to the offline keyword answerer, so the app
works with or without a key.

---

# Changelog — 2026-10-17: Track 02 follow-up — pooled connections, batched memory, CLI access

The detector's reads and writes no longer pay for a fresh connection per query,
and its memory is reachable without the API.

* **One shared FalkorDB client per host/port** (`rung/graph.py`): clients are
  cached and reused across calls and threads; `connect_to(name)` is the single
  connection helper for `ingest`, `compare`, the API and the CLI.
* **Batched memory writes**: per-route `:Finding` upserts and the `RELIES_ON`
  re-links are one `UNWIND … MERGE` round-trip per label instead of one query
  per route.
* **Grouped counts**: `/stats`, `/tenants`, ingest summaries and the attack-edge
  counters use one grouped server-side query instead of one query per
  label/edge type.
* **Gzip** compresses responses above 1 KB (the graph payload is ~400 KB).
* **`rung findings` and `rung snapshots`** print the detector's memory without
  the API; the agent gains a `list_snapshots` tool, summarizes findings by
  status, and rejects unknown node kinds (model output is untrusted input).
* **Modern FastAPI wiring**: lifespan startup instead of the deprecated
  `on_event`, `Annotated` upload parameters, and seed failures logged instead
  of swallowed.
* **Measured**: `/findings` ~98 ms → ~20 ms; attack-edge counts 45 ms → 12 ms;
  ingest counts 17 queries → 2; `/graph` 434 KB → 23 KB gzipped.
* **Monotonic timestamps**: replaying an older snapshot — the container
  re-seeds the committed snapshot on every boot — no longer rewinds a
  finding's `last_seen` behind its `first_seen`.

Verified: 37 tests pass (including the agent-tool and count-query coverage);
`ruff check app rung tests` is clean; each test drops its graph, so the suite
leaves nothing behind (239 accumulated scratch graphs swept in the same pass).
The scripted demo (collect A → delete `argocd-application-controller` → collect
B) still reports **68 RESOLVED** with `GET /findings` agreeing, and the whole
run takes ~4 s with the binding restored and the full stack verified through
the containers.

---

# Changelog — 2026-10-17: Track 02 — real findings, fingerprints, snapshot history

`/findings` was a stub: it re-walked every path on every request and answered
**350,720 all-`NEW` entries in 126 seconds**, with no fingerprints and no
cross-snapshot memory. It is now a persisted regression detector.

**Result:** the scripted demo — ingest snapshot A, delete one
ClusterRoleBinding, ingest snapshot B — reports **68 routes RESOLVED in 2.6 s**,
`GET /findings` answers in **~50 ms** and lists `NEW / RESOLVED / ACCEPTED /
REGRESSED` with route + target fingerprints and first/last-seen times.
**29 tests pass** (`22` existing + `7` new).

---

## 1. The memory model — `backend/rung/findings.py` (new)

* `:Finding` nodes hold one tracked route each: `route_fp`, `target_fp`,
  `route`, `target`, `status`, `previous_status`, `first_seen`, `last_seen`,
  the witness' node ids, and the snapshot that last saw it.
* `:Snapshot` nodes log every ingest (content-hash id, collected/ingested
  times, and that ingest's new/resolved/accepted/regressed counts).
* `:Exception` nodes are accepted risks: `target_fp` plus the `RELIES_ON`
  entities the acceptance trusts (durable as ids, re-linked as edges after
  every ingest rebuilds the Entity nodes).
* **None of the three is labelled `:Entity`** — `ingest`'s teardown is
  `MATCH (n:Entity) DETACH DELETE n`, so memory outside that label survives
  every re-ingest by construction. Tests assert both halves.

## 2. The detector

* One canonical witness per (source → admin grant), found by a BFS from every
  Pod and Identity: the demo graph's *exhaustive* path space is 350 k routes
  to 12 hops, which is unusable in a panel and pointless to diff. The
  canonical set is 73 routes and computes in ~10 ms.
* Fingerprints are stable: `route_fp = sha1(source + (edge, target)…)`,
  `target_fp = sha1(admin PermSet id)`.
* Statuses on every ingest: unseen route → `NEW`; stored route absent →
  `RESOLVED`; exception-covered → `ACCEPTED`; a route that closed and walks
  again → `REGRESSED`; and the Track-02 money shot — a *different* route to an
  accepted target that traverses **none** of the exception's `RELIES_ON`
  entities → `REGRESSED` ("waived risk back by a new route").
* Deterministic: adjacency is sorted before BFS, so the same graph always
  produces the same witness and no spurious diffs.
* Same-snapshot re-ingest is idempotent (snapshot content hash), so a server
  restart that re-seeds the demo snapshot cannot flip statuses.

## 3. Wiring

* `rung/ingest.py` — part 3 calls `record_snapshot()` after the attack edges
  are derived; the ingest result carries the diff summary
  (`{new, resolved, accepted, regressed, routes, snapshot, at}`) and `rung
  ingest --stats` prints it.
* `rung/paths.py` — `findings()` reads the stored memory (with a live
  `NEW`-only fallback for graphs ingested before the detector existed);
  `identities_reaching_admin()` now returns the canonical witnesses instead
  of every path, taking `/paths` from ~120 s to **56 ms** and keeping the
  agent's no-key fallback usable.
* `app/main.py` — `/findings` is memory-backed and adds `counts`;
  `GET /snapshots` lists the history; `GET/POST /exceptions` list and record
  accepted risks (`relies_on` defaults to the witness' intermediate entities).
* `/paths`, `/findings`, `/graph`, `/ask` and the agent's `list_findings` tool
  all read the same memory — no second source of truth.

## 4. The demo — `backend/scripts/regression-demo.sh`

Brings FalkorDB up if needed, resets the tenant's detector memory, collects
and ingests A (73 `NEW`), deletes
`ClusterRoleBinding/argocd-application-controller` (the grant the hero chain
steals a token for), collects and ingests B (**68 `RESOLVED`**), checks the
same answer through the running API, restores the binding, and exits non-zero
unless at least one route resolved. `--keep-history` / `--keep-broken` tune
that. Snapshots land in `backend/data/demo-snapshot-{a,b}.json` (gitignored).

## 5. Tests

`tests/test_findings.py` (new) covers: first ingest writes fingerprints and
timestamps; the snapshot log records each ingest; removing the grant resolves
routes while preserving `first_seen`; re-ingesting the same snapshot is
idempotent; a bypass route to an accepted target is `REGRESSED` and really
traverses none of the relied-on entities; exceptions survive re-ingest; the
canonical `/paths` view is well-formed. The two old "ingest creates only
`:Entity`" invariants were updated to exempt the three memory labels while
still proving teardown cannot touch them.

---

# Changelog — 2026-10-16: frontend takeover + backend contract integration

This entry records what changed in this codebase version: the newer UI from
[`github.com/hdp01/rung`](https://github.com/hdp01/rung) (main branch) was
adopted as the frontend, and the backend was rewritten to serve exactly the
API contract that UI consumes — with the whole stack verified end-to-end.

**Result:** `docker compose up -d` brings up a fully working app —
frontend on **http://localhost:3000**, API on **http://localhost:8000**
(Swagger at `/docs`), FalkorDB on **localhost:6380** (browser on
**http://localhost:3100**).

---

## 1. What was integrated

### Frontend: replaced with the remote repo's UI (no local edits beyond the copy)

The remote repo's frontend was cloned and overlaid onto `frontend/`:

| Copied from remote | Notes |
|---|---|
| `src/components/` — `Chat`, `FindingsPanel`, `GraphView`, `PathPanel`, `RegressionBanner`, `StatusBadge` | Chat consumes `POST /ask` SSE; GraphView renders cytoscape |
| `src/lib/graph-utils.ts`, `src/lib/types.ts` | `types.ts` **is** the API contract (see §3) |
| `src/mock/` | mock payloads kept for offline development |
| `src/app/page.tsx` | the dashboard: tenant picker, chat, findings, graph, stats, upload |
| `package.json` / `package-lock.json` | adds `cytoscape` (installed: 3.34.4) |

Local `next-env.d.ts` was kept; `frontend/AGENTS.md` rules were respected
(this Next.js version has breaking changes — no hand-written frontend code
was added, only the copy + `npm install` + `npm run build`).

### Backend: kept the local backend (it was newer than the remote one) and extended it to the frontend's contract

The remote repo's backend was **older** — it was not adopted. The local
FastAPI + `rung` package backend was rewritten where the contract demanded
it (details in §4).

---

## 2. Architecture decision: what a "tenant" is

**A tenant is a dedicated FalkorDB graph named `rung:<tenant>`.** Selecting
the graph *is* the scoping — there is no second, per-node filter.

- `GET …?tenant=X` reads `rung:X`; without a tenant, the default graph
  (`FALKORDB_GRAPH`, `rung:kind-graphhacks`) is read.
- `POST /ingest?tenant=X` writes into `rung:X` (teardown + rebuild of
  `:Entity` nodes, never memory nodes).
- `GET /tenants` lists the tenant graphs that exist, so the UI's dropdown
  and the upload form ("Loads into `rung:${tenant}`") are consistent.
- Everything in a tenant graph is in scope for that tenant — including the
  cluster-scoped identities and roles its snapshot references (users,
  groups, ClusterRole PermSets, the cluster root). An early hybrid design
  that additionally filtered nodes by a `namespace` property was removed:
  it silently dropped cluster-scoped entities (which have no namespace)
  and over-filtered multi-namespace snapshots.

The seeded demo (`backend/data/demo-snapshot.json`, a real cluster snapshot:
276 entities / 233 edges) is ingested into the default graph on backend
startup, and is always listed as tenant `kind-graphhacks`.

---

## 3. API contract as shipped (what the frontend consumes)

| Endpoint | Request | Response |
|---|---|---|
| `GET /health` | — | `{status, falkordb, graph}` |
| `GET /tenants` | — | **flat list** `[{tenant, counts: Record<string, number>}]` — test/compare scratch graphs and entity-less ghosts excluded, default graph always listed |
| `GET /stats` | `?tenant=` | flat `{Pod: n, …, ADMIN_OF: n, …}` — every label and edge type always present (0 when absent) |
| `GET /graph` | `?tenant=` | `{graph, nodes: [{id, label, kind, props}], edges: [{source, target, type, attack_path}], totals}` |
| `GET /findings` | `?tenant=` | `{graph, findings: [{status, route, target, title, note}], reaching_admin, attack_edge_counts}` |
| `POST /ask` | `{question, tenant?}` | **SSE stream** of `data:` events: `tool` → `path`* → `token`* → `final` |
| `POST /ingest` | multipart `file`, `?tenant=` | `{status: "ingested", counts}` |
| `GET /paths`, `GET /composition`, `POST /compare` | legacy endpoints, preserved unchanged |

Path steps (both in SSE `path` events and `/findings` internals) use the
frontend's `PathStep` shape: `{from, edge, to, attack_path}`.

---

## 4. Backend changes by file

### `backend/rung/graph.py`
- Added `graph_name_for(tenant)` / `connect_for(tenant)` — the `rung:<tenant>`
  selection, and `list_graphs()` (via `GRAPH.LIST`) for `/tenants`.
- Added `node_view(g)` / `edge_view(g)` — nodes as `{id, label, kind, props}`
  and edges as `{source, target, type, attack_path}`, the shapes the graph
  canvas renders.
- FalkorDB client gotchas handled: a node's `.id` attribute is the *internal*
  id (the real id is the `id` property — selected explicitly as
  `n.id AS node_id` in Cypher), and `labels()` returns `['Entity', 'Pod']`
  (the concrete type is the first label that isn't `Entity`).

### `backend/rung/paths.py` (rewritten)
- `paths_to(g, start_id)` walks only `attack_path=1` edges, up to 12 edges,
  returning `{nodes, edges:[{from, edge, to, attack_path}]}`.
- `attack_adjacency(g)` builds the walkable adjacency **once per request**;
  `identities_reaching_admin(g)` passes it down, so a findings/ask call
  scans the graph's edges one time instead of once per identity (was ~105
  full scans on the demo graph).
- `findings(g)` returns one entry per walkable route with the detector
  status the findings panel renders (`NEW` for everything seen now —
  cross-snapshot memory for RESOLVED/REGRESSED is future work).
- `attack_edge_counts(g)` reports only the five derived attack types
  (POD_EXEC, POD_CREATE, TOKEN_LIST, TOKEN_STEAL, ROLE_BIND).

### `backend/rung/ask.py` (rewritten)
- `events(question, context)` is the SSE generator: `tool` while routing,
  `path` to light up chains on the graph, `token` chunks as the answer
  types out, `final` with `{answer, citations, status, finding}`.
- `build_answer` / `_route` route natural-language questions (paths /
  findings / summary) to the plain graph functions. This module is the
  designated seam where the real agent can be dropped in later.

### `backend/app/main.py`
- `/stats`, `/graph`, `/findings`, `/ingest`, `/ask` all accept `tenant`
  and select the graph accordingly.
- `/graph` returns a node **list** with `source`/`target` edges (the old
  endpoint returned per-label counts).
- `/tenants` returns the flat `[{tenant, counts}]` list (the old response
  shape crashed the UI's tenant dropdown).
- `/ask` returns a `StreamingResponse` (SSE) instead of a single JSON.
- Edge counts are one grouped Cypher query
  (`MATCH ()-[r]->() RETURN type(r), count(r)`) instead of materializing
  every edge row.
- `/composition`, `/paths`, `/compare` preserved; dead helpers from the
  hybrid tenant design removed.

---

## 5. Bugs found and fixed during integration

1. **`/tenants` shape mismatch** — backend returned
   `{graph, tenants: [{namespace, nodes, edges, …}]}`, the frontend does
   `list.some(t => t.tenant === …)` on the response → the tenant dropdown
   would crash. Now a flat `[{tenant, counts}]` list.
2. **`/graph` returned counts, not the graph** — rewired to the node-list +
   `source`/`target` edge shape; node ids were initially the internal
   numeric ids (fixed via `n.id` projection, see §4).
3. **`node_view` returned nothing** — the label check looked for
   `Entity:Pod`-style labels; FalkorDB reports `['Entity', 'Pod']`.
4. **SSE stream died after the first event** — `ask.py:_path_steps` read
   `edge["type"]` while path views emit `edge["edge"]` (the `PathStep`
   contract). The `KeyError` killed the generator mid-stream, visible as
   `IncompleteRead` on the client.
5. **`attack_edge_counts` leaked structural edge types** — the counting
   expression inserted any edge type it saw; now only the five attack
   types are counted.
6. **`Entity` total missing** from `/stats` and `/composition` after the
   counting rewrite — restored.
7. **pytest destroyed the seeded demo graph** — three tests
   (`test_pod_exec_needs_a_privileged_container`,
   `test_role_bind_requires_bind_verb`,
   `test_pod_create_respects_restricted_psa`) created a scratch graph but
   called `ingest()` without pointing it there, so ingest fell back to the
   default graph and replaced the 276-node seed with a 4-node test
   snapshot. Fixed by passing `graph_name=graph`. (This was also the root
   of an earlier "the graph mysteriously has 4 nodes" debugging session.)
8. **Environment**: a stray `falkordb` container from an earlier run held
   ports 3100/6380 and blocked the compose stack — removed before the
   clean bring-up.

---

## 6. Verification

- **Backend unit tests**: `cd backend && .venv/bin/python -m pytest -q` →
  12 passed (and proven to no longer touch the default graph: seed count
  is 276 nodes / 233 edges before *and* after a test run).
- **End-to-end contract check** (`/tmp/opencode/verify_backend.py`, 35
  checks, all passing) covers: health; tenant list shape and filtering;
  scoped/unscoped stats; graph node/edge shapes and counts; findings
  shape and statuses; the full SSE event sequence; legacy endpoints; a
  real tenant ingest (`dataset/sample-10.json` → `rung:jenkins`) with
  findings, stats and chat answers scoped to it; and proof that a tenant
  ingest does not touch the demo graph.

## 7. Running it

```bash
docker compose up -d --build     # frontend :3000, backend :8000, FalkorDB :6380/:3100
```

The backend re-seeds the demo snapshot into the default graph on startup.
Upload any snapshot JSON from the UI (or
`curl -F file=@dataset/sample-10.json 'http://localhost:8000/ingest?tenant=<name>'`)
to create or replace a tenant's graph; it appears in the tenant dropdown on
Refresh.
