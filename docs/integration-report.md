# Frontend ↔ backend integration status

**16 Oct · branch `feat/frontend-integration` · checked against `origin/main` = `8569acf`**

The frontend talks to exactly one base URL — `NEXT_PUBLIC_API_URL`, default `http://localhost:8000` —
so switching from the mock to the real API is a one-line env change, no app code. What the API has to
do is match the **locked contract**: shapes in `frontend/src/lib/types.ts`, endpoints in
`TEAM_PLAN.md` §5. This document is what happens when you point the app at the real backend today.

## How to check it

```bash
cd frontend
node scripts/check-contract.mjs http://localhost:8000    # or: npm run check:contract
```

It walks every call the app makes, validates the response against the contract, prints
`PASS` / `MISSING` / `MISMATCH` per endpoint, and **exits non-zero on any drift** — so it can gate CI
or a deploy step. Tenants come from `/tenants`; the first one is used for the scoped calls.

- Against the **mock**: **9/9 PASS** (the mock is the reference implementation of the contract).
- `--selftest` runs the same checks against a deliberately broken API and asserts it reports the
  breakage — so a green run means something. It catches a wrong type, a missing field, an absent
  endpoint, and does *not* flag a valid one.

## Endpoint status

| Endpoint | Used by | Today on `main` |
|---|---|---|
| `GET /health` | header health dot + graph name | ✅ exists — `{status, falkordb, graph}` matches exactly |
| `GET /tenants` | tenant dropdown | ❌ missing — **the app cannot start against the real API without it** |
| `GET /stats?tenant=` | "Graph composition" cards | ⚠️ exists, shape fine, **tenant param ignored** (see below) |
| `GET /graph?tenant=` | the graph pane | ❌ missing |
| `GET /findings?tenant=` | regression badges + banner | ❌ missing |
| `GET /compare?tenant=` | the thesis panel | ❌ missing |
| `POST /ask` (SSE) | the chat stream | ❌ missing |
| `POST /ingest?tenant=` | snapshot uploader | ⚠️ exists, **tenant param ignored** |
| `POST /simulate` | not wired to the UI yet | ❌ missing |
| `GET /paths` | the app no longer calls it | ❌ missing — chains arrive as `path` events on `/ask` |

`/tenants` is the gate: it 404s, the dropdown is empty, and every tenant-scoped call returns nothing.
The app does not crash (every fetch is guarded), it just renders an empty shell — so the mock stays the
working demo until `/tenants` + `/graph` + `/ask` land.

## What will silently render wrong (found in the backend source)

These are the failures a 404 check cannot catch — the endpoint answers `200`, the type is satisfied,
and the UI shows the wrong thing.

1. **`/stats` and `/ingest` are not tenant-scoped.** `backend/app/main.py:64-72` takes no parameters
   and always counts `FALKORDB_GRAPH`; FastAPI silently ignores the app's `?tenant=`. With one tenant
   seeded that looks fine; with two, the UI labels the default graph's numbers with whichever tenant
   is selected — a silent lie of exactly the kind we swore off. `docs/stream-b-backend.md:69` already
   lists this ("add `?tenant=` to `/stats` and `/ingest`"). The checker **cannot** detect this — a 200
   carrying the wrong tenant's numbers is indistinguishable from the right ones — so verify it by hand
   once two tenants exist: switch the dropdown, and the counts must change.
2. **`/graph` must emit `label` on every node.** The contract requires it (`GraphNode.label`) and the
   graph pane renders it as the node's text. `rung.ingest` never writes a `label` property — pods get
   `id`/`name`/`namespace`/`serviceAccount`/`node`/`hostPID`/… (`backend/rung/ingest.py:163-203`), none
   of them called `label`. So `/graph` must map one across (`name`, or `"namespace/name"` for
   readability). The checker fails the moment `/graph` lands without it, which is the point of running
   it before Atharva wires the frontend.

## What is already aligned (keep it that way)

- **`/stats` key convention.** `_counts()` (`ingest.py:299-320`) returns node labels (`Pod`,
  `Container`, `Identity`, `PermSet`, `Volume`, `Node`, `Cluster`), the `Entity` total, *and* the six
  relationship types (`CONTAINED_IN`, `SCHEDULED_ON`, `MOUNTS`, `IDENTITY_ASSUME`,
  `PERMISSION_DISCOVER`, `ADMIN_OF`) in one flat object. The mock mirrors this deliberately
  (`mock/server.mjs:173-182`) and the UI renders every key as a card. So this is a *convention*, not
  drift — but it is worth knowing that six of those cards are edge types, and `Entity` double-counts
  every node. Change it in one place only if you change both.
- **`/health`.** `{status, falkordb, graph}` exactly, and `graph` defaults to `rung:kind-graphhacks` —
  the same `rung:<tenant>` name the header shows.
- **`/ask` events.** §5 lists `token|tool|path|final`; the checker flags anything else. The app already
  tolerates the optional extras: `final.citations`, `final.status` + `final.finding` (C5 regression
  data), and `path.steps[].why` / `.confidence`.
- **CORS.** Pinned to `http://localhost:3000` (`main.py:13-19`) — correct for dev; a deployed frontend
  origin has to be added.

## Can't be run from this machine

There is no Python interpreter and no Docker on this box — the `py` launcher points at a
`C:\Python313\python.exe` that no longer exists. So the real API cannot be started here; the checker
must be run where the backend runs (Atharva's machine, `docker-compose.yml`, or the deployed URL).
Everything above about the *live* backend is read from source, not executed.

## Next

1. When `/tenants`, `/graph` and `/ask` land: set `NEXT_PUBLIC_API_URL` to the backend and run
   `npm run check:contract` — the app needs no code change, only conformant responses.
2. Fix the two tenant-scoping gaps above (and have `/graph` emit `label`) before the first two-tenant
   demo, since the demo *is* two tenants, same question, different answers.
3. Keep the mock as the fallback: pointing `NEXT_PUBLIC_API_URL` back at `:8000` restores it.
