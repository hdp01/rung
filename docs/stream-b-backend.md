# Stream B — Backend & Data  (Atharva)

> **Day 2 scope grew:** you now also own the **attack-edge derivation** (the part that makes the
> graph mean something). Build it in `rung ingest` part 2 from the table in `TEAM_PLAN.md` §4 —
> follow every precondition exactly; a wrong edge is a silent lie Harsh's harness will flag. Also add
> `GET /findings` and `GET /compare` to the endpoint list below (shapes in `frontend/src/lib/types.ts`).
> Build fast, push, leave TODOs — the fix pass catches polish. Order: **collector → derivation →
> endpoints.** Expose plain Python functions (`paths.paths_to`, `graph.subgraph`, `sim.simulate`,
> `findings.list_findings`, `compare.compare`) so the HTTP layer is thin and Harsh can wire the agent.


You own: the **real collector**, the agent-facing API, and the baseline comparison. Branch
`feat/collect`, `feat/api-*`; PR into `main`; keep `cd backend && pytest` green.

Harsh (Stream A) owns the Cypher *logic* behind `/paths` and `/simulate` and the agent behind
`/ask` — you wire the HTTP; he provides the functions. Agree on the Python function signatures
early so you're not blocked (suggested: `rung.paths.paths_to(...)`, `rung.paths.blast_radius(...)`,
`rung.sim.simulate(...)`, `rung.agent.ask(question, tenant) -> iterator of SSE events`).

---

## B1 — `rung collect` (the priority — do this first)

A read-only cluster reader that writes the exact `snapshot.json` contract. Full field list is in
`backend/HANDOFF.md` §"The contract". It is a stub today. Use the `kubernetes` client.

Field → source mapping, so nothing gets missed:
| snapshot field | k8s source |
|---|---|
| `namespaces[].enforce` | `Namespace.metadata.labels["pod-security.kubernetes.io/enforce"]` |
| `nodes[]` | `list_node()` |
| `serviceaccounts[].automount` | `ServiceAccount.automount_service_account_token` |
| `secrets[]` (name,type,saName) | `list_secret_for_all_namespaces()` — type + `metadata.annotations["kubernetes.io/service-account.name"]`. **Never read `.data`.** |
| `pods[].hostPID / hostNetwork` | `Pod.spec.host_pid` / `host_network` |
| `pods[].automount` | `Pod.spec.automount_service_account_token` |
| `pods[].containers[]` | per container: `security_context.privileged`, `.capabilities.add` (→ `caps`), `.run_as_user` |
| `pods[].hostVolumes[]` | `Pod.spec.volumes[].host_path` + the container `volume_mounts` that reference them |
| `roles[]` | `list_role_for_all_namespaces()` + `list_cluster_role()`; keep `rules[].resourceNames` |
| `bindings[]` | `list_role_binding_for_all_namespaces()` + `list_cluster_role_binding()`; subjects + roleRef |

*Done when:* `rung collect --context kind-graphhacks -o backend/data/demo-snapshot.json` produces a
file that ingests to roughly the same counts we see from the datasets, with **no `data` key
anywhere** and both PSA-labelled namespaces present. Commit that snapshot as the demo seed.

Run `bash backend/scripts/bootstrap-cluster.sh` first if you need the cluster.

---

## B2 — API endpoints (contract in `TEAM_PLAN.md` §5)

Add to `backend/app/main.py`. Each takes `?tenant=` and selects `rung:<tenant>`.

- **`GET /tenants`** — list graphs in FalkorDB and their node counts.
  *Done when:* returns at least `kind-graphhacks` with counts.
- **`GET /graph?tenant=&focus=&depth=`** — nodes + edges for the UI. If `focus` given, return the
  subgraph within `depth` hops; else the whole graph (cap ~300 nodes). Shape: `{nodes:[{id,label,
  kind,props}], edges:[{source,target,type,attack_path}]}`.
  *Done when:* the frontend renders it; `attack_path` is present on every edge.
- **`GET /paths?tenant=&source=&target=&max_hops=`** — call Harsh's `paths_to`; return ordered
  steps with `why` + `confidence`. *Done when:* ci-runner→cluster returns the real chain.
- **`POST /simulate {tenant, remove:[ids]}`** — call Harsh's `simulate`; return before/after counts
  and which fingerprints closed vs survived. *Done when:* removing the argocd admin grant drops
  reachable pods to 0.
- **`POST /ask {question, tenant}`** — stream Harsh's agent as SSE (`text/event-stream`), forwarding
  each event (`tool` / `token` / `path` / `final`). Use `fastapi.responses.StreamingResponse`.
  *Done when:* one question streams end-to-end through to the frontend.

Housekeeping while you're in there: replace the deprecated `@app.on_event("startup")` with a
lifespan handler; add `?tenant=` to `/stats` and `/ingest`.

---

## B3 — Baseline comparison (the thesis-prover, 17th)

One endpoint, `GET /compare?tenant=`, returning two numbers from the **same** graph:
- **naive** — treat every permission as a capability (the way other tools do): count pods that
  reach cluster-admin if you ignore all preconditions (PSA, real-Secret, `bind`, hostPID). This is
  roughly "traverse every `attack_path:1` edge plus the ungated versions."
- **rung** — the precondition-gated count (what our real edges give).

Return `{naive_reachable, rung_reachable, naive_token_list_edges, rung_token_list_edges}`. On the
bundled cluster expect something like naive ≈ 16/16 and ~1500 TOKEN_LIST edges vs rung ≈ a handful.
*Done when:* the two numbers are clearly different and the frontend can show them side by side.
This single comparison is our strongest "why a graph, and why done right" evidence — don't skip it.

---

## B4 — Deploy plumbing (18th)
FalkorDB runs **beside** the app in the same deployment (compose already does this) — never the
managed free tier, which deletes idle instances before judging. App reseeds the graph from the
committed `demo-snapshot.json` on boot, so the deployment is stateless and can't rot.
*Done when:* a fresh `docker compose up` comes up healthy with the graph populated, on the host
we deploy to.
