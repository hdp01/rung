# Rung — Team Build Plan

**Audience:** the three of us building Rung, dividing the work for the rest of the window.
**Clock:** it is the evening of **15 Oct**. Submission closes **18 Oct 23:59 IST** — we treat
**20:00 IST on the 18th** as the real deadline. Tracks entered: **01** (agents on connected data)
and **02** (memory & coordination).

> ## ⏱ Day 2 update (16 Oct) — READ THIS FIRST
>
> **Where we really are.** Frontend (Omyerkar) is **ahead** — C1–C5 done (graph, chat/SSE, path
> highlight, tenant switcher, regression badges), all against the mock. `frontend/src/lib/types.ts`
> is now the **locked contract** — backend output must match it exactly, no field drift. It also
> expects `GET /findings` and `GET /compare`.
>
> **The bottleneck is the real product behind the mock:** collector still a stub, no API endpoints,
> no attack-edge layer, no agent. With the time left, the team **builds**; Harsh + the lead **polish,
> find errors, fix, integrate, and ship.** We don't hand-build in series and block — everyone builds
> in parallel against the spec, we harden it into a submission afterward.
>
> **Who builds what (build fast, we fix later)**
> | Who | Builds |
> |---|---|
> | **Atharva** | the **real `rung collect`** (our data story) → the **attack-edge derivation** (full spec in §4 — follow the preconditions exactly) → all **API endpoints** matching `types.ts`. The whole backend. |
> | **Omyerkar** (ahead → takes extra) | wire the frontend **off the mock** to the real API as endpoints land → own the **baseline comparison** vertical (`/compare` + UI) → **README + demo video + blog**. |
> | **Harsh + lead** | the **agent** (the novel core — Tool Runner + tools + prompt; we own it) → run the **assertion harness** over Atharva's derivation to catch false edges → **error-finding, fixing, integration, deploy, submission packaging.** |
>
> **The seam — Python functions in `backend/rung/` (endpoints wrap these, frontend already matches):**
> `graph.subgraph(tenant, focus, depth)` · `paths.paths_to(tenant, source, target, max_hops)` ·
> `paths.blast_radius(tenant, id, max_hops)` · `paths.critical_reach(tenant)` ·
> `paths.choke_points(tenant, top_n)` · `sim.simulate(tenant, remove)` ·
> `findings.list_findings(tenant)` · `compare.compare(tenant)` ·
> `agent.ask(question, tenant) -> iterator of AskEvent dicts`.
> Endpoints may return mock-shaped data until the function lands, then swap — no frontend change.
>
> **Build-fast rule:** get it working and pushed, don't gold-plate. Small commits, own branch, PR to
> `main`. Leave TODOs where you're unsure — the fix pass catches them. The one thing to get *right*,
> not fast, is the attack-edge **preconditions** (§4): a wrong edge is a silent lie the harness must
> catch, so follow the table exactly and don't invent edges.
>
> **Priority ladder — if time runs out, cut from the bottom:**
> 1. Attack edges correct (~7/16 reachable, not 16/16). 2. Real collector + `/graph` + `/paths` +
> agent answering one question with the path + frontend wired = **MVP, a full Track-01 demo**.
> 3. Memory + regression + `/findings` + baseline comparison = Track 02 + differentiators.
> 4. Deploy, demo video, blog, polish.
>
> Detailed per-stream guides: `docs/stream-a-core.md` (now = agent + QA/fix), `-b-backend.md`,
> `-c-frontend.md`.

---

## 1. Where we are tonight

**Done and working** (Atharva):
- `rung ingest` part 1 — entities + the six structural edges, correct `attack_path` flags,
  `SCHEDULED_ON` non-walkable. Tests pass (4/4).
- FastAPI backend: `/health`, `/stats`, `/ingest` (snapshot upload). Seeds on startup.
- Next.js dashboard (health / stats / upload), backend+frontend monorepo, docker-compose,
  run scripts, 6 test datasets, two docs (`APPLICATION_WORKFLOW.md`, `TECHNICAL_DOCUMENTATION.md`).

**Not done yet** (the actual product):
- **Real `rung collect`** — still a stub. We've been testing on hand-authored datasets. Those stay
  as fixtures, but the real-cluster collector is a **priority**, not optional (see §2).
- **Attack-edge derivation** — the layer that makes this more than a pretty graph. Harsh, tonight.
- **The agent** — tool-calling loop, tools, system prompt. Nothing yet. Tracks 01+02 core.
- **Memory + regression detector** — nothing yet. This is all of Track 02.
- **Path visualization** — the "show the path" requirement. Dashboard has no graph view yet.

---

## 2. The one thing we must not get wrong

**Rung's entire edge over every other submission is that its graph comes from a REAL cluster, not
hand-authored data.** Three security teams (KubeHound, IceKube, BloodHound-Kube) proved this graph
is real; none has an agent. If our demo runs on invented JSON, we look like every toy in the
field. So:

- The hand-authored `dataset/*.json` are **test fixtures only.** Never the demo data story.
- The demo runs on a snapshot collected from the bundled `kind` cluster via `rung collect`.
- Secrets are redacted at collection — we record that a Secret *exists* and its type, never its
  contents. (Datasets are already clean; keep them that way.)

And the correctness rule that keeps us honest, applied to **every** attack edge:
> *Does traversing this edge require a capability the attacker does not yet hold?* If yes, the
> precondition goes in the derivation rule, not a footnote.

---

## 3. Who owns what

| Stream | Owner | Scope |
|---|---|---|
| **A — Core / agent** | **Harsh** | Attack-edge derivation + assertion harness → the agent (Tool Runner, tools, prompt) → memory + regression detector. The correctness-critical, context-heavy spine. |
| **B — Backend / data** | **Atharva** | Real `rung collect` → agent-facing API (`/ask`, `/graph`, `/paths`, `/tenants`, `/simulate`) → the baseline-vs-precondition comparison → deploy plumbing. |
| **C — Frontend / demo** | **3rd person** | Cytoscape path visualization + chat UI on `/ask` → highlight the path as the agent walks it → regression badges + tenant switcher → README, demo video, blog post. |

**Each stream has a detailed, self-contained task guide with acceptance criteria — start there:**
- A → [`docs/stream-a-core.md`](docs/stream-a-core.md)
- B → [`docs/stream-b-backend.md`](docs/stream-b-backend.md)
- C → [`docs/stream-c-frontend.md`](docs/stream-c-frontend.md) (full onboarding + starter code — the new teammate starts here)

Why this split: A is coupled and needs the full design context. B and C are cleanly separable
behind the API contract in §5, so they can start immediately and in parallel without colliding.

---

## 4. Correctness guardrails — the attack-edge spec (Stream A)

Each rule was checked against KubeHound's own per-edge docs. Where we differ, it's deliberate and
more conservative — that difference is a headline, not a bug. `atk` = walkable (`attack_path:1`).

| Edge | Source → Dest | Precondition (ALL parts) |
|---|---|---|
| `POD_EXEC` | PermSet → Pod | `create` on `pods/exec`, pod in scope |
| `POD_ATTACH` | PermSet → Pod | `create`/`get` on `pods/attach` |
| `POD_PATCH` | PermSet → Pod | `patch`/`update` on `pods` — **low confidence** (only image/tolerations patchable) |
| `POD_CREATE` | PermSet → Node | `create` on `pods` **AND** target ns does NOT enforce baseline/restricted PSA |
| `TOKEN_LIST` | PermSet → Identity | `list` on `secrets` **AND** a real `kubernetes.io/service-account-token` Secret exists for it |
| `TOKEN_BRUTEFORCE` | PermSet → Identity | `get` (not `list`) on `secrets`, same real-Secret precondition |
| `TOKEN_CREATE` | PermSet → Identity | `create` on `serviceaccounts/token` — the modern token path |
| `TOKEN_STEAL` | Volume → Identity | projected SA-token volume **AND** identity does not set `automountServiceAccountToken:false` |
| `ROLE_BIND` | PermSet → PermSet | `create` on rolebindings **AND** `bind` on the target role |
| `ROLE_ESCALATE` | PermSet → PermSet | `escalate` on roles/clusterroles |
| `IDENTITY_IMPERSONATE` | PermSet → Identity | `impersonate` on users/groups/serviceaccounts |
| `CE_NSENTER` | Container → Node | `privileged:true` **AND** `hostPID:true` (BOTH) |
| `CE_MODULE_LOAD` | Container → Node | `CAP_SYS_MODULE` OR `privileged` |
| `CE_PRIV_MOUNT` | Container → Node | `privileged:true` |
| `EXPLOIT_HOST_TRAVERSE` | Volume → Identity | hostPath is `/var/lib/kubelet/pods` or a parent |
| `EXPLOIT_CONTAINERD_SOCK` | Container → Container | mounts `containerd.sock`/`docker.sock`/etc (ro counts) |

**Our four deliberate divergences from KubeHound** (the "we model the precondition, not the
permission" thesis): PSA gate on `POD_CREATE`; real-Secret gate on `TOKEN_LIST`; `bind` requirement
on `ROLE_BIND`; `privileged`+`hostPID` both for `CE_NSENTER`.

**Non-negotiable:** `SCHEDULED_ON` stays `attack_path:0`, forever. And every new attack edge ships
with a hand-written assertion (a path that must exist, and one that must not). On the bundled
cluster, ~7 of 16 pods should reach cluster-admin — **if it says 16, a precondition leaked.**

---

## 5. The contract — so B and C never collide

FalkorDB: one graph per tenant, `rung:<tenant>`. Backend on **:8000**, frontend on **:3000**.

```
GET  /health                              → {status, falkordb, graph}
GET  /tenants                             → [{tenant, counts}]
GET  /stats?tenant=                       → counts
POST /ingest   (multipart file, ?tenant=) → {status, counts}        # exists
GET  /graph?tenant=&focus=&depth=         → {nodes:[{id,label,kind,props}],
                                             edges:[{source,target,type,attack_path}]}
GET  /paths?tenant=&source=&target=&max_hops=
                                          → {paths:[{steps:[{from,edge,to,why,confidence}]}]}
POST /simulate (json {tenant, remove:[ids]})
                                          → {before, after, closed:[fp], survived:[fp]}
POST /ask      (json {question, tenant})  → SSE stream, events:
     {type:"tool",  name, args}           # agent chose a tool
     {type:"token", text}                 # streamed answer text
     {type:"path",  steps:[...]}          # a chain to render
     {type:"final", answer, citations}    # done
```

C builds against this contract with a **mock** server first (static JSON), swaps to real when B
ships each endpoint. B implements `/graph`,`/paths`,`/simulate` as thin Cypher; `/ask` wraps A's
agent. A owns the Cypher behind `/paths` and `/simulate` and the agent behind `/ask`.

---

## 6. Day-by-day

### Tonight (15th) — unblock everyone
- **A (Harsh):** attack-edge derivation (all of §4) in `rung ingest` part 2, behind a flag so part 1
  stays green. The assertion harness. Verify ~7/16 on the bundled cluster. Push to `feat/attack-edges`.
- **B (Atharva):** start the real `rung collect` against the bundled cluster (the capture list is in
  `backend/HANDOFF.md`). Target: a snapshot whose ingest matches the dataset-based counts.
- **C:** environment up, read the contract, get Cytoscape rendering a static path from
  `dataset/sample-attack-chain.json`. No backend needed yet.

### 16th — the agent answers, data is real
- **A:** the agent — Tool Runner loop (`claude-opus-5-5`, adaptive thinking, effort `high`), the
  nine tools over the graph, the system prompt. Make it answer the four core questions with the
  path. Terminal first, then expose behind `/ask`.
- **B:** finish `collect`; implement `/graph`, `/paths`, `/tenants`. Produce the real
  `demo-snapshot.json` from the cluster and commit it as the seed.
- **C:** chat UI → `/ask` (SSE), graph pane → `/graph`, highlight the path from a `path` event.
  Click a step → show `why`.

### 17th — memory, simulation, the differentiator
- **A:** findings with both fingerprints (route + target), `simulate()`, and the regression detector
  (NEW / RESOLVED / ACCEPTED / REGRESSED). Facts + Exceptions + `recall`/`remember` tools.
- **B:** `/simulate` endpoint; the **baseline-vs-precondition comparison** (naive "every permission
  is a capability" vs ours — show the two numbers side by side; it proves the thesis). Harden API.
- **C:** regression badges, the before/after simulate view, tenant switcher (two clusters, same
  question, different answers). Start the README + demo script.

### 18th — ship
- **AM:** integration, deploy (FalkorDB **beside** the app — never the managed free tier; it deletes
  idle instances before judging), end-to-end dry run twice.
- **PM:** demo video (pre-recorded, < 3 min, open on a popped pod, end on the one-line fix), blog
  post (side prize), final README. **Submit both tracks by 20:00 IST.**

---

## 7. Integration checkpoints (don't skip)
- **End of 15th:** A's attack edges merged; B can see real counts; C renders a static path.
- **Midday 16th:** `/graph` live → C renders the real graph. Agent answers in a terminal.
- **End of 16th:** `/ask` live end-to-end for one question, real snapshot seeded.
- **End of 17th:** regression demo runs twice unattended; baseline comparison shows two numbers.

## 8. Cut list (decided now, in order)
1. MCP server exposure 2. `run_cypher` tool 3. Playbooks (procedural memory) 4. Second demo tenant
5. Custom UI → FalkorDB Browser + terminal.
**Never cut:** derivation correctness · the path behind every answer · the regression detector.

## 9. Submission checklist
- [ ] Public repo, clean history, no shared-account commits
- [ ] README: what it is, why a graph, 3 commands to run locally
- [ ] KubeHound/IceKube/BloodHound-Kube named as prior art + what we add
- [ ] Real collector used for the demo snapshot (not a hand-authored dataset)
- [ ] Live URL or docker-compose + local instructions
- [ ] Demo video < 3 min, pre-recorded
- [ ] Entered Track 01 and Track 02
- [ ] Blog post submitted (side prize)
- [ ] Data provenance stated (synthetic/own cluster, secrets redacted)
- [ ] Submitted by 20:00 IST, 18 Oct

## 10. Conventions
- Branch per stream (`feat/attack-edges`, `feat/collect`, `feat/frontend-graph`); PR into `main`;
  merge often. Keep `main` green (`cd backend && pytest`).
- Everyone commits under **their own name**.
- Backend `:8000`, frontend `:3000`, FalkorDB `:6380`. Graph name `rung:<tenant>`.
