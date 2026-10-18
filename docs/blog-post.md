# The permission is not the capability

*Every attack-path tool we compared against says sixteen of sixteen workloads in our demo cluster can reach cluster-admin. Six actually can. The other ten are a road drawn through a wall — and that gap is the whole reason Rung exists.*

---

Picture a CI runner. It is one pod in a namespace called `jenkins`, and on its own it is boring: it can create a pod, read its own projected token, and touch a single ClusterRoleBinding. Each line in its RBAC manifest is something a reviewer would wave through.

Now ask a graph one question — *starting from this pod, what can it actually reach?* — and watch the answers diverge.

Ask it the way most attack-path tooling asks, and the cluster is on fire. The reading is "does this identity hold the verb?" `create pods`? then it can own the node. `list secrets`? then it holds every token in the namespace. Follow that logic honestly and the graph explodes: **sixteen of sixteen** workloads reach cluster-admin, trailing **1,472** `TOKEN_LIST` edges behind them.

Ask it the question Rung asks — *does the precondition actually hold?* — and the number is **six**. The `TOKEN_LIST` edges fall to **sixteen**. Same cluster, same graph engine, two utterly different maps of risk.

**1,472 edges that don't exist. That is the thesis in four digits.**

## The wrong question

A Kubernetes permission is a key in a drawer. A capability is that key, in a hand, in front of the door. Most tooling reads the verb and quietly assumes the rest.

Four mechanisms break the equivalence, and not one of them is exotic:

1. **Pod Security Admission.** `create pods` is real — but in a namespace enforcing baseline or restricted PSS, the privileged `hostPID` pod it implies is rejected at admission. The permission exists; the escape does not.
2. **Projected tokens, not stored Secrets.** Since Kubernetes 1.24, service-account tokens are projected into pods rather than written to Secret objects. The "list secrets ⇒ own the tokens" path — the one that turns a single edge into hundreds — only holds if a real `kubernetes.io/service-account-token` Secret exists. Rung simply refuses the edge otherwise.
3. **RBAC escalation prevention.** Holding `create clusterrolebindings` does not let you grant `cluster-admin` unless you also hold `bind` on that role — and only for the `resourceNames` you are permitted to touch.
4. **Host reach.** Being scheduled on a node is not owning its tokens. Stealing a kubelet token requires an actual escape first: `privileged` *and* `hostPID`, a hostPath traversal, or access to the container-runtime socket.

A permission is not a capability. The naive reading does not merely over-report — it draws a road straight through a wall. Over-reporting is the dominant failure mode of attack-path tooling, and it is the failure mode that gets the tool switched off.

## Why a graph — and why an agent on top

The graph is the right lens; KubeHound, IceKube and BloodHound-Kube each proved it. What they left on the table is that **a graph is a query engine you have to already know how to interrogate.** They hand a security engineer Cypher and wish them luck.

Rung puts an agent on top whose hands *are* the graph's algorithms. You ask in English. It decides — on its own — whether your question is a shortest-path question (`paths_to`), a betweenness question ("what is the one grant to cut?", `choke_points`), a PageRank question ("what does our attack surface actually centre on?", `attack_rank`), or a blast-radius question. Then it answers **with the path**, lighting the chain up on the graph as it walks.

Click any hop and you get the cluster fact that justifies it — not the verb:

> *"serviceAccount `jenkins` is mounted in this pod (automountServiceAccountToken not disabled)"* · *"bound by ClusterRoleBinding `cluster-admin`"*

*Show the path* is the most-repeated ask in the brief, and it is the thing Rung polishes hardest. Every edge can explain itself.

Then it does something a graph demo never does: it speaks the language the security team already uses. Every attack hop carries its **MITRE ATT&CK** technique and the **CIS Kubernetes Benchmark** control that would have prevented it — `CE_PRIV_MOUNT → T1611 · CIS §5.2`. And when you ask for the fix, it hands back the actual **Kyverno ClusterPolicy** that closes the edge, annotated with the same technique and control, ready to paste into a PR.

## The memory is the innovation

Track 02 asks for "memory." Most entries will store a chat log and call it memory. Rung stores **route fingerprints** — a graph-reachability invariant, not a transcript — and that buys the one moment nothing else in this space has:

> You accepted a risk last week. You marked it `ACCEPTED`. This week an integration re-adds the same admin grant through a **different route** that traverses none of the controls your acceptance relied on. The finding flips to **REGRESSED**, and a banner says so before you merge: *the risk you waived is back, and not the way you remember it.*

We scripted the whole cycle against a real `kind` cluster: v1 (73 routes, all `NEW`) → accept the hero chain (32 findings covered) → v2 (**68 `RESOLVED`**) → v3 (**7 `REGRESSED`**, three of them `previous_status = ACCEPTED`). It replays offline in a single command. That is not a slide; it is a fingerprint comparison over persisted graph state.

## What we actually built

- **A real collector.** `rung collect` reads a cluster read-only and writes a sanitised snapshot. Secret contents are redacted at collection — Rung records that a Secret *exists* and its *type*, never its data. The hosted graph never holds cluster credentials.
- **FalkorDB, one graph per tenant.** Ask two clusters the same question and get two different answers — isolation is a graph, not a filter.
- **An agent with 20 graph tools** — the algorithms above, plus `simulate_remove` ("if I delete this binding, what closes?"), `propose_policy`, `exploit_poc`, `snapshot_diff`, and a **red/blue debate** where two personas argue a finding over the live graph: the model supplies the voice, the graph verifies every claim.
- **All 20 tools over MCP**, so Claude Code, Cursor or your own agent can call Rung's reasoning directly. The graph stops being a page you visit and becomes a capability other agents use.
- **123 tests**, and they run with no model key at all.

## The honest edge

A false edge is a silent lie, so every hop carries a confidence, and every snapshot is re-derived rather than trusted. And Rung deliberately stops short of action: it will name the single binding worth removing and show the reachable set collapse to zero, but it never touches your cluster. It recommends and simulates. You decide.

## The proof

| | Naive: permission = capability | Rung: precondition checked |
|---|---|---|
| Workloads reaching cluster-admin | 16 of 16 | **6** |
| `TOKEN_LIST` edges | 1,472 | **16** |

Two numbers, side by side, in the same UI — because "why a graph, done right" should be provable in five seconds.

Every published tool in this space models the permission and calls it a capability. **Rung models the precondition** — and then remembers what you decided about it.

---

*Rung was built for **Graph Hacks: Context for AI Agents** (FalkorDB), 15–18 October 2026, across Track 01 (agents that act on connected data) and Track 02 (agent memory and coordination). Three commands and Docker are all you need to run it: `docker compose up --build -d`, then open `http://localhost:3000`.*
