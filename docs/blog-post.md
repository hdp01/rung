---
title: "A permission is not a capability: a Kubernetes attack-path agent on FalkorDB"
published: false
description: "We built an agent that reasons over a Kubernetes attack graph in FalkorDB. Here's the thesis, the build, and the three things that actually bit us."
tags: kubernetes, security, ai, database
---

Every Kubernetes attack-path tool we compared against says sixteen of sixteen workloads in our demo cluster can reach cluster-admin. Six actually can. The other ten are a road drawn through a wall.

That gap is the entire reason we built Rung, and chasing it down over a weekend taught us more about graph modeling, RBAC, and the limits of LLM guardrails than we expected. This is the write-up: the idea, how FalkorDB carries it, and the three problems that cost us the most time.

## The number that started it

Here's a CI runner. One pod in a namespace called `jenkins`. On its own it's boring: it can create a pod, read its own projected token, and it's attached to a single ClusterRoleBinding. Every line in its RBAC is something a reviewer waves through.

Ask a graph the obvious question (starting from this pod, what can it reach?) and the answer depends entirely on what you let an edge mean.

Read it the way most attack-path tooling does, asking only "does this identity hold the verb?", and the cluster is on fire. `create pods`, so it can own a node. `list secrets`, so it holds every token in the namespace. Follow that honestly and the graph explodes: **16 of 16** workloads reach cluster-admin, dragging **1,472** `TOKEN_LIST` edges behind them.

Ask instead *does the precondition actually hold?* and the number is **6**. The `TOKEN_LIST` edges collapse to **16**. Same cluster, same graph engine, two completely different maps of risk.

1,472 edges that don't exist. That's the thesis in four digits, and it isn't an academic point. Over-reporting is the failure mode that gets a security tool muted in week two.

## Why the naive reading is wrong

A permission is a key in a drawer. A capability is that key, in a hand, in front of the door. Four mechanisms break the equivalence, and none of them is exotic:

- **Pod Security Admission.** `create pods` is real, but in a namespace enforcing baseline or restricted PSS, the privileged `hostPID` pod it implies is rejected at admission. The permission exists; the escape doesn't.
- **Projected tokens, not stored Secrets.** Since Kubernetes 1.24, service-account tokens are projected into pods, not written to Secret objects. The "list secrets → own the tokens" path, the one that turns a single edge into hundreds, only holds if a real `kubernetes.io/service-account-token` Secret exists.
- **RBAC escalation prevention.** `create clusterrolebindings` doesn't let you grant cluster-admin unless you *also* hold `bind` on that role, and only for the `resourceNames` you're allowed to touch.
- **Host reach.** Being scheduled on a node isn't owning its tokens. Stealing a kubelet token needs a real escape first: `privileged` *and* `hostPID`, a hostPath traversal, or the container-runtime socket.

So in Rung an edge only exists in the attack graph if its precondition is satisfied in the snapshot. That one rule is the difference between the 16 and the 6.

## Why a graph, and why an agent on top

KubeHound, IceKube and BloodHound-Kube already proved the graph is the right lens. What they leave on the table is that a graph is a query engine you already have to know how to drive. They hand you Cypher or Gremlin and wish you luck.

We put an agent on top whose hands *are* the graph algorithms. You ask in English; it decides whether your question is a shortest-path one (`algo.SPpaths`), a betweenness one ("what's the single grant to cut?"), a PageRank one ("what does our attack surface actually centre on?"), or a blast-radius one, then answers *with the path* and lights the chain up on the graph as it walks. Click any hop and you get the cluster fact behind it, not the verb, plus the MITRE ATT&CK technique and the CIS Benchmark control that would have stopped it.

The part we're proudest of is the memory, because it's the thing a flat database genuinely can't do. Rung stores route *fingerprints* as graph state, so it can catch this moment: you accepted a risk last week and marked it `ACCEPTED`; this week an integration re-adds the same admin grant through a *different* route that traverses none of the controls your acceptance relied on. The finding flips to `REGRESSED` and a banner says so before you merge. That's a reachability comparison over persisted graph state, not a diff of two JSON files.

## Three things that actually bit us

The demo numbers are clean. Getting there was not. These are the three that cost us hours and taught us the most.

### 1. FalkorDB doesn't like a length expression inside a variable-length match

Our first blast-radius query looked reasonable:

```cypher
MATCH (a {id:$id})-[*1..5 {attack_path:1}]->(t)
WITH t, min(length((a)-[*1..5 {attack_path:1}]->(t))) AS hops
RETURN t.id, hops
```

It failed with `Type mismatch: expected Path or Null but was List`. The tool just returned an error object and the blast-radius view came back empty, which sent us poking at the frontend before we read the actual query result. The fix is to bind the path and take its length, instead of re-expressing the pattern inside `length()`:

```cypher
MATCH p = (a {id:$id})-[*1..5 {attack_path:1}]->(t)
WITH t, min(length(p)) AS hops
RETURN t.id, hops
```

Obvious in hindsight. The lesson that stuck: a graph-query error two layers down renders as "nothing drew," so when a pane goes blank, check the query result before you touch the renderer.

### 2. The attack graph is combinatorial, and you have to decide what "a finding" is

Our first instinct was to enumerate every path from every workload to cluster-admin. On one demo cluster that's roughly **350,000 paths** within twelve hops. The detector hung, the UI would have been unreadable, and even if it worked, "here are 350k findings" is useless to a human.

So we changed the definition of a finding. Instead of every path, Rung keeps one *canonical witness* per (source, admin-grant) pair: the shortest route, found with a bounded BFS over `attack_path:1` edges. That's a list a person can actually read, and critically the fingerprint of that witness still *changes* when the controls on the route change, which is exactly what regression detection needs. The modeling decision, what counts as one finding, mattered more than any query we wrote.

### 3. The model refused to talk about the security tool we built it into

This one is our favourite. Two of our best features, "show me an attacker playbook for this chain" and the red/blue debate, are exactly the kind of prompt a safety filter is trained to reject. Amazon Nova's guardrail intermittently blocked them on input, so clicking our own "attacker playbook" button sometimes returned *"the generated text has been blocked by our content filters."* A defensive tool, too defensive for the model running it.

So we stopped fighting the filter and routed those intents deterministically. We already had the structured tool output (the kubectl/nsenter steps, the red and blue positions, the graph-verified verdict), so we render it straight from the graph and skip the model turn entirely. It's more reliable *and* a better answer than a paraphrase. The learning: when the LLM is the flaky part, let the graph be the source of truth, and use the model only for the parts that genuinely need language.

A smaller cousin of this bug: the debate's "verdict" first claimed it couldn't verify a fix, because we were simulating removal of `ClusterRole/cluster-admin` when the demo's real route runs through `argocd-application-controller`. We'd hardcoded the wrong role, and we were reading the wrong key off the `simulate_remove` result. Deriving the role from the actual route, and stating only what the graph can prove, fixed both.

## What FalkorDB gave us

The reason an agent *can* call several graph algorithms per question is speed. SPpaths, betweenness, and bounded variable-length traversals all return in milliseconds on our graph, so the agent runs them in a loop without a human waiting on each hop. That's what makes "LLM proposes, graph verifies" feel instant instead of sluggish. Having the algorithms as Cypher procedures meant no separate graph-compute layer. One instance hosting many named graphs (`rung:<tenant>`) gave us per-tenant isolation for free. And because it speaks the Redis protocol with an official image, the whole stack (graph, API, Next.js UI, nginx) ships as a single container, which is how the live demo is one `docker run`.

The one architectural trick worth stealing: our memory nodes (`:Finding`, `:Snapshot`, `:Exception`) are deliberately *not* labelled `:Entity`, because ingest rebuilds the cluster with `MATCH (n:Entity) DETACH DELETE n` on every snapshot. If memory wore the `:Entity` label, every scan would wipe the exact state the regression detector exists to keep. Keep durable state outside the label you bulk-delete. We made that a contract the tests enforce, so a careless future edit can't quietly break it.

## What we'd want next

PageRank over a *filtered* subgraph would have saved us a detour. We wanted it over `attack_path:1` edges only and ended up computing it in Python, because projecting an induced subgraph for the built-in wasn't obvious. Clearer errors on the variable-length length mismatch, and fuller docs on the newer algorithm procedures, would both have saved real time. None of these slowed us down for long, but they're the rough edges we hit.

## Where it landed

| | Naive: permission = capability | Rung: precondition checked |
|---|---|---|
| Workloads reaching cluster-admin | 16 of 16 | **6** |
| `TOKEN_LIST` edges | 1,472 | **16** |

Twenty agent tools, all exposed over MCP so another agent can call Rung's reasoning directly; a regression detector that survives re-ingests; and a one-container deploy. Every published tool in this space models the permission and calls it a capability. Rung models the precondition, and then remembers what you decided about it.

---

*Rung was built over a weekend for Graph Hacks (FalkorDB), across Track 01 (agents that act on connected data) and Track 02 (agent memory and coordination).*

**Try it:** [live demo](https://35-154-42-179.sslip.io) · [code on GitHub](https://github.com/hdp01/rung) · runs locally with one `docker compose up`.
