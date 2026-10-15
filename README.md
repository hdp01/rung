# Rung

An agent that reasons over Kubernetes privilege-escalation paths in a graph.

> Built for **Graph Hacks: Context for AI Agents** (FalkorDB), 15–18 October 2026.
> Tracks 01 (Agents That Act on Connected Data) and 02 (Agent Memory and Coordination).

A cluster grants permissions in small, individually harmless pieces. Chain three of them and
you have cluster-admin. Nobody reviews the chains, because chains are not what the permission
model shows you. Rung loads the cluster into FalkorDB, derives the edges an attacker can
actually traverse, and puts an agent on top that answers in English — with the path.

## Quick start

```bash
docker compose up --build -d     # FalkorDB + app
open http://localhost:8090
```

To analyse your own cluster (read-only; nothing leaves your machine but a sanitised snapshot):

```bash
uv run rung collect --context <your-context> -o snapshot.json
curl -F file=@snapshot.json http://localhost:8090/snapshot
```

## Why a graph

<!-- TODO(event): the four questions, with real output -->

## Prior art, and what Rung adds

This graph has been built before — Datadog's [KubeHound](https://kubehound.io), WithSecure's
IceKube, IBM X-Force's BloodHound-Kube. All three require a human who knows Cypher or Gremlin
to ask the right question. Rung adds the agent, plus two things none of them do: change
simulation, and memory across snapshots.

It is also **more conservative than its prior art**, deliberately. Existing tools model
*permissions* and treat them as capabilities, which over-reports. Rung models the precondition:

| Common rule | Why it over-reports |
|---|---|
| scheduled on a node ⇒ can read its tokens | needs a container escape first |
| `secrets: list` ⇒ service-account tokens | not since k8s 1.24 — tokens are projected, not Secrets |
| `create rolebindings` ⇒ grant any role | RBAC escalation prevention blocks it without `bind`/`escalate` |
| `create pods` ⇒ own the node | not in a namespace enforcing restricted Pod Security Admission |

Each rule cites the KubeHound reference page it was checked against; the full table is in
`docs/edges.md`.

## Data

The bundled demo snapshot comes from a disposable local `kind` cluster built for this
project — our own synthetic data, no private, personal or restricted information. Secrets
are redacted at collection: Rung records that a Secret *exists* and its type, never its
contents. If you point `rung collect` at your own cluster, the snapshot stays on your
machine unless you choose to upload it.

## Status

Scaffolding. Implementation is written inside the event window, per the rules.

<!-- TODO(event): architecture, demo video, deployed URL -->
