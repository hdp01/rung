# Rung — demo video script

**Target length:** 2 min 45 sec (hard cap 3 min).
**Audience:** Graph Hacks judges. Assume they know Kubernetes but have never heard of Rung.
**One thing they must remember:** *"permission is not a capability"* — Rung models the precondition
and remembers decisions across scans.

**Recording setup:**
- Browser full-screen on the deployed Fly URL (fallback: localhost after `docker compose up -d`).
- `.env` with `BEDROCK_API_KEY` loaded so the real agent streams tool calls.
- Default tenant already seeded with `demo-snapshot.json`.
- OBS Studio or QuickTime, 1920×1080, 30 fps. One voice track, one screen track.
- No cursor wiggling — move with intent.

---

## Shot list

### Shot 1 — The thesis (0:00 – 0:20)
**Visual:** Compare panel in full view. Numbers already loaded: naive 16, rung 6, TOKEN_LIST 1472 → 16.

**Voiceover:**
> "Sixteen pods in this Kubernetes cluster reach cluster-admin — if you count every permission as a
> capability. Rung counts preconditions. The answer is six. The same cluster. The difference is what
> an edge is allowed to mean."

**Beat:** 2-second hold on the numbers before cutting.

---

### Shot 2 — The graph (0:20 – 0:40)
**Visual:** Switch to graph tab. Click one attack edge (CE_PRIV_MOUNT or TOKEN_STEAL).
Popup shows the cluster fact that justifies it.

**Voiceover:**
> "Every edge carries the fact that makes it real. This one: the container is privileged and mounts
> the host filesystem. Click any edge in the graph — the precondition is right there. SCHEDULED_ON is
> drawn muted because scheduling isn't an attack step, even though every graph tool before Rung
> treated it as one."

---

### Shot 3 — The agent reasoning (0:40 – 1:20)
**Visual:** Open chat. Click the first chip: *"Which pods can reach cluster-admin?"*
Let it stream. Tool-call pills appear (`critical_reach`), then the answer streams, then a path
lights up on the graph on the right.

**Voiceover:**
> "The chat on the left is the agent. It picks the right graph algorithm for the question — here,
> `critical_reach` runs a BFS over the attack subgraph. It streams the tool call, streams the answer,
> and lights up the chain on the graph. No one writes Cypher. KubeHound, IceKube, BloodHound-Kube —
> all three make you."

Then click the second chip: *"ci-runner is compromised — what can it reach, grouped by namespace?"*
Watch `blast_radius` tool pill appear, grouped-by-namespace output in the answer.

**Voiceover:**
> "Ask it a different shape of question and it picks a different tool — blast radius, grouped by
> namespace, so one compromised pod becomes a one-line summary of exactly which teams own the fallout."

---

### Shot 4 — The money shot: REGRESSED (1:20 – 1:55)
**Visual:** Show findings panel. Highlight the REGRESSED banner across the top.

**Voiceover:**
> "Here's what no other K8s graph tool does. You accepted a risk last week — *Jenkins needs
> privileged containers for Docker builds, we accept it*. Someone binds a new ClusterRoleBinding this
> week, and that same accepted target is reachable again, by a route that bypasses the control you
> trusted. Rung's regression detector catches it. The finding flips from ACCEPTED to REGRESSED, a
> banner lights up, and you look at it before you merge."

**Beat:** Hold on the REGRESSED banner for 2 seconds.

---

### Shot 5 — Executable PoC (1:55 – 2:20)
**Visual:** Chat chip: *"Show me an attacker playbook for the highest-risk chain"*.
Watch `exploit_poc` tool pill, output renders the kubectl/nsenter commands.

**Voiceover:**
> "And when a defender asks *'how would an attacker actually walk this?'*, Rung generates the
> playbook — the exact kubectl, nsenter and chroot commands per edge, what identity each hop needs,
> and the cleanup. Nobody else ships this. Prior tools stop at *there is a path*. Rung ships the
> repro."

---

### Shot 6 — MCP and the close (2:20 – 2:45)
**Visual:** Terminal split-screen with Claude Code or Cursor. Run a Rung tool via MCP — e.g.
`critical_reach` — and show it returning real data from the running stack.

**Voiceover:**
> "All nineteen of these tools are exposed over MCP. Any agent — Claude Code, Cursor, your own
> system — can call them against your cluster. Rung is a graph-native reasoner for Kubernetes
> security: it asks, simulates, remembers, and fixes. One repo, one `docker compose up`, pointed at
> your cluster — the attack paths that actually work."

**End card:** "github.com/hdp01/rung" + "Graph Hacks 2026 · Tracks 01 & 02"

---

## Backup chip questions (if a shot flubs and we need a retake)

- *"What should I fix first for the highest leverage?"* → `choke_points` tool pill
- *"Is the cluster getting better or worse — show the trend"* → `attack_trend` tool pill
- *"Simulate removing the argocd-application-controller clusterrolebinding"* → `simulate_remove` tool pill

## Pre-record checklist

- [ ] `docker compose up -d`; `curl localhost:8000/health` returns `connected`.
- [ ] Visit `localhost:3000`; compare panel shows `16 / 6 / 1472 / 16`.
- [ ] `.env` has `BEDROCK_API_KEY` and `BEDROCK_MODEL_ID=amazon.nova-pro-v1:0`.
- [ ] Ingest `demo-snapshot-v2.json` then `demo-snapshot-v3.json` so REGRESSED finding exists.
- [ ] One accepted exception recorded (so the REGRESSED banner has something to show).
- [ ] Browser zoom at 110% for legibility.
- [ ] Hide bookmarks bar, close other tabs.

## Post-production notes

- No background music under voiceover — the tool-call pills + numbers are the drama.
- Faint cursor highlight on each chip click.
- Lower-third captions on the thesis line (0:08) and the REGRESSED line (1:38).
- Cut aggressively — any pause > 1.5 seconds is wasted.
- Export MP4 H.264, upload unlisted to YouTube, link from submission form.
