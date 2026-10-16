# Winning strategy — how Rung wins, not just submits

The judging criteria weren't published, so the **brief is the rubric.** This maps every signal in
it to what we ship, names the gaps we're closing, and scripts the demo that wins. A great project
with a weak demo loses to a good one with a great demo — the demo script below is the single most
important artifact in this repo.

## 1. The rubric (from the brief) → what we deliver

| What the brief rewards | How Rung hits it | Status |
|---|---|---|
| Graph *shapes* what the agent does (not on the side) | The agent can't answer without traversing — the path IS the answer | core |
| Multi-hop reasoning | Variable-length attack chains, length unknown in advance | core |
| **Graph algorithms as agent tools** | `choke_points` = betweenness; `critical_reach`/`paths_to` = SPpaths; the agent CHOOSES them | **make visible in demo** |
| **Tool selection through MCP** | Expose our tools over MCP (FalkorDB ships a server) | **moved OFF the cut list — win multiplier** |
| Actions from what the graph shows | `simulate` a fix; recommend the one highest-leverage change | core |
| **Explainable results — "show the path" (said 3×)** | Path rendered + each edge's precondition evidence on click + agent cites every step | core — our signature |
| Episodic/semantic/procedural memory (Track 02) | Investigations, Facts, Exceptions; per-tenant isolated graphs | core |
| State across sessions + regression | The regression catch — a waived risk walks again by a new route | **our wow — never cut** |
| Powered by FalkorDB, centrally | One graph/tenant, FalkorDB algorithms as the agent's hands | core |

## 2. The three things that actually win — PROTECT these

These move us from "nice K8s tool" to "winner." They are **not** on the cut list.

1. **The path, evidence-linked.** Every answer names its chain, and every edge shows the cluster
   fact that justifies it. This is the most-repeated ask in the brief. If only one thing is polished,
   it's this.
2. **The baseline comparison (the proof).** Naive "every permission is a capability" says ~16/16
   pods reach cluster-admin (~1500 false TOKEN_LIST edges). Rung says a handful. Two numbers, side
   by side. This proves "why a graph, done right" in five seconds — judges remember proof.
3. **The regression catch (the Track-02 win).** "You accepted this risk yesterday; it's exploitable
   again by a new route that bypasses the control you trusted." Needs real persistence; can't be
   faked. This is the money shot.

## 3. The demo — scripted, < 3 min, pre-recorded (never live)

Open on the danger, close on the fix. Make a non-K8s judge feel it in 20 seconds.

| Time | Beat | On screen |
|---|---|---|
| 0:00 | **Hook.** "This CI-runner pod looks harmless. Watch what it becomes." | real cluster graph |
| 0:20 | Ask in English: *"This pod was just compromised — what can it reach?"* Agent streams, **picks tools**, walks the graph. | path lights up: pod →(CE_MODULE_LOAD)→ node →(TOKEN_STEAL)→ argocd SA →(PERMISSION_DISCOVER)→ cluster-admin →(ADMIN_OF)→ cluster |
| 0:45 | "Four steps to cluster-admin. Nobody reviewed this chain — it isn't in any single record." Click an edge → **why it exists**. | edge detail: the precondition fact |
| 1:10 | **The proof.** "Every other tool says 16 of 16 pods can do this. Most are false — they count permissions as capabilities. Rung counts preconditions." | baseline vs rung, side by side |
| 1:35 | **Algorithm as a tool.** *"What's the single highest-leverage fix?"* Agent runs **betweenness** → names one grant → `simulate` removing it. | before/after: reachable 7 → 0 |
| 2:05 | **Memory (Track 02).** *"I accepted this risk yesterday."* Re-collect. Agent: *"It's exploitable again — a new RoleBinding opens a second route that bypasses the control you relied on."* | **REGRESSED** banner |
| 2:35 | Close: "Real cluster data. An agent that reasons over the graph, uses its algorithms, shows every step, remembers, and won't overstate what it knows." | 2s of FalkorDB Browser — the graph is real |

Record it as soon as the MVP works. A recorded demo can't fail on judging-day wifi.

## 4. The MVP gate — hit this EARLY or we don't have time to win

**By end of 16th / first thing 17th:** real collector → correct attack edges (~7/16) → agent answers
ONE question with the path → frontend wired to real backend. That's a complete Track-01 demo. Reach
it fast; then 17th–18th is the two wow features + the demo + polish, not building. If we're still
building core on the 18th, we've already lost — so the gate is the forcing function.

## 5. Win multipliers (do these once MVP is locked)
- **MCP** — expose the tools via MCP; it's literally in the Track-01 focus list. Say it in the demo.
- **Blog post** — separate prize (AirPods), low cost; Omyerkar owns it. Write it from this doc + the
  "model the precondition" thesis. Submit it.
- **Two tenants** in the demo — same question, different clusters, different answers → proves the
  per-tenant isolation the brief calls out.

## 6. Honest risk register
- **Critical path is derivation + agent in ~2 days.** Mitigation: the MVP gate; pull Omyerkar onto
  endpoints if Atharva stalls; the agent is ours and starts now.
- **A false edge is a silent lie.** Mitigation: the assertion harness runs on every push; ~7/16 is
  the canary.
- **Niche domain.** Mitigation: the hook framing — danger a non-expert feels in 20 seconds.
- **Live-demo failure.** Mitigation: pre-recorded video + committed real snapshot + one-command
  bring-up with FalkorDB beside the app.

## 7. What we are NOT doing (focus is a weapon)
No Track 03 (no real ownership data — a stretch that dilutes). No autonomous remediation (we
recommend + simulate, we don't act on the cluster). No extra edges beyond the spec. Depth on the
three protected things beats breadth everywhere.
