# Stream A — Core & Agent  (Harsh)

For team visibility — what A delivers and when, so B/C know the functions they depend on.

## A1 — Attack-edge derivation (15th eve)
`rung ingest` part 2: all edges in `TEAM_PLAN.md` §4, each with its precondition, each with a
hand-written assertion (a path that must exist + one that must not). `SCHEDULED_ON` stays
`attack_path:0`. Target ~7/16 pods reaching cluster-admin on the bundled cluster.
*Exposes to B:* `rung.paths.paths_to(tenant, source, target, max_hops)`,
`rung.paths.blast_radius(tenant, id, max_hops)`, `rung.paths.critical_reach(tenant)`,
`rung.paths.choke_points(tenant, top_n)` — all returning plain dicts.

## A2 — The agent (16th)
Tool Runner loop, `claude-opus-5-5`, adaptive thinking, effort `high`. Nine tools over the graph,
strict schemas, structured (not prose) returns. System prompt enforces: answer only from tools,
always cite the chain, state confidence, a permission is not a capability.
*Exposes to B:* `rung.agent.ask(question, tenant) -> Iterator[dict]` yielding
`tool`/`token`/`path`/`final` events for `/ask` to stream.

## A3 — Memory + regression (17th)
Findings with both fingerprints (route + target), `simulate()`, the NEW/RESOLVED/ACCEPTED/REGRESSED
detector, Facts + Exceptions + `recall`/`remember`. Memory nodes never carry `:Entity` (so ingest
teardown can't touch them).
*Exposes to B:* `rung.sim.simulate(tenant, remove)`, and `status` on findings for C's badges.

## A4 — Integration (18th)
Help wire `/ask`, verify the regression demo runs twice unattended, support deploy.
