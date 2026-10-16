# Stream A — Agent + QA / Integration  (Harsh + lead)

Changed on Day 2: the team builds the backend; we build the **agent** and run the **polish/fix/
integration** pass that makes it submission-ready.

## A1 — The agent (the novel core — ours)
Tool Runner loop, `claude-opus-5-5`, adaptive thinking, effort `high`. Tools over the graph:
`list_entities`, `explain_entity`, `blast_radius`, `paths_to`, `critical_reach`, `choke_points`,
`simulate`, `recall`, `remember` — strict schemas, structured returns. System prompt enforces:
answer only from tools, always cite the chain, state confidence, a permission is not a capability.
Expose `rung.agent.ask(question, tenant) -> Iterator[AskEvent]` (shapes in `frontend/src/lib/
types.ts`) so B's `/ask` just forwards it as SSE.

## A2 — Assertion harness (our QA weapon over Atharva's derivation)
Hand-written expected paths: chains that MUST exist and chains that MUST NOT. Run it on every push
to `main`. This is how we catch a false edge before a judge does. On the bundled cluster: ~7/16
pods reach cluster-admin — **if it says 16, a precondition leaked; find which edge and fix it.**
Verify the four deliberate gates (PSA on POD_CREATE, real-Secret on TOKEN_LIST, `bind` on ROLE_BIND,
`privileged`+`hostPID` on CE_NSENTER) each actually fire on both the positive and negative fixtures.

## A3 — Fix / integrate / ship
Review each PR for correctness, fix bugs, wire the frontend to the real backend with B/C, deploy
(FalkorDB beside the app, reseed from the committed snapshot on boot), and package the submission
(README, data-provenance note, both tracks, demo video, blog). Keep `main` green:
`cd backend && pytest`.

**Working note for the lead:** project path has `[]`, which breaks pytest locally — run tests from a
bracket-free copy (teammates on normal paths are unaffected).
