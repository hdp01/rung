# Every published tool models permissions and calls them capabilities — Rung models the precondition

Sixteen pods can reach cluster-admin, according to every tool that counts permissions as capabilities. Rung counts preconditions, and says six. A raw 1,472 `TOKEN_LIST` edges shrinks to sixteen. The difference is the reason Rung exists.

## The wrong question: "does it have the verb?"

Kubernetes permissions are granular. Each on its own looks harmless: "create pods" in one namespace, "get secrets" in another, "bind roles" through a tightly-scoped ClusterRoleBinding. Chain three of these — each individually permissible under a naive read — and you have cluster-admin. The problem: most tooling treats the verb as the capability.

That over-counts. Four specific mechanisms break that equivalence:

1. **Pod Security Admission.** `create pods` is a verb; in a namespace enforcing restricted/baseline Pod Security Standards, creating a privileged hostPID pod is rejected. The permission exists, the capability does not.
2. **Projected tokens, not stored Secrets.** Since Kubernetes 1.24, service-account tokens are projected into pods. The "list secrets" path to tokens — the one that explodes the edge count — only holds when a `kubernetes.io/service-account-token` Secret actually exists. Rung ignores that edge unless the precondition is met.
3. **RBAC escalation prevention.** You can have `create clusterrolebindings` without being able to grant cluster-admin unless you also have `bind` on that role — and even then only for names permitted by `resourceNames`. A verb alone is not enough.
4. **Host reach.** Scheduled on a node does not mean you own its tokens. Token theft requires real host escape (privileged + hostPID, host path traversal, or runtime socket access). Without that precondition, the `TOKEN_STEAL` edge never exists.

None of these are edge cases. They explain why naive graph counts look terrifying while real clusters aren't falling over for those exact reasons.

## The 1472 → 16 moment

On the bundled demo cluster:

- Naive (permissions = capabilities): **16** workloads reach cluster-admin, with **1,472** `TOKEN_LIST` edges.
- Rung (preconditions checked): **6** workloads reach cluster-admin, with **16** `TOKEN_LIST` edges.

That's not a rounding error. It's the delta between "what could happen if nothing else stopped it" and "what can actually traverse the cluster as-is".

The graph pane shows it plainly: toggle between the two readings, and most of the web of edges disappears because the precondition wasn't satisfied — no host escape, no projected token in the right place, or the binding is blocked by RBAC constraints.

## The "accepted risk back by a new route" moment

Track-02's money shot isn't just the shrink. It's regression.

You accepted a risk last week. You marked it `ACCEPTED`. This week, someone changes a Pod Security setting, adds a new workload, or binds a different role — and that same *accepted* target becomes reachable by a route you've never seen before.

Rung's regression detector catches it: the route fingerprint changes, the finding flips to **REGRESSED**, and a banner across the top makes you look at it before you merge. You didn't forget the risk; the cluster grew a new path around it. The fact that you accepted it before doesn't mean you accept it now.

This is the difference between "we knew about X" and "X is exploitable again by a different means". Memory across snapshots matters here: the detector knows what was `RESOLVED` or `ACCEPTED`, so it can raise `REGRESSED` rather than just creating another `NEW` finding.

## Why the agent matters

Prior art (KubeHound, IceKube, BloodHound-Kube) proved the graph is the right lens. What they miss is usability: you have to know Cypher, and you have to ask the right question. Rung puts an agent on top that chooses the right graph algorithms (shortest paths, blast radius, choke points) in response to English questions, streams its reasoning, and lights up the chain on the graph as it goes. Click any edge and you see *why* that hop exists, with a confidence level — the precondition, not the verb.

Add change simulation ("if I remove this binding, what closes?"), persona overlays (redteam/defender/auditor), and the baseline comparison, and you're reasoning about the next change, not just the current state.

## Conclusion

Every published tool models permissions and calls them capabilities. Rung models the precondition.

The numbers — 1472 → 16 — tell you the thesis in four digits. The REGRESSED moment tells you why it needs memory. The chain you can click, step by step, tells you why each hop is actually traversable. That's the difference between alarming charts and actionable remediation.
