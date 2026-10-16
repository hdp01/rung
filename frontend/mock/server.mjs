import { createServer } from "node:http";
import { readFileSync } from "node:fs";
const j = (f) => JSON.parse(readFileSync(new URL(`./${f}`, import.meta.url)));
const send = (res, code, body, type="application/json") => {
  res.writeHead(code, { "content-type": type, "access-control-allow-origin": "*", "cache-control": "no-store" });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
};
const readBody = (req) => new Promise((resolve, reject) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => resolve(Buffer.concat(chunks)));
  req.on("error", reject);
});
// pull the file payload out of a multipart/form-data body (what fetch(FormData) sends)
const filePart = (buf, ctype) => {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/.exec(ctype || "");
  if (!m) return null;
  const boundary = `--${(m[1] || m[2]).trim()}`;
  const part = buf.toString("utf8").split(boundary).slice(1, -1)[0];
  if (!part) return null;
  const i = part.indexOf("\r\n\r\n");
  return i === -1 ? null : part.slice(i + 4).replace(/\r\n$/, "");
};
// split an answer into a few chunks so the client streams it token by token
const chunks = (text) => text.match(/[^.!?]+[.!?]?\s*/g)?.map((s) => s.trim()).filter(Boolean) ?? [text];

// Canned, question-aware answers: the mock picks a chain from paths.json instead of
// replaying one fixture, so different questions answer differently while A/B build /ask.
const REPLIES = [
  {
    match: /(volume|host[ -]?path|host root|hostroot|mount)/i,
    path: "vol-to-cluster",
    finding: "fp:vol-to-cluster",
    answer:
      "The hostroot volume is hostPath /, a parent of /var/lib/kubelet/pods, so the mount reads every service-account token on the node. From the jenkins identity that is two more hops to cluster-admin.",
  },
  {
    match: /(container|escape|privileged|hostpid|kernel|module|node|control[ -]?plane)/i,
    path: "container-to-node",
    finding: "fp:container-to-node",
    answer:
      "The container is privileged, so it loads kernel modules and reaches the node directly — no RBAC needed for that hop. The pod also sets hostPID, so nsenter is available; the runtime hardening is what stops it.",
  },
  {
    match: /(pod|jenkins|reach|compromised|admin)/i,
    path: "pod-to-cluster",
    finding: "fp:pod-to-cluster",
    answer:
      "The jenkins pod does not need an RBAC detour to reach cluster-admin. Its service account is bound straight to cluster-admin, so anyone who lands on pwn-pod is cluster-admin in three hops. That is the finding: the pod is the entry point, the binding is the fix.",
  },
];

// The hardened tenant answers the *same* questions differently: no privileged
// container, no hostPath, no cluster-admin grant — so some questions have no chain at all.
const REPLIES_SECURE = [
  {
    match: /(volume|host[ -]?path|host root|hostroot|mount)/i,
    path: null,
    answer:
      "This cluster has no hostPath volumes: neither pod mounts anything from the host, and both namespaces enforce the restricted Pod Security Standard. There is no host-traversal hop to walk.",
  },
  {
    match: /(container|escape|privileged|hostpid|kernel|module|control[ -]?plane)/i,
    path: null,
    answer:
      "No container here is privileged and neither pod sets hostPID or hostNetwork, so there is no container-to-node escape. The only links to the nodes are SCHEDULED_ON edges, which Rung marks as display-only, never as an attack step.",
  },
  {
    match: /(pod|jenkins|reach|compromised|admin)/i,
    path: "contained-to-namespaced-role",
    finding: "fp:pod-to-cluster",
    target: "cluster",
    answer:
      "Same question, different cluster: there is no pwn-pod here. The workloads are webapps/frontend and webapps/backend, neither privileged and neither granted anything dangerous. The only binding is a namespaced Role that can get pods in webapps, so the chain stops two hops in — nothing here reaches cluster-admin.",
  },
];

// One graph per tenant (contract §5: graph name `rung:<tenant>`).
const TENANTS = [
  { tenant: "kind-graphhacks", graph: "graph.json", paths: "paths.json", replies: REPLIES },
  { tenant: "kind-graphhacks-secure", graph: "graph-secure.json", paths: "paths-secure.json", replies: REPLIES_SECURE },
];
// Regression detector findings — C5 stub, the same route/target fingerprints and statuses the UI
// renders. A ships the real ones on the 17th; only this map and the /findings route change then.
const FINDINGS = {
  "kind-graphhacks": [
    {
      id: "fp:pod-to-cluster",
      status: "REGRESSED",
      title: "pwn-pod reaches cluster-admin",
      route: "IDENTITY_ASSUME › PERMISSION_DISCOVER › ADMIN_OF",
      target: "cluster-admin @ cluster",
      previous_status: "RESOLVED",
      note: "the cluster-admin RoleBinding removed in the fix is back in this snapshot",
      first_seen: "2026-10-15T09:00:00Z",
      last_seen: "2026-10-16T09:00:00Z",
    },
    {
      id: "fp:vol-to-cluster",
      status: "NEW",
      title: "hostPath volume exposes every token on the node",
      route: "EXPLOIT_HOST_TRAVERSE › PERMISSION_DISCOVER › ADMIN_OF",
      target: "cluster-admin @ cluster",
      note: "first seen in this ingest",
      first_seen: "2026-10-16T09:00:00Z",
      last_seen: "2026-10-16T09:00:00Z",
    },
    {
      id: "fp:container-to-node",
      status: "ACCEPTED",
      title: "container can load kernel modules",
      route: "CE_MODULE_LOAD",
      target: "control-plane @ node",
      note: "privileged and hostPID are deliberate in this lab; risk accepted",
      first_seen: "2026-10-15T09:00:00Z",
      last_seen: "2026-10-16T09:00:00Z",
    },
  ],
  "kind-graphhacks-secure": [
    {
      id: "fp:pod-to-cluster",
      status: "RESOLVED",
      title: "workload reaches cluster-admin",
      route: "IDENTITY_ASSUME › PERMISSION_DISCOVER › ADMIN_OF",
      target: "cluster-admin @ cluster",
      note: "no cluster-admin grant in this snapshot: the route no longer walks",
      first_seen: "2026-10-15T09:00:00Z",
      last_seen: "2026-10-16T09:00:00Z",
    },
    {
      id: "fp:sa-read-pods",
      status: "ACCEPTED",
      title: "service account can read pods in webapps",
      route: "IDENTITY_ASSUME › PERMISSION_DISCOVER",
      target: "get pods @ webapps",
      note: "namespaced read-only grant",
      first_seen: "2026-10-16T09:00:00Z",
      last_seen: "2026-10-16T09:00:00Z",
    },
  ],
};

// no tenant given -> first tenant; unknown tenant -> null (caller answers 404)
const resolve = (name) => TENANTS.find((t) => t.tenant === name) ?? (name ? null : TENANTS[0]);

const askEvents = (question = "", tenant) => {
  const t = resolve(tenant) ?? TENANTS[0];
  const reply = t.replies.find((r) => r.match.test(question)) ?? t.replies[t.replies.length - 1];
  const steps = reply.path
    ? ((j(t.paths).paths ?? []).find((p) => p.id === reply.path)?.steps ?? [])
    : [];
  const events = [];
  if (steps.length) {
    const last = steps[steps.length - 1];
    events.push({
      type: "tool",
      name: "paths_to",
      args: { source: steps[0].from, target: reply.target ?? last.to, max_hops: steps.length + 1 },
    });
  }
  events.push(...chunks(reply.answer).map((text) => ({ type: "token", text: `${text} ` })));
  if (steps.length) events.push({ type: "path", steps });
  const finding = reply.finding ? FINDINGS[t.tenant]?.find((f) => f.id === reply.finding) : null;
  events.push({
    type: "final",
    answer: reply.answer,
    citations: steps.length ? [steps[0].from, ...steps.map((s) => s.to)] : [],
    ...(finding ? { status: finding.status, finding } : {}),
  });
  return events;
};

// label + rel-type counts, shaped like backend `_counts`, so /stats agrees with /graph
const counts = (g) => {
  const out = { Entity: g.nodes.length };
  for (const n of g.nodes) out[n.kind] = (out[n.kind] ?? 0) + 1;
  for (const e of g.edges) out[e.type] = (out[e.type] ?? 0) + 1;
  return out;
};

// mock state; POST /ingest replaces the counts of the tenant it uploaded into
const statsByTenant = Object.fromEntries(TENANTS.map((t) => [t.tenant, counts(j(t.graph))]));

createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type",
      "cache-control": "no-store",
    });
    return res.end();
  }
  const want = url.searchParams.get("tenant");
  if (url.pathname === "/health") return send(res, 200, {status:"ok",falkordb:"connected",graph:`rung:${TENANTS[0].tenant}`});
  if (url.pathname === "/tenants") return send(res, 200, TENANTS.map((t) => ({tenant:t.tenant, counts:statsByTenant[t.tenant]})));
  if (url.pathname === "/stats")  { const t = resolve(want); return t ? send(res, 200, statsByTenant[t.tenant]) : send(res, 404, {detail:`unknown tenant: ${want}`}); }
  if (url.pathname === "/graph")  { const t = resolve(want); return t ? send(res, 200, j(t.graph)) : send(res, 404, {detail:`unknown tenant: ${want}`}); }
  if (url.pathname === "/paths")  {
    const t = resolve(want);
    if (!t) return send(res, 404, {detail:`unknown tenant: ${want}`});
    const paths = j(t.paths).paths ?? [];
    const source = url.searchParams.get("source");
    return send(res, 200, {paths: source ? paths.filter((p) => p.steps?.[0]?.from === source) : paths});
  }
  if (url.pathname === "/findings") {
    const t = resolve(want);
    if (!t) return send(res, 404, {detail:`unknown tenant: ${want}`});
    return send(res, 200, {findings: FINDINGS[t.tenant] ?? []});
  }
  if (url.pathname === "/ingest" && req.method === "POST") {
    const t = resolve(want);
    if (!t) return send(res, 404, {detail:`unknown tenant: ${want}`});
    const raw = filePart(await readBody(req), req.headers["content-type"]);
    if (raw === null) return send(res, 400, {detail:"expected multipart/form-data with a file field"});
    let snapshot;
    try { snapshot = JSON.parse(raw); }
    catch (e) { return send(res, 400, {detail:`invalid JSON: ${e.message}`}); }
    // entity counts: top-level collections of the uploaded snapshot (backend returns label counts)
    const c = Object.fromEntries(
      Object.entries(snapshot)
        .filter(([, v]) => Array.isArray(v))
        .map(([k, v]) => [k, v.length]),
    );
    if (!Object.keys(c).length) return send(res, 400, {detail:"snapshot has no entity collections"});
    statsByTenant[t.tenant] = c;
    return send(res, 200, {status:"ingested", counts:c});
  }
  if (url.pathname === "/ask") {   // stream SSE: question-aware events, or the fixture
    let question = "";
    let tenant = want;
    if (req.method === "POST") {
      try { const b = JSON.parse((await readBody(req)).toString("utf8")); question = b.question ?? ""; tenant = b.tenant ?? tenant; }
      catch { question = ""; }
    }
    const t = resolve(tenant);
    if (!t) return send(res, 404, {detail:`unknown tenant: ${tenant}`});
    res.writeHead(200, {"content-type":"text/event-stream","access-control-allow-origin":"*","cache-control":"no-store"});
    const events = askEvents(question, t.tenant);
    const lines = events.length
      ? events.map((e) => `data: ${JSON.stringify(e)}`)
      : readFileSync(new URL("./ask.sse", import.meta.url), "utf8").split("\n").filter((l) => l.trim());
    let i = 0; const timer = setInterval(() => { if (i >= lines.length) { clearInterval(timer); return res.end(); } res.write(lines[i++] + "\n"); }, 120);
    return;
  }
  send(res, 404, {error:"not found"});
}).listen(8000, () => console.log("mock on :8000"));
