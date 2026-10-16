import { createServer } from "node:http";
import { readFileSync } from "node:fs";
const j = (f) => JSON.parse(readFileSync(new URL(`./${f}`, import.meta.url)));
const send = (res, code, body, type="application/json") => {
  res.writeHead(code, { "content-type": type, "access-control-allow-origin": "*" });
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
    answer:
      "The hostroot volume is hostPath /, a parent of /var/lib/kubelet/pods, so the mount reads every service-account token on the node. From the jenkins identity that is two more hops to cluster-admin.",
  },
  {
    match: /(container|escape|privileged|hostpid|kernel|module|node|control[ -]?plane)/i,
    path: "container-to-node",
    answer:
      "The container is privileged, so it loads kernel modules and reaches the node directly — no RBAC needed for that hop. The pod also sets hostPID, so nsenter is available; the runtime hardening is what stops it.",
  },
  {
    match: /(pod|jenkins|reach|compromised|admin)/i,
    path: "pod-to-cluster",
    answer:
      "The jenkins pod does not need an RBAC detour to reach cluster-admin. Its service account is bound straight to cluster-admin, so anyone who lands on pwn-pod is cluster-admin in three hops. That is the finding: the pod is the entry point, the binding is the fix.",
  },
];

const askEvents = (question = "") => {
  const reply = REPLIES.find((r) => r.match.test(question)) ?? REPLIES[REPLIES.length - 1];
  const path = (j("paths.json").paths ?? []).find((p) => p.id === reply.path);
  if (!path?.steps?.length) return null;
  const first = path.steps[0];
  const last = path.steps[path.steps.length - 1];
  const citations = [first.from, ...path.steps.map((s) => s.to)];
  return [
    { type: "tool", name: "paths_to", args: { source: first.from, target: last.to, max_hops: path.steps.length + 1 } },
    ...chunks(reply.answer).map((text) => ({ type: "token", text: `${text} ` })),
    { type: "path", steps: path.steps },
    { type: "final", answer: reply.answer, citations },
  ];
};

// mock graph state; /stats reads it, POST /ingest replaces it
let stats = { Pod: 16 };

createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type",
    });
    return res.end();
  }
  if (url.pathname === "/health") return send(res, 200, {status:"ok",falkordb:"connected",graph:"rung:kind-graphhacks"});
  if (url.pathname === "/tenants") return send(res, 200, [{tenant:"kind-graphhacks",counts:{Pod:16}}]);
  if (url.pathname === "/stats")  return send(res, 200, stats);
  if (url.pathname === "/graph")  return send(res, 200, j("graph.json"));
  if (url.pathname === "/paths")  return send(res, 200, j("paths.json"));
  if (url.pathname === "/ingest" && req.method === "POST") {
    const raw = filePart(await readBody(req), req.headers["content-type"]);
    if (raw === null) return send(res, 400, {detail:"expected multipart/form-data with a file field"});
    let snapshot;
    try { snapshot = JSON.parse(raw); }
    catch (e) { return send(res, 400, {detail:`invalid JSON: ${e.message}`}); }
    // entity counts: top-level collections of the uploaded snapshot (backend returns label counts)
    const counts = Object.fromEntries(
      Object.entries(snapshot)
        .filter(([, v]) => Array.isArray(v))
        .map(([k, v]) => [k, v.length]),
    );
    if (!Object.keys(counts).length) return send(res, 400, {detail:"snapshot has no entity collections"});
    stats = counts;
    return send(res, 200, {status:"ingested", counts});
  }
  if (url.pathname === "/ask") {   // stream SSE: question-aware events, or the fixture
    res.writeHead(200, {"content-type":"text/event-stream","access-control-allow-origin":"*"});
    let question = "";
    if (req.method === "POST") {
      try { question = JSON.parse((await readBody(req)).toString("utf8")).question ?? ""; }
      catch { question = ""; }
    }
    const events = askEvents(question);
    const lines = events
      ? events.map((e) => `data: ${JSON.stringify(e)}`)
      : readFileSync(new URL("./ask.sse", import.meta.url), "utf8").split("\n").filter((l) => l.trim());
    let i = 0; const t = setInterval(() => { if (i >= lines.length) { clearInterval(t); return res.end(); } res.write(lines[i++] + "\n"); }, 120);
    return;
  }
  send(res, 404, {error:"not found"});
}).listen(8000, () => console.log("mock on :8000"));
