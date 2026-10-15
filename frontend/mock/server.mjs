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
  if (url.pathname === "/ask") {   // stream the SSE fixture line by line
    res.writeHead(200, {"content-type":"text/event-stream","access-control-allow-origin":"*"});
    const lines = readFileSync(new URL("./ask.sse", import.meta.url),"utf8").split("\n");
    let i=0; const t=setInterval(()=>{ if(i>=lines.length){clearInterval(t);return res.end();} res.write(lines[i++]+"\n"); }, 120);
    return;
  }
  send(res, 404, {error:"not found"});
}).listen(8000, () => console.log("mock on :8000"));
