# Stream C — Frontend & Demo  (for the new teammate)

You own the part judges actually look at: **showing the attack path**, in a chat + graph UI. The
brief says "show the path behind an answer" three times — that's this screen. You can start **now**;
nothing you do blocks on the backend, because you mock it first.

Everyone commits under their own name, on a branch `feat/frontend-*`, PR into `main`.

---

## 0. Get running (15 min)

```bash
git clone <repo> && cd rung/frontend
npm install
npm run dev            # http://localhost:3000
```

The app is Next.js (App Router) + React + Tailwind. `src/app/page.tsx` currently shows health /
stats / a snapshot uploader against a backend at `http://localhost:8000`. **Keep the uploader**,
but you'll move it into a small sidebar — the main stage becomes chat + graph.

You do **not** need the backend running to start. Run the mock in §2.

---

## 1. Target layout

```
┌───────────────────────────────────────────────────────────────┐
│  Rung            tenant: [kind-graphhacks ▾]      ● falkordb ok │
├───────────────────────┬───────────────────────────────────────┤
│  CHAT (left, ~380px)  │  GRAPH (right, fills)                   │
│                       │                                         │
│  ▸ "ci-runner is      │     ┌──────┐  CE_MODULE_LOAD  ┌──────┐  │
│     compromised,      │     │ pod  │ ───────────────▶ │ node │  │
│     what can it       │     └──────┘                  └──────┘  │
│     reach?"           │         path is highlighted in accent,  │
│                       │         rest of graph dimmed            │
│  ▸ agent answer,      │                                         │
│     streaming, with   │  click a node/edge → side detail:       │
│     the chain cited   │  "why this edge exists" + confidence    │
│                       │                                         │
│  [ask…]          send │  badges: NEW · RESOLVED · REGRESSED      │
└───────────────────────┴───────────────────────────────────────┘
```

---

## 2. Mock the backend so you're never blocked

Create `frontend/mock/` with static responses and a 25-line server. Run it on :8000; point the app
at it with `NEXT_PUBLIC_API_URL=http://localhost:8000`.

`frontend/mock/server.mjs`:
```js
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
const j = (f) => JSON.parse(readFileSync(new URL(`./${f}`, import.meta.url)));
const send = (res, code, body, type="application/json") => {
  res.writeHead(code, { "content-type": type, "access-control-allow-origin": "*" });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
};
createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/health") return send(res, 200, {status:"ok",falkordb:"connected",graph:"rung:kind-graphhacks"});
  if (url.pathname === "/tenants") return send(res, 200, [{tenant:"kind-graphhacks",counts:{Pod:16}}]);
  if (url.pathname === "/graph")  return send(res, 200, j("graph.json"));
  if (url.pathname === "/paths")  return send(res, 200, j("paths.json"));
  if (url.pathname === "/ask") {   // stream the SSE fixture line by line
    res.writeHead(200, {"content-type":"text/event-stream","access-control-allow-origin":"*"});
    const lines = readFileSync(new URL("./ask.sse", import.meta.url),"utf8").split("\n");
    let i=0; const t=setInterval(()=>{ if(i>=lines.length){clearInterval(t);return res.end();} res.write(lines[i++]+"\n"); }, 120);
    return;
  }
  send(res, 404, {error:"not found"});
}).listen(8000, () => console.log("mock on :8000"));
```
Build `graph.json` and `paths.json` from `dataset/sample-attack-chain.json` (shapes are in the
contract, §5 of `TEAM_PLAN.md`). `ask.sse` is a few lines like:
```
data: {"type":"tool","name":"paths_to","args":{"target":"cluster"}}
data: {"type":"token","text":"The CI runner reaches cluster-admin in four hops. "}
data: {"type":"path","steps":[{"from":"pod/jenkins/ci-runner","edge":"CE_MODULE_LOAD","to":"node/x","why":"privileged implies CAP_SYS_MODULE","confidence":"high"}]}
data: {"type":"final","answer":"...","citations":["pod/jenkins/ci-runner"]}
```
When the real backend ships an endpoint, just stop using that mock route — no code change in the app.

---

## 3. Tasks, in order, each with a "done when"

**C1 — Graph pane with Cytoscape.** `npm i cytoscape`. Build `components/GraphView.tsx` as a client
component (`"use client"`), `dynamic(() => import(...), { ssr:false })` to avoid SSR errors. Fetch
`/graph?tenant=`, render nodes colored by `kind` (Pod/Container/Identity/PermSet/Node/Volume/Cluster),
edges labeled by `type`. Starter styling is in the old scaffold at `backend/web/index.html` — reuse
the color map and the `breadthfirst` layout.
*Done when:* the sample graph renders, nodes are colored by kind, you can pan/zoom.

**C2 — Chat + SSE.** `components/Chat.tsx`. POST `/ask {question, tenant}`, read the SSE stream:
```ts
const res = await fetch(`${API}/ask`, {method:"POST", headers:{"content-type":"application/json"},
  body: JSON.stringify({question, tenant})});
const reader = res.body!.getReader(); const dec = new TextDecoder(); let buf="";
for (;;) { const {done,value} = await reader.read(); if (done) break;
  buf += dec.decode(value,{stream:true}); const parts = buf.split("\n"); buf = parts.pop()!;
  for (const line of parts) { if (!line.startsWith("data:")) continue;
    const ev = JSON.parse(line.slice(5).trim());
    if (ev.type==="token") appendText(ev.text);
    if (ev.type==="path")  onPath(ev.steps);     // hand to GraphView to highlight
    if (ev.type==="final") finish(ev);
  } }
```
*Done when:* typing a question streams an answer token-by-token and emits a `path` event.

**C3 — Highlight the path.** When a `path` event arrives, dim the whole graph and highlight the
path's nodes+edges in the accent color, in order. Clicking a highlighted edge opens a side panel
showing `why` and `confidence`.
*Done when:* asking a question visibly lights up the chain on the graph, and edge clicks explain it.

**C4 — Tenant switcher + header.** Dropdown from `/tenants`; switching re-fetches `/graph` and
scopes `/ask`. Header shows FalkorDB health dot.
*Done when:* two tenants show different graphs for the same question.

**C5 — Regression badges.** When `/ask` or a findings call returns a `status`
(NEW / RESOLVED / ACCEPTED / REGRESSED), render it as a colored badge on the finding and, for
REGRESSED, a short banner. (Backend ships this on the 17th; stub it from `ask.sse` until then.)
*Done when:* a REGRESSED finding is visually unmistakable — this is the money shot of the demo.

**C6 — Demo + docs (18th).** Own the README's "run it in 3 commands" section, record the demo video
(< 3 min, start on a popped pod, end on the one-line fix), and draft the blog post (side prize).

---

## 4. Rules
- Don't invent graph semantics — render what `/graph` and `path` events give you. Edge **labels and
  colors must match** what the backend sends (e.g. `CE_MODULE_LOAD` is a real escape; `SCHEDULED_ON`
  is non-walkable and should render muted/dashed, never as an attack step).
- Keep it working at phone width too (judges may open on a laptop at odd sizes).
- Ask in the team chat if a contract field is unclear — don't guess the shape.
