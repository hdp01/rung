#!/usr/bin/env node
/**
 * Contract conformance check — does an API match the locked frontend contract?
 *
 *   node scripts/check-contract.mjs [baseUrl]     # default http://localhost:8000
 *   node scripts/check-contract.mjs --selftest    # prove the check catches drift
 *
 * The contract is `frontend/src/lib/types.ts` (shapes) over `TEAM_PLAN.md` §5 (endpoints). The app
 * calls the API directly, so a shape that drifts breaks the UI silently — a missing `label` renders
 * an empty node, a string where a number belongs renders a blank stat. This walks every call the app
 * makes, validates the response against the contract, and exits non-zero on any drift.
 *
 * Run it against the mock (`node mock/server.mjs`) to see what conformant looks like; run it against
 * the real backend as each endpoint lands:
 *
 *   node mock/server.mjs
 *   node scripts/check-contract.mjs http://localhost:8000
 *
 * Tenants are discovered from `/tenants`; the first one is used for the scoped calls.
 */
const DEFAULT_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const TIMEOUT_MS = 20000;
const QUESTION = "What can the compromised pod reach?";

// ---------------------------------------------------------------- shape spec
const STRING = "string";
const NUMBER = "number";
const ANY = "any";
/** `Record<string, number>` — the stats/tenant count map. */
const numberMap = { kind: "numberMap" };
const arr = (of) => ({ kind: "array", of });
const shape = (fields, optional = {}) => ({ kind: "object", fields, optional });

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const typeOf = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);

function validate(value, spec, path, errors) {
  if (spec === ANY) return;
  if (spec === STRING || spec === NUMBER) {
    const ok =
      spec === STRING ? typeof value === "string" : typeof value === "number" && Number.isFinite(value);
    if (!ok) errors.push(`${path}: expected ${spec}, got ${typeOf(value)}`);
    return;
  }
  if (spec.kind === "array") {
    if (!Array.isArray(value)) {
      errors.push(`${path}: expected array, got ${typeOf(value)}`);
      return;
    }
    value.forEach((v, i) => validate(v, spec.of, `${path}[${i}]`, errors));
    return;
  }
  if (spec.kind === "numberMap") {
    if (!isPlainObject(value)) {
      errors.push(`${path}: expected object, got ${typeOf(value)}`);
      return;
    }
    for (const [k, v] of Object.entries(value)) {
      if (typeof v !== "number") errors.push(`${path}.${k}: expected number, got ${typeOf(v)}`);
    }
    return;
  }
  if (spec.kind === "object") {
    if (!isPlainObject(value)) {
      errors.push(`${path}: expected object, got ${typeOf(value)}`);
      return;
    }
    for (const [k, sub] of Object.entries(spec.fields)) validate(value[k], sub, `${path}.${k}`, errors);
    for (const [k, sub] of Object.entries(spec.optional)) {
      if (value[k] !== undefined) validate(value[k], sub, `${path}.${k}`, errors);
    }
    return;
  }
  throw new Error(`bad spec at ${path}`);
}

// ------------------------------------------------------- the contract itself
const HEALTH = shape({ status: STRING, falkordb: STRING, graph: STRING });
const TENANT = shape({ tenant: STRING, counts: numberMap });
const GRAPH = shape({
  nodes: arr(shape({ id: STRING, label: STRING, kind: STRING }, { props: ANY })),
  edges: arr(shape({ source: STRING, target: STRING, type: STRING }, { attack_path: NUMBER })),
});
const PATH_STEP = shape({ from: STRING, edge: STRING, to: STRING }, { why: STRING, confidence: STRING });
const FINDING = shape(
  { status: STRING },
  {
    id: STRING,
    route: STRING,
    target: STRING,
    title: STRING,
    note: STRING,
    previous_status: STRING,
    first_seen: STRING,
    last_seen: STRING,
  },
);
const FINDINGS = shape({ findings: arr(FINDING) });
const COMPARE = shape({
  naive_reachable: NUMBER,
  rung_reachable: NUMBER,
  naive_token_list_edges: NUMBER,
  rung_token_list_edges: NUMBER,
});
const FINAL = shape({ answer: STRING }, { citations: arr(STRING), status: STRING, finding: FINDING });
const EVENT_TYPES = ["tool", "token", "path", "final"];

// ------------------------------------------------------------------ fetching
async function timedFetch(url, init = {}) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { cache: "no-store", ...init, signal: ac.signal });
    return { res, text: await res.text() };
  } finally {
    clearTimeout(timer);
  }
}

/** GET + validate one endpoint. Returns the report row and, when it parsed, the body. */
async function probeJson(base, { id, method = "GET", path, tenant, expect }) {
  const url = tenant === undefined ? base + path : `${base}${path}?tenant=${encodeURIComponent(tenant)}`;
  try {
    const { res, text } = await timedFetch(url, { method });
    if (res.status === 404) return { row: { id, method, path, status: "MISSING", detail: "404 — not implemented" } };
    if (!res.ok) {
      return { row: { id, method, path, status: "ERROR", detail: `${res.status} ${text.slice(0, 90)}` } };
    }
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      return { row: { id, method, path, status: "MISMATCH", detail: `not JSON: ${text.slice(0, 70)}` } };
    }
    const errors = [];
    validate(body, expect, "body", errors);
    return {
      row: {
        id,
        method,
        path,
        status: errors.length ? "MISMATCH" : "PASS",
        detail: errors.slice(0, 2).join(" | "),
      },
      body,
    };
  } catch (exc) {
    return { row: { id, method, path, status: "ERROR", detail: String(exc).slice(0, 90) } };
  }
}

/** POST /ask — the stream the chat pane depends on. */
async function checkAsk(base, tenant) {
  const id = "ask";
  const method = "POST";
  const path = "/ask";
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(base + path, {
      method,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ question: QUESTION, tenant }),
      cache: "no-store",
      signal: ac.signal,
    });
    if (res.status === 404) return { id, method, path, status: "MISSING", detail: "404 — not implemented" };
    if (!res.ok) return { id, method, path, status: "ERROR", detail: `${res.status}` };
    const ctype = res.headers.get("content-type") || "";
    if (!ctype.includes("text/event-stream")) {
      return { id, method, path, status: "MISMATCH", detail: `content-type "${ctype}", expected text/event-stream` };
    }

    // Read until `final` (or the cap) — an SSE route may stay open after the turn ends.
    const events = [];
    let buf = "";
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.startsWith("data:")) continue;
        const raw = line.slice(5).trim();
        if (!raw) continue;
        try {
          events.push(JSON.parse(raw));
        } catch {
          events.push({ type: "__unparseable__", raw: raw.slice(0, 50) });
        }
      }
      if (events.some((e) => e.type === "final")) {
        await reader.cancel().catch(() => {});
        break;
      }
    }

    const errors = [];
    for (const ev of events) {
      if (!EVENT_TYPES.includes(ev.type)) {
        errors.push(`unknown event type "${ev.type}" (contract §5 lists ${EVENT_TYPES.join("|")})`);
      }
    }
    const finals = events.filter((e) => e.type === "final");
    if (!events.some((e) => e.type === "token")) errors.push("no token event — the answer never streams");
    if (!finals.length) errors.push("no final event — the turn never ends");
    else validate(finals[0], FINAL, "final", errors);
    for (const ev of events.filter((e) => e.type === "path")) validate(ev.steps, arr(PATH_STEP), "path.steps", errors);

    const noPath = events.some((e) => e.type === "path") ? "" : " (no path event: nothing to highlight)";
    return {
      id,
      method,
      path,
      status: errors.length ? "MISMATCH" : "PASS",
      detail: errors.length ? errors.slice(0, 2).join(" | ") : `${events.length} events${noPath}`,
    };
  } catch (exc) {
    return { id, method, path, status: "ERROR", detail: String(exc).slice(0, 90) };
  } finally {
    clearTimeout(timer);
  }
}

/** POST /ingest — the uploader. An empty upload must fail validation, not be missing. */
async function checkIngest(base, tenant) {
  const id = "ingest";
  const method = "POST";
  const path = `/ingest?tenant=${encodeURIComponent(tenant)}`;
  try {
    const { res } = await timedFetch(base + path, {
      method,
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    if (res.status === 404) return { id, method, path, status: "MISSING", detail: "404 — not implemented" };
    if (res.status === 405) return { id, method, path, status: "MISSING", detail: "405 — not a POST route" };
    return { id, method, path, status: "PASS", detail: `${res.status} on an empty upload — route exists` };
  } catch (exc) {
    return { id, method, path, status: "ERROR", detail: String(exc).slice(0, 90) };
  }
}

// ----------------------------------------------------------------- the run
async function runChecks(base) {
  const rows = [];

  rows.push((await probeJson(base, { id: "health", path: "/health", expect: HEALTH })).row);

  const tenants = await probeJson(base, { id: "tenants", path: "/tenants", expect: arr(TENANT) });
  rows.push(tenants.row);
  const tenant = Array.isArray(tenants.body) ? tenants.body[0]?.tenant : undefined;
  if (!tenant) {
    rows.push({
      id: "scoped",
      method: "-",
      path: "-",
      status: "MISSING",
      detail: "no tenant to test with — the dropdown would be empty and every scoped call 404s",
    });
    return rows;
  }
  rows.push({ id: "tenant", method: "GET", path: "/tenants", status: "PASS", detail: `using "${tenant}" below` });

  for (const spec of [
    { id: "stats", path: "/stats", expect: numberMap },
    { id: "graph", path: "/graph", expect: GRAPH },
    { id: "findings", path: "/findings", expect: FINDINGS },
    { id: "compare", path: "/compare", expect: COMPARE },
  ]) {
    rows.push((await probeJson(base, { ...spec, tenant })).row);
  }

  rows.push(await checkAsk(base, tenant));
  rows.push(await checkIngest(base, tenant));
  return rows;
}

function report(base, rows) {
  const pad = Math.max(...rows.map((r) => `${r.method} ${r.path}`.length));
  console.log(`\nRung contract check — ${base}`);
  console.log("contract: frontend/src/lib/types.ts + TEAM_PLAN.md §5\n");
  for (const r of rows) {
    const mark = { PASS: "PASS    ", MISSING: "MISSING ", MISMATCH: "MISMATCH", ERROR: "ERROR   " }[r.status];
    console.log(`  ${mark} ${`${r.method} ${r.path}`.padEnd(pad)}  ${r.detail}`);
  }
  const tally = rows.reduce((acc, r) => ({ ...acc, [r.status]: (acc[r.status] ?? 0) + 1 }), {});
  const failed = rows.filter((r) => r.status !== "PASS").length;
  console.log(
    `\n  ${rows.length} checks · ${tally.PASS ?? 0} pass · ${tally.MISSING ?? 0} missing · ` +
      `${tally.MISMATCH ?? 0} mismatch · ${tally.ERROR ?? 0} error`,
  );
  console.log(failed ? `  NOT CONFORMANT — ${failed} to fix\n` : "  CONFORMANT\n");
  return failed ? 1 : 0;
}

/**
 * A deliberately non-conformant server: /health has a number where a string belongs, /tenants has no
 * counts, /graph and the rest are absent. Proves the check above reports drift instead of passing
 * everything.
 */
async function selftest() {
  const { createServer } = await import("node:http");
  const broken = {
    "/health": { status: "ok", falkordb: 42, graph: "rung:kind-graphhacks" },
    "/tenants": [{ tenant: "kind-graphhacks" }],
    "/stats": { Pod: 3 },
  };
  const server = createServer((req, res) => {
    const body = broken[new URL(req.url, "http://x").pathname];
    if (!body) {
      res.writeHead(404, { "content-type": "application/json" });
      return res.end('{"detail":"not found"}');
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  const rows = await runChecks(base);
  await new Promise((r) => server.close(r));

  const expectations = [
    { id: "health", want: "MISMATCH", why: "a number where the contract says string" },
    { id: "tenants", want: "MISMATCH", why: "the tenant has no counts" },
    { id: "stats", want: "PASS", why: "a valid endpoint must not be flagged" },
    { id: "graph", want: "MISSING", why: "absent" },
    { id: "compare", want: "MISSING", why: "absent" },
    { id: "ask", want: "MISSING", why: "absent" },
    { id: "ingest", want: "MISSING", why: "absent" },
  ];

  console.log("\nselftest — a broken API must not pass:");
  let wrong = 0;
  for (const { id, want, why } of expectations) {
    const got = rows.find((r) => r.id === id)?.status;
    const ok = got === want;
    if (!ok) wrong += 1;
    console.log(`  ${ok ? "ok  " : "BAD "} ${id}: expected ${want}, got ${got}${why ? `  (${why})` : ""}`);
  }
  console.log(wrong ? `\nselftest FAILED — ${wrong} check(s) misclassified\n` : "\nselftest passed\n");
  return wrong ? 1 : 0;
}

const arg = process.argv[2];
if (arg === "--selftest") process.exit(await selftest());

// The base URL: an explicit argument wins, then NEXT_PUBLIC_API_URL (what the app itself uses).
const base = (arg || DEFAULT_BASE).replace(/\/$/, "");
process.exit(report(base, await runChecks(base)));
