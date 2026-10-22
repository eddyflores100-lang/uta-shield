// uta-shield v0.2.0 — hardened proxy end-to-end tests (real HTTP).
// Covers the v0.1.0 audit gaps: body size limits, upstream timeouts,
// MCP method policy, safe error messages, identity enforcement e2e,
// outbound policy e2e, and rate-limit bypass attempts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Feed } from "../src/feed.mjs";
import { createShield } from "../src/shield.mjs";
import { createProxyHandler } from "../src/proxy.mjs";
import { signBody, bodyDigest } from "../src/identity.mjs";

const feed = Feed.fromFile(join(dirname(fileURLToPath(import.meta.url)), "..", "feed", "iocs.json"));
const KEYS = { "helper-bot": "demo-secret-1", "hammer-bot": "demo-secret-2" };

function listen(server) {
  return new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
}
function portOf(server) { return server.address().port; }
async function closeServer(server) {
  server.closeAllConnections?.();
  await new Promise(r => server.close(r));
}

// ── fake upstream MCP server (the operator's real server, unshielded) ──
function mkUpstream({ hangTool = null } = {}) {
  return createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    let body = {};
    try { body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { /* ignore */ }
    if (hangTool && body?.params?.name === hangTool) return; // never respond → timeout path
    if (body.method === "tools/call" && body.params?.name === "dirty_lookup") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({
        jsonrpc: "2.0", id: body.id,
        result: { content: [{ type: "text", text: "resolved host: api.gaganata.ink (status: live)" }] }
      }));
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id ?? null, result: { ok: true, served: body.method || "?" } }));
  });
}

function signedFetch(url, rawBody, { agent = "helper-bot", secret = KEYS["helper-bot"], ts = Date.now(), extraHeaders = {}, corrupt = false } = {}) {
  const headers = {
    "content-type": "application/json",
    ...extraHeaders
  };
  if (agent) {
    const bh = bodyDigest(rawBody);
    headers["x-agent-name"] = agent;
    headers["x-agent-timestamp"] = String(ts);
    headers["x-agent-signature"] = corrupt
      ? "deadbeef".repeat(8)
      : signBody(secret, agent, ts, bh);
  }
  return fetch(url, { method: "POST", headers, body: rawBody });
}

const rpc = (method, params, id = 1) => JSON.stringify({ jsonrpc: "2.0", id, method, ...(params ? { params } : {}) });

async function startStack({ shieldOpts = {}, proxyOpts = {}, upstreamOpts = {} } = {}) {
  const upstream = mkUpstream(upstreamOpts);
  await listen(upstream);
  const shield = createShield({ feed, ...shieldOpts });
  const server = createServer(createProxyHandler({
    shield,
    upstream: `http://127.0.0.1:${portOf(upstream)}`,
    ...proxyOpts
  }));
  await listen(server);
  const url = `http://127.0.0.1:${portOf(server)}`;
  return {
    url, shield,
    async stop() { await closeServer(server); await closeServer(upstream); }
  };
}

test("fail-closed: keys configured + requireIdentity → unsigned request gets 401", async () => {
  const stack = await startStack({ shieldOpts: { requireIdentity: true, identity: { keys: KEYS } } });
  try {
    const r = await signedFetch(stack.url, rpc("initialize", {}), { agent: null });
    assert.equal(r.status, 401);
    const b = await r.json();
    assert.equal(b.error.code, -32001);
  } finally { await stack.stop(); }
});

test("HMAC end-to-end: signed request → ALLOW_VERIFIED → 200", async () => {
  const stack = await startStack({ shieldOpts: { identity: { keys: KEYS } } });
  try {
    const body = rpc("initialize", {});
    const r = await signedFetch(stack.url, body);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("x-uta-shield"), "OUT_OK");
    const b = await r.json();
    assert.equal(b.result.ok, true);
  } finally { await stack.stop(); }
});

test("identity spoofing e2e: corrupted signature → 401 REJECT_AUTH, upstream never called", async () => {
  const stack = await startStack({ shieldOpts: { identity: { keys: KEYS } } });
  try {
    const r = await signedFetch(stack.url, rpc("tools/list", null, 9), { corrupt: true });
    assert.equal(r.status, 401);
    const b = await r.json();
    assert.equal(b.error.code, -32001);
    assert.match(b.error.message, /signature/i);
  } finally { await stack.stop(); }
});

test("declared-name rotation e2e: rotating x-agent-name from one IP still rate-limits", async () => {
  const stack = await startStack({
    shieldOpts: { identity: { keys: KEYS }, ratelimit: { ratePerMin: 1, burst: 3, ipRatePerMin: 1, ipBurst: 3 } },
    proxyOpts: {}
  });
  try {
    let got429 = false;
    for (let i = 0; i < 5; i++) {
      const r = await signedFetch(stack.url, rpc("tools/list", null, 20 + i), { agent: null, extraHeaders: { "x-agent-name": `rot-${i}` } });
      if (r.status === 429) { got429 = true; break; }
      await r.arrayBuffer();
    }
    assert.equal(got429, true, "IP bucket must apply regardless of declared name");
  } finally { await stack.stop(); }
});

test("method policy: non-allowed MCP method → 403 METHOD_DENIED", async () => {
  const stack = await startStack({ shieldOpts: { identity: { keys: KEYS } } });
  try {
    const r = await signedFetch(stack.url, rpc("resources/list", null, 2));
    assert.equal(r.status, 403);
    assert.equal(r.headers.get("x-uta-shield"), "METHOD_DENIED");
    const b = await r.json();
    assert.equal(b.error.code, -32601);
    assert.match(b.error.message, /not permitted by uta-shield policy/);
  } finally { await stack.stop(); }
});

test("body size limit: oversized request → 413, upstream never called", async () => {
  const stack = await startStack({
    shieldOpts: { identity: { keys: KEYS } },
    proxyOpts: { limits: { maxBodyBytes: 200 } }
  });
  try {
    const big = JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list", params: { pad: "x".repeat(500) } });
    const r = await signedFetch(stack.url, big);
    assert.equal(r.status, 413);
    assert.equal(r.headers.get("x-uta-shield"), "BODY_TOO_LARGE");
    const b = await r.json();
    assert.equal(b.error.code, -32008);
  } finally { await stack.stop(); }
});

test("upstream timeout: hanging server → 504 with fixed message (no internals leaked)", async () => {
  const stack = await startStack({
    shieldOpts: { identity: { keys: KEYS } },
    proxyOpts: { limits: { upstreamTimeoutMs: 150 } },
    upstreamOpts: { hangTool: "hang_tool" }
  });
  try {
    const r = await signedFetch(stack.url, rpc("tools/call", { name: "hang_tool", arguments: {} }, 4));
    assert.equal(r.status, 504);
    const b = await r.json();
    assert.equal(b.error.message, "upstream timeout after 150ms");
  } finally { await stack.stop(); }
});

test("upstream unreachable → 502 with fixed message; no error details leaked", async () => {
  const dead = mkUpstream();
  await listen(dead);
  const deadPort = portOf(dead);
  await closeServer(dead); // grab a port, then free it

  const shield = createShield({ feed, identity: { keys: KEYS } });
  const server = createServer(createProxyHandler({ shield, upstream: `http://127.0.0.1:${deadPort}` }));
  await listen(server);
  try {
    const url = `http://127.0.0.1:${portOf(server)}`;
    const r = await signedFetch(url, rpc("tools/list", null, 5));
    assert.equal(r.status, 502);
    const b = await r.json();
    assert.equal(b.error.message, "upstream unreachable");
    assert.ok(!/ECONNREFUSED|Error:/i.test(JSON.stringify(b)), "raw error internals must not leak");
    assert.ok(shield.audit.last(1)[0].verdict === "UPSTREAM_ERROR", "detail goes to audit, not the client");
  } finally { await closeServer(server); }
});

test("BLOCK_INTEL e2e: hostile URL in tool arguments → 403 with campaign evidence", async () => {
  const stack = await startStack({ shieldOpts: { identity: { keys: KEYS } } });
  try {
    const body = rpc("tools/call", { name: "send_email", arguments: { to: "dev@example.com", body: "verify at https://taikotalent.xyz/verify_m" } }, 6);
    const r = await signedFetch(stack.url, body);
    assert.equal(r.status, 403);
    const b = await r.json();
    assert.equal(b.error.data.verdict, "BLOCK_INTEL");
    assert.ok(b.error.data.hits.some(h => h.campaign === "taikotalent-2026-10"));
  } finally { await stack.stop(); }
});

test("outbound redact e2e: upstream response carrying a C2 domain comes back redacted", async () => {
  const stack = await startStack({ shieldOpts: { identity: { keys: KEYS } } }); // default policy: redact
  try {
    const r = await signedFetch(stack.url, rpc("tools/call", { name: "dirty_lookup", arguments: {} }, 7));
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("x-uta-shield"), "OUT_REDACTED");
    const text = await r.text();
    assert.ok(!text.includes("gaganata.ink"), "C2 must not reach the client");
    assert.ok(text.includes("[IOC_REDACTED:taikotalent-2026-10/"));
  } finally { await stack.stop(); }
});

test("outbound block e2e: policy=block withholds dirty responses → 403 OUT_BLOCKED", async () => {
  const stack = await startStack({ shieldOpts: { identity: { keys: KEYS }, outboundPolicy: "block" } });
  try {
    const r = await signedFetch(stack.url, rpc("tools/call", { name: "dirty_lookup", arguments: {} }, 8));
    assert.equal(r.status, 403);
    assert.equal(r.headers.get("x-uta-shield"), "OUT_BLOCKED");
    const b = await r.json();
    assert.equal(b.error.code, -32006);
    // the upstream response CONTENT is withheld; the IOC value itself may appear
    // as SIEM-standard evidence (public feed), never the surrounding content
    assert.ok(!JSON.stringify(b).includes("resolved host"), "upstream content must be withheld");
    assert.ok(!JSON.stringify(b).includes("status: live"), "upstream content must be withheld");
    assert.ok(b.error.data.hits.some(h => h.campaign === "taikotalent-2026-10"), "campaign evidence present");
  } finally { await stack.stop(); }
});

test("verified agent rate limit e2e: burst exceeded → 429 with retry-after", async () => {
  const stack = await startStack({
    shieldOpts: { identity: { keys: KEYS }, ratelimit: { ratePerMin: 1, burst: 3 } }
  });
  try {
    let got429 = null;
    for (let i = 0; i < 6 && !got429; i++) {
      const r = await signedFetch(stack.url, rpc("tools/list", null, 30 + i));
      if (r.status === 429) got429 = r;
      else await r.arrayBuffer();
    }
    assert.ok(got429, "expected a 429 within 6 calls");
    assert.ok(got429.headers.get("retry-after") !== null);
    assert.equal(got429.headers.get("x-uta-shield"), "RATE_LIMITED");
  } finally { await stack.stop(); }
});

test("health endpoint discloses the actual security posture", async () => {
  const stack = await startStack({
    shieldOpts: { identity: { keys: KEYS }, outboundPolicy: "block" },
    proxyOpts: { limits: { maxBodyBytes: 4096, upstreamTimeoutMs: 1234 } }
  });
  try {
    const r = await fetch(stack.url + "/health");
    assert.equal(r.status, 200);
    const h = await r.json();
    assert.equal(h.version, "0.2.0");
    assert.equal(h.outbound_policy, "block");
    assert.equal(h.identity.mode, "hmac-verified");
    assert.equal(h.proxy.max_body_bytes, 4096);
    assert.equal(h.proxy.upstream_timeout_ms, 1234);
    assert.ok(Array.isArray(h.proxy.methods_allowed));
  } finally { await stack.stop(); }
});
