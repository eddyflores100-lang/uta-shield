#!/usr/bin/env node
// UTA Shield — end-to-end demo.
// Starts a fake "Apollo-style" contacts MCP server (sensitive data, no auth),
// wraps it with `uta-shield wrap`, then fires scripted agent traffic so you can
// SEE every verdict: ALLOW, OUT_MASKED, BLOCK_INTEL, RATE_LIMITED, REJECT_ANON.
//
// Run: node demo/run-demo.mjs

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createServer } from "node:http";

const __dirname = dirname(fileURLToPath(import.meta.url));
const UP_PORT = 3011, SHIELD_PORT = 8791;
const UP = `http://localhost:${UP_PORT}`;
const SH = `http://localhost:${SHIELD_PORT}`;
const j = JSON.stringify;

// ── 1. Fake sensitive MCP server (what an unshielded operator runs today) ──
const CONTACTS = [
  { name: "Jane Doe", title: "VP Eng", email: "jane.doe@bigcorp.com" },
  { name: "Raul Ruiz", title: "CTO", email: "raul@startup.io" }
];
const upstream = createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  if (body.method === "initialize")
    return res.end(j({ jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "contacts-mcp", version: "1.0.0" } } }));
  if (body.method === "tools/call" && body.params?.name === "search_contacts")
    return res.end(j({ jsonrpc: "2.0", id: body.id, result: { content: [{ type: "json", json: { contacts: CONTACTS } }] } }));
  if (body.method === "tools/call" && body.params?.name === "send_email")
    return res.end(j({ jsonrpc: "2.0", id: body.id, result: { content: [{ type: "text", text: `queued: ${body.params.arguments?.subject || ""}` }] } }));
  res.end(j({ jsonrpc: "2.0", id: body.id ?? null, error: { code: -32601, message: "not found" } }));
});
await new Promise(r => upstream.listen(UP_PORT, r));

// ── 2. The shield in front of it (the real CLI path) ──
const shield = spawn(process.execPath, [
  join(__dirname, "..", "bin", "cli.mjs"), "wrap",
  "--upstream", UP, "--port", String(SHIELD_PORT)
], { stdio: ["ignore", "pipe", "pipe"] });
await new Promise((res, rej) => {
  shield.stderr.on("data", d => { if (String(d).includes("wrapping")) res(); });
  shield.on("exit", () => rej(new Error("shield exited early")));
  setTimeout(res, 1500);
});
const post = (path, body, headers = {}) =>
  fetch(SH + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: j(body) });
const rpc = (method, params, id) => ({ jsonrpc: "2.0", id: id ?? 1, method, ...(params ? { params } : {}) });
const line = (s = "") => console.log(s);
const step = (n, title) => line(`\n[${n}] ${title}`);

line("╔══════════════════════════════════════════════════════════════╗");
line("║  UTA SHIELD — provider-side firewall for MCP servers (demo)  ║");
line("╚══════════════════════════════════════════════════════════════╝");
line(`upstream (unprotected): ${UP}   |   shielded proxy: ${SH}`);

step(1, "GET /health — what the operator sees");
const health = await (await fetch(SH + "/health")).json();
line(`  shield ${health.name} v${health.version} · feed ${health.feed.version} · ${health.feed.iocs_total} IOCs · ${health.feed.campaigns} campaign(s)`);

step(2, "Agent handshake (initialize) → ALLOW (forwarded to upstream)");
const init = await post("/", rpc("initialize", {}, 1));
line(`  HTTP ${init.status} · x-uta-shield: ${init.headers.get("x-uta-shield") || "OUT_OK"}`);

step(3, "Known agent calls search_contacts → ALLOW + outbound DLP masking");
const r3 = await post("/", rpc("tools/call", { name: "search_contacts", arguments: { q: "vp eng" } }, 2), { "x-agent-name": "recruiter-agent" });
const b3 = await r3.json();
const maskedText = b3?.result?.content?.[0]?.json ? j(b3.result.content[0].json) : j(b3);
line(`  HTTP ${r3.status} · response emails visible? ${maskedText.includes("@bigcorp.com") ? "YES (leak!)" : "NO → " + maskedText.match(/\[EMAIL_REDACTED\]/g)?.length + " field(s) masked"}`);

step(4, "Agent tries to send an email carrying a LIVE campaign URL → BLOCK_INTEL");
const r4 = await post("/", rpc("tools/call", {
  name: "send_email",
  arguments: { to: "dev@example.com", subject: "Job offer", body: "Congrats! Verify here: https://taikotalent.xyz/verify_m" }
}, 3), { "x-agent-name": "recruiter-agent" });
const b4 = await r4.json();
line(`  HTTP ${r4.status} · ${b4?.error?.message}`);
line(`  evidence: ${j(b4?.error?.data?.hits?.map(h => `${h.type}:${h.value} (${h.campaign})`) || [])}`);

step(5, "Same agent hammers the API → RATE_LIMITED (free tier)");
let got429 = null;
for (let i = 0; i < 40 && !got429; i++) {
  const r = await post("/", rpc("tools/call", { name: "search_contacts", arguments: { q: String(i) } }, 100 + i), { "x-agent-name": "recruiter-agent" });
  if (r.status === 429) got429 = { attempt: i + 1, retryAfter: r.headers.get("retry-after") };
}
line(`  429 after +${got429?.attempt ?? "?"} calls · retry-after: ${got429?.retryAfter ?? "?"}s`);

step(6, "Anonymous agent on a require-identity policy would get REJECT_ANON (run wrap with --require-identity)");
line("  (skipped here — covered by tests: test/shield.test.mjs)");

step(7, "Operator surfaces: /pricing (x402-ready) + /audit (last decisions)");
const pricing = await (await fetch(SH + "/pricing")).json();
line(`  pricing: ${j(pricing.prices)} · currency ${pricing.currency}`);
const audit = await (await fetch(SH + "/audit")).json();
line("  audit tail:");
for (const e of audit.slice(-4))
  line(`   · ${e.ts.slice(11, 19)} ${e.verdict.padEnd(14)} agent=${(e.agent || "-").padEnd(16)} tool=${e.tool || "-"}`);

line("\nWhat you just saw: the operator of an MCP server now knows WHO called, BLOCKED a");
line("known campaign payload, MASKED PII going out to an unverified agent, and can BILL per call.");
line("\nKill switch: Ctrl+C (demo cleans up upstream + shield).");
shield.kill("SIGTERM"); upstream.close();
process.exit(0);
