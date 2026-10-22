#!/usr/bin/env node
// UTA Shield — end-to-end demo (v0.2.0 hardened posture).
// Starts a fake "Apollo-style" contacts MCP server (sensitive data, no auth),
// wraps it with `uta-shield wrap` (HMAC keys + outbound policy), then fires
// signed and adversarial agent traffic so you can SEE every verdict:
// REJECT_ANON, ALLOW_VERIFIED, REJECT_AUTH, OUT_MASKED, OUT_REDACTED,
// BLOCK_INTEL, REJECT_FORBIDDEN, RATE_LIMITED.
//
// Run: node demo/run-demo.mjs

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { createHmac, createHash } from "node:crypto";
import { createServer } from "node:http";

const __dirname = dirname(fileURLToPath(import.meta.url));
const UP_PORT = 3011, SHIELD_PORT = 8791;
const UP = `http://localhost:${UP_PORT}`;
const SH = `http://localhost:${SHIELD_PORT}`;
const j = JSON.stringify;

// ── 0. throwaway agent credentials (operators: keep this file out of git) ──
const KEYS = { "recruiter-agent": "demo-secret-recruiter", "auditor-agent": "demo-secret-auditor" };
const keysDir = mkdtempSync(join(tmpdir(), "uta-shield-demo-"));
const keysFile = join(keysDir, "keys.json");
writeFileSync(keysFile, j(KEYS));
writeFileSync(join(keysDir, "acl.json"), j({ "auditor-agent": ["dirty_lookup"] })); // auditor: read-only

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
  if (body.method === "tools/call" && body.params?.name === "dirty_lookup")
    return res.end(j({ jsonrpc: "2.0", id: body.id, result: { content: [{ type: "text", text: `dns check: api.gaganata.ink → resolving (C2 of campaign taikotalent-2026-10)` }] } }));
  if (body.method === "tools/call" && body.params?.name === "send_email")
    return res.end(j({ jsonrpc: "2.0", id: body.id, result: { content: [{ type: "text", text: `queued: ${body.params.arguments?.subject || ""}` }] } }));
  res.end(j({ jsonrpc: "2.0", id: body.id ?? null, error: { code: -32601, message: "not found" } }));
});
await new Promise(r => upstream.listen(UP_PORT, r));

// ── 2. The shield in front of it (fail-closed, verified identity, redact policy) ──
const shield = spawn(process.execPath, [
  join(__dirname, "..", "bin", "cli.mjs"), "wrap",
  "--upstream", UP, "--port", String(SHIELD_PORT),
  "--keys-file", keysFile,
  "--acl-file", join(keysDir, "acl.json"),
  "--outbound-policy", "redact"
], { stdio: ["ignore", "pipe", "pipe"] });
await new Promise((res, rej) => {
  shield.stderr.on("data", d => { if (String(d).includes("wrapping")) res(); });
  shield.on("exit", c => rej(new Error(`shield exited early (${c})`)));
  setTimeout(res, 1500);
});

// signed request helper: signature = HMAC_SHA256(secret, agent|ts|sha256(body))
const sign = (agent, secret, rawBody) => {
  const ts = Date.now();
  return {
    "x-agent-name": agent,
    "x-agent-timestamp": String(ts),
    "x-agent-signature": createHmac("sha256", secret).update(`${agent}|${ts}|${createHash("sha256").update(rawBody).digest("hex")}`).digest("hex")
  };
};
const post = async (body, sig = null, corrupt = false) => {
  const raw = j(body);
  const headers = { "content-type": "application/json" };
  if (sig) {
    const s = sign(sig.agent, sig.secret, raw);
    if (corrupt) s["x-agent-signature"] = "f".repeat(64);
    Object.assign(headers, s);
  }
  return fetch(SH + "/", { method: "POST", headers, body: raw });
};
const rpc = (method, params, id) => ({ jsonrpc: "2.0", id: id ?? 1, method, ...(params ? { params } : {}) });
const RECRUITER = { agent: "recruiter-agent", secret: KEYS["recruiter-agent"] };
const AUDITOR = { agent: "auditor-agent", secret: KEYS["auditor-agent"] };

const line = (s = "") => console.log(s);
const step = (n, title) => line(`\n[${n}] ${title}`);

line("╔══════════════════════════════════════════════════════════════════╗");
line("║  UTA SHIELD v0.2.0 — hardened provider-side firewall for MCP     ║");
line("╚══════════════════════════════════════════════════════════════════╝");
line(`upstream (unprotected): ${UP}   |   shielded proxy: ${SH}`);

step(1, "GET /health — the operator's honest posture");
const health = await (await fetch(SH + "/health")).json();
line(`  v${health.version} · identity=${health.identity.mode} · outbound=${health.outbound_policy}`);
line(`  proxy: body≤${health.proxy.max_body_bytes}B · upstream timeout ${health.proxy.upstream_timeout_ms}ms · methods: ${health.proxy.methods_allowed.join(",")}`);
line(`  feed ${health.feed.version} · ${health.feed.iocs_total} IOCs · ${health.feed.campaigns} campaign(s)`);

step(2, "Unsigned agent (fail-closed default) → 401 REJECT_ANON");
const r2 = await post(rpc("initialize", {}, 1));
line(`  HTTP ${r2.status} · ${(await r2.json())?.error?.message}`);

step(3, "Signed agent (HMAC-SHA256 over body) → ALLOW_VERIFIED");
const r3 = await post(rpc("initialize", {}, 2), RECRUITER);
line(`  HTTP ${r3.status} · x-uta-shield: ${r3.headers.get("x-uta-shield")}`);

step(4, "Attacker replays the name but corrupts the signature → 401 REJECT_AUTH");
const r4 = await post(rpc("tools/list", null, 3), RECRUITER, true);
line(`  HTTP ${r4.status} · ${(await r4.json())?.error?.message}`);

step(5, "Signed agent pulls contacts → outbound DLP masks PII (OUT_MASKED)");
const r5 = await post(rpc("tools/call", { name: "search_contacts", arguments: { q: "vp eng" } }, 4), RECRUITER);
const t5 = await r5.text();
line(`  HTTP ${r5.status} · x-uta-shield: ${r5.headers.get("x-uta-shield")}`);
line(`  emails visible? ${t5.includes("@bigcorp.com") ? "YES (leak!)" : "NO → masked"}`);

step(6, "Upstream response carries a LIVE C2 domain → policy redact neutralizes it (OUT_REDACTED)");
const r6 = await post(rpc("tools/call", { name: "dirty_lookup", arguments: {} }, 5), RECRUITER);
const t6 = await r6.text();
line(`  HTTP ${r6.status} · x-uta-shield: ${r6.headers.get("x-uta-shield")}`);
line(`  raw C2 in response? ${t6.includes("gaganata.ink") ? "YES (bad!)" : "NO → " + (t6.match(/\[IOC_REDACTED:[^\]]+\]/)?.[0] || "redacted")}`);

step(7, "Signed agent tries to email a LIVE campaign URL → 403 BLOCK_INTEL");
const r7 = await post(rpc("tools/call", {
  name: "send_email",
  arguments: { to: "dev@example.com", subject: "Job offer", body: "Congrats! Verify here: https://taikotalent.xyz/verify_m" }
}, 6), RECRUITER);
const b7 = await r7.json();
line(`  HTTP ${r7.status} · ${b7?.error?.message}`);
line(`  evidence: ${j(b7?.error?.data?.hits?.map(h => `${h.type}:${h.value} (${h.campaign})`) || [])}`);

step(8, "Auditor-agent (ACL: dirty_lookup only) tries send_email → 403 REJECT_FORBIDDEN");
const r8 = await post(rpc("tools/call", { name: "send_email", arguments: { subject: "hi" } }, 7), AUDITOR);
line(`  HTTP ${r8.status} · ${(await r8.json())?.error?.message}`);

step(9, "Same verified agent hammers the API → RATE_LIMITED (agent bucket)");
let got429 = null;
for (let i = 0; i < 40 && !got429; i++) {
  const r = await post(rpc("tools/call", { name: "search_contacts", arguments: { q: String(i) } }, 100 + i), RECRUITER);
  if (r.status === 429) got429 = { attempt: i + 1, retryAfter: r.headers.get("retry-after") };
}
line(`  429 after +${got429?.attempt ?? "?"} calls · retry-after: ${got429?.retryAfter ?? "?"}s`);
line("  (and rotating declared names would NOT reset it — limits are keyed by verified agent + IP)");

step(10, "Operator surfaces: /pricing (x402-ready) + /audit (last decisions)");
const pricing = await (await fetch(SH + "/pricing")).json();
line(`  pricing: ${j(pricing.prices)} · currency ${pricing.currency}`);
const audit = await (await fetch(SH + "/audit")).json();
line("  audit tail:");
for (const e of audit.slice(-6))
  line(`   · ${e.ts.slice(11, 19)} ${e.verdict.padEnd(17)} agent=${(e.agent || "-").padEnd(16)} tool=${e.tool || "-"}`);

line("\nWhat you just saw: fail-closed identity (unsigned = 401, forged sig = 401),");
line("PII masked, live C2 neutralized on the way out, campaign payload blocked,");
line("per-tool ACL enforced, and per-agent+per-IP limits that survive name rotation.");
line("\nKill switch: Ctrl+C (demo cleans up upstream + shield + temp keys).");
shield.kill("SIGTERM"); upstream.close();
rmSync(keysDir, { recursive: true, force: true });
process.exit(0);
