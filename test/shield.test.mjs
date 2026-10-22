import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Feed } from "../src/feed.mjs";
import { createShield } from "../src/shield.mjs";
import { signBody, bodyDigest } from "../src/identity.mjs";

const feed = Feed.fromFile(join(dirname(fileURLToPath(import.meta.url)), "..", "feed", "iocs.json"));

function mk(opts = {}) {
  return createShield({ feed, ratelimit: { ratePerMin: 60, burst: 100 }, ...opts });
}

function signedHeaders(agent, secret, rawBody, ts = Date.now()) {
  return {
    "x-agent-name": agent,
    "x-agent-timestamp": String(ts),
    "x-agent-signature": signBody(secret, agent, ts, bodyDigest(rawBody))
  };
}

test("blocks tool calls whose arguments carry hostile IOCs", () => {
  const s = mk();
  const g = s.gateIn({
    headers: { "x-agent-name": "helper-bot" },
    tool: "send_email",
    args: { to: "victim@corp.com", body: "verify at https://taikotalent.xyz/verify_m" }
  });
  assert.equal(g.verdict, "BLOCK_INTEL");
  assert.equal(g.hits[0].campaign.id, "taikotalent-2026-10");
});

test("allows benign calls and meters them", () => {
  const s = mk({ billing: { enabled: true, prices: { search_contacts: { amount: "0.001" } } } });
  const g = s.gateIn({ headers: { "x-agent-name": "helper-bot" }, tool: "search_contacts", args: { q: "acme corp" } });
  assert.equal(g.verdict, "ALLOW");
  assert.ok(g.charge);
});

test("HMAC-verified agent gets ALLOW_VERIFIED", () => {
  const s = mk({ identity: { keys: { "helper-bot": "k1" } } });
  const raw = JSON.stringify({ id: 1 });
  const g = s.gateIn({
    headers: signedHeaders("helper-bot", "k1", raw),
    tool: "search_contacts", args: { q: "acme" }, rawBody: raw
  });
  assert.equal(g.verdict, "ALLOW_VERIFIED");
  assert.equal(g.verified, true);
});

test("presented-but-invalid credentials are rejected (fail closed)", () => {
  const s = mk({ identity: { keys: { "helper-bot": "k1" } } });
  const raw = JSON.stringify({ id: 1 });
  const g = s.gateIn({
    headers: signedHeaders("helper-bot", "WRONG", raw),
    tool: "search_contacts", args: {}, rawBody: raw
  });
  assert.equal(g.verdict, "REJECT_AUTH");
});

test("ACL denies tools not in the agent's allow-list", () => {
  const s = mk({ identity: { keys: { "helper-bot": "k1" }, acl: { "helper-bot": ["search_contacts"] } } });
  const raw = JSON.stringify({ id: 1 });
  const ok = s.gateIn({
    headers: signedHeaders("helper-bot", "k1", raw),
    tool: "search_contacts", args: {}, rawBody: raw
  });
  assert.equal(ok.verdict, "ALLOW_VERIFIED");
  const denied = s.gateIn({
    headers: signedHeaders("helper-bot", "k1", raw + "2"),
    tool: "delete_all", args: {}, rawBody: raw + "2"
  });
  assert.equal(denied.verdict, "REJECT_FORBIDDEN");
});

test("rejects anonymous callers when requireIdentity=true", () => {
  const s = mk({ requireIdentity: true });
  const g = s.gateIn({ headers: {}, tool: "search_contacts", args: {} });
  assert.equal(g.verdict, "REJECT_ANON");
  const g2 = s.gateIn({ headers: { "x-agent-name": "known-agent" }, tool: "search_contacts", args: {} });
  assert.equal(g2.verdict, "ALLOW");
  assert.equal(g2.verified, false);
});

test("rate-limits VERIFIED agents per agent+tool (agent bucket)", () => {
  const s = mk({ identity: { keys: { "hammer-bot": "k2" } }, ratelimit: { ratePerMin: 1, burst: 2 } });
  let n = 0;
  for (let i = 0; i < 4; i++) {
    const raw = JSON.stringify({ i });
    const g = s.gateIn({
      headers: signedHeaders("hammer-bot", "k2", raw),
      tool: "search_contacts", args: { q: "x" }, rawBody: raw, ip: "10.9.9.9"
    });
    if (g.verdict === "RATE_LIMITED") n++;
  }
  assert.ok(n >= 1, "verified agent must hit its own agent bucket");
});

test("ANTI-ROTATION: declared-name churn from one IP is still rate-limited (v0.1.0 bypass fixed)", () => {
  const s = mk({ ratelimit: { ratePerMin: 1, burst: 2, ipRatePerMin: 1, ipBurst: 2 } });
  let limited = 0;
  for (let i = 0; i < 6; i++) {
    const g = s.gateIn({
      headers: { "x-agent-name": `rotating-name-${i}` }, // fresh declared name every call
      tool: "search_contacts", args: { q: "x" }, ip: "10.0.0.1"
    });
    if (g.verdict === "RATE_LIMITED") limited++;
  }
  assert.equal(limited, 4, "IP bucket must apply no matter how names rotate");
});

test("unverified agents get NO per-agent bucket (limits keyed by origin)", () => {
  const s = mk({ ratelimit: { ratePerMin: 1, burst: 3, ipRatePerMin: 1, ipBurst: 1000 } });
  let limited = 0;
  for (let i = 0; i < 6; i++) {
    const g = s.gateIn({
      headers: { "x-agent-name": `name-${i}` },
      tool: "search_contacts", args: { q: "x" }, ip: `10.1.1.${i}` // distinct IPs
    });
    if (g.verdict === "RATE_LIMITED") limited++;
  }
  assert.equal(limited, 0, "no ip exhaustion here — and no agent-name bucket either");
});

test("gateOut masks PII in upstream responses", () => {
  const s = mk();
  const out = s.gateOut({ json: { contact: "jane@corp.com", phone_note: "sk-realkey1234567890abcd" } });
  assert.equal(out.json.contact, "[EMAIL_REDACTED]");
  assert.ok(JSON.stringify(out.json).includes("[API_KEY_REDACTED]"));
  assert.ok(out.dlp.length >= 1);
});

test("gateOut redacts IOCs by default (outbound policy: redact)", () => {
  const s = mk();
  const out = s.gateOut({ text: "host api.gaganata.ink still resolving" });
  assert.equal(out.policy, "redact");
  assert.ok(!out.text.includes("gaganata.ink"));
  assert.ok(out.text.includes("[IOC_REDACTED:taikotalent-2026-10/"));
});

test("health discloses the honest posture", () => {
  const s = mk({ identity: { keys: { a: "b" } }, outboundPolicy: "block" });
  const h = s.health();
  assert.equal(h.version, "0.2.2");
  assert.equal(h.outbound_policy, "block");
  assert.equal(h.identity.mode, "hmac-verified");
});

test("audit log records decisions: indicator + campaign yes, raw arguments no", () => {
  const s = mk();
  s.gateIn({
    headers: { "x-agent-name": "helper-bot" }, tool: "send_email",
    args: { body: "evil link https://taikotalent.xyz/verify_w" }
  });
  const evts = s.audit.last(5);
  assert.ok(evts.length >= 1);
  const blob = JSON.stringify(evts);
  assert.ok(!blob.includes("evil link"), "audit must not echo raw argument context");
  assert.ok(blob.includes("BLOCK_INTEL"));
  assert.ok(blob.includes("taikotalent-2026-10"), "campaign id present for triage");
  assert.ok(blob.includes("https://taikotalent.xyz/verify_w"), "matched indicator value present (SIEM standard)");
});
