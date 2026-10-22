// uta-shield v0.2.0 — verifiable identity (HMAC-SHA256) tests.
// Covers: verification, tampering, replay, unknown agents, fail-closed
// behavior and per-tool ACL authorization.

import { test } from "node:test";
import assert from "node:assert/strict";
import { identify, signBody, bodyDigest, agentAllowed } from "../src/identity.mjs";

const KEYS = { "bot-a": "s3cret-a", "bot-b": "s3cret-b" };

function signedHeaders(agent, secret, rawBody, ts = Date.now()) {
  const bh = bodyDigest(rawBody);
  return {
    "x-agent-name": agent,
    "x-agent-timestamp": String(ts),
    "x-agent-signature": signBody(secret, agent, ts, bh)
  };
}

test("valid HMAC credentials verify the agent (ALLOW_VERIFIED)", () => {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  const r = identify({ headers: signedHeaders("bot-a", "s3cret-a", body) }, { keys: KEYS, bodyHash: bodyDigest(body) });
  assert.equal(r.ok, true);
  assert.equal(r.verdict, "ALLOW_VERIFIED");
  assert.equal(r.verified, true);
  assert.equal(r.agent, "bot-a");
  assert.equal(r.method, "hmac-sha256");
});

test("tampered body → signature mismatch → REJECT_AUTH (fail closed)", () => {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  const headers = signedHeaders("bot-a", "s3cret-a", body);
  const tampered = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "delete_all" } });
  const r = identify({ headers }, { keys: KEYS, bodyHash: bodyDigest(tampered) });
  assert.equal(r.ok, false);
  assert.equal(r.verdict, "REJECT_AUTH");
  assert.match(r.reason, /invalid signature/);
});

test("forged signature with wrong secret → REJECT_AUTH", () => {
  const body = "{}";
  const r = identify({ headers: signedHeaders("bot-a", "wrong-secret", body) }, { keys: KEYS, bodyHash: bodyDigest(body) });
  assert.equal(r.verdict, "REJECT_AUTH");
  assert.equal(r.verified, false);
});

test("replayed/stale timestamp outside the window → REJECT_AUTH", () => {
  const body = "{}";
  const stale = Date.now() - 10 * 60 * 1000; // 10 min ago (window default ±5 min)
  const r = identify({ headers: signedHeaders("bot-a", "s3cret-a", body, stale) }, { keys: KEYS, bodyHash: bodyDigest(body) });
  assert.equal(r.verdict, "REJECT_AUTH");
  assert.match(r.reason, /window/);
});

test("unknown agent presenting credentials → REJECT_AUTH", () => {
  const body = "{}";
  const r = identify({ headers: signedHeaders("ghost-agent", "s3cret-a", body) }, { keys: KEYS, bodyHash: bodyDigest(body) });
  assert.equal(r.verdict, "REJECT_AUTH");
  assert.match(r.reason, /unknown agent/);
});

test("credentials presented but no keys configured → REJECT_AUTH (fail closed)", () => {
  const body = "{}";
  const r = identify({ headers: signedHeaders("bot-a", "s3cret-a", body) }, { keys: null, bodyHash: bodyDigest(body) });
  assert.equal(r.verdict, "REJECT_AUTH");
  assert.match(r.reason, /no keys configured/);
});

test("declared agent without credentials stays ALLOW but verified:false", () => {
  const r = identify({ headers: { "x-agent-name": "some-bot" } }, { keys: KEYS });
  assert.equal(r.ok, true);
  assert.equal(r.verdict, "ALLOW");
  assert.equal(r.verified, false);
});

test("anonymous caller rejected when requireIdentity=true", () => {
  const r = identify({ headers: {} }, { requireIdentity: true });
  assert.equal(r.verdict, "REJECT_ANON");
});

test("x-agent-name rotation can no longer fake a fresh identity (declared only)", () => {
  // The core bypass from the v0.1.0 audit: rotating declared names.
  // Identity-level: every declared name is just verified:false — no per-name trust.
  for (const name of ["rot-1", "rot-2", "rot-3"]) {
    const r = identify({ headers: { "x-agent-name": name } }, { keys: KEYS });
    assert.equal(r.verified, false, `declared name ${name} must not count as verified`);
  }
});

test("ACL: per-tool allow-list, wildcard, empty list denies, unlisted agent unaffected", () => {
  const acl = { "bot-a": ["search_contacts"], "bot-b": ["*"], "bot-c": [] };
  assert.equal(agentAllowed(acl, "bot-a", "search_contacts"), true);
  assert.equal(agentAllowed(acl, "bot-a", "delete_all"), false);
  assert.equal(agentAllowed(acl, "bot-b", "anything"), true);
  assert.equal(agentAllowed(acl, "bot-c", "anything"), false);
  assert.equal(agentAllowed(acl, "unlisted-bot", "anything"), true);
});
