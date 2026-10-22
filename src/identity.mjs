// uta-shield — agent identity (layer 1). v0.2.0: VERIFIABLE identity.
//
// Three identity modes, evaluated in order:
//   1. VERIFIED (hmac-sha256): the agent presents x-agent-name +
//      x-agent-timestamp + x-agent-signature, where signature =
//      HMAC_SHA256(secret, `${agent}|${timestamp}|${sha256(rawBody)}`).
//      Operators register agent secrets in the `keys` map. Fail-closed:
//      presented-but-invalid credentials are always a REJECT_AUTH.
//   2. DECLARED: x-agent-name / x-agent-passport / user-agent, verified:false.
//      Useful only for logging/labeling — rate limits are keyed by IP.
//   3. ANONYMOUS: no identity at all. Rejected when requireIdentity=true.
//
// Replay protection: timestamps outside ±maxSkewMs are rejected.
// Tamper protection: signature covers the exact raw request body.

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

const cache = new Map(); // origin -> { json, fetchedAt } (well-known verification cache)

export const VERIFY_METHOD = "hmac-sha256";

export function bodyDigest(rawBody) {
  return createHash("sha256").update(String(rawBody ?? ""), "utf8").digest("hex");
}

export function signBody(secret, agent, timestampMs, bodyHash) {
  return createHmac("sha256", String(secret))
    .update(`${agent}|${timestampMs}|${bodyHash}`)
    .digest("hex");
}

export function identify(req, opts = {}) {
  const {
    requireIdentity = false,
    keys = null,            // { agentName: secret } — operators register agents here
    maxSkewMs = 300000,     // ±5 min replay window
    bodyHash = null,        // sha256 hex of the raw request body
    now = Date.now()
  } = opts;

  const h = req.headers || {};
  const declaredRaw =
    (h["x-agent-name"] && String(h["x-agent-name"]).trim()) ||
    h["x-agent-passport"] ||
    parseUaAgent(h["user-agent"]) ||
    null;
  const declared = declaredRaw ? String(declaredRaw).trim().slice(0, 200) : null;
  const anon = !declared;

  // ── Mode 1: credentials presented → they MUST verify (fail closed) ──
  const sig = h["x-agent-signature"];
  const ts = h["x-agent-timestamp"];
  if (sig || ts) {
    if (!keys || typeof keys !== "object" || Object.keys(keys).length === 0) {
      return { ok: false, verdict: "REJECT_AUTH", agent: declared, verified: false, reason: "credentials presented but operator has no keys configured" };
    }
    if (!declared || !Object.prototype.hasOwnProperty.call(keys, declared)) {
      return { ok: false, verdict: "REJECT_AUTH", agent: declared, verified: false, reason: "unknown agent for presented credentials" };
    }
    const t = Number(ts);
    if (!Number.isFinite(t) || Math.abs(now - t) > maxSkewMs) {
      return { ok: false, verdict: "REJECT_AUTH", agent: declared, verified: false, reason: "timestamp outside acceptance window (clock skew or replay)" };
    }
    if (!bodyHash) {
      return { ok: false, verdict: "REJECT_AUTH", agent: declared, verified: false, reason: "missing body digest for signature verification" };
    }
    const expected = signBody(keys[declared], declared, t, bodyHash);
    const got = Buffer.from(String(sig), "utf8");
    const want = Buffer.from(expected, "utf8");
    if (got.length !== want.length || !timingSafeEqual(got, want)) {
      return { ok: false, verdict: "REJECT_AUTH", agent: declared, verified: false, reason: "invalid signature" };
    }
    return { ok: true, verdict: "ALLOW_VERIFIED", agent: declared, verified: true, method: VERIFY_METHOD };
  }

  // ── Mode 2/3: declared or anonymous ──
  if (anon && requireIdentity) {
    return { ok: false, verdict: "REJECT_ANON", agent: null, verified: false, reason: "anonymous caller rejected by policy" };
  }
  return {
    ok: true,
    verdict: anon ? "ALLOW_ANON" : "ALLOW",
    agent: declared || "anonymous",
    verified: false
  };
}

// Per-tool authorization (layer 1b). ACL maps agent name → tools.
//   acl = { "scraper-bot": ["search_contacts"], "ops-bot": ["*"] }
// Agents absent from the ACL map are not restricted by it.
export function agentAllowed(acl, agent, tool) {
  if (!acl || typeof acl !== "object") return true;
  if (!Object.prototype.hasOwnProperty.call(acl, agent)) return true;
  const tools = acl[agent];
  if (!Array.isArray(tools) || tools.length === 0) return false;
  return tools.includes("*") || tools.includes(tool);
}

function parseUaAgent(ua) {
  if (!ua) return null;
  const m = /([A-Za-z0-9_.-]+(?:\/[a-z-]+)?)-agent|^(mcp|claude|cursor|openai|gtb|copilot)/i.exec(ua);
  return m ? m[0].toLowerCase() : null;
}

export async function verifyAgentOrigin(agentUrl, { ttlMs = 300000 } = {}) {
  // Fetches <origin>/.well-known/agent.json and caches it. Returns { verified, name, error }.
  try {
    const u = new URL(agentUrl);
    const origin = u.origin;
    const hit = cache.get(origin);
    if (hit && Date.now() - hit.fetchedAt < ttlMs) return { verified: true, name: hit.json.name || origin, cached: true };
    const res = await fetch(origin + "/.well-known/agent.json", { signal: AbortSignal.timeout(4000) });
    if (!res.ok) return { verified: false, error: `agent.json HTTP ${res.status}` };
    const json = await res.json();
    cache.set(origin, { json, fetchedAt: Date.now() });
    return { verified: true, name: json.name || origin };
  } catch (e) {
    return { verified: false, error: String(e.message || e) };
  }
}

export function fingerprint(agent, tool, args) {
  return createHash("sha256").update(`${agent}|${tool}|${JSON.stringify(args ?? null)}`).digest("hex").slice(0, 16);
}
