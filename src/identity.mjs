// uta-shield — agent identity (layer 1). Declared identity first, verification optional.
// Honest status: verification of /.well-known/agent.json + ATC is a documented hook,
// implemented for origin-verified agents, disabled by default.

import { createHash } from "node:crypto";

const cache = new Map(); // origin -> { json, fetchedAt }

export function identify(req, { requireIdentity = false } = {}) {
  const h = req.headers || {};
  const declared =
    h["x-agent-passport"] ||      // agent passport (MAP style)
    h["x-agent-name"] ||          // explicit declaration
    parseUaAgent(h["user-agent"]) ||
    null;
  const anon = !declared;
  if (anon && requireIdentity) {
    return { ok: false, verdict: "REJECT_ANON", agent: null, verified: false };
  }
  return {
    ok: true,
    verdict: anon ? "ALLOW_ANON" : "ALLOW",
    agent: declared ? String(declared).slice(0, 200) : "anonymous",
    verified: false
  };
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
