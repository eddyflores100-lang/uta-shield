// uta-shield — core gate pipeline (provider-side firewall for MCP servers).
//
//   gateIn  : identity (HMAC-verified) → ACL → threat-intel (args) → two-tier rate limit
//   gateOut : threat-intel (response) → OUTBOUND POLICY → DLP masking
//
// v0.2.0 outbound policy (explicit, replaces silent pass-through):
//   "block"  — response with IOC is WITHHELD; client gets a JSON-RPC error
//   "redact" — IOC occurrences are neutralized in-place, response flows (default)
//   "log"    — response flows untouched, decision is audited (v0.1.0 behavior)
//
// Every decision is audited. Verdicts: ALLOW_VERIFIED | ALLOW | ALLOW_ANON |
// REJECT_ANON | REJECT_AUTH | REJECT_FORBIDDEN | BLOCK_INTEL | RATE_LIMITED |
// OUT_OK | OUT_REDACTED | OUTBOUND_INTEL | OUT_BLOCKED.

import { Feed } from "./feed.mjs";
import { maskSensitive, maskDeepDetailed } from "./dlp.mjs";
import { RateLimiter } from "./ratelimit.mjs";
import { AuditLog } from "./audit.mjs";
import { Billing } from "./billing.mjs";
import { identify, agentAllowed, bodyDigest } from "./identity.mjs";

export const OUTBOUND_POLICIES = ["block", "redact", "log"];

export function createShield(options = {}) {
  const opts = {
    feed: options.feed,                                    // Feed instance (required for intel)
    requireIdentity: options.requireIdentity ?? false,     // reject anonymous callers
    identity: options.identity ?? {},                      // { keys, acl, maxSkewMs }
    outboundPolicy: normalizePolicy(options.outboundPolicy ?? "redact"),
    dlp: options.dlp ?? { enabled: true },                 // layer 6
    ratelimit: options.ratelimit ?? { ratePerMin: 30, burst: 10 }, // layer 4 (adds ipRatePerMin/ipBurst)
    audit: options.audit ?? {},                            // layer 8 ({file})
    billing: options.billing ?? { enabled: false },        // layer 5
    name: options.name ?? "uta-shield",
    version: options.version ?? "0.2.1"
  };

  const audit = new AuditLog(opts.audit);
  const rl = new RateLimiter(opts.ratelimit);
  const billing = new Billing(opts.billing);

  function stringifyArgs(args) {
    if (args == null) return "";
    if (typeof args === "string") return args;
    try { return JSON.stringify(args); } catch { return String(args); }
  }

  function gateIn({ headers = {}, tool = null, args = null, ip = null, rawBody = null } = {}) {
    const t0 = Date.now();
    const argsText = stringifyArgs(args);

    // Layer 1 — identity (verified > declared > anonymous)
    const id = identify({ headers }, {
      requireIdentity: opts.requireIdentity,
      keys: opts.identity.keys || null,
      maxSkewMs: opts.identity.maxSkewMs,
      bodyHash: rawBody == null ? null : bodyDigest(rawBody)
    });
    if (!id.ok) {
      audit.log({ verdict: id.verdict, agent: id.agent ?? null, ip, tool, reason: id.reason });
      return { verdict: id.verdict, agent: id.agent ?? null, verified: id.verified, reason: id.reason, hits: [] };
    }

    // Layer 1b — per-tool authorization (ACL), for agents listed in the ACL map
    if (tool && opts.identity.acl && !agentAllowed(opts.identity.acl, id.agent, tool)) {
      audit.log({ verdict: "REJECT_FORBIDDEN", agent: id.agent, ip, tool, reason: `tool "${tool}" not authorized for this agent by ACL` });
      return { verdict: "REJECT_FORBIDDEN", agent: id.agent, verified: id.verified, reason: "tool not authorized by ACL", hits: [] };
    }

    // Layer 3 — threat-intel on tool call arguments
    let intel = { scanned: 0, hits: [] };
    if (opts.feed && argsText) {
      intel = opts.feed.screenText(argsText);
      if (intel.hits.length) {
        audit.log({
          verdict: "BLOCK_INTEL", agent: id.agent, ip, tool,
          reason: "IOC match in tool-call arguments",
          findings: intel.hits.map(h => ({ type: h.candidate_type, value: h.query, how: h.how, campaign: h.campaign.id }))
        });
        return { verdict: "BLOCK_INTEL", agent: id.agent, verified: id.verified, reason: "known-bad indicator in arguments", hits: intel.hits };
      }
    }

    // Layer 4 — two-tier rate limit: per-IP always, per-agent only when verified
    const tier = (headers && headers["x-agent-tier"]) || null;
    const entries = [];
    if (ip) entries.push({ key: `ip:${ip}`, ip: true });
    if (id.verified) entries.push({ key: `agent:${id.agent}|${tool || "*"}`, tier });
    if (entries.length) {
      const r = rl.takeMulti(entries);
      if (!r.ok) {
        audit.log({ verdict: "RATE_LIMITED", agent: id.agent, ip, tool, reason: `retry in ${r.retryAfterMs}ms (bucket ${r.key || "?"})` });
        return { verdict: "RATE_LIMITED", agent: id.agent, verified: id.verified, retryAfterMs: r.retryAfterMs, hits: [] };
      }
    }

    // Layer 5 — metering (billable only on ALLOW*)
    const charge = billing.meter(id.agent, tool || "unknown", "ALLOW");

    audit.log({
      verdict: id.verdict, agent: id.agent, ip, tool,
      reason: id.verified ? "HMAC-verified; passed ACL + intel + rate gates" : "passed intel + rate gates",
      intel_scanned: intel.scanned, charge, latency_ms: Date.now() - t0
    });
    return { verdict: id.verdict, agent: id.agent, verified: id.verified, charge, hits: [] };
  }

  function gateOut({ text = "", json = null, agent = null, tool = null } = {}) {
    const result = {
      policy: opts.outboundPolicy,
      intel: { scanned: 0, hits: [] },
      redacted: [],
      dlp: [],
      blocked: false,
      error: null,
      text,
      json
    };

    // Layer 3 (outbound) — screen the RAW upstream response first
    if (opts.feed && text) result.intel = opts.feed.screenText(text);
    if (opts.feed && json) {
      const jt = opts.feed.screenText(stringifyArgs(json));
      result.intel.scanned += jt.scanned;
      result.intel.hits.push(...jt.hits);
    }

    const evidence = () => result.intel.hits.map(h => ({ type: h.candidate_type, value: h.query, campaign: h.campaign.id }));

    // ── Outbound policy ──
    if (result.intel.hits.length && opts.outboundPolicy === "block") {
      result.blocked = true;
      result.text = null;
      result.json = null;
      result.error = {
        code: -32006,
        message: "response blocked by uta-shield: known-bad indicator in upstream response",
        data: { verdict: "OUT_BLOCKED", hits: evidence() }
      };
      audit.log({ verdict: "OUT_BLOCKED", agent, tool, reason: "policy=block: response withheld", findings: evidence() });
      return result;
    }

    if (result.intel.hits.length && opts.outboundPolicy === "redact") {
      if (text) {
        const rr = opts.feed.redactText(text);
        result.text = rr.text;
        result.redacted.push(...rr.redacted);
      }
      if (json) {
        try {
          const rr = opts.feed.redactText(stringifyArgs(json));
          result.json = JSON.parse(rr.text);
          result.redacted.push(...rr.redacted);
        } catch { /* keep original json; DLP still applies */ }
      }
    }

    // Layer 6 — DLP masking (applies in every policy)
    const m = maskSensitive(typeof result.text === "string" ? result.text : "", opts.dlp);
    if (typeof result.text === "string") result.text = m.masked;
    result.dlp.push(...m.findings);
    if (json) {
      const jd = maskDeepDetailed(result.json ?? json, opts.dlp);
      result.json = jd.value;
      result.dlp.push(...jd.findings);
    }

    // Verdict: OUT_BLOCKED | OUT_REDACTED | OUTBOUND_INTEL (log) | OUT_MASKED | OUT_OK
    let verdict = "OUT_OK";
    let reason = "outbound clean";
    if (result.intel.hits.length && opts.outboundPolicy === "block") { /* unreachable; handled above */ }
    else if (result.intel.hits.length && opts.outboundPolicy === "redact") { verdict = "OUT_REDACTED"; reason = "IOC occurrences neutralized in outbound response"; }
    else if (result.intel.hits.length && opts.outboundPolicy === "log") { verdict = "OUTBOUND_INTEL"; reason = "response contains known-bad indicator; policy=log passed it through"; }
    if (result.dlp.length) { verdict = verdict === "OUT_OK" ? "OUT_MASKED" : verdict; reason = result.dlp.length && verdict === "OUT_OK" ? "secrets masked in outbound response" : reason; }

    // v0.2.1: the verdict travels with the result so every consumer (proxy
    // header, MCP wrapper, tests) classifies the response EXACTLY as the core
    // did — no recomputation, no drift between layers.
    result.verdict = verdict;

    audit.log({ verdict, agent, tool, reason, findings: evidence(), redacted: result.redacted, dlp: result.dlp });
    return result;
  }

  return {
    name: opts.name, version: opts.version, feed: opts.feed || null,
    outboundPolicy: opts.outboundPolicy,
    gateIn, gateOut, audit, billing,
    health() {
      return {
        name: opts.name, version: opts.version,
        outbound_policy: opts.outboundPolicy,
        identity: {
          mode: opts.identity.keys && Object.keys(opts.identity.keys).length ? "hmac-verified" : (opts.requireIdentity ? "declared-required" : "declared/anonymous"),
          verified_supported: !!(opts.identity.keys && Object.keys(opts.identity.keys).length),
          acl_agents: opts.identity.acl ? Object.keys(opts.identity.acl).length : 0
        },
        feed: opts.feed ? opts.feed.stats() : null,
        audit: audit.stats()
      };
    }
  };
}

function normalizePolicy(p) {
  const s = String(p || "").toLowerCase();
  if (!OUTBOUND_POLICIES.includes(s)) {
    const e = new Error(`invalid outboundPolicy "${p}" — expected one of: ${OUTBOUND_POLICIES.join(", ")}`);
    e.code = "EOPTS";
    throw e;
  }
  return s;
}
