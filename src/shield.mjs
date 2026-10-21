// uta-shield — core gate pipeline (provider-side firewall for MCP servers).
//
//   gateIn  : identity → threat-intel (args) → rate limit
//   gateOut : threat-intel (response) → DLP masking
//
// Every decision is audited. Verdicts: ALLOW | ALLOW_ANON | REJECT_ANON |
// BLOCK_INTEL | RATE_LIMITED.

import { Feed } from "./feed.mjs";
import { maskSensitive, maskDeep } from "./dlp.mjs";
import { RateLimiter } from "./ratelimit.mjs";
import { AuditLog } from "./audit.mjs";
import { Billing } from "./billing.mjs";
import { identify } from "./identity.mjs";

export function createShield(options = {}) {
  const opts = {
    feed: options.feed,                                    // Feed instance (required for intel)
    requireIdentity: options.requireIdentity ?? false,     // layer 1 strictness
    dlp: options.dlp ?? { enabled: true },                 // layer 6
    ratelimit: options.ratelimit ?? { ratePerMin: 30, burst: 10 }, // layer 4
    audit: options.audit ?? {},                            // layer 8 ({file})
    billing: options.billing ?? { enabled: false },        // layer 5
    name: options.name ?? "uta-shield",
    version: options.version ?? "0.1.0"
  };

  const audit = new AuditLog(opts.audit);
  const rl = new RateLimiter(opts.ratelimit);
  const billing = new Billing(opts.billing);

  function stringifyArgs(args) {
    if (args == null) return "";
    if (typeof args === "string") return args;
    try { return JSON.stringify(args); } catch { return String(args); }
  }

  function gateIn({ headers = {}, tool = null, args = null }) {
    const t0 = Date.now();
    const argsText = stringifyArgs(args);

    // Layer 1 — identity
    const id = identify({ headers }, { requireIdentity: opts.requireIdentity });
    if (!id.ok) {
      audit.log({ verdict: id.verdict, agent: null, tool, reason: "anonymous caller rejected by policy" });
      return { verdict: id.verdict, agent: null, reason: "identity required by policy", hits: [] };
    }

    // Layer 3 — threat-intel on tool call arguments
    let intel = { scanned: 0, hits: [] };
    if (opts.feed && argsText) {
      intel = opts.feed.screenText(argsText);
      if (intel.hits.length) {
        audit.log({
          verdict: "BLOCK_INTEL", agent: id.agent, tool,
          reason: "IOC match in tool-call arguments",
          findings: intel.hits.map(h => ({ type: h.candidate_type, value: h.query, how: h.how, campaign: h.campaign.id }))
        });
        return { verdict: "BLOCK_INTEL", agent: id.agent, reason: "known-bad indicator in arguments", hits: intel.hits };
      }
    }

    // Layer 4 — rate limit per agent(+tool)
    const tier = (headers && headers["x-agent-tier"]) || null;
    const rlKey = `${id.agent}|${tool || "*"}`;
    const r = rl.take(rlKey, tier);
    if (!r.ok) {
      audit.log({ verdict: "RATE_LIMITED", agent: id.agent, tool, reason: `retry in ${r.retryAfterMs}ms` });
      return { verdict: "RATE_LIMITED", agent: id.agent, retryAfterMs: r.retryAfterMs, hits: [] };
    }

    // Layer 5 — metering (billable only on ALLOW)
    const charge = billing.meter(id.agent, tool || "unknown", id.verdict === "REJECT_ANON" ? null : "ALLOW");

    audit.log({
      verdict: id.verdict, agent: id.agent, tool,
      reason: "passed intel + rate gates", intel_scanned: intel.scanned,
      charge, latency_ms: Date.now() - t0
    });
    return { verdict: id.verdict, agent: id.agent, verified: id.verified, charge, hits: [] };
  }

  function gateOut({ text = "", json = null }) {
    // Layer 3 (outbound) — response must not carry known-bad infrastructure
    // Layer 6 — DLP masking
    const result = { intel: { scanned: 0, hits: [] }, dlp: { findings: [] }, text, json };
    if (opts.feed && text) result.intel = opts.feed.screenText(text);
    const source = text || stringifyArgs(json);
    const m = maskSensitive(source, opts.dlp);
    result.dlp = m.findings;
    if (text) result.text = m.masked;
    if (json) result.json = maskDeep(json, opts.dlp);
    audit.log({
      verdict: result.intel.hits.length ? "OUTBOUND_INTEL" : "OUT_OK",
      reason: result.intel.hits.length ? "response contains known-bad indicator" : "outbound clean/masked",
      findings: result.intel.hits.map(h => ({ type: h.candidate_type, value: h.query, campaign: h.campaign.id })),
      dlp: result.dlp
    });
    return result;
  }

  return {
    name: opts.name, version: opts.version, feed: opts.feed || null,
    gateIn, gateOut, audit, billing,
    health() {
      return {
        name: opts.name, version: opts.version,
        feed: opts.feed ? opts.feed.stats() : null,
        audit: audit.stats()
      };
    }
  };
}
