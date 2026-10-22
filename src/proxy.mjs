// uta-shield — hardened HTTP proxy handler (v0.2.1).
// Extracted from bin/cli.mjs so the exact production path is testable.
//
// Hardening (v0.2.0):
//   - maxBodyBytes: request bodies above the limit are rejected 413
//     (content-length honored AND streamed bytes counted — no trust in headers)
//   - upstreamTimeoutMs: fetch carries AbortSignal.timeout → 504 on hang
//   - allowMethods: JSON-RPC method allow-list (initialize, ping, tools/list,
//     tools/call, notifications/initialized by default) → 403 METHOD_DENIED
//   - safe errors: upstream failures return fixed messages; details go to the
//     audit log, never to the client; stack traces never leave the process
//   - client IP: socket remoteAddress, or X-Forwarded-For only with --trust-proxy
//   - forwards the EXACT raw body bytes upstream (signature integrity)
//
// Hardening (v0.2.1, second external review):
//   - /audit is AUTHENTICATED (x-uta-admin header, timing-safe compare) and
//     DISABLED (404) when no adminToken is configured — fail-closed. The
//     audit trail contains IOCs, agent names and tool usage; it is operator
//     telemetry, never public data.
//   - the outbound `x-uta-shield` flag is the verdict computed by the core
//     (out.verdict) — policy=log now correctly reports OUTBOUND_INTEL instead
//     of a recomputed (and wrong) OUT_REDACTED/OUT_OK.

import { timingSafeEqual } from "node:crypto";

const DEFAULT_METHODS = ["initialize", "notifications/initialized", "ping", "tools/list", "tools/call"];

// Timing-safe token compare over the raw bytes of both tokens — no external
// crypto dependency, constant-time regardless of where the first diff is.
function tokensEqual(a, b) {
  const ba = Buffer.from(String(a), "utf8");
  const bb = Buffer.from(String(b), "utf8");
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

function json(res, status, obj, headers = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(obj));
}

export function createProxyHandler({ shield, upstream, limits = {}, allowMethods = null, trustProxy = false, adminToken = null } = {}) {
  if (!shield || typeof shield.gateIn !== "function") throw new Error("createProxyHandler requires a shield instance");
  const lim = {
    maxBodyBytes: Math.max(1, Number(limits.maxBodyBytes ?? 1048576)),
    upstreamTimeoutMs: Math.max(1, Number(limits.upstreamTimeoutMs ?? 30000))
  };
  const allowed = allowMethods === "*" ? null : new Set(allowMethods || DEFAULT_METHODS);
  const admin = adminToken ? String(adminToken) : null; // null = /audit disabled (fail-closed)

  function clientIp(req) {
    if (trustProxy) {
      const xff = req.headers["x-forwarded-for"];
      if (xff) {
        const first = String(xff).split(",")[0].trim();
        if (first) return first;
      }
    }
    const ra = req.socket?.remoteAddress || null;
    if (!ra) return null;
    if (ra === "::1") return "127.0.0.1";
    return ra.replace(/^::ffff:/, "");
  }

  return async function handler(req, res) {
    // ── management endpoints (GET) ──
    // /health and /pricing: read-only posture metadata, safe to expose.
    // /audit: OPERATOR TELEMETRY — authenticated or disabled (v0.2.1).
    if (req.method === "GET" && req.url === "/audit") {
      const ip = clientIp(req);
      if (!admin) {
        // Fail-closed: no admin token configured → the endpoint does not exist
        // publicly. Answer 404 without leaking records or configuration state.
        shield.audit.log({ verdict: "AUDIT_DISABLED", ip, reason: "GET /audit while no admin token is configured — endpoint disabled (fail-closed)" });
        return json(res, 404, { jsonrpc: "2.0", id: null, error: { code: -32601, message: "not found" } });
      }
      const got = req.headers["x-uta-admin"];
      if (typeof got !== "string" || !got.length || !tokensEqual(got, admin)) {
        shield.audit.log({ verdict: "AUDIT_DENIED", ip, reason: "GET /audit with missing or invalid x-uta-admin token" });
        return json(res, 401, { jsonrpc: "2.0", id: null, error: { code: -32001, message: "admin authentication required (x-uta-admin)" } }, { "x-uta-shield": "AUDIT_DENIED" });
      }
      return json(res, 200, shield.audit.last(20));
    }
    if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
      const health = shield.health();
      health.proxy = {
        max_body_bytes: lim.maxBodyBytes,
        upstream_timeout_ms: lim.upstreamTimeoutMs,
        methods_allowed: allowed ? [...allowed] : "*",
        trust_proxy: !!trustProxy,
        audit_admin_required: !!admin
      };
      return json(res, 200, health);
    }
    if (req.method === "GET" && req.url === "/pricing") {
      return json(res, 200, shield.billing.x402Manifest());
    }
    if (req.method === "GET" && req.url === "/audit") {
      return json(res, 200, shield.audit.last(20));
    }
    if (req.method !== "POST") {
      return json(res, 405, { jsonrpc: "2.0", id: null, error: { code: -32600, message: "method not allowed — POST JSON-RPC over HTTP" } }, { allow: "GET, POST" });
    }

    // v0.2.2: resolved once, up front — the body-limit audit records below
    // need it before the gateIn section runs.
    const ip = clientIp(req);

    // ── request body: hard size limit (declared + streamed) ──
    const declaredLen = Number(req.headers["content-length"] || 0);
    if (declaredLen > lim.maxBodyBytes) {
      shield.audit.log({ verdict: "BODY_TOO_LARGE", ip, tool: req.url === "/" ? null : req.url, reason: `declared content-length ${declaredLen} > limit ${lim.maxBodyBytes}` });
      return json(res, 413, { jsonrpc: "2.0", id: null, error: { code: -32008, message: `request body too large (limit ${lim.maxBodyBytes} bytes)` } }, { "x-uta-shield": "BODY_TOO_LARGE" });
    }
    const chunks = [];
    let total = 0, overflow = false;
    for await (const c of req) {
      total += c.length;
      if (total > lim.maxBodyBytes) { overflow = true; break; }
      chunks.push(c);
    }
    if (overflow) {
      // v0.2.2: stop the upload, but let the 413 reach the client FIRST —
      // destroying the socket before the response is flushed would surface
      // as ECONNRESET instead of a clean 413. Socket dies on "finish".
      res.once("finish", () => req.destroy());
      shield.audit.log({ verdict: "BODY_TOO_LARGE", ip, reason: `streamed body exceeded ${lim.maxBodyBytes} bytes mid-read (content-length absent or false)` });
      return json(res, 413, { jsonrpc: "2.0", id: null, error: { code: -32008, message: `request body too large (limit ${lim.maxBodyBytes} bytes)` } }, { "x-uta-shield": "BODY_TOO_LARGE" });
    }
    const rawBody = Buffer.concat(chunks).toString("utf8");

    let body;
    try { body = JSON.parse(rawBody); }
    catch {
      return json(res, 400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
    }

    const id = body?.id ?? null;
    const method = typeof body?.method === "string" ? body.method : null;

    // ── MCP method policy ──
    if (allowed && method && !allowed.has(method)) {
      return json(res, 403, { jsonrpc: "2.0", id, error: { code: -32601, message: `method not permitted by uta-shield policy: ${method}` } }, { "x-uta-shield": "METHOD_DENIED" });
    }

    const isCall = method === "tools/call";
    const tool = isCall ? body?.params?.name : method;

    // ── gateIn (identity → ACL → intel → rate limit) ──
    let gate;
    try {
      gate = shield.gateIn({ headers: req.headers, tool, args: isCall ? body?.params?.arguments : null, ip, rawBody });
    } catch (e) {
      shield.audit.log({ verdict: "PROXY_ERROR", tool, ip, reason: `gateIn threw: ${String(e?.message || e).slice(0, 200)}` });
      return json(res, 500, { jsonrpc: "2.0", id, error: { code: -32000, message: "internal error" } });
    }

    if (gate.verdict === "BLOCK_INTEL") {
      return json(res, 403, {
        jsonrpc: "2.0", id,
        error: { code: -32604, message: "blocked by uta-shield: known-bad indicator in tool-call arguments", data: { verdict: "BLOCK_INTEL", hits: gate.hits.map(h => ({ type: h.candidate_type, value: h.query, campaign: h.campaign.id })) } }
      }, { "x-uta-shield": "BLOCK_INTEL" });
    }
    if (gate.verdict === "RATE_LIMITED") {
      return json(res, 429, { jsonrpc: "2.0", id, error: { code: -32005, message: "rate limited by uta-shield", data: { retryAfterMs: gate.retryAfterMs } } }, { "x-uta-shield": "RATE_LIMITED", "retry-after": String(Math.ceil(gate.retryAfterMs / 1000)) });
    }
    if (gate.verdict === "REJECT_ANON" || gate.verdict === "REJECT_AUTH" || gate.verdict === "REJECT_FORBIDDEN") {
      const status = gate.verdict === "REJECT_FORBIDDEN" ? 403 : 401;
      const code = gate.verdict === "REJECT_FORBIDDEN" ? -32002 : -32001;
      return json(res, status, { jsonrpc: "2.0", id, error: { code, message: gate.reason || "rejected by identity policy" } }, { "x-uta-shield": gate.verdict });
    }

    // ── forward upstream (raw bytes preserved; timeout enforced) ──
    try {
      const r = await fetch(upstream + (req.url === "/" ? "" : req.url), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-uta-shield-agent": gate.agent || "anonymous",
          "x-uta-shield-verdict": gate.verdict
        },
        body: rawBody,
        signal: AbortSignal.timeout(lim.upstreamTimeoutMs)
      });
      const text = await r.text();
      const out = shield.gateOut({ text, agent: gate.agent, tool });

      if (out.blocked) {
        return json(res, 403, { jsonrpc: "2.0", id, error: out.error }, { "x-uta-shield": "OUT_BLOCKED" });
      }
      // v0.2.1: single source of truth — the core verdict travels in out.verdict
      // (OUT_OK | OUT_MASKED | OUT_REDACTED | OUTBOUND_INTEL). No recomputation.
      res.writeHead(r.status, {
        "content-type": r.headers.get("content-type") || "application/json",
        "x-uta-shield": out.verdict || "OUT_OK"
      });
      return res.end(out.text);
    } catch (e) {
      const timedOut = e?.name === "TimeoutError" || e?.name === "AbortError";
      shield.audit.log({ verdict: "UPSTREAM_ERROR", agent: gate.agent ?? null, ip, tool, reason: timedOut ? `upstream timeout after ${lim.upstreamTimeoutMs}ms` : "upstream unreachable" });
      const message = timedOut ? `upstream timeout after ${lim.upstreamTimeoutMs}ms` : "upstream unreachable";
      return json(res, timedOut ? 504 : 502, { jsonrpc: "2.0", id, error: { code: -32000, message } });
    }
  };
}
