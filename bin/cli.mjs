#!/usr/bin/env node
// uta-shield CLI — zero-dependency firewall for MCP servers + PhishGuard intel.
//
//   uta-shield check <value>          offline IOC lookup against the bundled feed
//   uta-shield screen                 screen stdin text for indicators
//   uta-shield mcp                    run the PhishGuard MCP server (stdio)
//   uta-shield wrap --upstream URL    run a protective proxy in front of an MCP server
//   uta-shield verify-feed [path]     validate a feed file

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { createServer } from "node:http";
import { Feed, validateFeed } from "../src/feed.mjs";
import { createShield } from "../src/shield.mjs";
import { startStdio } from "../src/mcp/server.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BUNDLED_FEED = join(__dirname, "..", "feed", "iocs.json");

function loadFeed(path) {
  const p = resolve(path || BUNDLED_FEED);
  return Feed.fromFile(p);
}

function arg(name, argv) {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : null;
}

const [cmd, ...rest] = process.argv.slice(2);

try {
  switch (cmd) {
    case "check": {
      const value = rest.find(r => !r.startsWith("--"));
      if (!value) { console.error("usage: uta-shield check <domain|url|ip|sha256|email>"); process.exit(2); }
      const feed = loadFeed(arg("--feed", process.argv));
      const v = feed.lookup(value);
      console.log(JSON.stringify(v.matched
        ? { verdict: "MATCH", how: v.how, indicator: v.query, ioc: v.ioc, campaign: v.campaign }
        : { verdict: "NO_MATCH", indicator: value }, null, 2));
      process.exit(v.matched ? 1 : 0); // exit 1 on match → scriptable blocklists
      break;
    }
    case "screen": {
      const chunks = [];
      for await (const c of process.stdin) chunks.push(c);
      const text = Buffer.concat(chunks).toString("utf8");
      const feed = loadFeed(arg("--feed", process.argv));
      const r = feed.screenText(text);
      console.log(JSON.stringify({ verdict: r.hits.length ? "HITS" : "CLEAN", ...r }, null, 2));
      process.exit(r.hits.length ? 1 : 0);
      break;
    }
    case "mcp": {
      const feed = loadFeed(arg("--feed", process.argv));
      await startStdio({ feed, serverName: "uta-shield", serverVersion: "0.1.0" });
      break;
    }
    case "verify-feed": {
      const path = rest.find(r => !r.startsWith("--")) || BUNDLED_FEED;
      const json = JSON.parse(readFileSync(resolve(path), "utf8"));
      const v = validateFeed(json);
      if (!v.ok) { console.error("INVALID FEED:\n- " + v.errors.join("\n- ")); process.exit(2); }
      const feed = new Feed(json);
      console.log(JSON.stringify({ ok: true, path, ...feed.stats() }, null, 2));
      break;
    }
    case "wrap": {
      const upstream = arg("--upstream", process.argv);
      if (!upstream) { console.error("usage: uta-shield wrap --upstream http://localhost:3001 [--port 8787] [--require-identity]"); process.exit(2); }
      const port = Number(arg("--port", process.argv) || 8787);
      const feed = loadFeed(arg("--feed", process.argv));
      const shield = createShield({
        feed,
        requireIdentity: process.argv.includes("--require-identity"),
        billing: { enabled: true, prices: { "*": { amount: "0.001", unit: "per-call" } } }
      });
      const server = createServer(async (req, res) => {
        // management endpoints
        if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
          res.writeHead(200, { "content-type": "application/json" });
          return res.end(JSON.stringify(shield.health(), null, 2));
        }
        if (req.method === "GET" && req.url === "/pricing") {
          res.writeHead(200, { "content-type": "application/json" });
          return res.end(JSON.stringify(shield.billing.x402Manifest(), null, 2));
        }
        if (req.method === "GET" && req.url === "/audit") {
          res.writeHead(200, { "content-type": "application/json" });
          return res.end(JSON.stringify(shield.audit.last(20), null, 2));
        }
        if (req.method !== "POST") { res.writeHead(405); return res.end(); }

        const chunks = [];
        for await (const c of req) chunks.push(c);
        let body;
        try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
        catch { res.writeHead(400); return res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } })); }

        const id = body?.id ?? null;
        const isCall = body?.method === "tools/call";
        const tool = isCall ? body?.params?.name : body?.method;

        const gate = shield.gateIn({
          headers: req.headers,
          tool,
          args: isCall ? body?.params?.arguments : null
        });
        if (gate.verdict === "BLOCK_INTEL") {
          res.writeHead(403, { "content-type": "application/json", "x-uta-shield": "BLOCK_INTEL" });
          return res.end(JSON.stringify({
            jsonrpc: "2.0", id,
            error: { code: -32604, message: "blocked by uta-shield: known-bad indicator in tool-call arguments", data: { verdict: "BLOCK_INTEL", hits: gate.hits.map(h => ({ type: h.candidate_type, value: h.query, campaign: h.campaign.id })) } }
          }));
        }
        if (gate.verdict === "RATE_LIMITED") {
          res.writeHead(429, { "content-type": "application/json", "x-uta-shield": "RATE_LIMITED", "retry-after": Math.ceil(gate.retryAfterMs / 1000) });
          return res.end(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32005, message: "rate limited by uta-shield", data: { retryAfterMs: gate.retryAfterMs } } }));
        }
        if (gate.verdict === "REJECT_ANON") {
          res.writeHead(401, { "content-type": "application/json", "x-uta-shield": "REJECT_ANON" });
          return res.end(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32001, message: "agent identity required (x-agent-name header)" } }));
        }

        // forward upstream
        try {
          const r = await fetch(upstream + (req.url === "/" ? "" : req.url), {
            method: "POST",
            headers: { "content-type": "application/json", "x-uta-shield-agent": gate.agent || "anonymous", "x-uta-shield-verdict": gate.verdict },
            body: JSON.stringify(body)
          });
          const text = await r.text();
          const out = shield.gateOut({ text });
          res.writeHead(r.status, {
            "content-type": r.headers.get("content-type") || "application/json",
            "x-uta-shield": out.dlp.length ? "OUT_MASKED" : "OUT_OK"
          });
          return res.end(out.text);
        } catch (e) {
          res.writeHead(502, { "content-type": "application/json" });
          return res.end(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message: `upstream unreachable: ${e.message}` } }));
        }
      });
      server.listen(port, () => {
        console.error(`uta-shield v0.1.0 → wrapping ${upstream}`);
        console.error(`  proxy     http://localhost:${port}/  (point your agents here)`);
        console.error(`  health    http://localhost:${port}/health`);
        console.error(`  pricing   http://localhost:${port}/pricing  (x402-ready manifest)`);
        console.error(`  audit     http://localhost:${port}/audit`);
      });
      break;
    }
    default:
      console.error(`uta-shield v0.1.0 — provider-side firewall for MCP servers + PhishGuard intel
usage:
  uta-shield check <value>            offline IOC lookup (exit 1 on match)
  uta-shield screen < feed.txt        screen text for indicators
  uta-shield mcp                      PhishGuard MCP server (stdio)
  uta-shield wrap --upstream URL      protective proxy in front of an MCP server
  uta-shield verify-feed [path]       validate a feed file`);
      process.exit(cmd ? 2 : 0);
  }
} catch (e) {
  console.error("uta-shield error:", e.message);
  process.exit(2);
}
