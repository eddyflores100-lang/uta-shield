#!/usr/bin/env node
// uta-shield CLI — zero-dependency firewall for MCP servers + PhishGuard intel.
//
//   uta-shield check <value>          offline IOC lookup against the bundled feed
//   uta-shield screen                 screen stdin text for indicators
//   uta-shield mcp                    run the PhishGuard MCP server (stdio)
//   uta-shield wrap --upstream URL    run a protective proxy in front of an MCP server
//   uta-shield verify-feed [path]     validate a feed file
//
// v0.2.0 `wrap` is FAIL-CLOSED by default: it refuses to start without either
// --keys-file (HMAC-verified agents) or --allow-anonymous (explicit opt-in).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { createServer } from "node:http";
import { Feed, validateFeed } from "../src/feed.mjs";
import { createShield, OUTBOUND_POLICIES } from "../src/shield.mjs";
import { createProxyHandler } from "../src/proxy.mjs";
import { startStdio } from "../src/mcp/server.mjs";

const VERSION = "0.2.1";
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

function loadJsonFile(path, what) {
  try {
    return JSON.parse(readFileSync(resolve(path), "utf8"));
  } catch (e) {
    console.error(`uta-shield: cannot read ${what} at ${path}: ${e.message}`);
    process.exit(2);
  }
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
      await startStdio({ feed, serverName: "uta-shield", serverVersion: VERSION });
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
      if (!upstream) {
        console.error(`usage: uta-shield wrap --upstream http://localhost:3001 [--port 8787]
  identity     --keys-file keys.json | --allow-anonymous | --require-identity
               --acl-file acl.json          per-tool authorization per agent
  outbound     --outbound-policy block|redact|log      (default: redact)
  proxy limits --max-body-bytes N | --upstream-timeout-ms N | --allow-methods "m1,m2" | "*"
               --trust-proxy                             (honor X-Forwarded-For)
  admin        --admin-token SECRET | UTA_SHIELD_ADMIN  (enable authenticated /audit; disabled otherwise)`);
        process.exit(2);
      }
      const port = Number(arg("--port", process.argv) || 8787);
      const feed = loadFeed(arg("--feed", process.argv));

      // ── identity configuration (fail-closed default) ──
      const keysFile = arg("--keys-file", process.argv);
      const envKeys = process.env.UTA_SHIELD_KEYS;
      let keys = null;
      if (keysFile) {
        keys = loadJsonFile(keysFile, "keys file");
        if (!keys || typeof keys !== "object" || Array.isArray(keys) || !Object.keys(keys).length) {
          console.error("uta-shield: --keys-file must be a non-empty JSON object { \"agent-name\": \"secret\", ... }");
          process.exit(2);
        }
      } else if (envKeys) {
        try {
          keys = JSON.parse(envKeys);
          if (!keys || typeof keys !== "object" || !Object.keys(keys).length) throw new Error("empty");
        } catch {
          console.error("uta-shield: UTA_SHIELD_KEYS env must be a non-empty JSON object");
          process.exit(2);
        }
      }
      const allowAnonymous = process.argv.includes("--allow-anonymous");
      const requireIdentity = keys ? !allowAnonymous : process.argv.includes("--require-identity");
      if (!keys && !allowAnonymous && !requireIdentity) {
        console.error("uta-shield: refusing to start (fail-closed default, v0.2.0).");
        console.error("  Configure verified identity:  --keys-file keys.json   ({ \"agent\": \"secret\", ... })");
        console.error("  Or explicitly opt out:        --allow-anonymous      (declared/anonymous allowed; rate limits keyed by IP)");
        process.exit(2);
      }
      const aclFile = arg("--acl-file", process.argv);
      let acl = null;
      if (aclFile) {
        acl = loadJsonFile(aclFile, "ACL file");
        if (!acl || typeof acl !== "object" || Array.isArray(acl)) {
          console.error("uta-shield: --acl-file must be a JSON object { \"agent\": [\"tool1\", \"*\"], ... }");
          process.exit(2);
        }
      }

      // ── outbound + proxy limits ──
      const policyRaw = (arg("--outbound-policy", process.argv) || "redact").toLowerCase();
      if (!OUTBOUND_POLICIES.includes(policyRaw)) {
        console.error(`uta-shield: --outbound-policy must be one of: ${OUTBOUND_POLICIES.join(", ")}`);
        process.exit(2);
      }
      const maxBodyBytes = Number(arg("--max-body-bytes", process.argv) || 1048576);
      const upstreamTimeoutMs = Number(arg("--upstream-timeout-ms", process.argv) || 30000);
      const allowMethodsRaw = arg("--allow-methods", process.argv);
      const allowMethods = allowMethodsRaw
        ? (allowMethodsRaw.trim() === "*" ? "*" : allowMethodsRaw.split(",").map(s => s.trim()).filter(Boolean))
        : null;
      if (maxBodyBytes <= 0 || upstreamTimeoutMs <= 0) {
        console.error("uta-shield: --max-body-bytes and --upstream-timeout-ms must be positive numbers");
        process.exit(2);
      }

      // ── /audit administration (v0.2.1: authenticated or disabled) ──
      const adminToken = arg("--admin-token", process.argv) || process.env.UTA_SHIELD_ADMIN || null;
      if (adminToken && String(adminToken).length < 16) {
        console.error("uta-shield: --admin-token / UTA_SHIELD_ADMIN must be at least 16 characters (it guards the audit trail)");
        process.exit(2);
      }

      const shield = createShield({
        feed,
        requireIdentity,
        identity: { keys, acl },
        outboundPolicy: policyRaw,
        dlp: { enabled: !process.argv.includes("--no-dlp") },
        billing: { enabled: true, prices: { "*": { amount: "0.001", unit: "per-call" } } }
      });

      const handler = createProxyHandler({
        shield, upstream,
        limits: { maxBodyBytes, upstreamTimeoutMs },
        allowMethods,
        trustProxy: process.argv.includes("--trust-proxy"),
        adminToken
      });

      const server = createServer(handler);
      server.headersTimeout = Math.min(10000, upstreamTimeoutMs);
      server.requestTimeout = upstreamTimeoutMs + 5000;
      server.keepAliveTimeout = 5000;
      server.on("clientError", (err, socket) => {
        try { socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"); } catch { /* socket gone */ }
      });
      server.listen(port, () => {
        console.error(`uta-shield v${VERSION} → wrapping ${upstream}`);
        console.error(`  proxy     http://localhost:${port}/  (point your agents here)`);
        console.error(`  health    http://localhost:${port}/health`);
        console.error(`  pricing   http://localhost:${port}/pricing  (x402-ready manifest)`);
        console.error(`  audit     ${adminToken ? `http://localhost:${port}/audit  (GET + x-uta-admin; AUTHENTICATED)` : "DISABLED — /audit returns 404 until you start with --admin-token (or UTA_SHIELD_ADMIN)"}`);
        console.error(`  identity  ${keys ? `hmac-verified (${Object.keys(keys).length} agent key(s))${acl ? ` · ACL: ${Object.keys(acl).length} agent(s)` : ""}` : (allowAnonymous ? "declared/anonymous (explicit opt-out)" : "declared required (--require-identity)")}`);
        console.error(`  outbound  policy=${policyRaw} · body≤${maxBodyBytes}B · upstream timeout ${upstreamTimeoutMs}ms · methods ${allowMethods === "*" ? "any" : (allowMethods ? allowMethods.join(",") : "default set")}`);
      });
      break;
    }
    default:
      console.error(`uta-shield v${VERSION} — provider-side firewall for MCP servers + PhishGuard intel
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
