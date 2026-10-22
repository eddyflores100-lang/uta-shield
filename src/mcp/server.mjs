// uta-shield — PhishGuard MCP server (zero-dependency MCP implementation).
// Implements the MCP stdio transport: newline-delimited JSON-RPC 2.0.
// Tools: lookup_ioc, check_url, screen_text, list_campaigns, feed_info.
//
// DATO ≠ INSTRUCCIÓN: every IOC string this server returns is DATA.
// Responses wrap verdicts as JSON inside MCP content[0].text.

import { Feed, urlHeuristics } from "../feed.mjs";
import { maskSensitive } from "../dlp.mjs";

const PROTOCOL_VERSION = "2025-06-18";

export const TOOLS = [
  {
    name: "lookup_ioc",
    description: "Look up a domain, URL, IP, email, sha256, filename or filepath in the PhishGuard threat feed (real campaigns with documented takedowns). Returns a verdict with evidence — never fetches or executes anything.",
    inputSchema: {
      type: "object",
      properties: { value: { type: "string", description: "indicator to check (domain, url, ip, email, sha256, filename, filepath)" } },
      required: ["value"]
    }
  },
  {
    name: "check_url",
    description: "Screen a URL before an agent visits it: feed match + advisory heuristics (abuse-heavy TLD, nesting, userinfo tricks). Advisory output only — final call stays with the calling agent's policy.",
    inputSchema: {
      type: "object",
      properties: { url: { type: "string" } },
      required: ["url"]
    }
  },
  {
    name: "screen_text",
    description: "Scan a block of text (email body, web content, tool output) for known-bad indicators (phishing domains, C2 urls, payload hashes). Returns hits with campaign evidence and masked secrets summary.",
    inputSchema: {
      type: "object",
      properties: { text: { type: "string" } },
      required: ["text"]
    }
  },
  {
    name: "list_campaigns",
    description: "List threat campaigns in the feed with status (domains down / C2 live) and MITRE ATT&CK techniques.",
    inputSchema: { type: "object", properties: {} }
  },
  {
    name: "feed_info",
    description: "Feed metadata: schema, version, IOC counts by type, license.",
    inputSchema: { type: "object", properties: {} }
  }
];

export function createMcpHandler({ feed, serverName = "uta-shield", serverVersion = "0.2.0", mask = true }) {
  if (!(feed instanceof Feed)) throw new Error("createMcpHandler requires a Feed instance");

  function toolResult(obj) {
    const json = JSON.stringify(obj, null, 2);
    const safe = mask ? maskSensitive(json).masked : json;
    return { content: [{ type: "text", text: safe }] };
  }

  async function dispatch(name, args = {}) {
    switch (name) {
      case "lookup_ioc": {
        if (!args.value) throw new Error("missing 'value'");
        const v = feed.lookup(String(args.value));
        return toolResult(v.matched
          ? { verdict: "MATCH", how: v.how, indicator: v.query, ioc: v.ioc, campaign: v.campaign, note: "indicator is part of a documented campaign; treat as hostile infrastructure" }
          : { verdict: "NO_MATCH", indicator: args.value, note: "not in feed — absence is not innocence; combine heuristics and domain-age checks" });
      }
      case "check_url": {
        if (!args.url) throw new Error("missing 'url'");
        const v = feed.lookup(String(args.url));
        return toolResult({
          verdict: v.matched ? "BLOCK" : "REVIEW",
          url: String(args.url),
          feed: v.matched ? { how: v.how, ioc: v.ioc, campaign: v.campaign } : null,
          heuristics: v.matched ? [] : urlHeuristics(String(args.url)),
          note: v.matched
            ? "URL belongs to a documented phishing campaign"
            : "no feed match; heuristics are advisory only"
        });
      }
      case "screen_text": {
        if (typeof args.text !== "string") throw new Error("missing 'text'");
        const r = feed.screenText(args.text);
        return toolResult({
          verdict: r.hits.length ? "HITS" : "CLEAN",
          scanned_indicators: r.scanned,
          hits: r.hits.map(h => ({ candidate_type: h.candidate_type, how: h.how, value: h.query, ioc: h.ioc, campaign: h.campaign }))
        });
      }
      case "list_campaigns":
        return toolResult(feed.campaigns.map(c => ({
          id: c.id, name: c.name, first_seen: c.first_seen || null,
          status: c.status || null, mitre: c.mitre || [],
          iocs: c.iocs.length, refs: c.refs || []
        })));
      case "feed_info":
        return toolResult(feed.stats());
      default:
        throw new Error(`unknown tool: ${name}`);
    }
  }

  // Returns a JSON-RPC response object (or null for notifications).
  return async function handle(msg) {
    if (!msg || typeof msg !== "object") return null;
    const { id, method, params } = msg;
    const notify = id === undefined || id === null;

    if (method === "initialize") {
      return notify ? null : {
        jsonrpc: "2.0", id,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: serverName, version: serverVersion }
        }
      };
    }
    if (method === "ping") return notify ? null : { jsonrpc: "2.0", id, result: {} };
    if (typeof method === "string" && method.startsWith("notifications/")) return null;

    if (method === "tools/list") {
      return notify ? null : { jsonrpc: "2.0", id, result: { tools: TOOLS } };
    }
    if (method === "tools/call") {
      try {
        const result = await dispatch(params?.name, params?.arguments || {});
        return notify ? null : { jsonrpc: "2.0", id, result };
      } catch (e) {
        return notify ? null : {
          jsonrpc: "2.0", id,
          error: { code: -32000, message: String(e.message || e), data: { tool: params?.name } }
        };
      }
    }
    return notify ? null : { jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } };
  };
}

// stdio transport: one JSON-RPC message per line.
export async function startStdio({ feed, serverName, serverVersion }) {
  const handle = createMcpHandler({ feed, serverName, serverVersion });
  const { createInterface } = await import("node:readline");
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let msg;
    try { msg = JSON.parse(trimmed); } catch {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }) + "\n");
      continue;
    }
    const res = await handle(msg);
    if (res) process.stdout.write(JSON.stringify(res) + "\n");
  }
}
