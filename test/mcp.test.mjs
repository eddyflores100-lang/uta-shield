import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Feed } from "../src/feed.mjs";
import { createMcpHandler, TOOLS } from "../src/mcp/server.mjs";

const feed = Feed.fromFile(join(dirname(fileURLToPath(import.meta.url)), "..", "feed", "iocs.json"));
const handle = createMcpHandler({ feed });

test("MCP handshake returns protocol version and server info", async () => {
  const res = await handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.equal(res.result.protocolVersion, "2025-06-18");
  assert.equal(res.result.serverInfo.name, "uta-shield");
});

test("notifications produce no response", async () => {
  const res = await handle({ jsonrpc: "2.0", method: "notifications/initialized" });
  assert.equal(res, null);
});

test("tools/list exposes the 5 PhishGuard tools", async () => {
  const res = await handle({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  assert.equal(res.result.tools.length, TOOLS.length);
  assert.deepEqual(res.result.tools.map(t => t.name).sort(), [
    "check_url", "feed_info", "list_campaigns", "lookup_ioc", "screen_text"
  ]);
  for (const t of res.result.tools) {
    assert.ok(t.description.length > 40, "descriptions must be agent-usable");
    assert.ok(t.inputSchema, "each tool declares inputSchema");
  }
});

test("tools/call lookup_ioc returns MATCH with evidence", async () => {
  const res = await handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "lookup_ioc", arguments: { value: "gaganata.ink" } } });
  const obj = JSON.parse(res.result.content[0].text);
  assert.equal(obj.verdict, "MATCH");
  assert.equal(obj.campaign.id, "taikotalent-2026-10");
});

test("tools/call check_url blocks campaign URL and reviews unknown ones", async () => {
  const blocked = await handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "check_url", arguments: { url: "https://taikotalent.xyz/verify_m" } } });
  assert.equal(JSON.parse(blocked.result.content[0].text).verdict, "BLOCK");

  const review = await handle({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "check_url", arguments: { url: "https://suspicious-gift-cards.xyz/claim" } } });
  const obj = JSON.parse(review.result.content[0].text);
  assert.equal(obj.verdict, "REVIEW");
  assert.ok(obj.heuristics.length >= 1, "advisory heuristics present");
});

test("tools/call screen_text finds indicators in an email body", async () => {
  const res = await handle({
    jsonrpc: "2.0", id: 6, method: "tools/call",
    params: { name: "screen_text", arguments: { text: "Congrats! Run the check at https://taikotalent.xyz/verify_m (from josephquintana@hr.taikotalent.xyz)" } }
  });
  const obj = JSON.parse(res.result.content[0].text);
  assert.equal(obj.verdict, "HITS");
  assert.ok(obj.hits.length >= 2);
});

test("unknown tool and unknown method produce JSON-RPC errors", async () => {
  const e1 = await handle({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "nope" } });
  assert.equal(e1.error.code, -32000);
  const e2 = await handle({ jsonrpc: "2.0", id: 8, method: "resources/list" });
  assert.equal(e2.error.code, -32601);
});
