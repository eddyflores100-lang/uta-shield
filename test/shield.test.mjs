import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Feed } from "../src/feed.mjs";
import { createShield } from "../src/shield.mjs";

const feed = Feed.fromFile(join(dirname(fileURLToPath(import.meta.url)), "..", "feed", "iocs.json"));

function mk(opts = {}) {
  return createShield({ feed, ratelimit: { ratePerMin: 60, burst: 100 }, ...opts });
}

test("blocks tool calls whose arguments carry hostile IOCs", () => {
  const s = mk();
  const g = s.gateIn({
    headers: { "x-agent-name": "helper-bot" },
    tool: "send_email",
    args: { to: "victim@corp.com", body: "verify at https://taikotalent.xyz/verify_m" }
  });
  assert.equal(g.verdict, "BLOCK_INTEL");
  assert.equal(g.hits[0].campaign.id, "taikotalent-2026-10");
});

test("allows benign calls and meters them", () => {
  const s = mk({ billing: { enabled: true, prices: { search_contacts: { amount: "0.001" } } } });
  const g = s.gateIn({ headers: { "x-agent-name": "helper-bot" }, tool: "search_contacts", args: { q: "acme corp" } });
  assert.equal(g.verdict, "ALLOW");
  assert.ok(g.charge);
});

test("rejects anonymous callers when requireIdentity=true", () => {
  const s = mk({ requireIdentity: true });
  const g = s.gateIn({ headers: {}, tool: "search_contacts", args: {} });
  assert.equal(g.verdict, "REJECT_ANON");
  const g2 = s.gateIn({ headers: { "x-agent-name": "known-agent" }, tool: "search_contacts", args: {} });
  assert.equal(g2.verdict, "ALLOW");
});

test("rate-limits repeated calls per agent+tool", () => {
  const s = mk({ ratelimit: { ratePerMin: 1, burst: 2 } });
  const call = () => s.gateIn({ headers: { "x-agent-name": "hammer-bot" }, tool: "search_contacts", args: { q: "x" } });
  assert.equal(call().verdict, "ALLOW");
  assert.equal(call().verdict, "ALLOW");
  assert.equal(call().verdict, "RATE_LIMITED");
});

test("gateOut masks PII in upstream responses", () => {
  const s = mk();
  const out = s.gateOut({ json: { contact: "jane@corp.com", phone_note: "sk-realkey1234567890abcd" } });
  assert.equal(out.json.contact, "[EMAIL_REDACTED]");
  assert.ok(JSON.stringify(out.json).includes("[API_KEY_REDACTED]"));
  assert.ok(out.dlp.length >= 1);
});

test("audit log records decisions: indicator + campaign yes, raw arguments no", () => {
  const s = mk();
  s.gateIn({
    headers: { "x-agent-name": "helper-bot" }, tool: "send_email",
    args: { body: "evil link https://taikotalent.xyz/verify_w" }
  });
  const evts = s.audit.last(5);
  assert.ok(evts.length >= 1);
  const blob = JSON.stringify(evts);
  assert.ok(!blob.includes("evil link"), "audit must not echo raw argument context");
  assert.ok(blob.includes("BLOCK_INTEL"));
  assert.ok(blob.includes("taikotalent-2026-10"), "campaign id present for triage");
  assert.ok(blob.includes("https://taikotalent.xyz/verify_w"), "matched indicator value present (SIEM standard)");
});
