// uta-shield v0.2.0 — outbound IOC policy tests (the v0.1.0 gap: detect-only).
// gateOut must BLOCK, REDACT or LOG per explicit policy — never silently pass.

import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Feed } from "../src/feed.mjs";
import { createShield } from "../src/shield.mjs";

const feed = Feed.fromFile(join(dirname(fileURLToPath(import.meta.url)), "..", "feed", "iocs.json"));
const DIRTY = "DNS records for the new tenant: api.gaganata.ink (C2, live)";
const CLEAN_JSON = { note: "reach me at jane@corp.com", key: "sk-realkey1234567890abcd" };

test("default outbound policy is redact: IOC neutralized, response flows", () => {
  const s = createShield({ feed });
  const out = s.gateOut({ text: DIRTY });
  assert.equal(out.policy, "redact");
  assert.equal(out.blocked, false);
  assert.ok(!out.text.includes("gaganata.ink"), "raw C2 domain must not survive");
  assert.ok(out.text.includes("[IOC_REDACTED:taikotalent-2026-10/"), "evidence placeholder present");
  assert.ok(out.intel.hits.length >= 1);
  assert.ok(out.redacted.length >= 1);
});

test("policy=block withholds the response and returns a JSON-RPC error", () => {
  const s = createShield({ feed, outboundPolicy: "block" });
  const out = s.gateOut({ text: DIRTY });
  assert.equal(out.blocked, true);
  assert.equal(out.text, null);
  assert.equal(out.error.code, -32006);
  assert.equal(out.error.data.verdict, "OUT_BLOCKED");
  assert.ok(out.error.data.hits.length >= 1, "client gets evidence, not content");
  const last = s.audit.last(1)[0];
  assert.equal(last.verdict, "OUT_BLOCKED");
});

test("policy=block also withholds dirty JSON responses", () => {
  const s = createShield({ feed, outboundPolicy: "block" });
  const out = s.gateOut({ json: { host: "api.gaganata.ink" } });
  assert.equal(out.blocked, true);
  assert.equal(out.json, null);
  assert.equal(out.error.code, -32006);
});

test("policy=log passes the response through untouched but audits it", () => {
  const s = createShield({ feed, outboundPolicy: "log" });
  const out = s.gateOut({ text: DIRTY });
  assert.equal(out.blocked, false);
  assert.equal(out.text, DIRTY, "log policy is explicit pass-through");
  const last = s.audit.last(1)[0];
  assert.equal(last.verdict, "OUTBOUND_INTEL");
});

test("redact policy works inside JSON responses (stringify → redact → parse)", () => {
  const s = createShield({ feed, outboundPolicy: "redact" });
  const out = s.gateOut({ json: { results: [{ host: "api.gaganata.ink", note: "live C2" }] } });
  assert.equal(out.blocked, false);
  const blob = JSON.stringify(out.json);
  assert.ok(!blob.includes("gaganata.ink"));
  assert.ok(blob.includes("[IOC_REDACTED:taikotalent-2026-10/"));
});

test("DLP masking applies under every policy, including clean responses", () => {
  for (const policy of ["block", "redact", "log"]) {
    const s = createShield({ feed, outboundPolicy: policy });
    const out = s.gateOut({ json: CLEAN_JSON });
    assert.equal(out.blocked, false, `${policy}: clean content must flow`);
    const blob = JSON.stringify(out.json);
    assert.ok(blob.includes("[EMAIL_REDACTED]"), `${policy}: email masked`);
    assert.ok(blob.includes("[API_KEY_REDACTED]"), `${policy}: api key masked`);
    assert.ok(out.dlp.length >= 2, `${policy}: findings aggregated`);
  }
});

test("clean responses under redact policy pass through unmodified", () => {
  const s = createShield({ feed, outboundPolicy: "redact" });
  const clean = "quarterly results are on track; see dashboard";
  const out = s.gateOut({ text: clean });
  assert.equal(out.text, clean);
  assert.deepEqual(out.redacted, []);
});

test("invalid outboundPolicy is rejected at construction", () => {
  assert.throws(() => createShield({ feed, outboundPolicy: "yolo" }), /invalid outboundPolicy/);
});
