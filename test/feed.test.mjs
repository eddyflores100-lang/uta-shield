import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Feed, extractIndicators, validateFeed } from "../src/feed.mjs";

const feed = Feed.fromFile(join(dirname(fileURLToPath(import.meta.url)), "..", "feed", "iocs.json"));

test("feed loads and validates bundled campaign", () => {
  const s = feed.stats();
  assert.equal(s.feed_schema, "pg/1");
  assert.equal(s.campaigns, 1);
  assert.ok(s.iocs_total >= 23);
  assert.ok(validateFeed(feed.raw).ok);
});

test("domain exact + subdomain match", () => {
  assert.equal(feed.lookup("taikotalent.xyz").matched, true);
  assert.equal(feed.lookup("evil.gaganata.ink").matched, true, "subdomain of C2 must match");
  assert.equal(feed.lookup("taiko.xyz").matched, false, "legit domain must NOT match");
  assert.equal(feed.lookup("notataikotalent.xyz").matched, false, "suffix collision must not match");
});

test("url prefix + url-host match", () => {
  assert.equal(feed.lookup("https://taikotalent.xyz/verify_m?x=1").matched, true);
  assert.equal(feed.lookup("https://api.gaganata.ink/guard-launcher-result").matched, true);
  assert.equal(feed.lookup("http://anything.gaganata.ink/path").matched, true);
});

test("ip and sha256 exact match", () => {
  assert.equal(feed.lookup("193.160.32.10").matched, true);
  assert.equal(feed.lookup("c7c22e322c17bda8198257342d4034af6250a5c433242461b870879ba9aa285d").matched, true);
  assert.equal(feed.lookup("192.168.1.1").matched, false);
});

test("email, subject, filename, wildcard filepath, mutex", () => {
  assert.equal(feed.lookup("josephquintana@hr.taikotalent.xyz").matched, true);
  assert.equal(feed.lookup("engineering opening - taiko").matched, true, "subject case-insensitive");
  assert.equal(feed.lookup("v.cmd").matched, true);
  assert.equal(feed.lookup("/var/tmp/.kdm.3f9a1").matched, true, "wildcard second stage");
  assert.equal(feed.lookup("deepfake_guard").matched, true);
});

test("every verdict carries campaign evidence", () => {
  const v = feed.lookup("api.gaganata.ink");
  assert.equal(v.campaign.id, "taikotalent-2026-10");
  assert.ok(v.ioc.context);
});

test("extractIndicators pulls urls/ips/emails/sha256 from raw text", () => {
  const t = "contact https://taikotalent.xyz/verify_m or josephquintana@hr.taikotalent.xyz from 193.160.32.10 hash c7c22e322c17bda8198257342d4034af6250a5c433242461b870879ba9aa285d";
  const cands = extractIndicators(t);
  const types = new Set(cands.map(c => c.type));
  for (const want of ["url", "domain", "ip", "email-addr", "sha256"]) assert.ok(types.has(want), `missing ${want}`);
});

test("screenText finds hostile links inside innocent-looking text", () => {
  const r = feed.screenText("Hi! Congrats on your offer. Please verify: https://taikotalent.xyz/verify_w — the anti-bot check runs in your terminal.");
  assert.ok(r.hits.length >= 1);
  assert.equal(r.hits[0].campaign.id, "taikotalent-2026-10");
});
