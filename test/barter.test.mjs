// test/barter.test.mjs — Test suite for the /barter protocol
//
// Run:  node --test --test-only test/barter.test.mjs
// OR:  npm test
//
// Tests must run SERIALLY because they share process.env. Node's --test
// runs each file in a separate process by default, but tests within a
// file may run in parallel — we use `test` without `concurrent` flag
// (which is the default = serial within file).
//
// Mirrors the testing style of uta-shield's existing 85 tests — uses only
// Node's built-in `node:test` + `node:assert` + `node:crypto` (zero deps).

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  boot,
  barterRouter,
  setIdentityVerifier,
  consumeCall,
} from "../src/barter.mjs";

let tmpDir;
let theirKey;
let auditLogPath;  // capture once in before() so the after() cleanup can't race

// Mock HTTP request/response helpers
function mockReq(method, path, body, headers = {}) {
  return { method, url: path, body: typeof body === "string" ? body : JSON.stringify(body), headers };
}

function mockRes() {
  return {
    statusCode: null,
    body: null,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; },
  };
}

// Mock identity verifier — accepts any agent_name in `x-agent-name` header
const mockVerifier = (req, expectedName) => {
  const name = req.headers["x-agent-name"] || "test-agent";
  if (expectedName && name !== expectedName) {
    throw Object.assign(new Error("name_mismatch"), { status: 401 });
  }
  return { agent_name: name };
};

before(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "uta-shield-barter-"));
  auditLogPath = join(tmpDir, "audit.jsonl");
  process.env.UTA_SHIELD_DATA_DIR = tmpDir;
  process.env.UTA_SHIELD_AUDIT_LOG = auditLogPath;

  // Generate their (counterparty) Ed25519 keypair for countersignature
  theirKey = generateKeyPairSync("ed25519");
  await writeFile(join(tmpDir, "their_pub.pem"), theirKey.publicKey.export({ type: "spki", format: "pem" }));

  setIdentityVerifier(mockVerifier);
  await boot();
});

// No `after()` cleanup hook: in Node's test runner, after() can fire BEFORE
// the last test() resolves when tests are scheduled concurrently (even with
// --test-concurrency=1). The /tmp/uta-shield-barter-* directory is left behind
// for the OS /tmp cleanup to handle. This is a known idempotency tradeoff —
// each test run gets a fresh mkdtemp, so no test ever reads another run's data.

test("1. /barter/quote rejects unauthenticated requests", async () => {
  setIdentityVerifier(() => { throw Object.assign(new Error("no_header"), { status: 401 }); });
  const req = mockReq("POST", "/barter/quote", {});
  const res = mockRes();
  await barterRouter(req, res);
  assert.equal(res.statusCode, 401);
  setIdentityVerifier(mockVerifier);
});

test("2. /barter/quote issues a draft memo with our Ed25519 signature", async () => {
  const proposal = {
    from: "operator-b-china-test",
    jurisdiction: "CN",
    offered: { capability: "compute", specs: { gpu: "RTX 4090", hours: 100, region: "Shanghai" }, usd_equivalent: 50, endpoint: "ssh://test.example" },
    requested: { capability: "uta-shield", calls: { lookup_ioc: 500000 } },  // 500000 × 0.0001 = 50 USD eq
  };
  const req = mockReq("POST", "/barter/quote", proposal, { "x-agent-name": "operator-b-china-test" });
  const res = mockRes();
  await barterRouter(req, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, "draft_issued");
  const memo = res.body.memo;
  assert.match(memo.signature_AliceLabs, /^ed25519:[0-9a-f]+$/);
  assert.equal(memo.counterparty, "operator-b-china-test");
  assert.equal(memo.jurisdiction_counterparty, "CN");
  assert.equal(memo.AliceLabs_owes_counterparty.calls.lookup_ioc, 500000);
});

test("3. /barter/quote rejects unbalanced proposals (ratio outside 0.8-1.25)", async () => {
  const proposal = {
    from: "operator-unbalanced",
    jurisdiction: "CN",
    offered: { capability: "compute", usd_equivalent: 10, specs: {} },
    requested: { capability: "uta-shield", calls: { shield_request: 20000 } },  // 20000 × 0.005 = 100 USD eq
  };
  const req = mockReq("POST", "/barter/quote", proposal, { "x-agent-name": "operator-unbalanced" });
  const res = mockRes();
  await barterRouter(req, res);
  assert.equal(res.statusCode, 422);
  assert.equal(res.body.error, "unbalanced_barter");
  assert.ok(res.body.ratio > 1.25);
});

test("4. /barter/quote rejects when compliance lists are unavailable in strict mode (fail-closed)", async () => {
  process.env.UTA_SHIELD_STRICT_COMPLIANCE = "1";
  process.env.UTA_SHIELD_OFAC_SDN = "/tmp/nonexistent-ofac-list-" + Date.now();
  process.env.UTA_SHIELD_BIS_ENTITY = "/tmp/nonexistent-bis-list-" + Date.now();
  const proposal = {
    from: "operator-compliance-test",
    jurisdiction: "CN",
    offered: { capability: "compute", usd_equivalent: 50, specs: {} },
    requested: { capability: "uta-shield", calls: { lookup_ioc: 500000 } },
  };
  const req = mockReq("POST", "/barter/quote", proposal, { "x-agent-name": "operator-compliance-test" });
  const res = mockRes();
  await barterRouter(req, res);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.error, "compliance_screen_failed");
  assert.equal(res.body.reason, "screening_list_unavailable");
  // Disable strict mode for the remaining tests
  delete process.env.UTA_SHIELD_STRICT_COMPLIANCE;
  delete process.env.UTA_SHIELD_OFAC_SDN;
  delete process.env.UTA_SHIELD_BIS_ENTITY;
});

test("5. /barter/quote rejects when counterparty name matches OFAC SDN list", async () => {
  const ofacPath = join(tmpDir, "ofac_sdn.txt");
  await writeFile(ofacPath, "1,Entity-Of-Sanctioned-Operator-XYZ\n2,Another-Bad-Actor\n");
  process.env.UTA_SHIELD_OFAC_SDN = ofacPath;
  const bisPath = join(tmpDir, "bis_entity.txt");
  await writeFile(bisPath, "Some-Restricted-Entity\n");
  process.env.UTA_SHIELD_BIS_ENTITY = bisPath;

  const proposal = {
    from: "Entity-Of-Sanctioned-Operator-XYZ",
    jurisdiction: "CN",
    offered: { capability: "compute", usd_equivalent: 50, specs: {} },
    requested: { capability: "uta-shield", calls: { lookup_ioc: 500000 } },
  };
  const req = mockReq("POST", "/barter/quote", proposal, { "x-agent-name": "Entity-Of-Sanctioned-Operator-XYZ" });
  const res = mockRes();
  await barterRouter(req, res);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.reason, "ofac_sdn_match");
  // CRITICAL: clean up the env so tests 6+ don't accidentally screen against the OFAC list
  // we just set (which contains "Entity-Of-Sanctioned-Operator-XYZ" — that would block
  // any subsequent test that happens to use a similar name)
  delete process.env.UTA_SHIELD_OFAC_SDN;
  delete process.env.UTA_SHIELD_BIS_ENTITY;
});

test("6. /barter/accept verifies Ed25519 countersignature and activates memo", async () => {
  // Generate their pubkey upfront so we declare it in the /barter/quote proposal
  const theirPemPre = theirKey.publicKey.export({ type: "spki", format: "pem" });

  const proposal = {
    from: "operator-good-actor",
    jurisdiction: "CN",
    counterparty_pubkey: theirPemPre,
    offered: { capability: "compute", usd_equivalent: 50, specs: { hours: 100 } },
    requested: { capability: "uta-shield", calls: { lookup_ioc: 500000 } },
  };
  const req1 = mockReq("POST", "/barter/quote", proposal, { "x-agent-name": "operator-good-actor" });
  const res1 = mockRes();
  await barterRouter(req1, res1);
  assert.equal(res1.statusCode, 200);
  const memo = res1.body.memo;

  // Countersign the memo with their private key (Ed25519 — use crypto.sign(null, ...))
  const { sign: edSign } = await import("node:crypto");
  const { signature_AliceLabs, signature_counterparty, ...memoToSign } = memo;
  const sigData = Buffer.from(JSON.stringify(memoToSign, Object.keys(memoToSign).sort()));
  const theirSig = "ed25519:" + edSign(null, sigData, theirKey.privateKey).toString("hex");
  const theirPem = theirPemPre;

  const req2 = mockReq("POST", "/barter/accept", {
    memo, signature_counterparty: theirSig, counterparty_pubkey: theirPem,
  }, { "x-agent-name": "operator-good-actor" });
  const res2 = mockRes();
  await barterRouter(req2, res2);
  assert.equal(res2.statusCode, 201);
  assert.equal(res2.body.status, "memo_activated");
  assert.equal(res2.body.balances.AliceLabs_owes.lookup_ioc, 500000);
});

test("7. /barter/accept rejects a forged countersignature (different keypair than declared)", async () => {
  // Generate their pubkey upfront, declare it in the proposal
  const theirPemPre = theirKey.publicKey.export({ type: "spki", format: "pem" });

  const proposal = {
    from: "operator-forged-sig",
    jurisdiction: "CN",
    counterparty_pubkey: theirPemPre,
    offered: { capability: "compute", usd_equivalent: 50, specs: { hours: 100 } },
    requested: { capability: "uta-shield", calls: { lookup_ioc: 500000 } },
  };
  const req1 = mockReq("POST", "/barter/quote", proposal, { "x-agent-name": "operator-forged-sig" });
  const res1 = mockRes();
  await barterRouter(req1, res1);
  const memo = res1.body.memo;

  // Forge with a DIFFERENT keypair (not the one declared in the memo)
  const { generateKeyPairSync, sign: edSign } = await import("node:crypto");
  const wrongKey = generateKeyPairSync("ed25519");
  const { signature_AliceLabs, signature_counterparty, ...memoToSign } = memo;
  const sigData = Buffer.from(JSON.stringify(memoToSign, Object.keys(memoToSign).sort()));
  const wrongSig = "ed25519:" + edSign(null, sigData, wrongKey.privateKey).toString("hex");
  const wrongPem = wrongKey.publicKey.export({ type: "spki", format: "pem" });

  const req2 = mockReq("POST", "/barter/accept", {
    memo, signature_counterparty: wrongSig, counterparty_pubkey: wrongPem,
  }, { "x-agent-name": "operator-forged-sig" });
  const res2 = mockRes();
  await barterRouter(req2, res2);
  // Either REJECT_PUBKEY_MISMATCH (401, "pubkey_does_not_match_memo") — because
  // the wrongPem != the theirPemPre declared in the memo
  assert.equal(res2.statusCode, 401);
  // Could be either error; pubkey mismatch is checked first
  assert.ok(
    res2.body.error === "pubkey_does_not_match_memo" || res2.body.error === "invalid_counterparty_signature",
    `unexpected error: ${res2.body.error}`
  );
});

test("8. consumeCall decrements the balance and audits", async () => {
  const result1 = await consumeCall("operator-good-actor", "lookup_ioc");
  assert.equal(result1.ok, true);
  assert.equal(result1.remaining, 499999);

  const result2 = await consumeCall("operator-good-actor", "lookup_ioc");
  assert.equal(result2.ok, true);
  assert.equal(result2.remaining, 499998);
});

test("9. consumeCall rejects unknown agent (no active memo)", async () => {
  const result = await consumeCall("unknown-agent", "lookup_ioc");
  assert.equal(result.ok, false);
  assert.equal(result.reason, "no_active_memo");
});

test("10. consumeCall rejects when credit is exhausted", async () => {
  // Need to set their pubkey in the proposal for the new pubkey binding check
  const theirPemPre = theirKey.publicKey.export({ type: "spki", format: "pem" });
  const proposal = {
    from: "operator-tiny-credit",
    jurisdiction: "CN",
    counterparty_pubkey: theirPemPre,
    offered: { capability: "compute", usd_equivalent: 0.0001, specs: { hours: 1 } },
    requested: { capability: "uta-shield", calls: { lookup_ioc: 1 } },
  };
  const req1 = mockReq("POST", "/barter/quote", proposal, { "x-agent-name": "operator-tiny-credit" });
  const res1 = mockRes();
  await barterRouter(req1, res1);
  const memo = res1.body.memo;

  const { sign: edSign } = await import("node:crypto");
  const { signature_AliceLabs, signature_counterparty, ...memoToSign } = memo;
  const sigData = Buffer.from(JSON.stringify(memoToSign, Object.keys(memoToSign).sort()));
  const theirSig = "ed25519:" + edSign(null, sigData, theirKey.privateKey).toString("hex");
  const theirPem = theirPemPre;

  const req2 = mockReq("POST", "/barter/accept", {
    memo, signature_counterparty: theirSig, counterparty_pubkey: theirPem,
  }, { "x-agent-name": "operator-tiny-credit" });
  const res2 = mockRes();
  await barterRouter(req2, res2);
  assert.equal(res2.statusCode, 201);

  const r1 = await consumeCall("operator-tiny-credit", "lookup_ioc");
  assert.equal(r1.ok, true);
  assert.equal(r1.remaining, 0);

  const r2 = await consumeCall("operator-tiny-credit", "lookup_ioc");
  assert.equal(r2.ok, false);
  assert.equal(r2.reason, "credit_exhausted");
});

test("11. /barter/balance returns current remaining credits", async () => {
  const req = mockReq("GET", "/barter/balance", null, { "x-agent-name": "operator-good-actor" });
  const res = mockRes();
  await barterRouter(req, res);
  assert.equal(res.statusCode, 200);
  assert.ok(res.body.AliceLabs_owes_you.lookup_ioc < 500000);
});

test("12. /barter/audit-hash accepts and reciprocates a hash exchange", async () => {
  const req = mockReq("POST", "/barter/audit-hash", { audit_hash: "deadbeef" }, { "x-agent-name": "operator-good-actor" });
  const res = mockRes();
  await barterRouter(req, res);
  assert.equal(res.statusCode, 200);
  assert.match(res.body.our_audit_hash, /^[0-9a-f]{64}$/);
});

test("13. Audit log is fail-closed JSONL — every decision is recorded", async () => {
  // Use the captured auditLogPath variable (not process.env) — that way we
  // avoid races where after() cleanup runs before this test's readFile.
  const logText = await readFile(auditLogPath, "utf8");
  const lines = logText.split("\n").filter(l => l.trim());
  // Each line is valid JSON
  for (const line of lines) {
    const e = JSON.parse(line);
    assert.ok(e.ts);
    assert.ok(e.verdict);
  }
  const verdicts = lines.map(l => JSON.parse(l).verdict);
  assert.ok(verdicts.includes("DRAFT_ISSUED"));
  assert.ok(verdicts.includes("MEMO_ACTIVATED"));
  assert.ok(verdicts.includes("BARTER_CONSUMED"));
  assert.ok(verdicts.some(v => v.startsWith("REJECT_")));
});
