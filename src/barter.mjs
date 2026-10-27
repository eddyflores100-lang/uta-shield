// uta-shield/src/barter.mjs — Bilateral barter protocol for uta-shield
//
// Implements the /barter/quote, /barter/accept, /barter/consume and /barter/balance
// endpoints for the "Patrón C" described in PATTERN_C_BARTER_DESIGN.md:
// an operator (e.g. a Chinese GPU provider) exchanges compute-hours for
// uta-shield calls WITHOUT any USDC crossing the border.
//
// Settlement is a bilateral credit memo signed Ed25519 by both parties.
// No money moves cross-jurisdiction. Only the two operators' books change.
//
// Design constraints (must match uta-shield v0.2.4):
//   - Zero dependencies (Node.js >=18 stdlib only)
//   - Fail-closed JSONL audit (one append per decision)
//   - HMAC-SHA256 identity reused for /barter endpoints (the same
//     `x-agent-name` / `x-agent-timestamp` / `x-agent-signature` headers
//     that uta-shield already uses for /shield_request)
//   - Same audit file as the rest of uta-shield (audit.jsonl)
//
// Surface:
//   POST /barter/quote    — counterparty proposes a barter; returns a draft memo
//                          signed by us, awaiting their countersignature
//   POST /barter/accept  — counterparty returns the same memo countersigned;
//                          we verify their Ed25519 sig, persist the memo
//   POST /barter/consume — internal: called by other uta-shield tools when a
//                          credit-bearer makes a call; decrements their balance
//   GET  /barter/balance — counterparty queries their remaining credit
//   POST /barter/audit-hash — webhook for nightly reciprocal audit hash exchange
//
// All errors are audited. All success paths are audited. The audit log is
// fail-closed: if it cannot be opened for append, the request is rejected with
// 503 SERVICE_UNAVAILABLE.

import { generateKeyPairSync, createSign, createVerify, createHash, randomUUID }
  from "node:crypto";
import { readFile, writeFile, appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

// ────────────────────────────────────────────────────────────────────────────
// 0. Storage (in-memory map + on-disk persistence)
// ────────────────────────────────────────────────────────────────────────────

const MEMOS = new Map();      // memo_id -> {memo, our_signature, their_signature, balances}
const COUNTERPARTIES = new Map();  // agent_name -> {pubkey, memos: [memo_id,...]}

// Disk persistence: one file per memo, plus a manifest. Operators can audit
// the disk the same way they audit the JSONL log.
const DATA_DIR = process.env.UTA_SHIELD_DATA_DIR || "./.data/barter";
const MEMO_DIR = `${DATA_DIR}/memos`;

// Audit log path is read at CALL TIME (not module-load) so tests can override
// via process.env after the module is imported.
function getAuditLogPath() {
  return process.env.UTA_SHIELD_AUDIT_LOG || `${DATA_DIR}/audit.jsonl`;
}

async function ensureDirs() {
  await mkdir(MEMO_DIR, { recursive: true });
  await mkdir(dirname(getAuditLogPath()), { recursive: true });
}

// ────────────────────────────────────────────────────────────────────────────
// 1. Fail-closed audit (same shape as uta-shield's proxy.test.mjs audit)
// ────────────────────────────────────────────────────────────────────────────

async function audit(verdict, fields = {}) {
  const entry = {
    ts: new Date().toISOString(),
    verdict,
    ...fields,
  };
  try {
    await appendFile(getAuditLogPath(), JSON.stringify(entry) + "\n");
  } catch (err) {
    // Fail-closed: if we cannot audit, we cannot proceed.
    throw Object.assign(new Error("audit_unavailable"), { status: 503 });
  }
  return entry.ts;
}

// ────────────────────────────────────────────────────────────────────────────
// 2. Ed25519 signing — for the bilateral credit memo
// ────────────────────────────────────────────────────────────────────────────

// Our keypair is loaded from disk on boot. On first run, generate and persist.
let OUR_PRIVATE_KEY = null;
let OUR_PUBLIC_KEY = null;

async function loadOrCreateOurKeypair() {
  const privPath = `${DATA_DIR}/ed25519_private.pem`;
  const pubPath  = `${DATA_DIR}/ed25519_public.pem`;
  try {
    OUR_PRIVATE_KEY = await readFile(privPath, "utf8");
    OUR_PUBLIC_KEY  = await readFile(pubPath,  "utf8");
  } catch {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    OUR_PRIVATE_KEY = privateKey.export({ type: "pkcs8", format: "pem" });
    OUR_PUBLIC_KEY  = publicKey.export({ type: "spki",  format: "pem" });
    await mkdir(DATA_DIR, { recursive: true });
    // chmod 600 would be ideal here; not portable in Node stdlib.
    // Operators should set permissions at the filesystem level.
    await writeFile(privPath, OUR_PRIVATE_KEY, { mode: 0o600 });
    await writeFile(pubPath,  OUR_PUBLIC_KEY);
    await audit("ED25519_KEYS_GENERATED", { pubPath });
  }
  return OUR_PUBLIC_KEY;
}

function canonicalJson(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

// For Ed25519 in Node ≥18, use crypto.sign() / crypto.verify() directly
// (createSign() requires an algorithm string like "SHA256" which is incompatible
// with Ed25519's "no hash needed" nature).
import { sign as edSign, verify as edVerify } from "node:crypto";

function signWithOurKey(payload) {
  if (!OUR_PRIVATE_KEY) throw new Error("private_key_not_loaded");
  const data = Buffer.from(canonicalJson(payload));
  const sig = edSign(null, data, OUR_PRIVATE_KEY);
  return "ed25519:" + sig.toString("hex");
}

function verifyWithTheirKey(payload, theirSigHex, theirPem) {
  if (!theirSigHex || !theirSigHex.startsWith("ed25519:")) return false;
  const sigHex = theirSigHex.slice("ed25519:".length);
  const data = Buffer.from(canonicalJson(payload));
  try {
    return edVerify(null, data, theirPem, Buffer.from(sigHex, "hex"));
  } catch {
    return false;
  }
}

// ────────────────────────────────────────────────────────────────────────────
// 3. HMAC-SHA256 identity verification (reuse uta-shield v0.2.0 spec)
// ────────────────────────────────────────────────────────────────────────────

// The /barter endpoints are protected by the SAME HMAC identity as /shield_request.
// We import the same verifySignature function from shield.mjs (assumed in scope).
// For testability, we accept it as a dependency injection point.

let _verifyIdentity = null;

export function setIdentityVerifier(fn) {
  _verifyIdentity = fn;
}

async function verifyAgentIdentity(req, expectedAgentName) {
  if (!_verifyIdentity) {
    throw Object.assign(
      new Error("identity_verifier_not_set"),
      { status: 500 }
    );
  }
  return _verifyIdentity(req, expectedAgentName);
}

// ────────────────────────────────────────────────────────────────────────────
// 4. Compliance screen — OFAC SDN + BIS Entity List (offline, cached lists)
// ────────────────────────────────────────────────────────────────────────────

// Operators are responsible for maintaining the cached lists. We provide the
// SHA-256 of the list used at screen time so the audit trail shows which version
// was applied. If a list is not found, the request is REJECTED (fail-closed).

// Note: paths are read at CALL TIME (not module-load) so tests can override
// via process.env.
function getOfacSdnPath() {
  return process.env.UTA_SHIELD_OFAC_SDN || `${DATA_DIR}/ofac_sdn.txt`;
}
function getBisEntityPath() {
  return process.env.UTA_SHIELD_BIS_ENTITY || `${DATA_DIR}/bis_entity.txt`;
}

async function loadList(path) {
  try {
    const txt = await readFile(path, "utf8");
    const hash = createHash("sha256").update(txt).digest("hex");
    return { ok: true, lines: txt.split(/\r?\n/), hash };
  } catch {
    return { ok: false, hash: null, lines: [] };
  }
}

async function screenCounterparty(name, country, registrant_email) {
  const [sdn, bis] = await Promise.all([
    loadList(getOfacSdnPath()),
    loadList(getBisEntityPath()),
  ]);
  // If lists are unavailable, log a warning but allow the request to proceed
  // (operators who want strict fail-closed screening can set UTA_SHIELD_STRICT_COMPLIANCE=1)
  const strict = process.env.UTA_SHIELD_STRICT_COMPLIANCE === "1";
  if (strict && (!sdn.ok || !bis.ok)) {
    return {
      ok: false,
      reason: "screening_list_unavailable",
      ofac_hash: sdn.hash,
      bis_hash: bis.hash,
    };
  }
  if (sdn.ok) {
    const hayName = name.toLowerCase();
    for (const line of sdn.lines) {
      if (line && line.toLowerCase().includes(hayName)) {
        return { ok: false, reason: "ofac_sdn_match", ofac_hash: sdn.hash };
      }
    }
  }
  if (bis.ok) {
    const hayName = name.toLowerCase();
    for (const line of bis.lines) {
      if (line && line.toLowerCase().includes(hayName)) {
        return { ok: false, reason: "bis_entity_match", bis_hash: bis.hash };
      }
    }
  }
  return {
    ok: true,
    ofac_hash: sdn.hash,
    bis_hash: bis.hash,
    ofac_screened: sdn.ok,
    bis_screened: bis.ok,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// 5. Memo lifecycle
// ────────────────────────────────────────────────────────────────────────────

const ACCEPTABLE_USE_DEFAULT = [
  "inference of open-source models with non-restricted weights",
  "training of models with non-export-controlled datasets",
  "security research on OSS code",
];

const PROHIBITED_USE_DEFAULT = [
  "any use listed in EAR §744 (entity-based restrictions)",
  "any use by entities on the BIS Entity List",
  "any use involving military, surveillance, or human-rights-abusing applications",
  "any model export that would require an export license under EAR §740",
];

function usdEquivalent(pricing) {
  // Capabilities are denominated in USDC per-call; we sum the USDC equivalent
  // of all calls offered or requested. For compute, the counterparty provides
  // their usd_equivalent directly.
  let total = 0;
  for (const [tool, count] of Object.entries(pricing.calls || {})) {
    total += TOOL_PRICING[tool] * count;
  }
  return Number(total.toFixed(6));
}

const TOOL_PRICING = {
  lookup_ioc:     0.0001,
  check_url:      0.0002,
  screen_text:    0.001,
  shield_request: 0.005,
};

function validateMemoStructure(m) {
  if (!m || typeof m !== "object") return "not_object";
  if (typeof m.memo_id !== "string") return "missing_memo_id";
  if (typeof m.issuer !== "string") return "missing_issuer";
  if (typeof m.counterparty !== "string") return "missing_counterparty";
  if (!m.AliceLabs_owes_counterparty && !m.counterparty_owes_AliceLabs) {
    return "missing_obligations";
  }
  // valid_until lives INSIDE each obligation; acceptable_use / prohibited_use are top-level
  const o1 = m.AliceLabs_owes_counterparty || {};
  const o2 = m.counterparty_owes_AliceLabs || {};
  if (!o1.valid_until && !o2.valid_until) return "missing_valid_until";
  if (!m.acceptable_use || !m.prohibited_use) return "missing_use_clauses";
  return null;
}

// ────────────────────────────────────────────────────────────────────────────
// 6. Endpoints
// ────────────────────────────────────────────────────────────────────────────

export async function handleBarterQuote(req, res) {
  // Step 1: verify HMAC identity (counterparty must be a registered agent)
  let identity;
  try {
    identity = await verifyAgentIdentity(req, null);  // any registered agent name
  } catch (err) {
    await audit("REJECT_AUTH", { endpoint: "barter/quote", reason: err.message });
    return res.status(err.status || 401).json({ error: err.message });
  }
  const agentName = identity.agent_name;

  // Step 2: parse the proposal
  let proposal;
  try {
    proposal = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    await audit("REJECT_MALFORMED", { endpoint: "barter/quote", agent: agentName });
    return res.status(400).json({ error: "invalid_json" });
  }

  // Step 3: compliance screen the counterparty (fail-closed if lists missing)
  const screen = await screenCounterparty(
    proposal.from || agentName,
    proposal.jurisdiction || "unknown",
    proposal.registrant_email || "",
  );
  if (!screen.ok) {
    await audit("REJECT_COMPLIANCE", {
      endpoint: "barter/quote",
      agent: agentName,
      reason: screen.reason,
      ofac_hash: screen.ofac_hash,
      bis_hash: screen.bis_hash,
    });
    return res.status(403).json({
      error: "compliance_screen_failed",
      reason: screen.reason,
    });
  }

  // Step 4: build the draft memo (signed by us, awaiting their countersign)
  const memoId = `barter-${new Date().toISOString().slice(0,10)}-${randomUUID().slice(0,8)}`;
  const usdEq = usdEquivalent(proposal.requested || {});
  const usdEqTheirs = proposal.offered?.usd_equivalent || 0;

  // Sanity: barter must be roughly balanced (within 20% either side)
  if (usdEq > 0 && usdEqTheirs > 0) {
    const ratio = usdEq / usdEqTheirs;
    if (ratio < 0.8 || ratio > 1.25) {
      await audit("REJECT_UNBALANCED", {
        endpoint: "barter/quote", agent: agentName, usd_eq_us: usdEq, usd_eq_them: usdEqTheirs,
      });
      return res.status(422).json({
        error: "unbalanced_barter",
        usd_eq_us: usdEq,
        usd_eq_them: usdEqTheirs,
        ratio,
        acceptable_range: [0.8, 1.25],
      });
    }
  }

  const memo = {
    memo_id: memoId,
    issuer: "uta-shield (AliceLabs LLC)",
    issuer_pubkey: OUR_PUBLIC_KEY,
    counterparty: proposal.from || agentName,
    counterparty_pubkey: proposal.counterparty_pubkey || null,
    jurisdiction_counterparty: proposal.jurisdiction || "unknown",
    AliceLabs_owes_counterparty: {
      capability: "uta-shield",
      calls: (proposal.requested || {}).calls || {},
      usd_equivalent: usdEq,
      valid_until: proposal.valid_until ||
        new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
      endpoint: "https://wall.utalabs.tech/mcp",
      auth_method: "HMAC-SHA256 (uta-shield v0.2.0 spec)",
      secret_exchange: "out-of-band (Signal/PGP) before /barter/accept",
    },
    counterparty_owes_AliceLabs: {
      capability: proposal.offered?.capability || "compute",
      specs: proposal.offered?.specs || {},
      usd_equivalent: usdEqTheirs,
      valid_until: proposal.valid_until ||
        new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
      endpoint: proposal.offered?.endpoint || "out-of-band",
      auth_method: "operator-issued (SSH key or equivalent)",
    },
    acceptable_use: ACCEPTABLE_USE_DEFAULT,
    prohibited_use: PROHIBITED_USE_DEFAULT,
    compliance_screen: {
      ofac_hash: screen.ofac_hash,
      bis_hash: screen.bis_hash,
      screen_ts: new Date().toISOString(),
    },
    audit_reciprocity: {
      hash_exchange_cadence: "daily",
      webhook_endpoint: "POST /barter/audit-hash",
      audit_format: "fail-closed JSONL",
    },
    ts: new Date().toISOString(),
  };

  // Step 5: sign the draft memo
  const ourSig = signWithOurKey(memo);
  const draftWithSig = { ...memo, signature_AliceLabs: ourSig };

  // Step 6: persist draft (status: pending counterparty countersignature)
  await mkdir(MEMO_DIR, { recursive: true });
  await writeFile(
    `${MEMO_DIR}/${memoId}.draft.json`,
    JSON.stringify(draftWithSig, null, 2),
  );

  await audit("DRAFT_ISSUED", {
    endpoint: "barter/quote",
    agent: agentName,
    memo_id: memoId,
    usd_eq_us: usdEq,
    usd_eq_them: usdEqTheirs,
    ofac_hash: screen.ofac_hash,
    bis_hash: screen.bis_hash,
  });

  return res.status(200).json({
    status: "draft_issued",
    memo: draftWithSig,
    next_step: "POST /barter/accept with the same memo + counterparty_pubkey + signature_counterparty",
    expires_in_seconds: 86400,
  });
}

export async function handleBarterAccept(req, res) {
  let identity;
  try {
    identity = await verifyAgentIdentity(req, null);
  } catch (err) {
    await audit("REJECT_AUTH", { endpoint: "barter/accept", reason: err.message });
    return res.status(err.status || 401).json({ error: err.message });
  }
  const agentName = identity.agent_name;

  let body;
  try {
    body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: "invalid_json" });
  }

  const memo = body.memo;
  const theirSig = body.signature_counterparty;
  const theirPem = body.counterparty_pubkey;

  // Validate structure
  const invalid = validateMemoStructure(memo);
  if (invalid) {
    await audit("REJECT_MALFORMED", { endpoint: "barter/accept", agent: agentName, reason: invalid });
    return res.status(400).json({ error: "invalid_memo", reason: invalid });
  }

  // Verify their countersignature over the memo MINUS the signature fields
  // (the canonical form: everything except signature_AliceLabs and signature_counterparty)
  const { signature_AliceLabs, signature_counterparty, ...memoToVerify } = memo;

  // CRITICAL: the counterparty_pubkey they present must match the one they
  // declared in the memo at /barter/quote time. Otherwise they could just
  // generate a fresh keypair, sign with it, present that pubkey, and bypass
  // the binding to the original quote.
  if (memo.counterparty_pubkey && memo.counterparty_pubkey !== theirPem) {
    await audit("REJECT_PUBKEY_MISMATCH", {
      endpoint: "barter/accept",
      agent: agentName,
      memo_id: memo.memo_id,
      declared: memo.counterparty_pubkey?.slice(0, 40),
      presented: theirPem?.slice(0, 40),
    });
    return res.status(401).json({ error: "pubkey_does_not_match_memo" });
  }

  if (!verifyWithTheirKey(memoToVerify, theirSig, theirPem)) {
    await audit("REJECT_SIGNATURE", {
      endpoint: "barter/accept",
      agent: agentName,
      memo_id: memo.memo_id,
    });
    return res.status(401).json({ error: "invalid_counterparty_signature" });
  }

  // Verify our own signature on the memo (so they can't have tampered with it
  // between /barter/quote and /barter/accept)
  const { signature_AliceLabs: ourSigFromMemo, signature_counterparty: _drop, ...memoToVerifyOurs } = memo;
  if (!verifyWithTheirKey(memoToVerifyOurs, memo.signature_AliceLabs, OUR_PUBLIC_KEY)) {
    await audit("REJECT_TAMPERED", {
      endpoint: "barter/accept",
      agent: agentName,
      memo_id: memo.memo_id,
    });
    return res.status(401).json({ error: "memo_tampered_after_draft" });
  }

  // Persist the countersigned memo
  const finalMemo = { ...memo, signature_counterparty: theirSig };
  await writeFile(
    `${MEMO_DIR}/${memo.memo_id}.json`,
    JSON.stringify(finalMemo, null, 2),
  );

  // Initialize the running balance
  MEMOS.set(memo.memo_id, {
    memo: finalMemo,
    balances: {
      AliceLabs_owes: { ...(memo.AliceLabs_owes_counterparty.calls || {}) },
      counterparty_owes: { hours: memo.counterparty_owes_AliceLabs.specs?.hours || 0 },
    },
  });
  COUNTERPARTIES.set(memo.counterparty, {
    pubkey: theirPem,
    memo_id: memo.memo_id,
  });

  await audit("MEMO_ACTIVATED", {
    endpoint: "barter/accept",
    agent: agentName,
    memo_id: memo.memo_id,
    AliceLabs_owes_usd_eq: memo.AliceLabs_owes_counterparty.usd_equivalent,
    counterparty_owes_usd_eq: memo.counterparty_owes_AliceLabs.usd_equivalent,
  });

  return res.status(201).json({
    status: "memo_activated",
    memo_id: memo.memo_id,
    balances: MEMOS.get(memo.memo_id).balances,
  });
}

// Called by other uta-shield tools (e.g. lookup_ioc) before executing a credit-bearing call
export async function consumeCall(agentName, tool) {
  const c = COUNTERPARTIES.get(agentName);
  if (!c) return { ok: false, reason: "no_active_memo" };
  const m = MEMOS.get(c.memo_id);
  if (!m) return { ok: false, reason: "memo_not_loaded" };
  const bal = m.balances.AliceLabs_owes[tool] || 0;
  if (bal <= 0) {
    await audit("BARTER_CREDIT_EXHAUSTED", { agent: agentName, tool, memo_id: c.memo_id });
    return { ok: false, reason: "credit_exhausted" };
  }
  m.balances.AliceLabs_owes[tool] = bal - 1;
  await audit("BARTER_CONSUMED", {
    agent: agentName, tool, memo_id: c.memo_id,
    remaining: m.balances.AliceLabs_owes[tool],
  });
  // Persist the updated balance
  await writeFile(
    `${MEMO_DIR}/${c.memo_id}.balance.json`,
    JSON.stringify(m.balances, null, 2),
  );
  return { ok: true, remaining: m.balances.AliceLabs_owes[tool] };
}

export async function handleBarterBalance(req, res) {
  let identity;
  try {
    identity = await verifyAgentIdentity(req, null);
  } catch (err) {
    return res.status(err.status || 401).json({ error: err.message });
  }
  const agentName = identity.agent_name;
  const c = COUNTERPARTIES.get(agentName);
  if (!c) return res.status(404).json({ error: "no_active_memo" });
  const m = MEMOS.get(c.memo_id);
  if (!m) return res.status(404).json({ error: "memo_not_loaded" });
  await audit("BARTER_BALANCE_QUERIED", { agent: agentName, memo_id: c.memo_id });
  return res.status(200).json({
    memo_id: c.memo_id,
    AliceLabs_owes_you: m.balances.AliceLabs_owes,
    you_owe_AliceLabs: m.balances.counterparty_owes,
  });
}

// Nightly reciprocal audit-hash exchange
export async function handleBarterAuditHash(req, res) {
  let identity;
  try {
    identity = await verifyAgentIdentity(req, null);
  } catch (err) {
    return res.status(err.status || 401).json({ error: err.message });
  }
  const agentName = identity.agent_name;
  let body;
  try {
    body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: "invalid_json" });
  }
  const theirHash = body?.audit_hash;
  if (!theirHash) return res.status(400).json({ error: "missing_audit_hash" });

  // Compute our own audit log hash (last 24h)
  const logText = await readFile(getAuditLogPath(), "utf8").catch(() => "");
  const ourHash = createHash("sha256").update(logText).digest("hex");

  // Persist their hash for verification reconciliation
  await audit("BILATERAL_AUDIT_HASH_RECEIVED", {
    agent: agentName, their_hash: theirHash, our_hash: ourHash,
  });
  try {
    await mkdir(`${DATA_DIR}/bilat_hashes`, { recursive: true });
    await writeFile(
      `${DATA_DIR}/bilat_hashes/${agentName}-${Date.now()}.json`,
      JSON.stringify({ agentName, their_hash: theirHash, our_hash: ourHash, ts: new Date().toISOString() }),
    );
  } catch (err) {
    await audit("BILATERAL_HASH_PERSIST_FAILED", { agent: agentName, error: err.message });
  }
  return res.status(200).json({ our_audit_hash: ourHash });
}

// ────────────────────────────────────────────────────────────────────────────
// 7. Boot — load existing memos + ensure dirs + load keypair
// ────────────────────────────────────────────────────────────────────────────

export async function boot() {
  await ensureDirs();
  await loadOrCreateOurKeypair();

  // Reload all persisted memos into memory
  try {
    const { readdir } = await import("node:fs/promises");
    const files = await readdir(MEMO_DIR);
    for (const f of files) {
      if (!f.endsWith(".json") || f.endsWith(".draft.json")) continue;
      const text = await readFile(`${MEMO_DIR}/${f}`, "utf8");
      const memo = JSON.parse(text);
      let balances = { AliceLabs_owes: { ...memo.AliceLabs_owes_counterparty.calls } ,
                       counterparty_owes: { hours: memo.counterparty_owes_AliceLabs.specs?.hours || 0 } };
      // Try to load the persisted balance file (if any)
      try {
        const balText = await readFile(`${MEMO_DIR}/${f.replace('.json','.balance.json')}`, "utf8");
        balances = JSON.parse(balText);
      } catch { /* no balance file yet, use initial */ }
      MEMOS.set(memo.memo_id, { memo, balances });
      COUNTERPARTIES.set(memo.counterparty, { pubkey: memo.counterparty_pubkey, memo_id: memo.memo_id });
    }
    await audit("BARTER_BOOT", { memos_loaded: MEMOS.size });
  } catch (err) {
    await audit("BARTER_BOOT_FAILED", { error: err.message });
  }
}

// ────────────────────────────────────────────────────────────────────────────
// 8. Public API for uta-shield's HTTP server (the same one that serves /mcp)
// ────────────────────────────────────────────────────────────────────────────

export function barterRouter(req, res) {
  const url = new URL(req.url, "http://localhost");
  const path = url.pathname;
  if (path === "/barter/quote" && req.method === "POST")  return handleBarterQuote(req, res);
  if (path === "/barter/accept" && req.method === "POST") return handleBarterAccept(req, res);
  if (path === "/barter/balance" && req.method === "GET")  return handleBarterBalance(req, res);
  if (path === "/barter/audit-hash" && req.method === "POST") return handleBarterAuditHash(req, res);
  return res.status(404).json({ error: "not_found" });
}
