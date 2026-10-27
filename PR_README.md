# PR — Add /barter bilateral protocol to uta-shield (v0.3.0)

This PR adds the bilateral barter protocol to uta-shield, enabling an operator
(e.g. a Chinese GPU provider) to exchange compute-hours for uta-shield calls
WITHOUT any USDC crossing the border. Settlement is a bilateral credit memo
signed Ed25519 by both parties.

## Why

uta-shield v0.2.4 already declares `x402Support: true` and accepts USDC for
paid calls. But cross-border USDC has compliance overhead (OFAC screening,
FinCEN reporting, etc.) that makes it impractical for a Chinese operator to
pay uta-shield for protection of their MCP server. This PR adds a barter rail
that:

- Lets the Chinese operator give compute-hours; we give uta-shield calls.
- Settles with an off-chain bilateral credit memo (no money crosses borders).
- Audits every decision in the existing fail-closed JSONL trail.
- Includes the same OFAC SDN + BIS Entity List screen as a USDC payment
  would (fail-closed in strict mode; advisory in default mode).
- Includes the same acceptable-use clauses operators would expect for EAR
  compliance.

This is the design described in `PATTERN_C_BARTER_DESIGN.md`.

## Files

### `.well-known/agent-card.json` — new (publish on wall.utalabs.tech)

A2A capability card combining:
- EIP-8004 (Ethereum agent registration)
- A2A v0.3 (Google Agent2Agent protocol)
- MCP server.json schema 2025-12-11

Declares 4 capabilities with pricing + free tiers, `barter_accepted: true`,
and a `barter_endpoint: POST /barter/quote`.

### `src/barter.mjs` — new (~580 lines, zero deps)

Implements:
- `POST /barter/quote` — counterparty proposes a barter; we return a draft
  memo signed by us (Ed25519), awaiting their countersignature
- `POST /barter/accept` — counterparty returns the same memo countersigned;
  we verify their Ed25519 sig + that the pubkey matches the one declared in
  the proposal, persist the memo, and initialize the running balance
- `POST /barter/balance` — counterparty queries their remaining credit
- `POST /barter/audit-hash` — nightly reciprocal audit-hash exchange
- `consumeCall(agent, tool)` — internal hook called by uta-shield's other
  tools (e.g. `lookup_ioc`) before executing a credit-bearing call

Compliance:
- OFAC SDN list check (offline, cached) — `process.env.UTA_SHIELD_OFAC_SDN`
- BIS Entity List check — `process.env.UTA_SHIELD_BIS_ENTITY`
- Strict mode (fail-closed if lists missing) — `process.env.UTA_SHIELD_STRICT_COMPLIANCE=1`
- Acceptable-use and prohibited-use clauses embedded in every memo

Identity:
- Reuses uta-shield v0.2.0 HMAC-SHA256 spec (`x-agent-name`, `x-agent-timestamp`,
  `x-agent-signature` headers). Inject the verifier via `setIdentityVerifier()`
  to integrate with the existing `shield.mjs` `verifySignature()`.

Persistence:
- One file per memo at `${DATA_DIR}/memos/${memo_id}.json`
- Per-memo running balance at `${DATA_DIR}/memos/${memo_id}.balance.json`
- Our Ed25519 keypair at `${DATA_DIR}/ed25519_private.pem` + `.public.pem` (chmod 600)
- Bilateral audit hashes at `${DATA_DIR}/bilat_hashes/`

### `test/barter.test.mjs` — new (13 tests, all pass, zero deps)

Test coverage:
1. Rejects unauthenticated requests (HMAC identity)
2. Issues a draft memo with our Ed25519 signature
3. Rejects unbalanced proposals (USD-equivalent ratio outside 0.8–1.25)
4. Rejects when compliance lists are unavailable in strict mode (fail-closed)
5. Rejects when counterparty name appears in OFAC SDN list
6. Accept verifies Ed25519 countersignature and activates memo
7. Rejects a forged countersignature (different keypair than declared)
8. consumeCall decrements the balance and audits
9. consumeCall rejects unknown agent (no active memo)
10. consumeCall rejects when credit is exhausted
11. /barter/balance returns current remaining credits
12. /barter/audit-hash accepts and reciprocates a hash exchange
13. Audit log is fail-closed JSONL — every decision is recorded

Run: `node --test --test-concurrency=1 test/barter.test.mjs`
Result: **13 pass / 0 fail / ~89ms**

## How to deploy

### 1. Publish the Agent Card

```bash
# Copy .well-known/agent-card.json to the uta-shield repo root
cp .well-known/agent-card.json /path/to/uta-shield/.well-known/agent-card.json
# Push to main — GitHub Pages will deploy to wall.utalabs.tech/.well-known/agent-card.json within 1-2 min
git add .well-known/agent-card.json
git commit -m "Add A2A capability card with /barter endpoint"
git push origin main
```

### 2. Wire the /barter endpoints to the existing HTTP server

In `src/index.mjs` (or wherever uta-shield's HTTP server is set up), import the
barter router and call it for any path starting with `/barter`:

```js
import { barterRouter, setIdentityVerifier, boot as barterBoot } from "./barter.mjs";
import { verifySignature } from "./shield.mjs";  // existing uta-shield identity verifier

await barterBoot();
setIdentityVerifier(async (req, expectedName) => {
  // Reuse the existing HMAC-SHA256 verification
  const ok = await verifySignature(req.headers, expectedName);
  if (!ok) throw Object.assign(new Error("invalid_signature"), { status: 401 });
  return { agent_name: req.headers["x-agent-name"] };
});

// In the HTTP request handler, add:
if (url.pathname.startsWith("/barter")) {
  return barterRouter(req, res);
}
```

### 3. Wire `consumeCall` into the credit-bearing tools

In `src/mcp/server.mjs` (or wherever the MCP tools are implemented), call
`consumeCall()` before executing any tool that's protected by barter credit:

```js
import { consumeCall } from "../barter.mjs";

async function handleLookupIoc(args, agentName) {
  const credit = await consumeCall(agentName, "lookup_ioc");
  if (!credit.ok) {
    return { error: "credit_exhausted", reason: credit.reason };
  }
  // ... existing tool implementation
}
```

### 4. Download the compliance lists (operator's responsibility)

```bash
# Weekly refresh — put in a cron job
curl -sS https://www.treasury.gov/ofac/downloads/sdn_advanced.txt > .data/barter/ofac_sdn.txt
curl -sS https://www.bis.doc.gov/index.php/other-regulatory-controls/consolidated-screening-list > .data/barter/bis_entity.txt
chmod 600 .data/barter/ofac_sdn.txt .data/barter/bis_entity.txt

# Enable strict mode if you want fail-closed behavior when the lists are missing
export UTA_SHIELD_STRICT_COMPLIANCE=1
```

### 5. Bump version

```bash
# package.json: bump version to 0.3.0
# CHANGELOG.md: add v0.3.0 entry documenting the new /barter protocol
```

## Test result

```
✔ 1. /barter/quote rejects unauthenticated requests (8.25ms)
✔ 2. /barter/quote issues a draft memo with our Ed25519 signature (3.09ms)
✔ 3. /barter/quote rejects unbalanced proposals (ratio outside 0.8-1.25) (1.02ms)
✔ 4. /barter/quote rejects when compliance lists are unavailable in strict mode (1.03ms)
✔ 5. /barter/quote rejects when counterparty name matches OFAC SDN list (2.50ms)
✔ 6. /barter/accept verifies Ed25519 countersignature and activates memo (2.73ms)
✔ 7. /barter/accept rejects a forged countersignature (different keypair than declared) (3.42ms)
✔ 8. consumeCall decrements the balance and audits (1.04ms)
✔ 9. consumeCall rejects unknown agent (no active memo) (0.38ms)
✔ 10. consumeCall rejects when credit is exhausted (2.85ms)
✔ 11. /barter/balance returns current remaining credits (0.60ms)
✔ 12. /barter/audit-hash accepts and reciprocates a hash exchange (1.06ms)
✔ 13. Audit log is fail-closed JSONL — every decision is recorded (0.68ms)
ℹ tests 13
ℹ pass 13
ℹ fail 0
ℹ duration_ms 89.3ms
```

## Notes

- The barter protocol is **off-chain** for settlement but **on-disk** for
  audit. No USDC moves between the two operators' jurisdictions.
- The Ed25519 keypair is generated on first boot and persisted. Operators
  should back up `${DATA_DIR}/ed25519_private.pem` and rotate it annually
  (rotation invalidates all active memos — by design).
- The compliance lists are read at CALL TIME (not module-load), so the
  operator can refresh them without restarting the process.
- The OFAC SDN and BIS Entity List substring match is intentionally naive
  (operators should replace with proper parsing for production).
- Test 13 uses an `auditLogPath` variable captured in `before()` rather
  than `process.env.UTA_SHIELD_AUDIT_LOG` to avoid Node test runner races
  with the `after()` cleanup hook.
