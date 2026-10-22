# EVIDENCE.md — uta-shield v0.2.0 verification run

Reproducible record of the v0.2.0 security-hardening verification (2026-10-23).
Anyone can re-run every command below from a clean checkout.

## Environment

| | |
|---|---|
| Date | 2026-10-23 (UTC-5 session) |
| Node | v24.21.0 (`node --version`) |
| Platform | Linux x86_64 |
| Package | uta-shield 0.2.0 (zero dependencies) |
| Repo state | `main`, base commit `cb00f85` + this hardening change set |

## 1. Full test suite

Command:

```bash
node --test test/*.test.mjs
```

Result: **exit 0**

```
ℹ tests 78
ℹ suites 0
ℹ pass 78
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 747
```

What the 78 tests cover (audit finding → test):

| Audit finding (v0.1.0) | Fix | Tests |
|---|---|---|
| Identity declarative, `verified:false` always | HMAC-SHA256 verification, anti-replay window | `identity.test.mjs` (9): valid sig, tampered body, forged secret, stale timestamp, unknown agent, no keys, declared fallback, anonymous rejection, rotation-is-not-identity |
| No per-tool authorization | ACL (`--acl-file`) | `identity.test.mjs` + `shield.test.mjs` (2): allow/wildcard/deny/unlisted, ACL e2e gate |
| `gateOut()` detects but delivers | outbound policy `block/redact/log` (default redact) | `outbound.test.mjs` (8): redact text+JSON, block text+JSON, log pass-through, DLP under every policy, clean pass-through, invalid policy rejected |
| Rate limit bypass via declared-name rotation | two-tier buckets: per-IP always + per-agent (verified only) | `ratelimit.test.mjs` (7) + `shield.test.mjs` + `proxy.test.mjs`: anti-rotation, all-or-nothing consume, prune, e2e 429 |
| DLP `$1` substitution bug | capture groups fixed | `dlp.test.mjs` regression: no literal `$1`, scheme word kept, secret gone |
| DLP limited formats | GCP/GitHub-PAT/Stripe/hex/obfuscated-email/Luhn cards/opt-in base64, depth-aggregated findings | `dlp.test.mjs` (11) |
| No body limits / timeouts / safe errors / method policy | hardened proxy | `proxy.test.mjs` (13): 413 oversized, 504 timeout (fixed message), 502 unreachable without internals leak, 403 METHOD_DENIED, unsigned 401, corrupted-signature 401, BLOCK_INTEL e2e, OUT_REDACTED e2e, OUT_BLOCKED e2e, 429 with retry-after, health posture disclosure |
| (regression guard) v0.1.0 behavior | preserved | `feed.test.mjs` (8), `mcp.test.mjs` (7), shield tests for BLOCK_INTEL / REJECT_ANON / audit hygiene |

## 2. Feed validation

```bash
node bin/cli.mjs verify-feed   # exit 0
```

```json
{ "ok": true, "feed_schema": "pg/1", "version": "2026.10.21",
  "campaigns": 1, "iocs_total": 23, "license": "CC-BY-4.0" }
```

## 3. Fail-closed startup proof

```bash
$ node bin/cli.mjs wrap --upstream http://localhost:9999
uta-shield: refusing to start (fail-closed default, v0.2.0).
  Configure verified identity:  --keys-file keys.json   ({ "agent": "secret", ... })
  Or explicitly opt out:        --allow-anonymous      (declared/anonymous allowed; ...)
# exit code 2
```

## 4. End-to-end demo (real HTTP, signed traffic)

```bash
node demo/run-demo.mjs   # exit 0
```

Observed verdicts in one run: `401 REJECT_ANON` (unsigned) → `200 ALLOW_VERIFIED`
(HMAC) → `401 REJECT_AUTH` (corrupted signature) → `200 OUT_MASKED` (PII) →
`200 OUT_REDACTED` (live C2 domain neutralized: `[IOC_REDACTED:taikotalent-2026-10/domain]`)
→ `403 BLOCK_INTEL` (campaign URL in tool args) → `403 REJECT_FORBIDDEN` (ACL) →
`429 RATE_LIMITED` (agent bucket, retry-after present).

## 5. Packaging

```bash
npm pack --dry-run
# package size: 54 kB tarball · 108 kB unpacked · 28 files · 0 dependencies
```

## Reproduction checklist

1. `git clone https://github.com/eddyflores100-lang/uta-shield && cd uta-shield`
2. `node --version` (≥18 required; evidence generated on v24.21.0)
3. `npm test` → expect 78/78 pass
4. `npm run verify-feed` → expect `ok: true`, 23 IOCs
5. `npm run demo` → expect the verdict sequence in §4
