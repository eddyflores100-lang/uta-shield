# EVIDENCE.md — uta-shield v0.2.2 verification run

Reproducible record of the v0.2.0 security hardening, the v0.2.1 second-review
fixes AND the v0.2.2 third-review fixes (2026-10-23). Anyone can re-run every
command below from a clean checkout — or simply read the public CI run
(`.github/workflows/tests.yml` executes the full suite on GitHub's own
runners, Node 20/22/24, on every push).

## Environment

| | |
|---|---|
| Date | 2026-10-23 (UTC-5 session) |
| Node | v24.21.0 (`node --version`) |
| Platform | Linux x86_64 |
| Package | uta-shield 0.2.2 (zero dependencies) |
| Repo state | `main`, base commit `cb00f85` + hardening change sets v0.2.0/v0.2.1/v0.2.2 |

## 1. Full test suite

Command:

```bash
node --test test/*.test.mjs
```

Result: **exit 0**

```
ℹ tests 85
ℹ suites 0
ℹ pass 85
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 770
```

What the 85 tests cover (audit finding → test):

| Audit finding (v0.1.0 / second review) | Fix | Tests |
|---|---|---|
| Identity declarative, `verified:false` always | HMAC-SHA256 verification, anti-replay window | `identity.test.mjs` (9): valid sig, tampered body, forged secret, stale timestamp, unknown agent, no keys, declared fallback, anonymous rejection, rotation-is-not-identity |
| No per-tool authorization | ACL (`--acl-file`) | `identity.test.mjs` + `shield.test.mjs` (2): allow/wildcard/deny/unlisted, ACL e2e gate |
| `gateOut()` detects but delivers | outbound policy `block/redact/log` (default redact) | `outbound.test.mjs` (8): redact text+JSON, block text+JSON, log pass-through, DLP under every policy, clean pass-through, invalid policy rejected |
| **`/audit` unauthenticated (2nd review)** | fail-closed 404 without token; `x-uta-admin` + timing-safe compare with token; denials audited | `proxy.test.mjs` (2): 404 leak-proof (agent names / verdicts absent from body, attempt audited `AUDIT_DISABLED`); 401 missing / 401 wrong / 200 with records + `AUDIT_DENIED` audited |
| **Outbound flag misclassification (2nd review)** | core verdict travels in `out.verdict`; proxy forwards verbatim | `proxy.test.mjs` (1): `policy=log` e2e → `200`, header exactly `OUTBOUND_INTEL`, content passes (documented), decision audited with campaign evidence |
| Rate limit bypass via declared-name rotation | two-tier buckets: per-IP always + per-agent (verified only) | `ratelimit.test.mjs` (7) + `shield.test.mjs` + `proxy.test.mjs`: anti-rotation, all-or-nothing consume, prune, e2e 429 |
| DLP `$1` substitution bug | capture groups fixed | `dlp.test.mjs` regression: no literal `$1`, scheme word kept, secret gone |
| DLP limited formats | GCP/GitHub-PAT/Stripe/hex/obfuscated-email/Luhn cards/opt-in base64, depth-aggregated findings | `dlp.test.mjs` (11) |
| No body limits / timeouts / safe errors / method policy | hardened proxy | `proxy.test.mjs`: 413 oversized, 504 timeout (fixed message), 502 unreachable without internals leak, 403 METHOD_DENIED, unsigned 401, corrupted-signature 401, BLOCK_INTEL e2e, OUT_REDACTED e2e, OUT_BLOCKED e2e, 429 with retry-after, health posture disclosure |
| (regression guard) v0.1.0 behavior | preserved | `feed.test.mjs` (8), `mcp.test.mjs` (7), shield tests for BLOCK_INTEL / REJECT_ANON / audit hygiene |
| **ACL default-allow (3rd review)** | opt-in strict mode `aclDenyUnlisted` / `--acl-deny-unlisted` (CLI refuses it without `--acl-file`); health discloses posture | `identity.test.mjs` +1: unlisted denied, listed keep grants, flag inert without ACL map; `proxy.test.mjs` +1 e2e: verified-but-unlisted agent → 403 even with valid HMAC, listed agent → 200 |
| **Streamed overflow unproven (3rd review)** | mid-read branch audits `BODY_TOO_LARGE` and flushes the 413 before socket destroy | `proxy.test.mjs` +1 e2e: chunked body (no content-length) > limit against a DEAD upstream → clean 413 (a 502 would mean fetch ran), audit record present |
| **MCP compatibility undemonstrated (3rd review)** | lifecycle walked as a real client session | `proxy.test.mjs` +1 e2e: initialize → notifications/initialized → tools/list → tools/call → ping all 200 with HMAC identity; `resources/list` (outside allow-list) → 403 METHOD_DENIED |
| **Independent reproduction (3rd review)** | public CI on GitHub runners | `.github/workflows/tests.yml`: Node 20/22/24 matrix, full suite + verify-feed + fail-closed startup proof, on every push |

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

## 4. End-to-end demo (real HTTP, signed traffic, authenticated audit)

```bash
node demo/run-demo.mjs   # exit 0
```

Observed verdicts in one run: `401 REJECT_ANON` (unsigned) → `200 ALLOW_VERIFIED`
(HMAC) → `401 REJECT_AUTH` (corrupted signature) → `200 OUT_MASKED` (PII) →
`200 OUT_REDACTED` (live C2 domain neutralized: `[IOC_REDACTED:taikotalent-2026-10/domain]`)
→ `403 BLOCK_INTEL` (campaign URL in tool args) → `403 REJECT_FORBIDDEN` (ACL) →
`429 RATE_LIMITED` (agent bucket, retry-after present) →
`/audit: 401 without credentials · 401 with wrong token (audited AUDIT_DENIED) ·
200 + trail with the admin token`.

## 5. Packaging

```bash
npm pack --dry-run
# uta-shield-0.2.2.tgz · 0 dependencies
```

## Reproduction checklist

1. `git clone https://github.com/eddyflores100-lang/uta-shield && cd uta-shield`
2. `node --version` (≥18 required; evidence generated on v24.21.0)
3. `npm test` → expect 85/85 pass
4. `npm run verify-feed` → expect `ok: true`, 23 IOCs
5. `npm run demo` → expect the verdict sequence in §4 (including the two 401s on `/audit`)
6. or read the public CI run instead of steps 1-5 — same commands, GitHub's runners
