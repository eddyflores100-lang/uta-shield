# Changelog — uta-shield

## 0.2.2 — third-review hardening (2026-10-23)

Response to the third external review, which confirmed the v0.2.0/v0.2.1
progress and raised three code items plus one evidence item. All four closed;
81 → 85 tests.

### Fixed (third-review findings)

- **ACL default-allow** (`src/identity.mjs`): agents absent from the ACL map
  were always allowed. → NEW opt-in strict mode: `identity.aclDenyUnlisted`
  (API) / `--acl-deny-unlisted` (CLI) switches the ACL to allow-list semantics
  — unlisted agents get `403 REJECT_FORBIDDEN`. Fail-closed wiring: the CLI
  refuses to start with `--acl-deny-unlisted` but no `--acl-file` (with no ACL
  the flag would deny every agent). `/health` discloses
  `identity.acl_deny_unlisted`.
- **Streamed overflow had no dedicated proof** (`src/proxy.mjs`): the mid-read
  branch now audits `BODY_TOO_LARGE` (a lying or absent content-length cannot
  dodge the trail) and flushes the `413` BEFORE destroying the socket — the
  client sees a clean `413`, not `ECONNRESET`. New e2e test proves it with a
  chunked body (no content-length) against a DEAD upstream: a `413` response
  is only possible if the fetch never ran.
- **MCP compatibility undemonstrated** → new lifecycle e2e test walks a real
  client session over the proxy: `initialize` → `notifications/initialized` →
  `tools/list` → `tools/call` → `ping` all pass with HMAC identity; a surface
  outside the allow-list (`resources/list`) gets `403 METHOD_DENIED`.

### Added

- **`.github/workflows/tests.yml`** — public CI on GitHub's own runners
  (Node 20/22/24 matrix): full suite + `verify-feed` + fail-closed startup
  proof on every push. Independent reproduction no longer depends on trusting
  EVIDENCE.md: anyone can read the workflow run.

### Changed

- Version alignment across `package.json`, CLI banner, MCP `serverInfo`,
  shield default. Audit records for both 413 paths.

### Tests

- 85/85 green (`node --test test/*.test.mjs`, Node v24.21.0): `identity.test.mjs`
  +1 (strict ACL semantics), `proxy.test.mjs` +3 (strict-ACL e2e, streamed
  overflow e2e, MCP lifecycle e2e).

## 0.2.1 — second-review hardening (2026-10-23)

Direct response to a second external review of the v0.2.0 change set. Two real
gaps remained; both are now closed and covered by dedicated tests (78 → 81).

### Fixed (second-review findings)

- **`/audit` was unauthenticated** (`src/proxy.mjs`): the proxy served the last
  20 audit records — IOCs, agent names, tools, decisions — to any GET.
  → NEW: `/audit` is operator telemetry. With no admin token configured the
  endpoint answers **404 (fail-closed: it does not exist publicly)**. With
  `--admin-token` / `UTA_SHIELD_ADMIN` (≥16 chars) it requires an `x-uta-admin`
  header compared in constant time (`timingSafeEqual`). Every denied or
  disabled-access attempt is itself audited (`AUDIT_DISABLED` / `AUDIT_DENIED`).
  `/health` discloses the posture via `proxy.audit_admin_required`.

- **Outbound header could misclassify** (`src/proxy.mjs` + `src/shield.mjs`):
  the proxy recomputed the `x-uta-shield` flag from DLP/intel counts, so with
  `policy=log` a response carrying a live C2 indicator was flagged as if it had
  been redacted. → NEW: `gateOut()` now returns its exact verdict
  (`OUT_OK | OUT_MASKED | OUT_REDACTED | OUTBOUND_INTEL`) in `result.verdict`
  and the proxy forwards it verbatim — single source of truth, zero drift
  between the core decision and what the client sees. `policy=log` is honest:
  header says `OUTBOUND_INTEL`, never a clean-looking `OUT_OK`.

### Changed

- `demo/run-demo.mjs` now starts the shield with `--admin-token` and
  demonstrates the new posture: `/audit` without credentials → `401`, wrong
  token → `401` (audited as `AUDIT_DENIED`), correct token → `200` + trail.
- Version alignment across `package.json`, CLI banner, MCP `serverInfo`,
  shield default.

### Tests

- 81/81 green (`node --test test/*.test.mjs`, Node v24.21.0):
  `proxy.test.mjs` +3 — audit fail-closed 404 leak-proof, audit auth
  401/200 paths, `policy=log` e2e with exact `OUTBOUND_INTEL` header.

## 0.2.0 — security hardening release (2026-10-23)

Direct response to an external code audit of v0.1.0. Every finding below was
reproduced against the code, fixed, and covered by a dedicated test.

### Fixed (audit findings)

- **Identity was declarative only** (`src/identity.mjs`): `x-agent-name` was taken
  at face value, `verified` was always `false`, and `--require-identity` checked
  existence, not authenticity — name rotation weakened rate limits.
  → NEW: HMAC-SHA256 verified identity (`x-agent-name` + `x-agent-timestamp` +
  `x-agent-signature` over `agent|ts|sha256(rawBody)`), ±5 min anti-replay window,
  fail-closed on presented-but-invalid credentials, per-tool ACL (`--acl-file`).

- **Outbound detection did not block** (`src/shield.mjs`): `gateOut()` logged
  `OUTBOUND_INTEL` and then delivered the response anyway.
  → NEW: explicit outbound policy `block | redact | log` (default `redact`).
  `block` withholds the response (JSON-RPC `-32006`); `redact` neutralizes every
  IOC occurrence in-place (`feed.redactText()`); `log` is the documented v0.1.0
  pass-through, now an explicit opt-in.

- **Rate limit bypass by name rotation** (`src/ratelimit.mjs`): buckets keyed by
  the *declared* agent name — rotating names reset limits.
  → NEW: two-tier buckets — per-IP (always, cannot be rotated) + per-agent
  (verified agents only). All-or-nothing multi-bucket consumption. Lazy pruning
  against bucket-memory exhaustion.

- **DLP `$1` bug** (`src/dlp.mjs`): the `bearer/token` rule substituted `$1`
  without a capture group, emitting a literal `$1` into masked output.
  → FIXED with explicit capture groups + regression test. Also added: GCP keys,
  GitHub fine-grained PATs, Stripe keys, high-entropy hex secrets, obfuscated
  emails ("name at corp dot com"), Luhn-validated credit cards (phones no longer
  match), opt-in base64-blob masking, and findings aggregation at every JSON depth
  (`maskDeepDetailed`).

- **Proxy had no limits** (`bin/cli.mjs`): unbounded request bodies, no upstream
  timeout, raw upstream error messages echoed to clients.
  → NEW `src/proxy.mjs`: body cap 1 MiB (declared + streamed), upstream timeout
  (504, fixed message), MCP method allow-list (403 `METHOD_DENIED`), safe error
  messages with details only in the audit log, server header/request timeouts,
  raw-byte forwarding, `--trust-proxy` for X-Forwarded-For.

- **Anonymous-by-default proxy**: `wrap` accepted anonymous traffic unless told
  otherwise.
  → NEW: fail-closed startup — `wrap` refuses to run without `--keys-file`
  (or `UTA_SHIELD_KEYS`) or an explicit `--allow-anonymous`.

### Tests

28 → **78 tests**, including: HMAC verification/tamper/replay, ACL, identity
spoofing e2e, name-rotation bypass attempts, outbound block/redact/log e2e,
413 body-limit, 504 timeout, 502 safe errors, method policy, DLP format
coverage + `$1` regression, and all v0.1.0 behavior preserved.

### Packaging

- `npm test` updated for the Node 24 test-runner invocation.
- Version bumped to 0.2.0 across `package.json`, CLI banner, MCP `serverInfo`.

### Breaking changes

1. `wrap` fails closed without identity configuration.
2. Unverified callers are rate-limited per IP (no per-agent buckets for declared names).
3. `gateOut` default policy is `redact` (was silent pass-through).
4. New audit verdicts: `ALLOW_VERIFIED`, `REJECT_AUTH`, `REJECT_FORBIDDEN`,
   `OUT_REDACTED`, `OUT_BLOCKED`, `UPSTREAM_ERROR`.

## 0.1.0 — initial release (2026-10-21)

- Provider-side firewall for MCP servers (zero-dependency proxy wrapper).
- PhishGuard threat-intel MCP server (stdio) with bundled feed
  `taikotalent-2026-10` (23 IOCs, MITRE ATT&CK mapped).
- Layers: declared identity, IOC screening (in/out), token-bucket rate limits,
  per-call metering + x402-ready manifest, DLP masking, JSONL audit.
- 28 tests, zero dependencies, ~1,200 lines.
