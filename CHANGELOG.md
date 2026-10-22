# Changelog — uta-shield

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
