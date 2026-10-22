# uta-shield

**Provider-side firewall for MCP servers** + **PhishGuard threat-intel MCP server** — in one zero-dependency package.

**Landing / docs**: https://wall.utalabs.tech

Every gateway in the MCP security category (Lasso, Mintive, Obot, agentgateway, Cequence) protects the **consumer** — the company whose employees connect agents to third-party servers. Nothing protects the **operator** — the SaaS that publishes its MCP server and exposes its database to every anonymous agent on the internet.

`uta-shield` is the mirror side: you wrap YOUR MCP server and gain verified identity, per-tool authorization, threat-intel blocking (in AND out), two-tier rate limits, DLP masking, proxy hardening, per-call metering and a JSONL audit trail — without touching your server code.

Backed by a real, documented campaign: the [taikotalent phishing case](https://github.com/eddyflores100-lang/taikotalent-phishing-iocs) (fake-recruiter malware against open-source developers, domain taken down in ~12h, C2 infra tracked). The bundled feed ships its 23 verified IOCs.

## Quickstart

```bash
# 1. Screen any indicator offline (exit code 1 on match → scriptable)
npx uta-shield check gaganata.ink          # → MATCH (C2, campaign taikotalent-2026-10)
npx uta-shield check example.com           # → NO_MATCH

# 2. Screen text (email body, web content, tool output)
echo "verify at https://taikotalent.xyz/verify_m" | npx uta-shield screen

# 3. Run the PhishGuard MCP server (agents get lookup_ioc / check_url / screen_text)
npx uta-shield mcp

# 4. THE FIREWALL: wrap your MCP server (fail-closed: keys or explicit opt-out)
cat > keys.json <<'EOF'
{ "recruiter-agent": "generate-a-long-random-secret", "auditor-agent": "another-secret" }
EOF
npx uta-shield wrap --upstream http://localhost:3001 --port 8787 --keys-file keys.json --admin-token "$(openssl rand -hex 24)"
#    → agents now talk to :8787; your server stays at :3001
#    GET /health · GET /pricing (x402-ready) · GET /audit (admin-only: x-uta-admin header)

# 5. See it all live
node demo/run-demo.mjs
```

## Verified identity (v0.2.0)

Identity is no longer declared-only. Agents present three headers:

```
x-agent-name:      recruiter-agent
x-agent-timestamp: 1761196800000            (ms; ±5 min window)
x-agent-signature: <hex>                    HMAC_SHA256(secret, `${agent}|${ts}|${sha256(rawBody)}`)
```

- Valid signature → `ALLOW_VERIFIED` (per-agent rate buckets, ACL enforcement, metering).
- **Presented-but-invalid credentials → `REJECT_AUTH` (401). Fail-closed, always.**
- No credentials → `REJECT_ANON` (401) unless the operator passes `--allow-anonymous`.
- Declared names (no signature) are labels only, `verified:false` — they earn **no** per-agent rate bucket.

Signing a request (client side, any language):

```js
import { createHmac, createHash } from "node:crypto";
const ts = Date.now();
const bodyHash = createHash("sha256").update(rawBody).digest("hex");
const sig = createHmac("sha256", secret).update(`${agent}|${ts}|${bodyHash}`).digest("hex");
```

## The 8 layers

| # | Layer | Status in v0.2.0 |
|---|-------|------------------|
| 1 | Agent identity: **HMAC-SHA256 verified** (`--keys-file`, anti-replay window, fail-closed) + **per-tool ACL** (`--acl-file`) + declared/anonymous fallback | **SHIPPED** |
| 2 | Reputation score per agent | hook (identity verdicts recorded; scoring = roadmap) |
| 3 | Threat-intel in/out: inbound args **blocked**; outbound responses under explicit **policy** (`--outbound-policy block\|redact\|log`, default `redact`) | **SHIPPED** |
| 4 | Rate limiting: **two-tier** — per-IP bucket (always) + per-agent bucket (verified only); free/paid tiers | **SHIPPED** |
| 5 | Billing: per-call metering + x402-ready pricing manifest (settlement delegated to operator payment layer) | **SHIPPED (metering)** |
| 6 | DLP: emails (plain + obfuscated), JWTs, AWS/GCP keys, GitHub PATs, Stripe keys, bearer tokens, PEM blocks, hex secrets, credit cards (Luhn-validated), optional base64 blobs | **SHIPPED** |
| 7 | Reverse drift alerts (notify clients if schema changes) | roadmap |
| 8 | Audit: JSONL per decision (indicator + campaign for triage, never raw args or secrets) | **SHIPPED** |

Honesty policy: this README marks exactly what ships. Layers 2 and 7 are design hooks — no inflated claims.

## Proxy hardening (v0.2.1)

| Control | Default | Flag |
|---|---|---|
| Startup fail-closed | refuses to run without `--keys-file` or `--allow-anonymous` | — |
| **`/audit` authenticated** | **disabled (404) without a token; with one, requires `x-uta-admin` (timing-safe compare) — the trail holds IOCs and agent names, it is operator telemetry, never public** | `--admin-token SECRET` / `UTA_SHIELD_ADMIN` (≥16 chars) |
| Request body cap | 1 MiB (declared **and** streamed — header spoofing doesn't help) | `--max-body-bytes N` |
| Upstream timeout | 30 s → `504`, fixed message | `--upstream-timeout-ms N` |
| MCP method allow-list | `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call` → everything else `403 METHOD_DENIED` | `--allow-methods "a,b" \| "*"` |
| Safe errors | upstream failures return fixed messages; detail goes to the audit log, never the client | — |
| Exact outbound verdict | the `x-uta-shield` response flag is the core verdict (`OUT_OK`/`OUT_MASKED`/`OUT_REDACTED`/`OUTBOUND_INTEL`) — no recomputation, `policy=log` reports `OUTBOUND_INTEL`, never a clean-looking `OUT_OK` | — |
| Raw-body forwarding | exact bytes upstream (signature integrity) | — |
| Per-IP rate ceiling | 120 req/min, burst 60 | `--` config via API |
| Header timeouts | headers 10 s, request timeout = upstream + 5 s | automatic |

## Known limitations (honest scope)

- Identity verification is HMAC-shared-secret (operator-issued keys). It authenticates agents to the operator; it is not a federated PKI. `/.well-known/agent.json` origin verification remains a supplementary hook.
- `policy=log` records outbound IOCs but passes them through — it exists for operators who explicitly opt in; `redact` (default) or `block` are the safe choices.
- Obfuscated-email and hex-secret DLP patterns are heuristic; false positives are possible (tune via `dlp` options).
- No TLS termination — run behind your existing reverse proxy (Caddy/nginx/certbot).
- The feed ships ONE documented campaign (23 IOCs). Feed data is CC-BY-4.0; extend it with your own campaigns.

## Why zero dependencies?

A security product with 47 transitive dependencies is an attack surface, not a defense. `uta-shield` is ~1,600 lines of auditable Node.js ≥18 (ESM), including a hand-rolled MCP stdio implementation (newline-delimited JSON-RPC 2.0). `npm pack` ≈ 108 kB unpacked / 54 kB tarball.

## The bundled feed

`feed/iocs.json` (schema `pg/1`) ships campaign `taikotalent-2026-10`: 23 IOCs across 9 types — phishing domain (down via registrar clientHold), live C2 domains behind Cloudflare, sender IP, fake recruiter email, stager URLs, `sha256` of payloads, wildcard second-stage path (`/var/tmp/.kdm.*`), mutex name — with MITRE ATT&CK mapping (T1566.002, T1656, T1204.002, T1059.004, T1027, T1071.001, T1070.004, T1583.001) and per-IOC context. Every verdict carries this evidence so downstream agents can reason about WHY they were blocked.

Feed data CC-BY-4.0 from the public case repo. Update/extend it by adding a campaign object — schema validated by `uta-shield verify-feed`.

## As an MCP server (for agents, not just operators)

Agents get the intel as tools: `lookup_ioc(value)`, `check_url(url)` (feed + advisory heuristics), `screen_text(text)`, `list_campaigns()`, `feed_info()`. Every response is DATA — the server never fetches or executes anything.

## Commercial

| Offer | What | Price |
|---|---|---|
| Self-host (this package, license for use) | all shipped layers, bundled feed — run on your own infra, commercial use allowed | **free** |
| S7 — managed feed subscription | updated campaign feed + webhook alerts + YARA rules | **$50/mes** (free for first 100 ATC-holding agents) |
| S6 — Shield assessment + piloto | audit of your MCP server + deployed piloto (identity+intel+audit) + report | **$1,000 setup + $100/mes/server** |

Contact: AliceLabs LLC — support@alicelabs.energy

## Test (reproducible)

```bash
node --test test/*.test.mjs   # 81 tests: identity/HMAC, ACL, outbound policies, DLP formats,
                             # authenticated /audit, exact verdict propagation, proxy limits
                              # two-tier rate limits, hardened proxy e2e (413/502/504/403/429),
                              # feed matching, MCP protocol
npm run verify-feed           # feed schema validation
npm run demo                  # end-to-end with signed traffic
```

Test results for v0.2.1: see [EVIDENCE.md](EVIDENCE.md) (command, Node version, full runner summary).

## Migration v0.1.0 → v0.2.0 (breaking)

- `wrap` without `--keys-file`/`UTA_SHIELD_KEYS`/`--allow-anonymous` **refuses to start** (fail-closed default).
- Rate limits for unverified callers are keyed by IP; declared agent names no longer create per-agent buckets.
- `gateOut` default behavior changed from pass-through to `redact`. Set `outboundPolicy:"log"` for v0.1.0 behavior.
- New verdicts in the audit stream: `ALLOW_VERIFIED`, `REJECT_AUTH`, `REJECT_FORBIDDEN`, `OUT_REDACTED`, `OUT_BLOCKED`, `UPSTREAM_ERROR`.

## Migration v0.2.0 → v0.2.1 (breaking)

- **`GET /audit` no longer works without credentials.** Without `--admin-token` (or `UTA_SHIELD_ADMIN`) it answers **404**; with a token it requires the `x-uta-admin` header. Dashboards that scraped `/audit` anonymously must present the operator token. The response flag `x-uta-shield` is now the exact core verdict — `policy=log` users will see `OUTBOUND_INTEL` instead of the previously mislabeled flag.

Licensed for use — see [LICENSE](LICENSE) (license for use / licencia de uso). © 2026 AliceLabs LLC. Commercial exceptions (white label, OEM, redistribution, managed service): support@alicelabs.energy
