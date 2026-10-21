# uta-shield

**Provider-side firewall for MCP servers** + **PhishGuard threat-intel MCP server** — in one zero-dependency package.

**Landing / docs**: https://wall.utalabs.tech

Every gateway in the MCP security category (Lasso, Mintive, Obot, agentgateway, Cequence) protects the **consumer** — the company whose employees connect agents to third-party servers. Nothing protects the **operator** — the SaaS that publishes its MCP server and exposes its database to every anonymous agent on the internet.

`uta-shield` is the mirror side: you wrap YOUR MCP server and gain identity, reputation gates, threat-intel blocking, rate limits, DLP masking, per-call metering and a JSONL audit trail — without touching your server code.

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

# 4. THE FIREWALL: wrap your MCP server (2 minutes, zero code changes)
npx uta-shield wrap --upstream http://localhost:3001 --port 8787
#    → agents now talk to :8787; your server stays at :3001
#    GET /health · GET /pricing (x402-ready) · GET /audit

# 5. See it all live
node demo/run-demo.mjs
```

## The 8 layers

| # | Layer | Status in v0.1.0 |
|---|-------|------------------|
| 1 | Agent identity (`x-agent-name` / passport header, `--require-identity`, optional `/.well-known/agent.json` verification) | **SHIPPED** |
| 2 | Reputation score per agent | hook (identity verdicts recorded; scoring = roadmap) |
| 3 | Threat-intel in/out (IOC feed: domains, URLs, IPs, emails, hashes, wildcards — inbound args AND outbound responses) | **SHIPPED** |
| 4 | Rate limiting + tiers (token bucket per agent+tool, free/paid) | **SHIPPED** |
| 5 | Billing: per-call metering + x402-ready pricing manifest (settlement delegated to operator payment layer) | **SHIPPED (metering)** |
| 6 | DLP: emails, JWTs, AWS keys, API tokens, private keys, cards masked in responses | **SHIPPED** |
| 7 | Reverse drift alerts (notify clients if schema changes) | roadmap |
| 8 | Audit: JSONL per decision (indicator + campaign for triage, never raw args) | **SHIPPED** |

Honesty policy: this README marks exactly what ships. Layers 2 and 7 are design hooks — no inflated claims.

## Why zero dependencies?

A security product with 47 transitive dependencies is an attack surface, not a defense. `uta-shield` is ~1,200 lines of auditable Node.js ≥18 (ESM), including a hand-rolled MCP stdio implementation (newline-delimited JSON-RPC 2.0). `npm pack` = 19.8 kB.

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

## Test

```bash
node --test test/*.test.mjs   # 28 tests: feed matching, DLP, rate limit, gates, MCP protocol
```

Licensed for use — see [LICENSE](LICENSE) (license for use / licencia de uso). © 2026 AliceLabs LLC. Commercial exceptions (white label, OEM, redistribution, managed service): support@alicelabs.energy
