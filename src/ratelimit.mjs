// uta-shield — rate limiting (layer 4). v0.2.0: two-tier token buckets.
//
//   per-IP bucket        → ALWAYS applied (network origin; cannot be rotated)
//   per-agent bucket     → ONLY for VERIFIED agents (HMAC); keyed by the
//                          canonical verified name + tool
//
// A caller that merely DECLARAS a name gets no per-agent bucket: rotating
// declared names no longer resets limits. Buckets are pruned lazily so
// attacker-controlled IP/agent churn cannot grow memory unbounded.

export class RateLimiter {
  constructor({
    ratePerMin = 30, burst = 10,
    tiers = null,                       // e.g. { paid: { ratePerMin: 600, burst: 120 } }
    ipRatePerMin = 120, ipBurst = 60,   // global per-IP ceiling (applies to everyone)
    maxIdleMs = 3600000, maxBuckets = 10000
  } = {}) {
    this.ratePerMin = ratePerMin;
    this.burst = burst;
    this.tiers = tiers || {};
    this.ipRatePerMin = ipRatePerMin;
    this.ipBurst = ipBurst;
    this.maxIdleMs = maxIdleMs;
    this.maxBuckets = maxBuckets;
    this.buckets = new Map();           // key -> { tokens, last }
    this.now = () => Date.now();
  }

  configFor(tier) {
    return (tier && this.tiers[tier]) || { ratePerMin: this.ratePerMin, burst: this.burst };
  }

  ipConfig() {
    return { ratePerMin: this.ipRatePerMin, burst: this.ipBurst };
  }

  _refill(b, cfg, now) {
    const refill = ((now - b.last) / 60000) * cfg.ratePerMin;
    b.tokens = Math.min(cfg.burst, b.tokens + refill);
    b.last = now;
  }

  _bucket(key, cfg) {
    const now = this.now();
    let b = this.buckets.get(key);
    if (!b) { b = { tokens: cfg.burst, last: now }; this.buckets.set(key, b); }
    this._refill(b, cfg, now);
    return b;
  }

  take(key, tier) {
    // Back-compatible single-bucket consume.
    const cfg = this.configFor(tier);
    const b = this._bucket(key, cfg);
    if (b.tokens >= 1) { b.tokens -= 1; this._maybePrune(); return { ok: true, remaining: Math.floor(b.tokens) }; }
    return { ok: false, retryAfterMs: this._retryAfter(b.tokens, cfg.ratePerMin) };
  }

  // All-or-nothing consume across several buckets (e.g. per-IP + per-agent).
  // entries: [{ key, tier?, ip? }] — `ip:true` uses the per-IP ceiling config.
  takeMulti(entries) {
    if (!Array.isArray(entries) || entries.length === 0) return { ok: true, remaining: 0 };
    const cfgs = entries.map(e => ({ key: e.key, cfg: e.ip ? this.ipConfig() : this.configFor(e.tier) }));
    // peek: every bucket must have a token before any is consumed
    for (const { key, cfg } of cfgs) {
      const b = this._bucket(key, cfg);
      if (b.tokens < 1) return { ok: false, retryAfterMs: this._retryAfter(b.tokens, cfg.ratePerMin), key };
    }
    let remaining = Infinity;
    for (const { key, cfg } of cfgs) {
      const b = this.buckets.get(key);
      b.tokens -= 1;
      remaining = Math.min(remaining, b.tokens);
    }
    this._maybePrune();
    return { ok: true, remaining: Number.isFinite(remaining) ? Math.floor(remaining) : 0 };
  }

  _retryAfter(tokens, ratePerMin) {
    return Math.ceil((1 - tokens) / ratePerMin * 60000);
  }

  _maybePrune() {
    if (this.buckets.size <= this.maxBuckets) return;
    const cutoff = this.now() - this.maxIdleMs;
    for (const [k, b] of this.buckets) if (b.last < cutoff) this.buckets.delete(k);
    // hard cap: drop oldest half if still over
    if (this.buckets.size > this.maxBuckets) {
      const entries = [...this.buckets.entries()].sort((a, b) => a[1].last - b[1].last);
      for (let i = 0; i < Math.floor(entries.length / 2); i++) this.buckets.delete(entries[i][0]);
    }
  }

  reset(key) { this.buckets.delete(key); }
}
