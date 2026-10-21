// uta-shield — rate limiting (layer 4). Token bucket per agent+tool,
// with free/paid tier awareness via `limits` config.

export class RateLimiter {
  constructor({ ratePerMin = 30, burst = 10, tiers = null } = {}) {
    this.ratePerMin = ratePerMin;
    this.burst = burst;
    this.tiers = tiers || {};          // e.g. { paid: { ratePerMin: 600, burst: 120 } }
    this.buckets = new Map();          // key -> { tokens, last }
    this.now = () => Date.now();
  }

  configFor(tier) {
    return (tier && this.tiers[tier]) || { ratePerMin: this.ratePerMin, burst: this.burst };
  }

  take(key, tier) {
    const { ratePerMin, burst } = this.configFor(tier);
    const now = this.now();
    let b = this.buckets.get(key);
    if (!b) { b = { tokens: burst, last: now }; this.buckets.set(key, b); }
    const refill = ((now - b.last) / 60000) * ratePerMin;
    b.tokens = Math.min(burst, b.tokens + refill);
    b.last = now;
    if (b.tokens >= 1) { b.tokens -= 1; return { ok: true, remaining: Math.floor(b.tokens) }; }
    const retryAfterMs = Math.ceil((1 - b.tokens) / ratePerMin * 60000);
    return { ok: false, retryAfterMs };
  }

  reset(key) { this.buckets.delete(key); }
}
