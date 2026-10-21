// uta-shield — metering & billing hooks (layer 5). Agentic-commerce ready:
// per-call metering, tier pricing, x402-style pricing manifest. It meters and
// exposes the manifest; settlement (x402/USDC) is delegated to the operator's
// payment layer (e.g. m2m-checkout). Honest scope, no fake settlement.

export class Billing {
  constructor({ enabled = false, currency = "USDC", prices = {}, freeTier = { callsPerMonth: 1000 } } = {}) {
    this.enabled = enabled;
    this.currency = currency;
    this.prices = prices;                 // { "tool_name": { amount: "0.001", unit: "per-call" } }
    this.freeTier = freeTier;
    this.usage = new Map();               // agent -> { calls, billable, month }
  }

  priceFor(tool) { return this.prices[tool] || null; }

  meter(agent, tool, verdict) {
    if (!this.enabled || verdict !== "ALLOW") return null;
    const month = new Date().toISOString().slice(0, 7);
    let u = this.usage.get(agent);
    if (!u || u.month !== month) { u = { month, calls: 0, billable: 0 }; this.usage.set(agent, u); }
    u.calls += 1;
    const price = this.priceFor(tool);
    if (price && u.calls > this.freeTier.callsPerMonth) {
      u.billable += 1;
      return { charged: price.amount, currency: this.currency, tool };
    }
    return { charged: "0", currency: this.currency, tool, note: "free-tier" };
  }

  statement(agent) {
    return { agent, ...(this.usage.get(agent) || { month: new Date().toISOString().slice(0, 7), calls: 0, billable: 0 }) };
  }

  x402Manifest() {
    return {
      version: "x402-ready",
      currency: this.currency,
      note: "settlement delegated to operator payment layer; manifest exposes prices per tool",
      prices: Object.fromEntries(Object.entries(this.prices).map(([tool, p]) => [tool, { amount: p.amount, unit: p.unit || "per-call" }]))
    };
  }
}
