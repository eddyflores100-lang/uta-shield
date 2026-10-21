import { test } from "node:test";
import assert from "node:assert/strict";
import { RateLimiter } from "../src/ratelimit.mjs";

test("allows burst then rate-limits with retryAfterMs", () => {
  const rl = new RateLimiter({ ratePerMin: 1, burst: 3 });
  let ok = 0, limited = 0, retry = null;
  for (let i = 0; i < 10; i++) {
    const r = rl.take("agentA|search_contacts");
    if (r.ok) ok++; else { limited++; retry = r.retryAfterMs; }
  }
  assert.equal(ok, 3);
  assert.equal(limited, 7);
  assert.ok(retry > 0);
});

test("paid tier gets a higher ceiling", () => {
  const rl = new RateLimiter({
    ratePerMin: 1, burst: 2,
    tiers: { paid: { ratePerMin: 600, burst: 50 } }
  });
  let ok = 0;
  for (let i = 0; i < 20; i++) if (rl.take("agentB|*", "paid").ok) ok++;
  assert.equal(ok, 20);
});

test("independent buckets per agent", () => {
  const rl = new RateLimiter({ ratePerMin: 1, burst: 1 });
  assert.equal(rl.take("a|x").ok, true);
  assert.equal(rl.take("a|x").ok, false);
  assert.equal(rl.take("b|x").ok, true);
});
