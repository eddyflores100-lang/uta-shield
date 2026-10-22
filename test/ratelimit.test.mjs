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

test("takeMulti: per-IP ceiling applies on top of per-agent buckets", () => {
  const rl = new RateLimiter({ ratePerMin: 1, burst: 5, ipRatePerMin: 1, ipBurst: 2 });
  assert.equal(rl.takeMulti([{ key: "ip:1.2.3.4", ip: true }, { key: "agent:v|t" }]).ok, true);
  assert.equal(rl.takeMulti([{ key: "ip:1.2.3.4", ip: true }, { key: "agent:v|t" }]).ok, true);
  // agent bucket still has 3 tokens, but the IP bucket is empty → limited
  const r3 = rl.takeMulti([{ key: "ip:1.2.3.4", ip: true }, { key: "agent:v|t" }]);
  assert.equal(r3.ok, false);
  assert.match(r3.key, /^ip:/);
});

test("takeMulti: all-or-nothing — no tokens consumed when any bucket is empty", () => {
  const rl = new RateLimiter({ ratePerMin: 1, burst: 1, ipRatePerMin: 1, ipBurst: 5 });
  assert.equal(rl.take("agent:x|t").ok, true); // agent bucket now empty
  const before = rl.buckets.get("ip:9.9.9.9") ? rl.buckets.get("ip:9.9.9.9").tokens : 5;
  const r = rl.takeMulti([{ key: "ip:9.9.9.9", ip: true }, { key: "agent:x|t" }]);
  assert.equal(r.ok, false);
  const after = rl.buckets.get("ip:9.9.9.9")?.tokens ?? 5;
  assert.equal(after, before, "IP bucket must not be consumed when the combined check fails");
});

test("anti-rotation: declared-name churn cannot escape the per-IP bucket", () => {
  const rl = new RateLimiter({ ratePerMin: 1, burst: 2, ipRatePerMin: 1, ipBurst: 2 });
  const ips = "10.0.0.1";
  let limited = 0;
  for (let i = 0; i < 10; i++) {
    const r = rl.takeMulti([{ key: `ip:${ips}`, ip: true }]); // no verified agent bucket
    if (!r.ok) limited++;
  }
  assert.equal(limited, 8);
});

test("prune caps memory under key churn", () => {
  const rl = new RateLimiter({ maxBuckets: 50, maxIdleMs: 0 });
  for (let i = 0; i < 5000; i++) rl.take(`churn-${i}|t`);
  assert.ok(rl.buckets.size <= 50 + 1, `buckets=${rl.buckets.size}`);
});

test("ipConfig separates the per-IP ceiling from per-agent defaults", () => {
  const rl = new RateLimiter({ ratePerMin: 30, burst: 10, ipRatePerMin: 120, ipBurst: 60 });
  assert.deepEqual(rl.ipConfig(), { ratePerMin: 120, burst: 60 });
});
