import { test } from "node:test";
import assert from "node:assert/strict";
import { maskSensitive, maskDeep, maskDeepDetailed } from "../src/dlp.mjs";

// Secret literals are built at runtime so this test file itself carries no
// real-looking credentials (and mirrors how the DLP sees live traffic).
const AWS_KEY = "AKIA" + "IO" + "SFODNN7" + "EXAMPLE";           // AKIA + 16 [0-9A-Z]
const GCP_KEY = "AIza" + "A".repeat(35);                          // AIza + 35
const GH_PAT = ["github_", "pat_", "1"].join("") + "A".repeat(25); // prefix + >=22
const STRIPE_KEY = ["sk_", "live_"].join("") + "abcdefghijklmnopqrst";
const HEX_SECRET = "0123456789abcdef".repeat(2) + "0123456789abcdef01234567";
const PEM = `-----BEGIN ${["PRIVATE"].join(" ")} KEY-----\nMIIEvQIBADANBg\n-----END ${["PRIVATE"].join(" ")} KEY-----`;
const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

test("masks emails, JWTs, AWS keys, generic API keys", () => {
  const r = maskSensitive(`user jane@corp.com key ${AWS_KEY} sk-abc123def456ghi789jkl12 and ${JWT}`);
  assert.ok(!r.masked.includes("jane@corp.com"));
  assert.ok(r.masked.includes("[EMAIL_REDACTED]"));
  assert.ok(r.masked.includes("[AWS_KEY_REDACTED]"));
  assert.ok(r.masked.includes("[API_KEY_REDACTED]"));
  assert.ok(r.masked.includes("[JWT_REDACTED]"));
  const kinds = r.findings.map(f => f.kind);
  for (const k of ["email", "aws_access_key", "api_key_generic", "jwt"]) assert.ok(kinds.includes(k));
  assert.ok(!JSON.stringify(r.findings).includes("jane@corp.com"), "findings must not leak the secret");
});

test("masks private key blocks and bearer tokens", () => {
  const r = maskSensitive("auth: Bearer abcdef1234567890abcdef12\n" + PEM);
  assert.ok(r.masked.includes("[TOKEN_REDACTED]"));
  assert.ok(r.masked.includes("[PRIVATE_KEY_REDACTED]"));
  assert.ok(!r.masked.includes("MIIEvQIBADANBg"), "key body must not survive");
});

test("REGRESSION v0.2.0: bearer replacement no longer emits a literal '$1'", () => {
  const r = maskSensitive("Authorization: Bearer abcdef1234567890abcdef12");
  assert.ok(!r.masked.includes("$1"), "v0.1.0 bug: '$1' leaked into output");
  assert.ok(r.masked.includes("Bearer [TOKEN_REDACTED]"), "scheme word kept, secret gone");
  assert.ok(!r.masked.includes("abcdef1234567890abcdef12"));
  const r2 = maskSensitive("token=abcdefghijklmnopqrst");
  assert.ok(r2.masked.includes("[TOKEN_REDACTED]"));
  assert.ok(!r2.masked.includes("abcdefghijklmnopqrst"));
});

test("masks GCP API keys, GitHub fine-grained PATs and Stripe keys", () => {
  const r = maskSensitive(`gcp ${GCP_KEY} gh ${GH_PAT} stripe ${STRIPE_KEY}`);
  assert.ok(r.masked.includes("[GCP_KEY_REDACTED]"), r.masked);
  assert.ok(!r.masked.includes("AIza"));
  assert.ok(!r.masked.includes("A".repeat(25)), "PAT body must not survive");
  assert.ok(!r.masked.includes("sk_live_"), r.masked);
});

test("masks high-entropy hex secrets (40+ hex chars)", () => {
  const r = maskSensitive("secret: " + HEX_SECRET);
  assert.ok(r.masked.includes("[HEX_SECRET_REDACTED]"));
  assert.ok(!r.masked.includes("0123456789abcdef"));
});

test("masks obfuscated emails ('name at corp dot com')", () => {
  const r = maskSensitive("contact jane.doe at corp dot com or raul(arroba)startup(punto)io");
  assert.ok(r.masked.includes("[EMAIL_OBFUSCATED_REDACTED]"), r.masked);
  assert.ok(!r.masked.includes("jane.doe"));
  assert.ok(!r.masked.includes("startup"));
});

test("credit card: Luhn-valid numbers masked; phone numbers NOT masked", () => {
  const r = maskSensitive("card 4111 1111 1111 1111 but the office phone is 310 555 0123");
  assert.ok(r.masked.includes("[CARD_REDACTED]"), r.masked);
  assert.ok(r.masked.includes("310 555 0123"), "phone must survive");
  const noLuhn = maskSensitive("ticket id 1234567890123");
  assert.ok(!noLuhn.masked.includes("[CARD_REDACTED]"), "13-digit non-Luhn number must survive");
});

test("base64 blob masking is opt-in (off by default)", () => {
  const b64 = ("QWxhZGRpbjpvcGVuIHNlc2Ft").repeat(3);
  const off = maskSensitive("payload " + b64);
  assert.ok(off.masked.includes(b64), "default: legit base64 payloads untouched");
  const on = maskSensitive("payload " + b64, { base64: true });
  assert.ok(on.masked.includes("[BASE64_BLOB_REDACTED]"));
  assert.ok(on.findings.some(f => f.kind === "base64_blob"));
});

test("maskDeep walks nested JSON", () => {
  const out = maskDeep({ contacts: [{ name: "Jane", email: "jane@corp.com" }], note: "call her" });
  assert.equal(out.contacts[0].email, "[EMAIL_REDACTED]");
  assert.equal(out.note, "call her");
});

test("maskDeepDetailed aggregates findings from every depth", () => {
  const r = maskDeepDetailed({
    a: { b: [{ email: "x@y.co" }] },
    c: AWS_KEY
  });
  const kinds = r.findings.map(f => f.kind);
  assert.ok(kinds.includes("email"));
  assert.ok(kinds.includes("aws_access_key"));
  assert.equal(r.value.a.b[0].email, "[EMAIL_REDACTED]");
});

test("disabled DLP is a no-op", () => {
  const r = maskSensitive("a@b.co", { enabled: false });
  assert.equal(r.masked, "a@b.co");
  assert.deepEqual(r.findings, []);
});
