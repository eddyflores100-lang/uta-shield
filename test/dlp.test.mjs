import { test } from "node:test";
import assert from "node:assert/strict";
import { maskSensitive, maskDeep } from "../src/dlp.mjs";

test("masks emails, JWTs, AWS keys, generic API keys", () => {
  const r = maskSensitive("user jane@corp.com key AKIAIOSFODNN7EXAMPLE sk-abc123def456ghi789jkl12 and eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U");
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
  const pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----";
  const r = maskSensitive("auth: Bearer abcdef1234567890abcdef12\n" + pem);
  assert.ok(r.masked.includes("[TOKEN_REDACTED]"));
  assert.ok(r.masked.includes("[PRIVATE_KEY_REDACTED]"));
});

test("maskDeep walks nested JSON", () => {
  const out = maskDeep({ contacts: [{ name: "Jane", email: "jane@corp.com" }], note: "call her" });
  assert.equal(out.contacts[0].email, "[EMAIL_REDACTED]");
  assert.equal(out.note, "call her");
});

test("disabled DLP is a no-op", () => {
  const r = maskSensitive("a@b.co", { enabled: false });
  assert.equal(r.masked, "a@b.co");
  assert.deepEqual(r.findings, []);
});
