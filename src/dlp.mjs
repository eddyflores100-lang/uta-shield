// uta-shield — DLP masking layer (layer 6 of the UTA Shield design).
// Masks secrets and PII in responses flowing OUT to agents whose identity
// is unknown or unverified. Findings are counts only — never echo the secret.
//
// v0.2.0 fixes and additions:
//   - FIX: bearer/token substitution had `$1` with no capture group (v0.1.0
//     emitted a literal "$1" into masked output). Now groups are explicit.
//   - NEW formats: GCP API keys, GitHub fine-grained PATs, Stripe keys,
//     high-entropy hex secrets, obfuscated emails ("name at corp dot com").
//   - Credit cards now require a Luhn check — phone numbers no longer match.
//   - Optional base64-blob masking (off by default: legit binary payloads).

const PATTERNS = [
  { kind: "email", rx: /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi, replace: "[EMAIL_REDACTED]" },
  {
    kind: "email_obfuscated",
    // jane at corp dot com · jane(at)corp(dot)com · jane [at] corp [.] com · arroba/punto
    rx: /\b[a-z0-9._%+-]{2,}\s*(?:\(|\[|\{)?\s*(?:at|arroba)\s*(?:\)|\]|\})?\s*[a-z0-9-]{2,}\s*(?:\(|\[|\{)?\s*(?:\.|\[\.|\{\.)?\s*(?:dot|punto)\s*(?:\)|\]|\})?\s*[a-z]{2,}\b/gi,
    replace: "[EMAIL_OBFUSCATED_REDACTED]"
  },
  { kind: "jwt", rx: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g, replace: "[JWT_REDACTED]" },
  { kind: "aws_access_key", rx: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, replace: "[AWS_KEY_REDACTED]" },
  { kind: "gcp_api_key", rx: /\bAIza[0-9A-Za-z_-]{35}\b/g, replace: "[GCP_KEY_REDACTED]" },
  { kind: "github_fine_grained", rx: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, replace: "[API_KEY_REDACTED]" },
  { kind: "stripe_key", rx: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g, replace: "[API_KEY_REDACTED]" },
  { kind: "api_key_generic", rx: /\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{15,})\b/g, replace: "[API_KEY_REDACTED]" },
  {
    kind: "bearer_header",
    // FIX (v0.1.0): `$1` referenced a capture group that did not exist.
    rx: /\b((?:bearer|token)[\s=:|]+)([A-Za-z0-9._~+/=-]{20,})\b/gi,
    replace: "$1[TOKEN_REDACTED]"
  },
  { kind: "private_key_block", rx: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, replace: "[PRIVATE_KEY_REDACTED]" },
  { kind: "hex_secret", rx: /\b[a-f0-9]{40,}\b/gi, replace: "[HEX_SECRET_REDACTED]" },
  { kind: "base64_blob", rx: /\b[A-Za-z0-9+/]{64,}={0,2}\b/g, replace: "[BASE64_BLOB_REDACTED]", optional: "base64" },
  { kind: "credit_card", rx: /\b(?:\d[ -]?){12,15}\d\b/g, replace: "[CARD_REDACTED]", luhn: true }
];

function luhnOk(digits) {
  const d = digits.replace(/[ -]/g, "");
  if (!/^\d{13,16}$/.test(d)) return false;
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = Number(d[i]);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function maskSensitive(text, { enabled = true, base64 = false } = {}) {
  if (!enabled || typeof text !== "string" || !text) return { masked: text, findings: [] };
  let masked = text;
  const findings = [];
  for (const p of PATTERNS) {
    if (p.optional && !base64) continue;
    if (p.luhn) {
      const matches = masked.match(p.rx);
      if (matches && matches.length) {
        let count = 0;
        masked = masked.replace(p.rx, m => (luhnOk(m) ? (count++, p.replace) : m));
        if (count) findings.push({ kind: p.kind, count });
      }
      continue;
    }
    const matches = masked.match(p.rx);
    if (matches && matches.length) {
      findings.push({ kind: p.kind, count: matches.length });
      masked = masked.replace(p.rx, p.replace);
    }
  }
  return { masked, findings };
}

export function maskDeepDetailed(value, opts) {
  // Recursively masks strings inside JSON-serializable structures,
  // aggregating findings from every depth (v0.2.0).
  if (typeof value === "string") {
    const r = maskSensitive(value, opts);
    return { value: r.masked, findings: r.findings };
  }
  if (Array.isArray(value)) {
    const arr = [], findings = [];
    for (const v of value) {
      const r = maskDeepDetailed(v, opts);
      arr.push(r.value);
      findings.push(...r.findings);
    }
    return { value: arr, findings };
  }
  if (value && typeof value === "object") {
    const out = {}, findings = [];
    for (const [k, v] of Object.entries(value)) {
      const r = maskDeepDetailed(v, opts);
      out[k] = r.value;
      findings.push(...r.findings);
    }
    return { value: out, findings };
  }
  return { value, findings: [] };
}

export function maskDeep(value, opts) {
  return maskDeepDetailed(value, opts).value;
}
