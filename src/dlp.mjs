// uta-shield — DLP masking layer (layer 6 of the UTA Shield design).
// Masks secrets and PII in responses flowing OUT to agents whose identity
// is unknown or unverified. Findings are counts only — never echo the secret.

const PATTERNS = [
  { kind: "email", rx: /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi, replace: "[EMAIL_REDACTED]" },
  { kind: "jwt", rx: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g, replace: "[JWT_REDACTED]" },
  { kind: "aws_access_key", rx: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, replace: "[AWS_KEY_REDACTED]" },
  { kind: "api_key_generic", rx: /\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{15,})\b/g, replace: "[API_KEY_REDACTED]" },
  { kind: "bearer_header", rx: /\b(?:Bearer|token)\s+[A-Za-z0-9._~+/=-]{20,}\b/gi, replace: "$1 [TOKEN_REDACTED]" },
  { kind: "private_key_block", rx: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, replace: "[PRIVATE_KEY_REDACTED]" },
  { kind: "credit_card", rx: /\b(?:\d[ -]*?){13,16}\b/g, replace: "[CARD_REDACTED]" }
];

export function maskSensitive(text, { enabled = true } = {}) {
  if (!enabled || typeof text !== "string" || !text) return { masked: text, findings: [] };
  let masked = text;
  const findings = [];
  for (const p of PATTERNS) {
    const matches = masked.match(p.rx);
    if (matches && matches.length) {
      findings.push({ kind: p.kind, count: matches.length });
      masked = masked.replace(p.rx, p.replace);
    }
  }
  return { masked, findings };
}

export function maskDeep(value, opts) {
  // Recursively masks strings inside JSON-serializable structures.
  if (typeof value === "string") return maskSensitive(value, opts).masked;
  if (Array.isArray(value)) return value.map(v => maskDeep(v, opts));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = maskDeep(v, opts);
    return out;
  }
  return value;
}
