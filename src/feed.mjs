// uta-shield — PhishGuard feed engine (zero-dependency)
// Loads, validates and queries IOC feeds. Matching rules are intentionally
// conservative: every verdict carries the exact IOC + campaign as evidence.

import { readFileSync } from "node:fs";

export const FEED_SCHEMA = "pg/1";

export const IOC_TYPES = [
  "domain", "url", "ip", "email-addr", "email-subject",
  "filename", "filepath", "sha256", "mutex/process-name"
];

const rxUrl = /(https?:\/\/[^\s"'<>\\)\]]+)/gi;
const rxDomain = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const rxIp = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const rxSha256 = /\b[a-f0-9]{64}\b/gi;
const rxEmail = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;

function escapeRx(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function wildcardRx(value) {
  return new RegExp("^" + escapeRx(value).replace(/\\\*/g, ".*") + "$", "i");
}

export function validateFeed(feed) {
  const errs = [];
  if (!feed || typeof feed !== "object") errs.push("feed is not an object");
  if (feed.feed_schema !== FEED_SCHEMA) errs.push(`feed_schema must be "${FEED_SCHEMA}", got ${JSON.stringify(feed.feed_schema)}`);
  if (!Array.isArray(feed.campaigns) || feed.campaigns.length === 0) errs.push("campaigns[] missing or empty");
  if (Array.isArray(feed.campaigns)) {
    feed.campaigns.forEach((c, ci) => {
      if (!c.id) errs.push(`campaign[${ci}].id missing`);
      if (!Array.isArray(c.iocs) || c.iocs.length === 0) errs.push(`campaign[${ci}] "${c.id}" has no iocs`);
      if (Array.isArray(c.iocs)) {
        c.iocs.forEach((ioc, ii) => {
          if (!IOC_TYPES.includes(ioc.type)) errs.push(`campaign[${ci}].iocs[${ii}] unknown type "${ioc.type}"`);
          if (!ioc.value || typeof ioc.value !== "string") errs.push(`campaign[${ci}].iocs[${ii}] missing value`);
        });
      }
    });
  }
  return { ok: errs.length === 0, errors: errs };
}

export class Feed {
  constructor(json) {
    const v = validateFeed(json);
    if (!v.ok) {
      const e = new Error("invalid feed: " + v.errors.join("; "));
      e.code = "EFEED";
      throw e;
    }
    this.raw = json;
    this.version = json.version || "0.0.0";
    this.generated = json.generated || null;
    this.license = json.license || null;
    this.campaigns = json.campaigns;
    // indexes
    this.exact = new Map();   // type -> Map(lower(value) -> ioc[])
    this.suffix = [];         // domain IOCs for subdomain matching
    this.prefixUrl = [];      // url IOCs for prefix matching
    this.wildcards = [];      // filepath/filename with *
    for (const c of this.campaigns) {
      for (const ioc of c.iocs) {
        const t = ioc.type;
        if (t === "domain") {
          this.suffix.push({ ioc, campaign: c, value: ioc.value.toLowerCase() });
          this._put(t, ioc.value.toLowerCase(), ioc, c);
        } else if (t === "url") {
          this.prefixUrl.push({ ioc, campaign: c, value: ioc.value.toLowerCase().replace(/\/+$/, "") });
          this._put(t, ioc.value.toLowerCase().replace(/\/+$/, ""), ioc, c);
        } else if (t === "filepath" || t === "filename") {
          if (ioc.value.includes("*")) this.wildcards.push({ ioc, campaign: c, rx: wildcardRx(ioc.value) });
          this._put(t, ioc.value.toLowerCase(), ioc, c);
        } else {
          this._put(t, ioc.value.toLowerCase(), ioc, c);
        }
      }
    }
  }

  _put(type, key, ioc, campaign) {
    if (!this.exact.has(type)) this.exact.set(type, new Map());
    const m = this.exact.get(type);
    if (!m.has(key)) m.set(key, []);
    m.get(key).push({ ioc, campaign });
  }

  static fromFile(path) {
    return new Feed(JSON.parse(readFileSync(path, "utf8")));
  }

  static async fromFetch(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`feed fetch ${url} -> HTTP ${res.status}`);
    return new Feed(await res.json());
  }

  lookup(value) {
    if (typeof value !== "string" || !value.trim()) return { matched: false };
    const raw = value.trim();
    const low = raw.toLowerCase();

    const hitExact = (type, key) => {
      const m = this.exact.get(type);
      return m && m.has(key) ? m.get(key) : null;
    };

    // sha256
    let hits = hitExact("sha256", low);
    if (hits) return this._verdict(hits, raw, "exact");

    // ip
    hits = hitExact("ip", low);
    if (hits) return this._verdict(hits, raw, "exact");

    // email
    hits = hitExact("email-addr", low) || hitExact("email-subject", low) || hitExact("mutex/process-name", low);
    if (hits) return this._verdict(hits, raw, "exact");

    // domain: exact or subdomain-of
    if (rxDomainFull(low)) {
      const sub = this.suffix.find(s => low === s.value || low.endsWith("." + s.value));
      if (sub) return this._verdict([{ ioc: sub.ioc, campaign: sub.campaign }], raw, sub.value === low ? "exact" : "subdomain");
      const ex = hitExact("domain", low);
      if (ex) return this._verdict(ex, raw, "exact");
    }

    // url: prefix match against IOC urls
    if (/^https?:\/\//i.test(low)) {
      const norm = low.replace(/\/+$/, "");
      const p = this.prefixUrl.find(u => norm === u.value || norm.startsWith(u.value + "/") || norm.startsWith(u.value + "?"));
      if (p) return this._verdict([{ ioc: p.ioc, campaign: p.campaign }], raw, "url-prefix");
      // url whose host matches a domain IOC
      try {
        const host = new URL(raw).hostname.toLowerCase();
        const sub = this.suffix.find(s => host === s.value || host.endsWith("." + s.value));
        if (sub) return this._verdict([{ ioc: sub.ioc, campaign: sub.campaign }], raw, "url-host-subdomain");
      } catch { /* not parseable; fall through */ }
    }

    // filename / filepath (exact then wildcard)
    hits = hitExact("filepath", low) || hitExact("filename", low);
    if (hits) return this._verdict(hits, raw, "exact");
    const w = this.wildcards.find(x => x.rx.test(raw));
    if (w) return this._verdict([{ ioc: w.ioc, campaign: w.campaign }], raw, "wildcard");

    return { matched: false };
  }

  _verdict(hits, query, how) {
    return {
      matched: true,
      how,
      query,
      ioc: hits[0].ioc,
      campaign: {
        id: hits[0].campaign.id,
        name: hits[0].campaign.name,
        status: hits[0].campaign.status || null
      },
      all_hits: hits.length
    };
  }

  // Extract candidate indicators from arbitrary text and screen them all.
  screenText(text) {
    const cands = extractIndicators(text);
    const hits = [];
    for (const c of cands) {
      const v = this.lookup(c.value);
      if (v.matched) hits.push({ candidate_type: c.type, ...v });
    }
    return { scanned: cands.length, hits };
  }

  stats() {
    const byType = {};
    for (const c of this.campaigns) {
      for (const ioc of c.iocs) byType[ioc.type] = (byType[ioc.type] || 0) + 1;
    }
    return {
      feed_schema: FEED_SCHEMA, version: this.version, generated: this.generated,
      campaigns: this.campaigns.length, iocs_total: Object.values(byType).reduce((a, b) => a + b, 0),
      iocs_by_type: byType, license: this.license
    };
  }
}

function rxDomainFull(s) {
  return /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(s);
}

export function extractIndicators(text) {
  const out = new Map(); // key: type|value
  const push = (type, value) => {
    const v = value.trim();
    if (v) out.set(type + "|" + v.toLowerCase(), { type, value: v });
  };
  let m;
  for (const re of [rxUrl]) while ((m = re.exec(text)) !== null) push("url", m[0].replace(/[.,;)]+$/, ""));
  for (const re of [rxEmail]) while ((m = re.exec(text)) !== null) push("email-addr", m[0]);
  for (const re of [rxIp]) while ((m = re.exec(text)) !== null) {
    const octets = m[0].split(".").map(Number);
    if (octets.every(o => o >= 0 && o <= 255)) push("ip", m[0]);
  }
  for (const re of [rxSha256]) while ((m = re.exec(text)) !== null) push("sha256", m[0].toLowerCase());
  for (const re of [rxDomain]) while ((m = re.exec(text)) !== null) {
    // skip hosts already inside extracted URLs/emails where possible
    const d = m[0];
    if (text.toLowerCase().includes("http" + d)) continue;
    push("domain", d);
  }
  return [...out.values()];
}

// Advisory heuristic list — never a verdict on its own, always labeled.
export const ADVISORY_TLDS = new Set(["zip", "mov", "top", "ink", "xyz", "cam", "rest"]);

export function urlHeuristics(url) {
  const notes = [];
  try {
    const u = new URL(url);
    const tld = u.hostname.split(".").pop().toLowerCase();
    if (ADVISORY_TLDS.has(tld)) notes.push(`tld ".${tld}" appears in abuse-heavy TLD list (advisory only)`);
    if (u.hostname.split(".").length >= 4) notes.push("deep subdomain nesting (advisory only)");
    if (/%[0-9a-f]{2}/i.test(url) && /@/.test(url)) notes.push("userinfo/encoding trick in URL (advisory only)");
  } catch {
    notes.push("unparseable URL");
  }
  return notes;
}
