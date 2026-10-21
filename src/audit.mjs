// uta-shield — audit log (layer 8). JSONL, one event per gate decision.
// Log contains findings metadata only — never secrets or full payloads.

import { appendFileSync } from "node:fs";

export class AuditLog {
  constructor({ file = null, memory = 500 } = {}) {
    this.file = file;
    this.ring = [];
    this.max = memory;
    this.seq = 0;
  }

  log(event) {
    const rec = {
      ts: new Date().toISOString(),
      seq: ++this.seq,
      ...event
    };
    this.ring.push(rec);
    if (this.ring.length > this.max) this.ring.shift();
    if (this.file) {
      try { appendFileSync(this.file, JSON.stringify(rec) + "\n"); } catch { /* non-fatal */ }
    }
    return rec;
  }

  last(n = 20) { return this.ring.slice(-n); }

  stats() {
    const byVerdict = {};
    for (const r of this.ring) byVerdict[r.verdict] = (byVerdict[r.verdict] || 0) + 1;
    return { events: this.ring.length, by_verdict: byVerdict };
  }
}
