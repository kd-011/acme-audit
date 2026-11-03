// Shared state for one audit run: what was found, what was seen, and what each check may read.
export class Ctx {
  constructor(tree, schedule) {
    this.tree = tree;
    this.schedule = schedule;
    this.findings = [];
    this.notes = [];
    this.found = { certbot: 0, acmesh: 0, lego: 0, caddy: 0, traefik: 0 };
    this.counts = { timers: 0, cron_files: 0, scripts: 0 };
    this.schedulers = [];
    this.scanFiles = new Map();
    this.claimed = new Set();
    this.seen = new Set();
  }

  add({ kind, severity, client, file, line = null, summary, why, detail = {} }) {
    const key = `${kind}|${file}|${line}|${summary}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.findings.push({ kind, severity, client, file, line, summary, why, detail });
  }

  note(file, message) {
    this.notes.push({ file, message });
  }

  // Files whose lines are searched for renewal commands and hardcoded numbers.
  scan(file) {
    if (!this.scanFiles.has(file)) this.scanFiles.set(file, true);
  }
}

const ORDER = { error: 0, warn: 1, info: 2 };

export function sortFindings(findings) {
  return findings
    .map((f, i) => [f, i])
    .sort(([a, i], [b, j]) => ORDER[a.severity] - ORDER[b.severity] || i - j)
    .map(([f]) => f);
}

export const isStaging = (url) => /acme-staging/i.test(url);
