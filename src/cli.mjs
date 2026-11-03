import fs from 'node:fs';
import { audit } from './audit.mjs';
import { runDemo } from './demo.mjs';
import { renderText } from './report.mjs';

const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const HELP = `acme-audit ${pkg.version}: read-only lint of how a machine renews its ACME certificates

Usage:
  acme-audit [--root DIR] [options]
  acme-audit demo [--json]

Options:
  --root DIR          Audit the machine tree under DIR instead of / (or set ACME_AUDIT_ROOT)
  --json              Print the report as JSON (schema in docs/json-schema.md)
  --fail-on LEVEL     Exit 1 only for findings at LEVEL or worse: error, warn or info (default info)
  --schedule FILE     Use another schedule file instead of data/schedule.json
  --lifetime DAYS     Also test against a certificate lifetime of DAYS (repeatable)
  --version           Print the version
  --help              Print this help

demo audits a bundled fake machine that has one of each kind of finding.
Exit codes: 0 clean, 1 findings, 2 error. It never runs certbot, never uses the network and never writes.
`;

const LEVELS = { error: 0, warn: 1, info: 2 };

export function parseArgs(argv) {
  const o = { root: process.env.ACME_AUDIT_ROOT || '/', json: false, failOn: 'info', schedule: undefined, lifetimes: [], demo: false, help: false, version: false };
  const need = (i, name) => {
    if (i + 1 >= argv.length) throw new Error(`${name} needs a value`);
    return argv[i + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === 'demo') o.demo = true;
    else if (a === '--json') o.json = true;
    else if (a === '--help' || a === '-h') o.help = true;
    else if (a === '--version' || a === '-V') o.version = true;
    else if (a === '--root') o.root = need(i++, a);
    else if (a === '--schedule') o.schedule = need(i++, a);
    else if (a === '--fail-on') {
      o.failOn = need(i++, a);
      if (!(o.failOn in LEVELS)) throw new Error(`--fail-on must be error, warn or info, not ${o.failOn}`);
    } else if (a === '--lifetime') {
      const n = Number(need(i++, a));
      if (!(n > 0)) throw new Error('--lifetime must be a positive number of days');
      o.lifetimes.push(n);
    } else throw new Error(`unknown option ${a}`);
  }
  return o;
}

export function main(argv, io = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s), tty: process.stdout.isTTY }) {
  let o;
  try {
    o = parseArgs(argv);
  } catch (e) {
    io.err(`acme-audit: ${e.message}\nRun acme-audit --help for the options.\n`);
    return 2;
  }
  if (o.help) { io.out(HELP); return 0; }
  if (o.version) { io.out(`${pkg.version}\n`); return 0; }
  try {
    let report;
    let label = o.root;
    if (o.demo) {
      report = runDemo({ version: pkg.version, scheduleFile: o.schedule, lifetimes: o.lifetimes });
      label = '(bundled fake machine)';
    } else {
      if (!fs.existsSync(o.root) || !fs.statSync(o.root).isDirectory()) throw new Error(`root ${o.root} is not a directory`);
      report = audit({ root: o.root, scheduleFile: o.schedule, lifetimes: o.lifetimes, version: pkg.version });
    }
    if (o.demo) report.root = label;
    if (o.json) io.out(`${JSON.stringify(report, null, 2)}\n`);
    else {
      if (o.demo) io.out('acme-audit demo: a fake machine built in a temp dir with one of each kind of finding, removed afterwards.\n\n');
      io.out(renderText(report, { color: Boolean(io.tty) && !process.env.NO_COLOR, rootLabel: label }));
      if (o.demo) io.out('\nThe same on a real machine: acme-audit --root /\n');
    }
    const worst = Math.max(-1, ...report.findings.map((f) => 2 - LEVELS[f.severity]));
    return worst >= 2 - LEVELS[o.failOn] ? 1 : 0;
  } catch (e) {
    io.err(`acme-audit: ${e.message}\n`);
    return 2;
  }
}
