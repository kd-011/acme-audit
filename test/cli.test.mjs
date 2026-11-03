import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { audit, certbotConf, enableCertbotTimer, makeRoot, put, repo, run, snapshot } from '../test-support/tree.mjs';

const pkg = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'));

function dirty() {
  const root = makeRoot();
  put(root, 'etc/letsencrypt/renewal/example.com.conf', certbotConf({ before: '90 days', hooks: { renew_hook: '/nowhere/hook.sh' } }));
  fs.mkdirSync(`${root}/var/www/html`, { recursive: true });
  enableCertbotTimer(root);
  return root;
}

test('--version prints the package version', () => {
  const r = run(['--version']);
  assert.equal(r.status, 0);
  assert.equal(r.out.trim(), pkg.version);
});

test('exit codes: 0 when clean, 1 with findings, 2 for an error', () => {
  const clean = makeRoot();
  put(clean, 'etc/letsencrypt/renewal/example.com.conf', certbotConf({ hooks: { renew_hook: 'systemctl reload nginx' } }));
  fs.mkdirSync(`${clean}/var/www/html`, { recursive: true });
  enableCertbotTimer(clean);
  assert.equal(run(['--root', clean]).status, 0);
  assert.equal(run(['--root', dirty()]).status, 1);
  const missing = run(['--root', path.join(os.tmpdir(), 'acme-audit-no-such-root')]);
  assert.equal(missing.status, 2);
  assert.match(missing.err, /no-such-root/);
  assert.equal(run(['--bogus']).status, 2);
  assert.equal(run(['--root']).status, 2);
});

test('an empty root is clean and says nothing was found to audit', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'acme-audit-empty-'));
  const r = run(['--root', root]);
  assert.equal(r.status, 0);
  assert.match(r.out, /nothing to audit|no ACME/i);
});

test('--fail-on error ignores warnings and notes', () => {
  const root = makeRoot();
  put(root, 'etc/letsencrypt/renewal/example.com.conf', certbotConf({ before: '5 days', version: '2.1.0' }));
  fs.mkdirSync(`${root}/var/www/html`, { recursive: true });
  enableCertbotTimer(root);
  assert.equal(run(['--root', root]).status, 1);
  assert.equal(run(['--root', root, '--fail-on', 'error']).status, 0);
  assert.equal(run(['--root', root, '--fail-on', 'warn']).status, 1);
});

test('ACME_AUDIT_ROOT is used when --root is not given, and --root wins over it', () => {
  const root = dirty();
  assert.equal(run([], { ACME_AUDIT_ROOT: root }).status, 1);
  const clean = fs.mkdtempSync(path.join(os.tmpdir(), 'acme-audit-empty-'));
  assert.equal(run(['--root', clean], { ACME_AUDIT_ROOT: root }).status, 0);
});

test('--json has the documented keys and the findings carry the documented fields', () => {
  const res = audit(dirty());
  const j = res.json;
  assert.deepEqual(Object.keys(j), ['tool', 'schema', 'version', 'root', 'schedule', 'summary', 'findings', 'notes', 'scanned']);
  assert.equal(j.tool, 'acme-audit');
  assert.equal(j.schema, 1);
  assert.equal(j.version, pkg.version);
  assert.deepEqual(Object.keys(j.summary), ['error', 'warn', 'info', 'total']);
  assert.equal(j.summary.total, j.findings.length);
  assert.deepEqual(Object.keys(j.schedule), ['checked', 'targets']);
  for (const f of j.findings) {
    assert.deepEqual(Object.keys(f), ['kind', 'severity', 'client', 'file', 'line', 'summary', 'why', 'detail']);
    assert.ok(['HARDCODED-DAYS', 'HOOK-MISSING', 'HOOK-NOT-EXECUTABLE', 'RENEW-WINDOW', 'TIMER-INFREQUENT', 'ACMEJSON-PERMS', 'DEAD-AUTH', 'OLD-CLIENT'].includes(f.kind));
    assert.ok(['error', 'warn', 'info'].includes(f.severity));
    assert.equal(typeof f.summary, 'string');
    assert.equal(typeof f.why, 'string');
  }
  const order = { error: 0, warn: 1, info: 2 };
  const sorted = [...j.findings].sort((a, b) => order[a.severity] - order[b.severity]);
  assert.deepEqual(j.findings.map((f) => f.kind), sorted.map((f) => f.kind), 'worst first');
});

test('the human output names kind, file and line, and does not print the root twice', () => {
  const r = run(['--root', dirty()]);
  assert.match(r.out, /ERROR\s+HOOK-MISSING\s+\/etc\/letsencrypt\/renewal\/example\.com\.conf:\d+/);
  assert.match(r.out, /RENEW-WINDOW/);
});

test('it never writes: the tree is byte for byte the same afterwards', () => {
  const root = dirty();
  put(root, 'etc/traefik/traefik.yml', 'certificatesResolvers:\n  le:\n    acme:\n      storage: /etc/traefik/acme.json\n');
  put(root, 'etc/traefik/acme.json', '{}', 0o644);
  const before = snapshot(root);
  run(['--root', root]);
  run(['--root', root, '--json']);
  assert.equal(snapshot(root), before);
});

test('--help lists the options and exits 0', () => {
  const r = run(['--help']);
  assert.equal(r.status, 0);
  for (const w of ['--root', '--json', '--fail-on', '--schedule', '--lifetime', 'demo', '--version']) assert.ok(r.out.includes(w), w);
});
