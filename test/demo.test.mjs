import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { repo, run } from '../test-support/tree.mjs';

const KINDS = ['HARDCODED-DAYS', 'HOOK-MISSING', 'HOOK-NOT-EXECUTABLE', 'RENEW-WINDOW', 'TIMER-INFREQUENT', 'ACMEJSON-PERMS', 'DEAD-AUTH', 'OLD-CLIENT'];

test('demo trips every finding kind and exits 1', () => {
  const r = run(['demo', '--json']);
  assert.equal(r.status, 1, r.err);
  const j = JSON.parse(r.out);
  const seen = new Set(j.findings.map((f) => f.kind));
  for (const k of KINDS) assert.ok(seen.has(k), `demo does not show ${k}`);
});

test('demo from a clean HOME with no npm cache and no network config', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'acme-audit-home-'));
  const r = run(['demo'], { HOME: home, XDG_CACHE_HOME: path.join(home, '.cache'), npm_config_cache: path.join(home, '.npm') });
  assert.equal(r.status, 1, r.err);
  assert.match(r.out, /HARDCODED-DAYS/);
  assert.deepEqual(fs.readdirSync(home), [], 'the demo wrote nothing into HOME');
});

test('demo removes its temp tree and prints how to run the same on a real machine', () => {
  const before = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('acme-audit-demo-'));
  const r = run(['demo']);
  const after = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('acme-audit-demo-'));
  assert.deepEqual(after, before);
  assert.match(r.out, /acme-audit --root/);
});

test('demo output has no home paths, hostnames or personal data', () => {
  const r = run(['demo']);
  assert.ok(!r.out.includes(os.homedir()), 'real home dir leaked into demo output');
  assert.ok(!r.out.includes(os.tmpdir() + '/acme-audit-demo'), 'temp dir name leaked');
});

test('the demo tree builder is the only module that writes files', () => {
  const dir = path.join(repo, 'src');
  const writers = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/\b(writeFile|writeFileSync|appendFile|appendFileSync|mkdirSync|mkdtempSync|rmSync|unlinkSync|renameSync|chmodSync|symlinkSync|createWriteStream|copyFileSync)\b/.test(fs.readFileSync(p, 'utf8'))) writers.push(path.relative(dir, p)); } };
  walk(dir);
  assert.deepEqual(writers, ['demo-tree.mjs']);
});
