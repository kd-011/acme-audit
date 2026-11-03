// A tree under --root can contain symlinks that point at the host. They must be followed inside the root only.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { audit, certbotConf, link, makeRoot, put } from '../test-support/tree.mjs';

function outside() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'acme-audit-outside-'));
  fs.mkdirSync(path.join(dir, 'letsencrypt/renewal'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'letsencrypt/renewal/leak.conf'), certbotConf({ name: 'leak.example.com', hooks: { renew_hook: '/nowhere/leak.sh' } }));
  return dir;
}

test('a directory symlink to an absolute host path is read as that path inside the root, not on the host', () => {
  const host = outside();
  const root = makeRoot();
  link(root, 'etc/letsencrypt', path.join(host, 'letsencrypt'));
  const res = audit(root);
  assert.equal(res.json.scanned.certbot_lineages, 0);
  assert.deepEqual(res.findings, []);
});

test('a file symlink to an absolute host path is dangling inside the root', () => {
  const host = outside();
  const root = makeRoot();
  link(root, 'etc/letsencrypt/renewal/leak.conf', path.join(host, 'letsencrypt/renewal/leak.conf'));
  const res = audit(root);
  assert.equal(res.findings.some((f) => /leak/.test(f.summary)), false);
});

test('a relative symlink that climbs out of the root stops at the root', () => {
  const host = outside();
  const root = makeRoot();
  link(root, 'etc/letsencrypt', `../../../../../..${path.join(host, 'letsencrypt')}`);
  assert.equal(audit(root).json.scanned.certbot_lineages, 0);
});

test('a symlink inside the root that stays inside the root still works', () => {
  const root = makeRoot();
  put(root, 'srv/le/renewal/example.com.conf', certbotConf({ hooks: { renew_hook: '/nowhere/x.sh' } }));
  link(root, 'etc/letsencrypt', '/srv/le');
  assert.equal(audit(root).json.scanned.certbot_lineages, 1);
});

test('a symlink loop does not hang or crash', () => {
  const root = makeRoot();
  link(root, 'etc/caddy', '/etc/caddy');
  link(root, 'etc/traefik/traefik.yml', 'traefik.yml');
  const res = audit(root);
  assert.notEqual(res.status, 2, res.err);
});
