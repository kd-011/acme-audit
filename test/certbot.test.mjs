import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { audit, certbotConf, enableCertbotTimer, find, kinds, link, makeRoot, put } from '../test-support/tree.mjs';

const RENEWAL = 'etc/letsencrypt/renewal/example.com.conf';
const lineOf = (text, needle) => text.split('\n').findIndex((l) => l.includes(needle)) + 1;

function machine(conf, { timer = true, webroot = true } = {}) {
  const root = makeRoot();
  put(root, RENEWAL, conf);
  if (webroot) fs.mkdirSync(`${root}/var/www/html`, { recursive: true });
  if (timer) enableCertbotTimer(root);
  return root;
}

test('a modern certbot lineage with a working hook, a timer and twice-daily runs is clean', () => {
  const root = machine(certbotConf({ hooks: { renew_hook: 'systemctl reload nginx' } }));
  put(root, 'etc/letsencrypt/renewal-hooks/deploy/10-reload.sh', '#!/bin/sh\nnginx -s reload\n', 0o755);
  const res = audit(root);
  assert.equal(res.status, 0, res.err);
  assert.deepEqual(res.findings, []);
});

test('HOOK-MISSING: the deploy hook in the renewal file points at a script that is not there', () => {
  const conf = certbotConf({ hooks: { renew_hook: '/usr/local/bin/reload-nginx.sh' } });
  const res = audit(machine(conf));
  const [f, ...rest] = find(res, 'HOOK-MISSING');
  assert.equal(rest.length, 0);
  assert.equal(f.file, `/${RENEWAL}`);
  assert.equal(f.line, lineOf(conf, 'renew_hook'));
  assert.equal(f.severity, 'error');
  assert.match(f.summary, /reload-nginx\.sh/);
  assert.match(f.why, /deploy|reload/i);
  assert.equal(res.status, 1);
});

test('HOOK-NOT-EXECUTABLE: the hook exists but has no execute bit', () => {
  const conf = certbotConf({ hooks: { post_hook: '/usr/local/bin/after-renew.sh' } });
  const root = machine(conf);
  put(root, 'usr/local/bin/after-renew.sh', '#!/bin/sh\nexit 0\n', 0o644);
  const res = audit(root);
  const [f] = find(res, 'HOOK-NOT-EXECUTABLE');
  assert.equal(f.file, `/${RENEWAL}`);
  assert.equal(f.line, lineOf(conf, 'post_hook'));
  assert.match(f.summary, /after-renew\.sh/);
  assert.deepEqual(find(res, 'HOOK-MISSING'), []);
});

test('a hook that is a command found on PATH, with arguments, is fine', () => {
  const res = audit(machine(certbotConf({ hooks: { pre_hook: 'systemctl stop nginx', post_hook: 'systemctl start nginx' } })));
  assert.deepEqual(res.findings, []);
});

test('renewal-hooks directories: a non-executable file is skipped by certbot and flagged here', () => {
  const root = machine(certbotConf());
  put(root, 'etc/letsencrypt/renewal-hooks/deploy/10-reload.sh', '#!/bin/sh\nnginx -s reload\n', 0o644);
  put(root, 'etc/letsencrypt/renewal-hooks/deploy/20-ok.sh', '#!/bin/sh\nexit 0\n', 0o755);
  const res = audit(root);
  const [f] = find(res, 'HOOK-NOT-EXECUTABLE');
  assert.equal(f.file, '/etc/letsencrypt/renewal-hooks/deploy/10-reload.sh');
  assert.match(f.why, /skip|ignore/i);
  assert.equal(res.findings.length, 1);
});

test('renewal-hooks directories: a dangling symlink is HOOK-MISSING', () => {
  const root = machine(certbotConf());
  link(root, 'etc/letsencrypt/renewal-hooks/post/restart.sh', '/opt/gone/restart.sh');
  const res = audit(root);
  assert.equal(find(res, 'HOOK-MISSING')[0].file, '/etc/letsencrypt/renewal-hooks/post/restart.sh');
});

test('RENEW-WINDOW: renew_before_expiry of 5 days leaves too few tries', () => {
  const conf = certbotConf({ before: '5 days' });
  const res = audit(machine(conf));
  const [f] = find(res, 'RENEW-WINDOW');
  assert.equal(f.severity, 'warn');
  assert.equal(f.line, lineOf(conf, 'renew_before_expiry'));
  assert.match(f.summary, /5 days/);
});

test('RENEW-WINDOW: renew_before_expiry of 90 days is longer than the new lifetimes, so it renews on every run', () => {
  const res = audit(machine(certbotConf({ before: '90 days' })));
  const [f] = find(res, 'RENEW-WINDOW');
  assert.equal(f.severity, 'error');
  assert.match(f.why, /every run|every time/i);
});

test('renew_before_expiry units: weeks and bare numbers are read as days', () => {
  assert.deepEqual(kinds(audit(machine(certbotConf({ before: '2 weeks' })))), []);
  assert.deepEqual(kinds(audit(machine(certbotConf({ before: '10' })))), []);
  assert.deepEqual(kinds(audit(machine(certbotConf({ before: '3' })))), ['RENEW-WINDOW']);
});

test('DEAD-AUTH: a renewal file with no authenticator is skipped by certbot', () => {
  const res = audit(machine(certbotConf({ authenticator: null })));
  const [f] = find(res, 'DEAD-AUTH');
  assert.equal(f.severity, 'error');
  assert.match(f.why, /skip/i);
});

test('DEAD-AUTH: the manual authenticator with no auth hook cannot renew unattended', () => {
  const res = audit(machine(certbotConf({ authenticator: 'manual' })));
  assert.equal(find(res, 'DEAD-AUTH').length, 1);
  const withHook = machine(certbotConf({ authenticator: 'manual', extra: 'manual_auth_hook = /usr/local/bin/dns-auth.sh' }));
  put(withHook, 'usr/local/bin/dns-auth.sh', '#!/bin/sh\n', 0o755);
  assert.deepEqual(find(audit(withHook), 'DEAD-AUTH'), []);
});

test('DEAD-AUTH: a webroot path that is not on this machine', () => {
  const root = machine(certbotConf(), { webroot: false });
  const res = audit(root);
  assert.equal(find(res, 'DEAD-AUTH').length, 1);
  assert.match(find(res, 'DEAD-AUTH')[0].summary, /\/var\/www\/html/);
  fs.mkdirSync(`${root}/var/www/html`, { recursive: true });
  assert.deepEqual(find(audit(root), 'DEAD-AUTH'), []);
});

test('OLD-CLIENT: an installed certbot older than the first release with ARI', () => {
  const root = machine(certbotConf({ version: '2.1.0' }));
  put(root, 'usr/lib/python3/dist-packages/certbot-2.1.0.dist-info/METADATA', 'Name: certbot\nVersion: 2.1.0\n');
  const [f] = find(audit(root), 'OLD-CLIENT');
  assert.equal(f.severity, 'info');
  assert.match(f.summary, /2\.1\.0/);
  assert.match(f.summary, /4\.1\.0/);
});

test('OLD-CLIENT: falls back to the version certbot wrote into the renewal file', () => {
  const [f] = find(audit(machine(certbotConf({ version: '1.21.0' }))), 'OLD-CLIENT');
  assert.match(f.summary, /1\.21\.0/);
  assert.deepEqual(find(audit(machine(certbotConf({ version: '4.1.1' }))), 'OLD-CLIENT'), []);
});

test('an unreadable renewal file is reported as a note, not a crash', () => {
  const root = machine('this is [not a certbot file');
  const res = audit(root);
  assert.notEqual(res.status, 2, res.err);
  assert.ok(res.json.notes.length >= 1);
});
