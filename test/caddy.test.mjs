import assert from 'node:assert/strict';
import { test } from 'node:test';
import { audit, find, kinds, makeRoot, put } from '../test-support/tree.mjs';

const CADDYFILE = 'etc/caddy/Caddyfile';

test('a Caddyfile on its defaults is clean', () => {
  const root = makeRoot();
  put(root, CADDYFILE, '{\n\temail admin@example.com\n}\n\nexample.com {\n\treverse_proxy localhost:8080\n}\n');
  assert.deepEqual(audit(root).findings, []);
});

test('RENEW-WINDOW: a renewal_window_ratio of 0.05 leaves about three days of retries', () => {
  const root = makeRoot();
  const text = '{\n\trenewal_window_ratio 0.05\n}\n\nexample.com {\n\trespond "ok"\n}\n';
  put(root, CADDYFILE, text);
  const [f] = find(audit(root), 'RENEW-WINDOW');
  assert.equal(f.file, `/${CADDYFILE}`);
  assert.equal(f.line, 2);
  assert.equal(f.client, 'caddy');
});

test('the default ratio written out, and a generous one, are fine; a ratio of 1 renews on every scan', () => {
  const at = (r) => { const root = makeRoot(); put(root, CADDYFILE, `{\n\trenewal_window_ratio ${r}\n}\n`); return audit(root); };
  assert.deepEqual(at('0.3333').findings, []);
  assert.deepEqual(at('0.5').findings, []);
  assert.equal(find(at('1'), 'RENEW-WINDOW')[0].severity, 'error');
});

test('TIMER-INFREQUENT: renew_interval of 14d scans too rarely', () => {
  const root = makeRoot();
  put(root, CADDYFILE, '{\n\trenew_interval 14d\n}\n');
  assert.deepEqual(kinds(audit(root)), ['TIMER-INFREQUENT']);
  const ok = makeRoot();
  put(ok, CADDYFILE, '{\n\trenew_interval 12h\n}\n');
  assert.deepEqual(audit(ok).findings, []);
});

test('DEAD-AUTH: pinning the Let\'s Encrypt staging CA gives certificates no browser trusts', () => {
  const root = makeRoot();
  put(root, CADDYFILE, '{\n\tacme_ca https://acme-staging-v02.api.letsencrypt.org/directory\n}\n');
  const [f] = find(audit(root), 'DEAD-AUTH');
  assert.equal(f.line, 2);
  assert.match(f.summary, /staging/);
});

test('a CA pin in a site block (issuer acme { dir ... }) is read as well, from an imported file', () => {
  const root = makeRoot();
  put(root, CADDYFILE, 'import sites/*.caddy\n');
  put(root, 'etc/caddy/sites/a.caddy', 'a.example.com {\n\ttls {\n\t\tissuer acme {\n\t\t\tdir https://acme-staging-v02.api.letsencrypt.org/directory\n\t\t}\n\t}\n}\n');
  const [f] = find(audit(root), 'DEAD-AUTH');
  assert.equal(f.file, '/etc/caddy/sites/a.caddy');
  assert.equal(f.line, 4);
});

test('a production CA pin and a comment mentioning staging are not flagged', () => {
  const root = makeRoot();
  put(root, CADDYFILE, '{\n\t# acme_ca https://acme-staging-v02.api.letsencrypt.org/directory\n\tacme_ca https://acme-v02.api.letsencrypt.org/directory\n}\n');
  assert.deepEqual(audit(root).findings, []);
});
