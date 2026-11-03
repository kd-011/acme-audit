import assert from 'node:assert/strict';
import { test } from 'node:test';
import { audit, find, kinds, makeRoot, put } from '../test-support/tree.mjs';

const LEGO = '/usr/local/bin/lego --path /var/lib/lego --email admin@example.com --domains example.com --accept-tos --dns cloudflare';
const cronD = (root, line) => put(root, 'etc/cron.d/lego', `17 3 * * * root ${line}\n`);

test('lego renew --dynamic once a day, with a hook that exists, is clean', () => {
  const root = makeRoot();
  put(root, 'usr/local/bin/reload.sh', '#!/bin/sh\n', 0o755);
  cronD(root, `${LEGO} renew --dynamic --renew-hook /usr/local/bin/reload.sh`);
  assert.deepEqual(audit(root).findings, []);
});

test('RENEW-WINDOW: lego renew --days 60 renews on every run for a 45-day certificate', () => {
  const root = makeRoot();
  cronD(root, `${LEGO} renew --days 60`);
  const res = audit(root);
  const [f] = find(res, 'RENEW-WINDOW');
  assert.equal(f.file, '/etc/cron.d/lego');
  assert.equal(f.line, 1);
  assert.equal(f.severity, 'error');
  assert.equal(find(res, 'HARDCODED-DAYS').length, 0, 'one finding per line, not two');
});

test('lego renew with no --days is the default of 30 days before expiry and passes', () => {
  const root = makeRoot();
  cronD(root, `${LEGO} renew`);
  assert.deepEqual(audit(root).findings, []);
});

test('--days=N is read the same as --days N', () => {
  const root = makeRoot();
  cronD(root, `${LEGO} renew --days=60`);
  assert.deepEqual(kinds(audit(root)), ['RENEW-WINDOW']);
});

test('HOOK-MISSING and HOOK-NOT-EXECUTABLE on --renew-hook', () => {
  const missing = makeRoot();
  cronD(missing, `${LEGO} renew --days 20 --renew-hook "/usr/local/bin/gone.sh"`);
  assert.equal(find(audit(missing), 'HOOK-MISSING').length, 1);
  const noexec = makeRoot();
  put(noexec, 'usr/local/bin/reload.sh', '#!/bin/sh\n', 0o644);
  cronD(noexec, `${LEGO} renew --days 20 --renew-hook /usr/local/bin/reload.sh`);
  assert.equal(find(audit(noexec), 'HOOK-NOT-EXECUTABLE').length, 1);
});

test('lego run from a systemd service is found through the timer that starts it', () => {
  const root = makeRoot();
  put(root, 'etc/systemd/system/lego.service', `[Service]\nType=oneshot\nExecStart=${LEGO} renew --days 60\n`);
  put(root, 'etc/systemd/system/lego.timer', '[Timer]\nOnCalendar=daily\n\n[Install]\nWantedBy=timers.target\n');
  put(root, 'etc/systemd/system/timers.target.wants/lego.timer', '[Timer]\nOnCalendar=daily\n');
  const res = audit(root);
  assert.equal(find(res, 'RENEW-WINDOW')[0].file, '/etc/systemd/system/lego.service');
  assert.equal(find(res, 'RENEW-WINDOW')[0].line, 3);
});
