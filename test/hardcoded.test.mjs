import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { audit, certbotConf, enableCertbotTimer, find, kinds, makeRoot, put } from '../test-support/tree.mjs';

function base() {
  const root = makeRoot();
  put(root, 'etc/letsencrypt/renewal/example.com.conf', certbotConf());
  fs.mkdirSync(`${root}/var/www/html`, { recursive: true });
  enableCertbotTimer(root);
  return root;
}

const WRAPPER = `#!/bin/bash
# Renew when the certificate is older than 60 days.
set -e
cd /etc/letsencrypt/live
for c in */cert.pem; do
  if [ -n "$(find "$c" -mtime +60)" ]; then
    certbot renew --cert-name "\${c%%/*}" --quiet
  fi
done
`;

test('HARDCODED-DAYS: a cron job runs a wrapper that renews certificates older than 60 days', () => {
  const root = base();
  put(root, 'etc/cron.d/renew-wrapper', '30 3 * * * root /usr/local/bin/renew-certs.sh\n');
  put(root, 'usr/local/bin/renew-certs.sh', WRAPPER, 0o755);
  const hits = find(audit(root), 'HARDCODED-DAYS');
  assert.equal(hits.length, 1, 'the comment line is not flagged, the find line is');
  assert.equal(hits[0].file, '/usr/local/bin/renew-certs.sh');
  assert.equal(hits[0].line, 6);
  assert.equal(hits[0].severity, 'warn');
  assert.match(hits[0].summary, /60/);
  assert.match(hits[0].why, /64|45/);
});

test('-mtime +83 renews after the certificate has already expired, so it is an error', () => {
  const root = base();
  put(root, 'usr/local/bin/renew.sh', '#!/bin/sh\nfind /etc/letsencrypt/live -name cert.pem -mtime +83 -exec certbot renew \;\n', 0o755);
  const [f] = find(audit(root), 'HARDCODED-DAYS');
  assert.equal(f.severity, 'error');
});

test('openssl x509 -checkend with a number of seconds is converted to days', () => {
  const root = base();
  put(root, 'usr/local/bin/check.sh', '#!/bin/sh\nopenssl x509 -checkend 5184000 -noout -in /etc/letsencrypt/live/example.com/cert.pem || certbot renew\n', 0o755);
  const [f] = find(audit(root), 'HARDCODED-DAYS');
  assert.match(f.summary, /60 days/);
  const ok = base();
  put(ok, 'usr/local/bin/check.sh', '#!/bin/sh\nopenssl x509 -checkend 1296000 -noout -in /etc/letsencrypt/live/example.com/cert.pem || certbot renew\n', 0o755);
  assert.deepEqual(find(audit(ok), 'HARDCODED-DAYS'), []);
});

test('a variable holding one of the numbers Let\'s Encrypt names is flagged, with a note that the direction is unknown', () => {
  const root = base();
  put(root, 'etc/cron.daily/certs', '#!/bin/sh\nRENEW_DAYS=80\n[ "$age" -ge "$RENEW_DAYS" ] && certbot renew\n', 0o755);
  const [f] = find(audit(root), 'HARDCODED-DAYS');
  assert.equal(f.line, 2);
  assert.match(f.why, /direction|whether/i);
});

test('numbers that are not days are left alone: sleep 60, timeouts, a port', () => {
  const root = base();
  put(root, 'usr/local/bin/renew.sh', '#!/bin/sh\nsleep 60\ntimeout 60 certbot renew\nwait_for_port 8060\nTIMEOUT_SECONDS=60\n', 0o755);
  assert.deepEqual(find(audit(root), 'HARDCODED-DAYS'), []);
});

test('files that have nothing to do with certificates are not scanned for numbers', () => {
  const root = base();
  put(root, 'usr/local/bin/cleanup.sh', '#!/bin/sh\nfind /var/log -mtime +60 -delete\n', 0o755);
  assert.deepEqual(find(audit(root), 'HARDCODED-DAYS'), []);
});

test('a script referenced from a systemd service is scanned even outside the usual directories', () => {
  const root = base();
  put(root, 'etc/systemd/system/renew.service', '[Service]\nExecStart=/srv/ops/renew.sh\n');
  put(root, 'srv/ops/renew.sh', '#!/bin/sh\nDAYS=60\ncertbot renew --days-left $DAYS\n', 0o755);
  assert.equal(find(audit(root), 'HARDCODED-DAYS')[0].file, '/srv/ops/renew.sh');
});

test('the numbers come from data/schedule.json, so a different list flags a different number', () => {
  const root = base();
  put(root, 'usr/local/bin/renew.sh', '#!/bin/sh\nDAYS=75\ncertbot renew\n', 0o755);
  assert.deepEqual(find(audit(root), 'HARDCODED-DAYS'), []);
  const sched = JSON.parse(fs.readFileSync(new URL('../data/schedule.json', import.meta.url), 'utf8'));
  sched.facts.hardcoded_numbers = [75];
  fs.writeFileSync(`${root}/s.json`, JSON.stringify(sched));
  assert.equal(find(audit(root, ['--schedule', `${root}/s.json`]), 'HARDCODED-DAYS').length, 1);
});

test('the acme.sh script itself and binaries are not scanned', () => {
  const root = base();
  put(root, 'usr/local/bin/lego', Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0x36, 0x30, 0x20, 0x64, 0x61, 0x79, 0x73]).toString('latin1'), 0o755);
  assert.deepEqual(kinds(audit(root)), []);
});
