// Found in review: permission errors, shell syntax in hooks, disabled timers of any client, sub-daily schedules.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { audit, certbotConf, certbotTimer, enableCertbotTimer, find, kinds, link, makeRoot, put } from '../test-support/tree.mjs';

const RENEWAL = 'etc/letsencrypt/renewal/example.com.conf';
function withCertbot(conf = certbotConf()) {
  const root = makeRoot();
  put(root, RENEWAL, conf);
  fs.mkdirSync(`${root}/var/www/html`, { recursive: true });
  enableCertbotTimer(root);
  return root;
}

test('a path the audit may not read is a note, not a missing hook or webroot', { skip: process.getuid?.() === 0 }, () => {
  const root = withCertbot(certbotConf({ hooks: { renew_hook: '/opt/locked/reload.sh' } }));
  put(root, 'opt/locked/reload.sh', '#!/bin/sh\n', 0o755);
  put(root, RENEWAL, certbotConf({ hooks: { renew_hook: '/opt/locked/reload.sh' } }).replace('/var/www/html', '/opt/locked/html'));
  fs.chmodSync(`${root}/opt/locked`, 0o000);
  try {
    const res = audit(root);
    assert.deepEqual(res.findings, []);
    assert.equal(res.status, 0);
    assert.ok(res.json.notes.some((n) => /permission denied/.test(n.message)));
  } finally {
    fs.chmodSync(`${root}/opt/locked`, 0o755);
  }
});

test('an unreadable home does not make acme.sh vanish without a word', { skip: process.getuid?.() === 0 }, () => {
  const root = makeRoot();
  put(root, 'home/bob/.acme.sh/acme.sh', 'VER=3.1.7\n', 0o755);
  fs.chmodSync(`${root}/home/bob`, 0o000);
  try {
    const res = audit(root);
    assert.ok(res.json.notes.some((n) => /permission denied/.test(n.message)));
  } finally {
    fs.chmodSync(`${root}/home/bob`, 0o755);
  }
});

test('hooks written as shell are read as shell: if, subshell, trailing semicolon, [[ ]]', () => {
  const hook = (cmd) => audit(withCertbot(certbotConf({ hooks: { post_hook: cmd } })));
  assert.deepEqual(hook('if systemctl is-active nginx; then systemctl reload nginx; fi').findings, []);
  assert.deepEqual(hook('(cd /opt/app && ./reload)').findings, []);
  assert.deepEqual(hook('[[ -f /run/nginx.pid ]] && systemctl reload nginx').findings, []);
  assert.deepEqual(hook('! systemctl is-active nginx').findings, []);
  const semi = withCertbot(certbotConf({ hooks: { post_hook: '/usr/local/bin/reload.sh;' } }));
  put(semi, 'usr/local/bin/reload.sh', '#!/bin/sh\n', 0o755);
  assert.deepEqual(audit(semi).findings, []);
  assert.equal(find(hook('/usr/local/bin/gone.sh;'), 'HOOK-MISSING').length, 1);
});

test('a disabled lego timer is reported like a disabled certbot timer', () => {
  const root = makeRoot();
  put(root, 'etc/systemd/system/lego-renew.service', '[Service]\nType=oneshot\nExecStart=/usr/local/bin/lego --path /var/lib/lego --domains example.com renew --dynamic\n');
  put(root, 'etc/systemd/system/lego-renew.timer', '[Timer]\nOnCalendar=daily\n');
  const [f] = find(audit(root), 'TIMER-INFREQUENT');
  assert.equal(f.client, 'lego');
  assert.equal(f.severity, 'error');
  assert.match(f.summary, /not enabled/);
  put(root, 'etc/cron.d/lego', '17 3 * * * root /usr/local/bin/lego --path /var/lib/lego --domains example.com renew --dynamic\n');
  assert.deepEqual(audit(root).findings, [], 'another enabled scheduler for the same client is enough');
});

test('a masked timer is read from the later unit directory and reported as masked', () => {
  const root = makeRoot();
  put(root, 'etc/letsencrypt/renewal/example.com.conf', certbotConf());
  fs.mkdirSync(`${root}/var/www/html`, { recursive: true });
  put(root, 'lib/systemd/system/certbot.timer', certbotTimer.timer);
  put(root, 'lib/systemd/system/certbot.service', certbotTimer.service);
  link(root, 'etc/systemd/system/certbot.timer', '/dev/null');
  link(root, 'etc/systemd/system/timers.target.wants/certbot.timer', '/lib/systemd/system/certbot.timer');
  const [f] = find(audit(root), 'TIMER-INFREQUENT');
  assert.match(f.summary, /masked/);
  assert.equal(f.file, '/lib/systemd/system/certbot.timer');
});

test('sub-daily schedules have a gap under a day, so --lifetime 6 does not call them daily', () => {
  const root = makeRoot();
  put(root, 'etc/letsencrypt/renewal/example.com.conf', certbotConf());
  fs.mkdirSync(`${root}/var/www/html`, { recursive: true });
  enableCertbotTimer(root);
  assert.deepEqual(audit(root, ['--lifetime', '6']).findings, [], 'stock twice-daily timer');
  const hourly = makeRoot();
  put(hourly, 'etc/letsencrypt/renewal/example.com.conf', certbotConf());
  fs.mkdirSync(`${hourly}/var/www/html`, { recursive: true });
  put(hourly, 'etc/cron.d/certbot', '0 * * * * root certbot renew -q\n');
  assert.deepEqual(audit(hourly, ['--lifetime', '6']).findings, []);
  const script = makeRoot();
  put(script, 'etc/letsencrypt/renewal/example.com.conf', certbotConf());
  fs.mkdirSync(`${script}/var/www/html`, { recursive: true });
  put(script, 'etc/cron.hourly/certbot', '#!/bin/sh\ncertbot renew -q\n', 0o755);
  assert.deepEqual(audit(script, ['--lifetime', '6']).findings, []);
  const atHourly = makeRoot();
  put(atHourly, 'etc/letsencrypt/renewal/example.com.conf', certbotConf());
  fs.mkdirSync(`${atHourly}/var/www/html`, { recursive: true });
  put(atHourly, 'etc/crontab', '@hourly root certbot renew -q\n');
  assert.deepEqual(audit(atHourly, ['--lifetime', '6']).findings, []);
});

test('the gap of a twice-daily timer is half a day, and a once-daily one is a day', () => {
  const gap = (cal) => {
    const root = makeRoot();
    put(root, 'etc/letsencrypt/renewal/example.com.conf', certbotConf());
    fs.mkdirSync(`${root}/var/www/html`, { recursive: true });
    enableCertbotTimer(root, `[Timer]\n${cal}\n\n[Install]\nWantedBy=timers.target\n`);
    return find(audit(root, ['--lifetime', '1']), 'TIMER-INFREQUENT')[0]?.detail.gap_days;
  };
  assert.equal(gap('OnCalendar=*-*-* 00,12:00:00'), 0.5);
  assert.equal(gap('OnCalendar=*-*-* 03:00'), 1);
  assert.equal(gap('OnCalendar=*-*-* 00,06,12,18:00'), 0.25);
});
