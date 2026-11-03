import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { audit, certbotConf, certbotTimer, enableCertbotTimer, find, kinds, link, makeRoot, put, repo } from '../test-support/tree.mjs';

function withCertbot(timerText, { enable = true } = {}) {
  const root = makeRoot();
  put(root, 'etc/letsencrypt/renewal/example.com.conf', certbotConf());
  fs.mkdirSync(`${root}/var/www/html`, { recursive: true });
  if (timerText !== null) {
    if (enable) enableCertbotTimer(root, timerText);
    else {
      put(root, 'lib/systemd/system/certbot.timer', timerText);
      put(root, 'lib/systemd/system/certbot.service', certbotTimer.service);
    }
  }
  return root;
}
const timer = (cal) => `[Timer]\n${cal}\n\n[Install]\nWantedBy=timers.target\n`;

test('TIMER-INFREQUENT: a weekly timer gives two tries in a 45-day certificate\'s renewal window', () => {
  const [f] = find(audit(withCertbot(timer('OnCalendar=weekly'))), 'TIMER-INFREQUENT');
  assert.equal(f.file, '/lib/systemd/system/certbot.timer');
  assert.equal(f.line, 2);
  assert.equal(f.severity, 'warn');
  assert.match(f.summary, /7 days/);
  assert.match(f.why, /45/);
});

test('daily and twice daily timers pass', () => {
  assert.deepEqual(audit(withCertbot(timer('OnCalendar=daily'))).findings, []);
  assert.deepEqual(audit(withCertbot(timer('OnCalendar=*-*-* 00,12:00:00'))).findings, []);
  assert.deepEqual(audit(withCertbot(timer('OnCalendar=*-*-* 03:30:00\nRandomizedDelaySec=1h'))).findings, []);
});

test('calendar forms: monthly, a day of month, a weekday, a list of days', () => {
  const gap = (cal) => find(audit(withCertbot(timer(cal))), 'TIMER-INFREQUENT')[0]?.detail?.gap_days ?? null;
  assert.equal(gap('OnCalendar=monthly'), 31);
  assert.equal(gap('OnCalendar=*-*-01 03:00:00'), 31);
  assert.equal(gap('OnCalendar=Mon *-*-* 03:00'), 7);
  assert.equal(gap('OnCalendar=*-*-1,15 03:00'), 17);
  assert.equal(gap('OnCalendar=*-*-* 03:00'), null);
});

test('OnUnitActiveSec: 1w is flagged, 12h is not', () => {
  assert.equal(find(audit(withCertbot(timer('OnBootSec=5min\nOnUnitActiveSec=1w'))), 'TIMER-INFREQUENT').length, 1);
  assert.deepEqual(audit(withCertbot(timer('OnBootSec=5min\nOnUnitActiveSec=12h'))).findings, []);
});

test('TIMER-INFREQUENT: a certbot timer that is installed but not enabled never fires', () => {
  const [f] = find(audit(withCertbot(certbotTimer.timer, { enable: false })), 'TIMER-INFREQUENT');
  assert.equal(f.severity, 'error');
  assert.match(f.summary, /not enabled/);
});

test('TIMER-INFREQUENT: certbot lineages and nothing at all that runs certbot renew', () => {
  const [f] = find(audit(withCertbot(null)), 'TIMER-INFREQUENT');
  assert.equal(f.severity, 'error');
  assert.match(f.summary, /certbot/);
  assert.match(f.why, /outside|container|other/i, 'says what it cannot see');
});

test('cron: Debian\'s twice daily certbot line is clean, a monthly one is not', () => {
  const root = withCertbot(null);
  put(root, 'etc/cron.d/certbot', "0 */12 * * * root test -x /usr/bin/certbot -a \\! -d /run/systemd/system && perl -e 'sleep int(rand(43200))' && certbot -q renew\n");
  assert.deepEqual(audit(root).findings, []);
  const monthly = withCertbot(null);
  put(monthly, 'etc/cron.d/certbot', 'SHELL=/bin/sh\n0 3 1 * * root certbot renew -q\n');
  const [f] = find(audit(monthly), 'TIMER-INFREQUENT');
  assert.equal(f.file, '/etc/cron.d/certbot');
  assert.equal(f.line, 2);
});

test('cron: step and range fields, @weekly and a script dropped in cron.weekly', () => {
  const at = (line) => { const r = withCertbot(null); put(r, 'etc/crontab', `${line}\n`); return kinds(audit(r)); };
  assert.deepEqual(at('17 3 * * * root certbot renew'), []);
  assert.deepEqual(at('17 3 * * 1-5 root certbot renew'), []);
  assert.deepEqual(at('17 3 */3 * * root certbot renew'), []);
  assert.deepEqual(at('17 3 * * 0 root certbot renew'), ['TIMER-INFREQUENT']);
  assert.deepEqual(at('@weekly root certbot renew'), ['TIMER-INFREQUENT']);
  assert.deepEqual(at('@daily root certbot renew'), []);
  const weekly = withCertbot(null);
  put(weekly, 'etc/cron.weekly/certbot', '#!/bin/sh\ncertbot renew -q\n', 0o755);
  assert.deepEqual(kinds(audit(weekly)), ['TIMER-INFREQUENT']);
});

test('a user crontab under var/spool is read', () => {
  const root = withCertbot(null);
  put(root, 'var/spool/cron/crontabs/root', '# m h dom mon dow command\n0 4 1 */2 * certbot renew\n', 0o600);
  assert.equal(find(audit(root), 'TIMER-INFREQUENT')[0].file, '/var/spool/cron/crontabs/root');
});

test('the thresholds come from data/schedule.json: with only a 90-day target a weekly timer passes', () => {
  const root = withCertbot(timer('OnCalendar=weekly'));
  const schedule = JSON.parse(fs.readFileSync(path.join(repo, 'data/schedule.json'), 'utf8'));
  schedule.targets = [{ days: 90, label: 'classic', source: 'le-profiles' }];
  const file = path.join(root, 'schedule.json');
  fs.writeFileSync(file, JSON.stringify(schedule));
  assert.deepEqual(find(audit(root, ['--schedule', file]), 'TIMER-INFREQUENT'), []);
  assert.equal(find(audit(root), 'TIMER-INFREQUENT').length, 1);
});

test('--lifetime adds a target: a 6-day lifetime makes a daily timer too slow', () => {
  const root = withCertbot(timer('OnCalendar=daily'));
  assert.equal(find(audit(root, ['--lifetime', '6']), 'TIMER-INFREQUENT').length, 1);
});

test('systemd units in the user directory of a home are read, and a dangling wants link does not enable', () => {
  const root = withCertbot(null);
  put(root, 'etc/systemd/system/certbot.timer', timer('OnCalendar=daily'));
  put(root, 'etc/systemd/system/certbot.service', certbotTimer.service);
  link(root, 'etc/systemd/system/multi-user.target.wants/other.timer', '/nowhere');
  assert.equal(find(audit(root), 'TIMER-INFREQUENT')[0].summary.includes('not enabled'), true);
});
