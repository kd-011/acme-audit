import assert from 'node:assert/strict';
import { test } from 'node:test';
import { audit, find, homePath, makeRoot, put } from '../test-support/tree.mjs';

const b64 = (s) => `__ACME_BASE64__START_${Buffer.from(s).toString('base64')}__ACME_BASE64__END_`;
const DOMAIN_CONF = homePath('.acme.sh', 'example.com_ecc', 'example.com.conf');
const ACME_HOME = `/${homePath('.acme.sh')}`;
const CRON = `23 0,6,12,18 * * * "${ACME_HOME}"/acme.sh --cron --home "${ACME_HOME}" > /dev/null\n`;

// The keys acme.sh writes into a domain conf, in the order it writes them.
function domainConf({ renewalDays, reload, preHook = '', renewHook = '' } = {}) {
  const l = [
    "Le_Domain='example.com'", "Le_Alt='no'", "Le_Webroot='dns_cf'",
    `Le_PreHook='${preHook ? b64(preHook) : ''}'`, "Le_PostHook=''", `Le_RenewHook='${renewHook ? b64(renewHook) : ''}'`,
    "Le_API='https://acme-v02.api.letsencrypt.org/directory'", "Le_Keylength='ec-256'",
    "Le_CertCreateTime='1767225600'", "Le_NextRenewTime='1769731200'",
  ];
  if (renewalDays) l.push(`Le_RenewalDays='${renewalDays}'`);
  if (reload) l.push(`Le_ReloadCmd='${b64(reload)}'`);
  return l.join('\n') + '\n';
}

function machine(conf, { ver = '3.1.7', cron = true } = {}) {
  const root = makeRoot();
  put(root, DOMAIN_CONF, conf);
  put(root, homePath('.acme.sh', 'acme.sh'), `#!/usr/bin/env sh\nVER=${ver}\n`, 0o755);
  if (cron) put(root, 'var/spool/cron/crontabs/alice', CRON, 0o600);
  return root;
}

test('an acme.sh setup on its defaults with four runs a day is clean', () => {
  const res = audit(machine(domainConf({ reload: 'systemctl reload nginx' })));
  assert.equal(res.status, 0, res.err);
  assert.deepEqual(res.findings, []);
});

test('RENEW-WINDOW: --days 60 pinned in the domain conf leaves one day on a 45-day certificate', () => {
  const [f] = find(audit(machine(domainConf({ renewalDays: 60 }))), 'RENEW-WINDOW');
  assert.equal(f.file, `/${DOMAIN_CONF}`);
  assert.equal(f.line, 11);
  assert.match(f.summary, /60/);
  assert.match(f.why, /ARI|window/);
});

test('a pinned Le_RenewalDays that still leaves a wide margin is not flagged', () => {
  assert.deepEqual(find(audit(machine(domainConf({ renewalDays: 30 }))), 'RENEW-WINDOW'), []);
});

test('HOOK-MISSING: Le_ReloadCmd is stored base64 encoded and the script it names is gone', () => {
  const res = audit(machine(domainConf({ reload: '/usr/local/bin/reload-all.sh' })));
  const [f] = find(res, 'HOOK-MISSING');
  assert.match(f.summary, /reload-all\.sh/);
  assert.match(f.summary, /Le_ReloadCmd/);
});

test('HOOK-NOT-EXECUTABLE: Le_RenewHook names a file with no execute bit', () => {
  const root = machine(domainConf({ renewHook: '/opt/hooks/renewed.sh' }));
  put(root, 'opt/hooks/renewed.sh', '#!/bin/sh\n', 0o640);
  assert.equal(find(audit(root), 'HOOK-NOT-EXECUTABLE').length, 1);
});

test('OLD-CLIENT: acme.sh older than 3.1.3 has no ARI code', () => {
  const [f] = find(audit(machine(domainConf(), { ver: '3.0.7' })), 'OLD-CLIENT');
  assert.match(f.summary, /3\.0\.7/);
  assert.equal(f.file, `/${homePath('.acme.sh', 'acme.sh')}`);
  assert.deepEqual(find(audit(machine(domainConf(), { ver: '3.1.3' })), 'OLD-CLIENT'), []);
});

test('TIMER-INFREQUENT: acme.sh domains and no cron line or timer runs acme.sh --cron', () => {
  const res = audit(machine(domainConf(), { cron: false }));
  const [f] = find(res, 'TIMER-INFREQUENT');
  assert.equal(f.severity, 'error');
  assert.match(f.summary, /acme\.sh/);
});
