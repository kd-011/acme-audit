import assert from 'node:assert/strict';
import { test } from 'node:test';
import { audit, find, kinds, makeRoot, put } from '../test-support/tree.mjs';

const yml = (resolver) => `entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

certificatesResolvers:
${resolver}
`;
const GOOD = `  letsencrypt:
    acme:
      email: admin@example.com
      storage: /etc/traefik/acme.json
      httpChallenge:
        entryPoint: web`;

test('a resolver with a challenge and acme.json at mode 600 is clean', () => {
  const root = makeRoot();
  put(root, 'etc/traefik/traefik.yml', yml(GOOD));
  put(root, 'etc/traefik/acme.json', '{}\n', 0o600);
  assert.deepEqual(audit(root).findings, []);
});

test('ACMEJSON-PERMS: Traefik refuses an acme.json with group or other bits', () => {
  const root = makeRoot();
  put(root, 'etc/traefik/traefik.yml', yml(GOOD));
  put(root, 'etc/traefik/acme.json', '{}\n', 0o644);
  const [f] = find(audit(root), 'ACMEJSON-PERMS');
  assert.equal(f.file, '/etc/traefik/acme.json');
  assert.equal(f.severity, 'error');
  assert.match(f.summary, /644/);
  assert.match(f.why, /too open/);
});

test('mode 640 and 660 are flagged too, 400 is not', () => {
  const at = (mode) => { const root = makeRoot(); put(root, 'etc/traefik/traefik.yml', yml(GOOD)); put(root, 'etc/traefik/acme.json', '{}', mode); return kinds(audit(root)); };
  assert.deepEqual(at(0o640), ['ACMEJSON-PERMS']);
  assert.deepEqual(at(0o660), ['ACMEJSON-PERMS']);
  assert.deepEqual(at(0o400), []);
});

test('a relative storage path is looked up next to the static config', () => {
  const root = makeRoot();
  put(root, 'etc/traefik/traefik.yml', yml(GOOD.replace('/etc/traefik/acme.json', 'acme.json')));
  put(root, 'etc/traefik/acme.json', '{}', 0o666);
  assert.equal(find(audit(root), 'ACMEJSON-PERMS').length, 1);
});

test('DEAD-AUTH: a resolver with no challenge cannot renew', () => {
  const root = makeRoot();
  put(root, 'etc/traefik/traefik.yml', yml(`  nochallenge:
    acme:
      email: admin@example.com
      storage: /etc/traefik/acme.json`));
  const [f] = find(audit(root), 'DEAD-AUTH');
  assert.equal(f.line, 9);
  assert.match(f.summary, /nochallenge/);
});

test('RENEW-WINDOW: certificatesDuration of 24 hours makes Traefik renew only in the last six hours', () => {
  const root = makeRoot();
  put(root, 'etc/traefik/traefik.yml', yml(`${GOOD}\n      certificatesDuration: 24`));
  const [f] = find(audit(root), 'RENEW-WINDOW');
  assert.match(f.summary, /certificatesDuration/);
});

test('the default certificatesDuration written out, 2160 hours, is fine', () => {
  const root = makeRoot();
  put(root, 'etc/traefik/traefik.yml', yml(`${GOOD}\n      certificatesDuration: 2160`));
  assert.deepEqual(find(audit(root), 'RENEW-WINDOW'), []);
});

test('the TOML form of the static config is read as well', () => {
  const root = makeRoot();
  put(root, 'etc/traefik/traefik.toml', `[certificatesResolvers.le.acme]
  email = "admin@example.com"
  storage = "/etc/traefik/acme.json"
  [certificatesResolvers.le.acme.httpChallenge]
    entryPoint = "web"
`);
  put(root, 'etc/traefik/acme.json', '{}', 0o604);
  assert.deepEqual(kinds(audit(root)), ['ACMEJSON-PERMS']);
});
