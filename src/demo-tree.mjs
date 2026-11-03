// The fake machine `demo` audits. It is built in a temp dir with real file modes and removed afterwards.
// Nothing here is a real host: the names are example.com, example.org and example.net.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const b64 = (s) => `__ACME_BASE64__START_${Buffer.from(s).toString('base64')}__ACME_BASE64__END_`;

function certbotConf(name, { version, before, hooks = [], authenticator = 'webroot' }) {
  return [
    before ? `renew_before_expiry = ${before}` : '# renew_before_expiry = 30 days',
    `version = ${version}`,
    `archive_dir = /etc/letsencrypt/archive/${name}`,
    `cert = /etc/letsencrypt/live/${name}/cert.pem`,
    `privkey = /etc/letsencrypt/live/${name}/privkey.pem`,
    `chain = /etc/letsencrypt/live/${name}/chain.pem`,
    `fullchain = /etc/letsencrypt/live/${name}/fullchain.pem`,
    '',
    '# Options used in the renewal process',
    '[renewalparams]',
    'account = 3f8a6c1d9e2b47a05c6d8e1f0a2b4c6d',
    `authenticator = ${authenticator}`,
    'webroot_path = /var/www/html,',
    'server = https://acme-v02.api.letsencrypt.org/directory',
    'key_type = ecdsa',
    ...hooks,
    '[[webroot_map]]',
    `${name} = /var/www/html`,
    '',
  ].join('\n');
}

export function buildDemoTree() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'acme-audit-demo-'));
  const put = (rel, text, mode = 0o644) => {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, text);
    fs.chmodSync(full, mode);
  };
  const exe = (rel) => put(rel, '#!/bin/sh\nexit 0\n', 0o755);
  for (const b of ['usr/bin/systemctl', 'usr/bin/certbot', 'usr/local/bin/lego', 'usr/sbin/nginx']) exe(b);
  fs.mkdirSync(path.join(root, 'var/www/html'), { recursive: true });

  // certbot 2.1.0, a weekly timer, one lineage whose deploy hook is gone and one whose post hook lost its execute bit.
  put('usr/lib/python3/dist-packages/certbot-2.1.0.dist-info/METADATA', 'Name: certbot\nVersion: 2.1.0\n');
  put('etc/letsencrypt/renewal/example.com.conf', certbotConf('example.com', { version: '2.1.0', hooks: ['renew_hook = /usr/local/bin/reload-nginx.sh'] }));
  put('etc/letsencrypt/renewal/example.org.conf', certbotConf('example.org', { version: '2.1.0', hooks: ['post_hook = /usr/local/bin/notify-renewed.sh'] }));
  put('usr/local/bin/notify-renewed.sh', '#!/bin/sh\nlogger "certificate renewed"\n', 0o644);
  put('lib/systemd/system/certbot.timer', '[Unit]\nDescription=Run certbot weekly\n\n[Timer]\nOnCalendar=weekly\nRandomizedDelaySec=43200\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n');
  put('lib/systemd/system/certbot.service', '[Unit]\nDescription=Certbot\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/certbot -q renew\n');
  fs.mkdirSync(path.join(root, 'etc/systemd/system/timers.target.wants'), { recursive: true });
  fs.symlinkSync('/lib/systemd/system/certbot.timer', path.join(root, 'etc/systemd/system/timers.target.wants/certbot.timer'));

  // A wrapper script from the 90-day days that renews anything older than 60 days.
  put('etc/cron.d/renew-wrapper', '30 3 * * * root /usr/local/bin/renew-old-certs.sh\n');
  put('usr/local/bin/renew-old-certs.sh', [
    '#!/bin/bash',
    '# Renew certificates once they are close to the end of their 90 days.',
    'cd /etc/letsencrypt/live || exit 1',
    'for c in */cert.pem; do',
    '  if [ -n "$(find "$c" -mtime +60)" ]; then',
    '    certbot renew --cert-name "${c%%/*}" --quiet',
    '  fi',
    'done',
    '',
  ].join('\n'), 0o755);

  // acme.sh with a pinned --days, and four runs a day.
  const home = path.join('home', 'demo', '.acme.sh');
  put(path.join(home, 'acme.sh'), '#!/usr/bin/env sh\nVER=3.1.7\n', 0o755);
  put(path.join(home, 'example.net_ecc', 'example.net.conf'), [
    "Le_Domain='example.net'", "Le_Alt='no'", "Le_Webroot='dns_cf'", "Le_PreHook=''", "Le_PostHook=''", "Le_RenewHook=''",
    "Le_API='https://acme-v02.api.letsencrypt.org/directory'", "Le_Keylength='ec-256'",
    "Le_CertCreateTime='1767225600'", "Le_NextRenewTime='1772409600'",
    "Le_RenewalDays='60'", `Le_ReloadCmd='${b64('systemctl reload nginx')}'`, '',
  ].join('\n'));
  put('var/spool/cron/crontabs/demo', `23 0,6,12,18 * * * "/${home}"/acme.sh --cron --home "/${home}" > /dev/null\n`, 0o600);

  // lego renewing 60 days before expiry.
  put('etc/cron.d/lego', '17 3 * * * root /usr/local/bin/lego --path /var/lib/lego --email admin@example.com --domains lego.example.com --accept-tos --dns cloudflare renew --days 60\n');

  // Caddy with the renewal window cut to 5 percent.
  put('etc/caddy/Caddyfile', '{\n\temail admin@example.com\n\trenewal_window_ratio 0.05\n}\n\ncaddy.example.com {\n\trespond "ok"\n}\n');

  // Traefik with acme.json readable by everyone, and a second resolver with no challenge.
  put('etc/traefik/traefik.yml', [
    'entryPoints:', '  web:', '    address: ":80"', '  websecure:', '    address: ":443"', '',
    'certificatesResolvers:',
    '  letsencrypt:', '    acme:', '      email: admin@example.com', '      storage: /etc/traefik/acme.json', '      httpChallenge:', '        entryPoint: web',
    '  internal:', '    acme:', '      email: admin@example.com', '      storage: /etc/traefik/acme-internal.json', '',
  ].join('\n'));
  put('etc/traefik/acme.json', '{}\n', 0o644);
  return root;
}

export function removeDemoTree(root) {
  if (!path.basename(root).startsWith('acme-audit-demo-')) throw new Error(`refusing to remove ${root}`);
  fs.rmSync(root, { recursive: true, force: true });
}
