// Builds a fake machine under a temp root with real file layouts and real modes.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const repo = fileURLToPath(new URL('..', import.meta.url));
export const bin = path.join(repo, 'bin/acme-audit.mjs');
const HOME = path.join('home', 'alice');

export function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'acme-audit-test-'));
  // The commands every tree needs so hook lookups have something to find.
  for (const b of ['usr/bin/systemctl', 'usr/bin/sh', 'usr/sbin/nginx', 'usr/bin/certbot', 'usr/local/bin/lego']) put(root, b, '#!/bin/sh\nexit 0\n', 0o755);
  return root;
}

export function put(root, rel, text = '', mode = 0o644) {
  const full = path.join(root, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, text);
  fs.chmodSync(full, mode);
  return full;
}

export function link(root, rel, target) {
  const full = path.join(root, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.symlinkSync(target, full);
}

export const homePath = (...p) => path.join(HOME, ...p);

// A certbot renewal file as certbot writes it, with the pieces a test wants to vary.
export function certbotConf({ name = 'example.com', version = '5.2.2', authenticator = 'webroot', before, hooks = {}, extra = '' } = {}) {
  const lines = [];
  lines.push(before ? `renew_before_expiry = ${before}` : '# renew_before_expiry = 30 days');
  lines.push(`version = ${version}`);
  lines.push(`archive_dir = /etc/letsencrypt/archive/${name}`);
  lines.push(`cert = /etc/letsencrypt/live/${name}/cert.pem`);
  lines.push(`privkey = /etc/letsencrypt/live/${name}/privkey.pem`);
  lines.push(`chain = /etc/letsencrypt/live/${name}/chain.pem`);
  lines.push(`fullchain = /etc/letsencrypt/live/${name}/fullchain.pem`);
  lines.push('', '# Options used in the renewal process', '[renewalparams]');
  lines.push('account = 0123456789abcdef0123456789abcdef');
  if (authenticator) lines.push(`authenticator = ${authenticator}`);
  if (authenticator === 'webroot') lines.push('webroot_path = /var/www/html,');
  lines.push('server = https://acme-v02.api.letsencrypt.org/directory', 'key_type = ecdsa');
  for (const [k, v] of Object.entries(hooks)) lines.push(`${k} = ${v}`);
  if (extra) lines.push(extra);
  if (authenticator === 'webroot') lines.push('[[webroot_map]]', `${name} = /var/www/html`);
  return lines.join('\n') + '\n';
}

export const certbotTimer = {
  timer: '[Unit]\nDescription=Run certbot twice daily\n\n[Timer]\nOnCalendar=*-*-* 00,12:00:00\nRandomizedDelaySec=43200\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n',
  service: '[Unit]\nDescription=Certbot\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/certbot -q renew\n',
};

// certbot installed the way Debian does it: a timer in /lib, enabled by a symlink.
export function enableCertbotTimer(root, timer = certbotTimer.timer) {
  put(root, 'lib/systemd/system/certbot.timer', timer);
  put(root, 'lib/systemd/system/certbot.service', certbotTimer.service);
  link(root, 'etc/systemd/system/timers.target.wants/certbot.timer', '/lib/systemd/system/certbot.timer');
}

export function run(args, env = {}) {
  const r = spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', ...env } });
  return { status: r.status, out: r.stdout, err: r.stderr };
}

export function audit(root, extra = []) {
  const r = run(['--root', root, '--json', ...extra]);
  let json = null;
  try { json = JSON.parse(r.out); } catch { /* left null, the test shows stderr */ }
  return { ...r, json, findings: json?.findings ?? [] };
}

export const kinds = (res) => res.findings.map((f) => f.kind);
export const find = (res, kind) => res.findings.filter((f) => f.kind === kind);

// Every file path, mode and content under a root, for the "never writes" check.
export function snapshot(root) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = path.join(d, e.name);
      const st = fs.lstatSync(p);
      out.push(`${path.relative(root, p)} ${st.mode.toString(8)} ${st.mtimeMs} ${e.isFile() ? fs.readFileSync(p, 'utf8') : ''}`);
      if (e.isDirectory()) walk(p);
    }
  };
  walk(root);
  return out.join('\n');
}
