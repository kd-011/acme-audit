import path from 'node:path';
import { checkHook, checkHookDir } from '../hooks.mjs';
import { isStaging } from '../ctx.mjs';
import { cmpVersion } from '../schedule.mjs';
import { timespanDays } from '../cron.mjs';
import { describeJudgement, fmtDays, judge } from '../window.mjs';

const ALL_FOUR = ['cert', 'privkey', 'chain', 'fullchain'];

// certbot reads these with configobj: key = value, [section], [[subsection]], # comments.
export function parseIni(text) {
  const top = {};
  const sections = {};
  const subs = {};
  const lines = {};
  const bad = [];
  let cur = top;
  text.split('\n').forEach((raw, i) => {
    const l = raw.trim();
    if (!l || l.startsWith('#')) return;
    const sub = l.match(/^\[\[(.+)\]\]$/);
    const sec = l.match(/^\[([^\[\]]+)\]$/);
    if (sub) { subs[sub[1]] = {}; cur = subs[sub[1]]; return; }
    if (sec) { sections[sec[1]] = sections[sec[1]] ?? {}; lines[sec[1]] = i + 1; cur = sections[sec[1]]; return; }
    const kv = l.match(/^([^=]+?)\s*=\s*(.*)$/);
    if (kv) { cur[kv[1]] = { value: kv[2].replace(/^["']|["']$/g, ''), line: i + 1 }; return; }
    bad.push(i + 1);
  });
  return { top, sections, subs, lines, bad };
}

// "30 days", "2 weeks", "3 months" or a bare number of days, as certbot's parser reads them.
export function intervalDays(text) {
  const t = text.trim();
  if (/^\d+$/.test(t)) return Number(t);
  return timespanDays(t);
}

function installedVersions(tree) {
  const out = [];
  for (const base of ['/usr/lib', '/usr/local/lib', '/opt/eff.org/certbot/venv/lib']) {
    for (const py of tree.list(base).filter((n) => /^python3/.test(n))) {
      for (const pk of ['dist-packages', 'site-packages']) {
        for (const n of tree.list(`${base}/${py}/${pk}`)) {
          const m = n.match(/^certbot-(\d[\w.]*)\.(?:dist|egg)-info$/);
          if (m) out.push({ version: m[1], file: `${base}/${py}/${pk}/${n}` });
        }
      }
    }
  }
  return out.sort((a, b) => cmpVersion(b.version, a.version));
}

export function checkCertbot(ctx) {
  const t = ctx.tree;
  const L = ctx.schedule;
  const ari = L.clients.certbot.ari_since;
  const confs = t.children('/etc/letsencrypt/renewal').filter((p) => p.endsWith('.conf') && t.isFile(p));
  const versions = new Map();

  for (const file of confs) {
    ctx.found.certbot++;
    const text = t.read(file);
    if (text === null) { ctx.note(file, 'could not be read'); continue; }
    const ini = parseIni(text);
    const rp = ini.sections.renewalparams;
    const name = path.posix.basename(file, '.conf');

    const missing = ALL_FOUR.filter((k) => !ini.top[k]);
    if (ini.bad.length || missing.length) {
      ctx.note(file, ini.bad.length ? `line ${ini.bad[0]} is not valid renewal file syntax` : `missing ${missing.join(', ')}`);
      ctx.add({ kind: 'DEAD-AUTH', severity: 'error', client: 'certbot', file, line: ini.bad[0] ?? 1, summary: `certbot cannot read the renewal file for ${name}`, why: 'certbot logs the file as broken, skips the certificate and exits non-zero. It is never renewed, and it expires on its lifetime.', detail: { reason: ini.bad.length ? 'syntax' : 'missing-keys' } });
      continue;
    }
    if (ini.top.version) {
      const v = ini.top.version.value;
      if (!versions.has(v)) versions.set(v, { file, line: ini.top.version.line, count: 0 });
      versions.get(v).count++;
    }

    const before = ini.top.renew_before_expiry;
    if (before) {
      const days = intervalDays(before.value);
      if (days === null) ctx.note(file, `line ${before.line}: could not read renew_before_expiry = ${before.value}`);
      else {
        const j = judge(L, { kind: 'before', days: () => days });
        if (j) ctx.add({ kind: 'RENEW-WINDOW', severity: j.severity, client: 'certbot', file, line: before.line, summary: `renew_before_expiry is ${before.value} for ${name}`, why: `${describeJudgement(L, j)} Deleting the line lets certbot use its own default, which from ${L.clients.certbot.lifetime_fraction_since} is a third of the lifetime.`, detail: { days, target_days: j.target.days } });
      }
    }

    if (!rp) {
      ctx.add({ kind: 'DEAD-AUTH', severity: 'error', client: 'certbot', file, line: 1, summary: `${name} has no [renewalparams] section`, why: 'certbot logs the file, skips the certificate and exits non-zero. It is never renewed.', detail: { reason: 'no-renewalparams' } });
      continue;
    }
    const auth = rp.authenticator;
    if (!auth) {
      ctx.add({ kind: 'DEAD-AUTH', severity: 'error', client: 'certbot', file, line: ini.lines.renewalparams, summary: `${name} names no authenticator`, why: 'certbot skips a renewal file with no authenticator, logs an error and exits non-zero. The certificate is never renewed.', detail: { reason: 'no-authenticator' } });
    } else if (auth.value === 'manual' && !rp.manual_auth_hook) {
      ctx.add({ kind: 'DEAD-AUTH', severity: 'error', client: 'certbot', file, line: auth.line, summary: `${name} uses the manual authenticator with no auth hook`, why: 'certbot cannot ask a person to answer a challenge during an unattended run, so the renewal fails each time.', detail: { reason: 'manual-without-hook' } });
    } else if (auth.value === 'webroot') {
      const paths = new Map();
      for (const p of (rp.webroot_path?.value ?? '').split(',').map((x) => x.trim()).filter(Boolean)) paths.set(p, rp.webroot_path.line);
      for (const [, v] of Object.entries(ini.subs.webroot_map ?? {})) paths.set(v.value, v.line);
      const gone = [...paths].filter(([p]) => !t.isDir(p));
      if (gone.length) ctx.add({ kind: 'DEAD-AUTH', severity: 'warn', client: 'certbot', file, line: gone[0][1], summary: `${name} uses the webroot ${gone[0][0]}, which is not on this machine`, why: 'The webroot authenticator writes its challenge file there. If the directory is gone the challenge fails and the certificate is not renewed. A webroot that lives in a container will show up here too.', detail: { reason: 'webroot-missing', paths: gone.map(([p]) => p) } });
    }
    if (rp.autorenew && /^(false|0|no)$/i.test(rp.autorenew.value)) {
      ctx.add({ kind: 'DEAD-AUTH', severity: 'warn', client: 'certbot', file, line: rp.autorenew.line, summary: `${name} has autorenew switched off`, why: '`certbot renew` skips a certificate with autorenew set to False, so only a person renewing it by hand keeps it valid.', detail: { reason: 'autorenew-off' } });
    }
    if (rp.server && isStaging(rp.server.value)) {
      ctx.add({ kind: 'DEAD-AUTH', severity: 'warn', client: 'certbot', file, line: rp.server.line, summary: `${name} is issued by the Let's Encrypt staging CA`, why: 'Staging certificates are not trusted by browsers. Staging is where the 64-day lifetime is tested first, so it is the wrong place for a live site.', detail: { reason: 'staging' } });
    }

    for (const [key, role, field] of [['pre_hook', 'pre', 'pre_hook'], ['post_hook', 'post', 'post_hook'], ['renew_hook', 'deploy', 'renew_hook'], ['deploy_hook', 'deploy', 'deploy_hook'], ['manual_auth_hook', 'auth', 'manual_auth_hook']]) {
      if (rp[key]) checkHook(ctx, { client: 'certbot', file, line: rp[key].line, field, command: rp[key].value, role });
    }
  }

  for (const role of ['pre', 'deploy', 'post']) checkHookDir(ctx, `/etc/letsencrypt/renewal-hooks/${role}`, role);

  if (ctx.found.certbot === 0) return;
  const installed = installedVersions(t)[0];
  const report = (version, file, line, source, count) => {
    if (cmpVersion(version, ari) >= 0) return;
    ctx.add({
      kind: 'OLD-CLIENT', severity: 'info', client: 'certbot', file, line,
      summary: `certbot ${version} (${source}) is older than ${ari}, the first release that checks ARI`,
      why: `Without ARI the client renews on its own schedule, which before ${L.clients.certbot.lifetime_fraction_since} was a fixed ${fmtDays(L.clients.certbot.default_before_days)} before expiry, and ignores what Let's Encrypt suggests.`,
      detail: { version, first_ari_version: ari, source: source === 'installed' ? 'installed' : 'renewal-file', lineages: count },
    });
  };
  if (installed) report(installed.version, installed.file, null, 'installed', confs.length);
  else for (const [v, at] of versions) report(v, at.file, at.line, 'version recorded in the renewal file', at.count);
}
