import path from 'node:path';
import { checkHook } from '../hooks.mjs';
import { isStaging } from '../ctx.mjs';
import { cmpVersion } from '../schedule.mjs';
import { describeJudgement, fmtDays, judge } from '../window.mjs';

const B64_START = '__ACME_BASE64__START_';
const B64_END = '__ACME_BASE64__END_';
const SKIP_DIRS = new Set(['ca', 'deploy', 'dnsapi', 'notify']);

// acme.sh stores Key='value' lines. Hooks and the reload command are base64 wrapped.
export function parseConf(text) {
  const out = {};
  text.split('\n').forEach((raw, i) => {
    const m = raw.match(/^([A-Za-z_][\w]*)=(['"]?)(.*)\2\s*$/);
    if (!m) return;
    let v = m[3];
    if (v.startsWith(B64_START)) v = Buffer.from(v.slice(B64_START.length).replace(B64_END, ''), 'base64').toString('utf8');
    out[m[1]] = { value: v, line: i + 1 };
  });
  return out;
}

export function checkAcmesh(ctx) {
  const t = ctx.tree;
  const L = ctx.schedule;
  const ari = L.clients.acmesh.ari_since;
  for (const home of t.homes()) {
    const dir = `${home}/.acme.sh`;
    if (!t.isDir(dir)) continue;
    ctx.acmeHome ??= dir;
    const script = `${dir}/acme.sh`;
    const scriptText = t.read(script);
    let domains = 0;
    for (const d of t.children(dir)) {
      if (SKIP_DIRS.has(path.posix.basename(d)) || path.posix.basename(d).startsWith('.') || !t.isDir(d)) continue;
      for (const file of t.children(d).filter((p) => p.endsWith('.conf'))) {
        const text = t.read(file);
        if (text === null) continue;
        const conf = parseConf(text);
        if (!conf.Le_Domain) continue;
        domains++;
        ctx.found.acmesh++;
        const days = conf.Le_RenewalDays;
        if (days && /^\d+$/.test(days.value)) {
          const n = Number(days.value);
          const j = judge(L, { kind: 'since', days: n, acmesh: true });
          if (j) ctx.add({ kind: 'RENEW-WINDOW', severity: j.severity, client: 'acmesh', file, line: days.line, summary: `Le_RenewalDays is pinned to ${n} for ${conf.Le_Domain.value}`, why: `${describeJudgement(L, j)} From acme.sh 3.1.5 a pinned value also overrides the renewal window Let's Encrypt suggests (ARI). Re-issuing without --days drops the pin.`, detail: { days: n, target_days: j.target.days } });
        }
        if (conf.Le_API && isStaging(conf.Le_API.value)) ctx.add({ kind: 'DEAD-AUTH', severity: 'warn', client: 'acmesh', file, line: conf.Le_API.line, summary: `${conf.Le_Domain.value} is issued by the Let's Encrypt staging CA`, why: 'Staging certificates are not trusted by browsers. Staging is where the 64-day lifetime is tested first, so it is the wrong place for a live site.', detail: { reason: 'staging' } });
        for (const [key, role] of [['Le_PreHook', 'pre'], ['Le_PostHook', 'post'], ['Le_RenewHook', 'deploy'], ['Le_ReloadCmd', 'deploy']]) {
          if (conf[key]?.value) checkHook(ctx, { client: 'acmesh', file, line: conf[key].line, field: key, command: conf[key].value, role });
        }
      }
    }
    const ver = scriptText?.match(/^VER=(\S+)/m);
    if (domains && ver && cmpVersion(ver[1], ari) < 0) {
      const line = scriptText.slice(0, ver.index).split('\n').length;
      ctx.add({ kind: 'OLD-CLIENT', severity: 'info', client: 'acmesh', file: script, line, summary: `acme.sh ${ver[1]} is older than ${ari}, the first release with ARI code`, why: `Without ARI the client renews on its own schedule, ${fmtDays(L.clients.acmesh.default_renewal_days)} after issue by default, and ignores what Let's Encrypt suggests.`, detail: { version: ver[1], first_ari_version: ari } });
    }
  }
}
