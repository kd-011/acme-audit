import path from 'node:path';
import { isStaging } from '../ctx.mjs';
import { timespanDays } from '../cron.mjs';
import { describeJudgement, fmtDays, gapWhy, judge, judgeGap } from '../window.mjs';

const LOCATIONS = ['/etc/caddy/Caddyfile', '/usr/local/etc/caddy/Caddyfile', '/etc/Caddyfile'];

function importTargets(tree, from, pattern) {
  const dir = path.posix.dirname(from);
  const full = pattern.startsWith('/') ? pattern : path.posix.join(dir, pattern);
  if (!/[/*]|\.(caddy|conf)$/.test(pattern)) return [];
  if (!full.includes('*')) return tree.isFile(full) ? [full] : [];
  const re = new RegExp(`^${path.posix.basename(full).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`);
  return tree.list(path.posix.dirname(full)).filter((n) => re.test(n)).map((n) => path.posix.join(path.posix.dirname(full), n)).filter((p) => tree.isFile(p));
}

function readCaddyfile(ctx, file, seen, depth) {
  if (seen.has(file) || depth > 3) return;
  seen.add(file);
  const text = ctx.tree.read(file);
  if (text === null) return;
  const L = ctx.schedule;
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line) return;
    const [name, arg] = line.split(/\s+/);
    const at = i + 1;
    if (name === 'import' && arg) { for (const f of importTargets(ctx.tree, file, arg)) readCaddyfile(ctx, f, seen, depth + 1); return; }
    if (['acme_ca', 'dir', 'ca'].includes(name) && arg && isStaging(arg)) {
      ctx.add({ kind: 'DEAD-AUTH', severity: 'warn', client: 'caddy', file, line: at, summary: `${name} pins the Let's Encrypt staging CA`, why: 'Staging certificates are not trusted by browsers. Staging is where the 64-day lifetime is tested first, so it is the wrong place for a live site.', detail: { reason: 'staging', url: arg } });
    }
    if (name === 'renewal_window_ratio' && arg && !Number.isNaN(Number(arg))) {
      const r = Number(arg);
      const j = judge(L, { kind: 'before', days: (life) => r * life });
      if (j) ctx.add({ kind: 'RENEW-WINDOW', severity: j.severity, client: 'caddy', file, line: at, summary: `renewal_window_ratio is ${arg}, so Caddy renews with ${Math.round(r * 1000) / 10}% of the lifetime left`, why: `${describeJudgement(L, j)} Caddy's own default is ${L.clients.caddy.default_renewal_window_ratio}.`, detail: { ratio: r, target_days: j.target.days } });
    }
    if (name === 'renew_interval' && arg) {
      const gap = timespanDays(arg);
      const j = gap === null ? null : judgeGap(L, gap);
      if (j) ctx.add({ kind: 'TIMER-INFREQUENT', severity: 'warn', client: 'caddy', file, line: at, summary: `renew_interval is ${arg}: Caddy looks for due renewals every ${fmtDays(gap)}`, why: `${gapWhy(L, j, gap)} Caddy's own default is ${L.clients.caddy.default_renew_interval_minutes} minutes.`, detail: { gap_days: gap, target_days: j.target.days, schedule: 'caddy' } });
    }
  });
}

export function checkCaddy(ctx) {
  const seen = new Set();
  for (const f of LOCATIONS) {
    if (!ctx.tree.isFile(f)) continue;
    ctx.found.caddy++;
    readCaddyfile(ctx, f, seen, 0);
  }
}
