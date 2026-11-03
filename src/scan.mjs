// Finds what runs renewals on a machine: cron files, systemd timers and the scripts they call.
import path from 'node:path';
import { calendarDays, cronDays, maxGap, timespanDays } from './cron.mjs';
import { checkHook, shellWords } from './hooks.mjs';
import { judge, describeJudgement, judgeGap, gapWhy, fmtDays } from './window.mjs';

const RENEWERS = [
  ['certbot', (t) => /\bcertbot\b/.test(t) && /\brenew\b/.test(t)],
  ['acmesh', (t) => /acme\.sh\b/.test(t) && /--(cron|renew)/.test(t)],
  ['lego', (t) => /\blego\b/.test(t) && /\brenew\b/.test(t)],
];
export const clientOfCommand = (text) => RENEWERS.find(([, test]) => test(text))?.[0] ?? null;
export const ACME_WORDS = /certbot|acme\.sh|acme_sh|\blego\b|letsencrypt|let's encrypt|\bACME\b|checkend|openssl\s+x509|renew/i;
export const isComment = (line) => /^\s*[#;]/.test(line);

const CLIENT_NAME = { certbot: 'certbot', acmesh: 'acme.sh', lego: 'lego' };
export const clientName = (c) => CLIENT_NAME[c] ?? c;

// The client that a command line ends up running: directly, or through a script it names.
function attribute(ctx, text) {
  const direct = clientOfCommand(text);
  if (direct) return { client: direct, via: null };
  for (const tok of shellWords(text).filter((w) => w.startsWith('/')).slice(0, 4)) {
    const body = ctx.tree.read(tok);
    if (!body) continue;
    const hit = body.split('\n').filter((l) => !isComment(l)).map(clientOfCommand).find(Boolean);
    if (hit) { ctx.scan(tok); return { client: hit, via: tok }; }
  }
  return { client: null, via: null };
}

function addScheduler(ctx, s) {
  ctx.schedulers.push({ enabled: true, ...s });
}

const CRON_DIRS = { '/etc/cron.hourly': 1, '/etc/cron.daily': 1, '/etc/cron.weekly': 7, '/etc/cron.monthly': 31 };

export function scanCron(ctx) {
  const files = ['/etc/crontab', ...ctx.tree.children('/etc/cron.d'), ...ctx.tree.children('/var/spool/cron/crontabs'), ...ctx.tree.children('/var/spool/cron')];
  for (const file of new Set(files)) {
    if (!ctx.tree.isFile(file)) continue;
    const text = ctx.tree.read(file);
    if (text === null) continue;
    ctx.counts.cron_files++;
    ctx.scan(file);
    text.split('\n').forEach((raw, i) => {
      const line = raw.trim();
      if (!line || line.startsWith('#') || /^[A-Za-z_]\w*\s*=/.test(line)) return;
      const toks = line.split(/\s+/);
      const fields = toks[0].startsWith('@') ? toks.slice(0, 1) : toks.slice(0, 5);
      const rest = toks.slice(fields.length).join(' ');
      const { client, via } = attribute(ctx, rest);
      if (!client) return;
      const days = cronDays(fields);
      if (!days) { ctx.note(file, `line ${i + 1}: could not read the schedule "${fields.join(' ')}"`); }
      addScheduler(ctx, { client, kind: 'cron', file, line: i + 1, gap: days ? maxGap(days) : null, via, text: rest });
    });
  }
  const anacron = ctx.tree.read('/etc/anacrontab');
  if (anacron) {
    ctx.counts.cron_files++;
    ctx.scan('/etc/anacrontab');
    anacron.split('\n').forEach((raw, i) => {
      const m = raw.trim().match(/^(@\w+|\d+)\s+\d+\s+\S+\s+(.*)$/);
      if (!m || raw.trim().startsWith('#')) return;
      const client = attribute(ctx, m[2]).client;
      if (!client) return;
      const gap = m[1].startsWith('@') ? maxGap(cronDays([m[1]]) ?? new Set()) : Number(m[1]);
      addScheduler(ctx, { client, kind: 'cron', file: '/etc/anacrontab', line: i + 1, gap, text: m[2] });
    });
  }
  for (const [dir, gap] of Object.entries(CRON_DIRS)) {
    for (const file of ctx.tree.children(dir)) {
      const text = ctx.tree.read(file);
      if (!text) continue;
      ctx.scan(file);
      const lines = text.split('\n');
      const at = lines.findIndex((l) => !isComment(l) && clientOfCommand(l));
      if (at >= 0) addScheduler(ctx, { client: clientOfCommand(lines[at]), kind: 'cron', file, line: at + 1, gap, text: lines[at].trim() });
    }
  }
}

function parseUnit(text) {
  const keys = [];
  let section = '';
  text.split('\n').forEach((raw, i) => {
    const l = raw.trim();
    if (!l || l.startsWith('#') || l.startsWith(';')) return;
    const sec = l.match(/^\[(.+)\]$/);
    if (sec) { section = sec[1]; return; }
    const kv = l.match(/^([A-Za-z]+)\s*=\s*(.*)$/);
    if (kv) keys.push({ section, key: kv[1], value: kv[2], line: i + 1 });
  });
  return keys;
}

export function scanSystemd(ctx) {
  const t = ctx.tree;
  const userDirs = t.homes().map((h) => `${h}/.config/systemd/user`);
  const unitDirs = ['/etc/systemd/system', '/etc/systemd/user', ...userDirs, '/lib/systemd/system', '/usr/lib/systemd/system'];
  const units = new Map();
  const enabled = new Set();
  const masked = new Set();
  for (const dir of unitDirs) {
    for (const p of t.children(dir)) {
      const name = path.posix.basename(p);
      if (/\.(wants|requires)$/.test(name)) { for (const n of t.list(p)) enabled.add(n); continue; }
      if (!/\.(timer|service)$/.test(name) || units.has(name)) continue;
      const lst = t.lstat(p);
      if (lst?.isSymbolicLink() && t.resolve(p).path === '/dev/null') { masked.add(name); units.set(name, null); continue; }
      units.set(name, p);
    }
  }
  for (const [name, p] of units) {
    if (!p || !name.endsWith('.timer')) continue;
    const timerText = t.read(p);
    if (timerText === null) continue;
    ctx.counts.timers++;
    const keys = parseUnit(timerText);
    const unitKey = keys.find((k) => k.key === 'Unit' && k.section === 'Timer');
    const serviceName = unitKey?.value ?? name.replace(/\.timer$/, '.service');
    const servicePath = units.get(serviceName);
    const serviceText = servicePath ? t.read(servicePath) : null;
    if (serviceText === null) continue;
    const execs = parseUnit(serviceText).filter((k) => /^ExecStart/.test(k.key));
    let client = null;
    let text = '';
    for (const e of execs) {
      const cmd = e.value.replace(/^[-@+!:]+/, '');
      const a = attribute(ctx, cmd);
      if (a.client) { client = a.client; text = cmd; break; }
    }
    if (!client) continue;
    const spans = keys.filter((k) => k.section === 'Timer' && /^OnUnit(Active|Inactive)Sec$/.test(k.key));
    const cals = keys.filter((k) => k.section === 'Timer' && k.key === 'OnCalendar');
    const gaps = [];
    const days = new Set();
    let calOk = cals.length > 0;
    for (const c of cals) {
      const d = calendarDays(c.value);
      if (!d) { calOk = false; ctx.note(p, `line ${c.line}: could not read OnCalendar=${c.value}`); } else d.forEach((x) => days.add(x));
    }
    if (calOk) gaps.push(maxGap(days));
    for (const s of spans) { const g = timespanDays(s.value); if (g) gaps.push(g); else ctx.note(p, `line ${s.line}: could not read ${s.key}=${s.value}`); }
    const gap = gaps.length ? Math.min(...gaps) : null;
    if (!gaps.length && !keys.some((k) => /^OnCalendar$|^OnUnit/.test(k.key)) && keys.some((k) => /^On(Boot|Startup|Active)Sec$/.test(k.key))) ctx.note(p, 'runs only at boot or start, so the time between runs depends on uptime');
    const first = spans[0] ?? cals[0] ?? keys[0];
    addScheduler(ctx, { client, kind: 'timer', file: p, line: first?.line ?? null, gap, enabled: enabled.has(name) && !masked.has(name), name, text });
  }
  // Services that run a renewal are searched for hooks and numbers even when no timer starts them.
  for (const [name, p] of units) {
    if (!p || !name.endsWith('.service')) continue;
    const text = t.read(p);
    if (text !== null && text.split('\n').some((l) => !isComment(l) && attribute(ctx, l.replace(/^\s*Exec\w+=[-@+!:]*/, '')).client)) ctx.scan(p);
  }
}

// Wrapper scripts live in places nobody lists. Search the usual ones for anything that mentions a client.
export function discoverScripts(ctx) {
  const t = ctx.tree;
  const dirs = ['/usr/local/bin', '/usr/local/sbin', '/etc/letsencrypt/renewal-hooks/pre', '/etc/letsencrypt/renewal-hooks/deploy', '/etc/letsencrypt/renewal-hooks/post'];
  for (const h of t.homes()) dirs.push(`${h}/bin`, `${h}/scripts`, `${h}/.local/bin`);
  for (const d of dirs) for (const p of t.children(d)) if (t.isFile(p)) ctx.scan(p);
}

const optValue = (line, name) => {
  const m = line.match(new RegExp(`${name}(?:=|\\s+)("[^"]*"|'[^']*'|[^\\s"']+)`));
  return m ? m[1].replace(/^["']|["']$/g, '') : null;
};

// Lines that call a client with flags this tool understands: lego renew, certbot hook flags, acme.sh --days.
export function scanInvocations(ctx) {
  const L = ctx.schedule;
  for (const file of ctx.scanFiles.keys()) {
    if (/\/\.acme\.sh\//.test(file) || file.endsWith('/acme.sh')) continue;
    const text = ctx.tree.read(file);
    if (text === null) continue;
    if (file.startsWith('/usr/local/') || /\.(sh|bash)$/.test(file)) ctx.counts.scripts++;
    text.split('\n').forEach((raw, i) => {
      if (isComment(raw)) return;
      const line = raw.replace(/^\s*Exec\w+=[-@+!:]*/, '');
      const at = i + 1;
      if (/\blego\b/.test(line) && /\brenew\b/.test(line)) {
        ctx.found.lego++;
        const days = optValue(line, '--days');
        if (days && /^\d+$/.test(days) && !/--dynamic\b/.test(line)) {
          const n = Number(days);
          ctx.claimed.add(`${file}:${at}`);
          const j = judge(L, { kind: 'before', days: () => n });
          if (j) ctx.add({ kind: 'RENEW-WINDOW', severity: j.severity, client: 'lego', file, line: at, summary: `lego renew --days ${n} renews when ${fmtDays(n)} are left`, why: `${describeJudgement(L, j)} --dynamic picks the renewal point from the certificate's own lifetime.`, detail: { days: n, target_days: j.target.days } });
        }
        const hook = optValue(line, '--renew-hook');
        if (hook) checkHook(ctx, { client: 'lego', file, line: at, field: '--renew-hook', command: hook, role: 'deploy' });
      }
      if (/\bcertbot\b/.test(line) && /\brenew\b/.test(line)) {
        for (const [flag, role] of [['--deploy-hook', 'deploy'], ['--renew-hook', 'deploy'], ['--pre-hook', 'pre'], ['--post-hook', 'post']]) {
          const v = optValue(line, flag);
          if (v) checkHook(ctx, { client: 'certbot', file, line: at, field: flag, command: v, role });
        }
      }
      if (/acme\.sh\b/.test(line) && /--days\b/.test(line)) {
        const d = optValue(line, '--days');
        if (d && /^\d+$/.test(d)) {
          const n = Number(d);
          ctx.claimed.add(`${file}:${at}`);
          const j = judge(L, { kind: 'since', days: n, acmesh: true });
          if (j) ctx.add({ kind: 'RENEW-WINDOW', severity: j.severity, client: 'acmesh', file, line: at, summary: `acme.sh --days ${n} renews ${fmtDays(n)} after issue`, why: describeJudgement(L, j), detail: { days: n, target_days: j.target.days } });
        }
      }
    });
  }
}

// After every client has been read: judge the schedulers, and say so when a client with certificates has none.
export function judgeSchedulers(ctx) {
  const L = ctx.schedule;
  for (const s of ctx.schedulers) {
    if (!s.enabled || s.gap === null || s.gap === undefined) continue;
    const j = judgeGap(L, s.gap);
    if (!j) continue;
    ctx.add({
      kind: 'TIMER-INFREQUENT', severity: 'warn', client: s.client, file: s.file, line: s.line,
      summary: `${clientName(s.client)} renewal runs about every ${fmtDays(s.gap)}`,
      why: `${gapWhy(L, j, s.gap)} Under ${fmtDays(j.allowed)} between runs would give ${L.policy.min_runs_in_renew_window} tries.`,
      detail: { gap_days: s.gap, target_days: j.target.days, schedule: s.kind },
    });
  }
  for (const [client, dir] of [['certbot', '/etc/letsencrypt/renewal'], ['acmesh', ctx.acmeHome ?? '/.acme.sh']]) {
    if (!ctx.found[client]) continue;
    const mine = ctx.schedulers.filter((s) => s.client === client);
    if (mine.some((s) => s.enabled)) continue;
    const off = mine.find((s) => !s.enabled);
    const cmd = client === 'certbot' ? 'certbot renew' : 'acme.sh --cron';
    const blind = 'This audit only sees timers and cron files under the root it was given, so a scheduler in a container, on another machine or in a service manager it does not read is invisible to it.';
    ctx.add({
      kind: 'TIMER-INFREQUENT', severity: 'error', client,
      file: off ? off.file : dir, line: off ? off.line : null,
      summary: off ? `${off.name} runs ${cmd} but is not enabled` : `nothing under this root runs ${cmd}`,
      why: off ? 'Nothing starts the timer, so certificates are never renewed. They then expire on their lifetime, and shorter lifetimes make that come faster.' : `Certificates are only renewed when something runs it. ${blind}`,
      detail: { schedule: off ? 'timer-not-enabled' : 'none' },
    });
  }
}
