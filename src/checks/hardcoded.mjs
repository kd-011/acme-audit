// Renewal thresholds written into cron lines, units and wrapper scripts. Let's Encrypt's own advice is to
// grep for them: the numbers it names come from the schedule file, nothing is typed in here.
import { ACME_WORDS, isComment } from '../scan.mjs';
import { describeJudgement, fmtDays, judge } from '../window.mjs';

const DAY_WORDS = /days?|mtime|checkend|expir|\bage\b|thresh|86400/i;
const DAY_SECONDS = 86400;

export function checkHardcoded(ctx) {
  const L = ctx.schedule;
  const named = new Set(L.facts.hardcoded_numbers);
  for (const file of ctx.scanFiles.keys()) {
    if (/\/\.acme\.sh\//.test(file) || file.endsWith('/acme.sh')) continue;
    const text = ctx.tree.read(file);
    if (text === null || !ACME_WORDS.test(text)) continue;
    text.split('\n').forEach((raw, i) => {
      const at = i + 1;
      if (isComment(raw) || ctx.claimed.has(`${file}:${at}`)) return;
      const add = (severity, summary, why, detail) => { ctx.claimed.add(`${file}:${at}`); ctx.add({ kind: 'HARDCODED-DAYS', severity, client: 'any', file, line: at, summary, why, detail }); };

      const mt = raw.match(/-mtime\s+[+-]?(\d+)/);
      if (mt) {
        const n = Number(mt[1]);
        const j = judge(L, { kind: 'since', days: n });
        if (j) return add(j.severity, `acts on certificates ${fmtDays(n)} after issue (-mtime ${mt[0].split(/\s+/)[1]})`, describeJudgement(L, j), { days: n, direction: 'since-issue', target_days: j.target.days });
      }
      const ce = raw.match(/-checkend\s+(?:(\d+)|\$\(\(\s*(\d+)\s*\*\s*(\d+)\s*\)\))/);
      if (ce) {
        const secs = ce[1] ? Number(ce[1]) : Number(ce[2]) * Number(ce[3]);
        const n = secs / DAY_SECONDS;
        const j = judge(L, { kind: 'before', days: () => n });
        if (j) return add(j.severity, `renews when a certificate expires within ${fmtDays(n)} (-checkend ${ce[1] ?? `${ce[2]}*${ce[3]}`})`, describeJudgement(L, j), { days: n, direction: 'before-expiry', target_days: j.target.days });
      }
      if (!DAY_WORDS.test(raw)) return;
      for (const m of raw.matchAll(/(?<![\w./$-])(\d+)(?:\s?(?:d|days?)\b)?(?![\w.])/g)) {
        const n = Number(m[1]);
        if (!named.has(n)) continue;
        return add('warn', `has the number ${n} next to a day count`, `Let's Encrypt names ${[...named].join(', ')} as values to look for. If ${n} is how many days a certificate may age before renewal, it is too late for ${L.targets.map((x) => `${x.days}-day`).join(' and ')} certificates. Check whether it counts from issue or from expiry.`, { days: n, direction: 'unknown' });
      }
    });
  }
}
