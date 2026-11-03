// Turns cron lines and systemd calendar expressions into "how many days can pass between runs".
// Both are expanded to the set of days they fire on over a fixed window, so the answer is the longest gap.

const DAYS = 800;
const START = Date.UTC(2027, 0, 1);
const MON = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const DOW = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];

const dateOf = (i) => new Date(START + i * 86400000);

// Longest time in days between two runs. A schedule is the days it fires on plus the minutes of the day it
// fires at; a bare Set is read as one run at midnight. A job that fires several times a day has a gap under one.
export function maxGap(sched) {
  const days = sched instanceof Set ? sched : sched.days;
  const sorted = [...days].sort((a, b) => a - b);
  if (sorted.length < 2) return DAYS;
  const t = [...(sched instanceof Set ? [0] : sched.times)].sort((a, b) => a - b);
  const span = (t[t.length - 1] - t[0]) / 1440;
  let gap = 0;
  for (let i = 1; i < t.length; i++) gap = Math.max(gap, (t[i] - t[i - 1]) / 1440);
  for (let i = 1; i < sorted.length; i++) gap = Math.max(gap, sorted[i] - sorted[i - 1] - span);
  return gap;
}

const timesOf = (hours, minutes) => {
  const out = new Set();
  for (const h of hours) for (const m of minutes) out.add(h * 60 + m);
  return out;
};

function parseField(text, lo, hi, names, sysd = false) {
  const out = new Set();
  for (const part of text.split(',')) {
    const [rangePart, stepPart] = part.split('/');
    const step = stepPart === undefined ? 1 : Number(stepPart);
    if (!Number.isInteger(step) || step < 1) return null;
    let a, b;
    const num = (s) => {
      const i = names ? names.indexOf(s.toLowerCase().slice(0, 3)) : -1;
      return i >= 0 ? i + (names === MON ? 1 : 0) : /^\d+$/.test(s) ? Number(s) : NaN;
    };
    if (rangePart === '*' || rangePart === '') { a = lo; b = hi; }
    else if (rangePart.includes(sysd ? '..' : '-')) {
      const [x, y] = rangePart.split(sysd ? '..' : '-');
      a = num(x); b = num(y);
    } else { a = num(rangePart); b = stepPart === undefined ? a : hi; }
    if (Number.isNaN(a) || Number.isNaN(b) || a < lo || b > hi) return null;
    for (let v = a; v <= b; v += step) out.add(names === DOW && v === 7 ? 0 : v);
  }
  return out;
}

// Five cron fields (minute hour day-of-month month day-of-week) or an @macro. Returns { days, times } or null.
export function cronDays(fields) {
  if (fields.length === 1) {
    const m = { '@hourly': 'hourly', '@daily': 'daily', '@midnight': 'daily', '@weekly': 'weekly', '@monthly': 'monthly', '@yearly': 'yearly', '@annually': 'yearly' }[fields[0]];
    return m ? calendarDays(m) : null;
  }
  if (fields.length !== 5) return null;
  const [mi, ho, dom, mon, dow] = fields;
  const MI = parseField(mi, 0, 59);
  const HO = parseField(ho, 0, 23);
  if (!MI || !HO) return null;
  const D = parseField(dom, 1, 31);
  const M = parseField(mon, 1, 12, MON);
  const W = parseField(dow, 0, 7, DOW);
  if (!D || !M || !W) return null;
  const domStar = dom.startsWith('*');
  const dowStar = dow.startsWith('*');
  const out = new Set();
  for (let i = 0; i < DAYS; i++) {
    const d = dateOf(i);
    const okD = D.has(d.getUTCDate());
    const okW = W.has(d.getUTCDay());
    // cron ORs day-of-month and day-of-week when both are restricted.
    const day = !domStar && !dowStar ? okD || okW : okD && okW;
    if (day && M.has(d.getUTCMonth() + 1)) out.add(i);
  }
  return { days: out, times: timesOf(HO, MI) };
}

const SHORTCUTS = {
  minutely: '*-*-* *:*:00', hourly: '*-*-* *:00:00', daily: '*-*-*', weekly: 'Mon *-*-*', monthly: '*-*-01',
  quarterly: '*-01,04,07,10-01', semiannually: '*-01,07-01', 'semi-annually': '*-01,07-01', yearly: '*-01-01', annually: '*-01-01',
};

// systemd.time OnCalendar. Returns { days, times } like cronDays, or null. Seconds are ignored.
export function calendarDays(expr) {
  const e = expr.trim();
  if (SHORTCUTS[e.toLowerCase()]) return calendarDays(SHORTCUTS[e.toLowerCase()]);
  let W = null, D = null, M = null, times = new Set([0]);
  for (const tok of e.split(/\s+/)) {
    if (tok.includes(':')) {
      const [h, m] = tok.split(':');
      const HO = parseField(h, 0, 23, null, true);
      const MI = parseField(m, 0, 59, null, true);
      if (!HO || !MI) return null;
      times = timesOf(HO, MI);
      continue;
    }
    if (/^[A-Za-z]/.test(tok)) { W = new Set(); for (const p of tok.split(',')) { const r = parseField(p, 0, 6, DOW, true); if (!r) return null; r.forEach((v) => W.add(v)); } continue; }
    const parts = tok.split('-');
    if (parts.length === 3) parts.shift();
    if (parts.length !== 2) return null;
    M = parseField(parts[0], 1, 12, null, true);
    D = parseField(parts[1], 1, 31, null, true);
    if (!M || !D) return null;
  }
  const out = new Set();
  for (let i = 0; i < DAYS; i++) {
    const d = dateOf(i);
    if ((!W || W.has(d.getUTCDay())) && (!D || D.has(d.getUTCDate())) && (!M || M.has(d.getUTCMonth() + 1))) out.add(i);
  }
  return { days: out, times };
}

const UNITS = { us: 1e-6, ms: 1e-3, s: 1, sec: 1, second: 1, seconds: 1, m: 60, min: 60, minute: 60, minutes: 60, h: 3600, hr: 3600, hour: 3600, hours: 3600, d: 86400, day: 86400, days: 86400, w: 604800, week: 604800, weeks: 604800, month: 2629800, months: 2629800, y: 31557600, year: 31557600, years: 31557600 };

// "1w", "12h", "1d 12h", "300" (seconds). Returns days, or null.
export function timespanDays(text) {
  let secs = 0;
  let any = false;
  for (const m of text.trim().matchAll(/(\d+(?:\.\d+)?)\s*([a-z]*)/gi)) {
    const u = m[2] === '' ? 1 : UNITS[m[2].toLowerCase()];
    if (!u) return null;
    secs += Number(m[1]) * u;
    any = true;
  }
  return any ? secs / 86400 : null;
}
