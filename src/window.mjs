// The arithmetic behind RENEW-WINDOW, TIMER-INFREQUENT and the hardcoded-days check.
// Every number comes from the schedule: the lifetimes to test against and the two policy values.

const round = (n) => Math.round(n * 10) / 10;
export const fmtDays = (d) => `${round(d)} day${round(d) === 1 ? '' : 's'}`;

// A renewal rule says either "renew when T days are left" (kind before) or "renew N days after issue" (kind since).
// For each lifetime we work out when that fires and how many days are left to retry if it fails.
export function judge(schedule, rule) {
  let worst = null;
  for (const target of schedule.targets) {
    const L = target.days;
    let age, margin, everyRun = false;
    if (rule.kind === 'before') {
      const T = rule.days(L);
      everyRun = T >= L;
      age = Math.max(0, L - T);
      margin = Math.min(T, L);
    } else {
      // acme.sh renews one day early and never later than one day before expiry.
      age = rule.acmesh ? Math.min(rule.days, L) - 1 : rule.days;
      margin = L - age;
    }
    let severity = null;
    if (everyRun || margin <= 1) severity = 'error';
    else if (margin < schedule.policy.min_margin_days) severity = 'warn';
    if (!severity) continue;
    const cand = { severity, target, age, margin, everyRun };
    if (!worst || (severity === 'error' && worst.severity !== 'error') || (severity === worst.severity && margin < worst.margin)) worst = cand;
  }
  return worst;
}

export function describeJudgement(schedule, j) {
  const L = j.target.days;
  const good = Math.round(L * schedule.facts.renew_at_fraction_of_lifetime);
  const when = j.everyRun
    ? `On ${L}-day certificates (${j.target.label}) this renews on every run.`
    : j.margin <= 0
      ? `On ${L}-day certificates (${j.target.label}) it fires at day ${round(j.age)}, after expiry.`
      : `On ${L}-day certificates (${j.target.label}) it fires at day ${round(j.age)}, leaving ${fmtDays(j.margin)} of retries.`;
  return `${when} Let's Encrypt advises renewing at about two thirds of the lifetime, around day ${good}.`;
}

// The longest gap in days between runs that still leaves the policy number of tries inside the renewal window.
export function allowedGap(schedule, L) {
  const window = L * (1 - schedule.facts.renew_at_fraction_of_lifetime);
  return window / schedule.policy.min_runs_in_renew_window;
}

export function judgeGap(schedule, gapDays) {
  let worst = null;
  for (const target of schedule.targets) {
    const allowed = allowedGap(schedule, target.days);
    if (gapDays > allowed && (!worst || allowed < worst.allowed)) worst = { target, allowed };
  }
  if (!worst) return null;
  const L = worst.target.days;
  const window = L * (1 - schedule.facts.renew_at_fraction_of_lifetime);
  const tries = Math.max(1, Math.floor(window / gapDays));
  return { ...worst, window, tries };
}

export function gapWhy(schedule, j, gapDays) {
  const L = j.target.days;
  return `On ${L}-day certificates (${j.target.label}) the renewal window is about ${fmtDays(j.window)}. Running every ${fmtDays(gapDays)} gives ${j.tries} ${j.tries === 1 ? 'try' : 'tries'} there, and one failed run can cost most of it.`;
}
