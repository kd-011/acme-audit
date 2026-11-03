import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

export const DEFAULT_SCHEDULE = fileURLToPath(new URL('../data/schedule.json', import.meta.url));

export function loadSchedule(file = DEFAULT_SCHEDULE, extraLifetimes = []) {
  let s;
  try {
    s = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    throw new Error(`cannot read schedule ${file}: ${e.message}`);
  }
  const need = (ok, what) => { if (!ok) throw new Error(`schedule ${file}: ${what}`); };
  need(Array.isArray(s.targets) && s.targets.length > 0 && s.targets.every((t) => t.days > 0), 'targets must be a list of { days, label }');
  need(s.facts && s.facts.renew_at_fraction_of_lifetime > 0 && s.facts.renew_at_fraction_of_lifetime < 1, 'facts.renew_at_fraction_of_lifetime must be between 0 and 1');
  need(Array.isArray(s.facts.hardcoded_numbers), 'facts.hardcoded_numbers must be a list');
  need(s.policy && s.policy.min_margin_days > 0 && s.policy.min_runs_in_renew_window > 0, 'policy.min_margin_days and policy.min_runs_in_renew_window are required');
  need(s.clients && s.clients.certbot && s.clients.acmesh && s.clients.traefik && s.clients.caddy, 'clients must describe certbot, acmesh, caddy and traefik');
  for (const days of extraLifetimes) s.targets.push({ days, label: `${days}-day lifetime from --lifetime`, source: null });
  return s;
}

// "4.1.0" against "4.0.0": negative, zero or positive. Non-numeric parts count as zero.
export function cmpVersion(a, b) {
  const pa = String(a).split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
}
