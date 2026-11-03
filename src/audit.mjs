import { Tree } from './fsx.mjs';
import { Ctx, sortFindings } from './ctx.mjs';
import { loadSchedule } from './schedule.mjs';
import { checkAcmesh } from './checks/acmesh.mjs';
import { checkCaddy } from './checks/caddy.mjs';
import { checkCertbot } from './checks/certbot.mjs';
import { checkHardcoded } from './checks/hardcoded.mjs';
import { checkTraefik } from './checks/traefik.mjs';
import { discoverScripts, judgeSchedulers, scanCron, scanInvocations, scanSystemd } from './scan.mjs';

export const SCHEMA = 1;

export function audit({ root, schedule, scheduleFile, lifetimes = [], version }) {
  const L = schedule ?? loadSchedule(scheduleFile, lifetimes);
  const ctx = new Ctx(null, L);
  ctx.tree = new Tree(root, (p, e) => ctx.note(p, `could not be read: ${e.code ?? e.message}`));

  scanCron(ctx);
  scanSystemd(ctx);
  discoverScripts(ctx);
  checkCertbot(ctx);
  checkAcmesh(ctx);
  checkCaddy(ctx);
  checkTraefik(ctx);
  scanInvocations(ctx);
  checkHardcoded(ctx);
  judgeSchedulers(ctx);

  const findings = sortFindings(ctx.findings);
  const notes = tidyNotes(ctx.notes);
  const count = (s) => findings.filter((f) => f.severity === s).length;
  return {
    tool: 'acme-audit',
    schema: SCHEMA,
    version,
    root,
    schedule: { checked: L.checked, targets: L.targets.map((t) => ({ days: t.days, label: t.label })) },
    summary: { error: count('error'), warn: count('warn'), info: count('info'), total: findings.length },
    findings,
    notes,
    scanned: {
      certbot_lineages: ctx.found.certbot,
      acmesh_domains: ctx.found.acmesh,
      lego_jobs: ctx.found.lego,
      caddyfiles: ctx.found.caddy,
      traefik_configs: ctx.found.traefik,
      timers: ctx.counts.timers,
      cron_files: ctx.counts.cron_files,
      scripts: ctx.counts.scripts,
    },
  };
}

// Unreadable paths come in dozens when run as a normal user. Say it once.
function tidyNotes(notes) {
  const denied = notes.filter((n) => /EACCES|EPERM/.test(n.message));
  const rest = notes.filter((n) => !denied.includes(n));
  if (!denied.length) return rest;
  const shown = denied.slice(0, 4).map((n) => n.file).join(', ');
  const more = denied.length > 4 ? ` and ${denied.length - 4} more` : '';
  return [{ file: denied[0].file, message: `${denied.length} path${denied.length === 1 ? '' : 's'} could not be read (permission denied): ${shown}${more}. Run as root to include them.` }, ...rest];
}

export const nothingFound = (r) => Object.values(r.scanned).every((n) => n === 0);
