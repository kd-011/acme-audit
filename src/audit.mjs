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
  const count = (s) => findings.filter((f) => f.severity === s).length;
  return {
    tool: 'acme-audit',
    schema: SCHEMA,
    version,
    root,
    schedule: { checked: L.checked, targets: L.targets.map((t) => ({ days: t.days, label: t.label })) },
    summary: { error: count('error'), warn: count('warn'), info: count('info'), total: findings.length },
    findings,
    notes: ctx.notes,
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

export const nothingFound = (r) => Object.values(r.scanned).every((n) => n === 0);
