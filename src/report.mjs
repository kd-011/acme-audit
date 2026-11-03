const COLOR = { error: '31', warn: '33', info: '36' };
const LABEL = { error: 'ERROR', warn: 'WARN ', info: 'NOTE ' };
const WIDTH = 100;

function wrap(text, indent) {
  const out = [];
  let line = '';
  for (const word of text.split(/\s+/)) {
    if (line && indent.length + line.length + word.length + 1 > WIDTH) { out.push(indent + line); line = word; } else line = line ? `${line} ${word}` : word;
  }
  if (line) out.push(indent + line);
  return out.join('\n');
}

export function renderText(r, { color = false, rootLabel = r.root } = {}) {
  const paint = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const out = [];
  out.push(`acme-audit ${r.version}, root ${rootLabel}`);
  out.push(`Lifetimes checked: ${r.schedule.targets.map((t) => `${t.days} days (${t.label})`).join('; ')}. Schedule data checked ${r.schedule.checked}.`);
  out.push('');
  for (const f of r.findings) {
    out.push(`${paint(COLOR[f.severity], LABEL[f.severity])} ${paint('1', f.kind.padEnd(19))} ${f.file}${f.line ? `:${f.line}` : ''}`);
    out.push(wrap(f.summary, '      '));
    out.push(paint('2', wrap(f.why, '      ')));
    out.push('');
  }
  for (const n of r.notes) out.push(`note: ${n.file}: ${n.message}`);
  if (r.notes.length) out.push('');
  const s = r.summary;
  if (!s.total) {
    const empty = Object.values(r.scanned).every((n) => n === 0);
    out.push(empty ? 'Nothing to audit: no ACME client files found under this root.' : 'No findings.');
  } else {
    out.push(`${s.total} finding${s.total === 1 ? '' : 's'}: ${s.error} error${s.error === 1 ? '' : 's'}, ${s.warn} warning${s.warn === 1 ? '' : 's'}, ${s.info} note${s.info === 1 ? '' : 's'}.`);
  }
  const sc = r.scanned;
  const n = (c, one, many = `${one}s`) => `${c} ${c === 1 ? one : many}`;
  out.push(`Read: ${n(sc.certbot_lineages, 'certbot lineage')}, ${n(sc.acmesh_domains, 'acme.sh domain')}, ${n(sc.lego_jobs, 'lego job')}, ${n(sc.caddyfiles, 'Caddyfile')}, ${n(sc.traefik_configs, 'Traefik config')}, ${n(sc.timers, 'timer')}, ${n(sc.cron_files, 'cron file')}, ${n(sc.scripts, 'script')}.`);
  return out.join('\n') + '\n';
}
