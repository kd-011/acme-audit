import path from 'node:path';
import { isStaging } from '../ctx.mjs';
import { modeString } from '../fsx.mjs';
import { describeJudgement, judge } from '../window.mjs';

const NAMES = ['traefik.yml', 'traefik.yaml', 'traefik.toml'];
const DIRS = ['/etc/traefik', '/etc', '/usr/local/etc/traefik', '/opt/traefik', '/srv/traefik'];

const node = (key, line, value = null) => ({ key, line, value, children: new Map(), items: [] });
const scalar = (v) => v.replace(/^["']|["']$/g, '');

// The subset of YAML a Traefik static config uses: nested mappings, scalars, "- item" lists.
export function parseYaml(text) {
  const root = node('', 0);
  const stack = [{ indent: -1, node: root }];
  text.split('\n').forEach((raw, i) => {
    const stripped = raw.replace(/\s+#.*$/, '');
    if (!stripped.trim() || stripped.trim().startsWith('#') || stripped.trim() === '---') return;
    const indent = stripped.match(/^ */)[0].length;
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
    const parent = stack[stack.length - 1].node;
    const body = stripped.trim();
    if (body.startsWith('- ')) { parent.items.push(scalar(body.slice(2).trim())); return; }
    const m = body.match(/^("[^"]+"|'[^']+'|[^:]+?):(?:\s+(.*))?$/);
    if (!m) return;
    const key = scalar(m[1]).toLowerCase();
    const val = (m[2] ?? '').trim();
    const n = node(key, i + 1, val === '' || val === '{}' ? null : scalar(val));
    parent.children.set(key, n);
    if (val === '') stack.push({ indent, node: n });
  });
  return root;
}

export function parseToml(text) {
  const root = node('', 0);
  let cur = root;
  text.split('\n').forEach((raw, i) => {
    const l = raw.replace(/\s+#.*$/, '').trim();
    if (!l || l.startsWith('#')) return;
    const table = l.match(/^\[([^\[\]]+)\]$/);
    if (table) {
      cur = root;
      for (const part of table[1].split('.')) {
        const k = scalar(part.trim()).toLowerCase();
        if (!cur.children.has(k)) cur.children.set(k, node(k, i + 1));
        cur = cur.children.get(k);
      }
      return;
    }
    const kv = l.match(/^([^=]+?)\s*=\s*(.*)$/);
    if (kv) { const k = scalar(kv[1].trim()).toLowerCase(); cur.children.set(k, node(k, i + 1, scalar(kv[2].trim()))); }
  });
  return root;
}

const child = (n, ...keys) => keys.reduce((x, k) => x?.children.get(k), n);

// Traefik's own mapping from certificatesDuration to when it starts renewing.
function renewBeforeDays(L, hours) {
  const rows = [...L.clients.traefik.renew_periods].sort((a, b) => b.min_duration_hours - a.min_duration_hours);
  return rows.find((r) => hours >= r.min_duration_hours).renew_before_hours / 24;
}

function configs(ctx) {
  const t = ctx.tree;
  const out = [];
  for (const d of DIRS) for (const n of NAMES) if (t.isFile(`${d}/${n}`)) out.push(`${d}/${n}`);
  return out;
}

export function checkTraefik(ctx) {
  const t = ctx.tree;
  const L = ctx.schedule;
  for (const file of configs(ctx)) {
    const text = t.read(file);
    if (text === null) continue;
    const tree = file.endsWith('.toml') ? parseToml(text) : parseYaml(text);
    const resolvers = child(tree, 'certificatesresolvers');
    if (!resolvers) continue;
    ctx.found.traefik++;
    for (const [rname, r] of resolvers.children) {
      const acme = child(r, 'acme');
      if (!acme) continue;
      const hasChallenge = ['tlschallenge', 'httpchallenge', 'dnschallenge'].some((k) => {
        const c = acme.children.get(k);
        return c && !/^false$/i.test(c.value ?? '');
      });
      if (!hasChallenge) {
        ctx.add({ kind: 'DEAD-AUTH', severity: 'error', client: 'traefik', file, line: acme.line, summary: `resolver ${rname} sets no challenge (tlsChallenge, httpChallenge or dnsChallenge)`, why: 'Traefik cannot prove control of a domain without one, so this resolver cannot obtain or renew a certificate.', detail: { reason: 'no-challenge', resolver: rname } });
      }
      const ca = acme.children.get('caserver');
      if (ca?.value && isStaging(ca.value)) {
        ctx.add({ kind: 'DEAD-AUTH', severity: 'warn', client: 'traefik', file, line: ca.line, summary: `resolver ${rname} uses the Let's Encrypt staging CA`, why: 'Staging certificates are not trusted by browsers. Staging is where the 64-day lifetime is tested first, so it is the wrong place for a live site.', detail: { reason: 'staging', resolver: rname } });
      }
      const dur = acme.children.get('certificatesduration');
      if (dur && /^\d+$/.test(dur.value ?? '')) {
        const hours = Number(dur.value);
        const T = renewBeforeDays(L, hours);
        const j = judge(L, { kind: 'before', days: () => T });
        if (j) ctx.add({ kind: 'RENEW-WINDOW', severity: j.severity, client: 'traefik', file, line: dur.line, summary: `certificatesDuration is ${hours} hours, so Traefik starts renewing ${Math.round(T * 240) / 10} hours before expiry`, why: `${describeJudgement(L, j)} Traefik picks the renewal point from certificatesDuration, not from the certificate it actually received.`, detail: { hours, target_days: j.target.days } });
      }
      const storage = acme.children.get('storage')?.value ?? 'acme.json';
      const candidates = storage.startsWith('/') ? [storage] : [path.posix.join(path.posix.dirname(file), storage), `/${storage}`];
      const found = candidates.find((p) => t.isFile(p));
      if (!found) continue;
      const st = t.stat(found);
      if (st.mode & 0o077) {
        ctx.add({ kind: 'ACMEJSON-PERMS', severity: 'error', client: 'traefik', file: found, summary: `acme.json has mode ${modeString(st)}, Traefik needs 600`, why: 'Traefik refuses to use the file ("permissions are too open, please use 600"), so the resolver cannot load its certificates or store renewed ones.', detail: { mode: modeString(st), resolver: rname, config: file } });
      }
    }
  }
}
