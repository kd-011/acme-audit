// Regenerates docs/screenshots/terminal.png from a real `acme-audit demo` run, and
// .github/social-preview.png from the same text. Not part of the package. Needs a Chromium-family
// browser: set BROWSER, or it tries chromium, chromium-browser, google-chrome and brave-browser.
//   node scripts/make-hero.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const heroOut = path.join(root, 'docs/screenshots/terminal.png');
const socialOut = path.join(root, '.github/social-preview.png');

const demo = spawnSync(process.execPath, [path.join(root, 'bin/acme-audit.mjs'), 'demo'], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
if (demo.status !== 1) throw new Error(`demo should exit 1 (it has findings on purpose), got ${demo.status}\n${demo.stderr}`);

// The full output is about 70 lines. Show the header, four findings of different kinds and the summary.
const blocks = demo.stdout.trimEnd().split('\n\n');
const header = blocks[0].split('\n').slice(0, 1).concat(blocks[1].split('\n').slice(0, 2));
const findings = blocks.filter((b) => /^(ERROR|WARN |NOTE )/.test(b));
const KEEP = ['HOOK-MISSING', 'HARDCODED-DAYS', 'TIMER-INFREQUENT', 'ACMEJSON-PERMS'];
const shown = KEEP.map((k) => findings.find((b) => b.split('\n')[0].includes(k)));
const footer = blocks.filter((b) => /^\d+ findings?:/.test(b))[0].split('\n')[0];
const text = [
  '$ acme-audit demo',
  header.slice(1, 3).join('\n'),
  '',
  ...shown.flatMap((b) => [b, '']),
  `(${shown.length} of ${findings.length} findings shown)`,
  footer,
].join('\n');

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
function terminal(lines) {
  let inFinding = false;
  let idx = 0;
  const rows = lines.map((line) => {
    if (/^(ERROR|WARN |NOTE )/.test(line)) { inFinding = true; idx = 0; } else if (!line.trim()) inFinding = false;
    let cls = '';
    if (/^(ERROR|WARN |NOTE )/.test(line)) cls = line.startsWith('ERROR') ? 'err' : line.startsWith('WARN') ? 'warn' : 'note';
    else if (line.startsWith('$')) cls = 'cmd';
    else if (inFinding) { idx++; cls = idx >= 2 ? 'why' : 'sum'; } else if (/^\(/.test(line) || /^\d+ findings/.test(line)) cls = 'foot';
    return `<div class="${cls}">${esc(line) || '&nbsp;'}</div>`;
  });
  return `<div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i></div><main>${rows.join('')}</main>`;
}

const css = (font, lh, pad) => `
body{margin:0;background:#0d1117;color:#d6dbe3;font:${font}px/${lh}px "IBM Plex Mono","DejaVu Sans Mono",monospace;white-space:pre}
.bar{padding:${pad}px ${pad * 1.6}px 0;height:${font + 4}px}.bar i{display:inline-block;width:${font}px;height:${font}px;border-radius:50%;margin-right:${font * 0.7}px}
main{padding:${pad}px ${pad * 1.6}px}.err{color:#ff7b72}.warn{color:#e3b341}.note{color:#79c0ff}.cmd{color:#7ee2a8}.sum{color:#d6dbe3}.why{color:#8b949e}.foot{color:#8b949e}`;

const candidates = [process.env.BROWSER, 'chromium', 'chromium-browser', 'google-chrome', 'brave-browser'].filter(Boolean);
const browser = candidates.find((b) => spawnSync('sh', ['-c', `command -v ${b}`]).status === 0);
if (!browser) throw new Error('no Chromium-family browser found; set BROWSER');

function shoot(html, out, w, h) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aa-hero-'));
  const page = path.join(dir, 'page.html');
  fs.writeFileSync(page, html);
  const r = spawnSync(browser, ['--headless', '--no-sandbox', '--hide-scrollbars', '--force-device-scale-factor=1', `--window-size=${w},${h}`, `--screenshot=${out}`, `file://${page}`], { encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  if (r.status !== 0 || !fs.existsSync(out)) throw new Error(`screenshot failed: ${r.stderr}`);
  console.log(`wrote ${path.relative(root, out)}`);
}

const lines = text.split('\n');
const longest = Math.max(...lines.map((l) => l.length));
{
  const font = 19, lh = 32, pad = 28;
  const w = Math.ceil(longest * font * 0.602 + pad * 3.2 + 40);
  const h = Math.ceil(pad * 2 + font + 4 + lines.length * lh + 40);
  shoot(`<!doctype html><meta charset="utf-8"><style>${css(font, lh, pad)}</style>${terminal(lines)}`, heroOut, w, h);
}

{
  // The social card: title and one line on the left, a smaller terminal excerpt on the right.
  const excerpt = shown[0].split('\n').concat(['']).concat(shown[1].split('\n')).map((l) => (l.length > 58 ? `${l.slice(0, 57)}...` : l));
  const term = terminal(excerpt);
  shoot(`<!doctype html><meta charset="utf-8"><style>
body{margin:0;width:1280px;height:640px;background:#0d1015;color:#eef0f5;font-family:"Fira Sans","DejaVu Sans",sans-serif;position:relative;overflow:hidden;background-image:radial-gradient(circle at 0 100%,#1a2a22 0,#0d1015 45%)}
.accent{position:absolute;left:72px;top:96px;width:64px;height:8px;border-radius:4px;background:#5fd8a0}
h1{position:absolute;left:72px;top:118px;margin:0;font-size:104px;font-weight:700;letter-spacing:-3px}
p{position:absolute;left:72px;top:262px;width:520px;margin:0;font-size:32px;line-height:44px;color:#9aa4b5}
.slug{position:absolute;left:72px;bottom:56px;font:28px "DejaVu Sans Mono",monospace;color:#5fd8a0}
.card{position:absolute;left:624px;top:224px;width:600px;border:1px solid #2a2f3a;border-radius:18px;background:#10141a;overflow:hidden}
${css(11, 17, 12).replace('body{margin:0;background:#0d1117;color:#d6dbe3;', '.card{color:#d6dbe3;').replace(/\bbody\b/, '.card')}
</style><div class="accent"></div><h1>acme-audit</h1>
<p>Read-only lint of your ACME renewal setup, before the certificates get shorter.</p>
<div class="slug">kd-011/acme-audit</div><div class="card">${term}</div>`, socialOut, 1280, 640);
}
