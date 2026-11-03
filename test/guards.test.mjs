// The promises in the README that a future change could quietly break.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { repo } from '../test-support/tree.mjs';

const srcFiles = [];
const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else srcFiles.push(p); } };
walk(path.join(repo, 'src'));
walk(path.join(repo, 'bin'));

test('no module can reach the network or start a process', () => {
  const bad = /from ['"]node:(http|https|http2|net|tls|dns|dgram|child_process|worker_threads|cluster)['"]|require\(['"](http|https|net|child_process)['"]\)|\bfetch\(|XMLHttpRequest|WebSocket/;
  assert.deepEqual(srcFiles.filter((f) => bad.test(fs.readFileSync(f, 'utf8'))).map((f) => path.relative(repo, f)), []);
});

test('there are no runtime dependencies', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  for (const f of srcFiles) for (const m of fs.readFileSync(f, 'utf8').matchAll(/from ['"]([^'"]+)['"]/g)) assert.ok(m[1].startsWith('node:') || m[1].startsWith('.'), `${f}: ${m[1]}`);
});

test('data/schedule.json: every source has a URL and a check date, and every cited source exists', () => {
  const s = JSON.parse(fs.readFileSync(path.join(repo, 'data/schedule.json'), 'utf8'));
  for (const [id, src] of Object.entries(s.sources)) {
    assert.match(src.url, /^https:\/\//, id);
    assert.match(src.checked, /^\d{4}-\d{2}-\d{2}$/, id);
    assert.ok(src.says.length > 20, id);
  }
  const cited = new Set();
  const collect = (o) => { if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) { if (k === 'source' && typeof v === 'string') cited.add(v); if (k === 'sources') v.forEach((x) => cited.add(x)); collect(v); } };
  collect({ ...s, sources: undefined });
  for (const id of cited) assert.ok(s.sources[id], `cited source ${id} is not listed`);
  assert.ok(s.targets.length >= 2);
  assert.deepEqual(s.facts.hardcoded_numbers, [83, 80, 60]);
});

test('the thresholds in src are not numbers copied from the schedule', () => {
  // 64, 45, 83, 80 or 60 written as a day count in code would mean the schedule file is not the source.
  const hits = [];
  for (const f of srcFiles.filter((x) => !x.endsWith('demo-tree.mjs') && !x.endsWith('demo.mjs'))) {
    fs.readFileSync(f, 'utf8').split('\n').forEach((line, i) => {
      if (/^\s*(\/\/|\*)/.test(line)) return;
      if (/\b(64|45|83)\b/.test(line.replace(/'[^']*'|"[^"]*"|`[^`]*`/g, ''))) hits.push(`${path.relative(repo, f)}:${i + 1}: ${line.trim()}`);
    });
  }
  assert.deepEqual(hits, []);
});
