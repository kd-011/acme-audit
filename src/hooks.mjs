// Does a hook command name something that will run? Reads the tree, never runs anything.
import path from 'node:path';
import { isExecutable } from './fsx.mjs';

const PATH_DIRS = ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin'];
const BUILTINS = new Set([':', '.', '[', 'true', 'false', 'echo', 'cd', 'exit', 'export', 'source', 'test', 'exec', 'eval', 'set', 'read', 'printf', 'kill', 'wait', 'umask', 'trap', 'command', 'type']);

export function shellWords(text) {
  return [...text.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)].map((m) => m[1] ?? m[2] ?? m[3]);
}

// The program a hook command starts with, or null when it cannot be told from text alone.
export function hookProgram(command) {
  const words = shellWords(command.trim());
  const w = words.find((x) => !/^[A-Za-z_]\w*=/.test(x));
  if (!w || BUILTINS.has(w) || w.startsWith('$') || w.startsWith('./') || w.startsWith('../') || w.startsWith('~')) return null;
  return w;
}

// 'ok', or { problem: 'missing' | 'not-executable', path }.
export function probe(tree, program) {
  if (program.startsWith('/')) {
    const r = tree.resolve(program);
    if (!r.st) return { problem: 'missing', path: program };
    if (r.st.isDirectory() || !isExecutable(r.st)) return { problem: 'not-executable', path: program };
    return 'ok';
  }
  if (program.includes('/')) return null;
  let nonExec = null;
  for (const d of PATH_DIRS) {
    const p = path.posix.join(d, program);
    const st = tree.stat(p);
    if (st?.isFile()) {
      if (isExecutable(st)) return 'ok';
      nonExec ??= p;
    }
  }
  return nonExec ? { problem: 'not-executable', path: nonExec } : { problem: 'missing', path: program };
}

const WHY = {
  deploy: {
    missing: 'This hook is what reloads the service after a renewal. The new certificate gets written but the service keeps serving the old one until it expires, and shorter lifetimes bring that day closer.',
    'not-executable': 'The hook cannot run, so a renewal writes the new certificate and the service keeps serving the old one until it expires. Shorter lifetimes bring that day closer.',
  },
  pre: {
    missing: 'The hook fails before every renewal. certbot prints the error and tries the renewal anyway, but whatever the hook was there to do is not done.',
    'not-executable': 'The hook fails before every renewal. certbot prints the error and tries the renewal anyway, but whatever the hook was there to do is not done.',
  },
  post: {
    missing: 'The hook fails after every renewal, so whatever it was there to do (restarting a service, for one) is not done.',
    'not-executable': 'The hook fails after every renewal, so whatever it was there to do (restarting a service, for one) is not done.',
  },
  auth: {
    missing: 'The authentication hook is what proves control of the domain. Without it the challenge fails and the certificate is not renewed.',
    'not-executable': 'The authentication hook is what proves control of the domain. It cannot run, so the challenge fails and the certificate is not renewed.',
  },
};

export function checkHook(ctx, { client, file, line = null, field, command, role }) {
  const program = hookProgram(command);
  if (!program) return;
  const res = probe(ctx.tree, program);
  if (res === 'ok' || res === null) return;
  const missing = res.problem === 'missing';
  ctx.add({
    kind: missing ? 'HOOK-MISSING' : 'HOOK-NOT-EXECUTABLE',
    severity: 'error',
    client,
    file,
    line,
    summary: missing ? `${field} runs ${program}, which does not exist on this machine` : `${field} runs ${res.path}, which has no execute bit`,
    why: WHY[role][res.problem],
    detail: { field, command, path: res.path, role },
  });
}

// Files in certbot's renewal-hooks/{pre,deploy,post}. certbot runs only the executable ones.
export function checkHookDir(ctx, dir, role) {
  for (const p of ctx.tree.children(dir)) {
    if (p.endsWith('~')) continue;
    const r = ctx.tree.resolve(p);
    if (r.dangling || (!r.st && ctx.tree.lstat(p))) {
      ctx.add({ kind: 'HOOK-MISSING', severity: 'error', client: 'certbot', file: p, summary: `${path.posix.basename(p)} is a symlink to a file that does not exist`, why: `certbot runs the files in ${dir} as ${role} hooks. This one points nowhere, so the work it was meant to do is not done.`, detail: { field: `renewal-hooks/${role}`, role } });
    } else if (r.st?.isFile() && !isExecutable(r.st)) {
      ctx.add({ kind: 'HOOK-NOT-EXECUTABLE', severity: 'error', client: 'certbot', file: p, summary: `${path.posix.basename(p)} in renewal-hooks/${role} has no execute bit`, why: 'certbot runs only the executable files in this directory and skips the rest, so the work this file does never happens.', detail: { field: `renewal-hooks/${role}`, role } });
    }
  }
}
