// Read-only view of a machine under a root directory. Every path taken and returned here is
// "in-root": absolute as the machine sees it (/etc/caddy/Caddyfile), never the temp or real prefix.
import fs from 'node:fs';
import path from 'node:path';

const MAX_TEXT = 256 * 1024;

export class Tree {
  constructor(root, onError = () => {}) {
    this.root = path.resolve(root);
    this.onError = onError;
  }

  real(p) {
    return path.join(this.root, p);
  }

  // Walks a path one component at a time and follows every symlink, including the ones in the middle,
  // against the audited root. A link to /etc inside the tree means the tree's /etc, never the host's.
  // Returns { path, st } with the final lstat, or { path, st: null, dangling } when something is missing.
  resolve(p) {
    let hops = 0;
    let parts = p.split('/').filter(Boolean);
    let cur = '/';
    for (let i = 0; i < parts.length; i++) {
      const next = path.posix.join(cur, parts[i]);
      let st;
      try { st = fs.lstatSync(this.real(next)); } catch { return { path: path.posix.join(cur, ...parts.slice(i)), st: null, dangling: hops > 0 }; }
      if (!st.isSymbolicLink()) { cur = next; continue; }
      if (++hops > 20) return { path: next, st: null, dangling: true };
      let target;
      try { target = fs.readlinkSync(this.real(next)); } catch { return { path: next, st: null, dangling: true }; }
      const base = path.isAbsolute(target) ? '/' : cur;
      parts = [...path.posix.join(base, target).split('/').filter(Boolean), ...parts.slice(i + 1)];
      cur = '/';
      i = -1;
    }
    let st = null;
    try { st = fs.lstatSync(this.real(cur)); } catch { /* the root itself is checked by the caller */ }
    return { path: cur, st, dangling: false };
  }

  // lstat of the path itself, following links only in the directories above it.
  lstat(p) {
    const dir = this.resolve(path.posix.dirname(p));
    if (!dir.st) return null;
    try { return fs.lstatSync(this.real(path.posix.join(dir.path, path.posix.basename(p)))); } catch { return null; }
  }

  stat(p) {
    return this.resolve(p).st;
  }

  isFile(p) {
    return this.stat(p)?.isFile() ?? false;
  }

  isDir(p) {
    return this.stat(p)?.isDirectory() ?? false;
  }

  list(p) {
    try {
      return fs.readdirSync(this.real(this.resolve(p).path)).sort();
    } catch (e) {
      if (e.code !== 'ENOENT' && e.code !== 'ENOTDIR') this.onError(p, e);
      return [];
    }
  }

  // Text of a file, or null when it is missing, unreadable, too big or binary.
  read(p) {
    const r = this.resolve(p);
    if (!r.st?.isFile() || r.st.size > MAX_TEXT) return null;
    let buf;
    try { buf = fs.readFileSync(this.real(r.path)); } catch (e) { this.onError(p, e); return null; }
    if (buf.includes(0)) return null;
    return buf.toString('utf8');
  }

  // Immediate children, as in-root paths.
  children(p) {
    return this.list(p).map((n) => path.posix.join(p, n));
  }

  // The root user's directory plus one per user directory under the machine's home tree.
  homes() {
    const out = this.isDir('/root') ? ['/root'] : [];
    const base = path.posix.join('/', 'home');
    for (const n of this.list(base)) if (this.isDir(path.posix.join(base, n))) out.push(path.posix.join(base, n));
    return out;
  }
}

export const isExecutable = (st) => (st.mode & 0o111) !== 0;
export const modeString = (st) => (st.mode & 0o777).toString(8).padStart(3, '0');
