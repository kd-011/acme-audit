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

  // lstat that follows symlinks inside the root. Returns { path, st } or { path, st: null, dangling: true }.
  resolve(p) {
    let cur = p;
    for (let i = 0; i < 20; i++) {
      let st;
      try { st = fs.lstatSync(this.real(cur)); } catch { return { path: cur, st: null, dangling: i > 0 }; }
      if (!st.isSymbolicLink()) return { path: cur, st, dangling: false };
      let target;
      try { target = fs.readlinkSync(this.real(cur)); } catch { return { path: cur, st: null, dangling: true }; }
      cur = path.isAbsolute(target) ? path.posix.normalize(target) : path.posix.join(path.posix.dirname(cur), target);
    }
    return { path: cur, st: null, dangling: true };
  }

  lstat(p) {
    try { return fs.lstatSync(this.real(p)); } catch { return null; }
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
