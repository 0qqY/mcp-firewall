import { existsSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * A path pattern on canonical, `/`-separated paths. `**` crosses directories, `*` and `?` do not. A pattern
 * also covers everything below what it matches, so `~/projects` allows the whole tree and `**\/.ssh` denies
 * every file inside any `.ssh` directory.
 */
export interface PathPattern {
  source: string;
  match: RegExp;
}

export interface PathConstraint {
  /** Top-level argument names that hold a path (a string or a list of strings). */
  arguments: string[];
  allow: PathPattern[];
  deny: PathPattern[];
  /** Relative argument values resolve against this directory (the server's working directory). */
  base: string;
  platform: NodeJS.Platform;
  /**
   * A hard link is the same file under a second name, which no path spelling reveals: `deny` refuses
   * existing files with more than one name (nlink > 1), `allow` trusts the name.
   */
  hardLinks: 'deny' | 'allow';
}

const GLOB_CHARS = /[*?]/;

function api(platform: NodeJS.Platform): path.PlatformPath {
  return platform === 'win32' ? path.win32 : path.posix;
}

const caseInsensitive = (platform: NodeJS.Platform): boolean => platform === 'win32' || platform === 'darwin';

/** Longest existing prefix through realpath (symlinks, junctions, Windows 8.3 short names), the rest appended. */
function realPrefix(p: string, platform: NodeJS.Platform): string {
  // Touching a UNC path makes Windows connect to that host and offer the user's NTLM credentials.
  if (platform !== process.platform || (platform === 'win32' && p.startsWith('\\\\'))) return p;
  const lib = api(platform);
  let head = p;
  const rest: string[] = [];
  while (!existsSync(head)) {
    const parent = lib.dirname(head);
    if (parent === head) return p;
    rest.unshift(lib.basename(head));
    head = parent;
  }
  try {
    return lib.join(realpathSync.native(head), ...rest);
  } catch {
    return p;
  }
}

/** Absolute, normalized and `/`-separated form of one path string, as the file system will see it. */
function canonical(value: string, base: string, platform: NodeJS.Platform): string {
  const lib = api(platform);
  let p = value;
  if (/^file:/i.test(p)) p = fileURLToPath(p, { windows: platform === 'win32' });
  if (p === '~' || /^~[\\/]/.test(p)) p = homedir() + p.slice(1);
  if (platform === 'win32') {
    // `\\?\C:\...` and `\\?\UNC\...` name ordinary files; other device paths (pipes, volumes) are not files.
    if (/^[\\/]{2}[?.][\\/]/.test(p)) {
      if (/^..[?.][\\/]UNC[\\/]/i.test(p)) p = `\\\\${p.slice(8)}`;
      else if (/^..[?.][\\/][a-z]:[\\/]/i.test(p)) p = p.slice(4);
      else throw new Error('device path');
    }
  }
  p = lib.resolve(base, p);
  if (platform === 'win32') {
    // Windows drops trailing dots and spaces from names, and `name:stream` is a stream of `name`.
    const [root, ...parts] = p.split('\\');
    p = [root, ...parts.map((s) => s.replace(/:.*$/, '').replace(/[. ]+$/, '') || s)].join('\\');
  }
  return realPrefix(p, platform).replace(/\\/g, '/');
}

/**
 * Every reading of a path argument the server might act on: the value itself and its percent-decoded forms.
 * Returns an error string for values that cannot be a safe path.
 */
export function pathForms(value: string, base: string, platform: NodeJS.Platform = process.platform): string[] | string {
  if (/[\u0000-\u001f]/.test(value)) return 'control character in path';
  const variants = [value];
  for (let v = value, i = 0; i < 3; i++) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(v);
    } catch {
      break;
    }
    if (decoded === v) break;
    if (/[\u0000-\u001f]/.test(decoded)) return 'control character in decoded path';
    variants.push(decoded);
    v = decoded;
  }
  try {
    return [...new Set(variants.map((v) => canonical(v, base, platform)))];
  } catch (err) {
    return `not a valid path: ${(err as Error).message}`;
  }
}

function globSource(glob: string): string {
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') {
      const slash = glob[i + 2] === '/';
      out += slash ? '(?:.*/)?' : '.*';
      i += slash ? 2 : 1;
    } else if (c === '*') out += '[^/]*';
    else if (c === '?') out += '[^/]';
    else out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return out;
}

/** Compiles a policy path pattern; its literal prefix is canonicalized like argument values. */
export function compilePathPattern(source: string, baseDir: string, platform: NodeJS.Platform = process.platform): PathPattern {
  let glob = source.replace(/\\/g, '/').replace(/(.)\/+$/, '$1');
  if (!glob.startsWith('**')) {
    const parts = glob.split('/');
    const firstGlob = parts.findIndex((s) => GLOB_CHARS.test(s));
    const literal = firstGlob === -1 ? parts : parts.slice(0, firstGlob);
    const prefix = canonical(literal.join('/') || '/', baseDir, platform);
    glob = [prefix.replace(/\/$/, ''), ...(firstGlob === -1 ? [] : parts.slice(firstGlob))].join('/');
  }
  return { source, match: new RegExp(`^${globSource(glob)}(?:/.*)?$`, caseInsensitive(platform) ? 'i' : '') };
}

/** Checks the path arguments of a call; returns a reason when one is denied. */
export function checkPaths(c: PathConstraint, args: Record<string, unknown>): string | undefined {
  for (const name of c.arguments) {
    const raw = args[name];
    const values = typeof raw === 'string' ? [raw] : Array.isArray(raw) ? raw : raw === undefined ? [] : [raw];
    for (const value of values) {
      if (typeof value !== 'string') return `argument '${name}' is not a path string`;
      const forms = pathForms(value, c.base, c.platform);
      if (typeof forms === 'string') return `argument '${name}': ${forms}`;
      for (const form of forms) {
        const denied = c.deny.find((p) => p.match.test(form));
        if (denied) return `argument '${name}' resolves to '${form}', denied by path '${denied.source}'`;
        if (c.allow.length > 0 && !c.allow.some((p) => p.match.test(form))) {
          return `argument '${name}' resolves to '${form}', outside the allowed paths`;
        }
      }
      if (c.hardLinks === 'deny' && c.platform === process.platform && !forms[0].startsWith('//')) {
        const st = statSync(forms[0], { throwIfNoEntry: false });
        if (st?.isFile() && st.nlink > 1) {
          return `argument '${name}' names a file with ${st.nlink} hard links; its other names may be outside the allowed paths`;
        }
      }
    }
  }
  return undefined;
}
