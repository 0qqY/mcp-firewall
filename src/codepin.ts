import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, extname, join, relative, resolve } from 'node:path';

/**
 * Fingerprints the code of the MCP server the firewall launches, so a silently updated package
 * (the postmark-mcp case: same tool definitions, one malicious line in the code) is caught before
 * the server is used. Tool pinning cannot see that change; only the code can.
 */

/** Launchers that download and run an npm package by name. */
const PACKAGE_RUNNERS = new Set(['npx', 'bunx', 'pnpx']);
/** Directories that are dependencies, caches or VCS data rather than the server's own code. */
const SKIP_DIRS = new Set(['node_modules', '.git', '__pycache__', '.venv', 'venv', '.mypy_cache', '.pytest_cache']);
const SCRIPT_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.py']);
const MAX_FILES = 20_000;
const MAX_BYTES = 256 * 1024 * 1024;

export interface PackageSpec {
  name: string;
  version?: string;
}

/** Where to look for installed packages; defaults are the tools' own default locations. */
export interface InstallLocations {
  npmCache?: string;
  /** Directories whose children are Python virtual environments (uv/pipx caches and tool dirs). */
  pythonEnvParents?: string[];
}

export interface CodeFingerprint {
  /** sha256 over every file path and content; undefined when no code could be located. */
  hash?: string;
  /** Directories that were hashed (whole, or the files of one installed distribution). */
  roots: string[];
  /** Package names and versions found, for the audit log. */
  packages: string[];
  /** Why parts of the server could not be fingerprinted, or warnings such as unpinned versions. */
  notes: string[];
}

/** A set of files to hash: everything under `base`, or only `files` (paths relative to `base`). */
interface Source {
  base: string;
  files?: string[];
  label?: string;
}

/** Splits an npm spec such as `@scope/pkg@1.2.3` or `pkg@latest` into name and version. */
export function parseSpec(spec: string): PackageSpec {
  const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
  return at === -1 ? { name: spec } : { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

/** Splits a Python requirement such as `mcp-server-git==0.6.2`, `pkg@1.0` or `pkg[extra]>=2` into name and version. */
export function parsePythonSpec(spec: string): PackageSpec {
  const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:(?:==|@)\s*([^\s;,]+)|(.+))?$/.exec(spec);
  if (!m) return { name: spec };
  return { name: m[1], version: m[2] ?? (m[3]?.trim() || undefined) };
}

export const isExactVersion = (version: string | undefined): boolean => !!version && /^\d+(?:\.\d+)*(?:[-+.]?[\w.]+)?$/.test(version);

/** PEP 503 normalisation, so `MCP_Server.Git` and `mcp-server-git` compare equal. */
const normalizeDist = (name: string): string => name.toLowerCase().replace(/[-_.]+/g, '-');

const exeName = (command: string): string => basename(command).replace(/\.(cmd|exe|ps1|bat)$/i, '').toLowerCase();

/** The packages an `npx`-style command line runs (`--package` values, or the first positional argument). */
export function runnerPackages(command: string, args: string[]): PackageSpec[] | undefined {
  const exe = exeName(command);
  let rest: string[];
  if (PACKAGE_RUNNERS.has(exe)) rest = args;
  else if (exe === 'npm' && args[0] === 'exec') rest = args.slice(1);
  else if (exe === 'pnpm' && args[0] === 'dlx') rest = args.slice(1);
  else return undefined;

  const explicit: string[] = [];
  let positional: string | undefined;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--') {
      positional ??= rest[i + 1];
      break;
    }
    if (a === '-p' || a === '--package') explicit.push(rest[++i] ?? '');
    else if (a.startsWith('--package=')) explicit.push(a.slice('--package='.length));
    else if (!a.startsWith('-')) {
      positional = a;
      break;
    }
  }
  const specs = explicit.length > 0 ? explicit : positional ? [positional] : [];
  return specs.filter(Boolean).map(parseSpec);
}

/** uv/pipx options that take a value, so the value is not mistaken for the package. */
const PY_VALUE_OPTIONS = new Set([
  '--from', '--spec', '--with', '-w', '--with-requirements', '--with-editable', '--python', '-p', '--index', '--index-url',
  '--default-index', '--extra-index-url', '-i', '--find-links', '-f', '--constraint', '-c', '--override', '--directory',
  '--project', '--cache-dir', '--config-file', '--env-file', '--pip-args', '--index-strategy', '--keyring-provider',
  '--resolution', '--prerelease', '--exclude-newer', '--link-mode', '--refresh-package', '--reinstall-package',
  '--upgrade-package', '-P', '--color',
]);

/** The package a `uvx` / `uv tool run` / `pipx run` command line runs (`--from`/`--spec`, else the command). */
export function pythonRunnerPackage(command: string, args: string[]): PackageSpec | undefined {
  const exe = exeName(command);
  let rest: string[];
  if (exe === 'uvx') rest = args;
  else if (exe === 'uv' && args[0] === 'tool' && args[1] === 'run') rest = args.slice(2);
  else if (exe === 'uv' && args[0] === 'x') rest = args.slice(1);
  else if (exe === 'pipx' && args[0] === 'run') rest = args.slice(1);
  else return undefined;

  let from: string | undefined;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const eq = a.indexOf('=');
    const opt = a.startsWith('--') && eq !== -1 ? a.slice(0, eq) : a;
    const inline = opt !== a ? a.slice(eq + 1) : undefined;
    if (opt === '--from' || opt === '--spec') {
      from = inline ?? rest[++i];
    } else if (PY_VALUE_OPTIONS.has(opt)) {
      if (inline === undefined) i++;
    } else if (a === '--') {
      const target = rest[i + 1];
      return target ? parsePythonSpec(from ?? target) : undefined;
    } else if (!a.startsWith('-')) {
      return parsePythonSpec(from ?? a);
    }
  }
  return from ? parsePythonSpec(from) : undefined;
}

function npmCacheDir(): string {
  if (process.env.npm_config_cache) return process.env.npm_config_cache;
  if (process.platform === 'win32' && process.env.LOCALAPPDATA) return join(process.env.LOCALAPPDATA, 'npm-cache');
  return join(homedir(), '.npm');
}

/** Default parents of uv and pipx environments: uvx's cache, `uv tool` installs, pipx venvs and its run cache. */
function defaultPythonEnvParents(): string[] {
  const home = homedir();
  const env = process.env;
  const win = process.platform === 'win32';
  const local = env.LOCALAPPDATA ?? join(home, 'AppData', 'Local');
  const roaming = env.APPDATA ?? join(home, 'AppData', 'Roaming');
  const xdgCache = env.XDG_CACHE_HOME ?? join(home, '.cache');
  const xdgData = env.XDG_DATA_HOME ?? join(home, '.local', 'share');

  const uvCache = env.UV_CACHE_DIR ?? (win ? join(local, 'uv', 'cache') : join(xdgCache, 'uv'));
  const uvTools = env.UV_TOOL_DIR ?? (win ? join(roaming, 'uv', 'data', 'tools') : join(xdgData, 'uv', 'tools'));
  const pipxHomes = env.PIPX_HOME
    ? [env.PIPX_HOME]
    : [join(home, '.local', 'pipx'), win ? join(local, 'pipx', 'pipx') : process.platform === 'darwin' ? join(home, 'Library', 'Application Support', 'pipx') : join(xdgData, 'pipx')];
  const pipxCaches = win ? [join(local, 'pipx', 'pipx', 'Cache')] : [join(xdgCache, 'pipx')];

  return [
    ...['archive-v0', 'environments-v1', 'environments-v2'].map((b) => join(uvCache, b)),
    uvTools,
    ...pipxHomes.flatMap((h) => [join(h, 'venvs'), join(h, '.cache')]),
    ...pipxCaches,
  ];
}

/**
 * Where npx installed a package: `<npm cache>/_npx/<hash>/node_modules/<name>`. When several npx
 * installs hold the package, the most recently written one is the one that just ran.
 */
export function findNpxInstall(name: string, cacheDir = npmCacheDir()): string | undefined {
  const root = join(cacheDir, '_npx');
  if (!existsSync(root)) return undefined;
  let best: { dir: string; mtime: number } | undefined;
  for (const entry of readdirSync(root)) {
    const dir = join(root, entry, 'node_modules', ...name.split('/'));
    const manifest = join(dir, 'package.json');
    if (!existsSync(manifest)) continue;
    const mtime = statSync(manifest).mtimeMs;
    if (!best || mtime > best.mtime) best = { dir, mtime };
  }
  return best?.dir;
}

/** `site-packages` directories of a virtual environment (Windows and POSIX layouts). */
function sitePackages(venv: string): string[] {
  const out = [join(venv, 'Lib', 'site-packages')];
  const lib = join(venv, 'lib');
  if (existsSync(lib)) for (const py of readdirSync(lib)) if (py.startsWith('python')) out.push(join(lib, py, 'site-packages'));
  return out.filter((p) => existsSync(p));
}

export interface PythonInstall {
  sitePackages: string;
  /** Files of the distribution, relative to `sitePackages`, as listed in its RECORD. */
  files: string[];
  version: string;
}

/**
 * Finds an installed Python distribution in uv/pipx environments and lists its files from the
 * wheel RECORD, so only that package is hashed (not its dependencies or the interpreter). When
 * several environments hold it, the most recently installed one is the one that just ran.
 */
export function findPythonInstall(name: string, envParents = defaultPythonEnvParents()): PythonInstall | undefined {
  const wanted = normalizeDist(name);
  let best: (PythonInstall & { mtime: number }) | undefined;
  for (const parent of envParents) {
    if (!existsSync(parent)) continue;
    for (const env of readdirSync(parent)) {
      for (const site of sitePackages(join(parent, env))) {
        for (const entry of readdirSync(site)) {
          const m = /^(.+?)-([^-]+)\.dist-info$/.exec(entry);
          if (!m || normalizeDist(m[1]) !== wanted) continue;
          const record = join(site, entry, 'RECORD');
          if (!existsSync(record)) continue;
          const mtime = statSync(record).mtimeMs;
          if (best && mtime <= best.mtime) continue;
          best = { sitePackages: site, files: recordFiles(readFileSync(record, 'utf8')), version: m[2], mtime };
        }
      }
    }
  }
  if (!best) return undefined;
  const { mtime: _mtime, ...install } = best;
  return install;
}

/** Paths from a wheel RECORD (CSV), minus byte-code and files installed outside site-packages (launchers). */
function recordFiles(record: string): string[] {
  return record
    .split(/\r?\n/)
    .map((line) => (line.startsWith('"') ? line.slice(1, line.indexOf('"', 1)) : line.split(',')[0]))
    .filter((p) => p && !p.startsWith('..') && !p.startsWith('/') && !/__pycache__|\.pyc$/.test(p))
    .sort();
}

/** Nearest ancestor holding a package manifest, so a script is pinned together with the rest of its package. */
function packageRoot(file: string): string {
  let dir = dirname(file);
  for (let depth = 0; depth < 8; depth++) {
    if (['package.json', 'pyproject.toml', 'setup.py'].some((m) => existsSync(join(dir, m)))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return file;
}

/** Local scripts named on the command line. */
function localRoots(command: string, args: string[], cwd: string): string[] {
  const roots: string[] = [];
  for (const candidate of [command, ...args]) {
    if (candidate.startsWith('-')) continue;
    const path = resolve(cwd, candidate);
    if (!existsSync(path)) continue;
    const stat = statSync(path);
    if (stat.isFile() && SCRIPT_EXT.has(extname(path).toLowerCase())) roots.push(packageRoot(path));
  }
  return roots;
}

function packageLabel(root: string): string | undefined {
  try {
    const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { name?: string; version?: string };
    return manifest.name ? `${manifest.name}@${manifest.version ?? '?'}` : undefined;
  } catch {
    return undefined;
  }
}

/** Hashes every file of every source (sorted, paths included), skipping dependency and cache directories. */
function hashSources(sources: Source[], notes: string[]): string {
  const hash = createHash('sha256');
  let files = 0;
  let bytes = 0;
  const add = (path: string, base: string): boolean => {
    const stat = statSync(path);
    if (++files > MAX_FILES || (bytes += stat.size) > MAX_BYTES) {
      notes.push(`code fingerprint stopped after ${MAX_FILES} files or ${MAX_BYTES >> 20} MB`);
      return false;
    }
    hash.update(`${relative(base, path).replaceAll('\\', '/')}\0`);
    hash.update(readFileSync(path));
    hash.update('\0');
    return true;
  };
  const visit = (path: string, base: string): boolean => {
    const stat = statSync(path);
    if (stat.isDirectory()) {
      for (const entry of readdirSync(path).sort()) {
        if (SKIP_DIRS.has(entry)) continue;
        if (!visit(join(path, entry), base)) return false;
      }
      return true;
    }
    return stat.isFile() ? add(path, base) : true;
  };
  for (const source of [...sources].sort((a, b) => (a.base < b.base ? -1 : 1))) {
    hash.update(`root:${source.label ?? basename(source.base)}\0`);
    if (source.files) {
      for (const file of source.files) {
        const path = join(source.base, file);
        if (!existsSync(path)) {
          hash.update(`missing:${file}\0`);
          continue;
        }
        if (!add(path, source.base)) return hash.digest('hex');
      }
    } else if (!visit(source.base, statSync(source.base).isDirectory() ? source.base : dirname(source.base))) {
      break;
    }
  }
  return hash.digest('hex');
}

/**
 * Locates and hashes the server's code: packages run by npx or uvx/pipx, local scripts, and any
 * `extra` paths. Python packages are hashed file by file from their RECORD.
 */
export function fingerprintServer(command: string, args: string[], extra: string[] = [], cwd = process.cwd(), where: InstallLocations = {}): CodeFingerprint {
  const notes: string[] = [];
  const packages: string[] = [];
  const sources: Source[] = extra
    .map((p) => resolve(cwd, p))
    .filter((p) => {
      if (existsSync(p)) return true;
      notes.push(`code path not found: ${p}`);
      return false;
    })
    .map((base) => ({ base }));
  const unpinned = (spec: PackageSpec) => {
    if (!isExactVersion(spec.version)) notes.push(`package ${spec.name} is not pinned to an exact version (${spec.version ?? 'latest'}); updates install without review`);
  };

  for (const spec of runnerPackages(command, args) ?? []) {
    unpinned(spec);
    const dir = findNpxInstall(spec.name, where.npmCache);
    if (dir) sources.push({ base: dir });
    else notes.push(`installed files of ${spec.name} not found in the npx cache`);
  }

  const py = pythonRunnerPackage(command, args);
  if (py) {
    unpinned(py);
    const install = findPythonInstall(py.name, where.pythonEnvParents);
    if (install) {
      const label = `${normalizeDist(py.name)}==${install.version}`;
      sources.push({ base: install.sitePackages, files: install.files, label });
      packages.push(label);
    } else {
      notes.push(`installed files of ${py.name} not found in uv or pipx environments; pass --code <path> to pin it`);
    }
  }

  for (const root of localRoots(command, args, cwd)) sources.push({ base: root });

  const unique = sources.filter((s, i) => sources.findIndex((t) => t.base === s.base && t.label === s.label) === i);
  if (unique.length === 0) {
    if (!py) notes.push('server code could not be located; pass --code <path> to pin it');
    return { roots: [], packages, notes };
  }
  for (const s of unique) {
    const label = s.files ? undefined : packageLabel(s.base);
    if (label) packages.push(label);
  }
  return { hash: hashSources(unique, notes), roots: unique.map((s) => s.base), packages, notes };
}
