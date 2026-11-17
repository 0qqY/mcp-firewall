import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import spawn from 'cross-spawn';
import { DEFAULT_PROXY_IMAGE, inspectImage, isImageRef, missingHint, noNewPrivileges, SandboxError, unreachableHint, type Runner } from './sandbox.js';

/**
 * `mcp-firewall sandbox build`: makes the image a sandboxed npm MCP server runs in, so nobody has to write a
 * Dockerfile. The package is installed at one exact version with install scripts off; with `network: none`
 * the server cannot fetch anything at run time, so it has to be in the image.
 *
 * Only the top-level version is fixed: transitive dependency ranges and the base image tag are resolved when the
 * image is built. The firewall pins the built image by its content id, so a rebuild that pulls in different code
 * gives a new id and is held at `initialize` like any changed server code.
 */

export const DEFAULT_BUILD_BASE = DEFAULT_PROXY_IMAGE;
/** Debian-based: most Python wheels are built for glibc (manylinux), few for Alpine's musl. */
export const DEFAULT_PYPI_BASE = 'python:3.12-slim';

// npm's own rules: lower case, URL-safe, optional @scope/, at most 214 characters.
const NPM_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
// Exact semver only: no ranges, no dist-tags such as latest.
const EXACT_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export interface NpmPackage {
  /** Absent means npm. */
  ecosystem?: 'npm';
  name: string;
  version: string;
}

export interface PypiPackage {
  ecosystem: 'pypi';
  name: string;
  version: string;
}

export type BuildPackage = NpmPackage | PypiPackage;

const isPypi = (pkg: BuildPackage): pkg is PypiPackage => pkg.ecosystem === 'pypi';

// PEP 508 names (letters, digits, . _ -, starting and ending with a letter or digit).
const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$/;
// PEP 440 release with optional pre/post/dev part; no epoch, no local version, no wildcard.
const PYPI_VERSION = /^\d{1,9}(?:\.\d{1,9}){0,5}(?:(?:a|b|rc)\d{1,9})?(?:\.post\d{1,9})?(?:\.dev\d{1,9})?$/;

/** `pypi:<name>==<version>`: the ecosystem is said, never guessed from the name. */
export function parsePypiSpec(spec: string): PypiPackage {
  const body = spec.slice('pypi:'.length);
  const eq = body.indexOf('==');
  if (eq <= 0) throw new SandboxError(`sandbox build: give the PyPI package with an exact version, e.g. pypi:mcp-server-fetch==2025.4.7 (got ${spec})`);
  const name = body.slice(0, eq);
  const version = body.slice(eq + 2);
  if (!PYPI_NAME.test(name)) throw new SandboxError(`sandbox build: not a valid PyPI package name: ${name}`);
  if (!PYPI_VERSION.test(version)) {
    throw new SandboxError(`sandbox build: the version must be exact (like 2025.4.7), not a range, wildcard or local version: ${version}`);
  }
  return { ecosystem: 'pypi', name, version };
}

/** `name@version` for npm (optionally `npm:` in front), `pypi:name==version` for PyPI. */
export function parseBuildSpec(spec: string): BuildPackage {
  if (spec.startsWith('pypi:')) return parsePypiSpec(spec);
  return parseNpmSpec(spec.startsWith('npm:') ? spec.slice(4) : spec);
}

export const defaultBase = (pkg: BuildPackage): string => (isPypi(pkg) ? DEFAULT_PYPI_BASE : DEFAULT_BUILD_BASE);

/** `name@version` (scoped names keep their leading @); refuses anything but an exact version. */
export function parseNpmSpec(spec: string): NpmPackage {
  const at = spec.lastIndexOf('@');
  if (at <= 0) throw new SandboxError(`sandbox build: give the package with an exact version, e.g. @modelcontextprotocol/server-filesystem@2.2.0 (got ${spec})`);
  const name = spec.slice(0, at);
  const version = spec.slice(at + 1);
  if (name.length > 214 || !NPM_NAME.test(name)) throw new SandboxError(`sandbox build: not a valid npm package name: ${name}`);
  if (!EXACT_VERSION.test(version)) {
    throw new SandboxError(`sandbox build: the version must be exact (like 2.2.0), not a range or tag: ${version}`);
  }
  return { name, version };
}

/**
 * mcp-<name without @, / turned into ->:<version>, e.g. mcp-modelcontextprotocol-server-filesystem:2.2.0; PyPI
 * packages get mcp-pypi-<normalised name>, so an npm and a PyPI package of the same name never share an image.
 */
export function defaultTag(pkg: BuildPackage): string {
  const base = isPypi(pkg) ? `pypi-${pkg.name.toLowerCase().replace(/[._-]+/g, '-')}` : pkg.name.replace(/^@/, '').replace(/\//g, '-');
  const repo = `mcp-${base}`.replace(/[~]/g, '-').replace(/[._-]{2,}/g, '-').replace(/[._-]+$/, '');
  const tag = pkg.version.replace(/\+/g, '_').slice(0, 128);
  const ref = `${repo}:${tag}`;
  if (!isImageRef(ref)) throw new SandboxError(`sandbox build: cannot make an image name from ${specText(pkg)}; pass --tag`);
  return ref;
}

/** The whole Dockerfile. Every value in it has been validated above, so nothing can break out of a line. */
export function npmDockerfile(pkg: NpmPackage, base: string): string {
  return [
    `# made by mcp-firewall sandbox build`,
    `FROM ${base}`,
    `# --ignore-scripts: the package's install scripts do not run while the image is built`,
    `RUN npm install -g --ignore-scripts --no-audit --no-fund ${pkg.name}@${pkg.version} && npm cache clean --force`,
    '',
  ].join('\n');
}

/**
 * PyPI: wheels only (`--only-binary=:all:`). Installing a source distribution runs its build code, which is the
 * PyPI form of an install script; a package without a wheel for the base image fails to build instead.
 */
export function pypiDockerfile(pkg: PypiPackage, base: string): string {
  return [
    `# made by mcp-firewall sandbox build`,
    `FROM ${base}`,
    `# --only-binary=:all: wheels only: no source distribution's build code runs while the image is built`,
    `RUN pip install --no-cache-dir --only-binary=:all: --disable-pip-version-check --root-user-action=ignore ${pkg.name}==${pkg.version}`,
    '',
  ].join('\n');
}

export const dockerfileFor = (pkg: BuildPackage, base: string): string => (isPypi(pkg) ? pypiDockerfile(pkg, base) : npmDockerfile(pkg, base));

export const specText = (pkg: BuildPackage): string => (isPypi(pkg) ? `pypi:${pkg.name}==${pkg.version}` : `${pkg.name}@${pkg.version}`);

export function buildArgs(pkg: BuildPackage, tag: string, contextDir: string): string[] {
  const eco = isPypi(pkg) ? 'pypi' : 'npm';
  return [
    'build',
    '--tag', tag,
    '--label', `org.mcp-firewall.${eco}-package=${pkg.name}`,
    '--label', `org.mcp-firewall.${eco}-version=${pkg.version}`,
    contextDir,
  ];
}

/**
 * Reads the package's executables from inside the built image, in a container as locked down as the sandbox
 * itself (no network, read-only, nobody). The global prefix of the official node images is next to the node binary.
 */
export const BIN_SCRIPT =
  "const p=require('path');const d=p.join(p.dirname(p.dirname(process.execPath)),'lib','node_modules',process.argv[1],'package.json');" +
  "const j=require(d);const b=j.bin;process.stdout.write(JSON.stringify(typeof b==='string'?[j.name.replace(/^@[^/]+\\//,'')]:Object.keys(b||{})))";

/** The distribution's console_scripts entry points, which pip installed as commands on PATH. */
export const PYPI_BIN_SCRIPT =
  "import importlib.metadata as m,json,sys;d=m.distribution(sys.argv[1]);" +
  "sys.stdout.write(json.dumps(sorted(e.name for e in d.entry_points if e.group=='console_scripts')))";

export function binArgs(pkg: BuildPackage, tag: string, executable = 'docker'): string[] {
  const lock = ['run', '--rm', '--pull', 'never', '--network', 'none', '--cap-drop', 'ALL', '--security-opt', noNewPrivileges(executable), '--read-only', '--user', '65534:65534'];
  if (isPypi(pkg)) return [...lock, '--entrypoint', 'python', tag, '-B', '-I', '-c', PYPI_BIN_SCRIPT, pkg.name];
  return [...lock, '--entrypoint', 'node', tag, '-e', BIN_SCRIPT, pkg.name];
}

export type StreamRunner = (command: string, args: string[]) => Promise<number>;

/** docker build takes minutes and prints progress: its output goes to stderr so stdout stays clean. */
const streamRunner: StreamRunner = (command, args) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', process.stderr, process.stderr], windowsHide: true });
    child.on('error', reject);
    child.on('exit', (code) => resolve(code ?? 1));
  });

const syncRunner: Runner = (command, args, timeout) => {
  const r = spawn.sync(command, args, { encoding: 'utf8', timeout, windowsHide: true });
  return { status: r.status, stdout: String(r.stdout ?? ''), stderr: String(r.stderr ?? ''), error: r.error ?? undefined };
};

export interface BuildOptions {
  pkg: BuildPackage;
  tag: string;
  base: string;
  force: boolean;
}

export interface BuildResult {
  id: string;
  bins: string[];
}

export async function buildImage(o: BuildOptions, run: Runner = syncRunner, stream: StreamRunner = streamRunner, executable = 'docker'): Promise<BuildResult> {
  if (!isImageRef(o.base)) throw new SandboxError(`sandbox build: not a valid image reference for --base: ${o.base}`);
  if (!isImageRef(o.tag)) throw new SandboxError(`sandbox build: not a valid image reference for --tag: ${o.tag}`);
  const existing = inspectImage(o.tag, run, executable);
  if (existing.kind === 'no-docker') throw new SandboxError(`sandbox build: ${missingHint(executable)}`);
  if (existing.kind === 'unreachable') throw new SandboxError(`sandbox build: ${unreachableHint(executable)}`);
  if (existing.kind === 'ok' && !o.force) {
    throw new SandboxError(
      `sandbox build: image ${o.tag} already exists (${existing.id.slice(7, 19)}); a rebuild can contain different dependency versions and ` +
        'servers pinned to it would be held as changed code. Pass --force to rebuild, or --tag to build under another name',
    );
  }
  const context = mkdtempSync(join(tmpdir(), 'mcpfw-build-'));
  try {
    // An empty context with only the Dockerfile: nothing from the current folder is sent to Docker.
    writeFileSync(join(context, 'Dockerfile'), dockerfileFor(o.pkg, o.base));
    let code: number;
    try {
      code = await stream(executable, buildArgs(o.pkg, o.tag, context));
    } catch (err) {
      throw new SandboxError(`sandbox build: cannot run ${executable}: ${(err as Error).message}`);
    }
    if (code !== 0) throw new SandboxError(`sandbox build: ${executable} build failed (exit ${code}); see the output above`);
  } finally {
    rmSync(context, { recursive: true, force: true });
  }
  const built = inspectImage(o.tag, run, executable);
  if (built.kind !== 'ok') throw new SandboxError(`sandbox build: the image was built but cannot be inspected: ${built.problem}`);
  let bins: string[] = [];
  const r = run(executable, binArgs(o.pkg, o.tag, executable), 60_000);
  if (!r.error && r.status === 0) {
    try {
      const parsed: unknown = JSON.parse(r.stdout.trim());
      if (Array.isArray(parsed)) bins = parsed.filter((b): b is string => typeof b === 'string' && /^[A-Za-z0-9@._-]{1,214}$/.test(b));
    } catch {
      // Unknown layout (a base image without node's usual global prefix): the caller says so.
    }
  }
  return { id: built.id, bins };
}

/** The first name of this function, from when only npm was supported. */
export const buildNpmImage = buildImage;

/** What to put in the policy and the client config next. */
export function buildSummary(o: BuildOptions, result: BuildResult): string {
  const bin = result.bins[0] ?? '<executable>';
  const lines = [
    `built ${o.tag} (${result.id})`,
    `package ${specText(o.pkg)}, base ${o.base}, ${isPypi(o.pkg) ? 'wheels only (no build code ran)' : 'install scripts off'}`,
    result.bins.length > 0
      ? `executables: ${result.bins.join(', ')}`
      : `executables: could not be read from the image; see the package's ${isPypi(o.pkg) ? 'console_scripts entry points' : '"bin" field'}`,
    '',
    'policy:',
    '  sandbox:',
    '    enabled: true',
    `    image: ${o.tag}`,
    '',
    'try it without starting anything:',
    `  mcp-firewall sandbox show --sandbox ${o.tag} -- ${bin}`,
    '',
    'Only the package version is fixed; dependency versions and the base image were resolved now. The firewall pins',
    'this image by its id, so rebuilding it later shows up as changed server code (approve with mcp-firewall pins approve).',
  ];
  return `${lines.join('\n')}\n`;
}
