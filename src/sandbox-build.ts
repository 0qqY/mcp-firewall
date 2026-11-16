import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import spawn from 'cross-spawn';
import { DEFAULT_PROXY_IMAGE, inspectImage, isImageRef, SandboxError, type Runner } from './sandbox.js';

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

// npm's own rules: lower case, URL-safe, optional @scope/, at most 214 characters.
const NPM_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
// Exact semver only: no ranges, no dist-tags such as latest.
const EXACT_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export interface NpmPackage {
  name: string;
  version: string;
}

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

/** mcp-<name without @, / turned into ->:<version>, e.g. mcp-modelcontextprotocol-server-filesystem:2.2.0. */
export function defaultTag(pkg: NpmPackage): string {
  const repo = `mcp-${pkg.name.replace(/^@/, '').replace(/\//g, '-')}`.replace(/[~]/g, '-').replace(/[._-]{2,}/g, '-').replace(/[._-]+$/, '');
  const tag = pkg.version.replace(/\+/g, '_').slice(0, 128);
  const ref = `${repo}:${tag}`;
  if (!isImageRef(ref)) throw new SandboxError(`sandbox build: cannot make an image name from ${pkg.name}@${pkg.version}; pass --tag`);
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

export function buildArgs(pkg: NpmPackage, tag: string, contextDir: string): string[] {
  return [
    'build',
    '--tag', tag,
    '--label', `org.mcp-firewall.npm-package=${pkg.name}`,
    '--label', `org.mcp-firewall.npm-version=${pkg.version}`,
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

export function binArgs(pkg: NpmPackage, tag: string): string[] {
  return [
    'run', '--rm', '--pull', 'never', '--network', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
    '--read-only', '--user', '65534:65534', '--entrypoint', 'node', tag, '-e', BIN_SCRIPT, pkg.name,
  ];
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
  pkg: NpmPackage;
  tag: string;
  base: string;
  force: boolean;
}

export interface BuildResult {
  id: string;
  bins: string[];
}

export async function buildNpmImage(o: BuildOptions, run: Runner = syncRunner, stream: StreamRunner = streamRunner, executable = 'docker'): Promise<BuildResult> {
  if (!isImageRef(o.base)) throw new SandboxError(`sandbox build: not a valid image reference for --base: ${o.base}`);
  if (!isImageRef(o.tag)) throw new SandboxError(`sandbox build: not a valid image reference for --tag: ${o.tag}`);
  const existing = inspectImage(o.tag, run, executable);
  if (existing.kind === 'no-docker') throw new SandboxError('sandbox build: the docker command was not found; install Docker');
  if (existing.kind === 'unreachable') throw new SandboxError('sandbox build: Docker is installed but not reachable; start Docker Desktop (or the docker service) and try again');
  if (existing.kind === 'ok' && !o.force) {
    throw new SandboxError(
      `sandbox build: image ${o.tag} already exists (${existing.id.slice(7, 19)}); a rebuild can contain different dependency versions and ` +
        'servers pinned to it would be held as changed code. Pass --force to rebuild, or --tag to build under another name',
    );
  }
  const context = mkdtempSync(join(tmpdir(), 'mcpfw-build-'));
  try {
    // An empty context with only the Dockerfile: nothing from the current folder is sent to Docker.
    writeFileSync(join(context, 'Dockerfile'), npmDockerfile(o.pkg, o.base));
    let code: number;
    try {
      code = await stream(executable, buildArgs(o.pkg, o.tag, context));
    } catch (err) {
      throw new SandboxError(`sandbox build: cannot run docker: ${(err as Error).message}`);
    }
    if (code !== 0) throw new SandboxError(`sandbox build: docker build failed (exit ${code}); see the output above`);
  } finally {
    rmSync(context, { recursive: true, force: true });
  }
  const built = inspectImage(o.tag, run, executable);
  if (built.kind !== 'ok') throw new SandboxError(`sandbox build: the image was built but cannot be inspected: ${built.problem}`);
  let bins: string[] = [];
  const r = run(executable, binArgs(o.pkg, o.tag), 60_000);
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

/** What to put in the policy and the client config next. */
export function buildSummary(o: BuildOptions, result: BuildResult): string {
  const bin = result.bins[0] ?? '<executable>';
  const lines = [
    `built ${o.tag} (${result.id})`,
    `package ${o.pkg.name}@${o.pkg.version}, base ${o.base}, install scripts off`,
    result.bins.length > 0
      ? `executables: ${result.bins.join(', ')}`
      : 'executables: could not be read from the image; see the package\'s "bin" field',
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
