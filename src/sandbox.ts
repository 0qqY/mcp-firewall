import { createHash, randomBytes } from 'node:crypto';
import { existsSync, realpathSync } from 'node:fs';
import { posix, win32 } from 'node:path';
import { fileURLToPath } from 'node:url';
import spawn from 'cross-spawn';
import type { CodeFingerprint } from './codepin.js';
import { EGRESS_PORT, type EgressRule } from './egress.js';

/**
 * Runs the wrapped MCP server inside a locked-down Docker container instead of directly on the host.
 *
 * The firewall sees only the JSON-RPC stream. Everything else the server process does (files it reads,
 * hosts it connects to, programs it starts) is invisible to it, so the server runs with no network,
 * a read-only root filesystem, no Linux capabilities, a non-root user and resource limits unless the
 * policy opens something up. Nothing here is a hardened VM boundary: it is Docker's own isolation.
 */

export class SandboxError extends Error {}

export interface SandboxMount {
  /** Absolute host path. */
  source: string;
  /** Absolute path inside the container. */
  target: string;
  readOnly: boolean;
}

/** `sandbox.egress`: the server may reach only these destinations, through the firewall's own proxy. */
export interface SandboxEgress {
  /** The allowlist as written in the policy (`host[:port]`, `*.domain[:port]`). */
  allow: string[];
  rules: EgressRule[];
  /** Image with `node` in it that runs the proxy (the firewall's own code, mounted read-only). */
  proxyImage: string;
}

export type ContainerRuntime = 'docker' | 'podman';

export interface SandboxConfig {
  enabled: boolean;
  /** The container CLI: `docker` (default) or `podman`; both take the same command lines here. */
  runtime: ContainerRuntime;
  /** The image the server runs in; it must contain the server's command. */
  image: string;
  /** never: use only local images | missing: pull when absent | always: pull on every start. */
  pull: 'never' | 'missing' | 'always';
  /** `none` (default), `bridge` (Docker's default network: full outbound access) or an existing user-defined network. */
  network: string;
  /** Read-only root filesystem; /tmp stays writable (in memory). */
  readOnly: boolean;
  tmpfsSize: string;
  /** Numeric `uid[:gid]`. */
  user: string;
  memory: string;
  cpus: number;
  pidsLimit: number;
  mounts: SandboxMount[];
  /** Names of host environment variables handed to the server; nothing else is inherited. */
  env: string[];
  workdir?: string;
  /** Mounts may neither sit inside these nor contain them: credentials and the firewall's own state. */
  protectedPaths: string[];
  /** Mounts may not contain these (a sub-folder is fine): the home directory and the policy's own folder. */
  protectedRoots: string[];
  /** When set, `network` is `none` and the server instead sits on an internal network whose only exit is the proxy. */
  egress?: SandboxEgress;
}

export const SANDBOX_DEFAULTS = {
  runtime: 'docker',
  pull: 'never',
  network: 'none',
  readOnly: true,
  tmpfsSize: '64m',
  user: '65534:65534',
  memory: '512m',
  cpus: 1,
  pidsLimit: 256,
} as const;

/** `[registry[:port]/]name[/name]...[:tag][@sha256:digest]`, lower-case name as Docker requires. */
const NAME_PART = '[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*';
const IMAGE_REF = new RegExp(
  `^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::\\d{1,5})?/)?${NAME_PART}(?:/${NAME_PART})*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`,
);

export const isImageRef = (v: string): boolean => v.length <= 255 && IMAGE_REF.test(v);
/** `none`, `bridge` or the name of a user-defined network; `host` and `container:` joins would undo the isolation. */
export const isNetworkName = (v: string): boolean => /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/.test(v) && v !== 'host';
/** Docker size: digits with an optional b, k, m or g. */
export const isSize = (v: string): boolean => /^[1-9]\d{0,9}[bkmg]?$/.test(v);
export const isUser = (v: string): boolean => /^\d{1,10}(?::\d{1,10})?$/.test(v);
/** Variables the sandbox sets itself. */
export const PROXY_ENV = ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy'];
export const RESERVED_ENV = new Set(['HOME', 'PATH']);
/** Set by the sandbox when `egress` is on, so they cannot be passed through then. */
export const EGRESS_RESERVED_ENV = new Set([...PROXY_ENV, 'NODE_USE_ENV_PROXY']);
export const DEFAULT_PROXY_IMAGE = 'node:22-alpine';

/**
 * Podman refuses a short name such as `node:22-alpine` without a terminal when more than one registry could hold it
 * (short-name-mode enforcing), so the images the firewall picks itself are written out in full for it.
 */
export const qualifyDefaultImage = (image: string, runtime: ContainerRuntime): string =>
  runtime === 'podman' && !image.includes('/') ? `docker.io/library/${image}` : image;

/** Podman documents the bare form; Docker takes both. Docker's command line is left as it was. */
const noNewPrivileges = (runtime: string): string => (runtime === 'podman' ? 'no-new-privileges' : 'no-new-privileges:true');

const runtimeName = (executable: string): string => (/podman/i.test(executable) ? 'Podman' : 'Docker');

/** What to do when the runtime is installed but cannot be reached. */
export function unreachableHint(executable: string): string {
  return runtimeName(executable) === 'Podman'
    ? 'Podman is installed but not reachable; start it (podman machine start on Windows and macOS) and try again'
    : 'Docker is installed but not reachable; start Docker Desktop (or the docker service) and try again';
}

export function missingHint(executable: string): string {
  return `the ${executable} command was not found; install ${runtimeName(executable)}`;
}
export const isEnvName = (v: string): boolean => /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(v);
/**
 * Characters that break the `--mount` option syntax: Docker reads it as one CSV record, so a comma starts a new
 * field, a quote opens a quoted one and a line break ends the record (dropping a trailing `,readonly`).
 */
export const hasMountBreaker = (v: string): boolean => /[\x00-\x1f\x7f,"]/.test(v);
/** An absolute path inside the container, free of anything that breaks the `--mount` option syntax. */
export const isContainerPath = (v: string): boolean => v.startsWith('/') && !hasMountBreaker(v) && !v.includes('\\');

/** Folders under the home directory that hold credentials or the firewall's own files. */
export function defaultProtectedPaths(home: string, platform: NodeJS.Platform = process.platform): string[] {
  const p = platform === 'win32' ? win32 : posix;
  return ['.ssh', '.aws', '.gnupg', '.docker', '.kube', '.azure', p.join('.config', 'gcloud'), '.mcp-firewall', '.claude', '.claude.json', '.npmrc', '.pypirc', '.netrc', '.git-credentials'].map((rel) =>
    p.join(home, rel),
  );
}

/**
 * Why `source` must not be mounted into the server's container, or undefined when it may be. Absolute
 * paths only. Case is ignored on Windows and macOS.
 */
export function mountProblem(source: string, guard: Pick<SandboxConfig, 'protectedPaths' | 'protectedRoots'>, platform: NodeJS.Platform = process.platform): string | undefined {
  const p = platform === 'win32' ? win32 : posix;
  const fold = platform === 'win32' || platform === 'darwin';
  const norm = (v: string) => {
    const r = p.resolve(v);
    return fold ? r.toLowerCase() : r;
  };
  const inside = (child: string, parent: string) => {
    const rel = p.relative(parent, child);
    return rel === '' || (rel !== '..' && !rel.startsWith(`..${p.sep}`) && !p.isAbsolute(rel));
  };
  const abs = norm(source);
  if (p.dirname(abs) === abs) return 'the root of a drive or of the filesystem cannot be mounted';
  if (/docker[._-]?sock|docker_engine|dockerdesktoplinuxengine/.test(abs) || /^(\\\\|\/\/)[.?][\\/]pipe[\\/]/i.test(source)) {
    return 'the Docker socket would hand the server control of the host';
  }
  for (const guarded of guard.protectedPaths) {
    const g = norm(guarded);
    if (inside(abs, g)) return `it is inside ${guarded}, which holds credentials or the firewall's own files`;
    if (inside(g, abs)) return `it contains ${guarded}, which holds credentials or the firewall's own files; mount a narrower folder`;
  }
  for (const root of guard.protectedRoots) {
    if (inside(norm(root), abs)) return `it contains ${root}; mount a sub-folder instead`;
  }
  return undefined;
}

export interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}
export type Runner = (command: string, args: string[], timeoutMs: number) => RunResult;

const defaultRunner: Runner = (command, args, timeout) => {
  const r = spawn.sync(command, args, { encoding: 'utf8', timeout, windowsHide: true });
  return { status: r.status, stdout: String(r.stdout ?? ''), stderr: String(r.stderr ?? ''), error: r.error ?? undefined };
};

export interface SandboxLaunch {
  /** The container runtime's command line: what the firewall spawns in place of the server. */
  command: string;
  args: string[];
  /** Container name, so it can be stopped when the firewall ends. */
  container: string;
  /** With `sandbox.egress`: the internal network and the proxy that must be up before the server starts. */
  egress?: EgressLaunch;
}

export interface EgressLaunch {
  /** Internal network (no route out) shared by the server and the proxy. */
  network: string;
  /** `docker run` of the proxy; it starts on `bridge` and is then connected to `network`. */
  proxy: { command: string; args: string[]; container: string };
}

export interface LaunchOptions {
  /** Names the container; the audit log's server id. */
  serverId: string;
  /** Source of the variables listed in `sandbox.env`. */
  env?: NodeJS.ProcessEnv;
  random?: () => string;
  platform?: NodeJS.Platform;
  exists?: (path: string) => boolean;
  realpath?: (path: string) => string;
  executable?: string;
  /** Compiled proxy files to mount; defaults to the ones next to this module. */
  egressFiles?: { main: string; lib: string };
}

function containerName(serverId: string, random: () => string): string {
  const slug = serverId.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+/, '').slice(0, 24).replace(/-+$/, '') || 'server';
  return `mcp-fw-${slug}-${random()}`;
}

/**
 * The `docker run` command line that runs `server` (a command that exists inside the image) in the
 * sandbox. Values reach the container only through the options built here: there is no way to add
 * raw docker flags, so a policy cannot ask for `--privileged` or `--network host` by accident.
 */
export function buildSandboxCommand(cfg: SandboxConfig, server: { command: string; args: string[] }, options: LaunchOptions): SandboxLaunch {
  if (!cfg.enabled || !cfg.image) throw new SandboxError('sandbox: not enabled or no image set');
  if (!server.command) throw new SandboxError('sandbox: no server command to run inside the image');
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const exists = options.exists ?? existsSync;
  const realpath = options.realpath ?? realpathSync;
  const container = containerName(options.serverId, options.random ?? (() => randomBytes(3).toString('hex')));

  const egress = cfg.egress ? buildEgress(cfg, cfg.egress, container, options) : undefined;
  const args = [
    'run', '--rm', '-i', '--init',
    '--name', container,
    '--label', 'mcp-firewall=1',
    '--pull', cfg.pull,
    '--network', egress?.network ?? cfg.network,
    '--cap-drop', 'ALL',
    '--security-opt', noNewPrivileges(options.executable ?? cfg.runtime),
    '--pids-limit', String(cfg.pidsLimit),
    '--memory', cfg.memory,
    '--memory-swap', cfg.memory,
    '--cpus', String(cfg.cpus),
    '--user', cfg.user,
  ];
  if (cfg.readOnly) args.push('--read-only');
  args.push('--tmpfs', `/tmp:rw,nosuid,size=${cfg.tmpfsSize}`, '-e', 'HOME=/tmp');
  for (const name of cfg.env) {
    // `-e NAME` makes docker read the value from its own environment, so secrets stay off the command line.
    if (env[name] === undefined) throw new SandboxError(`sandbox.env: environment variable ${name} is not set`);
    args.push('-e', name);
  }
  if (egress) {
    // Advisory only: the internal network is what stops a server that ignores these.
    const url = `http://${egress.proxy.container}:${EGRESS_PORT}`;
    for (const name of PROXY_ENV.slice(0, 4)) args.push('-e', `${name}=${url}`);
    args.push('-e', 'NODE_USE_ENV_PROXY=1');
  }
  for (const mount of cfg.mounts) {
    if (!exists(mount.source)) throw new SandboxError(`sandbox.mounts: ${mount.source} does not exist`);
    const real = realpath(mount.source);
    // Checked again on the real path, so a symlink cannot lead into a protected folder.
    const problem = mountProblem(real, cfg, platform);
    if (problem) throw new SandboxError(`sandbox.mounts: ${mount.source}${real === mount.source ? '' : ` (resolves to ${real})`} cannot be mounted: ${problem}`);
    if (hasMountBreaker(real)) throw new SandboxError(`sandbox.mounts: ${real} contains a comma, quote or control character, which the mount option cannot carry`);
    args.push('--mount', `type=bind,source=${real},target=${mount.target}${mount.readOnly ? ',readonly' : ''}`);
  }
  if (cfg.workdir) args.push('-w', cfg.workdir);
  // --entrypoint makes the command after "--" the program that runs, whatever the image's own entrypoint is.
  args.push('--entrypoint', server.command, cfg.image, ...server.args);
  return { command: options.executable ?? cfg.runtime, args, container, egress };
}

function defaultEgressFiles(): { main: string; lib: string } {
  return { main: fileURLToPath(new URL('./egress-main.js', import.meta.url)), lib: fileURLToPath(new URL('./egress.js', import.meta.url)) };
}

/** The proxy container: as locked down as the server's, with only the firewall's two proxy files mounted. */
function buildEgress(cfg: SandboxConfig, egress: SandboxEgress, container: string, options: LaunchOptions): EgressLaunch {
  const files = options.egressFiles ?? defaultEgressFiles();
  for (const f of [files.main, files.lib]) {
    if (hasMountBreaker(f)) throw new SandboxError(`sandbox.egress: the firewall is installed under a path with a comma, quote or control character (${f}), which the mount option cannot carry`);
  }
  const proxy = `${container}-egress`;
  const args = [
    'run', '--rm', '-i', '--init',
    '--name', proxy,
    '--label', 'mcp-firewall=1',
    '--pull', cfg.pull,
    '--network', 'bridge',
    '--cap-drop', 'ALL',
    '--security-opt', noNewPrivileges(options.executable ?? cfg.runtime),
    '--pids-limit', '64',
    '--memory', '128m',
    '--memory-swap', '128m',
    '--cpus', '0.5',
    '--user', '65534:65534',
    '--read-only',
    '-e', `MCP_FW_EGRESS=${egress.allow.join(',')}`,
    '--mount', `type=bind,source=${files.main},target=/fw/egress-main.js,readonly`,
    '--mount', `type=bind,source=${files.lib},target=/fw/egress.js,readonly`,
    '--entrypoint', 'node',
    egress.proxyImage, '/fw/egress-main.js',
  ];
  return { network: `${container}-net`, proxy: { command: options.executable ?? cfg.runtime, args, container: proxy } };
}

const firstLine = (r: RunResult): string => (r.error?.message ?? r.stderr).trim().split('\n')[0];

/**
 * Removes internal networks an earlier firewall left behind (hard kill), then creates this one. Only networks
 * with the firewall's label, unused and older than five minutes: another firewall attaches its proxy within seconds of
 * creating its network, so a fresh one is never touched.
 */
export function createEgressNetwork(egress: EgressLaunch, run: Runner = defaultRunner, executable = egress.proxy.command): void {
  run(executable, ['network', 'prune', '--force', '--filter', 'label=mcp-firewall=1', '--filter', 'until=5m'], 20_000);
  const r = run(executable, ['network', 'create', '--internal', '--label', 'mcp-firewall=1', egress.network], 20_000);
  if (r.error || r.status !== 0) throw new SandboxError(`sandbox.egress: cannot create network ${egress.network}: ${firstLine(r)}`);
}

/** Puts the running proxy on the internal network, next to the server. */
export function connectEgressProxy(egress: EgressLaunch, run: Runner = defaultRunner, executable = egress.proxy.command): void {
  const r = run(executable, ['network', 'connect', egress.network, egress.proxy.container], 20_000);
  if (r.error || r.status !== 0) throw new SandboxError(`sandbox.egress: cannot attach the proxy to ${egress.network}: ${firstLine(r)}`);
}

/** Best effort, at exit: the proxy, then the network (which Docker removes only once no container uses it). */
export function removeEgress(egress: EgressLaunch, run: Runner = defaultRunner, executable = egress.proxy.command, wait: (ms: number) => void = sleepSync): void {
  killContainer(egress.proxy.container, run, executable);
  for (let i = 0; i < 6; i++) {
    const r = run(executable, ['network', 'rm', egress.network], 10_000);
    if (r.status === 0 || /not found|no such network|network not known/i.test(r.stderr)) return;
    // A killed container is removed asynchronously (--rm); give it a moment before the next try.
    wait(500);
  }
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** The command line as a user would type it, quoted for the shell of the current platform. */
export function formatLaunch(launch: SandboxLaunch, platform: NodeJS.Platform = process.platform): string {
  const quote = (a: string): string => {
    if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(a)) return a;
    return platform === 'win32' ? `"${a.replace(/"/g, '\\"')}"` : `'${a.replace(/'/g, `'\\''`)}'`;
  };
  return [launch.command, ...launch.args].map(quote).join(' ');
}

export type ImageStatus =
  | { kind: 'ok'; id: string }
  | { kind: 'no-docker' | 'unreachable' | 'missing' | 'error'; problem: string };

/** Asks Docker for the image's content id (`sha256:...`); this also shows whether Docker is reachable at all. */
export function inspectImage(image: string, run: Runner = defaultRunner, executable = 'docker'): ImageStatus {
  const r = run(executable, ['image', 'inspect', '--format', '{{.Id}}', image], 20_000);
  if (r.error) {
    const missing = (r.error as NodeJS.ErrnoException).code === 'ENOENT';
    return { kind: missing ? 'no-docker' : 'error', problem: r.error.message };
  }
  const err = r.stderr.trim();
  if (r.status !== 0) {
    // Checked first: an image name can contain words the connection patterns look for.
    if (/no such (image|object)|image not known|failed to find image/i.test(err)) return { kind: 'missing', problem: err.split('\n')[0] };
    if (/cannot connect to the docker daemon|error during connect|is the docker daemon running|system cannot find the file specified|dockerdesktoplinuxengine|docker_engine|cannot connect to podman|unable to connect to podman|podman machine/i.test(err)) {
      return { kind: 'unreachable', problem: err.split('\n')[0] };
    }
    return { kind: 'error', problem: err.split('\n')[0] || `docker exited with status ${r.status}` };
  }
  const id = r.stdout.trim();
  if (!/^sha256:[0-9a-f]{64}$/.test(id)) return { kind: 'error', problem: `unexpected image id: ${id.slice(0, 80)}` };
  return { kind: 'ok', id };
}

/** Fails early, with a message that says what to do, when the sandbox cannot start. Returns the image id when the image is local. */
export function preflight(cfg: SandboxConfig, run: Runner = defaultRunner, executable: string = cfg.runtime): string | undefined {
  if (cfg.egress) {
    const proxy = inspectImage(cfg.egress.proxyImage, run, executable);
    if (proxy.kind === 'missing' && cfg.pull === 'never') {
      throw new SandboxError(`sandbox.egress: proxy image ${cfg.egress.proxyImage} is not present locally and sandbox.pull is "never"; run: ${executable} pull ${cfg.egress.proxyImage}`);
    }
    if (proxy.kind === 'no-docker') throw new SandboxError(`sandbox: ${missingHint(executable)} or turn the sandbox off`);
    if (proxy.kind === 'unreachable') throw new SandboxError(`sandbox: ${unreachableHint(executable)}`);
    if (proxy.kind === 'error') throw new SandboxError(`sandbox.egress: cannot inspect proxy image ${cfg.egress.proxyImage}: ${proxy.problem}`);
  }
  const status = inspectImage(cfg.image, run, executable);
  if (status.kind === 'ok') return status.id;
  if (status.kind === 'missing') {
    if (cfg.pull !== 'never') return undefined;
    throw new SandboxError(`sandbox: image ${cfg.image} is not present locally and sandbox.pull is "never"; run: ${executable} pull ${cfg.image} (or build it), or set sandbox.pull: missing`);
  }
  if (status.kind === 'no-docker') throw new SandboxError(`sandbox: ${missingHint(executable)} or turn the sandbox off`);
  if (status.kind === 'unreachable') throw new SandboxError(`sandbox: ${unreachableHint(executable)}`);
  throw new SandboxError(`sandbox: cannot inspect image ${cfg.image}: ${status.problem}`);
}

/**
 * The server's code identity when it runs in a sandbox: the image's content id, so a re-tagged or
 * rebuilt image shows up as changed server code (package rug pull) exactly like a changed npx package.
 * `extra` carries host paths pinned with --code.
 */
export function sandboxFingerprint(cfg: SandboxConfig, extra?: CodeFingerprint, run: Runner = defaultRunner, executable: string = cfg.runtime): CodeFingerprint {
  const status = inspectImage(cfg.image, run, executable);
  if (status.kind !== 'ok') throw new Error(`cannot identify sandbox image ${cfg.image}: ${status.problem}`);
  const notes = [...(extra?.notes ?? [])];
  if (!/@sha256:[0-9a-f]{64}$/.test(cfg.image)) {
    notes.push(`sandbox image ${cfg.image} is referenced by a tag; it is pinned by its image id, so a re-tagged or rebuilt image will show up as changed server code`);
  }
  const packages = [`image ${cfg.image} (${status.id.slice(7, 19)})`];
  let proxyId = '';
  if (cfg.egress) {
    // The proxy decides what leaves the sandbox, so a swapped proxy image counts as changed server code too.
    const proxy = inspectImage(cfg.egress.proxyImage, run, executable);
    if (proxy.kind !== 'ok') throw new Error(`cannot identify egress proxy image ${cfg.egress.proxyImage}: ${proxy.problem}`);
    proxyId = proxy.id;
    packages.push(`egress proxy image ${cfg.egress.proxyImage} (${proxy.id.slice(7, 19)})`);
  }
  const hash = createHash('sha256').update(`docker-image:${status.id}\0${extra?.hash ?? ''}${proxyId ? `\0egress-proxy:${proxyId}` : ''}`).digest('hex');
  return { hash, roots: extra?.roots ?? [], packages: [...packages, ...(extra?.packages ?? [])], notes };
}

/** Best effort: a container whose docker client was killed (always the case on Windows) keeps running until stopped. */
export function killContainer(container: string, run: Runner = defaultRunner, executable = 'docker'): void {
  try {
    run(executable, ['kill', container], 5000);
  } catch {
    // The container is probably gone already.
  }
}

/** What the sandbox does, one line per setting, for the audit log and `sandbox show`. */
export function describeSandbox(cfg: SandboxConfig): string {
  const mounts = cfg.mounts.map((m) => `${m.source} -> ${m.target} (${m.readOnly ? 'ro' : 'rw'})`).join('; ') || 'none';
  const network = cfg.egress ? `internal, egress only to [${cfg.egress.allow.join(', ')}] via proxy ${cfg.egress.proxyImage}` : cfg.network;
  return `image ${cfg.image}, network ${network}, ${cfg.readOnly ? 'read-only root' : 'writable root'}, user ${cfg.user}, memory ${cfg.memory}, cpus ${cfg.cpus}, pids ${cfg.pidsLimit}, env [${cfg.env.join(', ')}], mounts: ${mounts}`;
}
