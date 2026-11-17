#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import type { ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import spawn from 'cross-spawn';
import { AuditLog } from './audit.js';
import { openSinks } from './siem.js';
import { DesktopNotifier } from './notify.js';
import { startDashboard } from './dashboard/server.js';
import type { Classifier } from './ml/classifier.js';
import { lazyClassifier } from './ml/lazy.js';
import { ScoreCache } from './ml/scorecache.js';
import { describeModel, loadTransformersClassifier, type ModelInfo } from './ml/transformers.js';
import { fingerprintServer } from './codepin.js';
import { Gateway } from './gateway.js';
import { approvePending, listPending, PinStore } from './pinning.js';
import { loadPolicy, PolicyError, type Policy } from './policy.js';
import { FirewallProxy } from './proxy.js';
import {
  buildSandboxCommand,
  connectEgressProxy,
  createEgressNetwork,
  describeSandbox,
  type EgressLaunch,
  formatLaunch,
  isImageRef,
  killContainer,
  preflight,
  removeEgress,
  sandboxFingerprint,
  qualifyDefaultImage,
  SandboxError,
  type SandboxLaunch,
} from './sandbox.js';
import { buildArgs, buildImage, buildSummary, defaultBase, defaultTag, dockerfileFor, parseBuildSpec } from './sandbox-build.js';
import { EgressThrottle } from './egress-throttle.js';
import { TaintTracker } from './taint.js';

const USAGE = `Usage: mcp-firewall [--policy <file>] [--name <server-id>] [--code <path>]... [--sandbox <image>] -- <command> [args...]
       mcp-firewall gateway --upstream <url> [--policy <file>] [--name <server-id>] [--listen <host:port>]
                            [--path </mcp>] [--header "Name: value"]... [--allow-origin <origin>]... [--allow-host <name>]...
                            [--no-forward-auth]
       mcp-firewall dashboard [--policy <file>] [--audit <file>] [--port <port>]
       mcp-firewall pins list [--policy <file>]
       mcp-firewall pins approve --name <server-id> [--policy <file>] [<tool>...]
       mcp-firewall sandbox show [--policy <file>] [--name <server-id>] [--sandbox <image>] -- <command> [args...]
       mcp-firewall sandbox build <npm-package>@<exact-version> | pypi:<package>==<exact-version>
                            [--tag <image>] [--base <image>] [--runtime docker|podman] [--print] [--force]

Options:
  --policy <file>   YAML policy file (default: $MCP_FIREWALL_POLICY, else built-in defaults)
  --name <id>       Identifier for this server in audit logs and the pin store
                    (default: the server command line)
  --code <path>     Server code to fingerprint, in addition to what is found automatically
                    (npx packages, local scripts); repeatable
  --sandbox <image> Run the server in a locked-down Docker container made from this image (same as
                    sandbox.enabled and sandbox.image in the policy). The command after "--" runs
                    inside the container, so it must exist in the image.
  --audit <file>    Audit log to show (default: the policy's audit.file)
  --port <port>     Dashboard port on 127.0.0.1 (default: 4747)

sandbox show prints the docker command a sandboxed server would be started with and checks that Docker
and the image are available; it starts nothing.

sandbox build makes an image for sandbox.image: the npm package at that exact version, installed with
install scripts off on --base (default node:22-alpine), tagged mcp-<package>:<version> unless --tag is
given. A PyPI package (pypi:name==version) is installed from wheels only, so no build code runs, on
python:3.12-slim and tagged mcp-pypi-<package>:<version>. --runtime podman builds with Podman (set
sandbox.runtime: podman in the policy too). It refuses to replace an existing image
without --force. --print shows the Dockerfile and builds nothing.

gateway serves a Streamable HTTP MCP endpoint (default http://127.0.0.1:8787/mcp) in front of a remote
server, with the same policy checks. --header values may name environment variables as \${VAR}, so
credentials stay out of client configs. The client's own Authorization header is passed upstream
unless a --header sets one or --no-forward-auth is given. Requests whose Host header is not localhost
(or the --listen address, or an --allow-host name) are refused, which stops DNS rebinding.

pins approve trusts what the firewall saw but held back: changed or held tool definitions and
prompt templates ('@prompt:<name>#<args>'), and changed server code ('@server-code'). Without
names, everything pending for the server.
`;

class UsageError extends Error {}

interface CliOptions {
  policyFile?: string;
  name?: string;
  code: string[];
  /** From --sandbox: turns the sandbox on with this image, over whatever the policy says. */
  sandboxImage?: string;
  command: string;
  args: string[];
}

function parseArgs(argv: string[]): CliOptions {
  const sep = argv.indexOf('--');
  if (sep === -1 || sep === argv.length - 1) throw new UsageError('missing server command after "--"');
  const flags = argv.slice(0, sep);
  const [command, ...args] = argv.slice(sep + 1);
  let policyFile = process.env.MCP_FIREWALL_POLICY || undefined;
  let name: string | undefined;
  let sandboxImage: string | undefined;
  const code: string[] = [];
  for (let i = 0; i < flags.length; i++) {
    const flag = flags[i];
    const value = flags[i + 1];
    if (flag !== '--policy' && flag !== '--name' && flag !== '--code' && flag !== '--sandbox') throw new UsageError(`unknown option ${flag}`);
    if (value === undefined) throw new UsageError(`${flag} needs a value`);
    if (flag === '--policy') policyFile = value;
    else if (flag === '--code') code.push(value);
    else if (flag === '--sandbox') {
      if (!isImageRef(value)) throw new UsageError(`--sandbox: not a valid image reference: ${value}`);
      sandboxImage = value;
    } else name = value;
    i++;
  }
  return { policyFile, name, code, sandboxImage, command, args };
}

/** The policy with --sandbox applied: that image, sandbox on, every other sandbox setting from the policy. */
function withSandboxFlag(policy: Policy, options: CliOptions): Policy {
  return options.sandboxImage ? { ...policy, sandbox: { ...policy.sandbox, enabled: true, image: options.sandboxImage } } : policy;
}

/** `sandbox build <package>@<version>`: an image with that npm package in it, for `sandbox.image`. */
async function runSandboxBuild(argv: string[]): Promise<void> {
  let spec: string | undefined;
  let tag: string | undefined;
  let base: string | undefined;
  let runtime: 'docker' | 'podman' = 'docker';
  let print = false;
  let force = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--print') print = true;
    else if (a === '--force') force = true;
    else if (a === '--runtime') {
      const value = argv[++i];
      if (value !== 'docker' && value !== 'podman') throw new UsageError('--runtime: expected docker or podman');
      runtime = value;
    } else if (a === '--tag' || a === '--base') {
      const value = argv[++i];
      if (value === undefined) throw new UsageError(`${a} needs a value`);
      if (!isImageRef(value)) throw new UsageError(`${a}: not a valid image reference: ${value}`);
      if (a === '--tag') tag = value;
      else base = value;
    } else if (a.startsWith('-')) throw new UsageError(`unknown option ${a}`);
    else if (spec === undefined) spec = a;
    else throw new UsageError(`sandbox build takes one package, got another: ${a}`);
  }
  if (spec === undefined) {
    throw new UsageError('sandbox build needs a package with an exact version, e.g. @modelcontextprotocol/server-filesystem@2.2.0 or pypi:mcp-server-fetch==2025.4.7');
  }
  const pkg = parseBuildSpec(spec);
  const options = { pkg, tag: tag ?? defaultTag(pkg), base: base ?? qualifyDefaultImage(defaultBase(pkg), runtime), force };
  if (print) {
    process.stdout.write(`${dockerfileFor(pkg, options.base)}\n# ${runtime} ${buildArgs(pkg, options.tag, '<empty folder with this Dockerfile>').join(' ')}\n`);
    return;
  }
  const result = await buildImage(options, undefined, undefined, runtime);
  process.stdout.write(buildSummary(options, result));
}

/** `sandbox show`: what a sandboxed server would be started with, and whether Docker and the image are ready. */
function runSandbox(argv: string[]): void {
  const [action, ...rest] = argv;
  if (action !== 'show') throw new UsageError(`unknown sandbox action ${action ?? ''}`);
  const options = parseArgs(rest);
  const policy = withSandboxFlag(loadPolicy(options.policyFile), options);
  if (!policy.sandbox.enabled) throw new UsageError('the sandbox is off: pass --sandbox <image>, or set sandbox.enabled and sandbox.image in the policy');
  const serverId = options.name ?? [options.command, ...options.args].join(' ');
  const launch = buildSandboxCommand(policy.sandbox, { command: options.command, args: options.args }, { serverId });
  if (launch.egress) {
    const e = launch.egress;
    process.stdout.write(
      `${describeSandbox(policy.sandbox)}\n\n` +
        `${e.proxy.command} network create --internal --label mcp-firewall=1 ${e.network}\n` +
        `${formatLaunch(e.proxy)}\n` +
        `${e.proxy.command} network connect ${e.network} ${e.proxy.container}\n` +
        `${formatLaunch(launch)}\n\n`,
    );
  } else process.stdout.write(`${describeSandbox(policy.sandbox)}\n\n${formatLaunch(launch)}\n\n`);
  try {
    const id = preflight(policy.sandbox);
    process.stdout.write(id ? `image is present: ${id}\n` : `image is not present locally; ${policy.sandbox.runtime} will pull it at start (sandbox.pull: ${policy.sandbox.pull})\n`);
  } catch (err) {
    process.stdout.write(`${(err as Error).message}\n`);
    process.exitCode = 1;
  }
}

function runPins(argv: string[]): void {
  const [action, ...rest] = argv;
  let policyFile = process.env.MCP_FIREWALL_POLICY || undefined;
  let name: string | undefined;
  const tools: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--policy' || rest[i] === '--name') {
      const value = rest[i + 1];
      if (value === undefined) throw new UsageError(`${rest[i]} needs a value`);
      if (rest[i] === '--policy') policyFile = value;
      else name = value;
      i++;
    } else {
      tools.push(rest[i]);
    }
  }
  const { file } = loadPolicy(policyFile).pinning;
  if (action === 'list') {
    const pending = listPending(file);
    const servers = Object.entries(pending);
    if (servers.length === 0) process.stdout.write('nothing pending\n');
    for (const [server, entries] of servers) process.stdout.write(`${server}\n${Object.keys(entries).map((t) => `  ${t}\n`).join('')}`);
  } else if (action === 'approve') {
    if (!name) throw new UsageError('pins approve needs --name <server-id>');
    const approved = approvePending(file, name, tools);
    process.stdout.write(approved.length > 0 ? `approved for ${name}: ${approved.join(', ')}\n` : `nothing pending for ${name}\n`);
  } else {
    throw new UsageError(`unknown pins action ${action ?? ''}`);
  }
}

function runDashboard(argv: string[]): void {
  let policyFile = process.env.MCP_FIREWALL_POLICY || undefined;
  let auditFile: string | undefined;
  let port = 4747;
  for (let i = 0; i < argv.length; i += 2) {
    const [flag, value] = [argv[i], argv[i + 1]];
    if (value === undefined) throw new UsageError(`${flag} needs a value`);
    if (flag === '--policy') policyFile = value;
    else if (flag === '--audit') auditFile = resolve(value);
    else if (flag === '--port' && /^\d+$/.test(value)) port = Number(value);
    else throw new UsageError(`unknown option ${flag}`);
  }
  const policy = loadPolicy(policyFile);
  const audit = auditFile ?? policy.audit.file;
  const labelsFile = join(dirname(audit), 'mcp-firewall-labels.jsonl');
  startDashboard({ policy, auditFile: audit, labelsFile, port }).on('listening', () => {
    process.stderr.write(`Tuuf MCP Firewall dashboard: http://127.0.0.1:${port}\n  audit:  ${audit}\n  labels: ${labelsFile}\n`);
  });
}

/** The audit log with the policy's SIEM sinks and desktop notifier; they never hold up or stop the firewall. */
function openAudit(policy: Policy, serverId: string): AuditLog {
  const siem = policy.audit.siem;
  const sinks = [...openSinks(siem, (message) => process.stderr.write(`mcp-firewall: ${message}
`))];
  if (policy.audit.notify.enabled) sinks.push(new DesktopNotifier(policy.audit.notify));
  return new AuditLog(policy.audit.enabled ? policy.audit.file : undefined, policy.audit.logAllowed, serverId, process.stderr, {
    sinks,
    logAllowed: siem?.logAllowed ?? false,
    excerpt: siem?.excerpt ?? false,
  });
}

/**
 * The ML loader; memoised, so a gateway with many sessions loads the model once. A model that cannot load stops the
 * firewall. The classifier it hands out reads the weights only when a text needs them (`ml.lazyLoad`), and a text
 * that is a definition seen before is answered from the score cache (`ml.cacheDefinitions`): a client starts one
 * firewall per server, and each used to hold a gigabyte of weights whether its server was called or not.
 */
function classifierLoader(policy: Policy, audit: AuditLog, onFail: () => void, model = policy.ml.model, cacheScores = true): (() => Promise<Classifier>) | undefined {
  if (!policy.ml.enabled) return undefined;
  // A missing model must fail loudly, not degrade silently, and before any server starts.
  if (!existsSync(model)) {
    process.stderr.write(`mcp-firewall: cannot load ML model ${model}: not found\n`);
    process.exit(1);
  }
  let loading: Promise<Classifier> | undefined;
  const loadWeights = (): Promise<Classifier> => {
    if (loading) return loading;
    const started = Date.now();
    loading = loadTransformersClassifier(model, policy.ml);
    loading.then(
      (loaded) => audit.record({ verdict: 'info', reason: `ML classifier ${loaded.name} loaded in ${Date.now() - started} ms` }),
      (err: Error) => {
        process.stderr.write(`mcp-firewall: cannot load ML model ${model}: ${err.message}\n`);
        onFail();
        process.exit(1);
      },
    );
    return loading;
  };
  if (!policy.ml.lazyLoad) return loadWeights;

  // The files are checked now, so a broken model still stops the firewall before any server starts.
  let info: ModelInfo;
  try {
    info = describeModel(model, policy.ml);
  } catch (err) {
    process.stderr.write(`mcp-firewall: cannot load ML model ${model}: ${(err as Error).message}\n`);
    process.exit(1);
  }
  const cache = cacheScores && policy.ml.cacheDefinitions ? new ScoreCache(policy.ml.cacheFile, info.fingerprint) : undefined;
  const classifier = lazyClassifier(info, loadWeights, cache);
  return () => Promise.resolve(classifier);
}

/**
 * The loaders for a policy: the main model and, with `ml.definitionModel`, the one that reads definitions. Only
 * definitions are remembered in the score cache, so with two models the cache belongs to the definition model.
 */
function classifierLoaders(policy: Policy, audit: AuditLog, onFail: () => void): { main?: () => Promise<Classifier>; definition?: () => Promise<Classifier> } {
  const { definitionModel, scan } = policy.ml;
  const split = definitionModel !== undefined && definitionModel !== policy.ml.model && scan.toolDefinitions !== 'off';
  return {
    main: classifierLoader(policy, audit, onFail, policy.ml.model, !split),
    definition: split ? classifierLoader(policy, audit, onFail, definitionModel) : undefined,
  };
}

/** `Name: value` with \${VAR} replaced from the environment; a missing variable is an error, not an empty credential. */
/**
 * Starts the egress proxy container and resolves once it listens and sits on the server's internal network.
 * Its decision lines go to the audit log through `EgressThrottle` (the server picks the host names, so it must not
 * be able to flood the log).
 */
function startEgressProxy(egress: EgressLaunch, audit: AuditLog, stopping: () => boolean): Promise<ChildProcess> {
  createEgressNetwork(egress);
  const proxy = spawn(egress.proxy.command, egress.proxy.args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const throttle = new EgressThrottle();
  let ready = false;
  return new Promise((resolveReady, reject) => {
    const timer = setTimeout(() => reject(new SandboxError('sandbox.egress: the proxy did not start within 30 seconds')), 30_000);
    let stderr = '';
    proxy.stderr!.on('data', (d: Buffer) => {
      stderr = (stderr + d.toString('utf8')).slice(-2000);
    });
    proxy.on('error', (err) => {
      clearTimeout(timer);
      reject(new SandboxError(`sandbox.egress: cannot start the proxy: ${err.message}`));
    });
    proxy.on('exit', (code) => {
      clearTimeout(timer);
      if (!ready) reject(new SandboxError(`sandbox.egress: the proxy exited (${code}) before it was ready: ${stderr.trim().split('\n').slice(-1)[0] ?? ''}`));
      // Fails closed: without the proxy the server's internal network has no exit at all.
      else if (!stopping()) audit.record({ verdict: 'warn', method: 'egress', reason: `egress proxy stopped (exit ${code}); the server has no network now` });
    });
    createInterface({ input: proxy.stdout! }).on('line', (line) => {
      let msg: { ready?: number; egress?: 'allow' | 'deny'; host?: string; port?: number; reason?: string };
      try {
        msg = JSON.parse(line);
      } catch {
        return;
      }
      if (msg.ready !== undefined && !ready) {
        try {
          connectEgressProxy(egress);
        } catch (err) {
          clearTimeout(timer);
          reject(err);
          return;
        }
        ready = true;
        clearTimeout(timer);
        resolveReady(proxy);
        return;
      }
      if (msg.egress !== 'allow' && msg.egress !== 'deny') return;
      const host = String(msg.host ?? '?').replace(/[^\x21-\x7e]/g, '?').slice(0, 120);
      const port = Number(msg.port) || 0;
      const t = throttle.take(`${msg.egress}|${host}|${port}`, Date.now());
      if (t.suppressed) audit.record({ verdict: 'warn', method: 'egress', reason: `${t.suppressed} more egress decisions in the last minute were not logged (over the per-minute limit)` });
      if (!t.write) return;
      const more = t.more ? ` (+${t.more} more in the last minute)` : '';
      const reason = msg.egress === 'allow'
        ? `server connected to ${host}:${port} through the egress proxy${more}`
        : `server's connection to ${host}:${port} refused: ${String(msg.reason ?? '').slice(0, 200)}${more}`;
      audit.record({ verdict: msg.egress === 'allow' ? 'info' : 'block', method: 'egress', tool: `${host}:${port}`, reason });
    });
  });
}

function parseHeader(spec: string): [string, string] {
  const colon = spec.indexOf(':');
  if (colon <= 0) throw new UsageError(`--header expects "Name: value", got ${spec}`);
  const value = spec.slice(colon + 1).trim().replace(/\$\{(\w+)\}/g, (_, name: string) => {
    const v = process.env[name];
    if (v === undefined) throw new UsageError(`--header: environment variable ${name} is not set`);
    return v;
  });
  return [spec.slice(0, colon).trim(), value];
}

function runGateway(argv: string[]): void {
  let policyFile = process.env.MCP_FIREWALL_POLICY || undefined;
  let upstream: URL | undefined;
  let name: string | undefined;
  let listen = '127.0.0.1:8787';
  let path = '/mcp';
  let forwardAuthorization = true;
  const headers: Record<string, string> = {};
  const allowedOrigins: string[] = [];
  const allowedHosts: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--no-forward-auth') {
      forwardAuthorization = false;
      continue;
    }
    const value = argv[++i];
    if (value === undefined) throw new UsageError(`${flag} needs a value`);
    if (flag === '--policy') policyFile = value;
    else if (flag === '--name') name = value;
    else if (flag === '--listen') listen = value;
    else if (flag === '--path') path = value.startsWith('/') ? value : `/${value}`;
    else if (flag === '--allow-origin') allowedOrigins.push(value);
    else if (flag === '--allow-host') allowedHosts.push(value);
    else if (flag === '--header') {
      const [k, v] = parseHeader(value);
      headers[k] = v;
    } else if (flag === '--upstream') {
      try {
        upstream = new URL(value);
      } catch {
        throw new UsageError(`--upstream: not a URL: ${value}`);
      }
      if (upstream.protocol !== 'https:' && upstream.protocol !== 'http:') throw new UsageError('--upstream must be an http(s) URL');
    } else throw new UsageError(`unknown option ${flag}`);
  }
  if (!upstream) throw new UsageError('gateway needs --upstream <url>');
  const match = /^(.*):(\d+)$/.exec(listen);
  if (!match) throw new UsageError(`--listen expects host:port, got ${listen}`);
  const [, host, port] = match;

  const policy = loadPolicy(policyFile);
  const serverId = name ?? upstream.origin + upstream.pathname;
  const audit = openAudit(policy, serverId);
  const pins = policy.pinning.enabled ? new PinStore(policy.pinning.file, serverId) : undefined;
  const { main: classifier, definition: definitionClassifier } = classifierLoaders(policy, audit, () => gateway.close());
  if (!/^(127\.\d+\.\d+\.\d+|localhost|::1|\[::1\]|0\.0\.0\.0|::)$/i.test(host)) allowedHosts.push(host);
  const gateway = new Gateway({ policy, audit, pins, upstream, headers, forwardAuthorization, path, allowedOrigins, allowedHosts, serverId, classifier, definitionClassifier });
  if (!/^(127\.\d+\.\d+\.\d+|localhost|::1|\[::1\])$/i.test(host)) {
    process.stderr.write(`mcp-firewall: warning: listening on ${host}, reachable from other machines; the gateway has no authentication of its own\n`);
  }
  if (upstream.protocol === 'http:' && !/^(127\.|localhost$|\[::1\]$)/.test(upstream.hostname)) {
    process.stderr.write('mcp-firewall: warning: upstream is plain http; credentials and data travel unencrypted\n');
  }
  gateway.server.listen(Number(port), host.replace(/^\[|\]$/g, ''), () => {
    audit.record({ verdict: 'info', reason: `gateway started in ${policy.mode} mode: http://${listen}${path} -> ${upstream!.href}` });
    process.stderr.write(`Tuuf MCP Firewall gateway: http://${listen}${path} -> ${upstream!.href}\n`);
  });
  for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => (gateway.close(), void audit.flush().finally(() => process.exit(0))));
}

async function main(): Promise<void> {
  // stdout carries JSON-RPC; keep stray library logging out of it.
  console.log = console.info = console.debug = console.error;

  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === '-h' || argv[0] === '--help') {
    process.stderr.write(USAGE);
    process.exit(argv.length === 0 ? 2 : 0);
  }
  if (argv[0] === 'dashboard') {
    try {
      runDashboard(argv.slice(1));
    } catch (err) {
      process.stderr.write(`mcp-firewall: ${(err as Error).message}\n`);
      process.exit(2);
    }
    return;
  }
  if (argv[0] === 'gateway') {
    try {
      runGateway(argv.slice(1));
    } catch (err) {
      process.stderr.write(`mcp-firewall: ${(err as Error).message}\n`);
      if (err instanceof UsageError) process.stderr.write(USAGE);
      process.exit(err instanceof UsageError || err instanceof PolicyError ? 2 : 1);
    }
    return;
  }
  if (argv[0] === 'pins') {
    try {
      runPins(argv.slice(1));
    } catch (err) {
      process.stderr.write(`mcp-firewall: ${(err as Error).message}\n`);
      if (err instanceof UsageError) process.stderr.write(USAGE);
      process.exit(2);
    }
    return;
  }
  if (argv[0] === 'sandbox') {
    try {
      if (argv[1] === 'build') await runSandboxBuild(argv.slice(2));
      else runSandbox(argv.slice(1));
    } catch (err) {
      process.stderr.write(`mcp-firewall: ${(err as Error).message}\n`);
      if (err instanceof UsageError) process.stderr.write(USAGE);
      process.exit(err instanceof UsageError || err instanceof PolicyError ? 2 : 1);
    }
    return;
  }

  let options: CliOptions;
  let policy: Policy;
  try {
    options = parseArgs(argv);
    policy = withSandboxFlag(loadPolicy(options.policyFile), options);
  } catch (err) {
    process.stderr.write(`mcp-firewall: ${(err as Error).message}\n`);
    if (err instanceof UsageError) process.stderr.write(USAGE);
    process.exit(err instanceof UsageError || err instanceof PolicyError ? 2 : 1);
  }

  // Two sandboxed servers can run the same command in different images, so the image is part of the default id.
  const serverId = options.name ?? [policy.sandbox.enabled ? `sandbox:${policy.sandbox.image}` : '', options.command, ...options.args].filter(Boolean).join(' ');

  // With the sandbox on, the process the firewall starts is the container runtime and the server runs inside it.
  let launch: SandboxLaunch | undefined;
  if (policy.sandbox.enabled) {
    try {
      preflight(policy.sandbox);
      launch = buildSandboxCommand(policy.sandbox, { command: options.command, args: options.args }, { serverId });
    } catch (err) {
      process.stderr.write(`mcp-firewall: ${(err as Error).message}\n`);
      process.exit(err instanceof SandboxError ? 1 : 2);
    }
  }

  const audit = openAudit(policy, serverId);
  const pins = policy.pinning.enabled ? new PinStore(policy.pinning.file, serverId) : undefined;

  // The proxy calls this once the handshake has been answered.
  const { main: loadClassifier, definition: loadDefinitionClassifier } = classifierLoaders(policy, audit, () => child.kill());

  // With egress, the server starts only once its proxy is up: there is no fallback to an open network.
  let egressProxy: ChildProcess | undefined;
  let stopped = false;
  if (launch?.egress) {
    try {
      egressProxy = await startEgressProxy(launch.egress, audit, () => stopped);
    } catch (err) {
      removeEgress(launch.egress);
      process.stderr.write(`mcp-firewall: ${(err as Error).message}\n`);
      process.exit(1);
    }
  }

  // stdout belongs to the JSON-RPC stream; server stderr passes straight through for host logs.
  const child = spawn(launch?.command ?? options.command, launch?.args ?? options.args, { stdio: ['pipe', 'pipe', 'inherit'] });
  /** A killed docker client (always the case on Windows) leaves its container running, so stop it by name. */
  const stopContainer = () => {
    if (!launch || stopped) return;
    stopped = true;
    killContainer(launch.container, undefined, launch.command);
    if (launch.egress) {
      egressProxy?.stdin?.end();
      removeEgress(launch.egress);
    }
  };
  child.on('error', (err) => {
    process.stderr.write(`mcp-firewall: failed to start server: ${err.message}\n`);
    process.exit(1);
  });
  child.on('exit', (code, signal) => {
    stopContainer();
    // Records still on their way to the SIEM get a moment to leave.
    void audit.flush().finally(() => process.stdout.write('', () => process.exit(code ?? (signal ? 1 : 0))));
  });
  child.stdin!.on('error', () => {
    // The server went away; its exit handler ends the firewall.
  });
  process.stdin.on('end', () => child.stdin!.end());
  for (const sig of ['SIGINT', 'SIGTERM'] as const) {
    process.on(sig, () => {
      child.kill(sig);
      stopContainer();
    });
  }

  audit.record({ verdict: 'info', reason: `firewall started in ${policy.mode} mode` });
  if (launch) audit.record({ verdict: 'info', reason: `sandbox on: container ${launch.container}; ${describeSandbox(policy.sandbox)}` });
  const serverCode = () =>
    policy.sandbox.enabled
      ? sandboxFingerprint(policy.sandbox, options.code.length > 0 ? fingerprintServer('', [], options.code) : undefined)
      : fingerprintServer(options.command, options.args, options.code);
  const proxy = new FirewallProxy(policy, audit, pins, {
    clientIn: process.stdin,
    clientOut: process.stdout,
    serverIn: child.stdin!,
    serverOut: child.stdout!,
  }, loadClassifier, serverCode, loadDefinitionClassifier);
  // Each server has its own firewall process; a shared tracker lets data read through one stop at another's sink.
  if (proxy.taint && policy.taint.scope === 'shared') proxy.taint = new TaintTracker(policy.taint, serverId, TaintTracker.sessionKey());
  proxy.start();
}

void main();
