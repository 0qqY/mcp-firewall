#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import spawn from 'cross-spawn';
import { AuditLog } from './audit.js';
import { openSinks } from './siem.js';
import { startDashboard } from './dashboard/server.js';
import type { Classifier } from './ml/classifier.js';
import { loadTransformersClassifier } from './ml/transformers.js';
import { fingerprintServer } from './codepin.js';
import { Gateway } from './gateway.js';
import { approvePending, listPending, PinStore } from './pinning.js';
import { loadPolicy, PolicyError, type Policy } from './policy.js';
import { FirewallProxy } from './proxy.js';
import { TaintTracker } from './taint.js';

const USAGE = `Usage: mcp-firewall [--policy <file>] [--name <server-id>] [--code <path>]... -- <command> [args...]
       mcp-firewall gateway --upstream <url> [--policy <file>] [--name <server-id>] [--listen <host:port>]
                            [--path </mcp>] [--header "Name: value"]... [--allow-origin <origin>]... [--allow-host <name>]...
                            [--no-forward-auth]
       mcp-firewall dashboard [--policy <file>] [--audit <file>] [--port <port>]
       mcp-firewall pins list [--policy <file>]
       mcp-firewall pins approve --name <server-id> [--policy <file>] [<tool>...]

Options:
  --policy <file>   YAML policy file (default: $MCP_FIREWALL_POLICY, else built-in defaults)
  --name <id>       Identifier for this server in audit logs and the pin store
                    (default: the server command line)
  --code <path>     Server code to fingerprint, in addition to what is found automatically
                    (npx packages, local scripts); repeatable
  --audit <file>    Audit log to show (default: the policy's audit.file)
  --port <port>     Dashboard port on 127.0.0.1 (default: 4747)

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
  const code: string[] = [];
  for (let i = 0; i < flags.length; i++) {
    const flag = flags[i];
    const value = flags[i + 1];
    if (flag !== '--policy' && flag !== '--name' && flag !== '--code') throw new UsageError(`unknown option ${flag}`);
    if (value === undefined) throw new UsageError(`${flag} needs a value`);
    if (flag === '--policy') policyFile = value;
    else if (flag === '--code') code.push(value);
    else name = value;
    i++;
  }
  return { policyFile, name, code, command, args };
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

/** The audit log with the policy's SIEM sinks; they never hold up or stop the firewall. */
function openAudit(policy: Policy, serverId: string): AuditLog {
  const siem = policy.audit.siem;
  const sinks = openSinks(siem, (message) => process.stderr.write(`mcp-firewall: ${message}
`));
  return new AuditLog(policy.audit.enabled ? policy.audit.file : undefined, policy.audit.logAllowed, serverId, process.stderr, {
    sinks,
    logAllowed: siem?.logAllowed ?? false,
    excerpt: siem?.excerpt ?? false,
  });
}

/** The ML loader; memoised, so a gateway with many sessions loads the model once. A model that cannot load stops the firewall. */
function classifierLoader(policy: Policy, audit: AuditLog, onFail: () => void): (() => Promise<Classifier>) | undefined {
  if (!policy.ml.enabled) return undefined;
  // A missing model must fail loudly, not degrade silently, and before any server starts.
  if (!existsSync(policy.ml.model)) {
    process.stderr.write(`mcp-firewall: cannot load ML model ${policy.ml.model}: not found\n`);
    process.exit(1);
  }
  let loading: Promise<Classifier> | undefined;
  return () => {
    if (loading) return loading;
    const started = Date.now();
    loading = loadTransformersClassifier(policy.ml.model, policy.ml);
    loading.then(
      (loaded) => audit.record({ verdict: 'info', reason: `ML classifier ${loaded.name} loaded in ${Date.now() - started} ms` }),
      (err: Error) => {
        process.stderr.write(`mcp-firewall: cannot load ML model ${policy.ml.model}: ${err.message}\n`);
        onFail();
        process.exit(1);
      },
    );
    return loading;
  };
}

/** `Name: value` with \${VAR} replaced from the environment; a missing variable is an error, not an empty credential. */
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
  const classifier = classifierLoader(policy, audit, () => gateway.close());
  if (!/^(127\.\d+\.\d+\.\d+|localhost|::1|\[::1\]|0\.0\.0\.0|::)$/i.test(host)) allowedHosts.push(host);
  const gateway = new Gateway({ policy, audit, pins, upstream, headers, forwardAuthorization, path, allowedOrigins, allowedHosts, serverId, classifier });
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

  let options: CliOptions;
  let policy: Policy;
  try {
    options = parseArgs(argv);
    policy = loadPolicy(options.policyFile);
  } catch (err) {
    process.stderr.write(`mcp-firewall: ${(err as Error).message}\n`);
    if (err instanceof UsageError) process.stderr.write(USAGE);
    process.exit(err instanceof UsageError || err instanceof PolicyError ? 2 : 1);
  }

  const serverId = options.name ?? [options.command, ...options.args].join(' ');
  const audit = openAudit(policy, serverId);
  const pins = policy.pinning.enabled ? new PinStore(policy.pinning.file, serverId) : undefined;

  // The proxy calls this once the handshake has been answered.
  const loadClassifier = classifierLoader(policy, audit, () => child.kill());

  // stdout belongs to the JSON-RPC stream; server stderr passes straight through for host logs.
  const child = spawn(options.command, options.args, { stdio: ['pipe', 'pipe', 'inherit'] });
  child.on('error', (err) => {
    process.stderr.write(`mcp-firewall: failed to start server: ${err.message}\n`);
    process.exit(1);
  });
  child.on('exit', (code, signal) => {
    // Records still on their way to the SIEM get a moment to leave.
    void audit.flush().finally(() => process.stdout.write('', () => process.exit(code ?? (signal ? 1 : 0))));
  });
  child.stdin!.on('error', () => {
    // The server went away; its exit handler ends the firewall.
  });
  process.stdin.on('end', () => child.stdin!.end());
  for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => child.kill(sig));

  audit.record({ verdict: 'info', reason: `firewall started in ${policy.mode} mode` });
  const proxy = new FirewallProxy(policy, audit, pins, {
    clientIn: process.stdin,
    clientOut: process.stdout,
    serverIn: child.stdin!,
    serverOut: child.stdout!,
  }, loadClassifier, () => fingerprintServer(options.command, options.args, options.code));
  // Each server has its own firewall process; a shared tracker lets data read through one stop at another's sink.
  if (proxy.taint && policy.taint.scope === 'shared') proxy.taint = new TaintTracker(policy.taint, serverId, TaintTracker.sessionKey());
  proxy.start();
}

void main();
