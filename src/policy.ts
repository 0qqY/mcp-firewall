import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { parse } from 'yaml';
import { buildDetectors, type Detector } from './dlp.js';
import { globToRegExp } from './glob.js';
import { compilePathPattern, type PathConstraint } from './paths.js';
import {
  defaultProtectedPaths,
  hasMountBreaker,
  isContainerPath,
  isEnvName,
  isImageRef,
  isNetworkName,
  isSize,
  isUser,
  mountProblem,
  RESERVED_ENV,
  SANDBOX_DEFAULTS,
  type SandboxConfig,
  type SandboxMount,
} from './sandbox.js';
import { SYSLOG_FACILITIES, type SiemConfig } from './siem.js';
import type { TaintConfig, TaintSink, TaintSource } from './taint.js';

export type Mode = 'enforce' | 'monitor';
/** ask: the call waits until the user approves it (MCP elicitation). */
export type Action = 'allow' | 'deny' | 'ask';

export interface ArgumentConstraint {
  allow: RegExp[];
  deny: RegExp[];
}

export interface ToolRule {
  pattern: string;
  match: RegExp;
  action: Action;
  reason?: string;
  /** Keyed by top-level argument name; `*` means every string anywhere in the arguments. */
  arguments: Map<string, ArgumentConstraint>;
  /** Path arguments, checked on their canonical form (decoded, resolved, symlinks followed). */
  paths?: PathConstraint;
}

/** Desktop notifications for the user, who otherwise learns of a block only if the model mentions it. */
export interface NotifyConfig {
  enabled: boolean;
  /** Verdicts that raise a notification. */
  on: NotifyVerdict[];
  /** After a notification, further ones are gathered for this long and shown as one summary. */
  quietSeconds: number;
}

export const NOTIFY_VERDICTS = ['block', 'would_block', 'redact', 'would_redact', 'warn'] as const;
export type NotifyVerdict = (typeof NOTIFY_VERDICTS)[number];

export interface Policy {
  mode: Mode;
  /** `siem`: copies of the records sent to syslog or an OpenTelemetry collector, independent of `enabled`. */
  audit: { enabled: boolean; file: string; logAllowed: boolean; siem?: SiemConfig; notify: NotifyConfig };
  tools: { default: Action; rules: ToolRule[] };
  methods: { deny: RegExp[] };
  descriptionScan: { enabled: boolean; action: 'hide' | 'warn'; patterns: RegExp[]; hiddenUnicode: boolean };
  /**
   * Limits on `sampling/createMessage`, which spends the user's model quota on the server's behalf.
   * 0 means unlimited. Token limits count the `maxTokens` each request asks for.
   */
  sampling: { maxPerMinute: number; maxPerSession: number; maxTokensPerRequest: number; maxTokensPerSession: number };
  /** Decode base64, hex, percent and escape runs and scan the decoded text too (patterns and ML). */
  decoding: { enabled: boolean };
  /** Invisible characters and terminal escapes in results, errors and server-initiated requests. */
  hiddenText: { action: 'strip' | 'block' | 'warn' | 'off' };
  pinning: {
    enabled: boolean;
    file: string;
    onChange: 'hide' | 'warn';
    /** allow: trust new tools on first use | hide: keep them hidden until approved. */
    onNew: 'allow' | 'hide';
    onNameCollision: 'hide' | 'warn' | 'off';
    /** What to do when the server's code changed since it was pinned (package rug pull). */
    serverCode: 'block' | 'warn' | 'off';
    /** What to do when a `prompts/get` template changed since it was pinned (argument values do not count). */
    prompts: 'block' | 'warn' | 'off';
  };
  /** How `ask` rules and taint flows reach the user: an elicitation the client shows, with a time limit. */
  approval: {
    timeoutSeconds: number;
    /** What happens when the client cannot ask (no elicitation support): deny or let the call through. */
    fallback: 'deny' | 'allow';
    /** Offer "allow this tool for the rest of the session" in the prompt. */
    remember: boolean;
  };
  /** Session data-flow tracking: what source tools returned must not leave through sink tools. */
  taint: TaintConfig;
  /** Runs the server in a locked-down Docker container instead of on the host (off by default). */
  sandbox: SandboxConfig;
  dlp: {
    enabled: boolean;
    scanRequests: boolean;
    scanResponses: boolean;
    action: 'redact' | 'block' | 'warn';
    detectors: Detector[];
  };
  ml: {
    enabled: boolean;
    model: string;
    /**
     * A second model for the definition channel (tool, prompt and resource definitions, server instructions);
     * everything else stays with `model`. Unset: `model` reads every channel.
     */
    definitionModel?: string;
    dtype: 'fp32' | 'fp16' | 'q8';
    injectionLabel: string;
    threshold: number;
    failMode: 'closed' | 'open';
    chunkChars: number;
    maxChunks: number;
    /** What to do with text longer than `maxChunks` chunks, whose middle is not scanned. */
    onTruncated: 'block' | 'warn';
    /** Texts per model call. Small batches keep the buffers (batch × length²) and the padding down. */
    batchSize: number;
    /** ONNX threads for one scan; 0 lets the runtime take every core. */
    threads: number;
    /** Keep ONNX's memory arena: no faster here, but a process then holds up to 2 GB more after a long scan. */
    memoryArena: boolean;
    /** Read the model's weights when a text first needs them, not right after the handshake. */
    lazyLoad: boolean;
    /** Remember the scores of definitions, so a server whose definitions did not change needs no model at start-up. */
    cacheDefinitions: boolean;
    cacheFile: string;
    scan: {
      toolDefinitions: 'hide' | 'warn' | 'off';
      toolResults: 'block' | 'warn' | 'off';
      /**
       * `prompts/get` templates. They address the model by design ("Act as ..."), which the classifier
       * cannot tell from an injection, so the default only warns; definition patterns still block.
       */
      promptResults: 'block' | 'warn' | 'off';
      serverRequests: 'block' | 'warn' | 'off';
    };
    /**
     * Logs text the model let through, with its score, so it can be labelled in the panel: everything scoring at
     * least `nearMiss` (0 = off) and a random `sample` share (0..1) of the rest. The text stays in the local audit file.
     */
    review: { nearMiss: number; sample: number };
  };
}

export class PolicyError extends Error {}

/** Common tool-poisoning phrasing; matched case-insensitively against every string in a tool definition. */
export const DEFAULT_DESCRIPTION_PATTERNS = [
  'ignore (all |any )?(previous|prior|above|earlier) (instructions|prompts|rules)',
  '<\\s*/?\\s*(important|system|instructions?|secret)\\s*>',
  'do not (tell|mention|inform|reveal|show)[^.]{0,40}(user|human)',
  '(before|prior to) (using|calling|invoking) (this|any|the) tool',
  '(id_rsa|id_ed25519|\\.ssh[\\\\/]|\\.aws[\\\\/]credentials|\\.env\\b|mcp\\.json)',
  '(send|forward|exfiltrate|upload|post)[^.]{0,60}(https?://|webhook)',
  '(conversation|chat) history',
];

type Obj = Record<string, unknown>;

function obj(v: unknown, path: string): Obj {
  if (v === undefined || v === null) return {};
  if (typeof v !== 'object' || Array.isArray(v)) throw new PolicyError(`${path}: expected a mapping`);
  return v as Obj;
}

function oneOf<T extends string>(v: unknown, allowed: readonly T[], def: T, path: string): T {
  if (v === undefined) return def;
  if (typeof v === 'string' && (allowed as readonly string[]).includes(v)) return v as T;
  throw new PolicyError(`${path}: expected one of ${allowed.join(', ')}`);
}

function bool(v: unknown, def: boolean, path: string): boolean {
  if (v === undefined) return def;
  if (typeof v !== 'boolean') throw new PolicyError(`${path}: expected true or false`);
  return v;
}

function num(v: unknown, def: number, min: number, max: number, path: string): number {
  if (v === undefined) return def;
  if (typeof v !== 'number' || Number.isNaN(v) || v < min || v > max) throw new PolicyError(`${path}: expected a number between ${min} and ${max}`);
  return v;
}

function strList(v: unknown, path: string): string[] | undefined {
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || !v.every((s) => typeof s === 'string')) throw new PolicyError(`${path}: expected a list of strings`);
  return v;
}

function regex(pattern: string, path: string): RegExp {
  try {
    return new RegExp(pattern, 'i');
  } catch (err) {
    throw new PolicyError(`${path}: invalid regex: ${(err as Error).message}`);
  }
}

function regexList(v: unknown, path: string): RegExp[] {
  return (strList(v, path) ?? []).map((p, i) => regex(p, `${path}[${i}]`));
}

function filePath(v: unknown, def: string, baseDir: string, path: string): string {
  if (v === undefined) return join(baseDir, def);
  if (typeof v !== 'string') throw new PolicyError(`${path}: expected a file path`);
  return isAbsolute(v) ? v : resolve(baseDir, v);
}

function compilePaths(raw: unknown, baseDir: string, path: string): PathConstraint | undefined {
  if (raw === undefined) return undefined;
  const p = obj(raw, path);
  const names = strList(p.arguments, `${path}.arguments`);
  if (!names?.length) throw new PolicyError(`${path}.arguments: list the argument names that hold paths`);
  if (p.base !== undefined && typeof p.base !== 'string') throw new PolicyError(`${path}.base: expected a directory`);
  const patterns = (key: 'allow' | 'deny') => (strList(p[key], `${path}.${key}`) ?? []).map((s) => compilePathPattern(s, baseDir));
  return {
    arguments: names,
    allow: patterns('allow'),
    deny: patterns('deny'),
    base: typeof p.base === 'string' ? resolve(baseDir, p.base) : process.cwd(),
    platform: process.platform,
    hardLinks: oneOf(p.hardLinks, ['deny', 'allow'] as const, 'deny', `${path}.hardLinks`),
  };
}

/** `${VAR}` in a value names an environment variable, so tokens stay out of the policy file. */
function expandEnv(v: string, path: string): string {
  return v.replace(/\$\{(\w+)\}/g, (_, name: string) => {
    const value = process.env[name];
    if (value === undefined) throw new PolicyError(`${path}: environment variable ${name} is not set`);
    return value;
  });
}

function url(v: unknown, protocols: string[], path: string): URL {
  if (typeof v !== 'string') throw new PolicyError(`${path}: expected a URL`);
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new PolicyError(`${path}: not a URL: ${v}`);
  }
  if (!protocols.includes(u.protocol)) throw new PolicyError(`${path}: expected a ${protocols.map((p) => p.slice(0, -1)).join(', ')} URL`);
  if (!u.hostname) throw new PolicyError(`${path}: the URL needs a host`);
  return u;
}

function compileNotify(raw: unknown): NotifyConfig {
  const n = obj(raw, 'audit.notify');
  const on = strList(n.on, 'audit.notify.on') ?? ['block'];
  for (const v of on) oneOf(v, NOTIFY_VERDICTS, 'block', 'audit.notify.on');
  return {
    enabled: bool(n.enabled, false, 'audit.notify.enabled'),
    on: on as NotifyVerdict[],
    quietSeconds: num(n.quietSeconds, 30, 0, 3600, 'audit.notify.quietSeconds'),
  };
}

function compileSiem(raw: unknown, baseDir: string): SiemConfig | undefined {
  if (raw === undefined) return undefined;
  const s = obj(raw, 'audit.siem');
  const syslog = s.syslog === undefined ? undefined : obj(s.syslog, 'audit.siem.syslog');
  const otlp = s.otlp === undefined ? undefined : obj(s.otlp, 'audit.siem.otlp');
  if (!syslog && !otlp) throw new PolicyError('audit.siem: configure syslog, otlp or both');
  let syslogConfig: SiemConfig['syslog'];
  if (syslog) {
    const target = url(syslog.target, ['udp:', 'tcp:', 'tls:'], 'audit.siem.syslog.target');
    const facility = oneOf(syslog.facility, Object.keys(SYSLOG_FACILITIES), 'local0', 'audit.siem.syslog.facility');
    if (syslog.appName !== undefined && typeof syslog.appName !== 'string') throw new PolicyError('audit.siem.syslog.appName: expected a string');
    if (syslog.ca !== undefined && target.protocol !== 'tls:') throw new PolicyError('audit.siem.syslog.ca: only for tls:// targets');
    const framing = oneOf(syslog.framing, ['octet-counting', 'newline'] as const, 'octet-counting', 'audit.siem.syslog.framing');
    if (syslog.framing !== undefined && target.protocol === 'udp:') throw new PolicyError('audit.siem.syslog.framing: only for tcp:// and tls:// targets');
    syslogConfig = {
      target,
      facility: SYSLOG_FACILITIES[facility],
      appName: typeof syslog.appName === 'string' ? syslog.appName : 'mcp-firewall',
      ca: syslog.ca === undefined ? undefined : filePath(syslog.ca, '', baseDir, 'audit.siem.syslog.ca'),
      framing,
    };
  }
  let otlpConfig: SiemConfig['otlp'];
  if (otlp) {
    const endpoint = url(otlp.endpoint, ['http:', 'https:'], 'audit.siem.otlp.endpoint');
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(obj(otlp.headers, 'audit.siem.otlp.headers'))) {
      if (typeof v !== 'string') throw new PolicyError(`audit.siem.otlp.headers.${k}: expected a string`);
      headers[k] = expandEnv(v, `audit.siem.otlp.headers.${k}`);
    }
    otlpConfig = { endpoint, headers };
  }
  return {
    syslog: syslogConfig,
    otlp: otlpConfig,
    logAllowed: bool(s.logAllowed, false, 'audit.siem.logAllowed'),
    excerpt: bool(s.excerpt, false, 'audit.siem.excerpt'),
    queueLimit: num(s.queueLimit, 1000, 1, 1_000_000, 'audit.siem.queueLimit'),
  };
}

function compileRule(raw: unknown, path: string, baseDir: string): ToolRule {
  const r = obj(raw, path);
  if (typeof r.match !== 'string') throw new PolicyError(`${path}.match: expected a tool name or glob`);
  if (r.action === undefined) throw new PolicyError(`${path}.action: required`);
  if (r.reason !== undefined && typeof r.reason !== 'string') throw new PolicyError(`${path}.reason: expected a string`);
  const args = new Map<string, ArgumentConstraint>();
  for (const [key, value] of Object.entries(obj(r.arguments, `${path}.arguments`))) {
    const c = obj(value, `${path}.arguments.${key}`);
    args.set(key, {
      allow: regexList(c.allow, `${path}.arguments.${key}.allow`),
      deny: regexList(c.deny, `${path}.arguments.${key}.deny`),
    });
  }
  return {
    pattern: r.match,
    match: globToRegExp(r.match),
    action: oneOf(r.action, ['allow', 'deny', 'ask'] as const, 'deny', `${path}.action`),
    reason: r.reason,
    arguments: args,
    paths: compilePaths(r.paths, baseDir, `${path}.paths`),
  };
}

function compileTaint(raw: Obj, baseDir: string): TaintConfig {
  const list = (key: 'sources' | 'sinks'): Obj[] => {
    const v = raw[key] ?? [];
    if (!Array.isArray(v)) throw new PolicyError(`taint.${key}: expected a list`);
    return v.map((e, i) => {
      const o = obj(e, `taint.${key}[${i}]`);
      if (typeof o.match !== 'string') throw new PolicyError(`taint.${key}[${i}].match: expected a tool name or glob`);
      return o;
    });
  };
  const label = (v: unknown, def: string, path: string): string => {
    if (v === undefined) return def;
    if (typeof v !== 'string') throw new PolicyError(`${path}: expected a label`);
    return v;
  };
  const sources: TaintSource[] = list('sources').map((o, i) => ({
    pattern: o.match as string,
    match: globToRegExp(o.match as string),
    label: label(o.label, 'private', `taint.sources[${i}].label`) || 'private',
  }));
  const sinks: TaintSink[] = list('sinks').map((o, i) => ({
    pattern: o.match as string,
    match: globToRegExp(o.match as string),
    labels: strList(o.labels, `taint.sinks[${i}].labels`) ?? [],
    when: oneOf(o.when, ['content', 'session'] as const, 'content', `taint.sinks[${i}].when`),
  }));
  return {
    enabled: bool(raw.enabled, true, 'taint.enabled'),
    action: oneOf(raw.action, ['block', 'warn', 'ask'] as const, 'block', 'taint.action'),
    scope: oneOf(raw.scope, ['server', 'shared'] as const, 'shared', 'taint.scope'),
    ttlMinutes: num(raw.ttlMinutes, 60, 0, 10_080, 'taint.ttlMinutes'),
    dir: filePath(raw.dir, 'mcp-firewall-taint', baseDir, 'taint.dir'),
    dlpLabel: label(raw.dlpLabel, 'secret', 'taint.dlpLabel'),
    minMatches: num(raw.minMatches, 1, 1, 1_000, 'taint.minMatches'),
    sources,
    sinks,
  };
}

const SANDBOX_KEYS = ['enabled', 'image', 'pull', 'network', 'readOnly', 'tmpfsSize', 'user', 'memory', 'cpus', 'pidsLimit', 'mounts', 'env', 'workdir'];

/**
 * `stateFiles` are the firewall's own files (audit log, pins, taint data, model): a mount that reaches them
 * would let the server rewrite the evidence or the defences.
 */
function compileSandbox(raw: unknown, baseDir: string, stateFiles: string[]): SandboxConfig {
  const s = obj(raw, 'sandbox');
  for (const key of Object.keys(s)) {
    if (!SANDBOX_KEYS.includes(key)) {
      const hint = /arg|flag|option|privileg|cap|security|device|volume|pid|ipc|host/i.test(key)
        ? ' (raw docker flags are not supported, so the sandbox cannot be loosened by accident; run docker yourself and wrap that command if you need more)'
        : '';
      throw new PolicyError(`sandbox.${key}: unknown option${hint}`);
    }
  }
  const text = (v: unknown, path: string): string | undefined => {
    if (v === undefined) return undefined;
    if (typeof v !== 'string') throw new PolicyError(`${path}: expected a string`);
    return v;
  };
  const size = (v: unknown, def: string, path: string): string => {
    const value = text(v, path) ?? def;
    if (!isSize(value)) throw new PolicyError(`${path}: expected a size such as 512m or 1g`);
    return value;
  };

  const enabled = bool(s.enabled, false, 'sandbox.enabled');
  const image = text(s.image, 'sandbox.image') ?? '';
  if (image && !isImageRef(image)) throw new PolicyError(`sandbox.image: not a valid image reference: ${image}`);
  if (enabled && !image) throw new PolicyError('sandbox.image: required when the sandbox is enabled');
  const network = text(s.network, 'sandbox.network') ?? SANDBOX_DEFAULTS.network;
  if (!isNetworkName(network)) throw new PolicyError(`sandbox.network: expected none, bridge or the name of a user-defined network (host is not allowed): ${network}`);
  const user = text(s.user, 'sandbox.user') ?? SANDBOX_DEFAULTS.user;
  if (!isUser(user)) throw new PolicyError('sandbox.user: expected a numeric uid or uid:gid');
  const pidsLimit = num(s.pidsLimit, SANDBOX_DEFAULTS.pidsLimit, 1, 100_000, 'sandbox.pidsLimit');
  if (!Number.isInteger(pidsLimit)) throw new PolicyError('sandbox.pidsLimit: expected a whole number');
  const workdir = text(s.workdir, 'sandbox.workdir');
  if (workdir !== undefined && !isContainerPath(workdir)) throw new PolicyError('sandbox.workdir: expected an absolute path inside the container');

  const env = strList(s.env, 'sandbox.env') ?? [];
  for (const name of env) {
    if (!isEnvName(name)) throw new PolicyError(`sandbox.env: ${name} is not a variable name`);
    if (RESERVED_ENV.has(name)) throw new PolicyError(`sandbox.env: ${name} is set by the sandbox`);
  }
  if (new Set(env).size !== env.length) throw new PolicyError('sandbox.env: a variable is listed twice');

  const home = homedir();
  const guard = { protectedPaths: [...defaultProtectedPaths(home), ...stateFiles], protectedRoots: [home, baseDir] };
  const rawMounts = s.mounts ?? [];
  if (!Array.isArray(rawMounts)) throw new PolicyError('sandbox.mounts: expected a list');
  const targets = new Set<string>();
  const mounts: SandboxMount[] = rawMounts.map((m, i) => {
    const path = `sandbox.mounts[${i}]`;
    const o = obj(m, path);
    for (const key of Object.keys(o)) if (!['source', 'target', 'mode'].includes(key)) throw new PolicyError(`${path}.${key}: unknown option`);
    if (typeof o.source !== 'string' || !o.source) throw new PolicyError(`${path}.source: expected a host folder or file`);
    if (typeof o.target !== 'string' || !isContainerPath(o.target)) throw new PolicyError(`${path}.target: expected an absolute path inside the container (no commas or quotes)`);
    if (o.target === '/' || /^\/(proc|sys|dev)(\/|$)/.test(o.target)) throw new PolicyError(`${path}.target: ${o.target} is not allowed`);
    if (targets.has(o.target)) throw new PolicyError(`${path}.target: ${o.target} is used by another mount`);
    targets.add(o.target);
    const source = isAbsolute(o.source) ? o.source : resolve(baseDir, o.source);
    if (hasMountBreaker(source)) throw new PolicyError(`${path}.source: a comma, quote or control character in the path breaks the mount option`);
    const problem = mountProblem(source, guard);
    if (problem) throw new PolicyError(`${path}.source: ${source} cannot be mounted: ${problem}`);
    return { source, target: o.target, readOnly: oneOf(o.mode, ['ro', 'rw'] as const, 'ro', `${path}.mode`) === 'ro' };
  });

  return {
    enabled,
    image,
    pull: oneOf(s.pull, ['never', 'missing', 'always'] as const, SANDBOX_DEFAULTS.pull, 'sandbox.pull'),
    network,
    readOnly: bool(s.readOnly, SANDBOX_DEFAULTS.readOnly, 'sandbox.readOnly'),
    tmpfsSize: size(s.tmpfsSize, SANDBOX_DEFAULTS.tmpfsSize, 'sandbox.tmpfsSize'),
    user,
    memory: size(s.memory, SANDBOX_DEFAULTS.memory, 'sandbox.memory'),
    cpus: num(s.cpus, SANDBOX_DEFAULTS.cpus, 0.1, 64, 'sandbox.cpus'),
    pidsLimit,
    mounts,
    env,
    workdir,
    ...guard,
  };
}

/** Validates a parsed policy document; relative file paths resolve against `baseDir`. */
export function compilePolicy(raw: unknown, baseDir: string): Policy {
  const root = obj(raw, 'policy');
  if (root.version !== undefined && root.version !== 1) throw new PolicyError('version: only version 1 is supported');

  const audit = obj(root.audit, 'audit');
  const tools = obj(root.tools, 'tools');
  const methods = obj(root.methods, 'methods');
  const desc = obj(root.descriptionScan, 'descriptionScan');
  const hiddenText = obj(root.hiddenText, 'hiddenText');
  const decoding = obj(root.decoding, 'decoding');
  const sampling = obj(root.sampling, 'sampling');
  const pinning = obj(root.pinning, 'pinning');
  const dlp = obj(root.dlp, 'dlp');
  const taint = obj(root.taint, 'taint');
  const approval = obj(root.approval, 'approval');
  const ml = obj(root.ml, 'ml');
  const mlScan = obj(ml.scan, 'ml.scan');
  const mlReview = obj(ml.review, 'ml.review');
  if (ml.injectionLabel !== undefined && typeof ml.injectionLabel !== 'string') throw new PolicyError('ml.injectionLabel: expected a string');

  const rules = tools.rules ?? [];
  if (!Array.isArray(rules)) throw new PolicyError('tools.rules: expected a list');

  const custom = dlp.custom ?? [];
  if (!Array.isArray(custom)) throw new PolicyError('dlp.custom: expected a list');
  let detectors: Detector[];
  try {
    detectors = buildDetectors(
      strList(dlp.detectors, 'dlp.detectors'),
      custom.map((c, i) => {
        const entry = obj(c, `dlp.custom[${i}]`);
        if (typeof entry.name !== 'string' || typeof entry.pattern !== 'string') {
          throw new PolicyError(`dlp.custom[${i}]: expected name and pattern strings`);
        }
        return { name: entry.name, pattern: entry.pattern };
      }),
    );
  } catch (err) {
    if (err instanceof PolicyError) throw err;
    throw new PolicyError(`dlp: ${(err as Error).message}`);
  }

  const mlThreads = num(ml.threads, 0, 0, 256, 'ml.threads');
  const mlBatchSize = num(ml.batchSize, 2, 1, 64, 'ml.batchSize');
  for (const [value, path] of [[mlThreads, 'ml.threads'], [mlBatchSize, 'ml.batchSize']] as const) {
    if (!Number.isInteger(value)) throw new PolicyError(`${path}: expected a whole number`);
  }
  const mlDefinitionModel = ml.definitionModel === undefined || ml.definitionModel === null ? undefined : filePath(ml.definitionModel, '', baseDir, 'ml.definitionModel');
  const mlCacheFile = filePath(ml.cacheFile, 'mcp-firewall-scores.jsonl', baseDir, 'ml.cacheFile');

  // The firewall's own files: a sandbox mount must not reach them.
  const stateFiles = [
    filePath(audit.file, 'mcp-firewall-audit.jsonl', baseDir, 'audit.file'),
    filePath(pinning.file, 'mcp-firewall-pins.json', baseDir, 'pinning.file'),
    filePath(taint.dir, 'mcp-firewall-taint', baseDir, 'taint.dir'),
    filePath(ml.model, join('models', 'prompt-injection'), baseDir, 'ml.model'),
    ...(mlDefinitionModel ? [mlDefinitionModel] : []),
    mlCacheFile,
  ];

  const useDefaults = bool(desc.useDefaults, true, 'descriptionScan.useDefaults');
  return {
    mode: oneOf(root.mode, ['enforce', 'monitor'] as const, 'enforce', 'mode'),
    audit: {
      enabled: bool(audit.enabled, true, 'audit.enabled'),
      file: filePath(audit.file, 'mcp-firewall-audit.jsonl', baseDir, 'audit.file'),
      logAllowed: bool(audit.logAllowed, true, 'audit.logAllowed'),
      siem: compileSiem(audit.siem, baseDir),
      notify: compileNotify(audit.notify),
    },
    tools: {
      default: oneOf(tools.default, ['allow', 'deny', 'ask'] as const, 'allow', 'tools.default'),
      rules: rules.map((r, i) => compileRule(r, `tools.rules[${i}]`, baseDir)),
    },
    methods: {
      deny: (strList(methods.deny, 'methods.deny') ?? []).map(globToRegExp),
    },
    descriptionScan: {
      enabled: bool(desc.enabled, true, 'descriptionScan.enabled'),
      action: oneOf(desc.action, ['hide', 'warn'] as const, 'hide', 'descriptionScan.action'),
      hiddenUnicode: bool(desc.hiddenUnicode, true, 'descriptionScan.hiddenUnicode'),
      patterns: [
        ...(useDefaults ? DEFAULT_DESCRIPTION_PATTERNS.map((p, i) => regex(p, `default pattern ${i}`)) : []),
        ...regexList(desc.patterns, 'descriptionScan.patterns'),
      ],
    },
    sampling: {
      maxPerMinute: num(sampling.maxPerMinute, 10, 0, 1_000_000, 'sampling.maxPerMinute'),
      maxPerSession: num(sampling.maxPerSession, 200, 0, 1_000_000_000, 'sampling.maxPerSession'),
      maxTokensPerRequest: num(sampling.maxTokensPerRequest, 4096, 0, 10_000_000, 'sampling.maxTokensPerRequest'),
      maxTokensPerSession: num(sampling.maxTokensPerSession, 100_000, 0, 1_000_000_000_000, 'sampling.maxTokensPerSession'),
    },
    decoding: { enabled: bool(decoding.enabled, true, 'decoding.enabled') },
    hiddenText: {
      action: oneOf(hiddenText.action, ['strip', 'block', 'warn', 'off'] as const, 'strip', 'hiddenText.action'),
    },
    pinning: {
      enabled: bool(pinning.enabled, true, 'pinning.enabled'),
      file: filePath(pinning.file, 'mcp-firewall-pins.json', baseDir, 'pinning.file'),
      onChange: oneOf(pinning.onChange, ['hide', 'warn'] as const, 'hide', 'pinning.onChange'),
      onNew: oneOf(pinning.onNew, ['allow', 'hide'] as const, 'allow', 'pinning.onNew'),
      onNameCollision: oneOf(pinning.onNameCollision, ['hide', 'warn', 'off'] as const, 'warn', 'pinning.onNameCollision'),
      serverCode: oneOf(pinning.serverCode, ['block', 'warn', 'off'] as const, 'block', 'pinning.serverCode'),
      prompts: oneOf(pinning.prompts, ['block', 'warn', 'off'] as const, 'block', 'pinning.prompts'),
    },
    approval: {
      timeoutSeconds: num(approval.timeoutSeconds, 120, 1, 86_400, 'approval.timeoutSeconds'),
      fallback: oneOf(approval.fallback, ['deny', 'allow'] as const, 'deny', 'approval.fallback'),
      remember: bool(approval.remember, true, 'approval.remember'),
    },
    taint: compileTaint(taint, baseDir),
    sandbox: compileSandbox(root.sandbox, baseDir, stateFiles),
    dlp: {
      enabled: bool(dlp.enabled, true, 'dlp.enabled'),
      scanRequests: bool(dlp.scanRequests, true, 'dlp.scanRequests'),
      scanResponses: bool(dlp.scanResponses, true, 'dlp.scanResponses'),
      action: oneOf(dlp.action, ['redact', 'block', 'warn'] as const, 'redact', 'dlp.action'),
      detectors,
    },
    ml: {
      enabled: bool(ml.enabled, false, 'ml.enabled'),
      model: filePath(ml.model, join('models', 'prompt-injection'), baseDir, 'ml.model'),
      definitionModel: mlDefinitionModel,
      dtype: oneOf(ml.dtype, ['fp32', 'fp16', 'q8'] as const, 'fp32', 'ml.dtype'),
      injectionLabel: (ml.injectionLabel as string | undefined) ?? 'INJECTION',
      threshold: num(ml.threshold, 0.9, 0, 1, 'ml.threshold'),
      failMode: oneOf(ml.failMode, ['closed', 'open'] as const, 'closed', 'ml.failMode'),
      chunkChars: num(ml.chunkChars, 1500, 100, 100_000, 'ml.chunkChars'),
      maxChunks: num(ml.maxChunks, 32, 1, 10_000, 'ml.maxChunks'),
      onTruncated: oneOf(ml.onTruncated, ['block', 'warn'] as const, 'warn', 'ml.onTruncated'),
      batchSize: mlBatchSize,
      threads: mlThreads,
      memoryArena: bool(ml.memoryArena, false, 'ml.memoryArena'),
      lazyLoad: bool(ml.lazyLoad, true, 'ml.lazyLoad'),
      cacheDefinitions: bool(ml.cacheDefinitions, true, 'ml.cacheDefinitions'),
      cacheFile: mlCacheFile,
      scan: {
        toolDefinitions: oneOf(mlScan.toolDefinitions, ['hide', 'warn', 'off'] as const, 'hide', 'ml.scan.toolDefinitions'),
        toolResults: oneOf(mlScan.toolResults, ['block', 'warn', 'off'] as const, 'block', 'ml.scan.toolResults'),
        promptResults: oneOf(mlScan.promptResults, ['block', 'warn', 'off'] as const, 'warn', 'ml.scan.promptResults'),
        serverRequests: oneOf(mlScan.serverRequests, ['block', 'warn', 'off'] as const, 'block', 'ml.scan.serverRequests'),
      },
      review: {
        nearMiss: num(mlReview.nearMiss, 0, 0, 1, 'ml.review.nearMiss'),
        sample: num(mlReview.sample, 0, 0, 1, 'ml.review.sample'),
      },
    },
  };
}

/** Loads a YAML policy; with no file, built-in defaults apply and state lives in ~/.mcp-firewall. */
export function loadPolicy(file?: string): Policy {
  if (!file) return compilePolicy({}, join(homedir(), '.mcp-firewall'));
  const path = resolve(file);
  let raw: unknown;
  try {
    raw = parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new PolicyError(`cannot read policy ${path}: ${(err as Error).message}`);
  }
  return compilePolicy(raw, dirname(path));
}
