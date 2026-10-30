import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { parse } from 'yaml';
import { buildDetectors, type Detector } from './dlp.js';
import { globToRegExp } from './glob.js';
import { compilePathPattern, type PathConstraint } from './paths.js';
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

export interface Policy {
  mode: Mode;
  audit: { enabled: boolean; file: string; logAllowed: boolean };
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
    dtype: 'fp32' | 'fp16' | 'q8';
    injectionLabel: string;
    threshold: number;
    failMode: 'closed' | 'open';
    chunkChars: number;
    maxChunks: number;
    /** What to do with text longer than `maxChunks` chunks, whose middle is not scanned. */
    onTruncated: 'block' | 'warn';
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

  const useDefaults = bool(desc.useDefaults, true, 'descriptionScan.useDefaults');
  return {
    mode: oneOf(root.mode, ['enforce', 'monitor'] as const, 'enforce', 'mode'),
    audit: {
      enabled: bool(audit.enabled, true, 'audit.enabled'),
      file: filePath(audit.file, 'mcp-firewall-audit.jsonl', baseDir, 'audit.file'),
      logAllowed: bool(audit.logAllowed, true, 'audit.logAllowed'),
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
      dtype: oneOf(ml.dtype, ['fp32', 'fp16', 'q8'] as const, 'fp32', 'ml.dtype'),
      injectionLabel: (ml.injectionLabel as string | undefined) ?? 'INJECTION',
      threshold: num(ml.threshold, 0.9, 0, 1, 'ml.threshold'),
      failMode: oneOf(ml.failMode, ['closed', 'open'] as const, 'closed', 'ml.failMode'),
      chunkChars: num(ml.chunkChars, 1500, 100, 100_000, 'ml.chunkChars'),
      maxChunks: num(ml.maxChunks, 32, 1, 10_000, 'ml.maxChunks'),
      onTruncated: oneOf(ml.onTruncated, ['block', 'warn'] as const, 'warn', 'ml.onTruncated'),
      scan: {
        toolDefinitions: oneOf(mlScan.toolDefinitions, ['hide', 'warn', 'off'] as const, 'hide', 'ml.scan.toolDefinitions'),
        toolResults: oneOf(mlScan.toolResults, ['block', 'warn', 'off'] as const, 'block', 'ml.scan.toolResults'),
        promptResults: oneOf(mlScan.promptResults, ['block', 'warn', 'off'] as const, 'warn', 'ml.scan.promptResults'),
        serverRequests: oneOf(mlScan.serverRequests, ['block', 'warn', 'off'] as const, 'block', 'ml.scan.serverRequests'),
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
