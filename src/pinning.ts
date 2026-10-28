import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { isObject, type JsonObject } from './jsonrpc.js';

export type PinStatus = 'new' | 'pending' | 'match' | 'changed';

/** server id -> tool name -> pin of the tool (toolPin) */
type PinFile = Record<string, Record<string, string>>;

/** Pin-file key under which a server's code fingerprint is stored; '@' cannot start an npm-style tool name. */
export const CODE_KEY = '@server-code';

/** Pin-file key prefix for prompt templates, kept apart from tool names the same way. */
export const PROMPT_PREFIX = '@prompt:';

/** Replaces argument values in a prompt template, so its hash does not depend on what the user filled in. */
const ARG_MARKER = '{{arg}}';

/** Keys whose values are protocol structure, not text a template interpolates into. */
const STRUCTURAL_KEYS = new Set(['role', 'type', 'mimeType']);

function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (typeof v === 'object' && v !== null) {
    const entries = Object.entries(v)
      .filter(([, x]) => x !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, x]) => `${JSON.stringify(k)}:${canonicalJson(x)}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

const sha256 = (value: unknown): string => createHash('sha256').update(canonicalJson(value)).digest('hex');

/** Hashes everything the model sees about a tool but its output schema; `_meta` is transport bookkeeping and excluded. */
export function hashTool(tool: JsonObject): string {
  const { _meta, outputSchema, ...definition } = tool;
  return sha256(definition);
}

/**
 * A tool's pin: its definition hash, plus `+` and the hash of its output schema when it has one. The
 * output schema is pinned apart because protocol versions disagree on sending it (2026-07-28 adds one
 * to every tool of the same server), and one pin has to hold for clients on either version.
 */
export function toolPin(tool: JsonObject): string {
  return tool.outputSchema === undefined ? hashTool(tool) : `${hashTool(tool)}+${sha256(tool.outputSchema)}`;
}

/** The pin written before the output schema was split off: one hash over the whole definition. */
function legacyToolPin(tool: JsonObject): string {
  const { _meta, ...definition } = tool;
  return sha256(definition);
}

/**
 * One pin per prompt and set of filled-in arguments (`args` holds only non-empty values): leaving an
 * optional argument out may legitimately change the template.
 */
export function promptPinKey(name: string, args: Record<string, string>): string {
  const filled = Object.keys(args).sort();
  return `${PROMPT_PREFIX}${name}${filled.length > 0 ? `#${filled.join(',')}` : ''}`;
}

function argumentPattern(args: Record<string, string>): RegExp | undefined {
  const values = [...new Set(Object.values(args).filter((v) => v.length > 0))].sort((a, b) => b.length - a.length);
  if (values.length === 0) return undefined;
  const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Short values such as language codes would otherwise match inside words ("en" in "when").
  const alternatives = values.map((v) => (v.length < 4 ? `(?<![\\p{L}\\p{N}_])${escape(v)}(?![\\p{L}\\p{N}_])` : escape(v)));
  return new RegExp(alternatives.join('|'), 'gu');
}

/**
 * Hashes a `prompts/get` result as a template: the request's argument values are replaced by one
 * marker (longest first), so the hash changes when the server-written text does, not with each call.
 * `_meta` is excluded at every level.
 */
export function hashPromptTemplate(result: JsonObject, args: Record<string, string>): string {
  const pattern = argumentPattern(args);
  const normalize = (value: unknown, key?: string): unknown => {
    if (typeof value === 'string') return pattern && !STRUCTURAL_KEYS.has(key ?? '') ? value.replace(pattern, ARG_MARKER) : value;
    if (Array.isArray(value)) return value.map((v) => normalize(v));
    if (isObject(value)) return Object.fromEntries(Object.entries(value).filter(([k]) => k !== '_meta').map(([k, v]) => [k, normalize(v, k)]));
    return value;
  };
  return createHash('sha256').update(canonicalJson(normalize(result))).digest('hex');
}

/** The file holding hashes that were seen but not trusted yet, next to the pin file. */
export const pendingFile = (pinFile: string): string => pinFile.replace(/(\.json)?$/i, '.pending.json');

function readPins(file: string): PinFile {
  if (!existsSync(file)) return {};
  return JSON.parse(readFileSync(file, 'utf8')) as PinFile;
}

function writePins(file: string, pins: PinFile): void {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(pins, null, 2)}\n`);
}

/**
 * Trust-on-first-use store for tool definitions, server code and prompt templates. A changed
 * definition keeps its original pin, so it stays flagged until an operator approves it
 * (`mcp-firewall pins approve`).
 * Hashes that are changed, or new while new tools are held, are recorded in the pending file so the
 * operator approves exactly what was seen.
 */
export class PinStore {
  constructor(
    private readonly file: string,
    private readonly serverKey: string,
  ) {}

  /** `holdNew`: new tools are not trusted automatically but recorded as pending. */
  checkAll(tools: JsonObject[], holdNew = false): Map<string, PinStatus> {
    const pins = readPins(this.file);
    const server = pins[this.serverKey] ?? {};
    const result = new Map<string, PinStatus>();
    const pending: Record<string, string> = {};
    const settled: string[] = [];
    let dirty = false;
    for (const tool of tools) {
      const name = String(tool.name ?? '');
      const pin = toolPin(tool);
      const pinned = server[name];
      if (!pinned) {
        if (holdNew) {
          result.set(name, 'pending');
          pending[name] = pin;
        } else {
          server[name] = pin;
          result.set(name, 'new');
          dirty = true;
        }
        continue;
      }
      const [definition, output] = pin.split('+');
      const [pinnedDefinition, pinnedOutput] = pinned.split('+');
      if (pinned === pin || (pinnedDefinition === definition && output === undefined)) {
        result.set(name, 'match');
        settled.push(name);
      } else if (pinnedDefinition === definition && pinnedOutput === undefined) {
        // The first output schema of a pinned tool, sent to a client on a newer protocol version. Pinned
        // even when new tools are held: holding it would hide every trusted tool after a client upgrade.
        server[name] = pin;
        result.set(name, 'new');
        settled.push(name);
        dirty = true;
      } else if (pinned === legacyToolPin(tool)) {
        // Pinned before the output schema was split off, and the definition is the same.
        server[name] = pin;
        result.set(name, 'match');
        settled.push(name);
        dirty = true;
      } else {
        result.set(name, 'changed');
        // A client that is not sent the output schema cannot vouch for a new one, so the pinned one stays.
        pending[name] = output === undefined && pinnedOutput !== undefined ? `${definition}+${pinnedOutput}` : pin;
      }
    }
    if (dirty) {
      pins[this.serverKey] = server;
      writePins(this.file, pins);
    }
    this.recordPending(pending, settled);
    return result;
  }

  /** Same trust-on-first-use rule for the server's code fingerprint. */
  checkCode(hash: string): PinStatus {
    return this.checkOne(CODE_KEY, hash, false);
  }

  /** Same rule for one prompt template (`key` from promptPinKey); `holdNew` as in checkAll. */
  checkPrompt(key: string, hash: string, holdNew = false): PinStatus {
    return this.checkOne(key, hash, holdNew);
  }

  private checkOne(key: string, hash: string, holdNew: boolean): PinStatus {
    const pins = readPins(this.file);
    const server = pins[this.serverKey] ?? {};
    const pinned = server[key];
    if (pinned === hash) {
      this.recordPending({}, [key]);
      return 'match';
    }
    if (pinned || holdNew) {
      this.recordPending({ [key]: hash });
      return pinned ? 'changed' : 'pending';
    }
    pins[this.serverKey] = { ...server, [key]: hash };
    writePins(this.file, pins);
    return 'new';
  }

  /**
   * Other servers in the same pin file that already expose a tool with one of these names. Two tools
   * with the same name let a malicious server shadow a trusted one ("cross-server tool shadowing").
   */
  collisions(names: string[]): Map<string, string[]> {
    const pins = readPins(this.file);
    const result = new Map<string, string[]>();
    for (const name of names) {
      const others = Object.keys(pins).filter((server) => server !== this.serverKey && pins[server]?.[name] !== undefined);
      if (others.length > 0) result.set(name, others);
    }
    return result;
  }

  /** Adds `entries` to the pending file and drops `settled` names, whose current hash matches the pin again. */
  private recordPending(entries: Record<string, string>, settled: string[] = []): void {
    const file = pendingFile(this.file);
    if (Object.keys(entries).length === 0 && (settled.length === 0 || !existsSync(file))) return;
    const pending = readPins(file);
    const server = { ...(pending[this.serverKey] ?? {}) };
    const stale = settled.filter((name) => name in server);
    if (stale.length === 0 && Object.entries(entries).every(([k, v]) => server[k] === v)) return;
    for (const name of stale) delete server[name];
    Object.assign(server, entries);
    if (Object.keys(server).length > 0) pending[this.serverKey] = server;
    else delete pending[this.serverKey];
    writePins(file, pending);
  }
}

/** Pending entries per server, for `mcp-firewall pins list`. */
export function listPending(pinFile: string): PinFile {
  return readPins(pendingFile(pinFile));
}

/** Moves pending hashes (all of a server's, or only `names`) into the pin file; returns what was approved. */
export function approvePending(pinFile: string, serverKey: string, names?: string[]): string[] {
  const pendingPath = pendingFile(pinFile);
  const pending = readPins(pendingPath);
  const waiting = pending[serverKey] ?? {};
  const approved = Object.keys(waiting).filter((n) => !names || names.length === 0 || names.includes(n));
  if (approved.length === 0) return [];
  const pins = readPins(pinFile);
  pins[serverKey] = { ...(pins[serverKey] ?? {}) };
  for (const name of approved) {
    pins[serverKey][name] = waiting[name];
    delete waiting[name];
  }
  if (Object.keys(waiting).length === 0) delete pending[serverKey];
  writePins(pinFile, pins);
  writePins(pendingPath, pending);
  return approved;
}
