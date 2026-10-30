import { createHash, randomUUID } from 'node:crypto';
import { appendFileSync, closeSync, mkdirSync, openSync, readdirSync, readSync, statSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { decodeEmbedded } from './decode.js';
import { extractText } from './ml/classifier.js';

export interface TaintSource {
  pattern: string;
  match: RegExp;
  label: string;
}

export interface TaintSink {
  pattern: string;
  match: RegExp;
  /** Labels this sink refuses; empty means every label. */
  labels: string[];
  /** content: only when the arguments carry text a source returned | session: any call once the label is set. */
  when: 'content' | 'session';
}

export interface TaintConfig {
  enabled: boolean;
  action: 'block' | 'warn';
  /** server: labels stay in this proxy | shared: every proxy of the same client session sees them. */
  scope: 'server' | 'shared';
  ttlMinutes: number;
  dir: string;
  /** Label for results in which DLP found sensitive data; empty disables it. */
  dlpLabel: string;
  /** Matching fingerprints needed before content flows into a sink. */
  minMatches: number;
  sources: TaintSource[];
  sinks: TaintSink[];
}

/** Words per shingle: eight words in a row rarely repeat by chance but survive light rewording around them. */
const SHINGLE_WORDS = 8;
/** Single words long and mixed enough to be keys, tokens or IDs are fingerprinted on their own. */
const RARE_TOKEN = /^(?=.*\p{L})(?=.*\p{N})[\p{L}\p{N}]{16,}$/u;
/** Fingerprints kept per label and session, so a huge result cannot exhaust memory. */
const MAX_HASHES = 200_000;

const words = (text: string): string[] => text.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [];
const digest = (s: string): string => createHash('sha256').update(s).digest('base64url').slice(0, 16);

/**
 * Fingerprints of a text: hashed word shingles plus key-like single words. Only hashes are kept, so the
 * tracker never holds (or writes to disk) the data it protects.
 */
export function fingerprints(text: string): Set<string> {
  const out = new Set<string>();
  for (const part of [text, ...decodeEmbedded(text)]) {
    const w = words(part);
    for (let i = 0; i + SHINGLE_WORDS <= w.length; i++) out.add(digest(w.slice(i, i + SHINGLE_WORDS).join(' ')));
    for (const t of w) if (RARE_TOKEN.test(t)) out.add(digest(t));
  }
  return out;
}

interface Mark {
  label: string;
  server: string;
  tool: string;
  at: number;
  hashes: Set<string>;
}

export interface TaintFlow {
  label: string;
  server: string;
  tool: string;
  when: 'content' | 'session';
  matches: number;
}

/** Shared marks file of one client session; every proxy appends JSON lines and reads the others'. */
interface SharedFile {
  path: string;
  offset: number;
  partial: string;
}

/**
 * Session taint tracking: results of source tools label the session, and sink tools that would carry
 * labelled data out are refused. Each proxy guards one server, so with `scope: shared` the labels go
 * through a per-session file every proxy of the same client reads.
 */
export class TaintTracker {
  private readonly marks: Mark[] = [];
  private shared?: SharedFile;
  /** Tells this tracker's lines in the shared file from other proxies'. */
  private readonly id = randomUUID();
  now: () => number = Date.now;

  constructor(
    readonly config: TaintConfig,
    private readonly server = 'this server',
    session?: string,
  ) {
    if (config.scope === 'shared' && session) this.shared = this.openShared(session);
  }

  /** The session key: set MCP_FIREWALL_SESSION when a wrapper (npx, a shell) sits between client and firewall. */
  static sessionKey(): string {
    return (process.env.MCP_FIREWALL_SESSION ?? String(process.ppid)).replace(/[^\w.-]/g, '_');
  }

  isSink(tool: string): boolean {
    return this.config.sinks.some((s) => s.match.test(tool));
  }

  /** Labels a tool result: its own source label, and the DLP label when DLP found something in it. */
  markResult(tool: string, result: unknown, dlpFound: boolean): string[] {
    const labels = new Set(this.config.sources.filter((s) => s.match.test(tool)).map((s) => s.label));
    if (dlpFound && this.config.dlpLabel) labels.add(this.config.dlpLabel);
    if (labels.size === 0) return [];
    const hashes = fingerprints(extractText(result));
    const at = this.now();
    for (const label of labels) {
      this.add({ label, server: this.server, tool, at, hashes });
      this.publish({ label, tool, at, hashes });
    }
    return [...labels];
  }

  /** The labelled data a sink call would carry out, or undefined when the call may proceed. */
  checkSink(tool: string, args: unknown): TaintFlow | undefined {
    const sink = this.config.sinks.find((s) => s.match.test(tool));
    if (!sink) return undefined;
    this.refresh();
    const live = this.marks.filter((m) => this.fresh(m) && (sink.labels.length === 0 || sink.labels.includes(m.label)));
    if (live.length === 0) return undefined;
    if (sink.when === 'session') return { ...this.describe(live[live.length - 1]), when: 'session', matches: 0 };
    const sent = fingerprints(extractText(args));
    let best: TaintFlow | undefined;
    for (const mark of live) {
      let matches = 0;
      for (const h of sent) if (mark.hashes.has(h)) matches++;
      if (matches >= this.config.minMatches && matches > (best?.matches ?? 0)) best = { ...this.describe(mark), when: 'content', matches };
    }
    return best;
  }

  /** Labels currently held, for the audit log and tests. */
  labels(): string[] {
    this.refresh();
    return [...new Set(this.marks.filter((m) => this.fresh(m)).map((m) => m.label))];
  }

  private describe(m: Mark): Omit<TaintFlow, 'when' | 'matches'> {
    return { label: m.label, server: m.server, tool: m.tool };
  }

  private fresh(m: Mark): boolean {
    return this.config.ttlMinutes <= 0 || this.now() - m.at < this.config.ttlMinutes * 60_000;
  }

  /** Merges into the newest mark with the same label and origin, so repeated reads do not pile up. */
  private add(mark: Mark): void {
    const same = this.marks.find((m) => m.label === mark.label && m.server === mark.server && m.tool === mark.tool);
    if (!same) {
      this.marks.push({ ...mark, hashes: new Set([...mark.hashes].slice(0, MAX_HASHES)) });
      return;
    }
    same.at = Math.max(same.at, mark.at);
    for (const h of mark.hashes) {
      if (same.hashes.size >= MAX_HASHES) break;
      same.hashes.add(h);
    }
  }

  private openShared(session: string): SharedFile {
    mkdirSync(this.config.dir, { recursive: true });
    // Files of sessions that ended long ago only cost disk; nothing in them is still live.
    const ttl = Math.max(this.config.ttlMinutes, 60) * 60_000;
    for (const f of readdirSync(this.config.dir)) {
      const p = join(this.config.dir, f);
      try {
        if (f.endsWith('.jsonl') && Date.now() - statSync(p).mtimeMs > ttl) unlinkSync(p);
      } catch {
        // Another proxy removed it first.
      }
    }
    return { path: join(this.config.dir, `${session}.jsonl`), offset: 0, partial: '' };
  }

  private publish(entry: { label: string; tool: string; at: number; hashes: Set<string> }): void {
    if (!this.shared) return;
    const line = { id: this.id, server: this.server, label: entry.label, tool: entry.tool, at: entry.at, h: [...entry.hashes] };
    mkdirSync(dirname(this.shared.path), { recursive: true });
    appendFileSync(this.shared.path, `${JSON.stringify(line)}\n`);
  }

  /** Reads marks other proxies appended since the last read. */
  private refresh(): void {
    const shared = this.shared;
    if (!shared) return;
    let size: number;
    try {
      size = statSync(shared.path).size;
    } catch {
      return;
    }
    if (size < shared.offset) Object.assign(shared, { offset: 0, partial: '' });
    if (size === shared.offset) return;
    const buf = Buffer.alloc(size - shared.offset);
    const fd = openSync(shared.path, 'r');
    try {
      readSync(fd, buf, 0, buf.length, shared.offset);
    } finally {
      closeSync(fd);
    }
    shared.offset = size;
    const lines = (shared.partial + buf.toString('utf8')).split('\n');
    shared.partial = lines.pop() ?? '';
    for (const line of lines) {
      try {
        const e = JSON.parse(line);
        if (e.id === this.id || typeof e.label !== 'string' || !Array.isArray(e.h)) continue;
        this.add({ label: e.label, server: String(e.server), tool: String(e.tool), at: Number(e.at), hashes: new Set(e.h) });
      } catch {
        // A torn or foreign line; the rest of the file still counts.
      }
    }
  }
}
