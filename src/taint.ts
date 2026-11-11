import { createHash, randomUUID } from 'node:crypto';
import { appendFileSync, closeSync, mkdirSync, openSync, readdirSync, readSync, statSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { decodeEmbedded, deobfuscate, stripInvisible } from './decode.js';
import { extractKeys, extractMessageText, extractText } from './ml/classifier.js';

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
  /** ask: the user approves or refuses the call (see `approval`). */
  action: 'block' | 'warn' | 'ask';
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

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

/**
 * Undoes the wrapping text picks up on its way between tools: JSON string escapes (once or twice: "\\n" glued
 * a newline's "n" onto the next word), HTML tags and entities, and invisible format characters (zero-width,
 * soft hyphen, bidi) that split words without showing. Variation selectors are marks, not format characters,
 * so they go with `stripInvisible`: left in, they cut a base64 run in two and stop a camelCase split.
 * Fullwidth and other compatibility forms fold (NFKC).
 */
function unwrap(text: string): string {
  let out = text;
  for (let i = 0; i < 2 && /\\[nrtbfu"\\/]/.test(out); i++) {
    out = out
      .replace(/\\u([0-9a-fA-F]{4})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
      .replace(/\\[nrtbf]/g, ' ')
      .replace(/\\(["\\/])/g, '$1');
  }
  out = out
    .replace(/<\/?[A-Za-z][^<>]{0,200}>/g, ' ')
    .replace(/&#(x[0-9a-fA-F]{1,6}|\d{1,7});/g, (_, n: string) => {
      const code = n.startsWith('x') ? parseInt(n.slice(1), 16) : Number(n);
      return code <= 0x10ffff ? String.fromCodePoint(code) : ' ';
    })
    .replace(/&([a-z]+);/g, (m, name: string) => ENTITIES[name] ?? m);
  return stripInvisible(out.replace(/\p{Cf}/gu, '')).normalize('NFKC');
}

/**
 * Words compared case- and accent-blind (Turkish dotless and dotted i included, so "ISIK" meets "ışık").
 * With `split`, camelCase humps become words ("sendChatHistory" -> send chat history).
 */
function words(text: string, split: boolean): string[] {
  const t = split ? text.replace(/(\p{Ll}|\p{N})(\p{Lu})/gu, '$1 $2') : text;
  const folded = t.toLowerCase().replace(/ı/g, 'i').normalize('NFD').replace(/\p{M}/gu, '');
  return folded.match(/[\p{L}\p{N}]+/gu) ?? [];
}

const digest = (s: string): string => createHash('sha256').update(s).digest('base64url').slice(0, 16);

/** The forms a text is compared in: as written, de-obfuscated (look-alikes, l33t, s p a c e d letters), and decoded. */
function forms(text: string): string[] {
  const plain = unwrap(text);
  const clear = deobfuscate(plain);
  // base64 wrapped at fixed width (MIME, PEM) decodes only once the lines are joined again.
  // PEM-style armour lines end in dashes, which would otherwise glue onto the first line and shift it.
  const joined = plain.replace(/-----[A-Z0-9 ]+-----/g, '\n').replace(/([A-Za-z0-9+/=_-])\s*\r?\n\s*(?=[A-Za-z0-9+/=_-])/g, '$1');
  const decoded = new Set([...decodeEmbedded(plain), ...decodeEmbedded(joined)].map(unwrap));
  return [...new Set([plain, clear, ...decoded])];
}

/** Hashes of every SHINGLE_WORDS-word window of `w`. */
function shingles(w: string[], out: Set<string>): void {
  for (let i = 0; i + SHINGLE_WORDS <= w.length; i++) out.add(digest(w.slice(i, i + SHINGLE_WORDS).join(' ')));
}

/**
 * Fingerprints of a text: hashed word shingles plus key-like single words, over each of its forms. Only
 * hashes are kept, so the tracker never holds (or writes to disk) the data it protects.
 */
export function fingerprints(text: string, before: string[] = []): Set<string> {
  const out = new Set<string>();
  for (const [i, form] of forms(text).entries()) {
    // Words carried over from earlier sink calls join the first form only, so text cut into short pieces
    // across several calls still forms whole shingles.
    shingles(i === 0 ? [...before, ...words(form, true)] : words(form, true), out);
    for (const t of words(form, false)) if (RARE_TOKEN.test(t)) out.add(digest(t));
  }
  return out;
}

/** The last words a sink sent, kept so the next call is checked as a continuation of it. */
const tailWords = (text: string, prev: string[]): string[] => [...prev, ...words(unwrap(text), true)].slice(-(SHINGLE_WORDS - 1));

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
  /** Last words that went out through content sinks, so a text cut into short pieces is still caught. */
  private sentTail: string[] = [];
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
      // Only hashes the session did not hold yet go to the shared file; a line with none still renews the label.
      const added = this.add({ label, server: this.server, tool, at, hashes });
      this.publish({ label, tool, at, hashes: added });
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
    // Everything the call carries counts, whatever a field is called: `_meta`, a media block's side fields, a text blob.
    const text = extractMessageText(args);
    const sent = fingerprints(text, this.sentTail);
    // Property names ride as data too (a sentence or a token can be a key). They are fingerprinted on their own, so
    // field names never enter the word stream that joins text cut into pieces over several calls.
    for (const h of fingerprints(extractKeys(args))) sent.add(h);
    let best: TaintFlow | undefined;
    for (const mark of live) {
      let matches = 0;
      for (const h of sent) if (mark.hashes.has(h)) matches++;
      if (matches >= this.config.minMatches && matches > (best?.matches ?? 0)) best = { ...this.describe(mark), when: 'content', matches };
    }
    // Only text that was let out continues: a refused call never reached the recipient.
    if (!best) this.sentTail = tailWords(text, this.sentTail);
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

  /**
   * Merges into the mark with the same label and origin, so repeated reads do not pile up; returns the
   * hashes that were new.
   */
  private add(mark: Mark): Set<string> {
    const same = this.marks.find((m) => m.label === mark.label && m.server === mark.server && m.tool === mark.tool);
    if (!same) {
      const hashes = new Set([...mark.hashes].slice(0, MAX_HASHES));
      this.marks.push({ ...mark, hashes });
      return hashes;
    }
    same.at = Math.max(same.at, mark.at);
    const added = new Set<string>();
    for (const h of mark.hashes) {
      if (same.hashes.size >= MAX_HASHES) break;
      if (!same.hashes.has(h)) {
        same.hashes.add(h);
        added.add(h);
      }
    }
    return added;
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
