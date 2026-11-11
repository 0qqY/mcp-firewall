import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * Remembers what the model scored a text, so a server whose definitions did not change since an earlier session
 * needs no model at start-up. The file holds one JSON line per text: a tag of the model (weights, dtype, label), a hash
 * of the text and the score. The text itself is never stored. Lines of other models are ignored and dropped when the
 * file is compacted.
 *
 * The file is part of the firewall's own state, like the pins: whoever can write it can make a definition look clean,
 * so a server must not be able to reach it (the sandbox refuses a mount that does).
 */
export class ScoreCache {
  /** Insertion order is age order: the oldest entries go first when the cache is full. */
  private readonly scores = new Map<string, number>();
  private readonly tag: string;
  private fileLines = 0;
  private writable = true;

  constructor(
    private readonly file: string,
    private readonly fingerprint: string,
    private readonly max = 20_000,
  ) {
    this.tag = createHash('sha256').update(fingerprint).digest('hex').slice(0, 12);
    this.load();
  }

  get size(): number {
    return this.scores.size;
  }

  private key(text: string): string {
    return createHash('sha256').update(this.fingerprint).update('\0').update(text).digest('base64url').slice(0, 32);
  }

  get(text: string): number | undefined {
    return this.scores.get(this.key(text));
  }

  /** Remembers `scores[i]` for `texts[i]`. A write that fails only costs the next session its shortcut. */
  set(texts: string[], scores: number[]): void {
    const lines: string[] = [];
    texts.forEach((text, i) => {
      const s = Math.round(scores[i] * 1e6) / 1e6;
      if (!(s >= 0 && s <= 1)) return;
      const k = this.key(text);
      if (this.scores.get(k) === s) return;
      this.scores.delete(k);
      this.scores.set(k, s);
      lines.push(JSON.stringify({ f: this.tag, k, s }));
    });
    this.trim();
    if (lines.length === 0 || !this.writable) return;
    try {
      mkdirSync(dirname(this.file), { recursive: true });
      appendFileSync(this.file, `${lines.join('\n')}\n`);
      this.fileLines += lines.length;
      if (this.fileLines > 2 * this.max) this.compact();
    } catch {
      this.writable = false;
    }
  }

  private trim(): void {
    for (const key of this.scores.keys()) {
      if (this.scores.size <= this.max) break;
      this.scores.delete(key);
    }
  }

  private load(): void {
    let raw: string;
    try {
      raw = readFileSync(this.file, 'utf8');
    } catch {
      return;
    }
    for (const line of raw.split('\n')) {
      if (!line) continue;
      this.fileLines++;
      try {
        const entry = JSON.parse(line) as { f?: unknown; k?: unknown; s?: unknown };
        if (entry.f !== this.tag || typeof entry.k !== 'string' || typeof entry.s !== 'number' || !(entry.s >= 0 && entry.s <= 1)) continue;
        this.scores.delete(entry.k);
        this.scores.set(entry.k, entry.s);
      } catch {
        // A line another process was still writing, or damage: skipped.
      }
    }
    this.trim();
    if (this.fileLines > 2 * this.max) this.compact();
  }

  /** Rewrites the file with what is still in memory. Another process appending meanwhile may lose a line: it is only a cache. */
  private compact(): void {
    const lines = [...this.scores].map(([k, s]) => JSON.stringify({ f: this.tag, k, s }));
    const temp = `${this.file}.${process.pid}.tmp`;
    try {
      writeFileSync(temp, lines.length > 0 ? `${lines.join('\n')}\n` : '');
      renameSync(temp, this.file);
      this.fileLines = lines.length;
    } catch {
      this.writable = false;
    }
  }
}
