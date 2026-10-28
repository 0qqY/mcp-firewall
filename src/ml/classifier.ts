import { isObject } from '../jsonrpc.js';

/** A prompt-injection model. Implementations must return one probability per input, in order. */
export interface Classifier {
  readonly name: string;
  injectionScores(texts: string[]): Promise<number[]>;
}

export interface ChunkOptions {
  chunkChars: number;
  maxChunks: number;
}

export interface TextScore {
  /** Highest chunk score; 0 for empty text. */
  score: number;
  /** The highest-scoring chunk, whitespace-collapsed, for audit logs only. */
  excerpt: string;
  /** True when the text had more chunks than `maxChunks` and its middle was not scanned. */
  truncated: boolean;
}

/** Splits text into overlapping windows so the model's token limit never hides the end of a long text. */
export function chunkText(text: string, size: number): string[] {
  if (!text.trim()) return [];
  if (text.length <= size) return [text];
  const step = size - Math.floor(size / 8);
  const chunks: string[] = [];
  for (let start = 0; ; start += step) {
    chunks.push(text.slice(start, start + size));
    if (start + size >= text.length) break;
  }
  return chunks;
}

/** Keeps head and tail chunks when over budget: injections tend to sit at either end. */
function withinBudget(chunks: string[], max: number): string[] {
  if (chunks.length <= max) return chunks;
  const head = Math.ceil(max / 2);
  return [...chunks.slice(0, head), ...chunks.slice(chunks.length - (max - head))];
}

/** Scores many texts with a single batched classifier call. */
export async function scoreTexts(classifier: Classifier, texts: string[], opts: ChunkOptions): Promise<TextScore[]> {
  const owners: number[] = [];
  const chunks: string[] = [];
  const results: TextScore[] = texts.map((text, i) => {
    const all = chunkText(text, opts.chunkChars);
    const kept = withinBudget(all, opts.maxChunks);
    for (const chunk of kept) {
      owners.push(i);
      chunks.push(chunk);
    }
    return { score: 0, excerpt: '', truncated: kept.length < all.length };
  });
  if (chunks.length === 0) return results;

  const scores = await classifier.injectionScores(chunks);
  if (scores.length !== chunks.length) {
    throw new Error(`classifier returned ${scores.length} scores for ${chunks.length} inputs`);
  }
  scores.forEach((score, k) => {
    const result = results[owners[k]];
    if (score > result.score || !result.excerpt) {
      result.score = score;
      result.excerpt = chunks[k].replace(/\s+/g, ' ').trim();
    }
  });
  return results;
}

/** Object keys that name a field. Other keys (spaces, punctuation, over 40 characters) are text the model scan reads. */
const FIELD_NAME = /^[A-Za-z_$][\w$.-]{0,39}$/;

/** The JSON object or array a string holds, or undefined when it holds anything else. */
function parseContainer(text: string): unknown {
  const t = text.trim();
  if (!t.startsWith('{') && !t.startsWith('[')) return undefined;
  try {
    return JSON.parse(t);
  } catch {
    return undefined;
  }
}

function collectText(value: unknown, readJson: boolean): string {
  const parts = new Set<string>();
  // `inData`: inside JSON a string held, where the protocol's binary and `_meta` fields mean nothing.
  const walk = (v: unknown, inData: boolean): void => {
    if (typeof v === 'string') {
      const data = readJson ? parseContainer(v) : undefined;
      if (data === undefined) parts.add(v);
      else walk(data, true);
    } else if (Array.isArray(v)) v.forEach((x) => walk(x, inData));
    else if (isObject(v)) {
      if (!inData && (v.type === 'image' || v.type === 'audio')) return;
      for (const [key, x] of Object.entries(v)) {
        if (!inData && (key === 'blob' || key === '_meta')) continue;
        if (readJson && !FIELD_NAME.test(key)) parts.add(key);
        walk(x, inData);
      }
    }
  };
  walk(value, false);
  return [...parts].join('\n');
}

/** Collects the human-readable text of a JSON value, skipping binary payloads and duplicates. */
export function extractText(value: unknown): string {
  return collectText(value, false);
}

/**
 * The text the classifier reads from a message: like extractText, but a string holding a JSON object or
 * array is read as its values, plus any key that is not a plain field name, instead of as raw JSON.
 * Benign API responses (a commit list, an issue) scored as injections on their JSON syntax and
 * metadata. Neighbouring values stay on adjacent lines, so text split across fields is read together.
 */
export function extractMlText(value: unknown): string {
  return collectText(value, true);
}
