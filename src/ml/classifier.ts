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

/** Collects the human-readable text of a JSON value, skipping binary payloads and duplicates. */
export function extractText(value: unknown): string {
  const parts = new Set<string>();
  const walk = (v: unknown): void => {
    if (typeof v === 'string') parts.add(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (isObject(v)) {
      if (v.type === 'image' || v.type === 'audio') return;
      for (const [key, x] of Object.entries(v)) if (key !== 'blob' && key !== '_meta') walk(x);
    }
  };
  walk(value);
  return [...parts].join('\n');
}
