import { isPayload, payloadText } from '../decode.js';
import { isObject } from '../jsonrpc.js';

/**
 * What the caller knows about a batch of texts. `stable`: the same texts come back session after session (tool,
 * prompt and resource definitions, server instructions), so a classifier may remember their scores.
 */
export interface ScoreHint {
  stable?: boolean;
}

/** A prompt-injection model. Implementations must return one probability per input, in order. */
export interface Classifier {
  readonly name: string;
  /** The model was trained with a channel tag in front of each input (see CHANNEL_TAGS). */
  readonly channelTags?: boolean;
  injectionScores(texts: string[], hint?: ScoreHint): Promise<number[]>;
}

/**
 * Where a text reached the firewall. The same sentence means different things in each: a tool definition and a
 * prompt template address the model by design, a tool result should not. Must match training/channels.py.
 */
export type Channel = 'definition' | 'output' | 'prompt';
export const CHANNEL_TAGS: Record<Channel, string> = {
  definition: '[tool definition]',
  output: '[tool output]',
  prompt: '[prompt template]',
};

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

/** Scores many texts with a single batched classifier call; a channel-tagged model gets the tag on every chunk. */
export async function scoreTexts(classifier: Classifier, texts: string[], opts: ChunkOptions, channel: Channel = 'output'): Promise<TextScore[]> {
  const prefix = classifier.channelTags ? `${CHANNEL_TAGS[channel]}\n` : '';
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

  // Only definitions repeat from one session to the next; a result is seen once.
  const scores = await classifier.injectionScores(prefix ? chunks.map((c) => prefix + c) : chunks, { stable: channel === 'definition' });
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

/**
 * `message` is for what a message puts in front of the model (a result, an error, a prompt, a server request, the
 * arguments of a call): there every field counts, whatever it is called. A definition keeps `_meta` and media blocks
 * out of its text, because icons and UI metadata sit there.
 */
function collectText(value: unknown, readJson: boolean, message: boolean): string {
  const parts = new Set<string>();
  // `inData`: inside JSON a string held, where the protocol's binary and `_meta` fields mean nothing.
  const walk = (v: unknown, inData: boolean): void => {
    if (typeof v === 'string') {
      const data = readJson ? parseContainer(v) : undefined;
      if (data === undefined) parts.add(v);
      else walk(data, true);
    } else if (Array.isArray(v)) v.forEach((x) => walk(x, inData));
    else if (isObject(v)) {
      const media = v.type === 'image' || v.type === 'audio';
      if (!inData && !message && media) return;
      for (const [key, x] of Object.entries(v)) {
        if (!inData && !message && (key === 'blob' || key === '_meta')) continue;
        if (!inData && message) {
          // A binary payload has nothing to read; one that decodes to text is read as the text it is.
          if (typeof x === 'string' && isPayload(v, key, x)) {
            const text = payloadText(x);
            if (text) parts.add(text);
            continue;
          }
          // What a media block is, not what it says.
          if (media && (key === 'type' || key === 'mimeType')) continue;
        }
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
  return collectText(value, false, false);
}

/**
 * Like extractText, for what a message puts in front of the model: `_meta`, the side fields of a media block and a
 * blob that is text count too; only binary payloads are skipped. (A client may hand the model more than the
 * `content` it is meant to, and a field called `blob` or `_meta` is no proof of binary data.)
 */
export function extractMessageText(value: unknown): string {
  return collectText(value, false, true);
}

/** Every object key of a JSON value, one per line and without duplicates: a property name carries data like any value. */
export function extractKeys(value: unknown): string {
  const keys = new Set<string>();
  const walk = (v: unknown): void => {
    if (Array.isArray(v)) v.forEach(walk);
    else if (isObject(v)) {
      for (const [key, x] of Object.entries(v)) {
        keys.add(key);
        walk(x);
      }
    }
  };
  walk(value);
  return [...keys].join('\n');
}

/**
 * The text the classifier reads from a message: like extractText, but a string holding a JSON object or
 * array is read as its values, plus any key that is not a plain field name, instead of as raw JSON.
 * Benign API responses (a commit list, an issue) scored as injections on their JSON syntax and
 * metadata. Neighbouring values stay on adjacent lines, so text split across fields is read together.
 */
export function extractMlText(value: unknown): string {
  return collectText(value, true, true);
}
