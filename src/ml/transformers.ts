import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, join, sep } from 'node:path';
import type { Classifier } from './classifier.js';

/** Optional `mcp-firewall.json` next to config.json: how the model expects its input (`{"channelTags": true}`). */
function readModelInfo(modelDir: string): { channelTags?: unknown } {
  const file = join(modelDir, 'mcp-firewall.json');
  if (!existsSync(file)) return {};
  try {
    const info: unknown = JSON.parse(readFileSync(file, 'utf8'));
    return typeof info === 'object' && info !== null ? info : {};
  } catch (err) {
    throw new Error(`cannot read ${file}: ${(err as Error).message}`);
  }
}

export interface TransformersOptions {
  dtype: 'fp32' | 'fp16' | 'q8';
  /** Label the model uses for the positive class; the model is assumed to be binary. */
  injectionLabel: string;
  /** Texts per model call (default 2). A call pads every text to the longest one and its buffers grow with batch × length². */
  batchSize?: number;
  /** ONNX threads for one scan; 0 or unset lets the runtime take every core. */
  threads?: number;
  /** Keep ONNX's memory arena: see onnxSessionOptions. Off by default. */
  memoryArena?: boolean;
}

/** The weights file of each dtype, as transformers.js names them. */
const WEIGHTS: Record<TransformersOptions['dtype'], string> = {
  fp32: 'model.onnx',
  fp16: 'model_fp16.onnx',
  q8: 'model_quantized.onnx',
};

/**
 * ONNX Runtime session settings. Its memory arena and memory-pattern reuse keep every buffer a scan ever needed.
 * Measured on the default model (1.6 GB once loaded): after one long result (32 chunks) a process held 3.6 GB with
 * them and 1.5 GB without, and over the same workload (batch size 2) the scans took as long (53 s against 54 s).
 * A client starts one firewall per server, so what each process keeps adds up.
 */
export function onnxSessionOptions(opts: Pick<TransformersOptions, 'threads' | 'memoryArena'>): {
  intraOpNumThreads?: number;
  enableCpuMemArena: boolean;
  enableMemPattern: boolean;
} {
  const arena = opts.memoryArena === true;
  return {
    ...(opts.threads !== undefined && opts.threads > 0 ? { intraOpNumThreads: opts.threads } : {}),
    enableCpuMemArena: arena,
    enableMemPattern: arena,
  };
}

export interface ModelInfo {
  name: string;
  channelTags: boolean;
  /** Changes when the weights, tokenizer or config change, or the dtype or label does: what a remembered score depends on. */
  fingerprint: string;
}

/**
 * What the firewall needs to know about a model before it reads its weights: its name, whether it takes a channel
 * tag and a fingerprint of the files. Throws when a file is missing, so a broken model still stops the firewall at
 * start-up, not at the first scan.
 */
export function describeModel(modelDir: string, opts: Pick<TransformersOptions, 'dtype' | 'injectionLabel'>): ModelInfo {
  const files = [join(modelDir, 'onnx', WEIGHTS[opts.dtype]), join(modelDir, 'config.json'), join(modelDir, 'tokenizer.json')];
  const stamps = files.map((file) => {
    try {
      const { size, mtimeMs } = statSync(file);
      return `${size}:${Math.round(mtimeMs)}`;
    } catch {
      throw new Error(`model file not found: ${file}`);
    }
  });
  const name = basename(modelDir);
  const fingerprint = createHash('sha256').update([name, opts.dtype, opts.injectionLabel, ...stamps].join('|')).digest('hex');
  return { name, channelTags: readModelInfo(modelDir).channelTags === true, fingerprint };
}

interface Prediction {
  label: string;
  score: number;
}

/**
 * Loads a local Hugging Face text-classification model exported to ONNX
 * (config.json + tokenizer.json at the root, weights in onnx/model.onnx or onnx/model_quantized.onnx).
 * Remote downloads are disabled: the firewall never fetches models at runtime.
 */
export async function loadTransformersClassifier(modelDir: string, opts: TransformersOptions): Promise<Classifier> {
  let lib: typeof import('@huggingface/transformers');
  try {
    lib = await import('@huggingface/transformers');
  } catch (err) {
    throw new Error(`the ML layer needs @huggingface/transformers (npm install @huggingface/transformers): ${(err as Error).message}`);
  }
  lib.env.allowRemoteModels = false;
  lib.env.allowLocalModels = true;
  lib.env.localModelPath = `${dirname(modelDir)}${sep}`;

  const classify = await lib.pipeline('text-classification', basename(modelDir), {
    dtype: opts.dtype,
    device: 'cpu',
    session_options: onnxSessionOptions(opts),
  });
  const batchSize = Math.max(1, Math.floor(opts.batchSize ?? 2));

  return {
    name: basename(modelDir),
    channelTags: readModelInfo(modelDir).channelTags === true,
    async injectionScores(texts: string[]): Promise<number[]> {
      const scores: number[] = [];
      for (let i = 0; i < texts.length; i += batchSize) {
        const out = (await classify(texts.slice(i, i + batchSize))) as unknown as (Prediction | Prediction[])[];
        for (const item of out) {
          const top = Array.isArray(item) ? item[0] : item;
          scores.push(top.label === opts.injectionLabel ? top.score : 1 - top.score);
        }
      }
      return scores;
    },
  };
}
