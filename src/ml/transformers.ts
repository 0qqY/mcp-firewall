import { basename, dirname, sep } from 'node:path';
import type { Classifier } from './classifier.js';

export interface TransformersOptions {
  dtype: 'fp32' | 'fp16' | 'q8';
  /** Label the model uses for the positive class; the model is assumed to be binary. */
  injectionLabel: string;
  batchSize?: number;
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

  const classify = await lib.pipeline('text-classification', basename(modelDir), { dtype: opts.dtype, device: 'cpu' });
  const batchSize = opts.batchSize ?? 8;

  return {
    name: basename(modelDir),
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
