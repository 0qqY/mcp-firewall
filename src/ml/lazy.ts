import type { Classifier, ScoreHint } from './classifier.js';
import type { ScoreCache } from './scorecache.js';

/**
 * A classifier that reads its weights only when a text needs them. A model takes over a gigabyte per firewall process,
 * and a client starts one firewall per server, so loading it right after every handshake filled the machine's memory.
 *
 * Texts the caller calls stable (definitions, which come back unchanged session after session) are looked up in
 * `cache` first: a server whose definitions did not change needs no model at start-up. A miss loads the weights once
 * and scores only the texts the cache did not know.
 */
export function lazyClassifier(
  info: { name: string; channelTags?: boolean },
  load: () => Promise<Classifier>,
  cache?: Pick<ScoreCache, 'get' | 'set'>,
): Classifier {
  let loading: Promise<Classifier> | undefined;
  return {
    name: info.name,
    channelTags: info.channelTags,
    async injectionScores(texts: string[], hint?: ScoreHint): Promise<number[]> {
      const remember = cache !== undefined && hint?.stable === true;
      const scores: number[] = new Array<number>(texts.length);
      const missing: number[] = [];
      texts.forEach((text, i) => {
        const known = remember ? cache.get(text) : undefined;
        if (known === undefined) missing.push(i);
        else scores[i] = known;
      });
      if (missing.length === 0) return scores;

      const model = await (loading ??= load());
      const fresh = await model.injectionScores(
        missing.map((i) => texts[i]),
        hint,
      );
      if (fresh.length !== missing.length) throw new Error(`classifier returned ${fresh.length} scores for ${missing.length} inputs`);
      missing.forEach((i, k) => {
        scores[i] = fresh[k];
      });
      if (remember) {
        cache.set(
          missing.map((i) => texts[i]),
          fresh,
        );
      }
      return scores;
    },
  };
}
