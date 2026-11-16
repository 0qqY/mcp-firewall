// Scores heldout-v1.jsonl with an ML model the way the firewall does: same text preparation per channel (hidden-character strip,
// product text extractors, redaction-marker and image neutralising, decoding, channel tag, 1500-character windows).
// usage: node bench/heldout/score.mjs --dist <dist/src folder> --model <model dir> --out <results.json> [--rows heldout-v1.jsonl] [--dtype fp32|q8]
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (name, def) => (args.includes(`--${name}`) ? args[args.indexOf(`--${name}`) + 1] : def);
const DIST = resolve(opt('dist', join(HERE, '..', '..', 'dist', 'src')));
const MODEL = resolve(opt('model'));
const OUT = opt('out') ? resolve(opt('out')) : undefined; // not needed with --dump
const ROWS = resolve(opt('rows', join(HERE, 'heldout-v1.jsonl')));
const DTYPE = opt('dtype', 'fp32');
const load = (f) => import(pathToFileURL(join(DIST, f)).href);

const { compilePolicy } = await load('policy.js');
const { loadTransformersClassifier } = await load('ml/transformers.js');
const { extractMlText, extractText, scoreTexts } = await load('ml/classifier.js');
const { parameterNamesText, stripHiddenChars } = await load('engine.js');
const { stripImageData, withDecoded } = await load('decode.js');
const { REDACTION_MARKER } = await load('dlp.js');

const policy = compilePolicy({ ml: { enabled: true, model: MODEL, dtype: DTYPE, injectionLabel: 'INJECTION', threshold: 0.3, chunkChars: 1500, maxChunks: 32 }, decoding: { enabled: true } }, mkdtempSync(join(tmpdir(), 'heldout-')));
const { ml } = policy;

/** The text the classifier gets, built like proxy.ts builds it for each place a text can come from. */
function productText(r) {
  const definitionMlText = (def) => [extractText(def), parameterNamesText(def)].join('\n');
  if (r.definition) return definitionMlText(r.definition);
  if (r.kind === 'instructions') return definitionMlText(r.text);
  const wrapped =
    r.kind === 'prompt_template' ? { messages: [{ role: 'user', content: { type: 'text', text: r.text } }] }
    : r.kind === 'elicitation' ? { message: r.text, requestedSchema: { type: 'object', properties: {} } }
    : r.kind === 'sampling' ? { messages: [{ role: 'user', content: { type: 'text', text: r.text } }], maxTokens: 200 }
    : { content: [{ type: 'text', text: r.text }] };
  return extractMlText(stripHiddenChars(wrapped).value); // hiddenText.action defaults to strip, which runs before the model
}

const rows = readFileSync(ROWS, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
// --dump <file>: write the prepared text of every row (what the classifier would read, before windowing) and stop. score_torch.py
// scores such a dump with any Hugging Face model, so models that have no ONNX export get exactly the product's text.
if (opt('dump')) {
  const lines = rows.map((r) => {
    const t = stripImageData(productText(r).replace(REDACTION_MARKER, 'redacted'));
    return JSON.stringify({ id: r.id, channel: r.channel, text: policy.decoding.enabled ? withDecoded(t) : t });
  });
  writeFileSync(resolve(opt('dump')), lines.join('\n') + '\n');
  console.log(`wrote ${lines.length} prepared texts to ${resolve(opt('dump'))}`);
  process.exit(0);
}
console.log(`loading ${MODEL.split(/[\\/]/).pop()} ...`);
const started = Date.now();
const classifier = await loadTransformersClassifier(ml.model, ml);
console.log(`loaded in ${Math.round((Date.now() - started) / 100) / 10} s; scoring ${rows.length} rows`);

const results = new Array(rows.length);
for (const channel of ['definition', 'output', 'prompt']) {
  const idx = rows.map((r, i) => [r, i]).filter(([r]) => (r.channel === channel)).map(([, i]) => i);
  const texts = idx.map((i) => {
    const t = stripImageData(productText(rows[i]).replace(REDACTION_MARKER, 'redacted'));
    return policy.decoding.enabled ? withDecoded(t) : t;
  });
  const scores = await scoreTexts(classifier, texts, ml, channel);
  idx.forEach((i, k) => { results[i] = { id: rows[i].id, score: scores[k].score }; });
}
writeFileSync(OUT, JSON.stringify({ model: MODEL.split(/[\\/]/).pop(), threshold: ml.threshold, scoredAt: new Date().toISOString(), results }, null, 1));
console.log(`wrote ${OUT}; peak resident memory ${Math.round(process.resourceUsage().maxRSS / 1024)} MB`);
