// Builds heldout-v1.jsonl from the hand-written rows next to this file, validates it and checks, line by line, that no row
// already sits in a training or evaluation set of this project (first 80 normalised characters). Run: node bench/heldout/build.mjs
// Held-out means: never mix this file into training data; doing so makes every number measured on it meaningless.
import { createReadStream, existsSync, readdirSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import definitions from './rows-definition.mjs';
import outputs from './rows-output.mjs';
import { benignDefinition, benignInstructions, benignOutput, benignPrompt, obfuscated, prompts, requests } from './rows-misc.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const TRAINING = join(HERE, '..', '..', 'training', 'data');
const SOURCE = 'claude_heldout_v1';

// ---------------------------------------------------------------------------------------------------- encoders
const CYRILLIC = { a: 'а', e: 'е', o: 'о', p: 'р', c: 'с', x: 'х', y: 'у', A: 'А', E: 'Е', O: 'О', P: 'Р', C: 'С', X: 'Х', H: 'Н', B: 'В', M: 'М', T: 'Т', K: 'К' };
const LEET = { a: '4', e: '3', i: '1', o: '0', s: '5', t: '7' };
const rot13 = (s) => s.replace(/[A-Za-z]/g, (c) => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) + 13) % 26) + (c <= 'Z' ? 65 : 97)));
const ENCODERS = {
  none: (s) => s,
  base64: (s) => Buffer.from(s, 'utf8').toString('base64'),
  rot13,
  hex: (s) => Buffer.from(s, 'utf8').toString('hex'),
  zwsp: (s) => [...s].join('​'),
  homoglyph: (s) => [...s].map((c) => CYRILLIC[c] ?? c).join(''),
  spaced: (s) => [...s].join(' '),
  leet: (s) => s.replace(/[aeiost]/gi, (c) => LEET[c.toLowerCase()]),
  percent: (s) => [...Buffer.from(s, 'utf8')].map((b) => `%${b.toString(16).padStart(2, '0')}`).join(''),
  tags: (s) => [...s].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join(''),
  b64hex: (s) => Buffer.from(Buffer.from(s, 'utf8').toString('hex')).toString('base64'),
};

// ---------------------------------------------------------------------------------------------------- rows
const rows = [];
const counters = {};
function add(prefix, row) {
  counters[prefix] = (counters[prefix] ?? 0) + 1;
  const id = `${prefix}-${String(counters[prefix]).padStart(3, '0')}`;
  rows.push({ id, source: SOURCE, ...row });
  return id;
}

/** Entries come as attack, twin, attack, twin ...: links each twin to its attack. */
function paired(list, make) {
  for (let i = 0; i < list.length; i += 2) {
    const a = list[i];
    const b = list[i + 1];
    if (a[2] !== 1 && !(typeof a[2] === 'number' && a[2] === 1)) throw new Error(`pair ${i / 2}: first row must be the attack (${JSON.stringify(a).slice(0, 60)})`);
    const ida = make(a);
    const idb = make(b);
    rows.find((r) => r.id === ida).pair = idb;
    rows.find((r) => r.id === idb).pair = ida;
  }
}

const defOf = (name, description, params) => ({
  name,
  description,
  inputSchema: { type: 'object', properties: Object.fromEntries(Object.entries(params).map(([k, v]) => [k, { type: 'string', description: v }])) },
});

// tool definitions: [class, lang, label, name, description, params]
paired(definitions, ([cls, lang, label, name, description, params]) =>
  add('HD', { channel: 'definition', kind: 'definition', cls, lang, carrier: 'description', label, definition: defOf(name, description, params) }));

// tool outputs: [class, lang, carrier, label, text]
if (outputs.length % 2) throw new Error('rows-output.mjs must hold attack/twin pairs');
for (let i = 0; i < outputs.length; i += 2) {
  const [a, b] = [outputs[i], outputs[i + 1]];
  if (a[3] !== 1 || b[3] !== 0 || a[0] !== b[0] || a[1] !== b[1] || a[2] !== b[2]) throw new Error(`output pair ${i / 2} is not an attack followed by its twin (${a[0]})`);
  const ida = add('HO', { channel: 'output', kind: 'tool_result', cls: a[0], lang: a[1], carrier: a[2], label: 1, text: a[4] });
  const idb = add('HO', { channel: 'output', kind: 'tool_result', cls: b[0], lang: b[1], carrier: b[2], label: 0, text: b[4] });
  rows.find((r) => r.id === ida).pair = idb;
  rows.find((r) => r.id === idb).pair = ida;
}

// prompt templates: [class, lang, label, text]
paired(prompts, ([cls, lang, label, text]) => add('HP', { channel: 'prompt', kind: 'prompt_template', cls, lang, carrier: 'prompt', label, text }));

// server requests and instructions: [class, lang, label, kind, text]
paired(requests, ([cls, lang, label, kind, text]) =>
  add('HR', { channel: kind === 'instructions' ? 'definition' : 'output', kind, cls, lang, carrier: kind, label, text }));

// obfuscated payloads: [class, lang, encoder, prefix, suffix, attack, twin]
for (const [cls, lang, encoder, prefix, suffix, attack, twin] of obfuscated) {
  const enc = ENCODERS[encoder];
  if (!enc) throw new Error(`unknown encoder ${encoder}`);
  const ida = add('HX', { channel: 'output', kind: 'tool_result', cls, lang, carrier: `obfuscated:${encoder}`, label: 1, text: `${prefix}${enc(attack)}${suffix}`, encoder });
  const idb = add('HX', { channel: 'output', kind: 'tool_result', cls, lang, carrier: `obfuscated:${encoder}`, label: 0, text: `${prefix}${enc(twin)}${suffix}`, encoder });
  rows.find((r) => r.id === ida).pair = idb;
  rows.find((r) => r.id === idb).pair = ida;
}

// extra benign hard negatives (no attack twin)
for (const [lang, cls, text] of benignOutput) add('HB', { channel: 'output', kind: 'tool_result', cls, lang, carrier: 'hard_negative', label: 0, text });
for (const [lang, cls, text] of benignPrompt) add('HB', { channel: 'prompt', kind: 'prompt_template', cls, lang, carrier: 'hard_negative', label: 0, text });
for (const [lang, cls, name, description, params] of benignDefinition) add('HB', { channel: 'definition', kind: 'definition', cls, lang, carrier: 'hard_negative', label: 0, definition: defOf(name, description, params) });
for (const [lang, cls, text] of benignInstructions) add('HB', { channel: 'definition', kind: 'instructions', cls, lang, carrier: 'hard_negative', label: 0, text });

// ---------------------------------------------------------------------------------------------------- validation
const norm = (s) => String(s).toLowerCase().replace(/\s+/g, ' ').trim();
// A twin starts like its attack on purpose (minimal pair), so duplicates inside this set are found on the whole text,
// and the overlap with other sets (as in training/build_eval.py) on the first 80 characters.
const keyOf = (r) => norm(r.text ?? `${r.definition.name} ${r.definition.description} ${Object.values(r.definition.inputSchema.properties).map((p) => p.description).join(' ')}`);
const prefixOf = (r) => keyOf(r).slice(0, 80);
const problems = [];
const seen = new Map();
for (const r of rows) {
  if (!(r.text ?? r.definition)) problems.push(`${r.id}: empty`);
  if (r.text !== undefined && String(r.text).trim().length < 8) problems.push(`${r.id}: text shorter than 8 characters`);
  if (r.label !== 0 && r.label !== 1) problems.push(`${r.id}: bad label`);
  const k = keyOf(r);
  if (seen.has(k)) problems.push(`${r.id}: duplicate of ${seen.get(k)}`);
  else seen.set(k, r.id);
}
if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}

// Overlap with this project's training and evaluation data: stream every top-level jsonl under training/data.
const wanted = new Map();
for (const r of rows) wanted.set(prefixOf(r), [...(wanted.get(prefixOf(r)) ?? []), r.id]);
const overlaps = [];
let scanned = 0;
if (existsSync(TRAINING)) {
  const files = [...readdirSync(TRAINING).filter((f) => f.endsWith('.jsonl')).map((f) => join(TRAINING, f)), ...(existsSync(join(TRAINING, 'hf_build')) ? readdirSync(join(TRAINING, 'hf_build')).filter((f) => f.endsWith('.jsonl')).map((f) => join(TRAINING, 'hf_build', f)) : [])];
  for (const file of files) {
    const rl = createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) continue;
      scanned++;
      let text;
      try { text = JSON.parse(line).text; } catch { continue; }
      if (typeof text !== 'string') continue;
      const hit = wanted.get(norm(text).slice(0, 80));
      if (hit) overlaps.push(`${hit.join(', ')} also in ${file.split(/[\\/]/).slice(-1)[0]}`);
    }
  }
  console.log(`independence check: ${scanned} existing rows read from ${files.length} files, ${overlaps.length} overlaps`);
} else {
  console.log('independence check skipped: training/data not found');
}
if (overlaps.length) {
  console.error(overlaps.join('\n'));
  process.exit(2);
}

writeFileSync(join(HERE, 'heldout-v1.jsonl'), `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`, 'utf8');
const count = (f) => rows.filter(f).length;
console.log(`heldout-v1.jsonl: ${rows.length} rows | attacks ${count((r) => r.label === 1)} | benign ${count((r) => r.label === 0)} | paired ${count((r) => r.pair)} | hard negatives without twin ${count((r) => r.carrier === 'hard_negative')}`);
for (const key of ['channel', 'lang']) console.log(`${key}:`, JSON.stringify(Object.fromEntries([...new Set(rows.map((r) => r[key]))].map((v) => [v, count((r) => r[key] === v)]))));
