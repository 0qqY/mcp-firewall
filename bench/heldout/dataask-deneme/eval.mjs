// usage: node dataask-eval.mjs <dist/src> <rows.jsonl> [split] [--miss N] [--fp N]
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve, join } from 'node:path';
const [dist, file, split] = process.argv.slice(2);
const n = (f) => (process.argv.includes(f) ? Number(process.argv[process.argv.indexOf(f) + 1]) : 0);
const { findDataAsks } = await import(new URL('./dataask.mjs', import.meta.url).href);
const { definitionText } = await import(pathToFileURL(join(resolve(dist), 'engine.js')).href);
let rows = readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
if (split && split !== '-') rows = rows.filter((r) => r.split === split);
let tp = 0, pos = 0, fp = 0, neg = 0; const miss = [], fps = [], by = {};
const t0 = performance.now();
for (const r of rows) {
  const text = r.definition ? definitionText(r.definition) : r.text;
  const k = findDataAsks(text);
  if (r.label === 1) { pos++; const c = (by[r.cls ?? '-'] ??= [0, 0]); c[1]++; if (k.length) { tp++; c[0]++; } else miss.push(r.id + ' ' + (r.cls ?? '') + ' | ' + text.replace(/\n/g, ' / ').slice(0, 400)); }
  else { neg++; if (k.length) { fp++; fps.push(r.id + ' ' + k + ' | ' + text.replace(/\n/g, ' / ').slice(0, 400)); } }
}
console.log(`recall ${tp}/${pos}  FP ${fp}/${neg}  (${Math.round(performance.now() - t0)} ms)`);
console.log(Object.entries(by).map(([k, [a, b]]) => `${k} ${a}/${b}`).join('  '));
miss.slice(0, n('--miss')).forEach((m) => console.log('MISS', m));
fps.slice(0, n('--fp')).forEach((m) => console.log('FP  ', m));
