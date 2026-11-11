// Side by side metrics of several score.mjs result files on heldout-v1.jsonl.
// usage: node bench/heldout/compare.mjs <results.json> [<results.json> ...] [--md <out.md>]
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const mdOut = argv.includes('--md') ? argv[argv.indexOf('--md') + 1] : undefined;
const files = argv.filter((a, i) => !a.startsWith('--') && argv[i - 1] !== '--md');
const rows = readFileSync(join(HERE, 'heldout-v1.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : '-');

function metrics(file) {
  const res = JSON.parse(readFileSync(file, 'utf8'));
  const score = new Map(res.results.map((r) => [r.id, r.score]));
  const T = res.threshold;
  const attacks = rows.filter((r) => r.label === 1);
  const benign = rows.filter((r) => r.label === 0);
  const hit = (list) => list.filter((r) => score.get(r.id) >= T).length;
  const a = attacks.map((r) => score.get(r.id));
  const b = benign.map((r) => score.get(r.id)).sort((x, y) => y - x);
  let wins = 0;
  for (const x of a) for (const y of b) wins += x > y ? 1 : x === y ? 0.5 : 0;
  // recall at a false positive budget: at most floor(fpr * n) benign texts may score above the cut
  const recallAt = (fpr) => {
    const cut = b[Math.min(b.length - 1, Math.floor(fpr * b.length))];
    return a.filter((s) => s > cut).length;
  };
  let clean = 0;
  for (const r of attacks.filter((x) => x.pair)) if (score.get(r.id) >= T && score.get(r.pair) < T) clean++;
  const channel = (c) => ({ atk: attacks.filter((r) => r.channel === c), ben: benign.filter((r) => r.channel === c) });
  const per = Object.fromEntries(['definition', 'output', 'prompt'].map((c) => {
    const { atk, ben } = channel(c);
    return [c, `${pct(hit(atk), atk.length)} / ${pct(hit(ben), ben.length)}`];
  }));
  return {
    model: res.model,
    T,
    recall: pct(hit(attacks), attacks.length),
    fpr: pct(hit(benign), benign.length),
    auc: (wins / (a.length * b.length)).toFixed(3),
    r1: pct(recallAt(0.01), attacks.length),
    r5: pct(recallAt(0.05), attacks.length),
    clean: pct(clean, attacks.filter((x) => x.pair).length),
    per,
  };
}

const lines = [
  '| model | eşik | recall | FPR | AUC | recall @1% FPR | recall @5% FPR | temiz çift | definition (recall / FPR) | output | prompt |',
  '|---|---|---|---|---|---|---|---|---|---|---|',
];
for (const f of files) {
  const m = metrics(f);
  lines.push(`| ${m.model} | ${m.T} | ${m.recall} | ${m.fpr} | ${m.auc} | ${m.r1} | ${m.r5} | ${m.clean} | ${m.per.definition} | ${m.per.output} | ${m.per.prompt} |`);
}
console.log(lines.join('\n'));
if (mdOut) writeFileSync(mdOut, `${lines.join('\n')}\n`, 'utf8');
