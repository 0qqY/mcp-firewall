// Metrics for a score.mjs result file on an external rows file (any jsonl in the heldout schema, labelled or all benign).
// usage: node bench/heldout/report-external.mjs --rows <rows.jsonl> --results <results.json> [--top 12] [--thresholds 0.3,0.5,0.9]
import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const opt = (name, def) => (args.includes(`--${name}`) ? args[args.indexOf(`--${name}`) + 1] : def);
const rows = readFileSync(opt('rows'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const res = JSON.parse(readFileSync(opt('results'), 'utf8'));
const score = new Map(res.results.map((r) => [r.id, r.score]));
const T = res.threshold;
const TOP = Number(opt('top', 12));
const extra = opt('thresholds', '0.5,0.9').split(',').map(Number);
const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : '-');
const text = (r) => String(r.text ?? `${r.definition.name}: ${r.definition.description}`).replace(/\s+/g, ' ');

const benign = rows.filter((r) => r.label === 0);
const attacks = rows.filter((r) => r.label === 1);
console.log(`${rows.length} rows (${attacks.length} attacks, ${benign.length} benign) scored by ${res.model}`);
const flagged = (list, t) => list.filter((r) => score.get(r.id) >= t).length;
for (const t of [T, ...extra]) {
  console.log(`threshold ${t}: benign flagged ${flagged(benign, t)}/${benign.length} (${pct(flagged(benign, t), benign.length)})` +
    (attacks.length ? `, attacks caught ${flagged(attacks, t)}/${attacks.length} (${pct(flagged(attacks, t), attacks.length)})` : ''));
}
const sorted = benign.map((r) => score.get(r.id)).sort((a, b) => a - b);
const q = (p) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
if (sorted.length) console.log(`benign score quantiles: p50 ${q(0.5).toFixed(4)}  p90 ${q(0.9).toFixed(4)}  p99 ${q(0.99).toFixed(4)}  max ${sorted[sorted.length - 1].toFixed(4)}`);

const byCls = new Map();
for (const r of rows) {
  const e = byCls.get(r.cls) ?? { benign: 0, benignFlagged: 0, attack: 0, attackFlagged: 0 };
  const hit = score.get(r.id) >= T;
  if (r.label === 0) { e.benign++; if (hit) e.benignFlagged++; } else { e.attack++; if (hit) e.attackFlagged++; }
  byCls.set(r.cls, e);
}
if (byCls.size > 1) {
  console.log(`\nper class at ${T}:`);
  for (const [cls, e] of [...byCls].sort((a, b) => b[1].benign + b[1].attack - a[1].benign - a[1].attack)) {
    console.log(`  ${cls.padEnd(28)} benign ${String(e.benign).padStart(5)} flagged ${pct(e.benignFlagged, e.benign).padStart(6)}` + (e.attack ? `   attacks ${e.attack} caught ${pct(e.attackFlagged, e.attack)}` : ''));
  }
}
const tops = rows.filter((r) => (r.label === 0 ? score.get(r.id) >= T : false)).sort((a, b) => score.get(b.id) - score.get(a.id)).slice(0, TOP);
if (tops.length) console.log(`\nhighest scoring benign rows (false positives, first ${tops.length}):`);
for (const r of tops) console.log(`  ${score.get(r.id).toFixed(3)} ${r.id} [${r.cls}] ${text(r).slice(0, 210)}`);
const missed = attacks.filter((r) => score.get(r.id) < T);
if (missed.length) console.log(`\nmissed attacks:`);
for (const r of missed) console.log(`  ${score.get(r.id).toFixed(3)} ${r.id} [${r.cls}] ${text(r).slice(0, 210)}`);
