// Metrics for a score.mjs result file against heldout-v1.jsonl. usage: node bench/heldout/report.mjs <results.json> [--md <out.md>]
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const file = process.argv[2];
const mdOut = process.argv.includes('--md') ? process.argv[process.argv.indexOf('--md') + 1] : undefined;
const res = JSON.parse(readFileSync(file, 'utf8'));
const rows = readFileSync(join(HERE, 'heldout-v1.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const score = new Map(res.results.map((r) => [r.id, r.score]));
const T = res.threshold;
const out = [];
const log = (s = '') => { out.push(s); console.log(s); };
const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : '-');

function confusion(list, t = T) {
  let tp = 0, fn = 0, fp = 0, tn = 0;
  for (const r of list) {
    const flagged = score.get(r.id) >= t;
    if (r.label === 1) flagged ? tp++ : fn++;
    else flagged ? fp++ : tn++;
  }
  return { tp, fn, fp, tn };
}
const line = (name, list) => {
  const c = confusion(list);
  return `| ${name} | ${c.tp + c.fn} | ${pct(c.tp, c.tp + c.fn)} | ${c.tn + c.fp} | ${pct(c.fp, c.tn + c.fp)} |`;
};
const table = (title, key) => {
  log(`\n**${title}**\n`);
  log('| grup | saldırı | recall (TPR) | benign | false positive oranı |');
  log('|---|---|---|---|---|');
  for (const v of [...new Set(rows.map(key))].sort()) log(line(v, rows.filter((r) => key(r) === v)));
};

// ranking quality: AUC and the recall at fixed false positive rates
const attacks = rows.filter((r) => r.label === 1).map((r) => score.get(r.id));
const benign = rows.filter((r) => r.label === 0).map((r) => score.get(r.id)).sort((a, b) => a - b);
let wins = 0;
for (const a of attacks) for (const b of benign) wins += a > b ? 1 : a === b ? 0.5 : 0;
const auc = wins / (attacks.length * benign.length);
const recallAtFpr = (fpr) => {
  const t = benign[Math.min(benign.length - 1, Math.floor(benign.length * (1 - fpr)))];
  return { t, tpr: attacks.filter((s) => s > t).length / attacks.length };
};
const c = confusion(rows);
// Pair test at the threshold, not on raw scores: both texts of a pair often sit at ~1.000, where "attack score > twin score" is float noise.
const pairs = rows.filter((r) => r.label === 1 && r.pair);
const pairCount = { clean: 0, bothFlagged: 0, bothMissed: 0, inverted: 0 };
for (const r of pairs) {
  const a = score.get(r.id) >= T;
  const b = score.get(r.pair) >= T;
  pairCount[a && !b ? 'clean' : a && b ? 'bothFlagged' : !a && !b ? 'bothMissed' : 'inverted']++;
}

log(`## Held-out v1: ${res.model}, eşik ${T}\n`);
log(`${rows.length} satır: ${attacks.length} saldırı, ${benign.length} benign (${rows.filter((r) => r.carrier === 'hard_negative').length} tanesi twin'siz hard negative).\n`);
log(`- **Eşik ${T}'te:** recall ${pct(c.tp, c.tp + c.fn)} (${c.tp}/${c.tp + c.fn}), false positive oranı ${pct(c.fp, c.fp + c.tn)} (${c.fp}/${c.fp + c.tn}), precision ${pct(c.tp, c.tp + c.fp)}`);
log(`- **Sıralama:** AUC ${auc.toFixed(3)}; false positive %1'de recall ${pct(Math.round(recallAtFpr(0.01).tpr * attacks.length), attacks.length)} (eşik ${recallAtFpr(0.01).t.toFixed(3)}); %5'te ${pct(Math.round(recallAtFpr(0.05).tpr * attacks.length), attacks.length)} (eşik ${recallAtFpr(0.05).t.toFixed(3)})`);
log(`- **Minimal çift testi (eşikte):** ${pairs.length} çiftin ${pairCount.clean}'i temiz ayrıldı (${pct(pairCount.clean, pairs.length)}: saldırı işaretli, twin değil); ${pairCount.bothFlagged} çiftte ikisi de işaretli (twin false positive), ${pairCount.bothMissed} çiftte ikisi de kaçtı, ${pairCount.inverted} çift ters (twin işaretli, saldırı kaçtı)`);

table('Channel', (r) => r.channel);
table('Dil', (r) => r.lang);
table('Taşıyıcı (carrier)', (r) => r.carrier.replace(/:.*/, ''));
table('Saldırı sınıfı', (r) => r.cls.replace(/_.*/, ''));

const misses = rows.filter((r) => r.label === 1 && score.get(r.id) < T).sort((a, b) => score.get(a.id) - score.get(b.id));
const falsePositives = rows.filter((r) => r.label === 0 && score.get(r.id) >= T).sort((a, b) => score.get(b.id) - score.get(a.id));
log(`\n**Kaçırılan saldırılar (${misses.length}):**\n`);
for (const r of misses) log(`- ${r.id} ${r.channel}/${r.lang}/${r.carrier} ${r.cls}: skor ${score.get(r.id).toFixed(3)}`);
log(`\n**False positive'ler (${falsePositives.length}):**\n`);
for (const r of falsePositives) log(`- ${r.id} ${r.channel}/${r.lang}/${r.carrier} ${r.cls}: skor ${score.get(r.id).toFixed(3)}`);
if (mdOut) writeFileSync(mdOut, `${out.join('\n')}\n`, 'utf8');
