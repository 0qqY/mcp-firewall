// False alarms of the data-ask rules on real tool definitions. usage: node dataask-real.mjs <dist/src> <rows.jsonl> [examples per kind]
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { resolve, join } from 'node:path';
const [dist, file, ex = '6'] = process.argv.slice(2);
const { DATA_ASK_RULES } = await import(new URL('./dataask.mjs', import.meta.url).href);
const { definitionText } = await import(pathToFileURL(join(resolve(dist), 'engine.js')).href);
let total = 0, hit = 0, slow = 0; const by = new Map(); const t0 = performance.now();
for await (const line of createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity })) {
  if (!line.trim()) continue;
  const row = JSON.parse(line); total++;
  const text = definitionText(row.definition); const t = performance.now(); let any = false;
  DATA_ASK_RULES.forEach((r, i) => {
    const m = r.pattern.exec(text);
    if (!m) return;
    any = true; const k = `${r.kind}#${i}`; const e = by.get(k) ?? { n: 0, ex: [] }; e.n++;
    if (e.ex.length < Number(ex) && !e.ex.some((x) => x.includes(m[0].slice(0, 30)))) e.ex.push(`${row.id} «${text.slice(Math.max(0, m.index - 70), m.index + m[0].length + 50).replace(/\s+/g, ' ')}»`);
    by.set(k, e);
  });
  if (performance.now() - t > 100) slow++;
  if (any) hit++;
}
console.log(`flagged ${hit}/${total} (${(100 * hit / total).toFixed(3)}%), ${Math.round(performance.now() - t0)} ms, slow rows ${slow}`);
for (const [k, e] of [...by].sort((a, b) => b[1].n - a[1].n)) { console.log(`\n${k}: ${e.n}`); e.ex.forEach((x) => console.log('   ' + x)); }
