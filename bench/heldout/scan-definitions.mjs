// Runs the product's descriptionScan (regex patterns, hidden characters, look-alike names, embedded blobs) over a jsonl of real-world
// definitions and reports how many it would hide, which pattern fires how often and a few examples of each.
// usage: node bench/heldout/scan-definitions.mjs --dist <dist/src folder> --rows <file.jsonl> [--out <hits.jsonl>] [--examples 3]
import { appendFileSync, createReadStream, mkdtempSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name, def) => (args.includes(`--${name}`) ? args[args.indexOf(`--${name}`) + 1] : def);
const DIST = resolve(opt('dist', 'dist/src'));
const ROWS = resolve(opt('rows'));
const OUT = opt('out') ? resolve(opt('out')) : undefined;
const EXAMPLES = Number(opt('examples', 3));
const load = (f) => import(pathToFileURL(join(DIST, f)).href);

const { compilePolicy } = await load('policy.js');
const { scanToolDefinition } = await load('engine.js');
const policy = compilePolicy({ decoding: { enabled: true } }, mkdtempSync(join(tmpdir(), 'scan-')));

let total = 0;
let hidden = 0;
const byReason = new Map();
const hits = [];
const slow = [];
const TRACE = opt('trace'); // appends each row id before it is scanned: the last line shows where a stalled scan is stuck
const SLOW_MS = Number(opt('slow-ms', 250));
const rl = createInterface({ input: createReadStream(ROWS, { encoding: 'utf8' }), crlfDelay: Infinity });
for await (const line of rl) {
  if (!line.trim()) continue;
  const row = JSON.parse(line);
  total++;
  if (TRACE) appendFileSync(TRACE, `${total} ${row.id}\n`);
  const started = performance.now();
  const found = scanToolDefinition(policy, row.definition);
  const took = performance.now() - started;
  if (took >= SLOW_MS) slow.push({ id: row.id, ms: Math.round(took), chars: JSON.stringify(row.definition).length });
  if (!found.length) continue;
  hidden++;
  const text = `${row.definition.name}: ${row.definition.description}`.replace(/\s+/g, ' ');
  hits.push({ id: row.id, reasons: found, text: text.slice(0, 600) });
  for (const reason of found) {
    const entry = byReason.get(reason) ?? { count: 0, examples: [] };
    entry.count++;
    if (entry.examples.length < EXAMPLES) entry.examples.push({ id: row.id, text: text.slice(0, 230) });
    byReason.set(reason, entry);
  }
}
console.log(`${ROWS.split(/[\\/]/).pop()}: ${total} definitions, ${hidden} would be hidden (${((100 * hidden) / total).toFixed(2)}%)`);
if (slow.length) console.log(`${slow.length} definitions took ${SLOW_MS} ms or more to scan: ${slow.slice(0, 10).map((s) => `${s.id} ${s.ms} ms (${s.chars} chars)`).join(', ')}`);
for (const [reason, { count, examples }] of [...byReason].sort((a, b) => b[1].count - a[1].count)) {
  console.log(`\n${String(count).padStart(5)}  ${reason.slice(0, 200)}`);
  for (const e of examples) console.log(`       ${e.id}: ${e.text}`);
}
if (OUT) writeFileSync(OUT, `${hits.map((h) => JSON.stringify(h)).join('\n')}\n`, 'utf8');
