// Runs the REAL compiled extractMlText/chunkText over sampled BIPIA rows and writes content hashes, so the Python port in
// mlview.py can be compared against the shipped code. usage: node check_port_node.mjs <dist/src/ml/classifier.js> <pairs.jsonl> <out.json>
import crypto from 'node:crypto';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

const [mod, pairs, out] = process.argv.slice(2);
const { extractMlText, chunkText } = await import(pathToFileURL(mod).href);
const rows = fs.readFileSync(pairs, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const h = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 16);
const res = [];
for (let i = 0; i < rows.length; i += 10) {
  const ex = extractMlText({ content: [{ type: 'text', text: rows[i].text }] });
  const ch = chunkText(ex, 1500);
  res.push({ i, ex: h(ex), n: ch.length, ch: h(ch.join('\u0001')) });
}
fs.writeFileSync(out, JSON.stringify(res));
console.log('rows sampled', res.length);
