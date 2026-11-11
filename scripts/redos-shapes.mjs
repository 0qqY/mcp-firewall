// Every collected regex against long uniform inputs (one repeated unit, 32,000 characters): finds the quadratic cases that
// need no clever input, such as a long run of letters.  node scripts/redos-shapes.mjs <collected.jsonl> [size]
import { readFileSync } from 'node:fs';

const size = Number(process.argv[3] ?? 32000);
const merged = new Map();
for (const line of readFileSync(process.argv[2], 'utf8').split('\n').filter(Boolean)) {
  const e = JSON.parse(line);
  merged.set(`${e.source}/${e.flags}`, e);
}
const rep = (unit) => unit.repeat(Math.floor(size / unit.length));
const inputs = {
  'A': rep('A'), 'ACGT': rep('ACGT'), "a+'": `a${rep("'")}`, 'word+spaces': 'a'.repeat(size / 2) + ' '.repeat(size / 2), '7': rep('7'), 'ab12': rep('ab12'),
  'space': rep(' '), 'a.': rep('a.'), 'a=': rep('a='), '/a': rep('/a'), 'a_': rep('a_'), 'a-': rep('a-'), '%4': rep('%4'), '\\u00': rep('\\u00'),
  '<a ': rep('<a '), '"a': rep('"a'), 'a\\n': rep('a\n'), 'a:': rep('a:'), '&#': rep('&#'), 'tr': rep('ığüşöç'), '@': rep('@'), 'a@': rep('a@'), 'a b': rep('a b'),
  '=': rep('='), '+': rep('+'), '-': rep('-'), '.': rep('.'), '\\n': rep('\n'), '\\t': rep('\t'), '0x': rep('0x'), 'aA': rep('aA'), '(': rep('('), '[': rep('['),
  '{': rep('{'), '\\\\': rep('\\'), "'": rep("'"), '"': rep('"'), '`': rep('`'), '!': rep('!'), '$': rep('$'), '#': rep('#'), '*': rep('*'), ',': rep(','),
};
const found = [];
for (const e of merged.values()) {
  let re;
  try { re = new RegExp(e.source, e.flags.includes('g') ? e.flags.replace('y', '') : `${e.flags.replace('y', '')}g`); } catch { continue; }
  for (const [name, s] of Object.entries(inputs)) {
    const t0 = performance.now();
    s.replace(re, '');
    const ms = performance.now() - t0;
    if (ms > 40) found.push({ ms: Math.round(ms), shape: name, where: e.where, regex: `/${e.source.slice(0, 120)}/${e.flags}` });
  }
}
found.sort((a, b) => b.ms - a.ms);
for (const f of found) console.log(`${f.ms} ms  shape ${JSON.stringify(f.shape)}  ${f.where}  ${f.regex}`);
console.log(`${merged.size} regexes x ${Object.keys(inputs).length} shapes at ${size} characters: ${found.length} slow pairs`);
