// Timing audit for catastrophic backtracking in the regular expressions the firewall runs on untrusted text.
//
//   node scripts/redos-audit.mjs <collected.jsonl> [--out report.json] [--only <substring of source>] [--budget-ms 250]
//
// <collected.jsonl> comes from scripts/redos-collect.mjs (run the test suite and a scan with it preloaded).
// For every regex the script builds repetitive inputs out of the characters and words of the pattern itself
// (prefix + pump x n + suffix), runs a global replace over them inside a vm with a timeout, and reports the inputs
// whose time grows faster than linearly. It is a search, not a proof: a clean result means none of these shapes hurt.
//
// Reading the result: `slope` is the growth exponent between the two largest sizes that finished (1 = linear,
// 2 = quadratic, larger or "timeout at small n" = exponential); `at` is the input length and `ms` its time.
import { readFileSync, writeFileSync } from 'node:fs';
import vm from 'node:vm';

const args = process.argv.slice(2);
const opt = (name, def) => (args.includes(`--${name}`) ? args[args.indexOf(`--${name}`) + 1] : def);
const BUDGET = Number(opt('budget-ms', 250));
const ONLY = opt('only');
const merged = new Map();
for (const line of readFileSync(args[0], 'utf8').split('\n').filter(Boolean)) {
  const e = JSON.parse(line);
  const key = `/${e.source}/${e.flags}`;
  const m = merged.get(key);
  if (m) { m.calls += e.calls; m.maxLen = Math.max(m.maxLen, e.maxLen); } else merged.set(key, e);
}
const ctx = vm.createContext({});

/** Milliseconds for a global replace over `input`; Infinity when it runs into the timeout. */
function time(source, flags, input, timeout) {
  ctx.re = new RegExp(source, flags.includes('g') ? flags.replace('y', '') : `${flags.replace('y', '')}g`);
  ctx.s = input;
  const t0 = performance.now();
  try { vm.runInContext('s.replace(re, "")', ctx, { timeout }); } catch { return Infinity; }
  return performance.now() - t0;
}

const BASE = ['a', 'A', 'z', '0', '9', ' ', '\n', '\t', '=', '+', '/', '-', '_', '.', ',', ':', ';', '%', '\\', '"', "'", '<', '>', '(', ')', '[', ']', '{', '}', '@', '#', '!', '?', '*', '&', '|', '$', '^', '~', '`', 'é', 'ı', '​'];

function candidates(source) {
  const chars = new Set(BASE);
  for (const c of source) if (c.charCodeAt(0) > 32 && c.charCodeAt(0) < 127) chars.add(c);
  const words = [...new Set(source.match(/[A-Za-z0-9]{2,}/g) ?? [])].slice(0, 24);
  const core = [...new Set([...source].filter((c) => /[A-Za-z0-9 =+/_.:%-]/.test(c)))].slice(0, 14);
  const pumps = new Set([...chars, ...words, ...words.map((w) => `${w} `), ...words.map((w) => `${w}=`)]);
  for (const a of core) for (const b of core) if (a !== b) pumps.add(a + b);
  for (const a of ['a', 'A', '0']) for (const b of [' ', '=', '+', '/', '-', '_', '.', ':', '\n', 'A', 'a', '0']) if (a !== b) { pumps.add(a + b); pumps.add(b + a); }
  const prefixes = ['', 'a', 'Aa', 'Ew', '0', ' ', '"', ...words.slice(0, 4), ...words.slice(0, 3).map((w) => `${w}=`), ...words.slice(0, 3).map((w) => `${w}: `)];
  const suffixes = ['', '!', '\n', '\u0001', 'a', ' ', '"', '=', 'PfwHLuRXafg'];
  return { pumps: [...pumps], prefixes: [...new Set(prefixes)], suffixes };
}

const build = (prefix, pump, suffix, length) => prefix + pump.repeat(Math.max(1, Math.floor(length / pump.length))) + suffix;

function audit(entry) {
  const { source, flags } = entry;
  const { pumps, prefixes, suffixes } = candidates(source);
  const findings = [];
  const started = performance.now();
  for (const size of [120, 2000]) { // 120: exponential shapes already explode here; 2000: polynomial ones show
    for (const pump of pumps) for (const prefix of prefixes) for (const suffix of suffixes) {
      if (performance.now() - started > 120_000) break;
      const input = build(prefix, pump, suffix, size);
      const ms = time(source, flags, input, BUDGET);
      if (ms < (size === 120 ? 8 : 25)) continue;
      // confirm and measure growth on a ladder of sizes
      const ladder = size === 120 ? [30, 45, 60, 80, 100, 120] : [500, 1000, 2000, 4000, 8000, 16000];
      const points = [];
      for (const n of ladder) {
        const t = Math.min(time(source, flags, build(prefix, pump, suffix, n), 2000), time(source, flags, build(prefix, pump, suffix, n), 2000));
        points.push([n, t]);
        if (!Number.isFinite(t)) break;
      }
      const finite = points.filter(([, t]) => Number.isFinite(t) && t > 0.2);
      let slope = 0;
      if (finite.length >= 2) {
        const [[n1, t1], [n2, t2]] = finite.slice(-2);
        slope = Math.log(t2 / t1) / Math.log(n2 / n1);
      }
      const timedOut = points.find(([, t]) => !Number.isFinite(t));
      if (timedOut || slope > 1.6) findings.push({ prefix, pump, suffix, points: points.map(([n, t]) => [n, Number.isFinite(t) ? Math.round(t * 10) / 10 : 'timeout']), slope: Math.round(slope * 100) / 100, timedOutAt: timedOut?.[0] });
      if (findings.length >= 40) break;
    }
  }
  if (!findings.length) return undefined;
  // worst first: an early timeout beats a steep slope
  findings.sort((a, b) => (a.timedOutAt ?? 1e9) - (b.timedOutAt ?? 1e9) || b.slope - a.slope);
  return { source, flags, where: entry.where, calls: entry.calls, maxLen: entry.maxLen, shapes: findings.length, worst: findings.slice(0, 3) };
}

const report = [];
let done = 0;
const entries = [...merged.values()].filter((e) => !ONLY || e.source.includes(ONLY));
for (const entry of entries) {
  const found = audit(entry);
  done++;
  if (found) {
    report.push(found);
    const w = found.worst[0];
    console.log(`FLAG ${found.where}  /${found.source.slice(0, 90)}/${found.flags}\n     ${w.timedOutAt ? `timeout at ${w.timedOutAt} chars` : `slope ${w.slope}`}  prefix=${JSON.stringify(w.prefix)} pump=${JSON.stringify(w.pump)} suffix=${JSON.stringify(w.suffix)}  ${JSON.stringify(w.points)}`);
  }
  if (done % 25 === 0) console.log(`... ${done}/${entries.length} regexes`);
}
console.log(`${entries.length} regexes audited, ${report.length} flagged`);
if (opt('out')) writeFileSync(opt('out'), JSON.stringify(report, null, 1));
