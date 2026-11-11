// Preload that records every regular expression the firewall actually runs, including the ones built at run time
// (DLP detectors, glob patterns, policy patterns), with the source file that ran it first. Used by scripts/redos-audit.mjs.
//
//   REDOS_OUT=<file.jsonl> NODE_OPTIONS="--import=file:///<abs>/scripts/redos-collect.mjs" npm test
//
// Every regex operation (test, match, matchAll, replace, split, search) reaches RegExp.prototype.exec, so one wrapper sees
// them all. Each process appends its own lines on exit; the audit script merges them.
import { appendFileSync } from 'node:fs';

const out = process.env.REDOS_OUT;
if (out) {
  const seen = new Map();
  const original = RegExp.prototype.exec;
  let busy = false; // the wrapper must not record (or recurse into) the string work it does itself
  /** "decode.js:123" for the first stack frame inside dist/src, found without regular expressions. */
  const firstProductFrame = (stack) => {
    for (const line of stack.split('\n')) {
      const normal = line.replaceAll('\\', '/');
      const at = normal.indexOf('/dist/src/');
      if (at < 0) continue;
      const rest = normal.slice(at + '/dist/src/'.length);
      const colon = rest.indexOf(':');
      const second = rest.indexOf(':', colon + 1);
      return second < 0 ? rest : rest.slice(0, second);
    }
    return '';
  };
  RegExp.prototype.exec = function exec(text) {
    if (busy) return original.call(this, text);
    busy = true;
    try {
      const key = `/${this.source}/${this.flags}`;
      let entry = seen.get(key);
      if (!entry) {
        entry = { source: this.source, flags: this.flags, where: firstProductFrame(new Error().stack ?? ''), calls: 0, maxLen: 0 };
        seen.set(key, entry);
      }
      entry.calls++;
      if (typeof text === 'string' && text.length > entry.maxLen) entry.maxLen = text.length;
    } finally {
      busy = false;
    }
    return original.call(this, text);
  };
  process.on('exit', () => {
    const lines = [...seen.values()].filter((e) => e.where).map((e) => JSON.stringify(e));
    if (lines.length) appendFileSync(out, lines.join('\n') + '\n');
  });
}
