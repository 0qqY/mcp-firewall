import { stripInvisible } from './decode.js';
import { isObject } from './jsonrpc.js';

export interface Detector {
  name: string;
  /** Must carry the `g` flag; every match is a candidate finding. */
  regex: RegExp;
  /** Optional checksum or shape check that weeds out false positives. */
  validate?: (match: string) => boolean;
}

export interface Finding {
  detector: string;
  count: number;
}

/**
 * Where one secret was masked, for the analyst. Never the secret itself: `hint` is at most its last four
 * characters and `context` is the surrounding text taken from the already-redacted copy.
 */
export interface Masked {
  detector: string;
  /** JSON path inside the scanned value, e.g. `content[0].text`; empty for a bare string. */
  where: string;
  hint?: string;
  context: string;
}

/** Masked entries kept per scan, and characters of redacted text shown on each side of a placeholder. */
const MAX_MASKED = 10;
const CONTEXT_CHARS = 60;
/** Detectors whose tail is boilerplate or whose value is short enough that four characters say too much. */
const NO_HINT = new Set(['private_key', 'jwt']);

function luhn(candidate: string): boolean {
  const digits = candidate.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let n = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
  }
  return sum % 10 === 0;
}

/** Turkish national ID (T.C. Kimlik No) checksum. */
function tckn(candidate: string): boolean {
  const d = [...candidate].map(Number);
  if (d.length !== 11 || d[0] === 0) return false;
  const odd = d[0] + d[2] + d[4] + d[6] + d[8];
  const even = d[1] + d[3] + d[5] + d[7];
  if ((((odd * 7 - even) % 10) + 10) % 10 !== d[9]) return false;
  return d.slice(0, 10).reduce((a, b) => a + b, 0) % 10 === d[10];
}

/** Order matters: more specific detectors run first so their redaction wins. */
export const BUILTIN_DETECTORS: Record<string, Omit<Detector, 'name'>> = {
  private_key: { regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g },
  aws_access_key: { regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  // The 40-char AWS secret access key has no fixed shape of its own, so match it only where a
  // `(aws_)secret_access_key` label and `=`/`:` name it; a bare 40-char base64 string is far too common to flag.
  // No left word boundary on the label: in a JSON-encoded blob a newline becomes a literal `\n`, and that `n`
  // glues onto the label (`...\nAWS_SECRET_ACCESS_KEY=`), which a leading \b would reject — letting the secret leak.
  aws_secret_key: {
    regex: /(?<=(?:aws[_-]?)?secret[_-]?access[_-]?key\b["']?\s{0,4}[:=]\s{0,4}["']?)[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/gi,
  },
  github_token: { regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g },
  slack_token: { regex: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  anthropic_key: { regex: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  openai_key: { regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  // Stripe secret and restricted keys (`sk_live_…`, `rk_test_…`); the publishable `pk_` ones are public by design.
  stripe_key: { regex: /\b[sr]k_(?:test|live)_[A-Za-z0-9]{16,}\b/g },
  jwt: { regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  credit_card: { regex: /\b(?:\d[ -]?){12,18}\d\b/g, validate: luhn },
  iban_tr: { regex: /\bTR\d{2} ?(?:\d{4} ?){5}\d{2}\b/gi },
  tckn: { regex: /\b[1-9]\d{10}\b/g, validate: tckn },
};

export function buildDetectors(names: string[] | undefined, custom: { name: string; pattern: string }[]): Detector[] {
  const selected = names ?? Object.keys(BUILTIN_DETECTORS);
  const detectors = selected.map((name) => {
    const builtin = BUILTIN_DETECTORS[name];
    if (!builtin) throw new Error(`unknown DLP detector '${name}'`);
    return { name, ...builtin };
  });
  for (const { name, pattern } of custom) detectors.push({ name, regex: new RegExp(pattern, 'g') });
  return detectors;
}

/** Placeholder scanText leaves where a secret was. */
const redactionPlaceholder = (name: string): string => `[REDACTED:${name}]`;
/**
 * Matches any placeholder `redactionPlaceholder` produces, for the ML layer to neutralise before scoring: the
 * bracketed `[REDACTED:…]` marker itself reads as an injection to the classifier, which would otherwise turn a
 * DLP-masked result into a hard block. Keep in sync with `redactionPlaceholder`.
 */
export const REDACTION_MARKER = /\[REDACTED:[^\]]+\]/g;

function scanText(text: string, detectors: Detector[], counts: Map<string, number>, where: string, masked: Masked[]): string {
  // Zero-width characters dropped into a key hide it from the reader and from a pattern alike, so look through
  // them. The cleaned copy is handed back only when a secret turned up in it; ordinary text goes on unchanged.
  let out = stripInvisible(text);
  let found = false;
  const hints = new Map<string, (string | undefined)[]>();
  for (const d of detectors) {
    out = out.replace(d.regex, (match) => {
      if (d.validate && !d.validate(match)) return match;
      found = true;
      counts.set(d.name, (counts.get(d.name) ?? 0) + 1);
      const tail = match.replace(/\s+/g, '');
      hints.set(d.name, [...(hints.get(d.name) ?? []), NO_HINT.has(d.name) || tail.length < 12 ? undefined : tail.slice(-4)]);
      return redactionPlaceholder(d.name);
    });
  }
  // Context comes from `out` only after every detector ran, so it can never hold a secret another detector masks.
  for (const [name, list] of hints) {
    const marker = redactionPlaceholder(name);
    let at = -1;
    for (const hint of list) {
      at = out.indexOf(marker, at + 1);
      if (masked.length >= MAX_MASKED || at < 0) break;
      const from = Math.max(0, at - CONTEXT_CHARS), to = Math.min(out.length, at + marker.length + CONTEXT_CHARS);
      const context = `${from > 0 ? '…' : ''}${out.slice(from, to).replace(/\s+/g, ' ')}${to < out.length ? '…' : ''}`;
      masked.push({ detector: name, where, ...(hint ? { hint } : {}), context });
    }
  }
  return found ? out : text;
}

/** Scans every string in a JSON value and returns a redacted copy plus what was found. */
export function deepScan(value: unknown, detectors: Detector[]): { value: unknown; findings: Finding[]; masked: Masked[] } {
  const counts = new Map<string, number>();
  const masked: Masked[] = [];
  const walk = (v: unknown, path: string): unknown => {
    if (typeof v === 'string') return scanText(v, detectors, counts, path, masked);
    if (Array.isArray(v)) return v.map((x, i) => walk(x, `${path}[${i}]`));
    if (isObject(v)) {
      // Base64 image/audio payloads only produce false positives; the other fields of a media block are read.
      const media = v.type === 'image' || v.type === 'audio';
      // A property name is data too: a secret used as a key must not slip past a scan that reads values only.
      // Two keys that mask to the same text stay two keys.
      const used = new Set<string>();
      return Object.fromEntries(
        Object.entries(v).map(([k, x]) => {
          const clean = scanText(k, detectors, counts, path ? `${path}.<key>` : '<key>', masked);
          let key = clean;
          if (clean !== k) for (let n = 2; used.has(key); n++) key = `${clean}#${n}`;
          used.add(key);
          return [key, media && k === 'data' && typeof x === 'string' ? x : walk(x, path ? `${path}.${k}` : k)];
        }),
      );
    }
    return v;
  };
  const out = walk(value, '');
  return { value: out, findings: [...counts].map(([detector, count]) => ({ detector, count })), masked };
}

/**
 * Detectors looked for across field boundaries. Their matches start with a fixed prefix, so two unrelated
 * neighbouring fields rarely join into one by chance; digit patterns (cards, national ids) would.
 */
const SPLITTABLE = new Set(['aws_access_key', 'github_token', 'slack_token', 'anthropic_key', 'openai_key', 'stripe_key']);
/** A secret is cut into at most this many neighbouring fields, each short; longer strings are scanned on their own. */
const MAX_WINDOW = 4;
const MAX_PIECE_CHARS = 128;
const MAX_SIBLINGS = 64;

const tally = (counts: Map<string, number>): Finding[] => [...counts].map(([detector, count]) => ({ detector, count }));

/**
 * Secrets cut into pieces that sit in neighbouring fields of one object or array (`access_key: "AKIAIOSFODNN"`,
 * `key_suffix: "7EXAMPLE"`). Each piece is harmless alone, so deepScan finds nothing; read as one string, 2 to 4
 * neighbouring short strings give the key away. Only matches that cross a field boundary count.
 */
export function splitFindings(value: unknown, detectors: Detector[]): Finding[] {
  const active = detectors.filter((d) => SPLITTABLE.has(d.name));
  if (active.length === 0) return [];
  const counts = new Map<string, number>();
  const seen = new Set<string>();
  const scanRun = (run: string[]): void => {
    for (let i = 0; i + 1 < run.length; i++) {
      for (let len = 2; len <= MAX_WINDOW && i + len <= run.length; len++) {
        const parts = run.slice(i, i + len).map(stripInvisible);
        const joined = parts.join('');
        for (const d of active) {
          for (const m of joined.matchAll(new RegExp(d.regex.source, d.regex.flags))) {
            const start = m.index ?? 0;
            const end = start + m[0].length;
            let offset = 0;
            let touched = 0;
            for (const p of parts) {
              if (start < offset + p.length && end > offset) touched++;
              offset += p.length;
            }
            const key = `${d.name}:${m[0]}`;
            if (touched < 2 || seen.has(key)) continue;
            seen.add(key);
            counts.set(d.name, (counts.get(d.name) ?? 0) + 1);
          }
        }
      }
    }
  };
  const walk = (v: unknown): void => {
    const kids = Array.isArray(v) ? v : isObject(v) ? Object.values(v) : undefined;
    if (!kids) return;
    let run: string[] = [];
    for (const kid of kids) {
      if (typeof kid === 'string' && kid.length <= MAX_PIECE_CHARS) {
        run.push(kid);
        if (run.length >= MAX_SIBLINGS) {
          scanRun(run);
          run = [];
        }
        continue;
      }
      scanRun(run);
      run = [];
      walk(kid);
    }
    scanRun(run);
  };
  walk(value);
  return tally(counts);
}

/** Media payloads are not scanned past this size (decoded bytes). */
const MAX_MEDIA_BYTES = 8 * 1024 * 1024;
/** Digit patterns match printable noise inside binary data by chance. */
const NOT_IN_MEDIA = new Set(['credit_card', 'tckn', 'iban_tr']);

/**
 * Secrets hidden inside a media block: an `image` or `audio` block, or a resource `blob`, whose bytes carry plain
 * text after a genuine-looking header (a forged PNG header followed by a credential). The printable runs of the
 * decoded bytes are matched like any other text. Real images hold no such secrets, so this does not misfire on them.
 */
export function mediaFindings(value: unknown, detectors: Detector[]): Finding[] {
  const active = detectors.filter((d) => !NOT_IN_MEDIA.has(d.name));
  const counts = new Map<string, number>();
  const scan = (b64: string): void => {
    if (b64.length > (MAX_MEDIA_BYTES * 4) / 3) return;
    const text = Buffer.from(b64, 'base64').toString('latin1');
    for (const run of text.match(/[\x20-\x7e\t\r\n]{12,}/g) ?? []) {
      for (const d of active) {
        for (const m of run.matchAll(new RegExp(d.regex.source, d.regex.flags))) {
          if (d.validate && !d.validate(m[0])) continue;
          counts.set(d.name, (counts.get(d.name) ?? 0) + 1);
        }
      }
    }
  };
  const walk = (v: unknown): void => {
    if (Array.isArray(v)) {
      v.forEach(walk);
      return;
    }
    if (!isObject(v)) return;
    if ((v.type === 'image' || v.type === 'audio') && typeof v.data === 'string') scan(v.data);
    else if (typeof v.blob === 'string') scan(v.blob);
    for (const x of Object.values(v)) if (typeof x === 'object' && x !== null) walk(x);
  };
  walk(value);
  return tally(counts);
}

/** Secrets that can be found but not masked in place: split across fields, or inside a media block. */
export function unredactableFindings(value: unknown, detectors: Detector[]): Finding[] {
  const merged = new Map<string, number>();
  for (const f of [...splitFindings(value, detectors), ...mediaFindings(value, detectors)]) {
    merged.set(f.detector, (merged.get(f.detector) ?? 0) + f.count);
  }
  return tally(merged);
}

export const formatFindings = (findings: Finding[]): string =>
  findings.map((f) => `${f.detector} x${f.count}`).join(', ');
