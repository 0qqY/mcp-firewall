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
  let out = text;
  const hints = new Map<string, (string | undefined)[]>();
  for (const d of detectors) {
    out = out.replace(d.regex, (match) => {
      if (d.validate && !d.validate(match)) return match;
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
  return out;
}

/** Scans every string in a JSON value and returns a redacted copy plus what was found. */
export function deepScan(value: unknown, detectors: Detector[]): { value: unknown; findings: Finding[]; masked: Masked[] } {
  const counts = new Map<string, number>();
  const masked: Masked[] = [];
  const walk = (v: unknown, path: string): unknown => {
    if (typeof v === 'string') return scanText(v, detectors, counts, path, masked);
    if (Array.isArray(v)) return v.map((x, i) => walk(x, `${path}[${i}]`));
    if (isObject(v)) {
      // Base64 image/audio payloads only produce false positives.
      if ((v.type === 'image' || v.type === 'audio') && typeof v.data === 'string') return v;
      return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x, path ? `${path}.${k}` : k)]));
    }
    return v;
  };
  const out = walk(value, '');
  return { value: out, findings: [...counts].map(([detector, count]) => ({ detector, count })), masked };
}

export const formatFindings = (findings: Finding[]): string =>
  findings.map((f) => `${f.detector} x${f.count}`).join(', ');
