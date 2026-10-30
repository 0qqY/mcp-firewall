import { withDecoded } from './decode.js';
import { isObject, type JsonObject } from './jsonrpc.js';
import { checkPaths } from './paths.js';
import type { Policy, ToolRule } from './policy.js';

export interface Decision {
  allowed: boolean;
  reason?: string;
}

const ALLOW: Decision = { allowed: true };

/**
 * Text a human does not see but a model reads: zero-width and bidi-override characters, Unicode tag
 * characters and supplementary variation selectors (both can encode whole ASCII payloads), and terminal
 * escape sequences (ANSI CSI/OSC) that can hide or overwrite text in CLI hosts. ZWNJ/ZWJ (U+200C/D)
 * are left out: emoji sequences and Persian or Indic text need them.
 */
const HIDDEN_SOURCE =
  '\\u001b\\][^\\u0007\\u001b]*(?:\\u0007|\\u001b\\\\)?|\\u001b\\[[0-?]*[ -/]*[@-~]?|[\\u001b\\u009b]' +
  '|[\\u200b\\u200e\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]|[\\u{E0000}-\\u{E007F}\\u{E0100}-\\u{E01EF}]';
const HIDDEN_CHARS = new RegExp(HIDDEN_SOURCE, 'u');

export const hasHiddenChars = (text: string): boolean => HIDDEN_CHARS.test(text);

/** Removes hidden characters and escape sequences from every string in a JSON value; counts removals. */
export function stripHiddenChars(v: unknown): { value: unknown; removed: number } {
  let removed = 0;
  const re = new RegExp(HIDDEN_SOURCE, 'gu');
  const walk = (x: unknown): unknown => {
    if (typeof x === 'string') return x.replace(re, () => (removed++, ''));
    if (Array.isArray(x)) return x.map(walk);
    if (isObject(x)) {
      if ((x.type === 'image' || x.type === 'audio') && typeof x.data === 'string') return x;
      return Object.fromEntries(Object.entries(x).map(([k, y]) => [k, walk(y)]));
    }
    return x;
  };
  const value = walk(v);
  return { value, removed };
}

/** Flattens every string (and number/boolean) value in a JSON value. */
export function collectStrings(v: unknown): string[] {
  if (typeof v === 'string') return [v];
  if (typeof v === 'number' || typeof v === 'boolean') return [String(v)];
  if (Array.isArray(v)) return v.flatMap(collectStrings);
  if (isObject(v)) return Object.values(v).flatMap(collectStrings);
  return [];
}

/**
 * Names of the parameters declared in a JSON Schema (keys of every `properties` object). The model
 * reads them as text, so they can carry instructions ("full-schema poisoning") while every value is clean.
 */
export function schemaPropertyNames(v: unknown): string[] {
  if (Array.isArray(v)) return v.flatMap(schemaPropertyNames);
  if (!isObject(v)) return [];
  const own = isObject(v.properties) ? Object.keys(v.properties) : [];
  return [...own, ...Object.values(v).flatMap(schemaPropertyNames)];
}

/** Parameter names, each also as words ("readSshKey" -> "read ssh key"), so patterns and the model can read them. */
export function parameterNamesText(def: unknown): string {
  return schemaPropertyNames(def)
    .map((n) => {
      const words = n.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_\-.]+/g, ' ').toLowerCase();
      return words === n ? n : `${n} (${words})`;
    })
    .join('\n');
}

/** Everything the model reads from a tool, prompt or resource definition. */
export function definitionText(def: unknown): string {
  return [...collectStrings(def), parameterNamesText(def)].join('\n');
}

/** First matching rule wins, like a firewall ACL. */
export function findToolRule(policy: Policy, name: string): ToolRule | undefined {
  return policy.tools.rules.find((r) => r.match.test(name));
}

export function evaluateToolName(policy: Policy, name: string): Decision {
  const rule = findToolRule(policy, name);
  if (rule) {
    return rule.action === 'allow'
      ? ALLOW
      : { allowed: false, reason: rule.reason ?? `tool '${name}' denied by rule '${rule.pattern}'` };
  }
  return policy.tools.default === 'allow' ? ALLOW : { allowed: false, reason: `tool '${name}' denied by default policy` };
}

export function evaluateToolCall(policy: Policy, name: string, args: unknown): Decision {
  const byName = evaluateToolName(policy, name);
  if (!byName.allowed) return byName;
  const rule = findToolRule(policy, name);
  if (!rule) return ALLOW;
  for (const [key, constraint] of rule.arguments) {
    const target = key === '*' ? args : isObject(args) ? args[key] : undefined;
    for (const value of collectStrings(target)) {
      const denied = constraint.deny.find((r) => r.test(value));
      if (denied) return { allowed: false, reason: `argument '${key}' matches deny pattern /${denied.source}/` };
      if (constraint.allow.length > 0 && !constraint.allow.some((r) => r.test(value))) {
        return { allowed: false, reason: `argument '${key}' is not in the allow list` };
      }
    }
  }
  if (rule.paths) {
    const reason = checkPaths(rule.paths, isObject(args) ? args : {});
    if (reason) return { allowed: false, reason };
  }
  return ALLOW;
}

export function evaluateMethod(policy: Policy, method: string): Decision {
  return policy.methods.deny.some((r) => r.test(method))
    ? { allowed: false, reason: `method '${method}' denied by policy` }
    : ALLOW;
}

/** Looks for prompt-injection markers in text the model will read as instructions or metadata. */
export function scanText(policy: Policy, text: string): string[] {
  const { patterns, hiddenUnicode } = policy.descriptionScan;
  // Patterns see both the raw text and its de-obfuscated, decoded form.
  const readable = policy.decoding.enabled ? `${text}\n${withDecoded(text)}` : text;
  const hits = patterns.filter((r) => r.test(readable)).map((r) => `suspicious pattern /${r.source}/`);
  if (hiddenUnicode && hasHiddenChars(text)) hits.push('hidden unicode characters');
  return hits;
}

/** Looks for prompt-injection markers anywhere in a definition, including schema descriptions and parameter names. */
export function scanToolDefinition(policy: Policy, tool: JsonObject): string[] {
  return scanText(policy, definitionText(tool));
}
