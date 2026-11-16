import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { basename } from 'node:path';
import { domainToASCII } from 'node:url';
import { isObject } from './jsonrpc.js';

/**
 * Offline list of known-bad hosts and URLs (URLhaus, a hosts file, an adblock domain list...), checked against the URLs a
 * call hands to a server. Nothing is looked up online: the lists are files the user downloads and refreshes.
 */
export interface UrlBlocklist {
  /** Blocked hosts; a host also blocks every subdomain under it. Value: index into `sources`. */
  hosts: Map<string, number>;
  /** Blocked URLs, normalised by `urlKey`. */
  urls: Map<string, number>;
  sources: string[];
}

export class BlocklistError extends Error {}

/** Names hosts files map to a sink address; they are not entries. */
const HOSTS_NOISE = new Set(['localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback', '0.0.0.0', '127.0.0.1', '::1']);
const SINK = /^(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::)\s+/;
const HOST_CHARS = /^[a-z0-9_.-]+$/;

/** Lowercase ASCII (punycode) host without a trailing dot or IPv6 brackets; undefined when it is not a host. */
function normHost(raw: string): string | undefined {
  let h = raw.trim().toLowerCase().replace(/\.$/, '');
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  // An IPv4 address written as IPv4-mapped IPv6 (the URL parser turns it into hex: ::ffff:cb00:7109) is that IPv4 address.
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
  if (mapped) {
    const [hi, lo] = [parseInt(mapped[1], 16), parseInt(mapped[2], 16)];
    h = `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  } else if (h.startsWith('::ffff:') && isIP(h.slice(7)) === 4) h = h.slice(7);
  if (isIP(h)) return h;
  const ascii = domainToASCII(h);
  return ascii && HOST_CHARS.test(ascii) && ascii.includes('.') ? ascii : undefined;
}

/** One spelling per URL: the scheme and the fragment do not count, the host is normalised, a lone trailing slash is dropped. */
function urlKey(u: URL): string | undefined {
  const host = normHost(u.hostname);
  if (!host) return undefined;
  const path = `${u.pathname}${u.search}`.replace(/\/$/, '');
  return `${host}${u.port ? `:${u.port}` : ''}${path}`;
}

/** Reads one list: hosts-file lines, adblock `||host^` lines, bare hosts, and full URLs (URLhaus). */
export function parseBlocklist(text: string, into: UrlBlocklist, source: number): number {
  let added = 0;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\s#.*$/, '').trim();
    if (!line || line.startsWith('#') || line.startsWith('!') || line.startsWith('[')) continue;
    if (line.includes('://')) {
      let u: URL;
      try {
        u = new URL(line.split(/\s/)[0]);
      } catch {
        continue;
      }
      const key = urlKey(u);
      // A list entry that is just a host blocks the whole host.
      if (key && (u.pathname === '/' || u.pathname === '') && !u.search) {
        into.hosts.set(key.replace(/:\d+$/, ''), source);
        added++;
      } else if (key) {
        into.urls.set(key, source);
        added++;
      }
      continue;
    }
    let entry = line;
    if (SINK.test(entry)) entry = entry.replace(SINK, '').split(/\s+/)[0];
    else if (entry.startsWith('||')) entry = entry.slice(2).replace(/\^.*$/, '');
    else entry = entry.split(/\s+/)[0];
    entry = entry.replace(/^\*\./, '');
    if (HOSTS_NOISE.has(entry.toLowerCase())) continue;
    const host = normHost(entry);
    if (host) {
      into.hosts.set(host, source);
      added++;
    }
  }
  return added;
}

export function loadBlocklist(files: string[]): UrlBlocklist {
  const list: UrlBlocklist = { hosts: new Map(), urls: new Map(), sources: files.map((f) => basename(f)) };
  files.forEach((file, i) => {
    let text: string;
    try {
      text = readFileSync(file, 'utf8');
    } catch (err) {
      throw new BlocklistError(`cannot read ${file}: ${(err as Error).message}`);
    }
    if (parseBlocklist(text, list, i) === 0) throw new BlocklistError(`${file}: no hosts or URLs found (expected a hosts file, a domain list or a URL list)`);
  });
  return list;
}

/** URLs written with a scheme anywhere in a string, and `www.` hosts in running text. */
const SCHEME_URL = /\b[a-z][a-z0-9+.-]{0,30}:\/\/[^\s"'<>`]+/gi;
const WWW_URL = /(?<![\w.-])www\.[^\s"'<>`]+/gi;
/** A whole value that is a host, maybe with a port and a path (a `url` argument written without a scheme). */
const BARE_HOST = /^(?:[a-z0-9_-]+\.)+[a-z0-9-]{2,}\.?(?::\d{1,5})?(?:[/?#]\S*)?$/i;
/** Strings longer than this are read as written but not decoded first. */
const MAX_DECODE = 64 * 1024;
const TRAILING = new Set([')', ',', '.', ';', ':', '!', '?', ']', "'"]);

/** Drops sentence punctuation after a URL in running text (a loop: a regex here could backtrack on long runs). */
function trimTrailing(s: string): string {
  let end = s.length;
  while (end > 0 && TRAILING.has(s[end - 1])) end--;
  return s.slice(0, end);
}

function candidates(value: string): string[] {
  const out = [...value.matchAll(SCHEME_URL)].map((m) => m[0]);
  for (const m of value.matchAll(WWW_URL)) out.push(`http://${m[0]}`);
  const trimmed = value.trim();
  if (trimmed.length <= 2048 && !trimmed.includes('://') && BARE_HOST.test(trimmed)) out.push(`http://${trimmed}`);
  return out;
}

/** Checks one URL-looking string; returns why it is blocked. */
function checkUrl(list: UrlBlocklist, raw: string): string | undefined {
  let u: URL;
  try {
    u = new URL(trimTrailing(raw));
  } catch {
    return undefined;
  }
  const host = normHost(u.hostname);
  if (!host) return undefined;
  const key = urlKey(u);
  const byUrl = key === undefined ? undefined : list.urls.get(key);
  if (byUrl !== undefined) return `URL ${key} is on the blocklist ${list.sources[byUrl]}`;
  if (isIP(host)) {
    const hit = list.hosts.get(host);
    return hit === undefined ? undefined : `host ${host} is on the blocklist ${list.sources[hit]}`;
  }
  // The host itself, then every parent domain: a listed domain covers its subdomains.
  for (let h = host; h.includes('.'); h = h.slice(h.indexOf('.') + 1)) {
    const hit = list.hosts.get(h);
    if (hit !== undefined) return `host ${host}${h === host ? '' : ` (under ${h})`} is on the blocklist ${list.sources[hit]}`;
  }
  return undefined;
}

/**
 * Looks through every string in a call's arguments (property names too) for a URL or host on the list; `decode` also
 * reads the decoded forms (percent, base64...) of each string. Returns the first reason found.
 */
export function findBlockedUrl(list: UrlBlocklist, args: unknown, decode?: (s: string) => string): string | undefined {
  const strings: string[] = [];
  const walk = (x: unknown): void => {
    if (typeof x === 'string') strings.push(x);
    else if (Array.isArray(x)) x.forEach(walk);
    else if (isObject(x)) for (const [k, y] of Object.entries(x)) (strings.push(k), walk(y));
  };
  walk(args);
  for (const s of strings) {
    const forms = decode && s.length <= MAX_DECODE ? [s, decode(s)] : [s];
    for (const form of forms) {
      for (const c of candidates(form)) {
        const reason = checkUrl(list, c);
        if (reason) return reason;
      }
    }
  }
  return undefined;
}
