import { lookup as dnsLookup } from 'node:dns/promises';
import { createServer, connect as netConnect, isIP, type Server, type Socket } from 'node:net';

/**
 * Egress allowlist for a sandboxed server (`sandbox.egress`).
 *
 * The server container sits on a Docker `--internal` network: it has no route anywhere. The only thing it can
 * reach is a small HTTP CONNECT proxy (this file, run with `node` in a second container that is attached to
 * that network and to `bridge`). The proxy lets a connection through only when its host and port match the
 * allowlist and the name resolves to public addresses; it dials the address it checked, so a second lookup
 * cannot swap in another one. Enforcement is the network layout, not the proxy variables: a server that ignores
 * HTTPS_PROXY simply has no network.
 *
 * Only node: built-ins are imported here, because the file runs inside the proxy container on its own.
 */

/** Where the proxy listens inside its container. */
export const EGRESS_PORT = 3128;

export interface EgressRule {
  /** Lower-case host name without a trailing dot, or an IP literal. For a wildcard, the domain after `*.`. */
  host: string;
  /** `*.example.com`: any name below example.com (not example.com itself). */
  wildcard: boolean;
  port: number;
}

export class EgressRuleError extends Error {}

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/** Lower case, no trailing dot; undefined when it is not a usable host name or IP literal. */
export function normalizeHost(raw: string): string | undefined {
  let h = raw.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (isIP(h)) return h;
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (h.length === 0 || h.length > 253) return undefined;
  return h.split('.').every((l) => LABEL.test(l)) ? h : undefined;
}

/** `host`, `host:port`, `*.domain[:port]`, `[v6]:port` or a bare IP literal; the port defaults to 443. */
export function parseEgressRule(spec: string): EgressRule {
  const s = spec.trim();
  if (/[/\\@?#\s]/.test(s) || s.includes('://')) throw new EgressRuleError(`${spec}: expected host[:port], not a URL or path`);
  let hostPart = s;
  let port = 443;
  const v6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
  if (v6) {
    hostPart = v6[1];
    if (v6[2] !== undefined) port = Number(v6[2]);
  } else if (!isIP(s)) {
    const m = /^(.*):(\d+)$/.exec(s);
    if (m) {
      hostPart = m[1];
      port = Number(m[2]);
    }
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new EgressRuleError(`${spec}: port must be 1-65535`);
  const wildcard = hostPart.startsWith('*.');
  if (hostPart.includes('*') && !wildcard) throw new EgressRuleError(`${spec}: a wildcard is only allowed as a leading "*." label`);
  const host = normalizeHost(wildcard ? hostPart.slice(2) : hostPart);
  if (!host) throw new EgressRuleError(`${spec}: not a valid host name or IP address`);
  if (wildcard && (isIP(host) || !host.includes('.'))) throw new EgressRuleError(`${spec}: "*." needs a domain with at least two labels, such as *.example.com`);
  return { host, wildcard, port };
}

export function matchEgress(rules: EgressRule[], host: string, port: number): EgressRule | undefined {
  const h = normalizeHost(host);
  if (!h) return undefined;
  return rules.find((r) => r.port === port && (r.wildcard ? h.endsWith(`.${r.host}`) : h === r.host));
}

function v4(ip: string): number[] {
  return ip.split('.').map(Number);
}

/** Loopback, private, link-local (cloud metadata), CGNAT, multicast and other non-public ranges, IPv4 and IPv6. */
export function isNonPublicAddress(ip: string): boolean {
  const kind = isIP(ip);
  if (kind === 4) {
    const [a, b, c] = v4(ip);
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113)
    );
  }
  if (kind !== 6) return true;
  const full = expandV6(ip);
  if (!full) return true;
  const words = full;
  // ::ffff:a.b.c.d (mapped), ::a.b.c.d (compatible) and 64:ff9b::a.b.c.d (NAT64) carry an IPv4 address.
  const embedded = `${words[6] >> 8}.${words[6] & 255}.${words[7] >> 8}.${words[7] & 255}`;
  if (words.slice(0, 5).every((w) => w === 0) && (words[5] === 0xffff || words[5] === 0)) {
    if (words[5] === 0 && words[6] === 0 && words[7] <= 1) return true; // :: and ::1
    return isNonPublicAddress(embedded);
  }
  if (words[0] === 0x64 && words[1] === 0xff9b && words.slice(2, 6).every((w) => w === 0)) return isNonPublicAddress(embedded);
  const w0 = words[0];
  return (
    (w0 & 0xfe00) === 0xfc00 || // unique local
    (w0 & 0xffc0) === 0xfe80 || // link-local
    (w0 & 0xff00) === 0xff00 || // multicast
    (w0 === 0x2001 && words[1] === 0x0db8) || // documentation
    w0 === 0x2002 || // 6to4 can carry private IPv4
    (w0 === 0x2001 && words[1] === 0) // Teredo
  );
}

function expandV6(ip: string): number[] | undefined {
  let s = ip.toLowerCase();
  const pct = s.indexOf('%');
  if (pct >= 0) s = s.slice(0, pct);
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (dotted) {
    const [a, b, c, d] = v4(dotted[1]);
    s = s.slice(0, -dotted[1].length) + `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0) return undefined;
  const parts = [...head, ...Array(fill).fill('0'), ...tail];
  if (parts.length !== 8) return undefined;
  const words = parts.map((p) => parseInt(p, 16));
  return words.every((w) => Number.isInteger(w) && w >= 0 && w <= 0xffff) ? words : undefined;
}

export type EgressDecision =
  | { allow: true; host: string; port: number; address: string }
  | { allow: false; host: string; port: number; reason: string };

export type Resolver = (host: string) => Promise<string[]>;

const defaultResolver: Resolver = async (host) => (await dnsLookup(host, { all: true, verbatim: true })).map((a) => a.address);

/** The checks a CONNECT request goes through, without any sockets: allowlist, then every resolved address. */
export async function decideEgress(rules: EgressRule[], rawHost: string, port: number, resolve: Resolver = defaultResolver): Promise<EgressDecision> {
  const host = normalizeHost(rawHost);
  const shown = host ?? rawHost.slice(0, 100).replace(/[^\x21-\x7e]/g, '?');
  if (!host) return { allow: false, host: shown, port, reason: 'not a valid host name' };
  const rule = matchEgress(rules, host, port);
  if (!rule) return { allow: false, host, port, reason: 'not on the egress allowlist' };
  // An IP literal the policy lists by hand is taken as written, private or not.
  if (isIP(host)) return { allow: true, host, port, address: host };
  let addresses: string[];
  try {
    addresses = await resolve(host);
  } catch (err) {
    return { allow: false, host, port, reason: `name does not resolve (${(err as NodeJS.ErrnoException).code ?? 'error'})` };
  }
  if (addresses.length === 0) return { allow: false, host, port, reason: 'name does not resolve' };
  // Every address must be public: a name that also resolves inside can be steered there on the next lookup.
  const inside = addresses.find(isNonPublicAddress);
  if (inside) return { allow: false, host, port, reason: `resolves to a non-public address (${inside})` };
  return { allow: true, host, port, address: addresses[0] };
}

export interface EgressEvent {
  egress: 'allow' | 'deny';
  host: string;
  port: number;
  reason?: string;
}

export interface ProxyOptions {
  rules: EgressRule[];
  port?: number;
  hostname?: string;
  resolve?: Resolver;
  /** Opens the upstream connection; tests replace it. */
  dial?: (address: string, port: number) => Socket;
  log: (event: EgressEvent) => void;
}

const MAX_HEAD = 8192;

/** An HTTP CONNECT proxy that only tunnels to allowed destinations. Plain-HTTP proxy requests are refused. */
export function createEgressProxy(options: ProxyOptions): Server {
  const dial = options.dial ?? ((address, port) => netConnect({ host: address, port }));
  return createServer((client) => {
    client.setTimeout(30_000, () => client.destroy());
    let head = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) {
        if (head.length > MAX_HEAD) reply(client, 431, 'Request Header Fields Too Large');
        return;
      }
      client.off('data', onData);
      client.pause();
      const rest = head.subarray(end + 4);
      const line = head.subarray(0, head.indexOf('\r\n')).toString('latin1');
      const m = /^CONNECT (\S+) HTTP\/1\.[01]$/.exec(line);
      if (!m) {
        options.log({ egress: 'deny', host: hostOfRequest(line), port: 80, reason: 'only HTTPS (CONNECT) is proxied' });
        reply(client, 405, 'Only CONNECT is allowed');
        return;
      }
      const target = splitHostPort(m[1]);
      if (!target) {
        options.log({ egress: 'deny', host: m[1].slice(0, 100).replace(/[^\x21-\x7e]/g, '?'), port: 0, reason: 'bad CONNECT target' });
        reply(client, 400, 'Bad Request');
        return;
      }
      void decideEgress(options.rules, target.host, target.port, options.resolve).then((d) => {
        if (!d.allow) {
          options.log({ egress: 'deny', host: d.host, port: d.port, reason: d.reason });
          reply(client, 403, 'Forbidden by egress allowlist');
          return;
        }
        const upstream = dial(d.address, d.port);
        upstream.setTimeout(10_000, () => upstream.destroy(new Error('connect timeout')));
        upstream.once('connect', () => {
          upstream.setTimeout(0);
          client.setTimeout(0);
          options.log({ egress: 'allow', host: d.host, port: d.port });
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (rest.length > 0) upstream.write(rest);
          client.pipe(upstream);
          upstream.pipe(client);
          client.resume();
        });
        upstream.on('error', (err) => {
          if (!client.destroyed && client.bytesWritten === 0) {
            options.log({ egress: 'deny', host: d.host, port: d.port, reason: `upstream: ${err.message.slice(0, 120)}` });
            reply(client, 502, 'Bad Gateway');
          } else client.destroy();
        });
        client.on('error', () => upstream.destroy());
        client.on('close', () => upstream.destroy());
        upstream.on('close', () => client.destroy());
      });
    };
    client.on('data', onData);
    client.on('error', () => client.destroy());
  });
}

function reply(socket: Socket, status: number, text: string): void {
  socket.end(`HTTP/1.1 ${status} ${text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
}

function splitHostPort(target: string): { host: string; port: number } | undefined {
  const m = /^\[([^\]]+)\]:(\d{1,5})$/.exec(target) ?? /^([^:]+):(\d{1,5})$/.exec(target);
  if (!m) return undefined;
  const port = Number(m[2]);
  return port >= 1 && port <= 65535 ? { host: m[1], port } : undefined;
}

function hostOfRequest(line: string): string {
  const m = /^\S+ https?:\/\/([^/:\s]+)/i.exec(line);
  return (m?.[1] ?? '?').slice(0, 100).replace(/[^\x21-\x7e]/g, '?');
}
