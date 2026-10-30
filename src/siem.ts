import { createSocket, type Socket as UdpSocket } from 'node:dgram';
import { readFileSync } from 'node:fs';
import { connect as tcpConnect, isIPv6, type Socket } from 'node:net';
import { hostname } from 'node:os';
import { connect as tlsConnect } from 'node:tls';
import type { Verdict } from './audit.js';

/** One audit record as it leaves the machine: the JSONL fields plus where it came from. */
export interface SiemRecord {
  ts: string;
  server: string;
  verdict: Verdict;
  direction?: string;
  method?: string;
  tool?: string;
  reason?: string;
  score?: number;
  excerpt?: string;
}

export interface AuditSink {
  send(record: SiemRecord): void;
  /** Sends what is still queued; resolves within `ms` even when the receiver is gone. */
  flush(ms: number): Promise<void>;
  close(): void;
}

export interface SyslogConfig {
  /** udp://host:514, tcp://host:601 or tls://host:6514 */
  target: URL;
  facility: number;
  appName: string;
  /** PEM file with the CA that signed the receiver's certificate (tls only); the system store otherwise. */
  ca?: string;
  /**
   * TCP/TLS message boundaries: `octet-counting` (a length prefix, RFC 5425/6587, the TLS standard) or `newline`
   * (one message per line, what Fluent Bit and plain-TCP rsyslog inputs expect). Safe here: the JSON body has no
   * raw newline.
   */
  framing: 'octet-counting' | 'newline';
}

export interface OtlpConfig {
  /** OTLP/HTTP logs endpoint, e.g. http://127.0.0.1:4318/v1/logs */
  endpoint: URL;
  headers: Record<string, string>;
}

export interface SiemConfig {
  syslog?: SyslogConfig;
  otlp?: OtlpConfig;
  /** Forward `allow` records too (off by default: one per message, the volume of all MCP traffic). */
  logAllowed: boolean;
  /** Forward the text that triggered the model (off by default: it is untrusted, possibly private, content). */
  excerpt: boolean;
  /** Records kept while a receiver is unreachable; the oldest are dropped beyond this. */
  queueLimit: number;
}

export const SYSLOG_FACILITIES: Record<string, number> = {
  kern: 0, user: 1, mail: 2, daemon: 3, auth: 4, syslog: 5, lpr: 6, news: 7, uucp: 8, cron: 9, authpriv: 10, ftp: 11,
  local0: 16, local1: 17, local2: 18, local3: 19, local4: 20, local5: 21, local6: 22, local7: 23,
};

/** Syslog severity: block 4 (warning), findings 5 (notice), the rest 6 (informational). */
function syslogSeverity(v: Verdict): number {
  if (v === 'block') return 4;
  if (v === 'allow' || v === 'info') return 6;
  return 5;
}

/** OpenTelemetry severity number and text, same grading as syslog. */
function otelSeverity(v: Verdict): [number, string] {
  if (v === 'block') return [13, 'WARN'];
  if (v === 'allow' || v === 'info') return [9, 'INFO'];
  return [10, 'INFO2'];
}

/** RFC 5424 header fields allow printable US-ASCII only, without spaces. */
const headerField = (s: string, max: number): string => s.replace(/[^\x21-\x7e]/g, '_').slice(0, max) || '-';

const MAX_UDP_BYTES = 8192;
const BOM = '﻿';

/**
 * One RFC 5424 line. The message is the record as JSON, so newlines and quotes in a reason (text a server
 * chose) are escaped and cannot forge a second line or field in the receiver.
 */
export function syslogMessage(record: SiemRecord, config: SyslogConfig, maxBytes = Infinity): string {
  const pri = config.facility * 8 + syslogSeverity(record.verdict);
  const head = `<${pri}>1 ${record.ts} ${headerField(hostname(), 255)} ${headerField(config.appName, 48)} ${process.pid} ${headerField(record.verdict, 32)} - `;
  let body = JSON.stringify(record);
  // A datagram must fit; cut the free-text fields rather than lose the record.
  for (let keep = 2000; Buffer.byteLength(head + BOM + body) > maxBytes && keep >= 0; keep = keep > 100 ? keep >> 1 : keep - 100) {
    body = JSON.stringify({ ...record, reason: record.reason?.slice(0, keep), excerpt: undefined, truncated: true });
  }
  return head + BOM + body;
}

/** Bounded queue shared by both sinks: drops the oldest record and counts what it dropped. */
class Queue<T> {
  items: T[] = [];
  dropped = 0;
  constructor(readonly limit: number) {}
  push(item: T): void {
    this.items.push(item);
    if (this.items.length > this.limit) {
      this.items.shift();
      this.dropped++;
    }
  }
}

type Warn = (message: string) => void;

/** Syslog over UDP (one datagram per record) or TCP/TLS (octet-counted frames, RFC 6587 / RFC 5425). */
export class SyslogSink implements AuditSink {
  private readonly queue: Queue<string>;
  private udp?: UdpSocket;
  private stream?: Socket;
  private connecting = false;
  private retryMs = 1000;
  private retry?: NodeJS.Timeout;
  private closed = false;
  private failing = false;

  constructor(
    private readonly config: SyslogConfig,
    queueLimit: number,
    private readonly warn: Warn,
  ) {
    this.queue = new Queue(queueLimit);
  }

  private get host(): string {
    return this.config.target.hostname.replace(/^\[|\]$/g, '');
  }

  private get port(): number {
    const { protocol, port } = this.config.target;
    return Number(port) || (protocol === 'tls:' ? 6514 : protocol === 'tcp:' ? 601 : 514);
  }

  send(record: SiemRecord): void {
    if (this.closed) return;
    if (this.config.target.protocol === 'udp:') {
      if (!this.udp) {
        this.udp = createSocket(isIPv6(this.host) ? 'udp6' : 'udp4');
        this.udp.on('error', (err) => this.report(err));
        this.udp.unref();
      }
      this.udp.send(syslogMessage(record, this.config, MAX_UDP_BYTES), this.port, this.host, (err) => (err ? this.report(err) : this.recovered()));
      return;
    }
    const msg = syslogMessage(record, this.config);
    this.queue.push(this.config.framing === 'newline' ? `${msg}\n` : `${Buffer.byteLength(msg)} ${msg}`);
    this.pump();
  }

  /** Writes the queue to the open stream, opening it first when needed. */
  private pump(): void {
    if (this.closed) return;
    if (!this.stream) return this.open();
    while (this.queue.items.length > 0) this.stream.write(this.queue.items.shift()!);
  }

  private open(): void {
    if (this.connecting || this.retry) return;
    this.connecting = true;
    const tls = this.config.target.protocol === 'tls:';
    const socket = tls
      ? tlsConnect({ host: this.host, port: this.port, servername: this.host, ca: this.config.ca ? readFileSync(this.config.ca) : undefined })
      : tcpConnect({ host: this.host, port: this.port });
    socket.unref();
    socket.setKeepAlive(true);
    socket.once(tls ? 'secureConnect' : 'connect', () => {
      this.connecting = false;
      this.stream = socket;
      this.retryMs = 1000;
      this.recovered();
      this.pump();
    });
    socket.on('error', (err) => this.report(err));
    socket.on('close', () => {
      this.connecting = false;
      if (this.stream === socket) this.stream = undefined;
      if (this.closed) return;
      // Reconnect with backoff; records wait in the bounded queue meanwhile.
      this.retry = setTimeout(() => {
        this.retry = undefined;
        if (this.queue.items.length > 0) this.open();
      }, this.retryMs).unref();
      this.retryMs = Math.min(this.retryMs * 2, 30_000);
    });
  }

  private report(err: Error): void {
    if (!this.failing) this.warn(`syslog ${this.config.target.href} unreachable: ${err.message}; records are queued (up to the queue limit)`);
    this.failing = true;
  }

  private recovered(): void {
    if (this.failing && this.queue.dropped > 0) this.warn(`syslog ${this.config.target.href} back; ${this.queue.dropped} records were dropped meanwhile`);
    if (this.failing) this.queue.dropped = 0;
    this.failing = false;
  }

  async flush(ms: number): Promise<void> {
    const deadline = Date.now() + ms;
    if (this.queue.items.length > 0 && !this.stream) this.open();
    while ((this.queue.items.length > 0 || (this.stream?.writableLength ?? 0) > 0) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  close(): void {
    this.closed = true;
    clearTimeout(this.retry);
    this.udp?.close();
    this.stream?.end();
  }
}

type Attribute = { key: string; value: { stringValue: string } | { doubleValue: number } | { intValue: string } };
const attr = (key: string, v: string | number): Attribute =>
  ({ key, value: typeof v === 'number' ? { doubleValue: v } : { stringValue: v } });

/** OTLP/HTTP with JSON encoding, batched: at most one request per second, 512 records per request. */
export class OtlpSink implements AuditSink {
  private readonly queue: Queue<SiemRecord>;
  private timer?: NodeJS.Timeout;
  private inFlight?: Promise<void>;
  private retryMs = 1000;
  private failing = false;
  private closed = false;
  fetch: typeof fetch = globalThis.fetch;

  constructor(
    private readonly config: OtlpConfig,
    queueLimit: number,
    private readonly warn: Warn,
  ) {
    this.queue = new Queue(queueLimit);
  }

  send(record: SiemRecord): void {
    if (this.closed) return;
    this.queue.push(record);
    this.schedule(this.queue.items.length >= 512 ? 0 : 1000);
  }

  private schedule(ms: number): void {
    if (this.timer || this.inFlight) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.post();
    }, ms).unref();
  }

  static body(records: SiemRecord[]): object {
    return {
      resourceLogs: [{
        resource: { attributes: [attr('service.name', 'mcp-firewall'), attr('host.name', hostname()), attr('process.pid', process.pid)] },
        scopeLogs: [{
          scope: { name: 'mcp-firewall' },
          logRecords: records.map((r) => {
            const [severityNumber, severityText] = otelSeverity(r.verdict);
            const attributes = [attr('mcp.server', r.server), attr('mcp.verdict', r.verdict)];
            if (r.direction) attributes.push(attr('mcp.direction', r.direction));
            if (r.method) attributes.push(attr('mcp.method', r.method));
            if (r.tool) attributes.push(attr('mcp.tool', r.tool));
            if (r.score !== undefined) attributes.push(attr('mcp.ml.score', r.score));
            if (r.excerpt !== undefined) attributes.push(attr('mcp.ml.excerpt', r.excerpt));
            return {
              timeUnixNano: `${BigInt(Date.parse(r.ts)) * 1_000_000n}`,
              severityNumber,
              severityText,
              body: { stringValue: r.reason ?? r.verdict },
              attributes,
            };
          }),
        }],
      }],
    };
  }

  private async post(): Promise<void> {
    const batch = this.queue.items.splice(0, 512);
    if (batch.length === 0) return;
    let retry = false;
    this.inFlight = (async () => {
      try {
        const res = await this.fetch(this.config.endpoint, {
          method: 'POST',
          headers: { ...this.config.headers, 'Content-Type': 'application/json' },
          body: JSON.stringify(OtlpSink.body(batch)),
          signal: AbortSignal.timeout(10_000),
        });
        await res.arrayBuffer().catch(() => undefined);
        if (res.ok) return this.recovered();
        // 429 and 5xx are worth another try; any other status means the request itself is wrong.
        retry = res.status === 429 || res.status >= 500;
        this.report(`HTTP ${res.status}`);
        if (!retry) this.queue.dropped += batch.length;
      } catch (err) {
        retry = true;
        this.report((err as Error).message);
      }
      if (retry) {
        this.queue.items.unshift(...batch);
        while (this.queue.items.length > this.queue.limit) {
          this.queue.items.shift();
          this.queue.dropped++;
        }
      }
    })();
    await this.inFlight;
    this.inFlight = undefined;
    if (this.closed || this.queue.items.length === 0) return;
    this.schedule(retry ? this.retryMs : 0);
    this.retryMs = retry ? Math.min(this.retryMs * 2, 30_000) : 1000;
  }

  private report(why: string): void {
    if (!this.failing) this.warn(`OTLP ${this.config.endpoint.href} failed: ${why}; records are queued (up to the queue limit)`);
    this.failing = true;
  }

  private recovered(): void {
    if (this.failing && this.queue.dropped > 0) this.warn(`OTLP ${this.config.endpoint.href} back; ${this.queue.dropped} records were dropped meanwhile`);
    if (this.failing) this.queue.dropped = 0;
    this.failing = false;
    this.retryMs = 1000;
  }

  async flush(ms: number): Promise<void> {
    const deadline = Date.now() + ms;
    clearTimeout(this.timer);
    this.timer = undefined;
    while (Date.now() < deadline && (this.inFlight || this.queue.items.length > 0)) {
      if (this.inFlight) await Promise.race([this.inFlight, new Promise((r) => setTimeout(r, deadline - Date.now()))]);
      else await Promise.race([this.post(), new Promise((r) => setTimeout(r, deadline - Date.now()))]);
      if (this.failing) break;
    }
  }

  close(): void {
    this.closed = true;
    clearTimeout(this.timer);
  }
}

/** The sinks a policy asks for. */
export function openSinks(config: SiemConfig | undefined, warn: Warn): AuditSink[] {
  if (!config) return [];
  const sinks: AuditSink[] = [];
  const local = (u: URL) => /^(127\.|localhost$|\[::1\]$)/.test(u.hostname);
  if (config.syslog) {
    const { target } = config.syslog;
    if (target.protocol !== 'tls:' && !local(target)) warn(`syslog target ${target.href} is not encrypted; use tls:// across a network`);
    sinks.push(new SyslogSink(config.syslog, config.queueLimit, warn));
  }
  if (config.otlp) {
    const { endpoint } = config.otlp;
    if (endpoint.protocol !== 'https:' && !local(endpoint)) warn(`OTLP endpoint ${endpoint.href} is plain http; records and headers travel unencrypted`);
    sinks.push(new OtlpSink(config.otlp, config.queueLimit, warn));
  }
  return sinks;
}
