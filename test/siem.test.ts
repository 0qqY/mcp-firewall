import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http';
import { createServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer as createTlsServer } from 'node:tls';
import { after, test } from 'node:test';
import { AuditLog } from '../src/audit.js';
import { compilePolicy, PolicyError } from '../src/policy.js';
import { openSinks, OtlpSink, type SiemConfig, type SiemRecord, syslogMessage, SyslogSink } from '../src/siem.js';

const dir = mkdtempSync(join(tmpdir(), 'mcpfw-siem-'));
const closers: (() => void)[] = [];
after(() => closers.forEach((c) => c()));

const record = (over: Partial<SiemRecord> = {}): SiemRecord => ({
  ts: '2026-10-31T09:00:00.000Z',
  server: 'github',
  verdict: 'block',
  method: 'tools/call',
  tool: 'send_email',
  reason: 'argument to matches deny pattern',
  ...over,
});
const syslog = (target: string, ca?: string, framing: 'octet-counting' | 'newline' = 'octet-counting') =>
  ({ target: new URL(target), facility: 16, appName: 'mcp-firewall', ca, framing });
const until = async (cond: () => boolean, ms = 5000) => {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
};

/** Splits an octet-counted syslog stream (RFC 6587) into messages. */
function frames(buf: string): string[] {
  const out: string[] = [];
  let rest = Buffer.from(buf);
  for (;;) {
    const space = rest.indexOf(0x20);
    if (space < 0) break;
    const len = Number(rest.subarray(0, space).toString());
    if (rest.length < space + 1 + len) break;
    out.push(rest.subarray(space + 1, space + 1 + len).toString());
    rest = rest.subarray(space + 1 + len);
  }
  return out;
}

const parse5424 = (line: string) => {
  const m = /^<(\d+)>1 (\S+) (\S+) (\S+) (\d+) (\S+) - \ufeff(.*)$/s.exec(line);
  assert.ok(m, `not RFC 5424: ${line.slice(0, 80)}`);
  return { pri: Number(m[1]), ts: m[2], host: m[3], app: m[4], msgid: m[6], body: JSON.parse(m[7]) };
};

test('RFC 5424 line: priority from facility and verdict, JSON body, no way to forge a line or a field', () => {
  const hostile = record({ reason: 'x\n<14>1 2026-10-31T00:00:00Z fake app - - - all clear', tool: 'a b"]' });
  const line = syslogMessage(hostile, { ...syslog('udp://127.0.0.1:514'), appName: 'mcp firewall' });
  assert.ok(!line.includes('\n'), 'one line');
  const p = parse5424(line);
  assert.equal(p.pri, 16 * 8 + 4, 'local0.warning for a block');
  assert.equal(p.app, 'mcp_firewall');
  assert.equal(p.msgid, 'block');
  assert.equal(p.body.reason, hostile.reason, 'the text survives, escaped');
  assert.equal(parse5424(syslogMessage(record({ verdict: 'redact' }), syslog('udp://h'))).pri, 16 * 8 + 5);
  assert.equal(parse5424(syslogMessage(record({ verdict: 'info' }), syslog('udp://h'))).pri, 16 * 8 + 6);
});

test('syslog over UDP: one datagram per record, oversized records cut to fit', async () => {
  const server = createSocket('udp4');
  const got: string[] = [];
  server.on('message', (m) => got.push(m.toString()));
  await new Promise<void>((r) => server.bind(0, '127.0.0.1', r));
  closers.push(() => server.close());
  const sink = new SyslogSink(syslog(`udp://127.0.0.1:${(server.address() as AddressInfo).port}`), 100, () => {});
  closers.push(() => sink.close());
  sink.send(record());
  sink.send(record({ reason: 'x'.repeat(20_000), excerpt: 'y'.repeat(20_000) }));
  await until(() => got.length === 2);
  assert.equal(parse5424(got[0]).body.tool, 'send_email');
  assert.ok(Buffer.byteLength(got[1]) <= 8192);
  const cut = parse5424(got[1]).body;
  assert.equal(cut.truncated, true);
  assert.equal(cut.excerpt, undefined);
});

function tcpReceiver(server: Server) {
  const data: string[] = [];
  const sockets: Socket[] = [];
  server.on('connection', (s) => {
    sockets.push(s);
    s.setEncoding('utf8');
    s.on('data', (d) => data.push(d as unknown as string));
  });
  closers.push(() => {
    sockets.forEach((s) => s.destroy());
    server.close();
  });
  return { messages: () => frames(data.join('')), sockets };
}

test('syslog over TCP: records wait while the receiver is down and arrive in order once it is up', async () => {
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const port = (probe.address() as AddressInfo).port;
  probe.close();
  const warnings: string[] = [];
  const sink = new SyslogSink(syslog(`tcp://127.0.0.1:${port}`), 100, (m) => warnings.push(m));
  closers.push(() => sink.close());
  const started = Date.now();
  for (let i = 0; i < 5; i++) sink.send(record({ reason: `r${i}` }));
  assert.ok(Date.now() - started < 50, 'send never waits for the network');
  await until(() => warnings.length > 0);
  assert.match(warnings[0], /unreachable/);

  const server = createServer();
  const rx = tcpReceiver(server);
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
  await until(() => rx.messages().length === 5, 10_000);
  assert.deepEqual(rx.messages().map((m) => parse5424(m).body.reason), ['r0', 'r1', 'r2', 'r3', 'r4']);

  // A dropped connection is reopened for the next record.
  rx.sockets.forEach((s) => s.destroy());
  await new Promise((r) => setTimeout(r, 50));
  sink.send(record({ reason: 'after' }));
  await sink.flush(5000);
  await until(() => rx.messages().length === 6, 10_000);
  assert.equal(parse5424(rx.messages()[5]).body.reason, 'after');
});

test('syslog over TCP with newline framing: one message per line', async () => {
  const server = createServer();
  const data: string[] = [];
  server.on('connection', (s) => s.on('data', (d) => data.push(d.toString())));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  closers.push(() => server.close());
  const sink = new SyslogSink(syslog(`tcp://127.0.0.1:${(server.address() as AddressInfo).port}`, undefined, 'newline'), 100, () => {});
  closers.push(() => sink.close());
  sink.send(record({ reason: 'one\ntwo' }));
  sink.send(record({ reason: 'three' }));
  await until(() => data.join('').split('\n').length === 3);
  const lines = data.join('').split('\n').filter(Boolean);
  assert.deepEqual(lines.map((l) => parse5424(l).body.reason), ['one\ntwo', 'three'], 'a newline in a reason stays inside its message');
});

test('the queue is bounded: the oldest records are dropped and counted', async () => {
  const warnings: string[] = [];
  const sink = new SyslogSink(syslog('tcp://127.0.0.1:9'), 10, (m) => warnings.push(m));
  closers.push(() => sink.close());
  const started = Date.now();
  for (let i = 0; i < 5000; i++) sink.send(record({ reason: `r${i}` }));
  assert.ok(Date.now() - started < 1000, `5000 records against a dead receiver took ${Date.now() - started} ms`);
  const queue = (sink as unknown as { queue: { items: string[]; dropped: number } }).queue;
  assert.equal(queue.items.length, 10);
  assert.equal(queue.dropped, 4990);
  assert.match(queue.items[9], /r4999/);
  const t = Date.now();
  await sink.flush(300);
  assert.ok(Date.now() - t < 1000, 'flush gives up at its deadline');
});

const openssl = ['openssl', 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe'].find((bin) => {
  try {
    execFileSync(bin, ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
});

test('syslog over TLS: the receiver certificate is verified against the configured CA', { skip: !openssl && 'openssl not found' }, async () => {
  const key = join(dir, 'key.pem');
  const cert = join(dir, 'cert.pem');
  execFileSync(openssl!, ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  assert.ok(existsSync(cert));
  const server = createTlsServer({ key: readFileSync(key), cert: readFileSync(cert) });
  const data: string[] = [];
  server.on('secureConnection', (s) => s.on('data', (d) => data.push(d.toString())));
  server.on('tlsClientError', () => {});
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  closers.push(() => server.close());
  const port = (server.address() as AddressInfo).port;

  const trusted = new SyslogSink(syslog(`tls://localhost:${port}`, cert), 100, () => {});
  closers.push(() => trusted.close());
  trusted.send(record());
  await until(() => frames(data.join('')).length === 1);
  assert.equal(parse5424(frames(data.join(''))[0]).body.verdict, 'block');

  const warnings: string[] = [];
  const untrusted = new SyslogSink(syslog(`tls://localhost:${port}`), 100, (m) => warnings.push(m));
  closers.push(() => untrusted.close());
  untrusted.send(record({ reason: 'must not arrive' }));
  await until(() => warnings.length > 0);
  assert.match(warnings[0], /self-signed|certificate/i);
  assert.equal(frames(data.join('')).length, 1);
});

function collector(statuses: number[] = []) {
  const posts: { headers: Record<string, unknown>; body: any }[] = [];
  const server: HttpServer = createHttpServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      posts.push({ headers: req.headers, body: JSON.parse(raw) });
      res.writeHead(statuses.shift() ?? 200, { 'Content-Type': 'application/json' }).end('{}');
    });
  });
  closers.push(() => {
    server.closeAllConnections();
    server.close();
  });
  return {
    posts,
    records: () => posts.flatMap((p) => p.body.resourceLogs[0].scopeLogs[0].logRecords),
    url: async () => {
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
      return new URL(`http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/logs`);
    },
  };
}

test('OTLP/HTTP: records are batched into one request with OpenTelemetry fields and the configured headers', async () => {
  const c = collector();
  const sink = new OtlpSink({ endpoint: await c.url(), headers: { Authorization: 'Bearer t0k' } }, 100, () => {});
  closers.push(() => sink.close());
  sink.send(record());
  sink.send(record({ verdict: 'redact', tool: 'read_inbox', reason: 'aws_access_key redacted', score: 0.97 }));
  await sink.flush(5000);
  assert.equal(c.posts.length, 1);
  assert.equal(c.posts[0].headers.authorization, 'Bearer t0k');
  const resource = c.posts[0].body.resourceLogs[0].resource.attributes;
  assert.deepEqual(resource.find((a: any) => a.key === 'service.name').value, { stringValue: 'mcp-firewall' });
  const [blocked, redacted] = c.records();
  assert.equal(blocked.severityText, 'WARN');
  assert.equal(blocked.severityNumber, 13);
  assert.equal(blocked.timeUnixNano, `${Date.parse('2026-10-31T09:00:00.000Z')}000000`);
  assert.equal(blocked.body.stringValue, 'argument to matches deny pattern');
  const attrs = Object.fromEntries(redacted.attributes.map((a: any) => [a.key, Object.values(a.value)[0]]));
  assert.deepEqual(attrs, { 'mcp.server': 'github', 'mcp.verdict': 'redact', 'mcp.method': 'tools/call', 'mcp.tool': 'read_inbox', 'mcp.ml.score': 0.97 });
});

test('OTLP/HTTP: 503 and 429 are retried, 400 is dropped with a warning', async () => {
  const c = collector([503, 429]);
  const warnings: string[] = [];
  const sink = new OtlpSink({ endpoint: await c.url(), headers: {} }, 100, (m) => warnings.push(m));
  closers.push(() => sink.close());
  sink.send(record({ reason: 'kept' }));
  await until(() => c.posts.length === 3, 15_000);
  assert.ok(c.records().every((r: any) => r.body.stringValue === 'kept'));
  assert.match(warnings[0], /HTTP 503/);
  await until(() => warnings.some((w) => /back/.test(w)) || (sink as any).failing === false);

  const bad = collector([400]);
  const badWarnings: string[] = [];
  const dropping = new OtlpSink({ endpoint: await bad.url(), headers: {} }, 100, (m) => badWarnings.push(m));
  closers.push(() => dropping.close());
  dropping.send(record());
  await dropping.flush(3000);
  await new Promise((r) => setTimeout(r, 1500));
  assert.equal(bad.posts.length, 1, 'not retried');
  assert.match(badWarnings[0], /HTTP 400/);
});

test('policy: audit.siem validation, ${VAR} headers and defaults', () => {
  process.env.MCPFW_TEST_OTLP_TOKEN = 'abc';
  const p = compilePolicy({ audit: { siem: { syslog: { target: 'tls://siem.example:6514', facility: 'auth' }, otlp: { endpoint: 'https://otel.example/v1/logs', headers: { Authorization: 'Bearer ${MCPFW_TEST_OTLP_TOKEN}' } } } } }, dir);
  const siem = p.audit.siem!;
  assert.equal(siem.syslog!.facility, 4);
  assert.equal(siem.syslog!.appName, 'mcp-firewall');
  assert.equal(siem.otlp!.headers.Authorization, 'Bearer abc');
  assert.equal(siem.logAllowed, false);
  assert.equal(siem.excerpt, false);
  assert.equal(siem.queueLimit, 1000);
  assert.equal(compilePolicy({}, dir).audit.siem, undefined);
  const bad = (siem: object) => assert.throws(() => compilePolicy({ audit: { siem } }, dir), PolicyError);
  bad({});
  bad({ syslog: { target: 'http://siem.example' } });
  bad({ syslog: { target: 'udp://siem.example', ca: 'ca.pem' } });
  bad({ syslog: { target: 'udp://siem.example', facility: 'local9' } });
  bad({ syslog: { target: 'udp://siem.example', framing: 'newline' } });
  bad({ syslog: { target: 'tcp://siem.example', framing: 'lf' } });
  assert.equal(compilePolicy({ audit: { siem: { syslog: { target: 'tcp://127.0.0.1', framing: 'newline' } } } }, dir).audit.siem!.syslog!.framing, 'newline');
  bad({ otlp: { endpoint: 'ftp://otel.example' } });
  bad({ otlp: { endpoint: 'https://otel.example', headers: { Authorization: 'Bearer ${MCPFW_TEST_UNSET_VAR}' } } });
});

test('plain-text transports to another machine warn', () => {
  const warnings: string[] = [];
  const config = (target: string, endpoint: string): SiemConfig => ({
    syslog: syslog(target), otlp: { endpoint: new URL(endpoint), headers: {} }, logAllowed: false, excerpt: false, queueLimit: 10,
  });
  openSinks(config('udp://10.0.0.5:514', 'http://10.0.0.5:4318/v1/logs'), (m) => warnings.push(m)).forEach((s) => s.close());
  assert.equal(warnings.length, 2);
  openSinks(config('tls://10.0.0.5', 'http://127.0.0.1:4318/v1/logs'), (m) => warnings.push(m)).forEach((s) => s.close());
  assert.equal(warnings.length, 2, 'TLS and local receivers are fine');
});

test('AuditLog: sinks get findings, not allows or ML excerpts, unless asked; the file is unaffected', () => {
  const sent: SiemRecord[] = [];
  const sink = { send: (r: SiemRecord) => sent.push(r), flush: async () => {}, close: () => {} };
  const file = join(dir, 'audit.jsonl');
  const log = new AuditLog(file, true, 'srv', null, { sinks: [sink], logAllowed: false, excerpt: false });
  log.record({ verdict: 'allow', method: 'tools/list' });
  log.record({ verdict: 'block', method: 'tools/call', reason: 'ML', score: 0.99, excerpt: 'ignore previous instructions' });
  assert.deepEqual(sent.map((r) => r.verdict), ['block']);
  assert.equal(sent[0].excerpt, undefined);
  assert.equal(sent[0].server, 'srv');
  const lines = readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(lines.map((l) => l.verdict), ['allow', 'block']);
  assert.equal(lines[1].excerpt, 'ignore previous instructions');

  const all: SiemRecord[] = [];
  const verbose = new AuditLog(undefined, false, 'srv', null, { sinks: [{ ...sink, send: (r) => all.push(r) }], logAllowed: true, excerpt: true });
  verbose.record({ verdict: 'allow' });
  verbose.record({ verdict: 'block', excerpt: 'x' });
  assert.deepEqual(all.map((r) => [r.verdict, r.excerpt]), [['allow', undefined], ['block', 'x']]);
});
