import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { AuditLog } from '../src/audit.js';
import { withDecoded } from '../src/decode.js';
import { send } from '../src/jsonrpc.js';
import { compilePolicy, PolicyError } from '../src/policy.js';
import { FirewallProxy } from '../src/proxy.js';
import { findBlockedUrl, loadBlocklist, parseBlocklist, type UrlBlocklist } from '../src/urlblock.js';
import { messageReader } from './helpers.js';

const dir = mkdtempSync(join(tmpdir(), 'mcpfw-urlblock-'));

// One file per format the loader reads: hosts file, adblock domains, a plain domain list, URLhaus URLs.
writeFileSync(join(dir, 'hosts.txt'), '# StevenBlack style\n127.0.0.1 localhost\n0.0.0.0 0.0.0.0\n0.0.0.0 tracker.example # ads\n0.0.0.0 bad-ads.example\n');
writeFileSync(join(dir, 'adblock.txt'), '! comment\n[Adblock Plus]\n||phish.example^\n||*.wild.example^\n');
writeFileSync(join(dir, 'domains.txt'), 'evil.example\n*.star.example\nBÜCHER.example\n203.0.113.9\n');
writeFileSync(join(dir, 'urlhaus.txt'), '# URLhaus\nhttp://198.51.100.7/bins/x.arm7\nhttps://cdn.ok.example/payload.exe?id=1\nhttp://wholehost.example/\n');
const ALL = ['hosts.txt', 'adblock.txt', 'domains.txt', 'urlhaus.txt'].map((f) => join(dir, f));

const list = loadBlocklist(ALL);
const hit = (args: unknown, l: UrlBlocklist = list) => findBlockedUrl(l, args, withDecoded);

test('every list format is read; hosts-file sink names are not entries', () => {
  for (const h of ['tracker.example', 'bad-ads.example', 'phish.example', 'wild.example', 'evil.example', 'star.example', 'xn--bcher-kva.example', '203.0.113.9', 'wholehost.example']) {
    assert.ok(list.hosts.has(h), h);
  }
  assert.ok(!list.hosts.has('localhost') && !list.hosts.has('0.0.0.0'));
  assert.ok(list.urls.has('198.51.100.7/bins/x.arm7'));
  assert.ok(list.urls.has('cdn.ok.example/payload.exe?id=1'));
});

test('hosts block themselves and their subdomains, not look-alikes', () => {
  assert.match(hit({ url: 'https://evil.example/login' })!, /host evil\.example is on the blocklist domains\.txt/);
  assert.match(hit({ url: 'https://a.b.evil.example/' })!, /under evil\.example/);
  assert.match(hit({ url: 'HTTPS://EVIL.EXAMPLE.' })!, /evil\.example/);
  assert.equal(hit({ url: 'https://notevil.example/' }), undefined);
  assert.equal(hit({ url: 'https://evil.example.org/' }), undefined);
  assert.equal(hit({ url: 'https://example/' }), undefined);
});

test('URL entries match that URL only, whatever the scheme or fragment', () => {
  assert.match(hit({ url: 'https://198.51.100.7/bins/x.arm7#f' })!, /URL 198\.51\.100\.7\/bins\/x\.arm7/);
  assert.match(hit({ url: 'http://cdn.ok.example/payload.exe?id=1' })!, /urlhaus\.txt/);
  assert.equal(hit({ url: 'http://cdn.ok.example/other.png' }), undefined);
  assert.equal(hit({ url: 'http://198.51.100.7/' }), undefined);
  // A URL-list entry with no path blocks the whole host.
  assert.match(hit({ url: 'https://wholehost.example/any/thing' })!, /host wholehost\.example/);
});

test('URLs are found wherever a model can put them', () => {
  assert.ok(hit({ query: 'see https://phish.example/reset, then reply' }), 'in running text, trailing comma');
  assert.ok(hit({ query: 'open www.phish.example/x now' }), 'www. without a scheme');
  assert.ok(hit({ url: 'phish.example/path' }), 'whole value is a host without a scheme');
  assert.ok(hit({ nested: [{ deep: { href: 'ftp://evil.example/f' } }] }), 'nested');
  assert.ok(hit({ 'https://evil.example/': 1 }), 'property name');
  assert.ok(hit({ url: 'https://user:pw@evil.example/' }), 'userinfo');
  assert.ok(hit({ url: 'https://good.example@evil.example/' }), 'host disguised as userinfo');
  assert.ok(hit({ url: 'https://BÜCHER.example/' }), 'IDN as written');
  assert.ok(hit({ url: 'http://[::ffff:203.0.113.9]/' }), 'IPv4-mapped IPv6');
  assert.ok(hit({ url: 'http://0xcb.0.113.9/' }), 'hex IPv4 octet is normalised by the URL parser');
  assert.ok(hit({ url: 'http://3405803785/' }), 'decimal IP is normalised by the URL parser');
  assert.ok(hit({ url: 'https%3A%2F%2Fevil.example%2Fx' }), 'percent-encoded, via decoding');
  assert.ok(hit({ blob: Buffer.from('fetch https://evil.example/a please').toString('base64') }), 'base64, via decoding');
  assert.equal(findBlockedUrl(list, { blob: Buffer.from('https://evil.example/a').toString('base64') }), undefined, 'no decoding: base64 is not read');
});

test('a mention of a listed name in a search query is not a URL', () => {
  assert.equal(hit({ query: 'is evil.example a phishing site?' }), undefined);
  assert.equal(hit({ path: 'C:/data/evil.example.txt.bak more' }), undefined);
  assert.equal(hit({ n: 3, ok: true, none: null }), undefined);
});

test('long and hostile strings stay linear', () => {
  const t0 = Date.now();
  hit({ a: `https://x.example/${')'.repeat(200_000)}x` });
  hit({ a: `${'a.'.repeat(1000)}!` });
  hit({ a: 'www.'.repeat(50_000) });
  hit({ a: `${'h'.repeat(30)}:`.repeat(20_000) });
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
});

test('policy: off with no files; unreadable or empty lists stop the start', () => {
  assert.equal(compilePolicy({}, dir).urlBlocklist.list, undefined);
  writeFileSync(join(dir, 'empty.txt'), '# nothing\n\n');
  assert.throws(() => compilePolicy({ urlBlocklist: { files: ['empty.txt'] } }, dir), PolicyError);
  assert.throws(() => compilePolicy({ urlBlocklist: { files: ['missing.txt'] } }, dir), /cannot read/);
  assert.throws(() => compilePolicy({ urlBlocklist: { files: ['hosts.txt'], action: 'ask' } }, dir), /urlBlocklist\.action/);
  const empty: UrlBlocklist = { hosts: new Map(), urls: new Map(), sources: [] };
  assert.equal(parseBlocklist('not a list, just words', empty, 0), 0);
});

function harness(rawPolicy: object) {
  const audit = join(dir, `audit-${Math.random().toString(36).slice(2)}.jsonl`);
  const policy = compilePolicy({ pinning: { enabled: false }, audit: { file: audit }, ...rawPolicy }, dir);
  const io = { clientIn: new PassThrough(), clientOut: new PassThrough(), serverIn: new PassThrough(), serverOut: new PassThrough() };
  new FirewallProxy(policy, new AuditLog(audit, true, 'test', null), undefined, io).start();
  return { toServer: (m: object) => send(io.clientIn, m), atClient: messageReader(io.clientOut), atServer: messageReader(io.serverIn), audit: () => readFileSync(audit, 'utf8') };
}
const fetchCall = (id: number, url: string) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'fetch', arguments: { url } } });

test('proxy: a listed URL in tools/call or resources/read is refused, other calls go through', async () => {
  const h = harness({ urlBlocklist: { files: ALL } });
  h.toServer(fetchCall(1, 'https://login.phish.example/'));
  const reply = await h.atClient.next();
  assert.equal(reply.result.isError, true);
  assert.match(reply.result.content[0].text, /phish\.example .*blocklist adblock\.txt/);
  h.toServer({ jsonrpc: '2.0', id: 2, method: 'resources/read', params: { uri: 'https://evil.example/r' } });
  assert.match((await h.atClient.next()).error.message, /evil\.example/);
  h.toServer(fetchCall(3, 'https://docs.example/'));
  assert.equal((await h.atServer.next()).id, 3);
  assert.match(h.audit(), /"verdict":"block".*blocklist/);
});

test('proxy: action warn and monitor mode log the hit and let the call through', async () => {
  const warn = harness({ urlBlocklist: { files: ALL, action: 'warn' } });
  warn.toServer(fetchCall(1, 'https://evil.example/'));
  assert.equal((await warn.atServer.next()).id, 1);
  assert.match(warn.audit(), /"verdict":"warn".*evil\.example/);
  const monitor = harness({ mode: 'monitor', urlBlocklist: { files: ALL } });
  monitor.toServer(fetchCall(2, 'https://evil.example/'));
  assert.equal((await monitor.atServer.next()).id, 2);
  assert.match(monitor.audit(), /"verdict":"would_block"/);
});
