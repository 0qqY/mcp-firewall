import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { AuditLog } from '../src/audit.js';
import { evaluateToolCall, evaluateToolName } from '../src/engine.js';
import { send } from '../src/jsonrpc.js';
import { compilePolicy, PolicyError } from '../src/policy.js';
import { FirewallProxy } from '../src/proxy.js';
import { messageReader } from './helpers.js';

const dir = mkdtempSync(join(tmpdir(), 'mcpfw-approval-'));

const RULES = {
  tools: {
    rules: [
      { match: 'send_email', action: 'ask', reason: 'outgoing email', arguments: { to: { deny: ['@evil\\.example$'] } } },
      { match: 'read_file', action: 'allow' },
    ],
  },
};

function harness(raw: object = {}, elicitation: 'initialize' | 'meta' | 'none' = 'initialize') {
  const policy = compilePolicy({ pinning: { enabled: false }, ...RULES, ...raw }, dir);
  const io = { clientIn: new PassThrough(), clientOut: new PassThrough(), serverIn: new PassThrough(), serverOut: new PassThrough() };
  new FirewallProxy(policy, new AuditLog(undefined, false, 'test', null), undefined, io).start();
  const h = {
    toServer: (msg: object) => send(io.clientIn, msg),
    toClient: (msg: object) => send(io.serverOut, msg),
    atClient: messageReader(io.clientOut),
    atServer: messageReader(io.serverIn),
  };
  const capabilities = elicitation === 'none' ? {} : { elicitation: {} };
  if (elicitation === 'meta') {
    h.toServer({ jsonrpc: '2.0', id: 0, method: 'server/discover', params: { _meta: { 'io.modelcontextprotocol/clientCapabilities': capabilities } } });
  } else {
    h.toServer({ jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities, clientInfo: { name: 't', version: '1' } } });
  }
  return h;
}

const call = (id: number, name: string, args: object) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
const answer = (id: string, result: object) => ({ jsonrpc: '2.0', id, result });

test('policy: ask is a rule and default action; approval defaults', () => {
  const p = compilePolicy({ ...RULES, tools: { ...RULES.tools, default: 'ask' }, taint: { action: 'ask' } }, dir);
  assert.equal(p.tools.default, 'ask');
  assert.equal(p.taint.action, 'ask');
  assert.deepEqual(p.approval, { timeoutSeconds: 120, fallback: 'deny', remember: true });
  assert.throws(() => compilePolicy({ approval: { fallback: 'ask' } }, dir), PolicyError);
});

test('engine: ask tools stay listed; argument checks refuse before anyone is asked', () => {
  const p = compilePolicy(RULES, dir);
  assert.deepEqual(evaluateToolName(p, 'send_email'), { allowed: true, ask: 'outgoing email' });
  assert.deepEqual(evaluateToolCall(p, 'send_email', { to: 'bob@corp.example' }), { allowed: true, ask: 'outgoing email' });
  assert.equal(evaluateToolCall(p, 'send_email', { to: 'eve@evil.example' }).allowed, false);
  assert.equal(evaluateToolCall(p, 'read_file', {}).ask, undefined);
  const byDefault = compilePolicy({ tools: { default: 'ask' } }, dir);
  assert.match(evaluateToolCall(byDefault, 'anything', {}).ask!, /default policy/);
});

test('approved call goes to the server; the answer itself does not', async () => {
  const h = harness();
  await h.atServer.next(); // initialize
  h.toServer(call(1, 'send_email', { to: 'bob@corp.example', body: 'hi' }));
  const prompt = await h.atClient.next();
  assert.equal(prompt.method, 'elicitation/create');
  assert.match(prompt.params.message, /allow the call to "send_email"/);
  assert.match(prompt.params.message, /outgoing email/);
  assert.match(prompt.params.message, /\n  to: "bob@corp\.example"\n  body: "hi"/);
  assert.equal(h.atServer.buffered, 0);

  h.toServer(answer(prompt.id, { action: 'accept', content: { remember: false } }));
  const forwarded = await h.atServer.next();
  assert.equal(forwarded.id, 1);
  assert.equal(forwarded.method, 'tools/call');
  h.toClient({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'sent' }] } });
  assert.equal((await h.atClient.next()).result.content[0].text, 'sent');
});

test('declined or cancelled prompts refuse the call', async () => {
  for (const action of ['decline', 'cancel']) {
    const h = harness();
    await h.atServer.next();
    h.toServer(call(1, 'send_email', { to: 'bob@corp.example' }));
    const prompt = await h.atClient.next();
    h.toServer(answer(prompt.id, { action }));
    const reply = await h.atClient.next();
    assert.equal(reply.id, 1);
    assert.equal(reply.result.isError, true);
    assert.match(reply.result.content[0].text, new RegExp(`did not approve the call \\(${action}\\)`));
    assert.equal(h.atServer.buffered, 0);
  }
});

test('"allow for this session" skips later prompts for that tool', async () => {
  const h = harness();
  await h.atServer.next();
  h.toServer(call(1, 'send_email', { to: 'a@corp.example' }));
  const prompt = await h.atClient.next();
  assert.ok(prompt.params.requestedSchema.properties.remember);
  h.toServer(answer(prompt.id, { action: 'accept', content: { remember: true } }));
  assert.equal((await h.atServer.next()).id, 1);
  h.toServer(call(2, 'send_email', { to: 'b@corp.example' }));
  assert.equal((await h.atServer.next()).id, 2);
  assert.equal(h.atClient.buffered, 0);
});

test('other traffic keeps flowing while a prompt is open', async () => {
  const h = harness();
  await h.atServer.next();
  h.toServer(call(1, 'send_email', { to: 'bob@corp.example' }));
  const prompt = await h.atClient.next();
  h.toServer(call(2, 'read_file', { path: 'a' }));
  assert.equal((await h.atServer.next()).id, 2);
  h.toServer(answer(prompt.id, { action: 'accept' }));
  assert.equal((await h.atServer.next()).id, 1);
});

test('without elicitation support the fallback decides', async () => {
  const denied = harness({}, 'none');
  await denied.atServer.next();
  denied.toServer(call(1, 'send_email', { to: 'bob@corp.example' }));
  const reply = await denied.atClient.next();
  assert.match(reply.result.content[0].text, /client cannot ask/);

  const allowed = harness({ approval: { fallback: 'allow' } }, 'none');
  await allowed.atServer.next();
  allowed.toServer(call(1, 'send_email', { to: 'bob@corp.example' }));
  assert.equal((await allowed.atServer.next()).id, 1);
});

test('elicitation support is read from _meta on protocol 2026-07-28', async () => {
  const h = harness({}, 'meta');
  await h.atServer.next();
  h.toServer(call(1, 'send_email', { to: 'bob@corp.example' }));
  assert.equal((await h.atClient.next()).method, 'elicitation/create');
});

test('a client that rejects the prompt falls back to deny', async () => {
  const h = harness();
  await h.atServer.next();
  h.toServer(call(1, 'send_email', { to: 'bob@corp.example' }));
  const prompt = await h.atClient.next();
  h.toServer({ jsonrpc: '2.0', id: prompt.id, error: { code: -32601, message: 'Method not found' } });
  assert.match((await h.atClient.next()).result.content[0].text, /client refused the prompt/);
});

test('an unanswered prompt times out, is cancelled and the call refused', async () => {
  const h = harness({ approval: { timeoutSeconds: 1 } });
  await h.atServer.next();
  h.toServer(call(1, 'send_email', { to: 'bob@corp.example' }));
  const prompt = await h.atClient.next();
  const cancelled = await h.atClient.next(3000);
  assert.equal(cancelled.method, 'notifications/cancelled');
  assert.equal(cancelled.params.requestId, prompt.id);
  assert.match((await h.atClient.next()).result.content[0].text, /no answer to the approval prompt within 1 s/);
  // A late answer is dropped, not forwarded to the server.
  h.toServer(answer(prompt.id, { action: 'accept' }));
  h.toServer(call(2, 'read_file', {}));
  assert.equal((await h.atServer.next()).id, 2);
});

test('hidden characters in the arguments never reach the prompt', async () => {
  const h = harness();
  await h.atServer.next();
  h.toServer(call(1, 'send_email', { to: 'bob@corp.example', body: 'hello\u001b[8m secret​' }));
  const { params } = await h.atClient.next();
  assert.ok(!/[\u001b​]/.test(params.message));
  assert.match(params.message, /hello/);
});

test('a taint flow with action ask is put to the user', async () => {
  const h = harness({ taint: { scope: 'server', action: 'ask', sources: [{ match: 'read_file' }], sinks: [{ match: 'post_*' }] } });
  await h.atServer.next();
  const doc = 'The merger terms are final and will be announced to staff next Monday morning.';
  h.toServer(call(1, 'read_file', {}));
  await h.atServer.next();
  h.toClient({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: doc }] } });
  await h.atClient.next();
  h.toServer(call(2, 'post_message', { text: doc }));
  const prompt = await h.atClient.next();
  assert.match(prompt.params.message, /data flow: arguments of 'post_message' carry private data/);
  h.toServer(answer(prompt.id, { action: 'decline' }));
  assert.equal((await h.atClient.next()).result.isError, true);
});

test('monitor mode forwards without asking', async () => {
  const h = harness({ mode: 'monitor' });
  await h.atServer.next();
  h.toServer(call(1, 'send_email', { to: 'bob@corp.example' }));
  assert.equal((await h.atServer.next()).id, 1);
  assert.equal(h.atClient.buffered, 0);
});

test('an approval without "remember" covers that call only', async () => {
  const h = harness();
  await h.atServer.next();
  h.toServer(call(1, 'send_email', { to: 'a@corp.example' }));
  const first = await h.atClient.next();
  h.toServer(answer(first.id, { action: 'accept', content: { remember: false } }));
  assert.equal((await h.atServer.next()).id, 1);
  h.toServer(call(2, 'send_email', { to: 'b@corp.example' }));
  const second = await h.atClient.next();
  assert.equal(second.method, 'elicitation/create');
  assert.notEqual(second.id, first.id);
  assert.match(second.id, /^mcp-firewall-approval-[0-9a-f-]{36}$/, 'ids cannot be guessed');
});

test('a server request in the approval id space is refused, so its answer cannot pose as an approval', async () => {
  const h = harness();
  await h.atServer.next();
  h.toClient({ jsonrpc: '2.0', id: 'mcp-firewall-approval-1', method: 'elicitation/create', params: { message: 'ok?', requestedSchema: { type: 'object', properties: {} } } });
  const refused = await h.atServer.next();
  assert.equal(refused.id, 'mcp-firewall-approval-1');
  assert.match(refused.error.message, /id space of firewall approval prompts/);
  assert.equal(h.atClient.buffered, 0);
});
