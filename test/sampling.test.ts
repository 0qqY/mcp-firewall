import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { AuditLog } from '../src/audit.js';
import { send } from '../src/jsonrpc.js';
import { compilePolicy } from '../src/policy.js';
import { FirewallProxy } from '../src/proxy.js';
import { messageReader, tick } from './helpers.js';

const dir = mkdtempSync(join(tmpdir(), 'mcpfw-sampling-'));

function harness(sampling: object, mode = 'enforce') {
  const policy = compilePolicy({ mode, pinning: { enabled: false }, sampling }, dir);
  const clientOut = new PassThrough();
  const serverIn = new PassThrough();
  const serverOut = new PassThrough();
  const proxy = new FirewallProxy(policy, new AuditLog(undefined, false, 'test', null), undefined, { clientIn: new PassThrough(), clientOut, serverIn, serverOut });
  let clock = 0;
  proxy.now = () => clock;
  proxy.start();
  const atClient = messageReader(clientOut);
  const atServer = messageReader(serverIn);
  return {
    advance: (ms: number) => (clock += ms),
    /** Sends a sampling request from the server; resolves to 'forwarded' (with params) or the refusal message. */
    async sample(id: number, maxTokens = 100) {
      send(serverOut, { jsonrpc: '2.0', id, method: 'sampling/createMessage', params: { messages: [{ role: 'user', content: { type: 'text', text: 'Summarize' } }], maxTokens } });
      await tick();
      if (atClient.buffered > 0) return { forwarded: (await atClient.next()).params };
      return { refused: (await atServer.next()).error.message as string };
    },
  };
}

test('sampling requests over the per-minute rate are refused until the window passes', async () => {
  const h = harness({ maxPerMinute: 2 });
  assert.ok((await h.sample(1)).forwarded);
  assert.ok((await h.sample(2)).forwarded);
  assert.match((await h.sample(3)).refused!, /rate limit/);
  h.advance(61_000);
  assert.ok((await h.sample(4)).forwarded);
});

test('per-session request and token budgets are enforced', async () => {
  const requests = harness({ maxPerMinute: 0, maxPerSession: 2 });
  await requests.sample(1);
  await requests.sample(2);
  assert.match((await requests.sample(3)).refused!, /per session/);

  const tokens = harness({ maxPerMinute: 0, maxTokensPerSession: 1000 });
  assert.ok((await tokens.sample(1, 600)).forwarded);
  assert.match((await tokens.sample(2, 600)).refused!, /token budget/);
  assert.ok((await tokens.sample(3, 400)).forwarded);
});

test('oversized maxTokens is lowered to the per-request cap', async () => {
  const h = harness({ maxTokensPerRequest: 500 });
  assert.equal((await h.sample(1, 100_000)).forwarded!.maxTokens, 500);
  assert.equal((await h.sample(2, 200)).forwarded!.maxTokens, 200);
});

test('monitor mode forwards over-limit requests unchanged', async () => {
  const h = harness({ maxPerMinute: 1, maxTokensPerRequest: 10 }, 'monitor');
  await h.sample(1);
  const over = await h.sample(2, 50);
  assert.equal(over.forwarded!.maxTokens, 50);
});

test('zero disables a limit', async () => {
  const h = harness({ maxPerMinute: 0, maxPerSession: 0, maxTokensPerRequest: 0, maxTokensPerSession: 0 });
  for (let i = 1; i <= 30; i++) assert.equal((await h.sample(i, 1_000_000)).forwarded!.maxTokens, 1_000_000);
});
