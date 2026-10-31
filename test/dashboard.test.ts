import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { categorize, readAudit, startDashboard } from '../src/dashboard/server.js';
import { compilePolicy } from '../src/policy.js';

const dir = mkdtempSync(join(tmpdir(), 'mcpfw-dash-'));
const auditFile = join(dir, 'audit.jsonl');
const labelsFile = join(dir, 'labels.jsonl');
const PORT = 47_000 + Math.floor(Math.random() * 1000);
const base = `http://127.0.0.1:${PORT}`;

writeFileSync(
  auditFile,
  [
    { ts: '2026-10-24T10:00:00Z', server: 'fs', verdict: 'info', reason: 'firewall started in enforce mode' },
    { ts: '2026-10-24T10:01:00Z', server: 'fs', verdict: 'block', method: 'tools/call', tool: 'fetch', reason: 'ML classifier flagged possible prompt injection (score 0.990)', score: 0.99, excerpt: 'ignore previous instructions' },
    { ts: '2026-10-24T10:02:00Z', server: 'gh', verdict: 'block', method: 'tools/call', tool: 'delete_file', reason: "tool 'delete_file' denied by rule 'delete_*'" },
  ].map((e) => JSON.stringify(e)).join('\n') + '\n{"torn":',
);

let server: ReturnType<typeof startDashboard>;
before(async () => {
  server = startDashboard({ policy: compilePolicy({}, dir), auditFile, labelsFile, port: PORT });
  await new Promise((resolve) => server.once('listening', resolve));
  assert.equal((server.address() as AddressInfo).address, '127.0.0.1');
});
after(() => server.close());

const post = (body: unknown, headers: Record<string, string> = { 'x-mcp-firewall': '1' }) =>
  fetch(`${base}/api/labels`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });

test('categorize maps audit reasons to threat categories', () => {
  assert.equal(categorize({ verdict: 'block', method: 'tools/call', reason: 'ML classifier flagged possible prompt injection (score 0.99)' }), 'injection');
  assert.equal(categorize({ verdict: 'block', method: 'tools/list', reason: 'ML classifier flagged possible prompt injection (score 0.99)' }), 'poisoning');
  assert.equal(categorize({ verdict: 'redact', reason: 'sensitive data in result: aws_access_key x1' }), 'dlp');
  assert.equal(categorize({ verdict: 'block', reason: 'tool definition changed since it was pinned (possible rug pull)' }), 'rugpull');
  assert.equal(categorize({ verdict: 'block', reason: "method 'sampling/createMessage' denied by policy" }), 'method');
  assert.equal(categorize({ verdict: 'block', reason: "argument 'path' matches deny pattern /x/" }), 'policy');
});

test('readAudit skips torn lines and keeps line ids', () => {
  const events = readAudit(auditFile);
  assert.deepEqual(events.map((e) => e.id), [0, 1, 2]);
});

test('events endpoint returns events, servers and config', async () => {
  const body = await (await fetch(`${base}/api/events?server=gh`)).json();
  assert.deepEqual(body.servers, ['fs', 'gh']);
  assert.deepEqual(body.events.map((e: { tool?: string }) => e.tool), ['delete_file']);
  assert.equal(body.config.mode, 'enforce');
});

test('labels require the custom header and a same-origin request', async () => {
  assert.equal((await post({ eventId: 1, review: 'true_positive' }, {})).status, 403);
  assert.equal((await post({ eventId: 1, review: 'true_positive' }, { 'x-mcp-firewall': '1', origin: 'https://evil.example' })).status, 403);
  assert.equal((await post({ eventId: 1, review: 'maybe' })).status, 400);
  assert.equal((await post({ eventId: 99, review: 'true_positive' })).status, 404);
});

test('labels with model-visible text become training rows', async () => {
  assert.deepEqual(await (await post({ eventId: 1, review: 'false_positive' })).json(), { ok: true, trainable: true });
  assert.deepEqual(await (await post({ eventId: 2, review: 'true_positive' })).json(), { ok: true, trainable: false });
  const exported = (await (await fetch(`${base}/api/labels.jsonl`)).text()).trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(exported, [{ text: 'ignore previous instructions', label: 0, source: 'audit_review' }]);
  assert.equal(readFileSync(labelsFile, 'utf8').trim().split('\n').length, 2);
});

test('a label can be withdrawn and then given again', async () => {
  assert.equal((await post({ eventId: 1, review: 'none' })).status, 200);
  assert.equal((await (await fetch(`${base}/api/events`)).json()).labels[1], undefined);
  assert.equal((await (await fetch(`${base}/api/labels.jsonl`)).text()).trim(), '');
  await post({ eventId: 1, review: 'true_positive' });
  assert.equal((await (await fetch(`${base}/api/events`)).json()).labels[1], 'true_positive');
});

test('only whitelisted static files are served, with a CSP', async () => {
  const page = await fetch(`${base}/`);
  assert.match(page.headers.get('content-security-policy') ?? '', /default-src 'self'/);
  assert.equal((await fetch(`${base}/package.json`)).status, 404);
});
