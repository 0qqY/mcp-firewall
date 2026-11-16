import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { send } from '../src/jsonrpc.js';
import { messageReader } from './helpers.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const MOCK = fileURLToPath(new URL('./mock-server.js', import.meta.url));

test('firewall CLI enforces policy against a real stdio server process', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcpfw-e2e-'));
  const policyFile = join(dir, 'policy.yaml');
  writeFileSync(
    policyFile,
    [
      'mode: enforce',
      'tools:',
      '  rules:',
      '    - match: "delete_*"',
      '      action: deny',
      '    - match: read_file',
      '      action: allow',
      '      arguments:',
      '        path:',
      "          deny: ['\\.\\.[/\\\\]']",
    ].join('\n'),
  );

  const child = spawn(process.execPath, [CLI, '--policy', policyFile, '--name', 'mock', '--', process.execPath, MOCK], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const out = messageReader(child.stdout);
  const request = (id: number, method: string, params?: object) => send(child.stdin, { jsonrpc: '2.0', id, method, params });

  request(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
  assert.equal((await out.next()).result.serverInfo.name, 'mock-server');

  request(2, 'tools/list');
  const tools = (await out.next()).result.tools.map((t: { name: string }) => t.name);
  assert.deepEqual(tools, ['read_file', 'echo']);

  request(3, 'tools/call', { name: 'read_file', arguments: { path: '/projects/config.txt' } });
  assert.equal((await out.next()).result.content[0].text, 'contents of /projects/config.txt: aws_key=[REDACTED:aws_access_key]');

  request(4, 'tools/call', { name: 'read_file', arguments: { path: '../../secret' } });
  assert.equal((await out.next()).result.isError, true);

  request(5, 'tools/call', { name: 'delete_file', arguments: { path: 'a' } });
  assert.equal((await out.next()).result.isError, true);

  child.stdin.end();
  const code = await new Promise((resolve) => child.on('exit', resolve));
  assert.equal(code, 0);

  const audit = readFileSync(join(dir, 'mcp-firewall-audit.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(audit.filter((e) => e.verdict === 'block').length, 4); // delete_file + add hidden, two calls blocked
  assert.ok(audit.some((e) => e.verdict === 'redact' && e.tool === 'read_file'));
  assert.ok(readFileSync(join(dir, 'mcp-firewall-pins.json'), 'utf8').includes('"mock"'));
});

test('a delete_* deny rule also catches deleteFile and Delete-File through the real CLI (style-blind deny)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcpfw-e2e-style-'));
  const policyFile = join(dir, 'policy.yaml');
  writeFileSync(policyFile, ['mode: enforce', 'tools:', '  rules:', '    - match: "delete_*"', '      action: deny'].join('\n'));
  const child = spawn(process.execPath, [CLI, '--policy', policyFile, '--name', 'mock-style', '--', process.execPath, MOCK], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, MOCK_STYLE_TOOLS: '1' },
  });
  const out = messageReader(child.stdout);
  const request = (id: number, method: string, params?: object) => send(child.stdin, { jsonrpc: '2.0', id, method, params });
  request(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
  await out.next();
  request(2, 'tools/list');
  const tools = (await out.next()).result.tools.map((t: { name: string }) => t.name);
  // DELETEFILE has no word boundary to split on, so delete_* cannot catch it (documented; write delete* for that).
  assert.deepEqual(tools.filter((n: string) => /delete/i.test(n)), ['DELETEFILE']);
  for (const [id, name] of [[3, 'deleteFile'], [4, 'Delete-File']] as const) {
    request(id, 'tools/call', { name, arguments: { path: 'a' } });
    const r = (await out.next()).result;
    assert.equal(r.isError, true, name);
    assert.doesNotMatch(r.content[0].text, /deleted/, `${name} reached the server`);
  }
  child.stdin.end();
  await new Promise((resolve) => child.on('exit', resolve));
});
