import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { inventory } from '../src/dashboard/inventory.js';
import type { StoredEvent } from '../src/dashboard/server.js';
import { compilePolicy } from '../src/policy.js';

const dir = mkdtempSync(join(tmpdir(), 'mcpfw-inv-'));
const write = (name: string, body: unknown) => {
  const file = join(dir, name);
  writeFileSync(file, typeof body === 'string' ? body : JSON.stringify(body));
  return file;
};

const policyFile = write('policy.yaml', `
mode: enforce
tools:
  rules:
    - match: "delete_*"
      action: deny
pinning:
  file: ./pins.json
`);
write('pins.json', { gh: { get_file_contents: 'a', create_issue: 'b', push_files: 'c', delete_file: 'd', '@server-code': 'e' } });
write('pins.pending.json', { gh: { push_files: 'f' } });

const claude = write('claude.json', {
  mcpServers: {
    gh: { command: 'node', args: ['/x/.mcp-firewall/app/dist/src/cli.js', '--policy', policyFile, '--name', 'gh', '--', 'docker', 'run', '-i', '--rm', 'ghcr.io/github/github-mcp-server:v2@sha256:' + 'a'.repeat(64)] },
    loose: { command: 'npx', args: ['-y', 'some-mcp-server'], env: { API_TOKEN: 'ghp_abcdefghijklmnop', DEBUG: '1' } },
  },
  projects: { 'C:/code/app': { mcpServers: { sql: { command: 'uvx', args: ['mcp-sql==1.2.0', '--token=sk-secretsecret'] } } } },
});

const now = Date.parse('2026-11-01T12:00:00Z');
const ev = (server: string, verdict: string, category: StoredEvent['category'], hoursAgo: number): StoredEvent =>
  ({ id: 0, ts: new Date(now - hoursAgo * 3600e3).toISOString(), server, verdict, category } as StoredEvent);

const result = inventory({
  configFiles: [[claude, 'Claude Code'], [join(dir, 'missing.json'), 'Claude Desktop']],
  events: [ev('gh', 'block', 'injection', 1), ev('gh', 'block', 'injection', 2), ev('gh', 'block', 'injection', 24 * 30), ev('ghost', 'allow', 'other', 1)],
  fallbackPolicy: compilePolicy({}, dir),
  now,
});
const byName = Object.fromEntries(result.map((s) => [s.name, s]));

test('lists configured servers, project-scoped ones and servers seen only in the audit log, riskiest first', () => {
  assert.deepEqual(Object.keys(byName).sort(), ['gh', 'ghost', 'loose', 'sql']);
  assert.equal(result[0].name, 'loose');
  assert.deepEqual(byName.sql.clients, ['Claude Code (app)']);
  assert.ok(byName.ghost.good[0].includes('olay kaydında'));
  for (let i = 1; i < result.length; i++) assert.ok(result[i - 1].score >= result[i].score);
});

test('an unwrapped server with a floating version and a plain-text token scores high', () => {
  const s = byName.loose;
  assert.equal(s.firewalled, false);
  assert.equal(s.level, 'high');
  const ids = s.factors.map((f) => f.id);
  assert.ok(ids.includes('unprotected') && ids.includes('floating') && ids.includes('secret'));
  assert.match(s.factors.find((f) => f.id === 'unprotected')!.snippet!, /^mcp-firewall --name loose -- npx -y some-mcp-server$/);
  // Key names are shown, never the values.
  assert.ok(!JSON.stringify(s).includes('ghp_abcdefghijklmnop'));
  assert.ok(s.factors.find((f) => f.id === 'secret')!.why.includes('API_TOKEN'));
});

test('command-line secrets are masked in the target', () => {
  assert.ok(!byName.sql.target.includes('sk-secretsecret'));
  assert.ok(byName.sql.factors.some((f) => f.id === 'secret'));
});

test('a wrapped server is scored from its own policy, pins, pending changes and last week of audit', () => {
  const s = byName.gh;
  assert.equal(s.firewalled, true);
  assert.equal(s.target.startsWith('docker run'), true);
  assert.deepEqual(s.tools.denied, ['delete_file']);
  assert.deepEqual(s.tools.read, ['get_file_contents']);
  assert.deepEqual(s.tools.write.sort(), ['create_issue', 'push_files']);
  assert.equal(s.tools.total, 4, '@-entries (server code, prompts) are not tools');
  const ids = s.factors.map((f) => f.id);
  assert.ok(ids.includes('trifecta'), 'reads and writes with taint off');
  assert.ok(ids.includes('rugpull'), 'a pending change');
  assert.ok(!ids.includes('floating') && !ids.includes('destructive'));
  assert.equal(s.week.blocked, 2, 'only the last 7 days count');
  assert.ok(s.good.some((g) => g.includes('Silme araçları kapalı')));
  assert.match(s.factors.find((f) => f.id === 'trifecta')!.snippet!, /match: "push_files"/);
});

test('taint rules and ask rules lower the score', () => {
  const safer = write('safer.yaml', `
tools:
  rules:
    - match: "delete_*"
      action: deny
    - match: "push_files"
      action: ask
taint:
  sources: [{ match: "get_*" }]
  sinks: [{ match: "create_*" }]
pinning:
  file: ./pins.json
  onNew: hide
`);
  const cfg = write('claude2.json', { mcpServers: { gh: { command: 'mcp-firewall', args: ['--policy', safer, '--name', 'gh', '--', 'docker', 'run', 'ghcr.io/github/github-mcp-server@sha256:' + 'a'.repeat(64)] } } });
  const [s] = inventory({ configFiles: [[cfg, 'Claude Code']], events: [], fallbackPolicy: compilePolicy({}, dir), now });
  const ids = s.factors.map((f) => f.id);
  assert.ok(!ids.includes('trifecta') && !ids.includes('write') && !ids.includes('pin-new'));
  assert.deepEqual(s.tools.asked, ['push_files']);
  assert.ok(s.score < byName.gh.score);
});
