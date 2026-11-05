// Runs the OFFICIAL @modelcontextprotocol/server-filesystem behind the firewall (real model) and reads three
// files from ./sandbox:
//   onboarding.txt — an ordinary note (passes)
//   config.env     — AWS keys (DLP redacts both the access-key id and the secret value; result passes, masked)
//   notes.md       — a markdown file whose comment carries an indirect injection (ML blocks)
// Audit, pins and policy are written next to this script as run-*. Needs a built dist and a local model
// (MCP_FIREWALL_MODEL overrides the path; default ./models/... at the repo root). Requires npx (network on the
// first run to fetch the server). On Windows keep the checkout path short — npx cannot start from a very deep cwd.
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..');
const cli = join(repo, 'dist', 'src', 'cli.js');
const model = process.env.MCP_FIREWALL_MODEL ?? join(repo, 'models', 'mcp-pi-mmbert-mix-ab4-lab-30');
if (!existsSync(cli)) throw new Error(`build first (npm run build): ${cli} is missing`);
if (!existsSync(model)) throw new Error(`model not found: ${model}. Set MCP_FIREWALL_MODEL to its path.`);

const sandbox = join(here, 'sandbox');
const auditFile = join(here, 'run-audit.jsonl');
const pinFile = join(here, 'run-pins.json');
for (const f of [auditFile, pinFile, pinFile.replace('.json', '.pending.json')]) if (existsSync(f)) rmSync(f);

const policyFile = join(here, 'run-policy.yaml');
writeFileSync(policyFile, [
  'version: 1', 'mode: enforce',
  `audit: { file: ${JSON.stringify(auditFile)}, logAllowed: true }`,
  'decoding: { enabled: true }',
  `pinning: { enabled: true, file: ${JSON.stringify(pinFile)}, onChange: hide }`,
  'dlp: { enabled: true, action: redact }',
  'ml:', '  enabled: true', `  model: ${JSON.stringify(model)}`,
  '  threshold: 0.9', '  scan: { toolResults: block }', '',
].join('\n'));

// The firewall wraps the official server. cwd is a short temp dir so the npx-spawned node can start even when
// the checkout path is deep (Windows MAX_PATH); the sandbox and policy are passed as absolute paths.
const child = spawn('node', [cli, '--policy', policyFile, '--name', 'filesystem', '--', 'npx', '-y', '@modelcontextprotocol/server-filesystem', sandbox], { stdio: ['pipe', 'pipe', 'inherit'], cwd: tmpdir() });

const files = [['onboarding.txt', 'benign'], ['config.env', 'secret'], ['notes.md', 'injection']];
const results = {};
let readTool = 'read_text_file';
const setup = [
  { id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'fs-demo', version: '1' } } },
  { method: 'notifications/initialized' },
  { id: 2, method: 'tools/list' },
];
let phase = 'setup', step = 0;
const next = () => {
  if (phase === 'setup' && step < setup.length) { const s = setup[step++]; child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...s })}\n`); if (s.id === undefined) next(); return; }
  if (phase === 'reads' && step < files.length) { const [name] = files[step]; child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 10 + step, method: 'tools/call', params: { name: readTool, arguments: { path: join(sandbox, name) } } })}\n`); step++; return; }
  child.stdin.end();
};
const timer = setTimeout(() => { console.log('TIMEOUT'); child.kill(); }, 120_000);
let buf = '';
child.stdout.on('data', (d) => {
  buf += d;
  for (let i; (i = buf.indexOf('\n')) >= 0; ) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id === 2) { const names = (msg.result?.tools ?? []).map((t) => t.name); readTool = names.find((n) => n === 'read_text_file') ?? names.find((n) => n === 'read_file') ?? readTool; console.log(`read tool: ${readTool}`); phase = 'reads'; step = 0; }
    if (msg.id >= 10 && msg.id < 20) { const [name, kind] = files[msg.id - 10]; const text = msg.result?.content?.[0]?.text ?? JSON.stringify(msg.error); const blocked = !!(msg.result?.isError || msg.error); const redacted = /\[REDACTED:/.test(String(text)); results[name] = { kind, blocked, redacted, text: String(text).replace(/\s+/g, ' ').slice(0, 72) }; }
    if (msg.id !== undefined) next();
  }
});
child.on('exit', () => {
  clearTimeout(timer);
  console.log('\nFILE                TYPE        FIREWALL');
  for (const [name, kind] of files) { const r = results[name] ?? {}; const verdict = r.blocked ? 'BLOCKED' : r.redacted ? 'MASKED (passed)' : 'passed'; console.log(`${name.padEnd(19)} ${kind.padEnd(11)} ${verdict}  ${r.text ?? ''}`); }
  for (const line of readFileSync(auditFile, 'utf8').trim().split('\n')) { const e = JSON.parse(line); if (['block', 'redact'].includes(e.verdict)) console.log(`  audit: ${e.verdict} ${e.tool ?? ''}${e.score !== undefined ? ` score=${e.score.toFixed(3)}` : ''}  ${e.reason ?? ''}`.slice(0, 130)); }
});
next();
