// Runs sql-server.mjs (in-memory SQLite) behind the firewall (real model) and sends four queries that each
// exercise a different layer:
//   SELECT products       — ordinary rows (passes)
//   SELECT tickets        — a row whose body carries an indirect injection (ML blocks the result)
//   SELECT app_config     — a row holding a GitHub token (DLP redacts the result; it passes, masked)
//   DROP TABLE products   — a destructive statement (policy denies it on the request side; never reaches the DB)
// Audit/pins/policy are written next to this script as run-*. Needs a built dist and a local model
// (MCP_FIREWALL_MODEL overrides; default ./models/... at the repo root). Self-contained — no external network.
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..');
const cli = join(repo, 'dist', 'src', 'cli.js');
const model = process.env.MCP_FIREWALL_MODEL ?? join(repo, 'models', 'mcp-pi-mmbert-soup05-ab2');
if (!existsSync(cli)) throw new Error(`build first (npm run build): ${cli} is missing`);
if (!existsSync(model)) throw new Error(`model not found: ${model}. Set MCP_FIREWALL_MODEL to its path.`);

const auditFile = join(here, 'run-audit.jsonl');
const pinFile = join(here, 'run-pins.json');
for (const f of [auditFile, pinFile, pinFile.replace('.json', '.pending.json')]) if (existsSync(f)) rmSync(f);

// Read-only database access: the query tool is allowed, but statements that mutate the schema or data are denied
// before they ever reach the server (case-insensitive — argument patterns compile with the i flag).
const policyFile = join(here, 'run-policy.yaml');
writeFileSync(policyFile, [
  'version: 1', 'mode: enforce',
  `audit: { file: ${JSON.stringify(auditFile)}, logAllowed: true }`,
  'tools:',
  '  default: allow',
  '  rules:',
  '    - match: query',
  '      action: allow',
  '      arguments:',
  '        sql:',
  "          deny: ['\\b(insert|update|delete|drop|alter|truncate|create|replace|attach|pragma)\\b']",
  'decoding: { enabled: true }',
  `pinning: { enabled: true, file: ${JSON.stringify(pinFile)}, onChange: hide }`,
  'dlp: { enabled: true, action: redact }',
  'ml:', '  enabled: true', `  model: ${JSON.stringify(model)}`,
  '  threshold: 0.9', '  scan: { toolResults: block }', '',
].join('\n'));

const child = spawn('node', [cli, '--policy', policyFile, '--name', 'sql', '--', 'node', join(here, 'sql-server.mjs')],
  { stdio: ['pipe', 'pipe', 'inherit'], cwd: tmpdir(), env: { ...process.env, NODE_NO_WARNINGS: '1' } });

const queries = [
  ['SELECT name, price FROM products', 'sıradan satırlar'],
  ['SELECT subject, body FROM tickets', 'satırda injection'],
  ['SELECT key, value FROM app_config', 'satırda secret'],
  ['DROP TABLE products', 'tehlikeli SQL'],
];
const results = [];
const steps = [
  { id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'sql-demo', version: '1' } } },
  { method: 'notifications/initialized' },
  { id: 2, method: 'tools/list' },
  ...queries.map(([sql], i) => ({ id: 10 + i, method: 'tools/call', params: { name: 'query', arguments: { sql } } })),
];
let step = 0;
const next = () => { if (step === steps.length) { child.stdin.end(); return; } const s = steps[step++]; child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...s })}\n`); if (s.id === undefined) next(); };
const timer = setTimeout(() => { console.log('TIMEOUT'); child.kill(); }, 120_000);
let buf = '';
child.stdout.on('data', (d) => {
  buf += d;
  for (let i; (i = buf.indexOf('\n')) >= 0; ) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id === 2) console.log(`tool: ${(msg.result?.tools ?? []).map((t) => t.name).join(', ')}`);
    if (msg.id >= 10 && msg.id < 20) { const [sql, kind] = queries[msg.id - 10]; const text = msg.result?.content?.[0]?.text ?? JSON.stringify(msg.error); const blocked = !!(msg.result?.isError || msg.error); const redacted = /\[REDACTED:/.test(String(text)); results[msg.id - 10] = { sql, kind, blocked, redacted, text: String(text).replace(/\s+/g, ' ').slice(0, 64) }; }
    if (msg.id !== undefined) next();
  }
});
child.on('exit', () => {
  clearTimeout(timer);
  console.log('\nSORGU                                TÜR                FIREWALL');
  for (const r of results) { const verdict = r.blocked ? 'ENGELLENDİ' : r.redacted ? 'MASKELENDİ' : 'geçti'; console.log(`${r.sql.padEnd(36)} ${r.kind.padEnd(18)} ${verdict}`); }
  console.log('');
  for (const line of readFileSync(auditFile, 'utf8').trim().split('\n')) { const e = JSON.parse(line); if (['block', 'redact'].includes(e.verdict)) console.log(`  audit: ${e.verdict} ${e.tool ?? ''}${e.score !== undefined ? ` score=${e.score.toFixed(3)}` : ''}  ${e.reason ?? ''}`.slice(0, 130)); }
});
next();
