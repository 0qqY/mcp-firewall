// Comprehensive SQL MCP test: runs sql-server.mjs (in-memory SQLite) behind the firewall (real model) and sends
// a dozen queries, each aimed at a different layer:
//   benign            — ordinary rows pass through untouched
//   injection (ML)    — a row whose text carries an indirect injection, in the clear and base64-encoded
//   secret/PII (DLP)  — rows holding tokens, keys, a stored .env and card/TCKN/IBAN; redacted in the result
//   dangerous SQL     — DROP/DELETE/UPDATE/stacked/ATTACH denied on the request side, never reaching the DB
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
const model = process.env.MCP_FIREWALL_MODEL ?? join(repo, 'models', 'mcp-pi-mmbert-mixraw-ab4-evilsandangels-30');
if (!existsSync(cli)) throw new Error(`build first (npm run build): ${cli} is missing`);
if (!existsSync(model)) throw new Error(`model not found: ${model}. Set MCP_FIREWALL_MODEL to its path.`);

const auditFile = join(here, 'run-audit.jsonl');
const pinFile = join(here, 'run-pins.json');
for (const f of [auditFile, pinFile, pinFile.replace('.json', '.pending.json')]) if (existsSync(f)) rmSync(f);

// Read-only database access: the query tool is allowed, but statements that mutate schema or data are denied
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
  "          deny: ['\\b(insert|update|delete|drop|alter|truncate|create|replace|attach|detach|pragma|vacuum|reindex)\\b']",
  'decoding: { enabled: true }',
  `pinning: { enabled: true, file: ${JSON.stringify(pinFile)}, onChange: hide }`,
  'dlp: { enabled: true, action: redact }',
  'ml:', '  enabled: true', `  model: ${JSON.stringify(model)}`,
  '  threshold: 0.3', '  scan: { toolResults: block }', '',
].join('\n'));

// [sql, layer label, short description]
const queries = [
  ['SELECT name, price FROM products', 'benign', 'sıradan satırlar'],
  ['SELECT subject, body FROM tickets WHERE id = 2', 'injection → ML', 'satırda açık injection'],
  ['SELECT body FROM tickets WHERE id = 3', 'injection → ML', 'satırda base64 injection'],
  ['SELECT key, value FROM app_config', 'secret → DLP', 'token/anahtar (4 tür)'],
  ['SELECT name, card, tckn, iban FROM customers', 'PII → DLP', 'kart / TCKN / IBAN'],
  ['SELECT content FROM deploy_config', 'secret → DLP', 'saklı .env (bağlamsal)'],
  ['DROP TABLE products', 'tehlikeli → politika', 'DROP'],
  ['DELETE FROM customers', 'tehlikeli → politika', 'DELETE'],
  ["UPDATE app_config SET value = 'x'", 'tehlikeli → politika', 'UPDATE'],
  ['SELECT 1; DROP TABLE products', 'tehlikeli → politika', 'stacked DROP'],
  ["ATTACH DATABASE 'ebf.db' AS e", 'tehlikeli → politika', 'ATTACH'],
  ["SELECT * FROM products WHERE name LIKE '%get%'", 'benign', 'filtreli SELECT (kontrol)'],
];

const child = spawn('node', [cli, '--policy', policyFile, '--name', 'sql', '--', 'node', join(here, 'sql-server.mjs')],
  { stdio: ['pipe', 'pipe', 'inherit'], cwd: tmpdir(), env: { ...process.env, NODE_NO_WARNINGS: '1' } });

const results = [];
const steps = [
  { id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'sql-demo', version: '1' } } },
  { method: 'notifications/initialized' },
  { id: 2, method: 'tools/list' },
  ...queries.map(([sql], i) => ({ id: 10 + i, method: 'tools/call', params: { name: 'query', arguments: { sql } } })),
];
let step = 0;
const next = () => { if (step === steps.length) { child.stdin.end(); return; } const s = steps[step++]; child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...s })}\n`); if (s.id === undefined) next(); };
const timer = setTimeout(() => { console.log('TIMEOUT'); child.kill(); }, 180_000);
let buf = '';
child.stdout.on('data', (d) => {
  buf += d;
  for (let i; (i = buf.indexOf('\n')) >= 0; ) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id === 2) console.log(`tool: ${(msg.result?.tools ?? []).map((t) => t.name).join(', ')}\n`);
    if (msg.id >= 10 && msg.id < 100) {
      const [sql, layer, desc] = queries[msg.id - 10];
      const text = msg.result?.content?.[0]?.text ?? JSON.stringify(msg.error);
      const blocked = !!(msg.result?.isError || msg.error);
      const redacted = /\[REDACTED:/.test(String(text));
      results[msg.id - 10] = { sql, layer, desc, blocked, redacted };
    }
    if (msg.id !== undefined) next();
  }
});
child.on('exit', () => {
  clearTimeout(timer);
  console.log('AÇIKLAMA'.padEnd(26) + 'KATMAN'.padEnd(22) + 'FIREWALL');
  console.log('-'.repeat(60));
  for (const r of results) { const verdict = r.blocked ? 'ENGELLENDİ' : r.redacted ? 'MASKELENDİ' : 'geçti'; console.log(r.desc.padEnd(26) + r.layer.padEnd(22) + verdict); }
  console.log('\nDenetim kaydı (block/redact):');
  for (const line of readFileSync(auditFile, 'utf8').trim().split('\n')) {
    const e = JSON.parse(line);
    if (['block', 'redact'].includes(e.verdict)) console.log(`  ${e.verdict.padEnd(7)}${e.score !== undefined ? `score=${e.score.toFixed(3)} ` : ''}${e.reason ?? ''}`.slice(0, 150));
  }
  const pass = results.filter((r) => !r.blocked && !r.redacted).length;
  const block = results.filter((r) => r.blocked).length;
  const mask = results.filter((r) => r.redacted).length;
  console.log(`\nToplam ${results.length} sorgu — geçti ${pass}, maskelendi ${mask}, engellendi ${block}`);
});
next();
