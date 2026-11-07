// Runs issues-server.mjs behind the firewall with the real ML model, the way a 2026-07-28 client does
// (server/discover + _meta), and prints what the client receives plus the audit verdicts. Audit and pins go
// to this folder, so no real install is touched.
//
//   node demo/toxic-agent-flow/run.mjs
//
// Needs a built dist (npm run build) and a local model. Override the model path with MCP_FIREWALL_MODEL;
// the default is ./models/mcp-pi-mmbert-mixraw-ab4-evilsandangels-30 at the repo root.
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..');
const cli = join(repo, 'dist', 'src', 'cli.js');
const model = process.env.MCP_FIREWALL_MODEL ?? join(repo, 'models', 'mcp-pi-mmbert-mixraw-ab4-evilsandangels-30');
if (!existsSync(cli)) throw new Error(`build the project first (npm run build): ${cli} is missing`);
if (!existsSync(model)) throw new Error(`model not found: ${model}. Set MCP_FIREWALL_MODEL to its path.`);

const auditFile = join(here, 'run-audit.jsonl');
const pinFile = join(here, 'run-pins.json');
for (const f of [auditFile, pinFile, pinFile.replace('.json', '.pending.json')]) if (existsSync(f)) rmSync(f);

const policyFile = join(here, 'run-policy.yaml');
writeFileSync(policyFile, [
  'version: 1',
  'mode: enforce',
  `audit: { file: ${JSON.stringify(auditFile)}, logAllowed: true }`,
  'decoding: { enabled: true }',
  `pinning: { enabled: true, file: ${JSON.stringify(pinFile)}, onChange: hide }`,
  'dlp: { enabled: true, action: redact }',
  `ml:`,
  `  enabled: true`,
  `  model: ${JSON.stringify(model)}`,
  `  threshold: 0.3`,
  `  scan: { toolResults: block }`,
  '',
].join('\n'));

const envelope = {
  'io.modelcontextprotocol/protocolVersion': '2026-07-28',
  'io.modelcontextprotocol/clientInfo': { name: 'claude-code', version: '2.1.309' },
  'io.modelcontextprotocol/clientCapabilities': { roots: { listChanged: true }, elicitation: {} },
};
const steps = [
  { id: 1, method: 'server/discover', params: { _meta: envelope } },
  { id: 2, method: 'tools/list', params: { _meta: envelope } },
  { id: 3, method: 'tools/call', params: { name: 'list_issues', arguments: { owner: 'acme', repo: 'web', number: 1 }, _meta: envelope } },
  { id: 4, method: 'tools/call', params: { name: 'list_issues', arguments: { owner: 'acme', repo: 'web', number: 2 }, _meta: envelope } },
];
const label = { 1: 'server/discover', 2: 'tools/list', 3: 'list_issues #1 (benign)', 4: 'list_issues #2 (injection)' };

const child = spawn('node', [cli, '--policy', policyFile, '--name', 'toxic-agent-flow', '--', 'node', join(here, 'issues-server.mjs')], { stdio: ['pipe', 'pipe', 'inherit'] });
const timer = setTimeout(() => { console.log('TIMEOUT'); child.kill(); }, 90_000);
let step = 0;
const next = () => {
  if (step === steps.length) { clearTimeout(timer); child.stdin.end(); return; }
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...steps[step++] })}\n`);
};
let buf = '';
child.stdout.on('data', (d) => {
  buf += d;
  for (let i; (i = buf.indexOf('\n')) >= 0; ) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id === 1) console.log(`${label[1].padEnd(26)} instructions: ${msg.result?.instructions ? 'passed' : '(removed)'}`);
    if (msg.id === 2) console.log(`${label[2].padEnd(26)} tools: ${(msg.result?.tools ?? []).map((t) => t.name).join(', ') || '(none)'}`);
    if (msg.id === 3 || msg.id === 4) {
      const text = msg.result?.content?.[0]?.text ?? JSON.stringify(msg.error);
      console.log(`${label[msg.id].padEnd(26)} ${msg.result?.isError || msg.error ? 'BLOCKED' : 'passed'}: ${String(text).replace(/\s+/g, ' ').slice(0, 80)}`);
    }
    if (msg.id !== undefined) next();
  }
});
child.on('exit', () => {
  console.log('\n--- audit ---');
  for (const line of readFileSync(auditFile, 'utf8').trim().split('\n')) {
    const e = JSON.parse(line);
    console.log(`${e.verdict.padEnd(6)} ${(e.method ?? '').padEnd(16)} ${(e.tool ?? '').padEnd(14)}${e.score !== undefined ? ` score=${e.score.toFixed(3)}` : ''}  ${e.reason ?? ''}`.slice(0, 140));
  }
});
next();
