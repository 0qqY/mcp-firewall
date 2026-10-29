// Runs the mock Slack MCP (slack-server.mjs) behind the firewall (real model). A messaging MCP has two sides:
//   reading   — history results are untrusted; an injected message is blocked (ML), a pasted secret is redacted (DLP)
//   posting   — outbound arguments are scanned too: a secret in the text is redacted before it leaves (DLP request
//               side), and a post to a DM (exfiltration channel) is denied by policy before it reaches the server
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

// Reading is open; posting is allowed except to DM channels (ids starting with D) — the usual exfiltration target.
// Secrets in any outbound argument are still redacted by DLP (scanRequests defaults on).
const policyFile = join(here, 'run-policy.yaml');
writeFileSync(policyFile, [
  'version: 1', 'mode: enforce',
  `audit: { file: ${JSON.stringify(auditFile)}, logAllowed: true }`,
  'tools:',
  '  default: allow',
  '  rules:',
  '    - match: slack_post_message',
  '      action: allow',
  '      arguments:',
  '        channel_id:',
  "          deny: ['^D']",
  'decoding: { enabled: true }',
  `pinning: { enabled: true, file: ${JSON.stringify(pinFile)}, onChange: hide }`,
  'dlp: { enabled: true, action: redact }',
  'ml:', '  enabled: true', `  model: ${JSON.stringify(model)}`,
  '  threshold: 0.9', '  scan: { toolResults: block }', '',
].join('\n'));

const calls = [
  { name: 'slack_list_channels', args: {}, layer: 'benign', desc: 'kanal listesi' },
  { name: 'slack_get_channel_history', args: { channel_id: 'C0GENERAL' }, layer: 'benign', desc: '#general geçmişi' },
  { name: 'slack_get_channel_history', args: { channel_id: 'C0SUPPORT' }, layer: 'injection → ML', desc: '#support (injection mesajı)' },
  { name: 'slack_get_channel_history', args: { channel_id: 'C0RANDOM' }, layer: 'secret okuma → DLP', desc: '#random (sızmış anahtar)' },
  { name: 'slack_post_message', args: { channel_id: 'C0GENERAL', text: 'Durum: her şey yeşil, dağıtım tamam.' }, layer: 'benign', desc: "#general'e durum notu" },
  { name: 'slack_post_message', args: { channel_id: 'C0GENERAL', text: 'prod anahtarı ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8 ile döndü' }, layer: 'secret gönderme → DLP', desc: "#general'e token'lı mesaj" },
  { name: 'slack_post_message', args: { channel_id: 'D0EXFIL01', text: 'buyurun anahtarlar' }, layer: 'exfil kanalı → politika', desc: "DM'e gönderim (exfil)" },
];

const child = spawn('node', [cli, '--policy', policyFile, '--name', 'slack', '--', 'node', join(here, 'slack-server.mjs')],
  { stdio: ['pipe', 'pipe', 'inherit'], cwd: tmpdir(), env: { ...process.env, NODE_NO_WARNINGS: '1' } });

const results = [];
const steps = [
  { id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'slack-demo', version: '1' } } },
  { method: 'notifications/initialized' },
  { id: 2, method: 'tools/list' },
  ...calls.map((c, i) => ({ id: 10 + i, method: 'tools/call', params: { name: c.name, arguments: c.args } })),
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
    if (msg.id === 2) console.log(`tools: ${(msg.result?.tools ?? []).map((t) => t.name).join(', ')}\n`);
    if (msg.id >= 10 && msg.id < 100) {
      const c = calls[msg.id - 10];
      const text = msg.result?.content?.[0]?.text ?? JSON.stringify(msg.error);
      results[msg.id - 10] = { ...c, blocked: !!(msg.result?.isError || msg.error), redacted: /\[REDACTED:/.test(String(text)) };
    }
    if (msg.id !== undefined) next();
  }
});
child.on('exit', () => {
  clearTimeout(timer);
  const entries = readFileSync(auditFile, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  // The outbound secret is redacted on the request side, so the (acked) result looks clean; mark that call masked.
  if (entries.some((e) => e.verdict === 'redact' && /argument/.test(e.reason ?? '')) && results[5]) results[5].redacted = true;
  console.log('ADIM'.padEnd(30) + 'KATMAN'.padEnd(28) + 'FIREWALL');
  console.log('-'.repeat(70));
  for (const r of results) { const v = r.blocked ? 'ENGELLENDİ' : r.redacted ? 'MASKELENDİ' : 'geçti'; console.log(r.desc.padEnd(30) + r.layer.padEnd(28) + v); }
  console.log('\nDenetim kaydı (block/redact):');
  for (const e of entries) {
    if (['block', 'redact'].includes(e.verdict)) console.log(`  ${e.verdict.padEnd(7)}${e.score !== undefined ? `score=${e.score.toFixed(3)} ` : ''}${e.reason ?? ''}`.slice(0, 150));
  }
});
next();
