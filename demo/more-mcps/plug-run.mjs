import { existsSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { printAudit, runFirewall, table, writePolicy } from './_lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const server = join(here, 'plug-server.mjs');
const pins = join(here, 'run-plug-pins.json');
for (const f of [pins, pins.replace('.json', '.pending.json')]) if (existsSync(f)) rmSync(f);

// No ML here — this demo is about pinning (tool rug pull) and a denied method, neither of which needs the model.
const { policy, audit } = writePolicy(here, 'plug', [
  'tools: { default: allow }',
  "methods: { deny: ['resources/*'] }",
  `pinning: { enabled: true, file: ${JSON.stringify(pins)}, onChange: hide, onNew: allow, serverCode: off }`,
  'dlp: { enabled: true, action: redact }',
  'ml: { enabled: false }',
]);

const base = [
  { id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'plug', version: '1' } } },
  { method: 'notifications/initialized' },
];
// Run 1: tools pinned on first sighting; a resources/* call is denied by policy.
const r1 = await runFirewall({ name: 'plug', server, policy, steps: [
  ...base,
  { id: 2, method: 'tools/list' },
  { id: 3, method: 'resources/list' },
  { id: 10, method: 'tools/call', params: { name: 'get_status', arguments: {} } },
] });
// Run 2: get_status is silently redefined; pinning hides the changed tool.
const r2 = await runFirewall({ name: 'plug', server, policy, env: { RUG: '1' }, steps: [
  ...base,
  { id: 2, method: 'tools/list' },
] });

const t1 = (r1.byId[2]?.result?.tools ?? []).map((t) => t.name);
const t2 = (r2.byId[2]?.result?.tools ?? []).map((t) => t.name);
console.log('=== Integrations MCP (pinning + methods) ===\n');
console.log(`1. koşu tools/list: ${t1.join(', ')}`);
console.log(`2. koşu tools/list: ${t2.join(', ')}  (get_status değişti)\n`);
table([
  ['tools/list (1. kez)', 'ilk görüşte pinlenir', t1.includes('get_status') ? 'geçti (pinlendi)' : 'eksik (!)'],
  ['resources/list', 'yasaklı metod → methods.deny', r1.byId[3]?.error ? 'ENGELLENDİ' : 'geçti (!)'],
  ['get_status çağrısı', 'pinli tool, normal', r1.byId[10]?.error ? 'ENGELLENDİ (!)' : 'geçti'],
  ['tools/list (2. kez)', 'get_status sessizce değişti → pinning', t2.includes('get_status') ? 'geçti (!)' : 'get_status GİZLENDİ'],
]);
printAudit(audit);
