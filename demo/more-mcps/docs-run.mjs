import { existsSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MODEL, printAudit, runFirewall, table, writePolicy } from './_lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const server = join(here, 'docs-server.mjs');
const pins = join(here, 'run-docs-pins.json');
for (const f of [pins, pins.replace('.json', '.pending.json')]) if (existsSync(f)) rmSync(f);

const { policy, audit } = writePolicy(here, 'docs', [
  'descriptionScan: { enabled: true, action: hide, hiddenUnicode: true }',
  'decoding: { enabled: true }',
  `pinning: { enabled: true, file: ${JSON.stringify(pins)}, onChange: hide, prompts: block, serverCode: off }`,
  'dlp: { enabled: true, action: redact }',
  'ml:', '  enabled: true', `  model: ${JSON.stringify(MODEL)}`,
  '  threshold: 0.9', '  scan: { promptResults: warn }',
]);

const base = [
  { id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'docs', version: '1' } } },
  { method: 'notifications/initialized' },
];
// Run 1: first sighting pins "summarize" (clean); "triage" is poisoned and blocked on sight.
const r1 = await runFirewall({ name: 'docs', server, policy, steps: [
  ...base,
  { id: 2, method: 'prompts/list' },
  { id: 10, method: 'prompts/get', params: { name: 'summarize' } },
  { id: 11, method: 'prompts/get', params: { name: 'triage' } },
] });
// Run 2: the server has quietly changed "summarize"; prompt pinning catches the rug pull.
const r2 = await runFirewall({ name: 'docs', server, policy, env: { RUG: '1' }, steps: [
  ...base,
  { id: 10, method: 'prompts/get', params: { name: 'summarize' } },
] });

const v = (m, ok) => (m?.error ? 'ENGELLENDİ' : ok);
console.log('=== Docs/Prompts MCP ===\n');
table([
  ['prompts/get summarize (1. kez)', 'temiz şablon → pinlenir', v(r1.byId[10], 'geçti (pinlendi)')],
  ['prompts/get triage', 'şablonda injection → descriptionScan', v(r1.byId[11], 'geçti (!)')],
  ['prompts/get summarize (2. kez)', 'şablon sessizce değişti → pinning', v(r2.byId[10], 'geçti (!)')],
]);
printAudit(audit);
