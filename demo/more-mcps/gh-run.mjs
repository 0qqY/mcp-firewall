import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MODEL, printAudit, runFirewall, table, verdict, writePolicy } from './_lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const { policy, audit } = writePolicy(here, 'gh', [
  'tools:',
  '  default: allow',
  '  rules:',
  '    - match: merge_pull_request',
  '      action: deny',
  '      reason: writes need human review',
  '    - match: delete_repo',
  '      action: deny',
  'descriptionScan: { enabled: true, action: hide, hiddenUnicode: true }',
  'decoding: { enabled: true }',
  'pinning: { enabled: false }',
  'dlp: { enabled: true, action: redact }',
  'ml:', '  enabled: true', `  model: ${JSON.stringify(MODEL)}`,
  '  threshold: 0.3', '  scan: { toolResults: block, toolDefinitions: hide }',
]);

const steps = [
  { id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'gh', version: '1' } } },
  { method: 'notifications/initialized' },
  { id: 2, method: 'tools/list' },
  { id: 10, method: 'tools/call', params: { name: 'get_issue', arguments: { number: 1 } } },
  { id: 11, method: 'tools/call', params: { name: 'get_issue', arguments: { number: 2 } } },
  { id: 12, method: 'tools/call', params: { name: 'get_file_contents', arguments: { path: 'config/settings.py' } } },
  { id: 13, method: 'tools/call', params: { name: 'merge_pull_request', arguments: { number: 7 } } },
  { id: 14, method: 'tools/call', params: { name: 'delete_repo', arguments: { name: 'prod' } } },
];

const { byId } = await runFirewall({ name: 'github', server: join(here, 'gh-server.mjs'), policy, steps });
const tools = (byId[2]?.result?.tools ?? []).map((t) => t.name);
console.log('=== GitHub MCP ===');
console.log(`tools/list döndü: ${tools.join(', ')}`);
console.log(`search_code (zehirli açıklama): ${tools.includes('search_code') ? 'GEÇTİ (!)' : 'GİZLENDİ'}\n`);
table([
  ['get_issue #1', 'sıradan issue', verdict(byId[10])],
  ['get_issue #2', 'issue gövdesinde injection → ML', verdict(byId[11])],
  ['get_file_contents', 'kodda AWS+GitHub secret → DLP', verdict(byId[12])],
  ['merge_pull_request', 'yazma işlemi → politika', verdict(byId[13])],
  ['delete_repo', 'yıkıcı işlem → politika', verdict(byId[14])],
]);
printAudit(audit);
