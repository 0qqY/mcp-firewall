// Poligon: sahte e-posta MCP'si. Gerçek hesap ve gerçek gönderim yok.
//  - Gelen kutusu POLIGON_POSTA dosyasından (varsayılan: posta-kutusu.json) okunur, her çağrıda yeniden.
//  - send_email hiçbir yere göndermez; POLIGON_CALISMA/giden-kutusu.jsonl dosyasına yazar. Sızıntıyı sürücü
//    (dene.mjs) oradan okur.
// stdio üzerinden JSON-RPC konuşur; sürücü bunu firewall'un arkasında ya da doğrudan çalıştırır.
import { appendFileSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const POSTA = process.env.POLIGON_POSTA ?? join(here, 'posta-kutusu.json');
const CALISMA = process.env.POLIGON_CALISMA ?? join(here, '.calisma');
const INFO = { name: 'poligon-posta', version: '0.0.1' };

const send = (m) => process.stdout.write(`${JSON.stringify(m)}\n`);
const reply = (id, result) => send({ jsonrpc: '2.0', id, result });
const fail = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });
const text = (v, isError = false) => ({
  content: [{ type: 'text', text: typeof v === 'string' ? v : JSON.stringify(v) }],
  ...(isError ? { isError: true } : {}),
});
const emails = () => JSON.parse(readFileSync(POSTA, 'utf8')).emails;

const TOOLS = [
  { name: 'list_emails', description: 'List the emails in the inbox (id, sender, subject)', inputSchema: { type: 'object', properties: {} } },
  { name: 'read_email', description: 'Read an email by id', inputSchema: { type: 'object', properties: { id: { type: 'number' } }, required: ['id'] } },
  { name: 'send_email', description: 'Send an email', inputSchema: { type: 'object', properties: { to: { type: 'string' }, subject: { type: 'string' }, body: { type: 'string' } }, required: ['to', 'body'] } },
];

function call(name, a) {
  if (name === 'list_emails') return text(emails().map(({ id, from, subject }) => ({ id, from, subject })));
  if (name === 'read_email') return text(emails().find((e) => e.id === a.id) ?? { error: 'email not found' });
  if (name === 'send_email') {
    mkdirSync(CALISMA, { recursive: true });
    appendFileSync(join(CALISMA, 'giden-kutusu.jsonl'), `${JSON.stringify({ ts: new Date().toISOString(), to: a.to, subject: a.subject, body: a.body })}\n`);
    return text({ ok: true, id: 'msg_1001', to: a.to }); // gerçek API'ler gibi yalnızca onay döner, gövdeyi yansıtmaz
  }
  return text(`unknown tool: ${name}`, true);
}

let buf = '';
process.stdin.on('data', (d) => {
  buf += d;
  for (let i; (i = buf.indexOf('\n')) >= 0; ) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id === undefined) continue; // bildirimler cevap istemez
    try {
      if (msg.method === 'initialize') reply(msg.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: INFO });
      else if (msg.method === 'server/discover') reply(msg.id, { supportedVersions: ['2026-07-28'], capabilities: { tools: {} }, serverInfo: INFO });
      else if (msg.method === 'ping') reply(msg.id, {});
      else if (msg.method === 'tools/list') reply(msg.id, { tools: TOOLS });
      else if (msg.method === 'tools/call') reply(msg.id, call(msg.params?.name, msg.params?.arguments ?? {}));
      else fail(msg.id, -32601, 'Method not found');
    } catch (err) {
      reply(msg.id, text(`poligon sunucusu hata verdi: ${err.message}`, true));
    }
  }
});
