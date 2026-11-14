// Test MCP server for the egress sandbox: one tool, `probe`, that tries a way out and reports what happened.
import { createInterface } from 'node:readline';
import net from 'node:net';
import dns from 'node:dns/promises';

const send = (m) => process.stdout.write(JSON.stringify(m) + '\n');
const withTimeout = (p, ms = 8000) => Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error('timeout')), ms))]);

function tcp(host, port) {
  return withTimeout(new Promise((res, rej) => {
    const s = net.connect({ host, port }, () => { s.destroy(); res('connected'); });
    s.on('error', rej);
  }));
}

async function probe(kind, target) {
  try {
    if (kind === 'fetch') {
      const r = await withTimeout(fetch(target), 15000);
      return `HTTP ${r.status}`;
    }
    if (kind === 'connect') { // CONNECT through the proxy by hand, whatever fetch does
      const proxy = new URL(process.env.HTTPS_PROXY);
      return await withTimeout(new Promise((res, rej) => {
        const s = net.connect({ host: proxy.hostname, port: Number(proxy.port) }, () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
        s.once('data', (d) => { s.destroy(); res(d.toString().split('\r\n')[0]); });
        s.on('error', rej);
      }));
    }
    if (kind === 'direct') { const [h, p] = target.split(':'); return await tcp(h, Number(p)); }
    if (kind === 'dns') return JSON.stringify(await withTimeout(dns.lookup(target, { all: true })));
    if (kind === 'env') return `${process.env.HTTPS_PROXY} ${process.env.NODE_USE_ENV_PROXY}`;
    return 'unknown kind';
  } catch (e) {
    return `ERROR ${e.cause?.code ?? e.code ?? ''} ${e.message}`.trim();
  }
}

createInterface({ input: process.stdin }).on('line', async (line) => {
  const m = JSON.parse(line);
  if (m.method === 'initialize') send({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'probe', version: '1' } } });
  else if (m.method === 'tools/list') send({ jsonrpc: '2.0', id: m.id, result: { tools: [{ name: 'probe', description: 'Network probe', inputSchema: { type: 'object', properties: { kind: { type: 'string' }, target: { type: 'string' } } } }] } });
  else if (m.method === 'tools/call') {
    const text = await probe(m.params.arguments.kind, m.params.arguments.target);
    send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text }] } });
  } else if (m.id !== undefined) send({ jsonrpc: '2.0', id: m.id, result: {} });
});
