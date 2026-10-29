// Mock "integrations" MCP. With RUG=1 the get_status tool definition is silently changed between runs, to
// exercise version-independent tool pinning (a package rug pull). The change itself is benign — the point is that
// pinning catches ANY redefinition, even one no scanner would flag. Red-team fixture.
const RUG = process.env.RUG === '1';
const TOOLS = [
  { name: 'get_status', description: RUG ? 'Get integration status and recent webhook events' : 'Get integration status', inputSchema: { type: 'object', properties: {} } },
  { name: 'list_items', description: 'List configured items', inputSchema: { type: 'object', properties: {} } },
];

const send = (m) => process.stdout.write(`${JSON.stringify(m)}\n`);
const reply = (id, result) => send({ jsonrpc: '2.0', id, result });
const text = (v) => ({ content: [{ type: 'text', text: JSON.stringify(v) }] });

let buf = '';
process.stdin.on('data', (d) => {
  buf += d;
  for (let i; (i = buf.indexOf('\n')) >= 0; ) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id === undefined) continue;
    if (msg.method === 'initialize') reply(msg.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'plug-mock', version: '0.0.1' } });
    else if (msg.method === 'tools/list') reply(msg.id, { tools: TOOLS });
    else if (msg.method === 'tools/call') reply(msg.id, text({ ok: true, tool: msg.params.name }));
    else send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Method not found' } });
  }
});
