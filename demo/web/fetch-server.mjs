// Minimal web-fetch MCP server: one tool, fetch_url, that performs a real HTTP GET and returns the page text.
// Stands in for a web/browser MCP; the firewall's handling of fetched content is the same whichever is used.
const send = (msg) => process.stdout.write(`${JSON.stringify(msg)}\n`);
const reply = (id, result) => send({ jsonrpc: '2.0', id, result });

const TOOLS = [
  { name: 'fetch_url', description: 'Fetch a web page and return its text', inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] } },
];

let buf = '';
process.stdin.on('data', (d) => {
  buf += d;
  for (let i; (i = buf.indexOf('\n')) >= 0; ) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id === undefined) continue;
    (async () => {
      switch (msg.method) {
        case 'initialize':
          return reply(msg.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'fetch-mock', version: '0.0.1' } });
        case 'tools/list':
          return reply(msg.id, { tools: TOOLS });
        case 'tools/call':
          try {
            const res = await fetch(msg.params.arguments.url);
            return reply(msg.id, { content: [{ type: 'text', text: await res.text() }] });
          } catch (err) {
            return reply(msg.id, { content: [{ type: 'text', text: `fetch error: ${err.message}` }], isError: true });
          }
        default:
          return send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Method not found' } });
      }
    })();
  }
});
