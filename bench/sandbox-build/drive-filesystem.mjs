// The image `mcp-firewall sandbox build @modelcontextprotocol/server-filesystem@<version>` made, run through the firewall
// with the strict sandbox defaults (network none, read-only root, nobody) and one read-only mount.
// usage: node drive-filesystem.mjs <repo> <work dir> <image>
// Isolated HOME and session; audit.jsonl and pins go into the work dir. Calls: initialize, tools/list, list_directory and
// read_text_file inside the mount, write_file into the read-only mount (must fail), read of a path outside the mount (must fail).
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
const [repo, work, image] = process.argv.slice(2);
const share = join(work, 'share');
mkdirSync(share, { recursive: true });
mkdirSync(join(work, 'home'), { recursive: true });
writeFileSync(join(share, 'merhaba.txt'), 'sandbox build denemesi\n');
const env = { ...process.env, USERPROFILE: join(work, 'home'), HOME: join(work, 'home'), MCP_FIREWALL_SESSION: 'sbuild-' + Date.now() };
writeFileSync(join(work, 'policy.yaml'), `version: 1
mode: enforce
audit:
  file: ./audit.jsonl
  logAllowed: true
pinning:
  enabled: true
  file: ./pins.json
ml:
  enabled: false
sandbox:
  enabled: true
  image: ${image}
  mounts:
    - { source: ${share.replace(/\\/g, '/')}, target: /workspace, mode: ro }
`);
const p = spawn('node', [join(repo, 'dist/src/cli.js'), '--policy', join(work, 'policy.yaml'), '--name', 'fs-sbuild', '--', 'mcp-server-filesystem', '/workspace'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
let err = ''; p.stderr.on('data', (d) => (err += d));
const waits = new Map(); let id = 0;
createInterface({ input: p.stdout }).on('line', (l) => { try { const m = JSON.parse(l); waits.get(m.id)?.(m); } catch {} });
const rpc = (method, params) => new Promise((res) => { const i = ++id; const t = setTimeout(() => res({ timeout: true }), 60000); waits.set(i, (m) => { clearTimeout(t); res(m); }); p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: i, method, params }) + '\n'); });
const short = (m) => m.timeout ? 'TIMEOUT' : m.error ? 'ERROR ' + JSON.stringify(m.error).slice(0, 200) : (m.result?.isError ? 'TOOL-ERROR ' : 'OK ') + JSON.stringify(m.result?.content ?? m.result).slice(0, 200);
console.log('initialize:', short(await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'sbuild-test', version: '1' } })));
p.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
const tl = await rpc('tools/list', {}); console.log('tools/list:', tl.result ? tl.result.tools.length + ' tools' : short(tl));
const call = (name, args) => rpc('tools/call', { name, arguments: args });
console.log('list_directory /workspace:', short(await call('list_directory', { path: '/workspace' })));
console.log('read_text_file merhaba.txt:', short(await call('read_text_file', { path: '/workspace/merhaba.txt' })));
console.log('write_file (ro mount):', short(await call('write_file', { path: '/workspace/yeni.txt', content: 'x' })));
console.log('read_text_file /etc/passwd (outside):', short(await call('read_text_file', { path: '/etc/passwd' })));
p.stdin.end(); setTimeout(() => p.kill(), 5000);
p.on('exit', (code) => console.log('firewall exit', code, '| stderr tail:', err.split('\n').filter(Boolean).slice(-3).join(' | ')));
