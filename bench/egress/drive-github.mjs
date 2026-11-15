// Real GitHub MCP image (v2.0.3, pinned digest) in an egress sandbox, read-only calls (get_me, search_repositories).
// usage: node drive-github.mjs <repo> <work dir> '<allow list, YAML flow items>' <env file with GITHUB_PERSONAL_ACCESS_TOKEN=...>
// The token is read from the env file into the child environment only, never printed. Isolated HOME, unique session;
// audit.jsonl goes into the work dir. 15.11.2026: allow api.github.com -> 46 tools, both calls OK, one egress line;
// allow example.com only -> both calls fail with 'Forbidden by egress allowlist', one block line.
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
const [repo, work, allow, envFile] = process.argv.slice(2);
const env = { ...process.env, USERPROFILE: join(work, 'home'), HOME: join(work, 'home'), MCP_FIREWALL_SESSION: 'gh-egress-' + Date.now() };
for (const l of readFileSync(envFile, 'utf8').split(/\r?\n/)) { const m = l.match(/^([A-Z_]+)=(.*)$/); if (m) env[m[1]] = m[2]; }
writeFileSync(join(work, 'policy.yaml'), `version: 1
mode: enforce
audit:
  file: ./audit.jsonl
  logAllowed: true
pinning:
  enabled: false
ml:
  enabled: false
sandbox:
  enabled: true
  image: ghcr.io/github/github-mcp-server:v2.0.3@sha256:250bc6ce70788207608ef74cef4397230ff2e8481218da74d6093e4bd9101132
  env: [GITHUB_PERSONAL_ACCESS_TOKEN]
  egress:
    allow: [${allow}]
`);
const p = spawn('node', [join(repo, 'dist/src/cli.js'), '--policy', join(work, 'policy.yaml'), '--name', 'github', '--', '/server/github-mcp-server', 'stdio'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
let err = ''; p.stderr.on('data', (d) => (err += d));
const waits = new Map(); let id = 0;
createInterface({ input: p.stdout }).on('line', (l) => { try { const m = JSON.parse(l); waits.get(m.id)?.(m); } catch {} });
const rpc = (method, params) => new Promise((res) => { const i = ++id; const t = setTimeout(() => res({ timeout: true }), 60000); waits.set(i, (m) => { clearTimeout(t); res(m); }); p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: i, method, params }) + '\n'); });
const short = (m) => m.timeout ? 'TIMEOUT' : m.error ? 'ERROR ' + JSON.stringify(m.error).slice(0, 200) : (m.result?.isError ? 'TOOL-ERROR ' : 'OK ') + JSON.stringify(m.result).slice(0, 160);
console.log('initialize:', short(await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'egress-test', version: '1' } })));
p.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
const tl = await rpc('tools/list', {}); console.log('tools/list:', tl.result ? tl.result.tools.length + ' tools' : short(tl));
console.log('get_me:', short(await rpc('tools/call', { name: 'get_me', arguments: {} })));
console.log('search_repositories:', short(await rpc('tools/call', { name: 'search_repositories', arguments: { query: 'modelcontextprotocol servers', perPage: 1 } })));
p.stdin.end(); setTimeout(() => p.kill(), 5000);
p.on('exit', () => { console.log('stderr tail:', err.split('\n').filter(Boolean).slice(-4).join(' | ').replace(/(gh[pousr]_|github_pat_)\w+/g, '<TOKEN>')); try { console.log(readFileSync(join(work, 'audit.jsonl'), 'utf8').split('\n').filter((l) => l.includes('"egress"')).map((l) => { const a = JSON.parse(l); return `${a.action ?? a.verdict ?? JSON.stringify(Object.keys(a))} ${a.tool} ${a.reason ?? ''}`; }).join('\n')); } catch (e) { console.log('no audit', e.message); } });
