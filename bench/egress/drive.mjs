// Drives the firewall CLI with the probe server in an egress sandbox; isolated HOME, unique session.
// usage: node drive.mjs <repo> <work dir>   (work dir must hold srv/server.mjs: copy bench/egress/server.mjs there)
// KILL_PROXY=1: kill the proxy after the first probe (fail-closed check); HARD_KILL=1: taskkill the firewall (Windows) and list leftovers.
// Needs Docker with node:22-alpine; opens a listener on port 4799; writes audit.jsonl into the work dir, never into ~/.mcp-firewall.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

const [repo, work] = process.argv.slice(2);
const home = join(work, 'home');
mkdirSync(home, { recursive: true });
const srv = join(work, 'srv').replace(/\\/g, '/');
writeFileSync(join(work, 'policy.yaml'), `version: 1
mode: enforce
audit:
  file: ./audit.jsonl
  logAllowed: true
pinning:
  enabled: false
sandbox:
  enabled: true
  image: node:22-alpine
  mounts:
    - { source: ${srv}, target: /srv }
  egress:
    allow: [example.com, "*.github.com", localtest.me, "*.nip.io"]
`);

const listener = createServer((q, s) => s.end('host')).on('error', () => {}).listen(4799, '0.0.0.0');
const probes = [
  ['env', ''],
  ['fetch', 'https://example.com/'],
  ['fetch', 'https://www.wikipedia.org/'],
  ['connect', 'example.com:443'],
  ['connect', 'example.org:443'],
  ['connect', 'example.com:22'],
  ['connect', '1.1.1.1:443'],
  ['connect', 'api.github.com:443'],
  ['connect', 'github.com:443'],
  ['connect', 'localtest.me:443'],
  ['connect', '10.0.0.1.nip.io:443'],
  ['connect', 'host.docker.internal:4799'],
  ['direct', '1.1.1.1:443'],
  ['direct', 'host.docker.internal:4799'],
  ['dns', 'example.org'],
];

const env = { ...process.env, USERPROFILE: home, HOME: home, MCP_FIREWALL_SESSION: `egress-e2e-${Date.now()}` };
const fw = spawn(process.execPath, [join(repo, 'dist/src/cli.js'), '--policy', join(work, 'policy.yaml'), '--name', 'egress-e2e', '--', 'node', '/srv/server.mjs'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
let stderr = '';
fw.stderr.on('data', (d) => { stderr += d; });
const pending = new Map();
createInterface({ input: fw.stdout }).on('line', (l) => {
  const m = JSON.parse(l);
  pending.get(m.id)?.(m);
});
const call = (id, method, params) => new Promise((res) => { pending.set(id, res); fw.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n'); });

const t0 = Date.now();
await call(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'drive', version: '1' } });
console.log(`initialized after ${Date.now() - t0} ms`);
fw.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
let id = 10;
for (const [kind, target] of probes) {
  const r = await call(id++, 'tools/call', { name: 'probe', arguments: { kind, target } });
  const text = r.result?.content?.[0]?.text ?? JSON.stringify(r.error ?? r.result);
  console.log(`${kind.padEnd(8)} ${target.padEnd(28)} -> ${text.slice(0, 140)}`);
  if (process.env.KILL_PROXY && kind === 'env') {
    const name = text.split('//')[1].split(':')[0];
    const { execSync } = await import('node:child_process');
    execSync(`docker kill ${name}`);
    await new Promise((r) => setTimeout(r, 1500));
    console.log('killed proxy', name);
  }
  if (process.env.HARD_KILL && kind === 'fetch') {
    const { execSync } = await import('node:child_process');
    execSync(`taskkill /F /PID ${fw.pid}`);
    console.log('hard-killed firewall');
    await new Promise((r) => setTimeout(r, 4000));
    console.log(execSync('docker ps --filter label=mcp-firewall=1 --format "{{.Names}}"').toString() || '(no containers)');
    console.log(execSync('docker network ls --filter label=mcp-firewall=1 --format "{{.Name}}"').toString() || '(no networks)');
    process.exit(0);
  }
}
fw.stdin.end();
await new Promise((r) => fw.on('exit', r));
listener.close();
console.log('--- firewall stderr (egress lines)');
console.log(stderr.split('\n').filter((l) => /egress|sandbox|ERROR|error/i.test(l)).join('\n'));
const audit = join(work, 'audit.jsonl');
if (existsSync(audit)) {
  console.log('--- audit egress records');
  for (const l of readFileSync(audit, 'utf8').trim().split('\n')) { const r = JSON.parse(l); if (r.method === 'egress') console.log(r.verdict, r.tool, '|', r.reason); }
}
