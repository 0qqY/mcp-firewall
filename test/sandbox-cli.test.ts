import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { send } from '../src/jsonrpc.js';
import { messageReader } from './helpers.js';

/**
 * The CLI against a fake `docker` on PATH: it answers `image inspect`, `kill` and `run`, and for `run` starts the
 * mock MCP server locally in place of the container. That exercises the real command line, the stdio hand-over,
 * the image pin and the container stop without needing Docker.
 */

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const MOCK = fileURLToPath(new URL('./mock-server.js', import.meta.url));
const IMAGE = 'fake/image:1';
const ID_A = `sha256:${'a'.repeat(64)}`;
const ID_B = `sha256:${'b'.repeat(64)}`;

const FAKE_DOCKER = `
import { appendFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
const [cmd, ...args] = process.argv.slice(2);
const log = (o) => appendFileSync(process.env.FAKE_DOCKER_LOG, JSON.stringify(o) + '\\n');
if (process.env.FAKE_DOCKER_DOWN === '1') {
  log({ cmd, down: true });
  process.stderr.write('error during connect: open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.\\n');
  process.exit(1);
}
if (cmd === 'image' && args[0] === 'inspect') {
  const image = args[args.length - 1];
  log({ cmd: 'inspect', image });
  if (image === process.env.FAKE_DOCKER_IMAGE) { process.stdout.write(process.env.FAKE_DOCKER_ID + '\\n'); process.exit(0); }
  process.stderr.write('Error response from daemon: No such image: ' + image + '\\n');
  process.exit(1);
}
if (cmd === 'kill') { log({ cmd: 'kill', name: args[0] }); process.exit(0); }
if (cmd === 'run') {
  const WITH_VALUE = new Set(['--name', '--label', '--pull', '--network', '--cap-drop', '--security-opt', '--pids-limit', '--memory', '--memory-swap', '--cpus', '--user', '--tmpfs', '-e', '--mount', '-w', '--entrypoint']);
  const opts = [];
  let entrypoint;
  let i = 0;
  for (; i < args.length; i++) {
    const a = args[i];
    if (WITH_VALUE.has(a)) { if (a === '--entrypoint') entrypoint = args[i + 1]; opts.push([a, args[i + 1]]); i++; }
    else if (a.startsWith('-')) opts.push([a]);
    else break;
  }
  log({ cmd: 'run', opts, image: args[i], entrypoint, rest: args.slice(i + 1) });
  const child = spawn(entrypoint, args.slice(i + 1), { stdio: 'inherit' });
  child.on('exit', (code) => process.exit(code ?? 1));
  child.on('error', (e) => { process.stderr.write(String(e) + '\\n'); process.exit(127); });
} else {
  process.exit(2);
}
`;

const top = mkdtempSync(join(tmpdir(), 'mcpfw-sbcli-'));
const bin = join(top, 'bin');
mkdirSync(bin);
const fakeScript = join(bin, 'fake-docker.mjs');
writeFileSync(fakeScript, FAKE_DOCKER);
if (process.platform === 'win32') {
  writeFileSync(join(bin, 'docker.cmd'), `@echo off\r\n"${process.execPath}" "${fakeScript}" %*\r\n`);
} else {
  writeFileSync(join(bin, 'docker'), `#!/bin/sh\nexec "${process.execPath}" "${fakeScript}" "$@"\n`);
  chmodSync(join(bin, 'docker'), 0o755);
}
const pathKey = Object.keys(process.env).find((k) => k.toLowerCase() === 'path') ?? 'PATH';

interface Setup {
  dir: string;
  policy: string;
  log: string;
  env: NodeJS.ProcessEnv;
}

function setup(name: string, fake: { id?: string; image?: string; down?: boolean } = {}, policyLines: string[] = ['sandbox:', '  enabled: true', `  image: ${IMAGE}`]): Setup {
  const dir = mkdtempSync(join(top, `${name}-`));
  const policy = join(dir, 'policy.yaml');
  writeFileSync(policy, ['mode: enforce', ...policyLines].join('\n'));
  const log = join(dir, 'docker.log');
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    [pathKey]: `${bin}${delimiter}${process.env[pathKey] ?? ''}`,
    FAKE_DOCKER_LOG: log,
    FAKE_DOCKER_IMAGE: fake.image ?? IMAGE,
    FAKE_DOCKER_ID: fake.id ?? ID_A,
    FAKE_DOCKER_DOWN: fake.down ? '1' : '0',
  };
  return { dir, policy, log, env };
}

const dockerLog = (s: Setup): any[] => (existsSync(s.log) ? readFileSync(s.log, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const auditOf = (s: Setup): any[] => readFileSync(join(s.dir, 'mcp-firewall-audit.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const init = { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } };

/** Starts the CLI, performs the handshake and returns the first reply. */
async function session(s: Setup, flags: string[] = []) {
  const child = spawn(process.execPath, [CLI, '--policy', s.policy, '--name', 'mock', ...flags, '--', 'node', MOCK], { env: s.env, stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (d) => (stderr += d));
  const out = messageReader(child.stdout);
  send(child.stdin, { jsonrpc: '2.0', id: 1, method: 'initialize', params: init });
  const reply = await out.next(20_000);
  const exit = new Promise<number | null>((resolve) => child.on('exit', resolve));
  return { child, out, reply, exit, stderr: () => stderr };
}

test('a sandboxed server runs through docker with the hardened command line and is stopped afterwards', async () => {
  const s = setup('happy');
  const { child, out, reply, exit } = await session(s);
  assert.equal(reply.result.serverInfo.name, 'mock-server');
  send(child.stdin, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { text: 'hello' } } });
  assert.equal((await out.next(20_000)).result.content[0].text, 'hello');
  child.stdin.end();
  assert.equal(await exit, 0);

  const calls = dockerLog(s);
  const run = calls.find((c) => c.cmd === 'run');
  assert.ok(run, 'docker run was called');
  const has = (...opt: string[]) => run.opts.some((o: string[]) => o.length === opt.length && o.every((v, i) => v === opt[i]));
  for (const opt of [['--network', 'none'], ['--cap-drop', 'ALL'], ['--security-opt', 'no-new-privileges:true'], ['--read-only'], ['--rm'], ['-i'], ['--pids-limit', '256'], ['--user', '65534:65534'], ['--pull', 'never'], ['--entrypoint', 'node']]) {
    assert.ok(has(...opt), `option ${opt.join(' ')}`);
  }
  assert.equal(run.image, IMAGE);
  assert.deepEqual(run.rest, [MOCK]);
  const name = run.opts.find((o: string[]) => o[0] === '--name')[1];
  assert.deepEqual(calls.filter((c) => c.cmd === 'kill').map((c) => c.name), [name], 'the container is stopped by name on exit');

  const audit = auditOf(s);
  assert.ok(audit.some((e) => e.verdict === 'info' && /sandbox on: container mcp-fw-/.test(e.reason) && /network none/.test(e.reason)));
  assert.ok(audit.some((e) => e.verdict === 'info' && /server code pinned: image fake\/image:1 \(aaaaaaaaaaaa\)/.test(e.reason)));
});

test('--sandbox turns the sandbox on without any policy setting', async () => {
  const s = setup('flag', {}, []);
  const { child, reply, exit } = await session(s, ['--sandbox', IMAGE]);
  assert.equal(reply.result.serverInfo.name, 'mock-server');
  child.stdin.end();
  assert.equal(await exit, 0);
  assert.equal(dockerLog(s).find((c) => c.cmd === 'run').image, IMAGE);
});

test('a rebuilt image is refused as changed server code until it is approved', async () => {
  const s = setup('rebuilt');
  const first = await session(s);
  assert.equal(first.reply.result.serverInfo.name, 'mock-server');
  first.child.stdin.end();
  assert.equal(await first.exit, 0);

  const second = await session({ ...s, env: { ...s.env, FAKE_DOCKER_ID: ID_B } });
  assert.match(second.reply.error.message, /server code changed since it was pinned \(image fake\/image:1/);
  second.child.stdin.end();
  await second.exit;
});

test('without a reachable Docker the firewall does not start and says what to do', async () => {
  const s = setup('down', { down: true });
  const r = spawnSync(process.execPath, [CLI, '--policy', s.policy, '--', 'node', MOCK], { env: s.env, encoding: 'utf8', timeout: 30_000 });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Docker is installed but not reachable; start Docker Desktop/);
  assert.equal(dockerLog(s).some((c) => c.cmd === 'run'), false, 'no container was started');
});

test('an image that is not local is not pulled behind the user\'s back', () => {
  const s = setup('missing', { image: 'some/other:2' });
  const r = spawnSync(process.execPath, [CLI, '--policy', s.policy, '--', 'node', MOCK], { env: s.env, encoding: 'utf8', timeout: 30_000 });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /image fake\/image:1 is not present locally.*docker pull fake\/image:1/);
  assert.equal(dockerLog(s).some((c) => c.cmd === 'run'), false);
});

test('sandbox show prints the command and checks Docker without starting anything', () => {
  const s = setup('show');
  const r = spawnSync(process.execPath, [CLI, 'sandbox', 'show', '--policy', s.policy, '--name', 'files', '--', 'node', '/app/server.js', '/workspace'], { env: s.env, encoding: 'utf8', timeout: 30_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /image fake\/image:1, network none, read-only root, user 65534:65534/);
  assert.match(r.stdout, /docker run --rm -i --init --name mcp-fw-files-[0-9a-f]{6} /);
  assert.match(r.stdout, /--network none --cap-drop ALL --security-opt no-new-privileges:true/);
  assert.match(r.stdout, /--entrypoint node fake\/image:1 \/app\/server\.js \/workspace/);
  assert.match(r.stdout, new RegExp(`image is present: ${ID_A}`));
  assert.equal(dockerLog(s).some((c) => c.cmd === 'run'), false);

  const down = spawnSync(process.execPath, [CLI, 'sandbox', 'show', '--policy', s.policy, '--', 'node', '/app/server.js'], { env: { ...s.env, FAKE_DOCKER_DOWN: '1' }, encoding: 'utf8', timeout: 30_000 });
  assert.equal(down.status, 1);
  assert.match(down.stdout, /not reachable/);

  const off = spawnSync(process.execPath, [CLI, 'sandbox', 'show', '--', 'node', '/app/server.js'], { env: { ...s.env, MCP_FIREWALL_POLICY: '' }, encoding: 'utf8', timeout: 30_000 });
  assert.equal(off.status, 2);
  assert.match(off.stderr, /the sandbox is off/);
});

test('a policy that tries to loosen the sandbox is rejected before anything starts', () => {
  const s = setup('loose', {}, ['sandbox:', '  enabled: true', `  image: ${IMAGE}`, '  network: host']);
  const r = spawnSync(process.execPath, [CLI, '--policy', s.policy, '--', 'node', MOCK], { env: s.env, encoding: 'utf8', timeout: 30_000 });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /sandbox\.network/);
  assert.equal(dockerLog(s).length, 0);
});
