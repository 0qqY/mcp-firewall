import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, realpathSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, parse } from 'node:path';
import { test } from 'node:test';
import {
  buildSandboxCommand,
  formatLaunch,
  inspectImage,
  isImageRef,
  killContainer,
  mountProblem,
  preflight,
  sandboxFingerprint,
  SandboxError,
  type RunResult,
  type Runner,
  type SandboxConfig,
} from '../src/sandbox.js';
import { compilePolicy, PolicyError } from '../src/policy.js';

const top = realpathSync(mkdtempSync(join(tmpdir(), 'mcpfw-sandbox-')));
const work = join(top, 'work');
mkdirSync(work);
const sandbox = (raw: Record<string, unknown> = {}, baseDir = top): SandboxConfig => compilePolicy({ sandbox: { enabled: true, image: 'node:22-alpine', ...raw } }, baseDir).sandbox;
const bad = (raw: unknown, pattern: RegExp, baseDir = top) => assert.throws(() => compilePolicy({ sandbox: raw }, baseDir), (err: Error) => err instanceof PolicyError && pattern.test(err.message));
const server = { command: 'node', args: ['/app/server.js', '--stdio'] };
const fixed = { serverId: 'My Server!', random: () => 'abc123' };

// ---------- policy ----------

test('the sandbox is off by default and its defaults are the strict ones', () => {
  const s = compilePolicy({}, top).sandbox;
  assert.equal(s.enabled, false);
  assert.deepEqual(
    { pull: s.pull, network: s.network, readOnly: s.readOnly, user: s.user, memory: s.memory, cpus: s.cpus, pidsLimit: s.pidsLimit, tmpfsSize: s.tmpfsSize },
    { pull: 'never', network: 'none', readOnly: true, user: '65534:65534', memory: '512m', cpus: 1, pidsLimit: 256, tmpfsSize: '64m' },
  );
  assert.deepEqual([s.mounts, s.env], [[], []]);
});

test('an enabled sandbox needs an image', () => {
  bad({ enabled: true }, /sandbox\.image: required/);
});

test('image references are checked, and cannot smuggle options', () => {
  for (const ok of ['node:22-alpine', 'ghcr.io/github/github-mcp-server:v2.0.3', 'localhost:5000/team/img', `alpine@sha256:${'a'.repeat(64)}`, 'library/node', 'my_image']) {
    assert.equal(isImageRef(ok), true, ok);
  }
  for (const no of ['-v/:/host', 'Node:22', 'node 22', 'node:22; rm -rf', '', 'node@sha256:short', '--privileged']) {
    assert.equal(isImageRef(no), false, no);
  }
  bad({ enabled: true, image: '--privileged' }, /sandbox\.image: not a valid image reference/);
});

test('network: none, bridge or a named network; never host or a container join', () => {
  assert.equal(sandbox({ network: 'bridge' }).network, 'bridge');
  assert.equal(sandbox({ network: 'mcp-egress' }).network, 'mcp-egress');
  bad({ enabled: true, image: 'x', network: 'host' }, /sandbox\.network/);
  bad({ enabled: true, image: 'x', network: 'container:db' }, /sandbox\.network/);
});

test('raw docker options are not accepted, and the error says why', () => {
  bad({ enabled: true, image: 'x', extraArgs: ['--privileged'] }, /sandbox\.extraArgs: unknown option .*raw docker flags/);
  bad({ enabled: true, image: 'x', privileged: true }, /sandbox\.privileged: unknown option/);
  bad({ enabled: true, image: 'x', netwrok: 'bridge' }, /sandbox\.netwrok: unknown option/);
});

test('limits and user are validated', () => {
  bad({ memory: '0' }, /sandbox\.memory/);
  bad({ memory: 'lots' }, /sandbox\.memory/);
  bad({ memory: '1.5g' }, /sandbox\.memory/);
  bad({ tmpfsSize: '-1' }, /sandbox\.tmpfsSize/);
  bad({ cpus: 0 }, /sandbox\.cpus/);
  bad({ cpus: 1000 }, /sandbox\.cpus/);
  bad({ pidsLimit: 1.5 }, /sandbox\.pidsLimit/);
  bad({ user: 'root' }, /sandbox\.user/);
  assert.equal(sandbox({ memory: '2g', cpus: 0.5, pidsLimit: 64, user: '1000' }).memory, '2g');
});

test('passed-through variables are names only, once, and not the ones the sandbox sets', () => {
  assert.deepEqual(sandbox({ env: ['GITHUB_TOKEN'] }).env, ['GITHUB_TOKEN']);
  bad({ env: ['HOME'] }, /sandbox\.env: HOME is set by the sandbox/);
  bad({ env: ['PATH'] }, /sandbox\.env: PATH is set by the sandbox/);
  bad({ env: ['A=1'] }, /sandbox\.env: A=1 is not a variable name/);
  bad({ env: ['TOKEN', 'TOKEN'] }, /listed twice/);
});

test('mounts resolve against the policy folder and are read-only unless asked', () => {
  const s = sandbox({ mounts: [{ source: 'work', target: '/workspace' }, { source: work, target: '/data', mode: 'rw' }] });
  assert.deepEqual(s.mounts, [
    { source: work, target: '/workspace', readOnly: true },
    { source: work, target: '/data', readOnly: false },
  ]);
});

test('mount targets are checked', () => {
  bad({ mounts: [{ source: work, target: 'relative' }] }, /target: expected an absolute path/);
  bad({ mounts: [{ source: work, target: '/' }] }, /target: \/ is not allowed/);
  bad({ mounts: [{ source: work, target: '/proc/x' }] }, /not allowed/);
  bad({ mounts: [{ source: work, target: '/a,readonly=false' }] }, /target/);
  // a line break would end Docker's one-record parse of --mount and drop the ",readonly" after it
  bad({ mounts: [{ source: work, target: '/a\n' }] }, /target/);
  bad({ mounts: [{ source: work, target: '/a\r' }] }, /target/);
  bad({ mounts: [{ source: `${work}\nx`, target: '/a' }] }, /control character/);
  bad({ mounts: [{ source: work, target: '/a"b' }] }, /target/);
  bad({ mounts: [{ source: work, target: '/a' }, { source: work, target: '/a' }] }, /used by another mount/);
  bad({ mounts: [{ source: work, target: '/a', mode: 'rwx' }] }, /mode/);
  bad({ mounts: [{ source: work, target: '/a', flags: 'x' }] }, /flags: unknown option/);
});

test('mounts cannot reach credentials, the home folder, the policy folder or the firewall state', () => {
  const home = homedir();
  const sources: [string, RegExp][] = [
    [parse(top).root, /root of a drive/],
    [home, /contains/],
    [join(home, '.ssh'), /inside .*\.ssh/],
    [join(home, '.ssh', 'keys'), /inside .*\.ssh/],
    [join(home, '.mcp-firewall'), /inside|contains/],
    [top, /contains/], // the policy folder itself: it holds the audit log, the pins and the policy
  ];
  for (const [source, why] of sources) bad({ mounts: [{ source, target: '/x' }] }, new RegExp(`cannot be mounted: .*${why.source}`), top);
  // a folder that holds the audit log cannot be mounted, a sibling can
  const logs = join(top, 'logs');
  const policy = compilePolicy({ audit: { file: join(logs, 'audit.jsonl') }, sandbox: { enabled: true, image: 'x', mounts: [{ source: work, target: '/w' }] } }, top);
  assert.equal(policy.sandbox.mounts.length, 1);
  assert.throws(() => compilePolicy({ audit: { file: join(logs, 'audit.jsonl') }, sandbox: { enabled: true, image: 'x', mounts: [{ source: logs, target: '/w' }] } }, top), /contains .*audit\.jsonl/);
  assert.throws(() => compilePolicy({ sandbox: { enabled: true, image: 'x', mounts: [{ source: join(work, 'a,b'), target: '/w' }] } }, top), /comma, quote or control character/);
});

test('mountProblem: filesystem root, Docker socket, credentials, ancestors; case is ignored on Windows', () => {
  const posix = { protectedPaths: ['/home/u/.ssh', '/home/u/.mcp-firewall/pins.json'], protectedRoots: ['/home/u', '/srv/policy'] };
  assert.match(mountProblem('/', posix, 'linux')!, /root/);
  assert.match(mountProblem('/var/run/docker.sock', posix, 'linux')!, /Docker socket/);
  assert.match(mountProblem('/home/u/.ssh/id_ed25519', posix, 'linux')!, /inside \/home\/u\/\.ssh/);
  assert.match(mountProblem('/home/u/.mcp-firewall', posix, 'linux')!, /contains \/home\/u\/\.mcp-firewall\/pins\.json/);
  assert.match(mountProblem('/home', posix, 'linux')!, /contains/);
  assert.match(mountProblem('/srv', posix, 'linux')!, /contains/);
  assert.equal(mountProblem('/home/u/project', posix, 'linux'), undefined);
  assert.equal(mountProblem('/srv/policy/work', posix, 'linux'), undefined);
  assert.equal(mountProblem('/home/U/.SSH', posix, 'linux'), undefined, 'case matters on Linux');

  const win = { protectedPaths: ['C:\\Users\\u\\.ssh'], protectedRoots: ['C:\\Users\\u'] };
  assert.match(mountProblem('c:\\users\\U\\.SSH', win, 'win32')!, /inside/);
  assert.match(mountProblem('C:\\', win, 'win32')!, /root/);
  assert.match(mountProblem('C:\\Users', win, 'win32')!, /contains/);
  assert.match(mountProblem('\\\\.\\pipe\\docker_engine', win, 'win32')!, /Docker socket/);
  assert.equal(mountProblem('C:\\Users\\u\\project', win, 'win32'), undefined);
  assert.equal(mountProblem('D:\\data', win, 'win32'), undefined);
});

// ---------- the docker command ----------

test('the default command line carries every hardening option, in a fixed order', () => {
  const launch = buildSandboxCommand(sandbox(), server, fixed);
  assert.equal(launch.command, 'docker');
  assert.equal(launch.container, 'mcp-fw-my-server-abc123');
  assert.deepEqual(launch.args, [
    'run', '--rm', '-i', '--init',
    '--name', 'mcp-fw-my-server-abc123',
    '--label', 'mcp-firewall=1',
    '--pull', 'never',
    '--network', 'none',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges:true',
    '--pids-limit', '256',
    '--memory', '512m',
    '--memory-swap', '512m',
    '--cpus', '1',
    '--user', '65534:65534',
    '--read-only',
    '--tmpfs', '/tmp:rw,nosuid,size=64m',
    '-e', 'HOME=/tmp',
    '--entrypoint', 'node', 'node:22-alpine', '/app/server.js', '--stdio',
  ]);
});

test('settings change the matching options and nothing else', () => {
  const args = buildSandboxCommand(sandbox({ network: 'bridge', readOnly: false, pull: 'missing', memory: '1g', cpus: 2, pidsLimit: 32, user: '1000:1000', tmpfsSize: '8m', workdir: '/w' }), server, fixed).args;
  const at = (flag: string) => args[args.indexOf(flag) + 1];
  assert.equal(at('--network'), 'bridge');
  assert.equal(at('--pull'), 'missing');
  assert.equal(at('--memory'), '1g');
  assert.equal(at('--memory-swap'), '1g');
  assert.equal(at('--cpus'), '2');
  assert.equal(at('--pids-limit'), '32');
  assert.equal(at('--user'), '1000:1000');
  assert.equal(at('--tmpfs'), '/tmp:rw,nosuid,size=8m');
  assert.equal(at('-w'), '/w');
  assert.equal(args.includes('--read-only'), false);
  assert.equal(args.includes('--cap-drop') && at('--cap-drop') === 'ALL', true);
  assert.equal(at('--security-opt'), 'no-new-privileges:true');
});

test('the server command is the entrypoint; its arguments are never read as docker options', () => {
  const args = buildSandboxCommand(sandbox(), { command: 'npx', args: ['--privileged', '-v', '/:/host', '--network=host'] }, fixed).args;
  const image = args.indexOf('node:22-alpine');
  assert.deepEqual(args.slice(image - 2), ['--entrypoint', 'npx', 'node:22-alpine', '--privileged', '-v', '/:/host', '--network=host']);
  assert.equal(args.slice(0, image - 2).includes('--privileged'), false);
  assert.throws(() => buildSandboxCommand(sandbox(), { command: '', args: [] }, fixed), SandboxError);
});

test('variables are passed by name; their values never reach the command line', () => {
  const cfg = sandbox({ env: ['GITHUB_TOKEN', 'OTHER'] });
  const launch = buildSandboxCommand(cfg, server, { ...fixed, env: { GITHUB_TOKEN: 'ghp_secretvalue', OTHER: 'x' } });
  const pairs = launch.args.flatMap((a, i) => (launch.args[i - 1] === '-e' ? [a] : []));
  assert.deepEqual(pairs, ['HOME=/tmp', 'GITHUB_TOKEN', 'OTHER']);
  assert.equal(launch.args.join(' ').includes('ghp_secretvalue'), false);
  assert.throws(() => buildSandboxCommand(cfg, server, { ...fixed, env: { GITHUB_TOKEN: 'x' } }), /OTHER is not set/);
});

test('mounts become read-only bind mounts; missing or redirected sources are refused', () => {
  const cfg = sandbox({ mounts: [{ source: work, target: '/workspace' }, { source: work, target: '/data', mode: 'rw' }] });
  const args = buildSandboxCommand(cfg, server, fixed).args;
  const mounts = args.filter((a, i) => args[i - 1] === '--mount');
  assert.deepEqual(mounts, [`type=bind,source=${work},target=/workspace,readonly`, `type=bind,source=${work},target=/data`]);

  assert.throws(() => buildSandboxCommand(cfg, server, { ...fixed, exists: () => false }), /does not exist/);
  // a symlink that leads into a protected folder is judged by where it ends up
  const ssh = join(homedir(), '.ssh');
  assert.throws(() => buildSandboxCommand(cfg, server, { ...fixed, realpath: () => ssh }), (err: Error) => err instanceof SandboxError && /resolves to .*\.ssh.*inside/.test(err.message));
  assert.throws(() => buildSandboxCommand(cfg, server, { ...fixed, realpath: () => join(top, 'a,b') }), /comma, quote or control character/);
  assert.throws(() => buildSandboxCommand(cfg, server, { ...fixed, realpath: () => `${join(top, 'a')}\n` }), /comma, quote or control character/);
});

test('container names are valid Docker names whatever the server id looks like', () => {
  const valid = /^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/;
  for (const id of ['x', 'node /app/server.js --root "C:\\My Files"', '!!!', 'ünïcödé', 'a'.repeat(300), '--rm -v /:/h']) {
    const { container } = buildSandboxCommand(sandbox(), server, { serverId: id, random: () => 'f00dca' });
    assert.match(container, valid, id);
    assert.ok(container.length <= 40, container);
  }
  assert.equal(buildSandboxCommand(sandbox(), server, { serverId: '!!!', random: () => 'f00dca' }).container, 'mcp-fw-server-f00dca');
  const a = buildSandboxCommand(sandbox(), server, { serverId: 'x' }).container;
  const b = buildSandboxCommand(sandbox(), server, { serverId: 'x' }).container;
  assert.notEqual(a, b);
});

test('formatLaunch quotes for the shell of the platform', () => {
  const launch = { command: 'docker', args: ['run', '--entrypoint', 'node', 'img', 'a b', "it's"], container: 'c' };
  assert.equal(formatLaunch(launch, 'linux'), `docker run --entrypoint node img 'a b' 'it'\\''s'`);
  assert.equal(formatLaunch(launch, 'win32'), `docker run --entrypoint node img "a b" "it's"`);
});

// ---------- Docker availability and the image id ----------

const run = (r: Partial<RunResult>): Runner => () => ({ status: 0, stdout: '', stderr: '', ...r });
const ID = `sha256:${'1'.repeat(64)}`;
const ID2 = `sha256:${'2'.repeat(64)}`;

test('inspectImage tells a missing image from an unreachable Docker', () => {
  assert.deepEqual(inspectImage('x', run({ stdout: `${ID}\n` })), { kind: 'ok', id: ID });
  assert.equal(inspectImage('x', run({ status: 1, stderr: 'Error response from daemon: No such image: x:latest\n' })).kind, 'missing');
  assert.equal(inspectImage('x', run({ status: 1, stderr: 'error during connect: this error may indicate that the docker daemon is not running' })).kind, 'unreachable');
  assert.equal(inspectImage('x', run({ status: 1, stderr: 'open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.' })).kind, 'unreachable');
  assert.equal(inspectImage('x', run({ error: Object.assign(new Error('spawn docker ENOENT'), { code: 'ENOENT' }) })).kind, 'no-docker');
  assert.equal(inspectImage('x', run({ stdout: 'garbage' })).kind, 'error');
  // an image name with a word the connection patterns look for is still just a missing image
  assert.equal(inspectImage('mypipe:1', run({ status: 1, stderr: 'Error response from daemon: No such image: mypipe:1' })).kind, 'missing');
});

test('preflight explains what to do', () => {
  const cfg = sandbox();
  assert.equal(preflight(cfg, run({ stdout: ID })), ID);
  assert.throws(() => preflight(cfg, run({ status: 1, stderr: 'No such image' })), /not present locally.*docker pull node:22-alpine/);
  assert.equal(preflight(sandbox({ pull: 'missing' }), run({ status: 1, stderr: 'No such image' })), undefined);
  assert.throws(() => preflight(cfg, run({ status: 1, stderr: 'Cannot connect to the Docker daemon' })), /start Docker Desktop/);
  assert.throws(() => preflight(cfg, run({ error: Object.assign(new Error('x'), { code: 'ENOENT' }) })), /docker command was not found/);
});

test('the code fingerprint is the image id, so a rebuilt image looks like changed server code', () => {
  const cfg = sandbox();
  const a = sandboxFingerprint(cfg, undefined, run({ stdout: ID }));
  const again = sandboxFingerprint(cfg, undefined, run({ stdout: ID }));
  const rebuilt = sandboxFingerprint(cfg, undefined, run({ stdout: ID2 }));
  assert.equal(a.hash, again.hash);
  assert.notEqual(a.hash, rebuilt.hash);
  assert.match(a.packages[0], /image node:22-alpine \(1{12}\)/);
  assert.ok(a.notes.some((n) => /referenced by a tag/.test(n)));
  const pinned = sandboxFingerprint(sandbox({ image: `node@sha256:${'a'.repeat(64)}` }), undefined, run({ stdout: ID }));
  assert.deepEqual(pinned.notes, []);
  const withCode = sandboxFingerprint(cfg, { hash: 'abc', roots: ['/src'], packages: ['pkg@1'], notes: ['n'] }, run({ stdout: ID }));
  assert.notEqual(withCode.hash, a.hash);
  assert.deepEqual(withCode.roots, ['/src']);
  assert.throws(() => sandboxFingerprint(cfg, undefined, run({ status: 1, stderr: 'Cannot connect' })), /cannot identify sandbox image/);
});

test('killContainer asks Docker to stop the container by name and never throws', () => {
  const calls: string[][] = [];
  killContainer('mcp-fw-x-1', (cmd, args) => (calls.push([cmd, ...args]), { status: 0, stdout: '', stderr: '' }));
  assert.deepEqual(calls, [['docker', 'kill', 'mcp-fw-x-1']]);
  assert.doesNotThrow(() => killContainer('c', () => { throw new Error('boom'); }));
});
