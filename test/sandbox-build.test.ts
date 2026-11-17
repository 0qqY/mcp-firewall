import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { RunResult } from '../src/sandbox.js';
import { binArgs, buildImage, buildNpmImage, buildSummary, defaultBase, defaultTag, npmDockerfile, parseBuildSpec, parseNpmSpec, PYPI_BIN_SCRIPT, pypiDockerfile } from '../src/sandbox-build.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const ID_OLD = `sha256:${'a'.repeat(64)}`;
const ID_NEW = `sha256:${'c'.repeat(64)}`;
const ok = (stdout: string): RunResult => ({ status: 0, stdout, stderr: '' });
const noImage = (image: string): RunResult => ({ status: 1, stdout: '', stderr: `Error response from daemon: No such image: ${image}` });

test('parseNpmSpec takes an exact version only and a valid npm name', () => {
  assert.deepEqual(parseNpmSpec('@modelcontextprotocol/server-filesystem@2.2.0'), { name: '@modelcontextprotocol/server-filesystem', version: '2.2.0' });
  assert.deepEqual(parseNpmSpec('mcp-server@1.0.0-beta.2'), { name: 'mcp-server', version: '1.0.0-beta.2' });
  for (const bad of ['mcp-server', '@scope/pkg', 'pkg@latest', 'pkg@^1.2.0', 'pkg@1.x', 'pkg@1.2', 'pkg@>=1.0.0', 'pkg@1.0.0 || 2.0.0']) {
    assert.throws(() => parseNpmSpec(bad), /exact version|exact \(like/, bad);
  }
  // Anything that could break a Dockerfile line or a shell word is refused by the name or version pattern.
  for (const bad of ['Pkg@1.0.0', 'pkg name@1.0.0', 'pkg;rm@1.0.0', 'pkg@1.0.0;rm -rf /', 'pkg@1.0.0\nRUN id', '../x@1.0.0', 'pkg$(id)@1.0.0']) {
    assert.throws(() => parseNpmSpec(bad), /sandbox build/, JSON.stringify(bad));
  }
});

test('defaultTag is a valid image reference made from the package', () => {
  assert.equal(defaultTag({ name: '@modelcontextprotocol/server-filesystem', version: '2.2.0' }), 'mcp-modelcontextprotocol-server-filesystem:2.2.0');
  assert.equal(defaultTag({ name: 'mcp-server-x', version: '1.0.0+build.5' }), 'mcp-mcp-server-x:1.0.0_build.5');
  assert.equal(defaultTag({ name: 'a..b', version: '1.0.0' }), 'mcp-a-b:1.0.0');
});

test('npmDockerfile pins the version and turns install scripts off', () => {
  const file = npmDockerfile({ name: '@modelcontextprotocol/server-filesystem', version: '2.2.0' }, 'node:22-alpine');
  assert.match(file, /^FROM node:22-alpine$/m);
  assert.match(file, /^RUN npm install -g --ignore-scripts .*@modelcontextprotocol\/server-filesystem@2\.2\.0 /m);
  assert.equal(file.split('\n').filter((l) => /^[A-Z]+ /.test(l)).length, 2, 'only FROM and RUN');
});

test('the executables are read in a container as locked down as the sandbox', () => {
  const args = binArgs({ name: 'p', version: '1.0.0' }, 'mcp-p:1.0.0');
  for (const [flag, value] of [['--network', 'none'], ['--user', '65534:65534'], ['--cap-drop', 'ALL'], ['--pull', 'never'], ['--entrypoint', 'node']]) {
    assert.equal(args[args.indexOf(flag) + 1], value, flag);
  }
  assert.ok(args.includes('--read-only') && args.includes('--rm'));
});

/** A docker stand-in: `image inspect` answers from `images`, `build` "builds" into it, `run` lists executables. */
function fakeDocker(images: Map<string, string>, bins = '["mcp-server-filesystem"]') {
  const calls: string[][] = [];
  let dockerfile = '';
  const run = (_cmd: string, args: string[]): RunResult => {
    calls.push(args);
    if (args[0] === 'image') {
      const image = args[args.length - 1];
      const id = images.get(image);
      return id ? ok(`${id}\n`) : noImage(image);
    }
    if (args[0] === 'run') return ok(bins);
    return { status: 2, stdout: '', stderr: 'unexpected' };
  };
  const stream = async (_cmd: string, args: string[]): Promise<number> => {
    calls.push(args);
    const context = args[args.length - 1];
    dockerfile = readFileSync(`${context}/Dockerfile`, 'utf8');
    images.set(args[args.indexOf('--tag') + 1], ID_NEW);
    return 0;
  };
  return { run, stream, calls, dockerfile: () => dockerfile };
}

const pkg = { name: '@modelcontextprotocol/server-filesystem', version: '2.2.0' };
const opts = { pkg, tag: 'mcp-fs:2.2.0', base: 'node:22-alpine', force: false };

test('buildNpmImage builds in an empty context, then reports the id and the executables', async () => {
  const d = fakeDocker(new Map());
  const result = await buildNpmImage(opts, d.run, d.stream);
  assert.deepEqual(result, { id: ID_NEW, bins: ['mcp-server-filesystem'] });
  const build = d.calls.find((c) => c[0] === 'build')!;
  assert.ok(build.includes('org.mcp-firewall.npm-version=2.2.0'));
  assert.equal(existsSync(build[build.length - 1]), false, 'the temporary context is removed');
  assert.match(d.dockerfile(), /server-filesystem@2\.2\.0/);
  const summary = buildSummary(opts, result);
  assert.match(summary, /image: mcp-fs:2\.2\.0/);
  assert.match(summary, /sandbox show --sandbox mcp-fs:2\.2\.0 -- mcp-server-filesystem/);
});

test('buildNpmImage refuses to replace an existing image unless forced', async () => {
  const d = fakeDocker(new Map([['mcp-fs:2.2.0', ID_OLD]]));
  await assert.rejects(buildNpmImage(opts, d.run, d.stream), /already exists \(aaaaaaaaaaaa\).*--force/);
  assert.equal(d.calls.some((c) => c[0] === 'build'), false);
  const result = await buildNpmImage({ ...opts, force: true }, d.run, d.stream);
  assert.equal(result.id, ID_NEW);
});

test('buildNpmImage: Docker down, failed build, unreadable executables', async () => {
  const down = (): RunResult => ({ status: 1, stdout: '', stderr: 'error during connect: open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.' });
  await assert.rejects(buildNpmImage(opts, down, async () => 0), /not reachable/);
  const d = fakeDocker(new Map());
  await assert.rejects(buildNpmImage(opts, d.run, async () => 1), /docker build failed \(exit 1\)/);
  const odd = fakeDocker(new Map(), 'not json; ["rm -rf /"]');
  const result = await buildNpmImage(opts, odd.run, odd.stream);
  assert.deepEqual(result.bins, []);
  assert.match(buildSummary(opts, result), /could not be read/);
  const evil = fakeDocker(new Map(), '["good-bin","bad bin; id"]');
  assert.deepEqual((await buildNpmImage(opts, evil.run, evil.stream)).bins, ['good-bin']);
  await assert.rejects(buildNpmImage({ ...opts, tag: 'Bad Tag' }, d.run, d.stream), /--tag/);
});

test('CLI: sandbox build --print shows the Dockerfile without Docker; bad input is refused', () => {
  const env = { ...process.env, PATH: '', Path: '' }; // no docker reachable: --print must not need it
  const print = spawnSync(process.execPath, [CLI, 'sandbox', 'build', '@modelcontextprotocol/server-filesystem@2.2.0', '--print'], { encoding: 'utf8', env });
  assert.equal(print.status, 0, print.stderr);
  assert.match(print.stdout, /^FROM node:22-alpine$/m);
  assert.match(print.stdout, /--tag mcp-modelcontextprotocol-server-filesystem:2\.2\.0/);
  const range = spawnSync(process.execPath, [CLI, 'sandbox', 'build', 'pkg@^1.0.0', '--print'], { encoding: 'utf8', env });
  assert.equal(range.status, 1);
  assert.match(range.stderr, /exact/);
  const flag = spawnSync(process.execPath, [CLI, 'sandbox', 'build', 'pkg@1.0.0', '--network', 'host'], { encoding: 'utf8', env });
  assert.equal(flag.status, 2);
  assert.match(flag.stderr, /unknown option --network/);
  const base = spawnSync(process.execPath, [CLI, 'sandbox', 'build', 'pkg@1.0.0', '--base', 'x;y', '--print'], { encoding: 'utf8', env });
  assert.equal(base.status, 2);
  const none = spawnSync(process.execPath, [CLI, 'sandbox', 'build'], { encoding: 'utf8', env });
  assert.equal(none.status, 2);
});

test('PyPI: only pypi:name==exact is taken, and the ecosystem is never guessed', () => {
  assert.deepEqual(parseBuildSpec('pypi:mcp-server-fetch==2025.4.7'), { ecosystem: 'pypi', name: 'mcp-server-fetch', version: '2025.4.7' });
  assert.deepEqual(parseBuildSpec('pypi:Mcp_Thing==1.0rc1.post2'), { ecosystem: 'pypi', name: 'Mcp_Thing', version: '1.0rc1.post2' });
  assert.deepEqual(parseBuildSpec('npm:pkg@1.0.0'), { name: 'pkg', version: '1.0.0' });
  for (const bad of ['pypi:x==1.*', 'pypi:x>=1.0', 'pypi:x==1.0+local', 'pypi:x==1!2.0', 'pypi:x', 'pypi:==1.0', 'pypi:x y==1.0', 'pypi:x;id==1.0', 'pypi:x==1.0 --index-url=http://e', 'pypi:-x==1.0']) {
    assert.throws(() => parseBuildSpec(bad), /exact|valid PyPI/, bad);
  }
  assert.throws(() => parseBuildSpec('mcp-server-fetch==2025.4.7'), /exact version/); // a PyPI spec without the prefix is not read as one
});

test('PyPI: wheels only on a glibc base, an image name apart from npm, labels and executables per ecosystem', () => {
  const py = { ecosystem: 'pypi' as const, name: 'mcp.server_fetch', version: '2025.4.7' };
  assert.equal(defaultBase(py), 'python:3.12-slim');
  assert.equal(defaultBase({ name: 'p', version: '1.0.0' }), 'node:22-alpine');
  assert.equal(defaultTag(py), 'mcp-pypi-mcp-server-fetch:2025.4.7');
  assert.notEqual(defaultTag({ ecosystem: 'pypi', name: 'foo', version: '1.0.0' }), defaultTag({ name: 'foo', version: '1.0.0' }));
  const file = pypiDockerfile(py, 'python:3.12-slim');
  assert.match(file, /^RUN pip install --no-cache-dir --only-binary=:all: .* mcp\.server_fetch==2025\.4\.7$/m);
  const args = binArgs(py, 'mcp-pypi-x:1');
  assert.equal(args[args.indexOf('--entrypoint') + 1], 'python');
  assert.equal(args[args.indexOf('--network') + 1], 'none');
  assert.ok(args.includes('--read-only') && args.includes(PYPI_BIN_SCRIPT) && args[args.length - 1] === 'mcp.server_fetch');
});

test('PyPI: buildImage writes the pip Dockerfile and labels the image as PyPI', async () => {
  const d = fakeDocker(new Map(), '["mcp-server-fetch"]');
  const py = { pkg: { ecosystem: 'pypi' as const, name: 'mcp-server-fetch', version: '2025.4.7' }, tag: 'mcp-pypi-fetch:1', base: 'python:3.12-slim', force: false };
  const result = await buildImage(py, d.run, d.stream);
  assert.deepEqual(result.bins, ['mcp-server-fetch']);
  assert.match(d.dockerfile(), /only-binary=:all:/);
  const build = d.calls.find((c) => c[0] === 'build')!;
  assert.ok(build.includes('org.mcp-firewall.pypi-package=mcp-server-fetch') && !build.some((a) => a.includes('npm-')));
  assert.match(buildSummary(py, result), /pypi:mcp-server-fetch==2025\.4\.7, base python:3\.12-slim, wheels only/);
});

test('CLI: sandbox build --print for a PyPI package', () => {
  const env = { ...process.env, PATH: '', Path: '' };
  const r = spawnSync(process.execPath, [CLI, 'sandbox', 'build', 'pypi:mcp-server-fetch==2025.4.7', '--print'], { encoding: 'utf8', env });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^FROM python:3\.12-slim$/m);
  assert.match(r.stdout, /--tag mcp-pypi-mcp-server-fetch:2025\.4\.7/);
  const bad = spawnSync(process.execPath, [CLI, 'sandbox', 'build', 'pypi:mcp-server-fetch==2025.*', '--print'], { encoding: 'utf8', env });
  assert.equal(bad.status, 1);
});

test('CLI: sandbox build --runtime podman writes the base image out in full; other runtimes are refused', () => {
  const env = { ...process.env, PATH: '', Path: '' };
  const r = spawnSync(process.execPath, [CLI, 'sandbox', 'build', 'pypi:mcp-server-fetch==2025.4.7', '--runtime', 'podman', '--print'], { encoding: 'utf8', env });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^FROM docker\.io\/library\/python:3\.12-slim$/m);
  assert.match(r.stdout, /^# podman build --tag/m);
  const own = spawnSync(process.execPath, [CLI, 'sandbox', 'build', 'pkg@1.0.0', '--runtime', 'podman', '--base', 'node:20', '--print'], { encoding: 'utf8', env });
  assert.match(own.stdout, /^FROM node:20$/m, 'a base the user gave is left as given');
  const lxc = spawnSync(process.execPath, [CLI, 'sandbox', 'build', 'pkg@1.0.0', '--runtime', 'lxc'], { encoding: 'utf8', env });
  assert.equal(lxc.status, 2);
});

test('podman: the executables are read with podman\'s form of no-new-privileges', () => {
  const args = binArgs({ ecosystem: 'pypi', name: 'p', version: '1.0' }, 'x:1', 'podman');
  assert.equal(args[args.indexOf('--security-opt') + 1], 'no-new-privileges');
  assert.ok(binArgs({ name: 'p', version: '1.0.0' }, 'x:1').includes('no-new-privileges:true'));
});
