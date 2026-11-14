import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync } from 'node:fs';
import { createServer, connect, type AddressInfo, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  createEgressProxy,
  decideEgress,
  isNonPublicAddress,
  matchEgress,
  parseEgressRule,
  type EgressEvent,
} from '../src/egress.js';
import { EgressThrottle } from '../src/egress-throttle.js';
import { compilePolicy, PolicyError } from '../src/policy.js';
import {
  buildSandboxCommand,
  connectEgressProxy,
  createEgressNetwork,
  preflight,
  removeEgress,
  sandboxFingerprint,
  SandboxError,
  type RunResult,
  type Runner,
  type SandboxConfig,
} from '../src/sandbox.js';

const top = realpathSync(mkdtempSync(join(tmpdir(), 'mcpfw-egress-')));
const sandbox = (raw: Record<string, unknown> = {}): SandboxConfig =>
  compilePolicy({ sandbox: { enabled: true, image: 'mcp-x:1', egress: { allow: ['api.example.com', '*.cdn.example.net:8443'] }, ...raw } }, top).sandbox;
const bad = (raw: unknown, pattern: RegExp) =>
  assert.throws(() => compilePolicy({ sandbox: raw }, top), (err: Error) => err instanceof PolicyError && pattern.test(err.message));
const files = { main: '/opt/fw/egress-main.js', lib: '/opt/fw/egress.js' };
const fixed = { serverId: 'srv', random: () => 'abc123', egressFiles: files, platform: 'linux' as const };
const ID = `sha256:${'1'.repeat(64)}`;
const ID2 = `sha256:${'2'.repeat(64)}`;

// ---------- rules ----------

test('rules: host, port, wildcard, IP literals; URLs, paths and bare wildcards are refused', () => {
  assert.deepEqual(parseEgressRule('API.Example.com.'), { host: 'api.example.com', wildcard: false, port: 443 });
  assert.deepEqual(parseEgressRule('api.example.com:8080'), { host: 'api.example.com', wildcard: false, port: 8080 });
  assert.deepEqual(parseEgressRule('*.example.com'), { host: 'example.com', wildcard: true, port: 443 });
  assert.deepEqual(parseEgressRule('203.0.113.7:9000'), { host: '203.0.113.7', wildcard: false, port: 9000 });
  assert.deepEqual(parseEgressRule('[2001:db8::1]:443'), { host: '2001:db8::1', wildcard: false, port: 443 });
  assert.deepEqual(parseEgressRule('2001:db8::1'), { host: '2001:db8::1', wildcard: false, port: 443 });
  for (const spec of ['*', '*.com', 'https://api.example.com', 'api.example.com/path', 'user@host.com', 'a*.example.com', 'host:0', 'host:70000', 'bad_host.com', '-x.com', '', 'a b.com']) {
    assert.throws(() => parseEgressRule(spec), Error, spec);
  }
});

test('matching: exact host and port; a wildcard covers sub-domains but not the domain itself', () => {
  const rules = ['api.example.com', '*.cdn.example.net:8443'].map(parseEgressRule);
  assert.ok(matchEgress(rules, 'API.EXAMPLE.COM.', 443));
  assert.equal(matchEgress(rules, 'api.example.com', 80), undefined);
  assert.equal(matchEgress(rules, 'evil-api.example.com', 443), undefined);
  assert.equal(matchEgress(rules, 'api.example.com.evil.net', 443), undefined);
  assert.ok(matchEgress(rules, 'a.b.cdn.example.net', 8443));
  assert.equal(matchEgress(rules, 'cdn.example.net', 8443), undefined);
  assert.equal(matchEgress(rules, 'xcdn.example.net', 8443), undefined);
});

test('non-public addresses: private, loopback, link-local, CGNAT, mapped and NAT64 forms', () => {
  for (const ip of ['10.1.2.3', '127.0.0.1', '169.254.169.254', '172.16.0.1', '172.31.255.255', '192.168.65.254', '100.64.0.1', '0.0.0.0', '224.0.0.1',
    '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '64:ff9b::a00:1', 'ff02::1', 'not-an-ip']) {
    assert.equal(isNonPublicAddress(ip), true, ip);
  }
  for (const ip of ['93.184.215.14', '1.1.1.1', '172.32.0.1', '100.128.0.1', '2606:4700:4700::1111', '::ffff:1.1.1.1']) {
    assert.equal(isNonPublicAddress(ip), false, ip);
  }
});

test('decideEgress: allowlist first, then every resolved address must be public', async () => {
  const rules = ['api.example.com', 'listed.internal.test', '10.9.9.9:5432'].map(parseEgressRule);
  const dns = (map: Record<string, string[]>) => async (h: string) => {
    if (!map[h]) throw Object.assign(new Error('nx'), { code: 'ENOTFOUND' });
    return map[h];
  };
  const ok = await decideEgress(rules, 'api.example.com', 443, dns({ 'api.example.com': ['93.184.215.14'] }));
  assert.deepEqual(ok, { allow: true, host: 'api.example.com', port: 443, address: '93.184.215.14' });
  assert.match((await decideEgress(rules, 'other.com', 443, dns({}))  as { reason: string }).reason, /not on the egress allowlist/);
  // a name that also resolves inside is refused, even when one answer is public (rebinding)
  const mixed = await decideEgress(rules, 'api.example.com', 443, dns({ 'api.example.com': ['93.184.215.14', '127.0.0.1'] }));
  assert.equal(mixed.allow, false);
  assert.match((mixed as { reason: string }).reason, /non-public address \(127\.0\.0\.1\)/);
  assert.match((await decideEgress(rules, 'listed.internal.test', 443, dns({ 'listed.internal.test': ['10.0.0.5'] })) as { reason: string }).reason, /non-public/);
  assert.match((await decideEgress(rules, 'api.example.com', 443, dns({})) as { reason: string }).reason, /does not resolve \(ENOTFOUND\)/);
  // an IP literal the policy lists by hand is taken as written
  assert.equal((await decideEgress(rules, '10.9.9.9', 5432, dns({}))).allow, true);
  const junk = await decideEgress(rules, 'a\x07b\nc', 443, dns({}));
  assert.equal(junk.allow, false);
  assert.doesNotMatch(junk.host, /[\x00-\x1f]/);
});

// ---------- proxy ----------

function listen(server: Server): Promise<number> {
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r((server.address() as AddressInfo).port)));
}

function ask(port: number, request: string, send?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect({ host: '127.0.0.1', port }, () => s.write(request));
    let data = '';
    s.on('data', (d) => {
      data += d.toString();
      if (send && data.includes('\r\n\r\n') && data.startsWith('HTTP/1.1 200')) {
        s.write(send);
        send = undefined;
      }
    });
    s.on('end', () => resolve(data));
    s.on('close', () => resolve(data));
    s.on('error', reject);
    setTimeout(() => s.end(), 600);
  });
}

test('the proxy tunnels allowed CONNECTs to the checked address and refuses the rest', async () => {
  const echo = createServer((s) => s.on('data', (d) => s.write(`echo:${d}`)));
  const echoPort = await listen(echo);
  const dialed: string[] = [];
  const events: EgressEvent[] = [];
  const proxy = createEgressProxy({
    rules: ['api.example.com'].map(parseEgressRule),
    resolve: async (h) => (h === 'api.example.com' ? ['93.184.215.14'] : ['10.0.0.1']),
    dial: (address, port) => {
      dialed.push(`${address}:${port}`);
      return connect({ host: '127.0.0.1', port: echoPort });
    },
    log: (e) => events.push(e),
  });
  const port = await listen(proxy);
  try {
    const ok = await ask(port, 'CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n', 'hello');
    assert.match(ok, /^HTTP\/1\.1 200 Connection Established\r\n\r\necho:hello/);
    assert.deepEqual(dialed, ['93.184.215.14:443']);
    assert.match(await ask(port, 'CONNECT other.com:443 HTTP/1.1\r\n\r\n'), /^HTTP\/1\.1 403/);
    assert.match(await ask(port, 'CONNECT api.example.com:22 HTTP/1.1\r\n\r\n'), /^HTTP\/1\.1 403/);
    assert.match(await ask(port, 'GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n'), /^HTTP\/1\.1 405/);
    assert.match(await ask(port, 'CONNECT nonsense HTTP/1.1\r\n\r\n'), /^HTTP\/1\.1 400/);
    assert.match(await ask(port, `CONNECT ${'a'.repeat(9000)}`), /^HTTP\/1\.1 431/);
    assert.deepEqual(dialed, ['93.184.215.14:443'], 'nothing else was dialed');
    assert.deepEqual(events.map((e) => `${e.egress} ${e.host}:${e.port}`), [
      'allow api.example.com:443', 'deny other.com:443', 'deny api.example.com:22', 'deny api.example.com:80', 'deny nonsense:0',
    ]);
  } finally {
    proxy.close();
    echo.close();
  }
});

// ---------- policy ----------

test('policy: egress needs an allowlist, refuses an open network and checks every rule', () => {
  const s = sandbox();
  assert.deepEqual(s.egress?.allow, ['api.example.com:443', '*.cdn.example.net:8443']);
  assert.equal(s.egress?.proxyImage, 'node:22-alpine');
  assert.equal(s.network, 'none');
  assert.equal(sandbox({ network: 'none' }).egress?.rules.length, 2);
  bad({ egress: { allow: ['a.com'] }, network: 'bridge' }, /cannot be combined with sandbox\.network: bridge/);
  bad({ egress: { allow: ['a.com'] }, network: 'my-net' }, /cannot be combined/);
  bad({ egress: { allow: [] } }, /list at least one/);
  bad({ egress: {} }, /list at least one/);
  bad({ egress: { allow: ['https://a.com'] } }, /egress\.allow\[0\].*not a URL/);
  bad({ egress: { allow: ['ok.com', '*'] } }, /egress\.allow\[1\]/);
  bad({ egress: { allow: ['a.com'], extraArgs: ['--privileged'] } }, /egress\.extraArgs: unknown option/);
  bad({ egress: { allow: ['a.com'], proxyImage: 'x y' } }, /proxyImage: not a valid image/);
  assert.equal(sandbox({ egress: { allow: ['a.com'], proxyImage: 'my/node:22' } }).egress?.proxyImage, 'my/node:22');
});

test('policy: with egress the sandbox sets the proxy variables; without it they still pass through (corporate proxy)', () => {
  for (const name of ['HTTPS_PROXY', 'http_proxy', 'NO_PROXY', 'ALL_PROXY', 'NODE_USE_ENV_PROXY']) {
    bad({ enabled: false, env: [name], egress: { allow: ['a.com'] } }, /is set by the sandbox when egress is on/);
    assert.deepEqual(compilePolicy({ sandbox: { network: 'bridge', env: [name] } }, top).sandbox.env, [name]);
  }
});

test('throttle: once per key per minute, a global budget across fresh names, and nothing lost silently', () => {
  const t = new EgressThrottle(3, 60_000);
  assert.deepEqual(t.take('deny|a|443', 0), { write: true, more: 0, suppressed: undefined });
  assert.equal(t.take('deny|a|443', 1000).write, false);
  assert.equal(t.take('deny|a|443', 2000).write, false);
  // a stream of fresh host names: the budget (3) caps them
  assert.equal(t.take('deny|b|443', 3000).write, true);
  assert.equal(t.take('deny|c|443', 4000).write, true);
  for (let i = 0; i < 50; i++) assert.equal(t.take(`deny|x${i}|443`, 5000 + i).write, false);
  // next window: one summary of what the budget held back, and the repeated key reports its count
  const next = t.take('deny|a|443', 61_000);
  assert.deepEqual(next, { write: true, more: 2, suppressed: 50 });
  assert.equal(t.take('deny|d|443', 62_000).suppressed, undefined);
});

// ---------- launch ----------

const opt = (args: string[], name: string) => args[args.indexOf(name) + 1];

test('launch: the server sits on its own internal network with the proxy variables set', () => {
  const l = buildSandboxCommand(sandbox(), { command: 'node', args: ['/s.js'] }, fixed);
  assert.equal(l.egress?.network, 'mcp-fw-srv-abc123-net');
  assert.equal(opt(l.args, '--network'), 'mcp-fw-srv-abc123-net');
  for (const v of ['HTTPS_PROXY=http://mcp-fw-srv-abc123-egress:3128', 'https_proxy=http://mcp-fw-srv-abc123-egress:3128', 'HTTP_PROXY=http://mcp-fw-srv-abc123-egress:3128', 'NODE_USE_ENV_PROXY=1']) {
    assert.ok(l.args.includes(v), v);
  }
  // still every hardening option of the plain sandbox
  for (const flag of ['--cap-drop', '--read-only', '--pids-limit', '--memory']) assert.ok(l.args.includes(flag), flag);
  // without egress nothing changes
  const plain = buildSandboxCommand(sandbox({ egress: undefined }), { command: 'node', args: [] }, fixed);
  assert.equal(plain.egress, undefined);
  assert.equal(opt(plain.args, '--network'), 'none');
  assert.ok(!plain.args.some((a) => /PROXY/.test(a)));
});

test('launch: the proxy is locked down, runs only the mounted firewall files and gets the normalised allowlist', () => {
  const p = buildSandboxCommand(sandbox(), { command: 'node', args: [] }, fixed).egress!.proxy;
  assert.equal(p.container, 'mcp-fw-srv-abc123-egress');
  assert.equal(opt(p.args, '--network'), 'bridge');
  assert.equal(opt(p.args, '--user'), '65534:65534');
  assert.equal(opt(p.args, '--cap-drop'), 'ALL');
  assert.ok(p.args.includes('--read-only'));
  assert.ok(p.args.includes('MCP_FW_EGRESS=api.example.com:443,*.cdn.example.net:8443'));
  assert.ok(p.args.includes('type=bind,source=/opt/fw/egress-main.js,target=/fw/egress-main.js,readonly'));
  assert.ok(p.args.includes('type=bind,source=/opt/fw/egress.js,target=/fw/egress.js,readonly'));
  assert.deepEqual(p.args.slice(-4), ['--entrypoint', 'node', 'node:22-alpine', '/fw/egress-main.js']);
  assert.throws(() => buildSandboxCommand(sandbox(), { command: 'node', args: [] }, { ...fixed, egressFiles: { main: '/a,b/m.js', lib: '/l.js' } }), SandboxError);
});

function recorder(results: Partial<RunResult>[] = []): { calls: string[]; run: Runner } {
  const calls: string[] = [];
  return {
    calls,
    run: (cmd, args) => {
      calls.push([cmd, ...args].join(' '));
      return { status: 0, stdout: '', stderr: '', ...(results.shift() ?? {}) };
    },
  };
}

test('lifecycle: stale labelled networks are pruned (older than five minutes only), then the network is created, joined and removed', () => {
  const e = buildSandboxCommand(sandbox(), { command: 'node', args: [] }, fixed).egress!;
  const r = recorder();
  createEgressNetwork(e, r.run);
  connectEgressProxy(e, r.run);
  assert.deepEqual(r.calls, [
    'docker network prune --force --filter label=mcp-firewall=1 --filter until=5m',
    'docker network create --internal --label mcp-firewall=1 mcp-fw-srv-abc123-net',
    'docker network connect mcp-fw-srv-abc123-net mcp-fw-srv-abc123-egress',
  ]);
  assert.throws(() => createEgressNetwork(e, recorder([{}, { status: 1, stderr: 'pool overlaps\n' }]).run), /cannot create network.*pool overlaps/);
  assert.throws(() => connectEgressProxy(e, recorder([{ status: 1, stderr: 'no such container' }]).run), /cannot attach the proxy/);
  // the network is still in use until Docker has removed the killed server container: retried, then given up quietly
  const busy = recorder([{}, { status: 1, stderr: 'has active endpoints' }, { status: 0 }]);
  removeEgress(e, busy.run, 'docker', () => {});
  assert.deepEqual(busy.calls, ['docker kill mcp-fw-srv-abc123-egress', 'docker network rm mcp-fw-srv-abc123-net', 'docker network rm mcp-fw-srv-abc123-net']);
  const never = recorder(Array(10).fill({ status: 1, stderr: 'has active endpoints' }));
  assert.doesNotThrow(() => removeEgress(e, never.run, 'docker', () => {}));
  assert.equal(never.calls.length, 7);
});

test('preflight checks the proxy image too; the fingerprint covers it', () => {
  const cfg = sandbox();
  assert.throws(() => preflight(cfg, recorder([{ status: 1, stderr: 'No such image' }]).run), /proxy image node:22-alpine is not present locally/);
  assert.equal(preflight(cfg, recorder([{ stdout: ID2 }, { stdout: ID }]).run), ID);
  assert.throws(() => preflight(cfg, recorder([{ status: 1, stderr: 'Cannot connect to the Docker daemon' }]).run), /start Docker Desktop/);
  // calls: server image, then proxy image
  const fp = (server: string, proxy: string) => sandboxFingerprint(cfg, undefined, recorder([{ stdout: server }, { stdout: proxy }]).run);
  const a = fp(ID, ID2);
  assert.equal(a.hash, fp(ID, ID2).hash);
  assert.notEqual(a.hash, fp(ID, ID).hash, 'a swapped proxy image is changed server code');
  assert.ok(a.packages.some((p) => /egress proxy image node:22-alpine \(2{12}\)/.test(p)));
  // a sandbox without egress keeps the fingerprint it had before egress existed
  const plain = sandbox({ egress: undefined });
  assert.equal(sandboxFingerprint(plain, undefined, recorder([{ stdout: ID }]).run).packages.length, 1);
  assert.throws(() => sandboxFingerprint(cfg, undefined, recorder([{ stdout: ID }, { status: 1, stderr: 'No such image' }]).run), /cannot identify egress proxy image/);
});
