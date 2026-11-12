// Agent Egress Bench MCP-case runner for Tuuf MCP Firewall (own code).
// Reads the benchmark's case JSON files as data only; nothing from that repository is executed.
//
// Contract followed (docs/RUNNER.md of the benchmark): a runner-owned upstream records what reaches it; an allow needs
// proof of delivery at that upstream, a block needs a structured deny signal. Cases run on the transport they declare:
//   mcp_stdio -> the firewall CLI in front of a stdio-to-TCP bridge that points at the runner's loopback listener
//   mcp_http  -> the firewall's HTTP gateway in front of the runner's HTTP upstream
// Each case gets a fresh firewall process, a fresh pin file and a unique MCP_FIREWALL_SESSION (taint state).
//
// usage: node run.mjs --aeb <benchmark checkout> --cli <dist/src/cli.js> --project <project dir> --profile <name>
//          --out <dir> [--transport stdio|http|all] [--filter <regex>] [--concurrency 2]
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const argv = process.argv.slice(2);
const opt = (name, def) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : def;
};
const AEB = opt('aeb');
const CLI = opt('cli');
const PROJECT = opt('project');
const PROFILE = opt('profile', 'defaults');
const OUT = path.resolve(opt('out', 'out'));
const TRANSPORT = opt('transport', 'all');
const FILTER = new RegExp(opt('filter', '.'));
const CONCURRENCY = Number(opt('concurrency', '2'));
const BRIDGE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'bridge.mjs');
const COLD_MS = 120_000; // the first scan waits for the classifier to load
const WARM_MS = 45_000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sortKeys = (v) =>
  Array.isArray(v) ? v.map(sortKeys) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])) : v;
const canon = (v) => JSON.stringify(sortKeys(v ?? null));
const idKey = (id) => JSON.stringify(id ?? null);
const isRequest = (m) => m && typeof m === 'object' && 'method' in m && m.id !== undefined;

// ---------------------------------------------------------------------------------------------------- cases
function loadCases() {
  const found = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.json') && !['before.json', 'after.json', 'expected.json'].includes(e.name)) {
        try {
          const c = JSON.parse(fs.readFileSync(p, 'utf8'));
          const it = c.input_type || '';
          if (it.startsWith('mcp_') || ['mcp_input', 'mcp_tool', 'mcp_chain'].includes(c.category)) found.push(c);
        } catch {
          /* not a case file */
        }
      }
    }
  };
  walk(path.join(AEB, 'cases'));
  return found.sort((a, b) => a.id.localeCompare(b.id));
}

// ---------------------------------------------------------------------------------------------------- policies
const HOME = os.homedir();
// AEB_MODEL: another model directory (absolute), to run the ML profiles with a candidate instead of the installed default.
const MODEL_DIR = (process.env.AEB_MODEL ?? path.join(HOME, '.mcp-firewall', 'models', 'mcp-pi-mmbert-mixraw-ab4-evilsandangels-30')).replace(/\\/g, '/');

// AEB_DEFINITION_MODEL: a second model directory (absolute) for the definition channel (ml.definitionModel), example-ml profiles only.
const DEFINITION_MODEL_DIR = process.env.AEB_DEFINITION_MODEL?.replace(/\\/g, '/');

function must(before, after, what) {
  if (before === after) throw new Error(`policy edit did not apply: ${what}`);
  return after;
}

/** Policy text for a profile. Relative audit/pin paths resolve to the per-case folder, so state never leaks between cases. */
function policyText(profile) {
  if (profile === 'defaults') return null; // no policy file: the built-in defaults
  if (profile === 'installed') {
    // The policy the user actually runs for filesystem/fetch/git/memory/playwright; only the model path is made absolute
    // and desktop notifications are turned off.
    let t = fs.readFileSync(path.join(HOME, '.mcp-firewall', 'policy-genel.yaml'), 'utf8');
    t = must(t, t.replace('model: ./models/mcp-pi-mmbert-mixraw-ab4-evilsandangels-30', `model: ${MODEL_DIR}`), 'model path');
    t = must(t, t.replace(/(notify:[^\n]*\n\s*enabled:\s*)true/, '$1false'), 'notify off');
    return t;
  }
  if (profile === 'example-ml' || profile === 'example-ml-block') {
    // policy.example.yaml as shipped, with the classifier switched on (it ships disabled); the -block variant also
    // makes the DLP act by blocking instead of redacting.
    let t = fs.readFileSync(path.join(PROJECT, 'policy.example.yaml'), 'utf8');
    t = must(t, t.replace(/(\nml:\r?\n\s*enabled:\s*)false/, '$1true'), 'ml on');
    t = must(t, t.replace(/(\n\s*model:\s*)\.\/models\/mcp-pi-mmbert-mixraw-ab4-evilsandangels-30/, `$1${MODEL_DIR}`), 'model path');
    if (DEFINITION_MODEL_DIR) t = must(t, t.replace(`model: ${MODEL_DIR}`, `model: ${MODEL_DIR}
  definitionModel: ${DEFINITION_MODEL_DIR}`), 'definition model');
    if (profile === 'example-ml-block') t = must(t, t.replace(/(\n\s*action:\s*)redact(\s+# redact \| block \| warn)/, '$1block$2'), 'dlp block');
    return t;
  }
  if (profile === 'probe-taint') {
    // Gap classification only (not a score): example-ml-block plus an env source and a session-mode network sink, to see
    // whether the chain misses are a configuration matter or a missing feature.
    let t = policyText('example-ml-block');
    t = must(t, t.replace(/(\n\s*- match: "get_file_contents"[^\n]*\r?\n)/, '$1    - match: "get_env"\n'), 'taint source');
    t = must(t, t.replace(/(\n\s*- match: "post_message"[^\n]*\r?\n)/, '$1    - match: "fetch"\n      when: session\n'), 'taint sink');
    return t;
  }
  throw new Error(`unknown profile ${profile}`);
}

// ---------------------------------------------------------------------------------------------------- upstream fixture
/** The runner-owned upstream: records every message it receives and answers from the case. */
function makeUpstream(c) {
  const msgs = c.payload.jsonrpc_messages;
  const resp = msgs.find((m) => !('method' in m));
  const type = c.input_type;
  const received = [];
  const reply = (id, body) => ({ jsonrpc: '2.0', id, ...body });
  const caseBody = () => (resp.error !== undefined ? { error: resp.error } : { result: resp.result });
  function handle(msg) {
    received.push(msg);
    if (!isRequest(msg)) return undefined;
    switch (msg.method) {
      case 'initialize':
        if (type === 'mcp_initialize_response' && resp) return reply(msg.id, caseBody());
        return reply(msg.id, { result: { protocolVersion: msg.params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'aeb-fixture', version: '1.0.0' } } });
      case 'tools/list':
        if (type === 'mcp_tool_definition' && resp) return reply(msg.id, caseBody());
        return reply(msg.id, { result: { tools: [] } });
      case 'tools/call':
        if (type === 'mcp_tool_result' && resp) return reply(msg.id, caseBody());
        return reply(msg.id, { result: { content: [{ type: 'text', text: 'ok' }] } });
      case 'ping':
        return reply(msg.id, { result: {} });
      default:
        return reply(msg.id, { error: { code: -32601, message: 'Method not found' } });
    }
  }
  return { handle, received };
}

function startTcpFixture(up) {
  return new Promise((resolve) => {
    const sockets = new Set();
    const server = net.createServer((sock) => {
      sockets.add(sock);
      sock.setEncoding('utf8');
      let buf = '';
      sock.on('data', (d) => {
        buf += d;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i);
          buf = buf.slice(i + 1);
          if (!line.trim()) continue;
          let m;
          try {
            m = JSON.parse(line);
          } catch {
            continue;
          }
          const r = up.handle(m);
          if (r) sock.write(`${JSON.stringify(r)}\n`);
        }
      });
      sock.on('error', () => {});
    });
    server.listen(0, '127.0.0.1', () =>
      resolve({
        addr: `127.0.0.1:${server.address().port}`,
        close: () => {
          for (const s of sockets) s.destroy();
          server.close();
        },
      }),
    );
  });
}

function startHttpFixture(up) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      let body = '';
      req.on('data', (d) => (body += d));
      req.on('end', () => {
        if (req.method !== 'POST') return void res.writeHead(405).end();
        let j;
        try {
          j = JSON.parse(body);
        } catch {
          return void res.writeHead(400).end();
        }
        const list = Array.isArray(j) ? j : [j];
        const replies = list.map((m) => up.handle(m)).filter(Boolean);
        if (replies.length === 0) return void res.writeHead(202).end();
        const hdr = { 'content-type': 'application/json' };
        if (list.some((m) => m.method === 'initialize')) hdr['mcp-session-id'] = 'aeb-fixture-session';
        res.writeHead(200, hdr).end(JSON.stringify(Array.isArray(j) ? replies : replies[0]));
      });
    });
    srv.listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${srv.address().port}/mcp`, close: () => srv.close() }));
  });
}

// ---------------------------------------------------------------------------------------------------- clients
function stdioClient(child) {
  const recv = [];
  let buf = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      try {
        recv.push(JSON.parse(line));
      } catch {
        recv.push({ _raw: line });
      }
    }
  });
  return {
    recv,
    async request(msg, ms) {
      const from = recv.length;
      child.stdin.write(`${JSON.stringify(msg)}\n`);
      const t0 = Date.now();
      while (Date.now() - t0 < ms) {
        const r = recv.slice(from).find((m) => !('method' in m) && idKey(m.id) === idKey(msg.id));
        if (r) return r;
        if (child.exitCode !== null) return undefined;
        await sleep(20);
      }
      return undefined;
    },
    async notify(msg) {
      child.stdin.write(`${JSON.stringify(msg)}\n`);
      await sleep(60);
    },
  };
}

function httpClient(url) {
  const recv = [];
  let session;
  async function post(msg, ms) {
    const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-06-18' };
    if (session) headers['mcp-session-id'] = session;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), ms);
    try {
      const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(msg), signal: ctl.signal });
      const sid = res.headers.get('mcp-session-id');
      if (sid) session = sid;
      const text = await res.text();
      const msgs = [];
      if ((res.headers.get('content-type') || '').includes('text/event-stream')) {
        for (const block of text.split(/\r?\n\r?\n/)) {
          const data = block.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trimStart()).join('\n');
          if (data) {
            try {
              msgs.push(JSON.parse(data));
            } catch {
              /* ignore */
            }
          }
        }
      } else if (text.trim()) {
        try {
          const j = JSON.parse(text);
          if (Array.isArray(j)) msgs.push(...j);
          else msgs.push(j);
        } catch {
          msgs.push({ _raw: text.slice(0, 300), _status: res.status });
        }
      }
      recv.push(...msgs);
      return { status: res.status, msgs };
    } catch (err) {
      return { status: 0, msgs: [], error: String(err) };
    } finally {
      clearTimeout(timer);
    }
  }
  return {
    recv,
    async request(msg, ms) {
      const r = await post(msg, ms);
      return r.msgs.find((m) => !('method' in m) && idKey(m.id) === idKey(msg.id));
    },
    async notify(msg) {
      await post(msg, 15_000);
    },
  };
}

// ---------------------------------------------------------------------------------------------------- verdicts
/** A structured, attributable deny: this firewall's JSON-RPC error, or its tool-error result (isError: true). */
function isDeny(m) {
  if (!m || typeof m !== 'object') return false;
  if (m.error && /Tuuf MCP Firewall/.test(String(m.error.message ?? ''))) return true;
  return Boolean(m.result && m.result.isError === true && /\[Tuuf MCP Firewall\] Blocked/.test(JSON.stringify(m.result.content ?? '')));
}
const denyReason = (m) => String(m?.error?.message ?? m?.result?.content?.[0]?.text ?? '').slice(0, 300);

function judgeResponse(method, r, resp) {
  if (!r) return { actual: 'error', detail: 'no response from the firewall within the time limit' };
  if (isDeny(r)) return { actual: 'block', detail: denyReason(r) };
  if (r.error && !isDeny(r)) return { actual: 'error', detail: `unattributed error: ${JSON.stringify(r.error).slice(0, 200)}` };
  const sent = resp.error !== undefined ? { error: resp.error } : { result: resp.result };
  const got = r.error !== undefined ? { error: r.error } : { result: r.result };
  if (canon(sent) === canon(got)) return { actual: 'allow' };
  if (method === 'tools/list') {
    const names = (x) => (x?.result?.tools ?? []).map((t) => t?.name);
    const have = names(r);
    const missing = names(resp).filter((n) => !have.includes(n));
    if (missing.length > 0) return { actual: 'block', detail: `definition withheld (hidden from tools/list): ${missing.join(', ') || '(unnamed)'}`, withheld: true };
  }
  return { actual: 'modified', detail: 'forwarded with changes' };
}

async function script(c, T, up) {
  const type = c.input_type;
  const msgs = c.payload.jsonrpc_messages;
  const resp = msgs.find((m) => !('method' in m));
  const reqs = msgs.filter((m) => 'method' in m);
  const handshake = async () => {
    const r = await T.request({ jsonrpc: '2.0', id: 'aeb-init', method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'aeb-runner', version: '1.0.0' } } }, COLD_MS);
    if (!r) throw new Error('handshake: no response');
    if (isDeny(r)) throw new Error(`handshake denied: ${denyReason(r)}`);
    await T.notify({ jsonrpc: '2.0', method: 'notifications/initialized' });
  };

  if (type === 'mcp_initialize_response') {
    const init = reqs[0];
    return judgeResponse('initialize', await T.request(init, COLD_MS), resp);
  }
  await handshake();
  if (type === 'mcp_tool_definition') return judgeResponse('tools/list', await T.request({ jsonrpc: '2.0', id: resp.id, method: 'tools/list' }, COLD_MS), resp);
  if (type === 'mcp_tool_result') {
    return judgeResponse('tools/call', await T.request({ jsonrpc: '2.0', id: resp.id, method: 'tools/call', params: { name: 'aeb_tool', arguments: {} } }, COLD_MS), resp);
  }

  // request / sequence cases: allow = every request reached the runner-owned upstream unchanged
  const steps = [];
  for (const [i, m] of reqs.entries()) {
    const before = up.received.length;
    const r = await T.request(m, i === 0 ? COLD_MS : WARM_MS);
    const got = up.received.slice(before).find((x) => x.method === m.method && idKey(x.id) === idKey(m.id));
    if (r && isDeny(r)) steps.push({ id: m.id, actual: 'block', detail: denyReason(r) });
    else if (got) steps.push(canon(got.params) === canon(m.params) ? { id: m.id, actual: 'allow' } : { id: m.id, actual: 'modified', detail: 'forwarded with changes', forwarded: got.params });
    else steps.push({ id: m.id, actual: 'error', detail: r ? 'neither a deny nor an upstream receipt' : 'no response and not delivered' });
  }
  const blocked = steps.find((s) => s.actual === 'block');
  const actual = blocked ? 'block' : steps.some((s) => s.actual === 'error') ? 'error' : steps.some((s) => s.actual === 'modified') ? 'modified' : 'allow';
  return { actual, detail: (blocked ?? steps.find((s) => s.actual !== 'allow'))?.detail, steps, firstBlockId: blocked?.id };
}

function scoreOf(c, res) {
  if (res.actual === 'error') return { strict: 'error', lenient: 'error' };
  const exp = c.expected_verdict === 'warn' ? 'allow' : c.expected_verdict;
  let strict = res.actual === exp ? 'pass' : 'fail';
  if (exp === 'block' && c.payload.over_budget_call_id !== undefined) strict = res.firstBlockId === c.payload.over_budget_call_id ? 'pass' : 'fail';
  const lenient = res.actual === 'modified' ? 'pass' : strict;
  return { strict, lenient };
}

// ---------------------------------------------------------------------------------------------------- one case
function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

function auditNotes(dir) {
  const out = [];
  const files = [dir, path.join(dir, '.mcp-firewall')].flatMap((d) => (fs.existsSync(d) ? fs.readdirSync(d).filter((f) => f.endsWith('.jsonl')).map((f) => path.join(d, f)) : []));
  for (const file of files) {
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const e = JSON.parse(line);
        if (e.verdict && e.verdict !== 'allow' && e.verdict !== 'info') out.push(`${e.verdict}: ${String(e.reason ?? '').slice(0, 160)}`);
      } catch {
        /* skip */
      }
    }
  }
  return [...new Set(out)].slice(0, 6);
}

async function runCase(c) {
  const t0 = Date.now();
  const dir = path.join(OUT, c.id);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const text = policyText(PROFILE);
  let policyPath;
  if (text) {
    policyPath = path.join(dir, 'policy.yaml');
    fs.writeFileSync(policyPath, text);
  }
  const up = makeUpstream(c);
  const isHttp = c.transport === 'mcp_http';
  // Home is the case folder: whatever the firewall keeps under ~ by default (audit log, pin store, shared taint state)
  // lands here and never in the real ~/.mcp-firewall.
  const env = { ...process.env, MCP_FIREWALL_SESSION: `aeb-${crypto.randomBytes(6).toString('hex')}`, USERPROFILE: dir, HOME: dir };
  const policyArgs = policyPath ? ['--policy', policyPath] : [];
  let fixture;
  let child;
  let T;
  let stderr = '';
  let res;
  try {
    if (!isHttp) {
      fixture = await startTcpFixture(up);
      child = spawn(process.execPath, [CLI, ...policyArgs, '--name', 'aeb', '--', process.execPath, BRIDGE, fixture.addr], { cwd: dir, env, stdio: ['pipe', 'pipe', 'pipe'] });
      child.stderr.on('data', (d) => (stderr += d));
      T = stdioClient(child);
    } else {
      fixture = await startHttpFixture(up);
      const port = await freePort();
      child = spawn(process.execPath, [CLI, 'gateway', '--upstream', fixture.url, ...policyArgs, '--name', 'aeb', '--listen', `127.0.0.1:${port}`], { cwd: dir, env, stdio: ['ignore', 'pipe', 'pipe'] });
      child.stderr.on('data', (d) => (stderr += d));
      child.stdout.on('data', () => {});
      const t1 = Date.now();
      while (!/gateway: http/.test(stderr) && Date.now() - t1 < 60_000 && child.exitCode === null) await sleep(50);
      if (!/gateway: http/.test(stderr)) throw new Error(`gateway did not start: ${stderr.slice(-300)}`);
      T = httpClient(`http://127.0.0.1:${port}/mcp`);
    }
    res = await script(c, T, up);
  } catch (err) {
    res = { actual: 'error', detail: String(err.message ?? err).slice(0, 300) };
  } finally {
    try {
      if (!isHttp) child?.stdin.end();
    } catch {
      /* ignore */
    }
    await sleep(isHttp ? 200 : 600);
    try {
      child?.kill();
    } catch {
      /* ignore */
    }
    fixture?.close();
  }
  const { strict, lenient } = scoreOf(c, res);
  const row = {
    profile: PROFILE, case_id: c.id, category: c.category, input_type: c.input_type, transport: c.transport,
    expected: c.expected_verdict, actual: res.actual, score: strict, lenient, detail: res.detail,
    steps: res.steps, audit: auditNotes(dir), ms: Date.now() - t0,
  };
  fs.writeFileSync(path.join(dir, 'trace.json'), JSON.stringify({ row, upstream_received: up.received, client_received: T?.recv, stderr: stderr.slice(-2000) }, null, 1));
  return row;
}

// ---------------------------------------------------------------------------------------------------- main
function summarize(rows) {
  const pct = (a, b) => (b ? `${((100 * a) / b).toFixed(0)}%` : '-');
  const groups = new Map();
  for (const r of rows) {
    const k = `${r.category}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(r);
  }
  const line = (name, rs) => {
    const blk = rs.filter((r) => r.expected === 'block');
    const alw = rs.filter((r) => r.expected !== 'block');
    const det = blk.filter((r) => r.score === 'pass').length;
    const detL = blk.filter((r) => r.lenient === 'pass').length;
    const ok = alw.filter((r) => r.score === 'pass').length;
    const fp = alw.filter((r) => r.actual === 'block').length;
    const alt = alw.filter((r) => r.actual === 'modified').length;
    const mod = blk.filter((r) => r.actual === 'modified').length;
    const err = rs.filter((r) => r.score === 'error').length;
    return `| ${name} | ${rs.length} | ${blk.length} | ${det} (${pct(det, blk.length)}) | ${mod} | ${detL} (${pct(detL, blk.length)}) | ${alw.length} | ${ok} (${pct(ok, alw.length)}) | ${fp} | ${alt} | ${err} |`;
  };
  const out = [`profile: ${PROFILE}`, '', '| category | n | block exp. | detected (strict) | modified | detected (lenient) | allow exp. | allowed | false block | altered | error |', '|---|---|---|---|---|---|---|---|---|---|---|'];
  for (const [k, rs] of [...groups].sort()) out.push(line(k, rs));
  out.push(line('**all**', rows));
  return out.join('\n');
}

/** Number of lines this runner's server name ("aeb") has in the user's real audit log; must not grow during a run. */
function realAuditAebLines() {
  try {
    return fs.readFileSync(path.join(HOME, '.mcp-firewall', 'mcp-firewall-audit.jsonl'), 'utf8').split('\n').filter((l) => l.includes('"server":"aeb"')).length;
  } catch {
    return 0;
  }
}

async function main() {
  const aebBefore = realAuditAebLines();
  fs.mkdirSync(OUT, { recursive: true });
  let cases = loadCases().filter((c) => FILTER.test(c.id));
  if (TRANSPORT !== 'all') cases = cases.filter((c) => c.transport === `mcp_${TRANSPORT}`);
  console.error(`profile ${PROFILE}: ${cases.length} cases (${cases.filter((c) => c.transport === 'mcp_stdio').length} stdio, ${cases.filter((c) => c.transport === 'mcp_http').length} http), concurrency ${CONCURRENCY}`);
  const rows = [];
  const queue = [...cases];
  const resultsFile = path.join(OUT, 'results.jsonl');
  fs.writeFileSync(resultsFile, '');
  const worker = async () => {
    for (let c = queue.shift(); c; c = queue.shift()) {
      const row = await runCase(c);
      rows.push(row);
      fs.appendFileSync(resultsFile, `${JSON.stringify(row)}\n`);
      console.error(`${row.score.toUpperCase().padEnd(5)} ${row.case_id} ${row.expected}->${row.actual} ${row.ms}ms${row.detail ? ` | ${String(row.detail).slice(0, 110)}` : ''}`);
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  rows.sort((a, b) => a.case_id.localeCompare(b.case_id));
  const md = summarize(rows);
  fs.writeFileSync(path.join(OUT, 'summary.md'), `${md}\n`);
  console.log(md);
  const aebAfter = realAuditAebLines();
  if (aebAfter !== aebBefore) {
    console.error(`WARNING: the real audit log gained ${aebAfter - aebBefore} "aeb" lines during this run; state isolation failed`);
    process.exitCode = 3;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
