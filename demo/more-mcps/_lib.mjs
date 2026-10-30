// Shared harness for the "more MCPs" firewall demos. Each mock server (gh/shell/mail/docs/plug) is a tiny local
// stdio MCP; this drives it behind the real firewall (dist/src/cli.js) with a per-demo policy, then reports the
// verdicts. Generated files are written next to each driver as run-* (gitignored). Needs a built dist; demos that
// use ML also need a local model (MCP_FIREWALL_MODEL overrides; default ./models/... at the repo root).
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const libDir = dirname(fileURLToPath(import.meta.url));
export const REPO = resolve(libDir, '..', '..');
const CLI = join(REPO, 'dist', 'src', 'cli.js');
export const MODEL = process.env.MCP_FIREWALL_MODEL ?? join(REPO, 'models', 'mcp-pi-mmbert-soup04-ab4');
if (!existsSync(CLI)) throw new Error(`build first (npm run build): ${CLI} is missing`);

export function writePolicy(dir, name, lines) {
  const policy = join(dir, `run-${name}-policy.yaml`);
  const audit = join(dir, `run-${name}-audit.jsonl`);
  if (existsSync(audit)) rmSync(audit);
  writeFileSync(policy, ['version: 1', 'mode: enforce', `audit: { file: ${JSON.stringify(audit)}, logAllowed: true }`, ...lines, ''].join('\n'));
  return { policy, audit };
}

// Drives one firewall+server session. `steps` are JSON-RPC messages (no jsonrpc field). Returns { byId }.
export function runFirewall({ name, server, policy, steps, env = {} }) {
  return new Promise((resolve) => {
    const child = spawn('node', [CLI, '--policy', policy, '--name', name, '--', 'node', server],
      { stdio: ['pipe', 'pipe', 'inherit'], cwd: tmpdir(), env: { ...process.env, NODE_NO_WARNINGS: '1', ...env } });
    const byId = {};
    let step = 0;
    const next = () => {
      if (step === steps.length) { child.stdin.end(); return; }
      const s = steps[step++];
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...s })}\n`);
      if (s.id === undefined) next();
    };
    const timer = setTimeout(() => { console.log(`${name}: TIMEOUT`); child.kill(); }, 120_000);
    let buf = '';
    child.stdout.on('data', (d) => {
      buf += d;
      for (let i; (i = buf.indexOf('\n')) >= 0; ) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        if (!line) continue;
        let msg; try { msg = JSON.parse(line); } catch { continue; }
        if (msg.id !== undefined) { byId[msg.id] = msg; next(); }
      }
    });
    child.on('exit', () => { clearTimeout(timer); resolve({ byId }); });
    next();
  });
}

export function readAudit(audit) {
  return existsSync(audit) ? readFileSync(audit, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
}

// Verdict of a tools/call response: blocked (error), masked (redacted), or passed.
export function verdict(msg) {
  const text = msg?.result?.content?.[0]?.text ?? JSON.stringify(msg?.error ?? '');
  if (msg?.result?.isError || msg?.error) return 'ENGELLENDİ';
  if (/\[REDACTED:/.test(String(text))) return 'MASKELENDİ';
  return 'geçti';
}

export function table(rows) {
  const w0 = Math.max(...rows.map((r) => r[0].length), 4);
  const w1 = Math.max(...rows.map((r) => r[1].length), 6);
  for (const [a, b, c] of rows) console.log(a.padEnd(w0 + 2) + b.padEnd(w1 + 2) + c);
}

export function printAudit(audit) {
  console.log('\nDenetim (allow hariç):');
  for (const e of readAudit(audit)) {
    if (e.verdict !== 'allow') {
      console.log(`  ${(e.verdict ?? '').padEnd(7)}${e.score !== undefined ? `score=${e.score.toFixed(3)} ` : ''}${e.tool ? `[${e.tool}] ` : ''}${e.reason ?? ''}`.slice(0, 150));
    }
  }
}
