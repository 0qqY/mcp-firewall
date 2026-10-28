import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuditEvent } from '../audit.js';
import type { Policy } from '../policy.js';

const UI_DIR = fileURLToPath(new URL('../../../ui/', import.meta.url));
const STATIC: Record<string, [file: string, type: string]> = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
};
const MAX_EVENTS = 5000;
const MAX_BODY = 4096;

export type Category = 'injection' | 'poisoning' | 'dlp' | 'rugpull' | 'policy' | 'method' | 'protocol' | 'other';
export type Review = 'true_positive' | 'false_positive';

export interface StoredEvent extends AuditEvent {
  /** Line index in the append-only audit file. */
  id: number;
  ts: string;
  server: string;
  category: Category;
}

interface LabelRecord {
  eventId: number;
  review: Review;
  reviewedAt: string;
  server?: string;
  tool?: string;
  category: Category;
  /** Present only when the event carried model-visible text; these rows are training data. */
  text?: string;
  label?: 0 | 1;
  source: 'audit_review';
}

export interface DashboardOptions {
  policy: Policy;
  auditFile: string;
  labelsFile: string;
  port: number;
}

/** Maps an audit reason to the threat category shown in the dashboard. */
export function categorize(e: AuditEvent): Category {
  const r = (e.reason ?? '').toLowerCase();
  if (r.includes('ml classifier')) return e.method === 'tools/list' ? 'poisoning' : 'injection';
  if (r.includes('tool poisoning')) return 'poisoning';
  if (r.includes('sensitive data')) return 'dlp';
  if (r.includes('rug pull')) return 'rugpull';
  if (r.includes("method '")) return 'method';
  if (r.includes('malformed') || r.includes('oversized') || r.includes('internal error')) return 'protocol';
  if (r.includes('denied') || r.includes('argument')) return 'policy';
  return 'other';
}

export function readAudit(file: string): StoredEvent[] {
  if (!existsSync(file)) return [];
  const events: StoredEvent[] = [];
  readFileSync(file, 'utf8')
    .split('\n')
    .forEach((line, id) => {
      if (!line.trim()) return;
      try {
        const e = JSON.parse(line);
        if (e && typeof e === 'object' && typeof e.verdict === 'string') events.push({ ...e, id, category: categorize(e) });
      } catch {
        // A torn final line while the firewall is writing; skip it.
      }
    });
  return events.slice(-MAX_EVENTS);
}

function readLabels(file: string): Map<number, LabelRecord> {
  const labels = new Map<number, LabelRecord>();
  if (!existsSync(file)) return labels;
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    try {
      const r = JSON.parse(line) as LabelRecord;
      if (typeof r.eventId === 'number') labels.set(r.eventId, r);
    } catch {
      // ignore blank or partial lines
    }
  }
  return labels;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(body));
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk: string) => {
      body += chunk;
      if (body.length > MAX_BODY) {
        reject(new Error('body too large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

/**
 * Local-only dashboard over the audit log. Audit text is attacker-controlled, so the server binds to
 * loopback, rejects foreign Host/Origin headers (DNS rebinding, CSRF) and serves a strict CSP.
 */
export function startDashboard(opts: DashboardOptions): Server {
  const { policy, auditFile, labelsFile, port } = opts;
  const origins = new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`]);
  const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);

  const config = {
    mode: policy.mode,
    auditFile,
    labelsFile,
    ml: { enabled: policy.ml.enabled, model: policy.ml.model.split(/[\\/]/).pop(), threshold: policy.ml.threshold, failMode: policy.ml.failMode },
    dlp: { enabled: policy.dlp.enabled, action: policy.dlp.action },
    pinning: policy.pinning.enabled,
  };

  const server = createServer(async (req, res) => {
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    if (!hosts.has(req.headers.host ?? '')) return json(res, 403, { error: 'forbidden host' });
    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);

    try {
      if (req.method === 'GET' && url.pathname === '/api/events') {
        const server = url.searchParams.get('server');
        const all = readAudit(auditFile);
        const events = server ? all.filter((e) => e.server === server) : all;
        const labels = Object.fromEntries([...readLabels(labelsFile)].map(([id, l]) => [id, l.review]));
        return json(res, 200, { config, servers: [...new Set(all.map((e) => e.server).filter(Boolean))].sort(), events, labels });
      }

      if (req.method === 'POST' && url.pathname === '/api/labels') {
        // Custom header + same-origin check: a cross-site page can do neither without a CORS preflight we never grant.
        if (req.headers['x-mcp-firewall'] !== '1' || (req.headers.origin && !origins.has(req.headers.origin))) {
          return json(res, 403, { error: 'forbidden' });
        }
        const { eventId, review } = JSON.parse(await readBody(req)) as { eventId: unknown; review: unknown };
        if (typeof eventId !== 'number' || (review !== 'true_positive' && review !== 'false_positive')) {
          return json(res, 400, { error: 'expected eventId and review' });
        }
        const event = readAudit(auditFile).find((e) => e.id === eventId);
        if (!event) return json(res, 404, { error: 'event not found' });
        const record: LabelRecord = {
          eventId,
          review,
          reviewedAt: new Date().toISOString(),
          server: event.server,
          tool: event.tool,
          category: event.category,
          source: 'audit_review',
          ...(event.excerpt ? { text: event.excerpt, label: review === 'true_positive' ? 1 : 0 } : {}),
        };
        mkdirSync(dirname(labelsFile), { recursive: true });
        appendFileSync(labelsFile, `${JSON.stringify(record)}\n`);
        return json(res, 200, { ok: true, trainable: record.text !== undefined });
      }

      if (req.method === 'GET' && url.pathname === '/api/labels.jsonl') {
        // Training rows only, in the format training/prepare_data.py --extra-train expects.
        const rows = [...readLabels(labelsFile).values()]
          .filter((l) => l.text !== undefined)
          .map((l) => JSON.stringify({ text: l.text, label: l.label, source: l.source }));
        res.writeHead(200, {
          'content-type': 'application/x-ndjson; charset=utf-8',
          'content-disposition': 'attachment; filename="mcp-firewall-labels.jsonl"',
        });
        return res.end(rows.length ? `${rows.join('\n')}\n` : '');
      }

      const asset = req.method === 'GET' ? STATIC[url.pathname] : undefined;
      if (asset) {
        res.writeHead(200, {
          'content-type': asset[1],
          'cache-control': 'no-cache',
          'content-security-policy': "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        });
        return res.end(readFileSync(join(UI_DIR, asset[0])));
      }
      json(res, 404, { error: 'not found' });
    } catch (err) {
      json(res, 400, { error: (err as Error).message });
    }
  });
  server.listen(port, '127.0.0.1');
  return server;
}
