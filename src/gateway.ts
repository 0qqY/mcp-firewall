import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { PassThrough } from 'node:stream';
import type { AuditLog } from './audit.js';
import {
  idKey,
  isObject,
  isRequest,
  isResponse,
  MAX_LINE_LENGTH,
  onLines,
  parseMessage,
  send,
  type JsonRpcMessage,
} from './jsonrpc.js';
import type { Classifier } from './ml/classifier.js';
import type { PinStore } from './pinning.js';
import type { Policy } from './policy.js';
import { FirewallProxy, type ProxyStreams } from './proxy.js';
import { TaintTracker } from './taint.js';

export interface GatewayOptions {
  policy: Policy;
  audit: AuditLog;
  pins?: PinStore;
  /** The remote MCP server's Streamable HTTP endpoint. */
  upstream: URL;
  /** Sent with every upstream request (credentials for the remote server). */
  headers: Record<string, string>;
  /** Pass the client's own Authorization header upstream when no static one is set. */
  forwardAuthorization: boolean;
  /** Path the gateway serves MCP on. */
  path: string;
  /** Browser origins allowed besides localhost; any other Origin is refused (DNS rebinding). */
  allowedOrigins: string[];
  serverId: string;
  classifier?: () => Promise<Classifier>;
  /** Replaces fetch in tests. */
  fetch?: typeof fetch;
}

const LOCAL_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i;

/** An open client response carrying SSE events: a POST waiting for its responses, or the GET stream. */
class EventSink {
  /** Request ids whose responses still have to go out on this stream. */
  readonly ids = new Set<string>();
  closed = false;

  constructor(readonly res: ServerResponse) {
    res.on('close', () => (this.closed = true));
  }

  write(msg: JsonRpcMessage): void {
    if (!this.closed) this.res.write(`event: message\ndata: ${JSON.stringify(msg)}\n\n`);
  }

  end(): void {
    if (!this.closed) this.res.end();
    this.closed = true;
  }
}

/**
 * One client session: its own FirewallProxy between in-memory line streams, so every policy check
 * of the stdio proxy applies unchanged; the gateway only translates HTTP on both sides.
 */
class Session {
  readonly io: ProxyStreams & { clientIn: PassThrough; clientOut: PassThrough; serverIn: PassThrough; serverOut: PassThrough };
  upstreamSession?: string;
  protocolVersion?: string;
  authorization?: string;
  /** Client request id → the POST stream its response must go out on. */
  readonly waiting = new Map<string, EventSink>();
  readonly posts = new Set<EventSink>();
  getSink?: EventSink;
  /** Server-initiated messages with no open stream to carry them yet. */
  readonly backlog: JsonRpcMessage[] = [];
  upstreamGet?: AbortController;

  constructor(
    readonly id: string,
    private readonly gw: Gateway,
  ) {
    this.io = { clientIn: new PassThrough(), clientOut: new PassThrough(), serverIn: new PassThrough(), serverOut: new PassThrough() };
    const { policy, audit, pins, classifier } = gw.options;
    const proxy = new FirewallProxy(policy, audit, pins, this.io, classifier);
    // Each session is one client; MCP_FIREWALL_SESSION ties it to the client's stdio firewalls.
    if (proxy.taint && policy.taint.scope === 'shared' && process.env.MCP_FIREWALL_SESSION) {
      proxy.taint = new TaintTracker(policy.taint, gw.options.serverId, TaintTracker.sessionKey());
    }
    proxy.start();
    onLines(this.io.clientOut, (line) => {
      for (const msg of parseMessage(line) ?? []) this.toClient(msg);
    });
    onLines(this.io.serverIn, (line) => {
      for (const msg of parseMessage(line) ?? []) void gw.toUpstream(this, msg);
    });
  }

  /** Routes what the firewall lets through to the client stream that is waiting for it. */
  private toClient(msg: JsonRpcMessage): void {
    if (isResponse(msg)) {
      const key = idKey(msg.id);
      const sink = this.waiting.get(key);
      this.waiting.delete(key);
      if (!sink) return;
      sink.write(msg);
      sink.ids.delete(key);
      if (sink.ids.size === 0) {
        sink.end();
        this.posts.delete(sink);
      }
      return;
    }
    // Server requests and notifications, and the firewall's own approval prompts: the newest open POST
    // stream (most likely the call they belong to), else the GET stream, else held until one opens.
    const open = [...this.posts].filter((s) => !s.closed);
    const sink = open[open.length - 1] ?? (this.getSink && !this.getSink.closed ? this.getSink : undefined);
    if (sink) sink.write(msg);
    else this.backlog.push(msg);
  }

  fromServer(msg: JsonRpcMessage): void {
    send(this.io.serverOut, msg);
  }

  close(): void {
    this.upstreamGet?.abort();
    for (const sink of [...this.posts, this.getSink]) sink?.end();
    for (const s of Object.values(this.io)) s.end();
  }
}

export class Gateway {
  private readonly sessions = new Map<string, Session>();
  private readonly fetch: typeof fetch;
  readonly server: Server;

  constructor(readonly options: GatewayOptions) {
    this.fetch = options.fetch ?? fetch;
    this.server = createServer((req, res) => {
      this.handle(req, res).catch((err: Error) => {
        options.audit.record({ verdict: 'warn', reason: `gateway error: ${err.message}` });
        if (!res.headersSent) res.writeHead(500).end();
        else res.end();
      });
    });
  }

  close(): void {
    for (const s of this.sessions.values()) s.close();
    this.sessions.clear();
    this.server.close();
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname !== this.options.path) return void res.writeHead(404).end();
    // A web page the user visits can reach a localhost port; only local or allowed origins may talk to MCP.
    const origin = req.headers.origin;
    if (origin && !LOCAL_ORIGIN.test(origin) && !this.options.allowedOrigins.includes(origin)) {
      this.options.audit.record({ verdict: 'block', reason: `gateway: request from origin ${origin} refused` });
      return void res.writeHead(403).end();
    }

    if (req.method === 'POST') return this.post(req, res);
    if (req.method === 'GET') return this.get(req, res);
    if (req.method === 'DELETE') return this.remove(req, res);
    res.writeHead(405, { Allow: 'GET, POST, DELETE' }).end();
  }

  private session(req: IncomingMessage, res: ServerResponse, create: boolean): Session | undefined {
    const id = req.headers['mcp-session-id'];
    if (typeof id === 'string') {
      const found = this.sessions.get(id);
      if (!found) res.writeHead(404).end();
      return found;
    }
    // A new client session on initialize; clients that never get a session id share one.
    const sid = create ? randomUUID() : 'stateless';
    let session = this.sessions.get(sid);
    if (!session) this.sessions.set(sid, (session = new Session(sid, this)));
    return session;
  }

  private remember(session: Session, req: IncomingMessage): void {
    const version = req.headers['mcp-protocol-version'];
    if (typeof version === 'string') session.protocolVersion = version;
    if (this.options.forwardAuthorization && typeof req.headers.authorization === 'string') session.authorization = req.headers.authorization;
  }

  private async post(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    const messages = body === undefined ? undefined : parseMessage(body);
    if (!messages) {
      return void res
        .writeHead(400, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
    }
    const opening = messages.some((m) => m.method === 'initialize');
    const session = this.session(req, res, opening);
    if (!session) return;
    this.remember(session, req);

    const requests = messages.filter(isRequest);
    const headers: Record<string, string> = { 'Mcp-Session-Id': session.id };
    if (requests.length === 0) {
      res.writeHead(202, headers).end();
    } else {
      res.writeHead(200, { ...headers, 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
      res.flushHeaders();
      const sink = new EventSink(res);
      for (const r of requests) {
        sink.ids.add(idKey(r.id));
        session.waiting.set(idKey(r.id), sink);
      }
      session.posts.add(sink);
      res.on('close', () => session.posts.delete(sink));
      for (const msg of session.backlog.splice(0)) sink.write(msg);
    }
    for (const msg of messages) send(session.io.clientIn, msg);
  }

  /** The client's stream for server-initiated messages, backed by the remote server's own GET stream. */
  private async get(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!String(req.headers.accept ?? '').includes('text/event-stream')) return void res.writeHead(406).end();
    const session = this.session(req, res, false);
    if (!session) return;
    this.remember(session, req);
    res.writeHead(200, { 'Mcp-Session-Id': session.id, 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.flushHeaders();
    session.getSink?.end();
    const sink = (session.getSink = new EventSink(res));
    for (const msg of session.backlog.splice(0)) sink.write(msg);

    session.upstreamGet?.abort();
    const abort = (session.upstreamGet = new AbortController());
    res.on('close', () => abort.abort());
    try {
      const upstream = await this.fetch(this.options.upstream, {
        method: 'GET',
        headers: this.upstreamHeaders(session, 'text/event-stream'),
        signal: abort.signal,
      });
      // 405: the remote server has no GET stream; this one still carries the firewall's own prompts.
      if (upstream.ok && upstream.body) await readEvents(upstream, (msg) => session.fromServer(msg));
    } catch (err) {
      if (!abort.signal.aborted) this.options.audit.record({ verdict: 'warn', reason: `gateway: upstream GET stream failed: ${(err as Error).message}` });
    }
  }

  private async remove(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const session = this.session(req, res, false);
    if (!session) return;
    this.sessions.delete(session.id);
    session.close();
    if (session.upstreamSession) {
      await this.fetch(this.options.upstream, { method: 'DELETE', headers: this.upstreamHeaders(session) }).catch(() => undefined);
    }
    res.writeHead(200).end();
  }

  private upstreamHeaders(session: Session, accept = 'application/json, text/event-stream'): Record<string, string> {
    const headers: Record<string, string> = { Accept: accept };
    if (session.upstreamSession) headers['Mcp-Session-Id'] = session.upstreamSession;
    if (session.protocolVersion) headers['MCP-Protocol-Version'] = session.protocolVersion;
    if (session.authorization) headers.Authorization = session.authorization;
    // Static headers win: a configured credential is never replaced by whatever the client sent.
    return { ...headers, ...this.options.headers };
  }

  /** Sends one message the firewall let through to the remote server and feeds what comes back into the firewall. */
  async toUpstream(session: Session, msg: JsonRpcMessage): Promise<void> {
    const fail = (reason: string) => {
      this.options.audit.record({ direction: 'client->server', method: msg.method, verdict: 'warn', reason: `gateway: ${reason}` });
      if (isRequest(msg)) session.fromServer({ jsonrpc: '2.0', id: msg.id, error: { code: -32603, message: `MCP Firewall gateway: ${reason}` } });
    };
    let res: Response;
    try {
      res = await this.fetch(this.options.upstream, {
        method: 'POST',
        headers: { ...this.upstreamHeaders(session), 'Content-Type': 'application/json' },
        body: JSON.stringify(msg),
      });
    } catch (err) {
      return fail(`remote server unreachable: ${(err as Error).message}`);
    }
    const sid = res.headers.get('mcp-session-id');
    if (sid) session.upstreamSession = sid;
    if (!res.ok) {
      await res.body?.cancel();
      const auth = res.status === 401 || res.status === 403 ? ' (set credentials with --header)' : '';
      return fail(`remote server answered HTTP ${res.status}${auth}`);
    }
    const type = res.headers.get('content-type') ?? '';
    if (type.includes('text/event-stream')) return readEvents(res, (m) => session.fromServer(m));
    const text = await res.text();
    if (!text.trim()) return;
    const messages = parseMessage(text);
    if (!messages) return fail('remote server sent a malformed response');
    for (const m of messages) session.fromServer(m);
  }
}

/** Reads a request body, refusing anything over the stdio line limit. */
function readBody(req: IncomingMessage): Promise<string | undefined> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_LINE_LENGTH) {
        req.destroy();
        resolve(undefined);
      } else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/** Parses an SSE body into JSON-RPC messages (`data:` lines of each event, joined). */
async function readEvents(res: Response, onMessage: (msg: JsonRpcMessage) => void): Promise<void> {
  const decoder = new TextDecoder();
  let buffer = '';
  let data: string[] = [];
  const dispatch = () => {
    if (data.length === 0) return;
    const parsed = parseMessage(data.join('\n'));
    data = [];
    for (const m of parsed ?? []) if (isObject(m)) onMessage(m);
  };
  for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
    buffer += decoder.decode(chunk, { stream: true });
    if (buffer.length > MAX_LINE_LENGTH) throw new Error('oversized SSE event');
    let nl: number;
    while ((nl = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, nl).replace(/\r$/, '');
      buffer = buffer.slice(nl + 1);
      if (line === '') dispatch();
      else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
    }
  }
  dispatch();
}
