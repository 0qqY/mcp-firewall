import { randomUUID } from 'node:crypto';
import type { Readable, Writable } from 'node:stream';
import type { AuditEvent, AuditLog } from './audit.js';
import type { CodeFingerprint } from './codepin.js';
import { decodeEmbedded, stripImageData, withDecoded } from './decode.js';
import { deepScan, formatFindings, REDACTION_MARKER, unredactableFindings } from './dlp.js';
import {
  evaluateMethod,
  evaluateToolCall,
  evaluateToolName,
  hasHiddenChars,
  parameterNamesText,
  scanText,
  scanToolDefinition,
  stripHiddenChars,
} from './engine.js';
import {
  errorResponse,
  idKey,
  isObject,
  isRequest,
  isResponse,
  onLines,
  parseMessage,
  send,
  toolErrorResponse,
  type JsonObject,
  type JsonRpcMessage,
} from './jsonrpc.js';
import { extractMlText, extractText, scoreTexts, type Channel, type Classifier } from './ml/classifier.js';
import { hashPromptTemplate, promptPinKey, type PinStatus, type PinStore } from './pinning.js';
import type { Policy } from './policy.js';
import { TaintTracker } from './taint.js';

/** Response types whose payload reaches the model and is therefore scanned. */
const SCANNED_RESULTS = new Set(['tools/call', 'resources/read', 'prompts/get']);

/** List responses whose entries (name, description, schema) the model reads, keyed to the array that holds them. */
const DEFINITION_LISTS: Record<string, string> = {
  'prompts/list': 'prompts',
  'resources/list': 'resources',
  'resources/templates/list': 'resourceTemplates',
};

/** Server-initiated requests that put server-written text in front of the model or the user. */
const SERVER_PROMPTS = new Set(['sampling/createMessage', 'elicitation/create']);

/**
 * Responses that open a session and carry the server's instructions: `initialize`, and `server/discover`
 * from protocol 2026-07-28 on, which a client may send instead of initialize or besides it.
 */
const HANDSHAKES = new Set(['initialize', 'server/discover']);

export interface ProxyStreams {
  clientIn: Readable;
  clientOut: Writable;
  serverIn: Writable;
  serverOut: Readable;
}

type Direction = 'client->server' | 'server->client';
type Context = Omit<AuditEvent, 'verdict' | 'reason'>;

/** Prefix of the ids of the firewall's own elicitation requests, so the client's answers are not forwarded. */
const APPROVAL_ID = 'mcp-firewall-approval-';
/** Characters of each argument value shown in an approval prompt, and how many arguments are listed. */
const APPROVAL_VALUE_CHARS = 200;
const APPROVAL_MAX_ARGS = 25;

/** A client request awaiting its response; `args` are the non-empty `prompts/get` arguments. */
interface PendingRequest {
  method: string;
  tool?: string;
  args?: Record<string, string>;
}

/** `prompts/get` arguments as strings (the spec allows only strings; numbers and booleans are tolerated). */
function promptArguments(value: unknown): Record<string, string> {
  if (!isObject(value)) return {};
  const args: Record<string, string> = {};
  for (const [k, v] of Object.entries(value)) {
    if ((typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') && String(v) !== '') args[k] = String(v);
  }
  return args;
}

/** An ML verdict: `reason` may reach the model, `excerpt` only the audit log. */
interface MlFlag {
  reason: string;
  score?: number;
  excerpt?: string;
}

/** Why a definition must be hidden, plus the ML score behind it for the audit log. */
interface Screening {
  hide: string[];
  score?: number;
  excerpt?: string;
}

/** What the model reads from a definition for the classifier: its text plus its parameter names. */
const definitionMlText = (def: unknown): string => [extractText(def), parameterNamesText(def)].join('\n');

/**
 * The approval prompt. Arguments are model-written, so hidden characters and terminal escapes are removed
 * before the user reads them (they could hide what the call really sends).
 */
function approvalMessage(tool: string, args: unknown, why: string): string {
  const clip = (v: unknown): string => {
    const s = JSON.stringify(v) ?? 'null';
    return s.length > APPROVAL_VALUE_CHARS ? `${s.slice(0, APPROVAL_VALUE_CHARS)}… (${s.length} characters)` : s;
  };
  // One line per argument with every value cut short, so a long harmless value cannot push the one that
  // matters (a recipient, a URL) out of sight.
  const clean = stripHiddenChars(args ?? {}).value;
  const entries = isObject(clean) ? Object.entries(clean) : [['(arguments)', clean] as const];
  const lines = entries.slice(0, APPROVAL_MAX_ARGS).map(([k, v]) => `  ${oneLine(k)}: ${clip(v)}`);
  if (entries.length > APPROVAL_MAX_ARGS) lines.push(`  … and ${entries.length - APPROVAL_MAX_ARGS} more arguments`);
  return `Tuuf MCP Firewall: allow the call to ${quoted(tool)}?\nWhy it needs approval: ${oneLine(why)}\nArguments:\n${lines.join('\n') || '  (none)'}`;
}

/** Model-written text on one line, without hidden characters, so it cannot forge the prompt's layout. */
const oneLine = (s: string): string => String(stripHiddenChars(s).value).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ');
const quoted = (s: string): string => JSON.stringify(oneLine(s));

export class FirewallProxy {
  /** Requests the client sent, so server responses can be matched to the method that produced them. */
  private readonly pending = new Map<string, PendingRequest>();
  /** Per-direction chains keep messages in arrival order while async scans run. */
  private readonly queues: Record<Direction, Promise<void>> = {
    'client->server': Promise.resolve(),
    'server->client': Promise.resolve(),
  };

  /** Set when the server's code failed its pin check: from then on nothing passes in either direction. */
  private serverBlocked?: string;
  private codeChecked = false;
  /** The model, from the first loadModel call on. */
  private model?: Promise<Classifier>;
  /** Sampling usage this session: start times of the last minute's requests, request and token totals. */
  private readonly samplingUse = { recent: [] as number[], requests: 0, tokens: 0 };
  /** Clock for the sampling rate window; tests replace it. */
  now: () => number = Date.now;
  /** Session data-flow tracking; in this proxy only until the CLI swaps in one shared with the client's other servers. */
  taint?: TaintTracker;
  /** Whether the client declared elicitation support, so the firewall can ask the user. */
  private clientCanAsk = false;
  /** The firewall's open approval requests, keyed by id, resolved by the client's answer (or undefined on timeout). */
  private readonly approvals = new Map<string, (reply: JsonRpcMessage | undefined) => void>();
  /** Tools the user allowed for the rest of the session. */
  private readonly approvedTools = new Set<string>();

  constructor(
    private readonly policy: Policy,
    private readonly audit: AuditLog,
    private readonly pins: PinStore | undefined,
    private readonly io: ProxyStreams,
    /**
     * The model, or a loader for it. Loading blocks the event loop for seconds, so the loader is called
     * once the handshake has been answered, or earlier by the first scan that needs the model.
     */
    private readonly classifier?: Classifier | (() => Promise<Classifier>),
    /** Fingerprints the server's code; called once, when the server answers the handshake (npx has installed it by then). */
    private readonly serverCode?: () => CodeFingerprint,
  ) {
    const { taint } = policy;
    // A server with sources only still labels the session for the sinks of the client's other servers.
    if (taint.enabled && taint.sources.length + taint.sinks.length > 0) this.taint = new TaintTracker({ ...taint, scope: 'server' });
  }

  start(): void {
    for (const [direction, input] of [['client->server', this.io.clientIn], ['server->client', this.io.serverOut]] as const) {
      onLines(
        input,
        (line) => {
          this.queues[direction] = this.queues[direction].then(() => this.guard(direction, line));
        },
        () => this.violation({ direction }, 'oversized message dropped'),
      );
    }
  }

  private get enforcing(): boolean {
    return this.policy.mode === 'enforce';
  }

  private loadModel(): Promise<Classifier> {
    const classifier = this.classifier!;
    return (this.model ??= typeof classifier === 'function' ? classifier() : Promise.resolve(classifier));
  }

  /** Records a policy violation; returns true when the message must actually be stopped. */
  private violation(ctx: Context, reason: string): boolean {
    this.audit.record({ ...ctx, verdict: this.enforcing ? 'block' : 'would_block', reason });
    return this.enforcing;
  }

  /** Fails closed: a message the firewall cannot parse or process is never forwarded in enforce mode. */
  private async guard(direction: Direction, line: string): Promise<void> {
    const out = direction === 'client->server' ? this.io.serverIn : this.io.clientOut;
    const messages = parseMessage(line);
    if (!messages) {
      if (!this.violation({ direction }, 'malformed JSON-RPC message dropped')) out.write(`${line}\n`);
      return;
    }
    for (const msg of messages) {
      if (this.serverBlocked) {
        // Answer the client's requests; drop everything the server sends.
        if (direction === 'client->server' && isRequest(msg)) send(this.io.clientOut, errorResponse(msg.id, this.serverBlocked));
        continue;
      }
      try {
        if (direction === 'client->server') this.fromClient(msg);
        else await this.fromServer(msg);
      } catch (err) {
        if (!this.violation({ direction, method: msg.method }, `internal error: ${(err as Error).message}`)) send(out, msg);
      }
    }
  }

  private fromClient(msg: JsonRpcMessage): void {
    const direction = 'client->server';
    // The user's answer to the firewall's own approval prompt (or a late one, after it timed out): the
    // server never asked anything, so it is not forwarded.
    if (isResponse(msg) && typeof msg.id === 'string' && msg.id.startsWith(APPROVAL_ID)) {
      this.approvals.get(idKey(msg.id))?.(msg);
      return;
    }
    if (isRequest(msg)) this.noteClientCapabilities(msg);
    if (typeof msg.method === 'string') {
      const decision = evaluateMethod(this.policy, msg.method);
      if (!decision.allowed && this.violation({ direction, method: msg.method }, decision.reason!)) {
        if (isRequest(msg)) send(this.io.clientOut, errorResponse(msg.id, decision.reason!));
        return;
      }
      if (isRequest(msg)) {
        const request: PendingRequest = { method: msg.method };
        if (msg.method === 'tools/call') {
          const inspected = this.inspectToolCall(msg);
          if (!inspected) return;
          request.tool = inspected.tool;
          if (inspected.ask.length > 0) {
            // Other messages keep flowing while the user decides; this call goes out only on approval.
            void this.forwardIfApproved(msg, request, inspected.ask);
            return;
          }
        } else if (msg.method === 'prompts/get' && isObject(msg.params) && typeof msg.params.name === 'string') {
          request.tool = msg.params.name;
          request.args = promptArguments(msg.params.arguments);
        }
        this.pending.set(idKey(msg.id), request);
      }
    }
    send(this.io.serverIn, msg);
  }

  /** Elicitation support, from `initialize` or, from protocol 2026-07-28 on, any request's `_meta`. */
  private noteClientCapabilities(msg: JsonRpcMessage): void {
    const params = isObject(msg.params) ? msg.params : {};
    const meta = isObject(params._meta) ? params._meta['io.modelcontextprotocol/clientCapabilities'] : undefined;
    const caps = msg.method === 'initialize' ? params.capabilities : meta;
    if (isObject(caps)) this.clientCanAsk = isObject(caps.elicitation);
  }

  /**
   * Returns the tool name, plus why the user must approve the call first, when it may proceed;
   * undefined when it was blocked and answered.
   */
  private inspectToolCall(msg: JsonRpcMessage): { tool: string; ask: string[] } | undefined {
    const params = isObject(msg.params) ? msg.params : {};
    const name = typeof params.name === 'string' ? params.name : '';
    const ctx: Context = { direction: 'client->server', method: 'tools/call', tool: name };

    const decision = evaluateToolCall(this.policy, name, params.arguments);
    if (!decision.allowed && this.violation(ctx, decision.reason!)) {
      send(this.io.clientOut, toolErrorResponse(msg.id, decision.reason!));
      return undefined;
    }

    const { dlp } = this.policy;
    if (dlp.enabled && dlp.scanRequests && params.arguments !== undefined) {
      const scan = this.applyDlp(params.arguments, ctx, 'arguments');
      if (scan.blockReason) {
        send(this.io.clientOut, toolErrorResponse(msg.id, scan.blockReason));
        return undefined;
      }
      params.arguments = scan.value;
    }

    const ask = decision.ask ? [decision.ask] : [];
    // Checked on the arguments as they will leave: a secret DLP has just redacted no longer flows anywhere.
    const flow = this.taintFlow(name, params.arguments);
    if (flow) {
      const { action } = this.taint!.config;
      if (action === 'warn') this.audit.record({ ...ctx, verdict: 'warn', reason: flow });
      else if (action === 'ask') ask.push(flow);
      else if (this.violation(ctx, flow)) {
        send(this.io.clientOut, toolErrorResponse(msg.id, flow));
        return undefined;
      }
    }

    if (ask.length === 0) this.audit.record({ ...ctx, verdict: 'allow' });
    return { tool: name, ask };
  }

  /** Holds a tools/call until the user answers; forwards it on approval, refuses it otherwise. */
  private async forwardIfApproved(msg: JsonRpcMessage, request: PendingRequest, reasons: string[]): Promise<void> {
    const ctx: Context = { direction: 'client->server', method: 'tools/call', tool: request.tool };
    const refusal = await this.approve(request.tool ?? '', (msg.params as JsonObject).arguments, reasons, ctx);
    const reason = refusal ?? this.serverBlocked;
    if (reason) {
      send(this.io.clientOut, toolErrorResponse(msg.id, reason));
      return;
    }
    this.pending.set(idKey(msg.id), request);
    send(this.io.serverIn, msg);
  }

  /**
   * Asks the user through an elicitation the client shows. Returns the refusal reason, or undefined
   * when the call may go ahead.
   */
  private async approve(tool: string, args: unknown, reasons: string[], ctx: Context): Promise<string | undefined> {
    const why = reasons.join('; ');
    const { approval } = this.policy;
    if (!this.enforcing) {
      this.audit.record({ ...ctx, verdict: 'warn', reason: `approval required, forwarded in monitor mode: ${why}` });
      return undefined;
    }
    if (this.approvedTools.has(tool)) {
      this.audit.record({ ...ctx, verdict: 'info', reason: `allowed for this session by the user earlier: ${why}` });
      return undefined;
    }
    const unavailable = (detail: string): string | undefined => {
      if (approval.fallback === 'allow') {
        this.audit.record({ ...ctx, verdict: 'warn', reason: `${detail}; allowed by approval.fallback: ${why}` });
        return undefined;
      }
      const reason = `${detail}, so the call is refused: ${why}`;
      this.violation(ctx, reason);
      return reason;
    };
    if (!this.clientCanAsk) return unavailable('needs user approval but the client cannot ask (no elicitation support)');

    // Unguessable: a server that could predict it would ask something harmless under this id and the user's
    // "accept" to that would approve this call.
    const id = `${APPROVAL_ID}${randomUUID()}`;
    let timer: NodeJS.Timeout | undefined;
    const answer = new Promise<JsonRpcMessage | undefined>((resolve) => {
      this.approvals.set(idKey(id), resolve);
      // The stdio streams keep the firewall alive; the timer alone must not.
      timer = setTimeout(() => resolve(undefined), approval.timeoutSeconds * 1000).unref();
    });
    send(this.io.clientOut, {
      jsonrpc: '2.0',
      id,
      method: 'elicitation/create',
      params: {
        message: approvalMessage(tool, args, why),
        requestedSchema: {
          type: 'object',
          properties: approval.remember
            ? { remember: { type: 'boolean', title: `Allow ${quoted(tool)} for the rest of this session`, default: false } }
            : {},
        },
      },
    });
    this.audit.record({ ...ctx, verdict: 'info', reason: `waiting for user approval: ${why}` });
    const reply = await answer;
    clearTimeout(timer);
    this.approvals.delete(idKey(id));

    if (!reply) {
      send(this.io.clientOut, { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id, reason: 'approval timed out' } });
      const reason = `no answer to the approval prompt within ${approval.timeoutSeconds} s: ${why}`;
      this.violation(ctx, reason);
      return reason;
    }
    if (reply.error !== undefined) return unavailable('needs user approval but the client refused the prompt');
    const result = isObject(reply.result) ? reply.result : {};
    if (result.action !== 'accept') {
      const reason = `the user did not approve the call (${String(result.action ?? 'no answer')}): ${why}`;
      this.violation(ctx, reason);
      return reason;
    }
    const remember = approval.remember && isObject(result.content) && result.content.remember === true;
    if (remember) this.approvedTools.add(tool);
    this.audit.record({ ...ctx, verdict: 'info', reason: `approved by the user${remember ? ' for this session' : ''}: ${why}` });
    return undefined;
  }

  private async fromServer(msg: JsonRpcMessage): Promise<void> {
    const direction = 'server->client';
    let handshake = false;
    if (typeof msg.method === 'string') {
      // Server-initiated request or notification (sampling, elicitation, list_changed...).
      const decision = evaluateMethod(this.policy, msg.method);
      if (!decision.allowed && this.violation({ direction, method: msg.method }, decision.reason!)) {
        if (isRequest(msg)) send(this.io.serverIn, errorResponse(msg.id, decision.reason!));
        return;
      }
      if (msg.method === 'notifications/tools/list_changed') {
        this.audit.record({ direction, method: msg.method, verdict: 'info', reason: 'tool list changed; definitions are re-verified on the next tools/list' });
      } else if (isRequest(msg)) {
        // The client's answer would be taken for the user's answer to a firewall approval prompt.
        if (typeof msg.id === 'string' && msg.id.startsWith(APPROVAL_ID)) {
          const reason = 'server request uses the id space of firewall approval prompts';
          this.audit.record({ direction, method: msg.method, verdict: 'block', reason });
          send(this.io.serverIn, errorResponse(msg.id, reason));
          return;
        }
        if (SERVER_PROMPTS.has(msg.method)) {
          const refusal = (msg.method === 'sampling/createMessage' && this.limitSampling(msg)) || (await this.inspectServerPrompt(msg));
          if (refusal) {
            send(this.io.serverIn, errorResponse(msg.id, refusal));
            return;
          }
        }
        this.audit.record({ direction, method: msg.method, verdict: 'allow' });
      }
    } else if (isResponse(msg)) {
      const request = this.pending.get(idKey(msg.id));
      this.pending.delete(idKey(msg.id));
      handshake = request !== undefined && HANDSHAKES.has(request.method);
      if (request && handshake && !this.codeChecked) {
        this.codeChecked = true;
        this.serverBlocked = this.checkServerCode(request.method);
        if (this.serverBlocked) {
          send(this.io.clientOut, errorResponse(msg.id, this.serverBlocked));
          return;
        }
      }
      if (request && isObject(msg.result)) {
        if (request.method === 'tools/list') msg.result = await this.filterToolsList(msg.result);
        else if (request.method in DEFINITION_LISTS) msg.result = await this.filterDefinitions(msg.result, request.method);
        else if (handshake) msg.result = await this.inspectInstructions(msg.result, request.method);
        else if (SCANNED_RESULTS.has(request.method)) msg = await this.inspectResult(msg, request);
      } else if (request && msg.error !== undefined) {
        msg = await this.inspectError(msg, request);
      }
    }
    send(this.io.clientOut, msg);
    // A client probing the protocol version stops waiting after a while, so the model loads only now.
    if (handshake && this.classifier) setImmediate(() => void this.loadModel().catch(() => undefined));
  }

  /**
   * Package rug pull: the server's code changed since it was pinned while its tool definitions may
   * be identical. Returns the reason when the server must not be used.
   */
  private checkServerCode(method: string): string | undefined {
    const { serverCode } = this.policy.pinning;
    if (!this.pins || !this.serverCode || serverCode === 'off') return undefined;
    const ctx: Context = { direction: 'server->client', method, tool: '(server code)' };
    let fp: CodeFingerprint;
    try {
      fp = this.serverCode();
    } catch (err) {
      const reason = `server code fingerprint failed: ${(err as Error).message}`;
      if (serverCode === 'warn') {
        this.audit.record({ ...ctx, verdict: 'warn', reason });
        return undefined;
      }
      return this.violation(ctx, reason) ? reason : undefined;
    }
    for (const note of fp.notes) this.audit.record({ ...ctx, verdict: 'warn', reason: note });
    if (!fp.hash) return undefined;
    const what = fp.packages.length > 0 ? fp.packages.join(', ') : fp.roots.join(', ');
    const status = this.pins.checkCode(fp.hash);
    if (status === 'new') {
      this.audit.record({ ...ctx, verdict: 'info', reason: `server code pinned: ${what}` });
      return undefined;
    }
    if (status !== 'changed') return undefined;
    const reason = `server code changed since it was pinned (${what}); possible package rug pull. Review it, then run: mcp-firewall pins approve`;
    if (serverCode === 'warn') {
      this.audit.record({ ...ctx, verdict: 'warn', reason });
      return undefined;
    }
    return this.violation(ctx, reason) ? reason : undefined;
  }

  /**
   * Prompt rug pull: the template behind a pinned prompt changed. Hashed before any redaction, so every
   * change the server makes counts. Returns the reason when the result must be refused.
   */
  private checkPromptPin(result: JsonObject, request: PendingRequest, ctx: Context): string | undefined {
    const { pinning } = this.policy;
    if (!this.pins || pinning.prompts === 'off') return undefined;
    const args = request.args ?? {};
    const key = promptPinKey(request.tool ?? '', args);
    let status: PinStatus;
    try {
      status = this.pins.checkPrompt(key, hashPromptTemplate(result, args), pinning.onNew === 'hide');
    } catch (err) {
      this.audit.record({ ...ctx, verdict: 'warn', reason: `pin store unreadable, treating the prompt template as changed: ${(err as Error).message}` });
      status = 'changed';
    }
    if (status === 'new') {
      this.audit.record({ ...ctx, verdict: 'info', reason: `new prompt template pinned (${key})` });
      return undefined;
    }
    if (status === 'pending') {
      const reason = `new prompt template held until approved (${key}): mcp-firewall pins approve`;
      return this.violation(ctx, reason) ? reason : undefined;
    }
    if (status !== 'changed') return undefined;
    const reason = `prompt template changed since it was pinned (${key}); possible rug pull. Review it, then run: mcp-firewall pins approve`;
    if (pinning.prompts === 'warn') {
      this.audit.record({ ...ctx, verdict: 'warn', reason });
      return undefined;
    }
    return this.violation(ctx, reason) ? reason : undefined;
  }

  /** Describes the labelled session data a sink call would carry out, if any. */
  private taintFlow(tool: string, args: unknown): string | undefined {
    const flow = this.taint?.checkSink(tool, args);
    if (!flow) return undefined;
    const origin = `'${flow.tool}'${flow.server === 'this server' ? '' : ` on ${flow.server}`}`;
    return flow.when === 'content'
      ? `data flow: arguments of '${tool}' carry ${flow.label} data returned by ${origin} earlier in this session`
      : `data flow: '${tool}' may send data out and this session holds ${flow.label} data from ${origin}`;
  }

  private async inspectResult(msg: JsonRpcMessage, request: PendingRequest): Promise<JsonRpcMessage> {
    const ctx: Context = { direction: 'server->client', method: request.method, tool: request.tool };
    const refuse = (reason: string) =>
      request.method === 'tools/call' ? toolErrorResponse(msg.id, reason) : errorResponse(msg.id, reason);
    const { dlp, ml, descriptionScan } = this.policy;

    const isPrompt = request.method === 'prompts/get';
    if (isPrompt) {
      const reason = this.checkPromptPin(msg.result as JsonObject, request, ctx);
      if (reason) return refuse(reason);
    }

    let dlpFound = false;
    if (dlp.enabled && dlp.scanResponses) {
      const scan = this.applyDlp(msg.result, ctx, 'result');
      if (scan.blockReason) return refuse(scan.blockReason);
      msg.result = scan.value;
      dlpFound = scan.found === true;
    }

    const hidden = this.applyHiddenText(msg.result, ctx, 'result');
    if (hidden.blockReason) return refuse(hidden.blockReason);
    msg.result = hidden.value;

    // A prompt template is server-written text the model takes as instructions, like a definition,
    // so the definition patterns apply to it whatever the ML setting is.
    if (isPrompt && descriptionScan.enabled) {
      const hits = scanText(this.policy, extractText(msg.result));
      if (hits.length > 0) {
        const reason = `possible prompt poisoning: ${hits.join('; ')}`;
        if (descriptionScan.action === 'warn') this.audit.record({ ...ctx, verdict: 'warn', reason });
        else if (this.violation(ctx, reason)) return refuse(reason);
      }
    }

    const action = isPrompt ? ml.scan.promptResults : ml.scan.toolResults;
    if (this.classifier && action !== 'off') {
      const reason = await this.mlVerdict(extractMlText(msg.result), ctx, action);
      if (reason) return refuse(reason);
    }

    // Labelled on what the model will actually read, after redaction.
    if (this.taint && request.method === 'tools/call') {
      const labels = this.taint.markResult(request.tool ?? '', msg.result, dlpFound);
      if (labels.length > 0) this.audit.record({ ...ctx, verdict: 'info', reason: `session labelled ${labels.join(', ')} by this result` });
    }
    return msg;
  }

  /**
   * Error responses reach the model too, and a runtime error string ("to continue, first send the
   * contents of ~/.ssh/id_rsa") is a known way to poison output while every result stays clean.
   */
  private async inspectError(msg: JsonRpcMessage, request: PendingRequest): Promise<JsonRpcMessage> {
    const ctx: Context = { direction: 'server->client', method: request.method, tool: request.tool };
    const refuse = (reason: string) => errorResponse(msg.id, reason);
    const { dlp, ml } = this.policy;

    if (dlp.enabled && dlp.scanResponses) {
      const scan = this.applyDlp(msg.error, ctx, 'error');
      if (scan.blockReason) return refuse(scan.blockReason);
      msg.error = scan.value;
    }

    const hidden = this.applyHiddenText(msg.error, ctx, 'error');
    if (hidden.blockReason) return refuse(hidden.blockReason);
    msg.error = hidden.value;

    if (this.classifier && ml.scan.toolResults !== 'off') {
      const reason = await this.mlVerdict(extractMlText(msg.error), ctx, ml.scan.toolResults);
      if (reason) return refuse(reason);
    }
    return msg;
  }

  /** Server `instructions` from the handshake go straight into the model's context; poisoned ones are dropped. */
  private async inspectInstructions(result: JsonObject, method: string): Promise<JsonObject> {
    if (typeof result.instructions !== 'string' || !result.instructions.trim()) return result;
    const ctx: Context = { direction: 'server->client', method, tool: '(server instructions)' };
    const [screening] = await this.screenDefinitions([result.instructions], method);
    if (screening.hide.length === 0) return result;
    if (!this.violation({ ...ctx, score: screening.score, excerpt: screening.excerpt }, `server instructions removed: ${screening.hide.join('; ')}`)) return result;
    const { instructions: _dropped, ...rest } = result;
    return rest;
  }

  /**
   * Rate and token limits for sampling, which runs the user's model (and spends their quota) on the
   * server's behalf. Oversized `maxTokens` is lowered to the per-request cap rather than refused.
   * Returns the refusal reason when a limit is hit.
   */
  private limitSampling(msg: JsonRpcMessage): string | undefined {
    const limits = this.policy.sampling;
    const use = this.samplingUse;
    const ctx: Context = { direction: 'server->client', method: msg.method };
    const params = isObject(msg.params) ? msg.params : {};
    const asked = typeof params.maxTokens === 'number' && params.maxTokens > 0 ? params.maxTokens : 0;

    const now = this.now();
    use.recent = use.recent.filter((t) => now - t < 60_000);
    let reason: string | undefined;
    if (limits.maxPerMinute > 0 && use.recent.length >= limits.maxPerMinute) {
      reason = `sampling rate limit: more than ${limits.maxPerMinute} requests per minute`;
    } else if (limits.maxPerSession > 0 && use.requests >= limits.maxPerSession) {
      reason = `sampling limit: ${limits.maxPerSession} requests per session reached`;
    }

    let tokens = asked;
    if (!reason && limits.maxTokensPerRequest > 0 && asked > limits.maxTokensPerRequest) {
      tokens = limits.maxTokensPerRequest;
      if (this.enforcing) params.maxTokens = tokens;
      this.audit.record({ ...ctx, verdict: this.enforcing ? 'redact' : 'would_redact', reason: `sampling maxTokens ${asked} lowered to ${tokens}` });
    }
    if (!reason && limits.maxTokensPerSession > 0 && use.tokens + tokens > limits.maxTokensPerSession) {
      reason = `sampling token budget: ${limits.maxTokensPerSession} tokens per session would be exceeded (${use.tokens} used, ${tokens} asked)`;
    }

    if (reason && this.violation(ctx, reason)) return reason;
    use.recent.push(now);
    use.requests++;
    use.tokens += tokens;
    return undefined;
  }

  /** Sampling and elicitation let a server write the prompt; scan what it wrote before the host acts on it. */
  private async inspectServerPrompt(msg: JsonRpcMessage): Promise<string | undefined> {
    const ctx: Context = { direction: 'server->client', method: msg.method };
    const hidden = this.applyHiddenText(msg.params, ctx, 'request');
    if (hidden.blockReason) return hidden.blockReason;
    msg.params = hidden.value;

    const { ml } = this.policy;
    if (!this.classifier || ml.scan.serverRequests === 'off') return undefined;
    return this.mlVerdict(extractMlText(msg.params), ctx, ml.scan.serverRequests);
  }

  /** Runs the classifier on one text; returns the refusal reason when the message must be stopped. */
  private async mlVerdict(text: string, ctx: Context, action: 'block' | 'warn'): Promise<string | undefined> {
    const [flag] = await this.mlFlags([text], ctx, ctx.method === 'prompts/get' ? 'prompt' : 'output');
    if (!flag) return undefined;
    const event = { ...ctx, score: flag.score, excerpt: flag.excerpt };
    if (action === 'warn') {
      this.audit.record({ ...event, verdict: 'warn', reason: flag.reason });
      return undefined;
    }
    return this.violation(event, flag.reason) ? flag.reason : undefined;
  }

  /**
   * DLP over a value. Secrets found in place are masked or refused per `dlp.action`; secrets that cannot be masked in
   * place (cut into neighbouring fields, hidden inside a media block) are refused, or only reported under `warn`.
   */
  private applyDlp(value: unknown, ctx: Context, what: string): { value: unknown; blockReason?: string; found?: boolean } {
    const { detectors, action } = this.policy.dlp;
    const hidden = unredactableFindings(value, detectors);
    if (hidden.length === 0) return this.applyRedactingDlp(value, ctx, what);
    const reason = `sensitive data in ${what} that cannot be masked in place (split across fields or inside a media block): ${formatFindings(hidden)}`;
    if (action === 'warn') this.audit.record({ ...ctx, verdict: 'warn', reason });
    else if (this.violation(ctx, reason)) return { value, blockReason: reason, found: true };
    return { ...this.applyRedactingDlp(value, ctx, what), found: true };
  }

  private applyRedactingDlp(value: unknown, ctx: Context, what: string): { value: unknown; blockReason?: string; found?: boolean } {
    const { detectors, action } = this.policy.dlp;
    const scan = deepScan(value, detectors);
    if (scan.findings.length === 0) return this.encodedDlp(value, ctx, what);
    const reason = `sensitive data in ${what}: ${formatFindings(scan.findings)}`;
    const event = { ...ctx, masked: scan.masked };
    if (action === 'block') return { value, blockReason: this.violation(event, reason) ? reason : undefined, found: true };
    if (action === 'warn') {
      this.audit.record({ ...event, verdict: 'warn', reason });
      return { value, found: true };
    }
    this.audit.record({ ...event, verdict: this.enforcing ? 'redact' : 'would_redact', reason });
    return { value: this.enforcing ? scan.value : value, found: true };
  }

  /**
   * Secrets hidden by encoding (a base64'd AWS key in a URL is a classic exfiltration channel). The
   * encoded form cannot be redacted in place, so `redact` escalates to blocking here.
   */
  private encodedDlp(value: unknown, ctx: Context, what: string): { value: unknown; blockReason?: string; found?: boolean } {
    if (!this.policy.decoding.enabled) return { value };
    const decoded = decodeEmbedded(extractText(value));
    if (decoded.length === 0) return { value };
    const { findings } = deepScan(decoded, this.policy.dlp.detectors);
    if (findings.length === 0) return { value };
    const reason = `encoded sensitive data in ${what}: ${formatFindings(findings)}`;
    if (this.policy.dlp.action === 'warn') {
      this.audit.record({ ...ctx, verdict: 'warn', reason });
      return { value, found: true };
    }
    return { value, blockReason: this.violation(ctx, reason) ? reason : undefined, found: true };
  }

  /** Invisible characters and terminal escapes hide text from the user that the model still reads. */
  private applyHiddenText(value: unknown, ctx: Context, what: string): { value: unknown; blockReason?: string } {
    const { action } = this.policy.hiddenText;
    if (action === 'off' || !hasHiddenChars(extractText(value))) return { value };
    const stripped = stripHiddenChars(value);
    const reason = `hidden characters or terminal escape sequences in ${what} (${stripped.removed})`;
    if (action === 'block') return { value, blockReason: this.violation(ctx, reason) ? reason : undefined };
    if (action === 'warn') {
      this.audit.record({ ...ctx, verdict: 'warn', reason });
      return { value };
    }
    this.audit.record({ ...ctx, verdict: this.enforcing ? 'redact' : 'would_redact', reason });
    return { value: this.enforcing ? stripped.value : value };
  }

  /** Runs the classifier over `texts`; one flag (or undefined) per text, honouring `ml.failMode` and `ml.onTruncated`. */
  private async mlFlags(texts: string[], ctx: Context, channel: Channel = 'output'): Promise<(MlFlag | undefined)[]> {
    const { ml, decoding } = this.policy;
    try {
      // Neutralise our own DLP redaction markers before scoring: the bracketed [REDACTED:…] reads as an injection
      // to the classifier and would turn a masked result into a block. Embedded images go too (see stripImageData).
      // Affects only the scan input, not the output.
      const scan = texts.map((t) => stripImageData(t.replace(REDACTION_MARKER, 'redacted')));
      const scores = await scoreTexts(await this.loadModel(), decoding.enabled ? scan.map(withDecoded) : scan, ml, channel);
      return scores.map((s) => {
        if (s.score >= ml.threshold) {
          return { reason: `ML classifier flagged possible prompt injection (score ${s.score.toFixed(3)})`, score: s.score, excerpt: s.excerpt };
        }
        const { nearMiss, sample } = ml.review;
        const review = nearMiss > 0 && s.score >= nearMiss ? 'near miss' : sample > 0 && Math.random() < sample ? 'sample' : '';
        if (review && s.excerpt) {
          this.audit.record({ ...ctx, verdict: 'info', reason: `ML ${review} for review (score ${s.score.toFixed(3)})`, score: s.score, excerpt: s.excerpt });
        }
        if (s.truncated) {
          const reason = `text too long to scan fully: only the first and last ${ml.maxChunks} chunks were checked`;
          if (ml.onTruncated === 'block') return { reason };
          this.audit.record({ ...ctx, verdict: 'warn', reason });
        }
        return undefined;
      });
    } catch (err) {
      const reason = `ML classifier failed: ${(err as Error).message}`;
      if (ml.failMode === 'open') {
        this.audit.record({ ...ctx, verdict: 'warn', reason });
        return texts.map(() => undefined);
      }
      return texts.map(() => ({ reason }));
    }
  }

  /**
   * Pattern, hidden-character and ML checks for anything the model reads as a definition
   * (tools, prompts, resources, server instructions). Warn-only findings are logged here.
   */
  private async screenDefinitions(items: unknown[], method: string, names: string[] = []): Promise<Screening[]> {
    const { ml, descriptionScan } = this.policy;
    const mlResults =
      this.classifier && ml.scan.toolDefinitions !== 'off'
        ? await this.mlFlags(items.map(definitionMlText), { direction: 'server->client', method }, 'definition')
        : [];
    return items.map((item, i) => {
      const ctx: Context = { direction: 'server->client', method, tool: names[i] };
      const screening: Screening = { hide: [] };
      if (descriptionScan.enabled) {
        const hits = typeof item === 'string' ? scanText(this.policy, item) : scanToolDefinition(this.policy, item as JsonObject);
        if (hits.length > 0) {
          const reason = `possible tool poisoning: ${hits.join('; ')}`;
          if (descriptionScan.action === 'hide') screening.hide.push(reason);
          else this.audit.record({ ...ctx, verdict: 'warn', reason });
        }
      }
      const flag = mlResults[i];
      if (flag) {
        Object.assign(screening, { score: flag.score, excerpt: flag.excerpt });
        if (ml.scan.toolDefinitions === 'hide') screening.hide.push(flag.reason);
        else this.audit.record({ ...ctx, score: flag.score, excerpt: flag.excerpt, verdict: 'warn', reason: flag.reason });
      }
      return screening;
    });
  }

  /** Hides prompts and resources whose descriptions look poisoned. */
  private async filterDefinitions(result: JsonObject, method: string): Promise<JsonObject> {
    const key = DEFINITION_LISTS[method];
    if (!Array.isArray(result[key])) return result;
    const items = (result[key] as unknown[]).filter(isObject);
    const names = items.map((d) => String(d.name ?? d.uri ?? d.uriTemplate ?? ''));
    const screenings = await this.screenDefinitions(items, method, names);
    const kept = items.filter((_, i) => {
      const { hide, score, excerpt } = screenings[i];
      return hide.length === 0 || !this.violation({ direction: 'server->client', method, tool: names[i], score, excerpt }, hide.join('; '));
    });
    return { ...result, [key]: kept };
  }

  /** Hides tools that are denied, look poisoned, changed since they were pinned, or shadow another server's tool. */
  private async filterToolsList(list: JsonObject): Promise<JsonObject> {
    // Server `instructions` normally ride on the handshake, but a server can put them here too; the model reads them either way.
    const result = await this.inspectInstructions(list, 'tools/list');
    const tools = (Array.isArray(result.tools) ? result.tools : []).filter(isObject);
    const names = tools.map((t) => String(t.name ?? ''));
    const { pinning } = this.policy;

    let pinStatus = new Map<string, PinStatus>();
    let collisions = new Map<string, string[]>();
    if (this.pins) {
      try {
        pinStatus = this.pins.checkAll(tools, pinning.onNew === 'hide');
        if (pinning.onNameCollision !== 'off') collisions = this.pins.collisions(names);
      } catch (err) {
        this.audit.record({ direction: 'server->client', method: 'tools/list', verdict: 'warn', reason: `pin store unreadable, treating all tools as changed: ${(err as Error).message}` });
        pinStatus = new Map(names.map((n) => [n, 'changed']));
      }
    }

    const screenings = await this.screenDefinitions(tools, 'tools/list', names);

    const kept: JsonObject[] = [];
    tools.forEach((tool, i) => {
      const name = names[i];
      const { hide, score, excerpt } = screenings[i];
      const ctx: Context = { direction: 'server->client', method: 'tools/list', tool: name, score, excerpt };
      const hideReasons = [...hide];

      const byName = evaluateToolName(this.policy, name);
      if (!byName.allowed) hideReasons.unshift(byName.reason!);

      const status = pinStatus.get(name);
      if (status === 'new') {
        this.audit.record({ ...ctx, verdict: 'info', reason: 'new tool definition pinned' });
      } else if (status === 'pending') {
        hideReasons.push('new tool held until approved (mcp-firewall pins approve)');
      } else if (status === 'changed') {
        const reason = 'tool definition changed since it was pinned (possible rug pull)';
        if (pinning.onChange === 'hide') hideReasons.push(reason);
        else this.audit.record({ ...ctx, verdict: 'warn', reason });
      }

      const others = collisions.get(name);
      if (others) {
        const reason = `tool name also exposed by another server (${others.join(', ')}); possible tool shadowing`;
        if (pinning.onNameCollision === 'hide') hideReasons.push(reason);
        else this.audit.record({ ...ctx, verdict: 'warn', reason });
      }

      if (hideReasons.length > 0 && this.violation(ctx, hideReasons.join('; '))) return;
      kept.push(tool);
    });
    return { ...result, tools: kept };
  }
}
