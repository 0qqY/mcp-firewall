import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { AuditSink, SiemRecord } from './siem.js';

export type Verdict = 'allow' | 'block' | 'would_block' | 'redact' | 'would_redact' | 'warn' | 'info';

export interface AuditEvent {
  direction?: 'client->server' | 'server->client';
  verdict: Verdict;
  method?: string;
  tool?: string;
  reason?: string;
  /** ML classifier score, when the verdict came from the model. */
  score?: number;
  /** Text that triggered the model. Logged for analysts, never echoed back to the model. */
  excerpt?: string;
}

/** What goes to the SIEM sinks besides the JSONL file. */
export interface SinkOptions {
  sinks: AuditSink[];
  logAllowed: boolean;
  excerpt: boolean;
}

/** Appends JSONL audit records, forwards them to SIEM sinks and mirrors anything that is not a plain allow to stderr. */
export class AuditLog {
  private writeFailed = false;

  constructor(
    private readonly file: string | undefined,
    private readonly logAllowed: boolean,
    private readonly server: string,
    private readonly stderr: NodeJS.WritableStream | null = process.stderr,
    private readonly forward: SinkOptions = { sinks: [], logAllowed: false, excerpt: false },
  ) {
    if (file) mkdirSync(dirname(file), { recursive: true });
  }

  record(event: AuditEvent): void {
    const allowed = event.verdict === 'allow';
    if (!allowed) {
      const target = [event.method, event.tool].filter(Boolean).join(' ');
      this.stderr?.write(`[mcp-firewall] ${event.verdict.toUpperCase()} ${target}${event.reason ? `: ${event.reason}` : ''}\n`);
    }
    const toFile = this.file && (!allowed || this.logAllowed);
    const toSinks = this.forward.sinks.length > 0 && (!allowed || this.forward.logAllowed);
    if (!toFile && !toSinks) return;
    const record: SiemRecord = { ts: new Date().toISOString(), server: this.server, ...event };
    if (toSinks) {
      const out = this.forward.excerpt ? record : { ...record, excerpt: undefined };
      for (const sink of this.forward.sinks) sink.send(out);
    }
    if (!toFile) return;
    try {
      appendFileSync(this.file!, `${JSON.stringify(record)}\n`);
    } catch (err) {
      if (!this.writeFailed) this.stderr?.write(`[mcp-firewall] cannot write audit log: ${(err as Error).message}\n`);
      this.writeFailed = true;
    }
  }

  /** Gives the SIEM sinks up to `ms` to send what they hold; call before the process exits. */
  async flush(ms = 2000): Promise<void> {
    await Promise.all(this.forward.sinks.map((s) => s.flush(ms)));
  }

  close(): void {
    for (const sink of this.forward.sinks) sink.close();
  }
}
