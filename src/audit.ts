import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

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

/** Appends JSONL audit records and mirrors anything that is not a plain allow to stderr. */
export class AuditLog {
  private writeFailed = false;

  constructor(
    private readonly file: string | undefined,
    private readonly logAllowed: boolean,
    private readonly server: string,
    private readonly stderr: NodeJS.WritableStream | null = process.stderr,
  ) {
    if (file) mkdirSync(dirname(file), { recursive: true });
  }

  record(event: AuditEvent): void {
    if (event.verdict !== 'allow') {
      const target = [event.method, event.tool].filter(Boolean).join(' ');
      this.stderr?.write(`[mcp-firewall] ${event.verdict.toUpperCase()} ${target}${event.reason ? `: ${event.reason}` : ''}\n`);
    } else if (!this.logAllowed) {
      return;
    }
    if (!this.file) return;
    try {
      appendFileSync(this.file, `${JSON.stringify({ ts: new Date().toISOString(), server: this.server, ...event })}\n`);
    } catch (err) {
      if (!this.writeFailed) this.stderr?.write(`[mcp-firewall] cannot write audit log: ${(err as Error).message}\n`);
      this.writeFailed = true;
    }
  }
}
