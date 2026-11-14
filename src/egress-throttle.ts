/**
 * How many egress decisions reach the audit log. The server picks the host names, so neither a repeated
 * connection nor a stream of fresh names may flood the log, stderr or the SIEM: the same decision for the
 * same host and port is written at most once per window, and all of them together at most `perWindow` times.
 * What was held back is reported, not lost: as a count on the key's next record, and as one summary line.
 */
export interface ThrottleResult {
  /** Write this record. */
  write: boolean;
  /** Same-key records held back since this key was last written. */
  more: number;
  /** Records held back by the overall budget in the window that just ended; write a summary line first. */
  suppressed?: number;
}

export class EgressThrottle {
  private readonly keys = new Map<string, { at: number; skipped: number }>();
  private windowStart = -Infinity;
  private written = 0;
  private overBudget = 0;

  constructor(
    private readonly perWindow = 30,
    private readonly windowMs = 60_000,
    private readonly maxKeys = 1000,
  ) {}

  take(key: string, now: number): ThrottleResult {
    let suppressed: number | undefined;
    if (now - this.windowStart >= this.windowMs) {
      if (this.overBudget > 0) suppressed = this.overBudget;
      this.windowStart = now;
      this.written = 0;
      this.overBudget = 0;
    }
    const last = this.keys.get(key);
    if (last && now - last.at < this.windowMs) {
      last.skipped++;
      return { write: false, more: 0, suppressed };
    }
    if (this.written >= this.perWindow) {
      this.overBudget++;
      return { write: false, more: 0, suppressed };
    }
    this.written++;
    if (this.keys.size >= this.maxKeys) this.keys.clear();
    this.keys.set(key, { at: now, skipped: 0 });
    return { write: true, more: last?.skipped ?? 0, suppressed };
  }
}
