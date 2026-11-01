import { spawn } from 'node:child_process';
import type { NotifyConfig } from './policy.js';
import type { AuditSink, SiemRecord } from './siem.js';

/** Shows one desktop notification; must never throw or block the firewall. */
export type Show = (title: string, body: string) => void;

const PANEL = 'http://127.0.0.1:4747';

/** Short Turkish wording for the reasons a user is most likely to see. */
const REASONS: [RegExp, string][] = [
  [/ML classifier flagged/i, 'olası prompt enjeksiyonu'],
  [/sensitive data/i, 'hassas veri (anahtar, parola, kişisel veri)'],
  [/rug pull|changed since it was pinned/i, 'araç tanımı onaydan sonra değişti'],
  [/server code/i, 'sunucu kodu değişti'],
  [/tool poisoning/i, 'zehirli araç tanımı'],
  [/hidden characters/i, 'gizli karakterler'],
  [/data flow|session labelled/i, 'okunan veri dışarı gönderilecekti'],
  [/method '/i, 'izin verilmeyen istek'],
  [/denied|not allowed|argument/i, 'politika kuralı'],
];

const VERBS: Record<string, string> = {
  block: 'engelledi',
  would_block: 'engellerdi (izleme modu)',
  redact: 'veriyi maskeledi',
  would_redact: 'veriyi maskelerdi (izleme modu)',
  warn: 'uyarı verdi',
};

export function describe(r: SiemRecord): { title: string; body: string } {
  const why = REASONS.find(([re]) => re.test(r.reason ?? ''))?.[1] ?? (r.reason ?? '').slice(0, 120);
  const what = r.tool ?? r.method ?? 'mesaj';
  return { title: `Tuuf MCP Firewall ${VERBS[r.verdict] ?? r.verdict}`, body: `${r.server} · ${what}: ${why}` };
}

/**
 * Turns audit records into desktop notifications. The first one shows at once; the rest during `quietSeconds`
 * are counted and shown as one summary, so a burst (a flagged file read in a loop) is a single popup.
 */
export class DesktopNotifier implements AuditSink {
  private readonly on: Set<string>;
  private quietUntil = 0;
  private held: SiemRecord[] = [];
  private timer: NodeJS.Timeout | undefined;

  constructor(
    private readonly config: NotifyConfig,
    private readonly show: Show = showDesktop,
    private readonly now: () => number = Date.now,
  ) {
    this.on = new Set(config.on);
  }

  send(record: SiemRecord): void {
    if (!this.on.has(record.verdict)) return;
    const t = this.now();
    if (t >= this.quietUntil) {
      const { title, body } = describe(record);
      this.show(title, `${body}\nAyrıntı: ${PANEL}`);
      this.quietUntil = t + this.config.quietSeconds * 1000;
      return;
    }
    this.held.push(record);
    if (!this.timer) {
      this.timer = setTimeout(() => this.summarise(), this.quietUntil - t);
      this.timer.unref();
    }
  }

  private summarise(): void {
    this.timer = undefined;
    const held = this.held;
    this.held = [];
    if (held.length === 0) return;
    const { title, body } = describe(held.at(-1)!);
    if (held.length === 1) this.show(title, `${body}\nAyrıntı: ${PANEL}`);
    else this.show(`Tuuf MCP Firewall: ${held.length} yeni olay`, `Sonuncusu ${body}\nAyrıntı: ${PANEL}`);
    this.quietUntil = this.now() + this.config.quietSeconds * 1000;
  }

  /** Shows what is still held, so a firewall that exits mid-burst does not swallow the summary. */
  async flush(): Promise<void> {
    if (!this.timer) return;
    clearTimeout(this.timer);
    this.summarise();
  }

  close(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
  }
}

/**
 * Native notification without dependencies. Title and body travel in environment variables, never in the
 * command line, so text from a server cannot become a command.
 */
export const showDesktop: Show = (title, body) => {
  const env = { ...process.env, TUUF_TITLE: title, TUUF_BODY: body };
  let cmd: string;
  let args: string[];
  if (process.platform === 'win32') {
    const script = [
      '$e = { param($s) [Security.SecurityElement]::Escape($s) }',
      "$x = \"<toast><visual><binding template='ToastGeneric'><text>$(& $e $env:TUUF_TITLE)</text><text>$(& $e $env:TUUF_BODY)</text></binding></visual></toast>\"",
      '[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]',
      '[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]',
      '$d = New-Object Windows.Data.Xml.Dom.XmlDocument; $d.LoadXml($x)',
      // PowerShell's own AppUserModelID: present on every Windows, so no shortcut has to be registered.
      '$app = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"',
      '[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($d))',
    ].join('; ');
    cmd = 'powershell.exe';
    args = ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', script];
  } else if (process.platform === 'darwin') {
    cmd = 'osascript';
    args = ['-e', 'display notification (system attribute "TUUF_BODY") with title (system attribute "TUUF_TITLE")'];
  } else {
    cmd = 'notify-send';
    args = ['--app-name=Tuuf MCP Firewall', title, body];
  }
  try {
    const child = spawn(cmd, args, { env, stdio: 'ignore', detached: true, windowsHide: true });
    child.on('error', () => {});
    child.unref();
  } catch {
    // No notifier on this machine: the audit log still has the event.
  }
};
