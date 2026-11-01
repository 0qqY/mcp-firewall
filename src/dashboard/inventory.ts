import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { evaluateToolName } from '../engine.js';
import { listPending } from '../pinning.js';
import { loadPolicy, type Policy } from '../policy.js';
import type { StoredEvent } from './server.js';

/** One `mcpServers` entry as an MCP client stores it. */
interface ClientEntry {
  name: string;
  client: string;
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
}

export interface RiskFactor {
  id: string;
  points: number;
  title: string;
  why: string;
  fix: string;
  /** Policy YAML or a command line that applies the fix. */
  snippet?: string;
}

export interface ServerRisk {
  /** The name the firewall logs under (`--name`), else the client's key. */
  name: string;
  clients: string[];
  firewalled: boolean;
  /** The wrapped server's command line or URL; secret-looking values masked. */
  target: string;
  transport: 'stdio' | 'http' | 'unknown';
  policyFile?: string;
  tools: { total: number; read: string[]; network: string[]; write: string[]; destructive: string[]; exec: string[]; denied: string[]; asked: string[] };
  week: { blocked: number; detections: number; lastSeen?: string };
  score: number;
  level: 'low' | 'medium' | 'high';
  factors: RiskFactor[];
  good: string[];
}

const WEEK = 7 * 86400e3;
const DETECTIONS = new Set(['block', 'would_block', 'redact', 'would_redact', 'warn']);
const BLOCKS = new Set(['block', 'would_block']);
const SECRET_KEY = /token|secret|passw|api[_-]?key|access[_-]?key|private[_-]?key|credential|(^|_)pat($|_)|auth/i;
const SECRET_VALUE = /^(ghp_|gho_|github_pat_|sk-|xox[abp]-|AKIA|glpat-|AIza)/;
const FIREWALL_CLI = /mcp-firewall|[\\/]dist[\\/]src[\\/]cli\.js$/i;

// Capability classes from tool-name words: create_issue -> create, issue; listRepos -> list, repos.
const CLASSES = {
  destructive: new Set(['delete', 'remove', 'destroy', 'purge', 'truncate', 'wipe', 'kill', 'erase', 'rm', 'unlink']),
  exec: new Set(['exec', 'execute', 'run', 'shell', 'command', 'cmd', 'eval', 'terminal', 'bash', 'powershell', 'script', 'spawn', 'process', 'evaluate']),
  write: new Set(['create', 'update', 'write', 'edit', 'push', 'merge', 'send', 'post', 'publish', 'upload', 'add', 'assign', 'fork', 'commit',
    'set', 'move', 'rename', 'request', 'submit', 'dismiss', 'close', 'reopen', 'comment', 'reply', 'patch', 'put', 'insert', 'save', 'mkdir', 'copy']),
  // Tools that reach arbitrary URLs bring untrusted content in and can carry data out in the URL itself.
  network: new Set(['fetch', 'navigate', 'http', 'https', 'url', 'browse', 'curl', 'wget', 'webhook', 'scrape', 'crawl']),
  read: new Set(['get', 'read', 'search', 'list', 'query', 'download', 'view', 'find', 'open', 'lookup', 'snapshot', 'show', 'status', 'log', 'diff']),
};
// Writes that land somewhere other people or services read (an issue, a push, a message), not local files or notes.
const EXTERNAL = new Set(['push', 'send', 'post', 'publish', 'upload', 'comment', 'reply', 'issue', 'pull', 'message', 'email', 'mail',
  'tweet', 'share', 'webhook', 'invite', 'fork', 'repository', 'release', 'review', 'gist', 'channel', 'chat', 'sms']);
// `drop` alone is drag and drop (browser_drop); with a store word it is DROP TABLE.
const isDestructive = (w: string[]) => w.some((x) => CLASSES.destructive.has(x)) ||
  (w.includes('drop') && w.some((x) => ['table', 'database', 'db', 'schema', 'collection', 'index', 'bucket'].includes(x)));
// Example taint rules lead with the tools that move the most data: file and content reads, pushes and sends.
const READ_FIRST = ['file', 'contents', 'content', 'read', 'fetch', 'download', 'email', 'message', 'document'];
const SINK_FIRST = ['push', 'send', 'post', 'upload', 'publish', 'file', 'create', 'merge', 'write'];
const byImpact = (names: string[], order: string[]) => {
  const rank = (t: string) => Math.min(...words(t).map((w) => (order.includes(w) ? order.indexOf(w) : order.length)));
  return [...names].sort((a, b) => rank(a) - rank(b));
};
const words = (name: string) => name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

/** Claude Code (user and project scope) and Claude Desktop config files on this machine. */
export function defaultClientConfigs(home = homedir()): [file: string, client: string][] {
  const appData = process.env.APPDATA ?? join(home, 'AppData', 'Roaming');
  const desktop = process.platform === 'darwin'
    ? join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
    : process.platform === 'win32' ? join(appData, 'Claude', 'claude_desktop_config.json') : join(home, '.config', 'Claude', 'claude_desktop_config.json');
  return [[join(home, '.claude.json'), 'Claude Code'], [desktop, 'Claude Desktop']];
}

function entriesOf(servers: unknown, client: string): ClientEntry[] {
  if (!servers || typeof servers !== 'object') return [];
  return Object.entries(servers as Record<string, Record<string, unknown>>).flatMap(([name, s]) => {
    if (!s || typeof s !== 'object') return [];
    const args = Array.isArray(s.args) ? s.args.filter((a): a is string => typeof a === 'string') : [];
    const env = s.env && typeof s.env === 'object' ? Object.fromEntries(Object.entries(s.env).filter(([, v]) => typeof v === 'string')) as Record<string, string> : {};
    return [{ name, client, command: typeof s.command === 'string' ? s.command : undefined, args, env, url: typeof s.url === 'string' ? s.url : undefined }];
  });
}

export function readClientEntries(files: [file: string, client: string][]): ClientEntry[] {
  const out: ClientEntry[] = [];
  for (const [file, client] of files) {
    if (!existsSync(file)) continue;
    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(readFileSync(file, 'utf8'));
    } catch {
      continue;
    }
    out.push(...entriesOf(raw.mcpServers, client));
    // Claude Code keeps project-scoped servers under projects[<path>].mcpServers.
    if (raw.projects && typeof raw.projects === 'object') {
      for (const [path, p] of Object.entries(raw.projects as Record<string, Record<string, unknown>>)) {
        const folder = path.split(/[\\/]/).filter(Boolean).pop() ?? path;
        out.push(...entriesOf(p?.mcpServers, `${client} (${folder})`));
      }
    }
  }
  return out;
}

const mask = (a: string) => (SECRET_VALUE.test(a) || /^--?[\w-]*(token|key|secret|password)[\w-]*=/i.test(a) ? a.replace(/=.*$|^(.{4}).*$/, (_m, p) => (p ? `${p}…` : '=…')) : a);

interface Parsed {
  firewalled: boolean;
  id: string;
  policyFile?: string;
  command?: string;
  args: string[];
  url?: string;
}

/** Splits `mcp-firewall [opts] -- <command>` (and the gateway form) into the firewall part and the wrapped server. */
function parseEntry(e: ClientEntry): Parsed {
  const all = [e.command ?? '', ...e.args];
  const cli = all.findIndex((a) => FIREWALL_CLI.test(a));
  if (cli === -1) return { firewalled: false, id: e.name, command: e.command, args: e.args, url: e.url };
  const rest = all.slice(cli + 1);
  const opt = (flag: string) => {
    const i = rest.indexOf(flag);
    return i !== -1 && i < (rest.indexOf('--') === -1 ? rest.length : rest.indexOf('--')) ? rest[i + 1] : undefined;
  };
  const policyFile = opt('--policy') ?? e.env.MCP_FIREWALL_POLICY;
  if (rest[0] === 'gateway') {
    const url = opt('--upstream');
    return { firewalled: true, id: opt('--name') ?? url ?? e.name, policyFile, args: [], url };
  }
  const sep = rest.indexOf('--');
  const wrapped = sep === -1 ? [] : rest.slice(sep + 1);
  return { firewalled: true, id: opt('--name') ?? (wrapped.join(' ') || e.name), policyFile, command: wrapped[0], args: wrapped.slice(1) };
}

/** How the server's code is fetched: pinned (digest or exact version), floating, local or remote. */
function sourcePinning(p: Parsed): { kind: 'pinned' | 'tag' | 'floating' | 'local' | 'remote'; what: string } {
  if (p.url) return { kind: 'remote', what: p.url };
  const cmd = (p.command ?? '').split(/[\\/]/).pop()?.replace(/\.(cmd|exe)$/i, '').toLowerCase() ?? '';
  const positional = p.args.filter((a) => !a.startsWith('-'));
  if (cmd === 'docker' || cmd === 'podman') {
    const image = p.args.find((a, i) => i > 0 && !a.startsWith('-') && /^[\w.-]+(:\d+)?\/[\w./-]+(:[\w.-]+)?(@sha256:[0-9a-f]{64})?$/.test(a) && !p.args[i - 1].startsWith('--env'));
    if (!image) return { kind: 'floating', what: 'docker' };
    if (image.includes('@sha256:')) return { kind: 'pinned', what: image.split('@')[0] };
    const tag = image.split('/').pop()!.split(':')[1];
    return { kind: tag && tag !== 'latest' ? 'tag' : 'floating', what: image };
  }
  if (['npx', 'bunx', 'uvx', 'pipx', 'pnpx'].includes(cmd) || (['pnpm', 'yarn', 'bun'].includes(cmd) && positional[0] === 'dlx')) {
    const pkg = positional.find((a) => a !== 'dlx' && a !== 'run');
    if (!pkg) return { kind: 'floating', what: cmd };
    const version = pkg.startsWith('@') ? pkg.slice(1).split('@')[1] : pkg.split(/@|==/)[1];
    return { kind: version && /^\d/.test(version) ? 'pinned' : 'floating', what: pkg };
  }
  return { kind: 'local', what: positional[0] ?? cmd };
}

/** Pinned tool names of a server, and the changes still waiting for `pins approve`. */
function pinsOf(policy: Policy, id: string): { tools: string[]; pending: string[] } {
  const names = (o: Record<string, unknown> | undefined) => Object.keys(o ?? {}).filter((k) => !k.startsWith('@'));
  if (!policy.pinning.file) return { tools: [], pending: [] };
  let pins: Record<string, Record<string, unknown>> = {};
  try {
    if (existsSync(policy.pinning.file)) pins = JSON.parse(readFileSync(policy.pinning.file, 'utf8'));
  } catch {
    // unreadable pin file: no tools known
  }
  let pending: string[] = [];
  try {
    pending = Object.keys(listPending(policy.pinning.file)[id] ?? {});
  } catch {
    // no pending file
  }
  return { tools: names(pins[id]), pending };
}

const list = (names: string[], max = 4) => (names.length > max ? `${names.slice(0, max).join(', ')} ve ${names.length - max} araç daha` : names.join(', '));

/** Scores one server 0–100 from what the firewall can see: config, policy, pinned tools and the last week of audit. */
export function assessServer(input: {
  name: string;
  clients: string[];
  parsed: Parsed;
  policy?: Policy;
  policyError?: string;
  toolNames: string[];
  /** Pin-store entries waiting for approval (changed tools, prompts or server code). */
  pending?: string[];
  events: StoredEvent[];
  env: Record<string, string>;
  now?: number;
}): ServerRisk {
  const { parsed, policy, toolNames, events } = input;
  const now = input.now ?? Date.now();
  const factors: RiskFactor[] = [];
  const good: string[] = [];
  const add = (f: RiskFactor) => factors.push(f);

  const tools = { total: toolNames.length, read: [] as string[], network: [] as string[], write: [] as string[], destructive: [] as string[], exec: [] as string[], denied: [] as string[], asked: [] as string[] };
  for (const t of toolNames) {
    const w = words(t);
    const decision = policy ? evaluateToolName(policy, t) : { allowed: true };
    if (!decision.allowed) tools.denied.push(t);
    else if ('ask' in decision && decision.ask) tools.asked.push(t);
    const open = decision.allowed && !('ask' in decision && decision.ask);
    if (!open) continue;
    if (isDestructive(w)) tools.destructive.push(t);
    else if (w.some((x) => CLASSES.exec.has(x))) tools.exec.push(t);
    else if (w.some((x) => CLASSES.network.has(x))) tools.network.push(t);
    else if (w.some((x) => CLASSES.write.has(x))) tools.write.push(t);
    else if (w.some((x) => CLASSES.read.has(x))) tools.read.push(t);
  }

  if (!parsed.firewalled) {
    add({
      id: 'unprotected', points: 45, title: "Firewall'un arkasında değil",
      why: "Bu sunucunun trafiği firewall'dan geçmiyor. Araç tanımları, sonuçlar ve çağrılar hiç denetlenmiyor; enjeksiyon, veri sızıntısı ve sonradan değişen araçlar fark edilmez.",
      fix: "Sunucuyu istemci ayarında mcp-firewall ile sar. Komutun başına firewall'u ekle, asıl komutu '--' işaretinden sonra yaz.",
      snippet: parsed.url
        ? `mcp-firewall gateway --name ${input.name} --upstream ${parsed.url}`
        : `mcp-firewall --name ${input.name} -- ${[parsed.command, ...parsed.args.map(mask)].filter(Boolean).join(' ')}`,
    });
  } else good.push("Trafik firewall'dan geçiyor");

  if (input.policyError) {
    add({ id: 'policy-error', points: 10, title: 'Politika dosyası okunamadı', why: `Bu sunucunun politika dosyası okunamadı (${input.policyError}). Firewall bu durumda başlamaz; sunucu çalışmıyor olabilir.`, fix: 'Dosya yolunu ve YAML sözdizimini kontrol et.' });
  }

  if (policy && parsed.firewalled) {
    if (policy.mode === 'monitor') {
      add({ id: 'monitor', points: 20, title: 'İzleme modunda: hiçbir şey engellenmiyor', why: 'Politika monitor modunda. Firewall tehditleri yalnızca kaydediyor, engellemiyor.', fix: 'Yanlış alarmlar azaldıysa engelleme moduna geç.', snippet: 'mode: enforce' });
    } else good.push('Engelleme modu açık');

    if (!policy.ml.enabled) {
      add({ id: 'ml-off', points: 15, title: 'ML katmanı kapalı', why: 'Araç sonuçlarındaki prompt enjeksiyonu yalnızca desenlerle aranıyor; desene uymayan saldırılar geçer.', fix: 'ML sınıflandırıcıyı aç ve araç sonuçlarında engellemeye ayarla.', snippet: 'ml:\n  enabled: true\n  scan:\n    toolResults: block' });
    } else if (policy.ml.scan.toolResults !== 'block') {
      add({ id: 'ml-results', points: 10, title: 'Araç sonuçlarındaki enjeksiyon engellenmiyor', why: `ML açık ama araç sonuçlarında yalnızca '${policy.ml.scan.toolResults}' ayarında. Saldırı içeren bir sonuç modele ulaşır.`, fix: 'Araç sonuçlarında engellemeye geç.', snippet: 'ml:\n  scan:\n    toolResults: block' });
    } else good.push('Araç sonuçları ML ile taranıp engelleniyor');

    if (!policy.dlp.enabled) {
      add({ id: 'dlp-off', points: 10, title: 'Veri sızıntısı (DLP) kapalı', why: 'Anahtar, token ve parola gibi gizli bilgiler maskelenmeden modele ya da sunucuya gidebilir.', fix: 'DLP\'yi aç; istekleri ve yanıtları maskele.', snippet: 'dlp:\n  enabled: true\n  scanRequests: true\n  scanResponses: true\n  action: redact' });
    } else if (!policy.dlp.scanRequests || !policy.dlp.scanResponses) {
      add({ id: 'dlp-half', points: 5, title: 'DLP yalnızca tek yönde', why: `DLP ${policy.dlp.scanRequests ? 'yanıtları' : 'istekleri'} taramıyor.`, fix: 'İki yönü de tara.', snippet: 'dlp:\n  scanRequests: true\n  scanResponses: true' });
    } else good.push('Gizli bilgiler iki yönde maskeleniyor');

    if (!policy.pinning.enabled) {
      add({ id: 'pin-off', points: 10, title: 'Araç sabitleme kapalı', why: 'Sunucu bir aracın tanımını sonradan değiştirirse (rug pull) bunu fark eden yok.', fix: 'Sabitlemeyi aç; değişen araçları onaya kadar gizle.', snippet: 'pinning:\n  enabled: true\n  onChange: hide\n  onNew: hide' });
    } else {
      good.push('Araç tanımları sabitleniyor');
      if (policy.pinning.onNew === 'allow') {
        add({ id: 'pin-new', points: 4, title: 'Yeni araçlar onaysız kullanılabiliyor', why: 'Sunucu sonradan yeni bir araç eklerse ilk kullanımda güvenilir sayılıyor.', fix: 'Yeni araçları onaya kadar gizle; onaylamak için: mcp-firewall pins approve --name ' + input.name, snippet: 'pinning:\n  onNew: hide' });
      }
    }

    if (tools.exec.length) {
      add({ id: 'exec', points: 20, title: 'Komut/kod çalıştıran araçlar onaysız', why: `${list(tools.exec)} kod ya da komut çalıştırabiliyor ve politika bunlara onaysız izin veriyor. Enjeksiyonla ele geçen bir model bu araçlarla makinede iş yapabilir.`, fix: 'Bu araçları kullanıcı onayına bağla ya da kapat; gerekiyorsa argümanlara izin listesi koy.', snippet: `tools:\n  rules:\n${tools.exec.slice(0, 3).map((t) => `    - match: "${t}"\n      action: ask`).join('\n')}` });
    }
    if (tools.destructive.length) {
      add({ id: 'destructive', points: 15, title: 'Silme araçları onaysız', why: `${list(tools.destructive)} geri alınamaz silme yapabiliyor ve onaysız çalışıyor.`, fix: 'Silme araçlarını kapat ya da onaya bağla.', snippet: 'tools:\n  rules:\n    - match: "delete_*"\n      action: deny' });
    } else if (tools.denied.some((t) => isDestructive(words(t)))) good.push('Silme araçları kapalı');

    // Untrusted content in, a channel out: what an injection needs to exfiltrate (the "lethal trifecta").
    const taintOn = policy.taint.enabled && policy.taint.sources.length > 0 && policy.taint.sinks.length > 0;
    const inbound = [...tools.network, ...tools.read];
    const outbound = [...tools.write.filter((t) => words(t).some((x) => EXTERNAL.has(x))), ...tools.network, ...tools.exec];
    if (inbound.length && outbound.length && !taintOn) {
      add({
        id: 'trifecta', points: 15, title: 'Okunan içerik dışarı yazılabiliyor',
        why: `Sunucu dışarıdan içerik okuyor (${list(inbound, 3)}) ve aynı oturumda dışarı yazabiliyor (${list(outbound, 3)}). Okunan bir metindeki enjeksiyon, özel veriyi yazma aracıyla dışarı taşıyabilir. Veri akışı takibi (taint) kapalı.`,
        fix: 'Taint takibini aç: okuma araçlarının döndürdüğü içerik yazma araçlarının argümanında görünürse çağrı onaya düşsün.',
        snippet: `taint:\n  enabled: true\n  action: ask\n  sources:\n${byImpact(inbound, READ_FIRST).slice(0, 3).map((t) => `    - match: "${t}"\n      label: private`).join('\n')}\n  sinks:\n${byImpact(outbound, SINK_FIRST).slice(0, 3).map((t) => `    - match: "${t}"`).join('\n')}`,
      });
    } else if (taintOn) good.push('Veri akışı takibi (taint) açık');
    if (tools.write.length && !tools.asked.length && policy.tools.default !== 'ask') {
      add({ id: 'write', points: 8, title: `${tools.write.length} yazma aracı onaysız`, why: `${list(tools.write)} dışarıda kalıcı değişiklik yapıyor ve hiçbiri onay istemiyor.`, fix: 'En etkili olanları (birleştirme, dosya yazma, gönderme) kullanıcı onayına bağla.', snippet: `tools:\n  rules:\n${byImpact(tools.write, SINK_FIRST).slice(0, 3).map((t) => `    - match: "${t}"\n      action: ask`).join('\n')}` });
    } else if (tools.asked.length) good.push(`${tools.asked.length} araç kullanıcı onayı istiyor`);
  }

  if (!toolNames.length && parsed.firewalled) {
    good.push('Araç listesi henüz görülmedi; puan araçlar sabitlenince kesinleşir');
  }

  const src = sourcePinning(parsed);
  if (src.kind === 'floating') {
    add({ id: 'floating', points: 10, title: 'Sürüm sabit değil', why: `${src.what} her başlatmada en son sürümü çekiyor. Paket ele geçirilirse (postmark-mcp gibi) değişen kod sessizce çalışır.`, fix: 'Paketi tam sürümle, Docker imajını digest ile sabitle.', snippet: src.what.includes('/') && !src.what.startsWith('@') ? `${src.what.split(':')[0]}@sha256:<digest>` : `${src.what.split('@')[0] || src.what}@<sürüm>` });
  } else if (src.kind === 'tag') {
    add({ id: 'tag', points: 5, title: 'İmaj etiketle sabit, digest ile değil', why: `${src.what} etiketi sonradan başka bir imaja taşınabilir.`, fix: 'İmajı digest ile sabitle.', snippet: `${src.what}@sha256:<digest>` });
  } else if (src.kind === 'pinned') good.push(`Kod sürümü sabit (${src.what})`);
  else if (src.kind === 'remote') {
    add({ id: 'remote', points: 5, title: 'Uzak sunucu', why: 'Kod başka bir makinede çalışıyor; firewall sunucu kodunu sabitleyemez, yalnızca trafiği görür.', fix: 'Araç sabitlemeyi açık tut ve yeni araçları onaya bağla.' });
  }

  const secrets = Object.entries(input.env).filter(([k, v]) => SECRET_KEY.test(k) && v.length >= 8 && !/^\$\{.+\}$/.test(v)).map(([k]) => k);
  const argSecret = [parsed.command ?? '', ...parsed.args].some((a) => SECRET_VALUE.test(a.replace(/^--?[\w-]+=/, '')));
  if (secrets.length || argSecret) {
    add({ id: 'secret', points: 10, title: 'Gizli bilgi ayar dosyasında açık', why: `${secrets.length ? secrets.join(', ') : 'Komut satırı'} istemcinin ayar dosyasında düz metin olarak duruyor. O dosyayı okuyan her araç ya da sunucu bu anahtara ulaşır.`, fix: 'Anahtarı ayrı bir dosyaya (--env-file) ya da ortam değişkenine taşı ve en dar yetkiyle yeniden üret.' });
  } else if (parsed.args.includes('--env-file')) good.push('Anahtarlar ayrı bir env dosyasında');

  const recent = events.filter((e) => now - Date.parse(e.ts) < WEEK);
  const week = { blocked: recent.filter((e) => BLOCKS.has(e.verdict)).length, detections: recent.filter((e) => DETECTIONS.has(e.verdict)).length, lastSeen: events.at(-1)?.ts };
  const attacks = recent.filter((e) => BLOCKS.has(e.verdict) && (e.category === 'injection' || e.category === 'poisoning'));
  const rugpulls = recent.filter((e) => e.category === 'rugpull' && e.verdict !== 'allow');
  const pending = input.pending ?? [];
  if (pending.length) {
    add({ id: 'rugpull', points: 15, title: `${pending.length} değişiklik onay bekliyor`, why: `Sabitlenen ${list(pending.map((p) => p.replace(/^@prompt:|#.*$/g, '').replace('@server-code', 'sunucu kodu')))} değişmiş ve onaya kadar gizleniyor ya da engelleniyor.${rugpulls.length ? ` Son 7 günde ${rugpulls.length} değişiklik olayı var.` : ''}`, fix: `Olaylar sayfasında değişikliği incele. Bilinen bir güncellemeyse onayla, değilse sunucuyu kaldır.`, snippet: `mcp-firewall pins list
mcp-firewall pins approve --name ${input.name}` });
  } else if (rugpulls.length) good.push(`Son 7 gündeki ${rugpulls.length} araç değişikliği onaylandı; bekleyen yok`);
  if (attacks.length) {
    add({ id: 'attacks', points: Math.min(10, 3 + attacks.length), title: `Son 7 günde ${attacks.length} saldırı girişimi`, why: 'Bu sunucudan gelen içerikte enjeksiyon ya da zehirli araç tanımı yakalandı ve engellendi. Sunucu güvenilmeyen içerik taşıyor.', fix: 'Olayları incele; yanlış alarm olanları etiketle. Engelleme ayarlarını gevşetme.' });
  }

  const score = Math.min(100, factors.reduce((s, f) => s + f.points, 0));
  factors.sort((a, b) => b.points - a.points);
  return {
    name: input.name,
    clients: input.clients,
    firewalled: parsed.firewalled,
    target: parsed.url ?? [parsed.command, ...parsed.args.map(mask)].filter(Boolean).join(' '),
    transport: parsed.url ? 'http' : parsed.command ? 'stdio' : 'unknown',
    policyFile: parsed.policyFile,
    tools,
    week,
    score,
    level: score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low',
    factors,
    good,
  };
}

/** Every MCP server the clients on this machine know, plus servers seen only in the audit log, riskiest first. */
export function inventory(opts: { configFiles: [string, string][]; events: StoredEvent[]; fallbackPolicy: Policy; now?: number }): ServerRisk[] {
  const byId = new Map<string, { entry: ClientEntry; parsed: Parsed; clients: string[] }>();
  for (const entry of readClientEntries(opts.configFiles)) {
    const parsed = parseEntry(entry);
    const known = byId.get(parsed.id);
    if (known) known.clients.push(entry.client);
    else byId.set(parsed.id, { entry, parsed, clients: [entry.client] });
  }
  const policies = new Map<string, { policy?: Policy; error?: string }>();
  const policyFor = (file?: string) => {
    const key = file ?? '';
    if (!policies.has(key)) {
      try {
        policies.set(key, { policy: loadPolicy(file) });
      } catch (err) {
        policies.set(key, { error: (err as Error).message });
      }
    }
    return policies.get(key)!;
  };

  const out: ServerRisk[] = [];
  for (const [id, { entry, parsed, clients }] of byId) {
    const { policy, error } = parsed.firewalled ? policyFor(parsed.policyFile) : { policy: undefined, error: undefined };
    const pins = policy ? pinsOf(policy, id) : { tools: [], pending: [] };
    out.push(assessServer({
      name: id, clients, parsed, policy, policyError: error, env: entry.env, now: opts.now,
      toolNames: pins.tools, pending: pins.pending,
      events: opts.events.filter((e) => e.server === id),
    }));
  }
  // Seen in the audit log but in no client config: another client, a removed server, or a test run.
  const audited = [...new Set(opts.events.map((e) => e.server).filter(Boolean))].filter((s) => !byId.has(s));
  for (const id of audited) {
    const events = opts.events.filter((e) => e.server === id);
    const url = /^https?:\/\//.test(id) ? id : undefined;
    const pins = pinsOf(opts.fallbackPolicy, id);
    const risk = assessServer({
      name: id, clients: [], parsed: { firewalled: true, id, args: [], url }, policy: opts.fallbackPolicy, env: {}, now: opts.now,
      toolNames: pins.tools, pending: pins.pending, events,
    });
    risk.good.unshift('Yalnızca olay kaydında görülüyor; bu makinedeki istemci ayarlarında yok');
    out.push(risk);
  }
  return out.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
}
