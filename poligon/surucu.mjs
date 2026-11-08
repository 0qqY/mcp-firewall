// Poligon sürücüsü: bir MCP sunucusunu firewall'un arkasında (ya da firewall'suz) başlatır, JSON-RPC ile konuşur,
// profil başına politika yazar, denetim kaydını okur. demo/more-mcps/_lib.mjs'ten farkı: istekler önceden
// sıralanmaz; bir sonraki adım öncekinin cevabına bağlı olabilir (saf ajanın uyup uymaması gibi).
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const POLIGON = dirname(fileURLToPath(import.meta.url));
export const REPO = resolve(POLIGON, '..');
export const CLI = join(REPO, 'dist', 'src', 'cli.js');
export const MODEL = process.env.MCP_FIREWALL_MODEL ?? join(REPO, 'models', 'mcp-pi-mmbert-mixraw-ab4-evilsandangels-30');
// ML eşiği: varsayılan model için 0,3. Önceki varsayılan (mix-ab4-lab-30) 0,9 ister; ikisini karşılaştırmak için:
// MCP_FIREWALL_MODEL=<mutlak yol>/mcp-pi-mmbert-mix-ab4-lab-30 POLIGON_ESIK=0.9 node poligon/dene.mjs eposta
export const ESIK = Number(process.env.POLIGON_ESIK ?? 0.3);
if (!(ESIK >= 0 && ESIK <= 1)) throw new Error(`POLIGON_ESIK 0 ile 1 arasında bir sayı olmalı (verilen: ${process.env.POLIGON_ESIK})`);
// Koşu dizinleri (denetim kayıtları, giden kutusu ...). İki poligon aynı anda çalışacaksa ikisine ayrı kök verin:
// POLIGON_CALISMA_KOK=poligon/.calisma/ikinci (aynı dizine yazan iki koşu birbirinin klasörünü siler).
export const CALISMA = process.env.POLIGON_CALISMA_KOK ? resolve(process.env.POLIGON_CALISMA_KOK) : join(POLIGON, '.calisma');

// Her profil hangi koruma katmanlarının açık olduğunu söyler. Kapalı katmanlar politikada AÇIKÇA kapatılır
// (firewall'un varsayılanı çoğunu açık tutar); böylece katmanlar tek tek ölçülebilir. katman: null = firewall yok.
export const TUM_KATMANLAR = { ml: true, kodcozme: true, gizliMetin: true, dlp: true, taint: true, sabitleme: true, tanimTarama: true };
export const POSTA_PROFILLERI = [
  { ad: 'kapali', baslik: 'kapalı', katman: null },
  { ad: 'okuma', baslik: 'okuma (ML)', katman: { ml: true, kodcozme: true, gizliMetin: true } },
  { ad: 'cikis', baslik: 'çıkış (DLP+taint)', katman: { dlp: true, taint: true } },
  { ad: 'tam', baslik: 'tam', katman: { ml: true, kodcozme: true, gizliMetin: true, dlp: true, taint: true } },
];
export const RUGPULL_PROFILLERI = [
  { ad: 'kapali', baslik: 'kapalı', katman: null },
  { ad: 'sabitleme', baslik: 'sabitleme', katman: { sabitleme: true } },
  { ad: 'tarama', baslik: 'tarama (desen+ML)', katman: { tanimTarama: true, ml: true } },
  { ad: 'tam', baslik: 'tam', katman: { sabitleme: true, tanimTarama: true, ml: true } },
];

export function politikaMetni(k, { denetim, pin }) {
  const j = JSON.stringify;
  return [
    'version: 1',
    'mode: enforce',
    `audit: { file: ${j(denetim)}, logAllowed: true }`,
    'tools: { default: allow }',
    `decoding: { enabled: ${!!k.kodcozme} }`,
    `hiddenText: { action: ${k.gizliMetin ? 'strip' : 'off'} }`,
    // onNew: ilk pinden sonra listeye eklenen yeni tool'a ne olsun? Varsayılan allow (kullanıcının gerçek politikası gibi);
    // POLIGON_ON_NEW=hide ile sıkı hâli denenir.
    `pinning: { enabled: ${!!k.sabitleme}, file: ${j(pin)}, onChange: hide, onNew: ${process.env.POLIGON_ON_NEW === 'hide' ? 'hide' : 'allow'}, onNameCollision: off, serverCode: off, prompts: off }`,
    `dlp: { enabled: ${!!k.dlp}, action: redact }`,
    `taint: { enabled: ${!!k.taint}, action: block, scope: server, sources: [{ match: read_email }], sinks: [{ match: send_email }] }`,
    `descriptionScan: { enabled: ${!!k.tanimTarama}, action: hide }`,
    'ml:',
    `  enabled: ${!!k.ml}`,
    `  model: ${j(MODEL)}`,
    `  threshold: ${ESIK}`,
    '  scan: { toolResults: block, toolDefinitions: hide }',
    '',
  ].join('\n');
}

export function onKontrol(profiller) {
  if (profiller.some((p) => p.katman) && !existsSync(CLI)) throw new Error(`Önce derleyin: npm run build (${CLI} yok)`);
  if (profiller.some((p) => p.katman?.ml) && !existsSync(MODEL)) throw new Error(`ML modeli bulunamadı: ${MODEL}. MCP_FIREWALL_MODEL ile yolunu verin.`);
}

export function temizDizin(ad) {
  const d = join(CALISMA, ad);
  rmSync(d, { recursive: true, force: true });
  mkdirSync(d, { recursive: true });
  return d;
}

export class Oturum {
  constructor(komut, argumanlar, env = {}) {
    this.sonId = 0;
    this.sunucuIstekleri = [];
    this.bekleyen = new Map();
    this.tampon = '';
    this.hata = '';
    this.kapandi = false;
    this.child = spawn(komut, argumanlar, {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: tmpdir(),
      env: { ...process.env, NODE_NO_WARNINGS: '1', ...env },
    });
    this.child.stdin.on('error', () => {});
    this.child.stderr.on('data', (d) => { this.hata = (this.hata + d).slice(-2000); });
    this.child.stdout.on('data', (d) => this.oku(String(d)));
    this.bitti = new Promise((coz) => {
      this.child.on('exit', () => {
        this.kapandi = true;
        const son = this.hata.trim().split('\n').pop();
        for (const b of this.bekleyen.values()) b.reddet(new Error(`süreç beklenmedik biçimde kapandı${son ? `: ${son}` : ''}`));
        this.bekleyen.clear();
        coz();
      });
    });
  }

  oku(parca) {
    this.tampon += parca;
    for (let i; (i = this.tampon.indexOf('\n')) >= 0; ) {
      const satir = this.tampon.slice(0, i).trim();
      this.tampon = this.tampon.slice(i + 1);
      if (!satir) continue;
      let msg;
      try { msg = JSON.parse(satir); } catch { continue; }
      // `method` taşıyan mesaj sunucudan (firewall dahil) gelen bir istek ya da bildirimdir. Kimliği bizim isteklerimizle
      // çakışabilir (ikisi de 1'den başlar); yanıt sayılırsa yanlış isteğin cevabı olarak teslim edilirdi.
      if (msg.method !== undefined) { this.sunucuIstegi(msg); continue; }
      const b = msg.id !== undefined ? this.bekleyen.get(msg.id) : undefined;
      if (b) { this.bekleyen.delete(msg.id); b.coz(msg); }
    }
  }

  // Sunucunun bize yönelttiği istek: ping'e cevap verilir, desteklenmeyenler (elicitation, sampling ...) hata ile reddedilir.
  sunucuIstegi(msg) {
    this.sunucuIstekleri.push(msg);
    if (msg.id === undefined) return; // bildirim: cevap istemez
    if (msg.method === 'ping') this.yaz({ id: msg.id, result: {} });
    else this.yaz({ id: msg.id, error: { code: -32601, message: 'poligon istemcisi bu isteği desteklemiyor' } });
  }

  yaz(msg) {
    if (!this.kapandi) this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...msg })}\n`);
  }

  istek(method, params, zamanAsimiMs = 90_000) {
    const id = ++this.sonId;
    return new Promise((coz, reddet) => {
      const zaman = setTimeout(() => { this.bekleyen.delete(id); reddet(new Error(`zaman aşımı: ${method}`)); }, zamanAsimiMs);
      this.bekleyen.set(id, { coz: (m) => { clearTimeout(zaman); coz(m); }, reddet: (e) => { clearTimeout(zaman); reddet(e); } });
      this.yaz({ id, method, params });
    });
  }

  async baslat() {
    await this.istek('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'poligon', version: '1' } });
    this.yaz({ method: 'notifications/initialized' });
  }

  async kapat() {
    if (this.kapandi) return;
    this.child.stdin.end();
    const zaman = setTimeout(() => this.child.kill(), 10_000);
    await this.bitti;
    clearTimeout(zaman);
  }
}

// katman null ise sunucu doğrudan (firewall'suz), değilse gerçek firewall'un (dist/src/cli.js) arkasında başlar.
export function oturumAc({ katman, ad, dizin, sunucu, env }) {
  if (!katman) return new Oturum('node', [sunucu], env);
  const politika = join(dizin, 'politika.yaml');
  writeFileSync(politika, politikaMetni(katman, { denetim: join(dizin, 'denetim.jsonl'), pin: join(dizin, 'pins.json') }));
  return new Oturum('node', [CLI, '--policy', politika, '--name', ad, '--', 'node', sunucu], env);
}

export function jsonlOku(dosya) {
  return existsSync(dosya) ? readFileSync(dosya, 'utf8').split('\n').filter((s) => s.trim()).map((s) => JSON.parse(s)) : [];
}
export const denetimOku = (dizin) => jsonlOku(join(dizin, 'denetim.jsonl'));
export const engelOlaylari = (denetim) => denetim.filter((e) => e.verdict === 'block' || e.verdict === 'redact');

// Bir denetim kaydının "reason" metni birden çok katmanı birlikte anabilir (ör. desen taraması + ML), hepsi listelenir.
const KATMANLAR = [
  [/poisoning|suspicious pattern|hidden unicode/i, 'desen'],
  [/ML classifier/i, 'ML'],
  [/definition changed|rug pull|held until approved/i, 'sabitleme'],
  [/sensitive data/i, 'DLP'],
  [/hidden characters|escape sequences/i, 'gizli metin'],
  [/allow list|denied by|not allowed/i, 'politika'],
  [/data flow|taint|carry private/i, 'taint'],
];
export const katmanlar = (neden = '') => {
  const bulunan = KATMANLAR.filter(([re]) => re.test(neden)).map(([, ad]) => ad);
  return bulunan.length ? bulunan : ['diğer'];
};
export const olayOzeti = (e) => `${katmanlar(e.reason).join('+')}${typeof e.score === 'number' ? ` ${e.score.toFixed(2)}` : ''}`;
