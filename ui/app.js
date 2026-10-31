// Tuuf MCP Firewall dashboard. Audit data is attacker-influenced (tool names, excerpts), so every value
// reaches the DOM through textContent/attributes via h(); nothing is ever assigned to innerHTML.

const SVG_NS = 'http://www.w3.org/2000/svg';

const ICONS = {
  home: 'M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z',
  shield: 'M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z',
  server: 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01',
  cpu: 'M7 7h10v10H7zM10 10h4v4h-4zM9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3',
  sliders: 'M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1M15 4v4M9 10v4M17 16v4',
  help: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1 1.5V14M12 17h.01',
  bell: 'M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.9 1.9 0 0 0 3.4 0',
  arrowRight: 'M5 12h14M13 6l6 6-6 6',
  arrowLeft: 'M19 12H5M11 6l-6 6 6 6',
  plus: 'M12 5v14M5 12h14',
  alert: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 8v4M12 16h.01',
  lock: 'M6 11h12v10H6zM8 11V7a4 4 0 1 1 8 0v4',
  check: 'M20 6 9 17l-5-5',
  x: 'M18 6 6 18M6 6l12 12',
  search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3',
  download: 'M12 3v12M7 10l5 5 5-5M5 21h14',
  zap: 'M13 2 3 14h9l-1 8 10-12h-9z',
  file: 'M14 3H6v18h12V7zM14 3v4h4',
  refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5',
  activity: 'M22 12h-4l-3 9L9 3l-3 9H2',
  copy: 'M9 9h11v11H9zM5 15H4V4h11v1',
};

const CATEGORIES = {
  injection: { label: 'Prompt injection', short: 'Injection', icon: 'zap', bg: '#fff1e6', fg: '#e8590c' },
  poisoning: { label: 'Tool poisoning', short: 'Poisoning', icon: 'alert', bg: '#ffe9ea', fg: '#e5484d' },
  dlp: { label: 'Veri sızıntısı', short: 'DLP', icon: 'lock', bg: '#e6ecff', fg: '#0038ff' },
  rugpull: { label: 'Rug pull', short: 'Rug pull', icon: 'refresh', bg: '#f3e8ff', fg: '#8e4ec6' },
  policy: { label: 'Politika ihlali', short: 'Politika', icon: 'shield', bg: '#e8f6ee', fg: '#30a46c' },
  method: { label: 'Yetkisiz metod', short: 'Metod', icon: 'server', bg: '#e6f4fe', fg: '#0b84d6' },
  protocol: { label: 'Protokol hatası', short: 'Protokol', icon: 'file', bg: '#f1f2f4', fg: '#646a73' },
  other: { label: 'Diğer', short: 'Diğer', icon: 'activity', bg: '#f1f2f4', fg: '#646a73' },
};
const RADAR = ['injection', 'poisoning', 'dlp', 'rugpull', 'policy', 'method'];

// cls picks the pill/marker shape: blk square, msk diamond, wrn hollow diamond, ok circle.
const VERDICTS = {
  block: { label: 'Engellendi', cls: 'blk' },
  would_block: { label: 'Engellenirdi', cls: 'wrn' },
  redact: { label: 'Maskelendi', cls: 'msk' },
  would_redact: { label: 'Maskelenirdi', cls: 'wrn' },
  warn: { label: 'Uyarı', cls: 'wrn' },
  info: { label: 'Bilgi', cls: '' },
  allow: { label: 'İzin', cls: 'ok' },
};
const DETECTIONS = new Set(['block', 'would_block', 'redact', 'would_redact', 'warn']);
const BLOCKS = new Set(['block', 'would_block']);
const AVATAR_COLORS = ['#0038ff', '#e8590c', '#30a46c', '#8e4ec6', '#0b84d6', '#e5484d', '#d6409f', '#12a594'];
const DAYS = ['Paz', 'Pzt', 'Sal', 'Çar', 'Per', 'Cum', 'Cmt'];
const THRESHOLDS = [0.5, 0.7, 0.8, 0.9, 0.95];
const DAY = 86400e3;

const VIEWS = { overview: 'Genel bakış', events: 'Olaylar', ml: 'ML olayları' };
const EVENT_TABS = [['detections', 'Tespitler'], ['blocked', 'Engellenen'], ['masked', 'Maskelenen'], ['warn', 'Uyarılar'], ['allowed', 'İzin'], ['all', 'Tümü']];
const MASKS = new Set(['redact', 'would_redact']);

const state = {
  view: VIEWS[storage('view')] ? storage('view') : 'overview',
  mlFilter: 'all',
  server: '',
  data: null,
  signature: '',
  selectedId: null,
  tab: 'detections',
  category: '',
  q: '',
  /** Event list time window in ms (the overview's 24-hour counts open with one); null = all time. */
  since: null,
  overviewId: null,
  radarMode: 'list',
  threshold: null,
  lastRead: null,
};

// ---------- helpers ----------

function storage(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(`mcpfw.${key}`);
    localStorage.setItem(`mcpfw.${key}`, value);
  } catch {
    return null;
  }
}

function h(tag, props = {}, ...children) {
  const svg = tag.startsWith('svg:');
  const el = svg ? document.createElementNS(SVG_NS, tag.slice(4)) : document.createElement(tag);
  for (const [k, v] of Object.entries(props ?? {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'style') Object.assign(el.style, v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
  return el;
}

function icon(name, size = 18, stroke = 1.8) {
  return h('svg:svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': stroke, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' },
    h('svg:path', { d: ICONS[name] }));
}

const pad2 = (n) => String(n).padStart(2, '0');
const evId = (e) => `EVT-${pad2(e.id).padStart(4, '0')}`;
const ago = (ts) => Date.now() - Date.parse(ts);

function rel(ts) {
  const s = ago(ts) / 1000;
  if (s < 45) return 'az önce';
  if (s < 3600) return `${Math.round(s / 60)} dk önce`;
  if (s < 86400) return `${Math.round(s / 3600)} sa önce`;
  return `${Math.round(s / 86400)} gün önce`;
}

const fmtTime = (ts) => new Date(ts).toLocaleString('tr-TR', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' });
const subject = (e) => e.tool || e.method || 'firewall';
const NORMAL = { label: 'Normal trafik', short: 'Normal', icon: 'check', bg: '#e8f6ee', fg: '#30a46c' };
const cat = (e) => (e.verdict === 'allow' ? NORMAL : CATEGORIES[e.category] ?? CATEGORIES.other);
const verdict = (e) => VERDICTS[e.verdict] ?? VERDICTS.info;
const pill = (e) => h('span', { class: `vd ${verdict(e).cls}` }, verdict(e).label);
const clock = (ts) => new Date(ts).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });

function avatarColor(name) {
  let hash = 0;
  for (const ch of name) hash = (hash * 31 + ch.charCodeAt(0)) | 0;
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
}

function toast(text) {
  const el = document.getElementById('toast');
  el.textContent = text;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (el.hidden = true), 2600);
}

/** Clipboard API first, then the older execCommand path (some embedded browsers deny the API). */
async function writeClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch { /* permission denied or no focus */ }
  const area = h('textarea', { readonly: true, 'aria-hidden': 'true', class: 'copy-buffer' }, text);
  document.body.append(area);
  area.select();
  const ok = document.execCommand('copy');
  area.remove();
  return ok;
}

/** Copies `text`; when the browser refuses, shows it so it can be copied by hand. */
async function copy(text, message) {
  if (await writeClipboard(text)) return toast(message);
  textDialog('Panoya kopyalanamadı', 'Tarayıcı panoya yazmaya izin vermedi. Metin seçili, Ctrl+C ile kopyala.', text, message);
}

/** Modal with a read-only block of text and a copy button. */
function textDialog(title, note, text, copied = 'Panoya kopyalandı') {
  document.getElementById('text-dialog')?.remove();
  // Removed on close directly too: the `close` event (Escape) can arrive late in a background tab.
  const close = () => { if (dialog.open) dialog.close(); dialog.remove(); };
  const pre = h('pre', { tabindex: '0' }, text);
  const status = () => dialog.querySelector('.text-dialog-status');
  const dialog = h('dialog', { id: 'text-dialog', class: 'text-dialog', 'aria-labelledby': 'text-dialog-title', onclose: close },
    h('h2', { id: 'text-dialog-title' }, title),
    note ? h('p', {}, note) : null,
    pre,
    h('p', { class: 'text-dialog-status', role: 'status' }),
    h('div', { class: 'text-dialog-act' },
      h('button', { class: 'btn-ghost-dark', onclick: close }, 'Kapat'),
      h('button', { class: 'btn-dark', onclick: async () => {
        if (await writeClipboard(text)) { close(); return toast(copied); }
        getSelection().selectAllChildren(pre);
        status().textContent = 'Tarayıcı panoya izin vermedi: metin seçili, Ctrl+C ile kopyala.';
      } }, icon('copy', 14), 'Kopyala')));
  dialog.addEventListener('click', (ev) => { if (ev.target === dialog) close(); });
  document.body.append(dialog);
  dialog.showModal();
  getSelection().selectAllChildren(pre);
}

/** Training-row count: labelled events that carried text. Only those rows end up in the download. */
const trainableCount = ({ events, labels }) => events.filter((e) => labels[e.id] && e.excerpt).length;

/** The labels download, which explains itself instead of saving an empty file when nothing is labelled yet. */
function labelsLink(cls, d, text = 'Etiketleri indir') {
  const n = trainableCount(d);
  return h('a', {
    class: cls, href: '/api/labels.jsonl', download: 'mcp-firewall-labels.jsonl', style: { textDecoration: 'none' },
    title: n ? `${n} eğitim satırı` : 'Henüz eğitime uygun etiket yok',
    onclick: (ev) => {
      if (n) return;
      ev.preventDefault();
      toast('İndirilecek etiket yok: önce metni olan bir tespiti Doğru tespit ya da Yanlış alarm olarak işaretle');
    },
  }, icon('download', 14), `${text} (${n})`);
}

const MARKER = /(\[REDACTED:[^\]]+\])/;

/** Context text with each `[REDACTED:…]` placeholder drawn as a masked block. */
function redactedText(text) {
  return text.split(MARKER).map((part, i) => (i % 2 ? h('mark', { class: 'redacted' }, part.slice(10, -1)) : part));
}

/** What DLP masked and where. The audit log never holds the secret, only its type, path and last characters. */
function maskedBlock(e) {
  if (!MASKS.has(e.verdict) && e.category !== 'dlp') return null;
  if (!e.masked?.length) {
    return h('div', { class: 'masked' },
      h('div', { class: 'masked-h' }, 'Maskelenen veri'),
      h('p', { class: 'masked-note' }, 'Bu kayıtta yalnızca türü ve sayısı var (eski sürümde yazılmış). Yeni kayıtlarda yeri ve çevresindeki metin de görünür.'));
  }
  return h('div', { class: 'masked' },
    h('div', { class: 'masked-h' }, `Maskelenen veri · ${e.masked.length}`),
    e.masked.map((m) => h('div', { class: 'masked-row' },
      h('div', { class: 'masked-top' },
        h('b', {}, m.detector),
        h('span', {}, m.where ? `konum: ${m.where}` : 'konum: metin'),
        m.hint ? h('span', { class: 'hint' }, `…${m.hint}`) : null),
      m.context ? h('div', { class: 'masked-ctx' }, redactedText(m.context)) : null)),
    h('p', { class: 'masked-note' }, 'Sırrın kendisi hiçbir yere kaydedilmez; yalnızca son 4 karakteri gösterilir.'));
}

function tile(e, size = 34) {
  const c = cat(e);
  return h('span', { class: 'tile', style: { background: c.bg, color: c.fg, width: `${size}px`, height: `${size}px` } }, icon(c.icon, 16));
}

/** Monotone cubic interpolation: smooth like the reference chart, but never dips below zero. */
function monotonePath(pts) {
  const n = pts.length;
  if (n < 2) return '';
  const dx = [], m = [];
  for (let i = 0; i < n - 1; i++) {
    dx[i] = pts[i + 1][0] - pts[i][0];
    m[i] = (pts[i + 1][1] - pts[i][1]) / dx[i];
  }
  const t = [m[0]];
  for (let i = 1; i < n - 1; i++) t[i] = m[i - 1] * m[i] <= 0 ? 0 : (m[i - 1] + m[i]) / 2;
  t[n - 1] = m[n - 2];
  for (let i = 0; i < n - 1; i++) {
    if (m[i] === 0) { t[i] = 0; t[i + 1] = 0; continue; }
    const a = t[i] / m[i], b = t[i + 1] / m[i], s = a * a + b * b;
    if (s > 9) { const k = 3 / Math.sqrt(s); t[i] = k * a * m[i]; t[i + 1] = k * b * m[i]; }
  }
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 0; i < n - 1; i++) {
    const third = dx[i] / 3;
    d += ` C${pts[i][0] + third},${pts[i][1] + t[i] * third} ${pts[i + 1][0] - third},${pts[i + 1][1] - t[i + 1] * third} ${pts[i + 1][0]},${pts[i + 1][1]}`;
  }
  return d;
}

/** Closed Catmull-Rom curve for the radar blob. */
function smoothClosed(pts) {
  const n = pts.length;
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 0; i < n; i++) {
    const [p0, p1, p2, p3] = [pts[(i - 1 + n) % n], pts[i], pts[(i + 1) % n], pts[(i + 2) % n]];
    d += ` C${p1[0] + (p2[0] - p0[0]) / 6},${p1[1] + (p2[1] - p0[1]) / 6} ${p2[0] - (p3[0] - p1[0]) / 6},${p2[1] - (p3[1] - p1[1]) / 6} ${p2[0]},${p2[1]}`;
  }
  return `${d}Z`;
}

// ---------- derived data ----------

function derive() {
  const { events = [], labels = {}, config = {} } = state.data ?? {};
  const detections = events.filter((e) => DETECTIONS.has(e.verdict));
  const ml = detections.filter((e) => typeof e.score === 'number');
  const pending = ml.filter((e) => e.excerpt && !labels[e.id]);
  return { events, labels, config, detections, ml, pending };
}

function buckets(events, count = 12) {
  const size = 3600e3;
  const end = Math.ceil(Date.now() / size) * size;
  const start = end - count * size;
  const out = Array.from({ length: count }, (_, i) => ({ n: 0, label: `${pad2(new Date(start + i * size).getHours())}:00` }));
  for (const e of events) {
    const t = Date.parse(e.ts);
    if (t >= start && t < end) out[Math.floor((t - start) / size)].n++;
  }
  return out;
}

function radarData(detections) {
  const now = Date.now();
  const first = detections.reduce((min, e) => Math.min(min, Date.parse(e.ts)), now);
  const days = Math.max(1, (now - first) / DAY);
  return RADAR.map((c) => {
    const all = detections.filter((e) => e.category === c);
    return { c, cur: all.filter((e) => now - Date.parse(e.ts) < DAY).length, avg: all.length / days };
  });
}

// ---------- data loading ----------

async function load() {
  const live = document.getElementById('live');
  try {
    const res = await fetch(`/api/events${state.server ? `?server=${encodeURIComponent(state.server)}` : ''}`, { cache: 'no-store' });
    if (!res.ok) throw new Error(res.statusText);
    const data = await res.json();
    state.lastRead = new Date();
    live.classList.remove('stale');
    renderStatus(data.config);
    const last = data.events.at(-1);
    const signature = `${state.server}|${data.events.length}|${last?.id}|${Object.keys(data.labels).length}`;
    state.data = data;
    if (signature !== state.signature) {
      state.signature = signature;
      render();
    } else {
      renderFoot();
    }
  } catch {
    live.classList.add('stale');
    renderStatus();
  }
}

async function label(e, review) {
  try {
    const res = await fetch('/api/labels', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-mcp-firewall': '1' },
      body: JSON.stringify({ eventId: e.id, review }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error);
    state.data.labels[e.id] = review;
    toast(body.trainable ? 'Etiket kaydedildi · eğitim verisine eklendi' : 'Etiket kaydedildi');
    render();
  } catch (err) {
    toast(`Etiket kaydedilemedi: ${err.message}`);
  }
}

function setView(view, extra = {}) {
  Object.assign(state, { view, since: null }, extra);
  storage('view', view);
  render();
  window.scrollTo({ top: 0 });
}

function openEvent(e) {
  setView('events', { selectedId: e.id, tab: 'detections', category: '', q: '' });
}

// ---------- chrome ----------

function renderChrome() {
  const { config, detections } = derive();
  document.getElementById('title').textContent = VIEWS[state.view];
  for (const v of Object.keys(VIEWS)) document.getElementById(`view-${v}`).hidden = state.view !== v;
  for (const b of document.querySelectorAll('[data-view]')) {
    b.classList.toggle('active', b.dataset.view === state.view);
    if (b.dataset.view === state.view) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  }

  const select = document.getElementById('server-filter');
  const servers = state.data?.servers ?? [];
  select.replaceChildren(h('option', { value: '' }, 'Tüm sunucular'), ...servers.map((s) => h('option', { value: s }, s)));
  select.value = state.server;

  renderStatus(config);

  const bell = document.getElementById('bell');
  const recentBlocks = detections.filter((e) => BLOCKS.has(e.verdict) && ago(e.ts) < 3600e3).length;
  bell.replaceChildren(icon('bell', 17), recentBlocks ? h('span', { class: 'dot' }) : null);
  bell.title = recentBlocks ? `Son 1 saatte ${recentBlocks} engelleme` : 'Son 1 saatte engelleme yok';
}

function renderStatus(config = derive().config) {
  const live = document.getElementById('live');
  const stale = live.classList.contains('stale');
  const mode = config.mode ? config.mode[0].toUpperCase() + config.mode.slice(1) : '';
  live.classList.toggle('monitor', config.mode === 'monitor');
  document.getElementById('mode-badge').textContent = stale ? 'Bağlantı yok' : mode ? `${mode} · canlı` : 'Canlı';
}

function renderFoot() {
  const { config } = derive();
  const foot = document.getElementById('foot');
  foot.replaceChildren(
    h('span', {}, 'Audit: ', h('code', {}, config.auditFile ?? '—')),
    h('span', {}, 'Etiketler: ', h('code', {}, config.labelsFile ?? '—')),
    h('span', {}, `Son okuma: ${state.lastRead ? state.lastRead.toLocaleTimeString('tr-TR') : '—'}`),
  );
}

// ---------- overview ----------

function statsRow({ events }) {
  const day = events.filter((e) => ago(e.ts) < DAY);
  // Same verdict sets as the event tabs these counts open, so the number matches the list.
  const count = (set) => day.filter((e) => set.has(e.verdict)).length;
  const stat = (cls, n, text, note, onclick) => h('button', { class: 'stat', onclick },
    h('span', { class: `badge-n ${cls}` }, String(n)), h('p', {}, text, h('small', {}, note)));
  const openTab = (tab) => () => setView('events', { tab, selectedId: null, category: '', q: '', since: DAY });
  return h('div', { class: 'wrap' }, h('section', { class: 'stats', 'aria-label': 'Özet sayılar' },
    stat('blk', count(BLOCKS), 'Engellenen', 'son 24 saat', openTab('blocked')),
    stat('msk', count(MASKS), 'Maskelenen', 'son 24 saat', openTab('masked')),
    stat('ok', count(new Set(['allow'])), 'İzin verilen', 'loglananlar, 24 saat', openTab('allowed')),
    stat('ink', (state.data?.servers ?? []).length, 'Sunucu', 'filtrelemek için seç', pickServer)));
}

function pickServer() {
  const select = document.getElementById('server-filter');
  select.focus();
  try { select.showPicker(); } catch { /* older browsers: focus is enough */ }
}

/** Hourly detections as stations on a line: the station grows with the count. */
function lineMap({ detections }) {
  const data = buckets(detections);
  const top = Math.max(...data.map((b) => b.n));
  const peak = top ? data.reduce((best, b, i) => (b.n >= data[best].n ? i : best), 0) : -1;
  const cols = data.map((b, i) => {
    const st = h('i', { class: `st ${b.n ? '' : 'z'}` });
    st.style.setProperty('--d', `${b.n ? Math.round(22 + (56 * b.n) / top) : 18}px`);
    return h('div', { class: `col ${i === peak ? 'pk' : ''}` }, h('b', {}, String(b.n)), st, h('span', { class: 'hr' }, b.label));
  });
  return h('section', { class: 'map', 'aria-labelledby': 'saatlik' },
    h('div', { class: 'wrap' },
      h('div', { class: 'sec-h' },
        h('h2', { id: 'saatlik' }, 'Son 12 saatte tespitler'),
        h('p', {}, peak < 0 ? 'Son 12 saatte tespit yok.' : `Durak büyüklüğü tespit sayısını gösterir. En yoğun saat ${data[peak].label}, ${top} tespit.`)),
      h('div', { class: 'line', role: 'img', 'aria-label': `Saatlik tespit sayısı, ${data[0].label} ile ${data.at(-1).label} arası: ${data.map((b) => b.n).join(', ')}` },
        h('div', { class: 'cols', 'aria-hidden': 'true' }, cols))));
}

function routeList(recent, selected) {
  return h('section', { 'aria-labelledby': 'son-olaylar' },
    h('div', { class: 'sec-h' },
      h('h2', { id: 'son-olaylar' }, 'Son olaylar'),
      h('button', { class: 'btn-dark', onclick: () => setView('events', { tab: 'detections' }) }, 'Tümü', icon('arrowRight', 14, 2.2))),
    recent.length
      ? h('ol', { class: 'route' }, recent.map((e) =>
        h('li', { class: e === selected ? 'on' : '' },
          h('button', { 'aria-current': e === selected ? 'true' : null, title: e.reason ?? '', onclick: () => { state.overviewId = e.id; renderOverview(); } },
            h('span', { class: `mk ${verdict(e).cls}`, 'aria-hidden': 'true' }),
            h('span', { class: 'tm' }, clock(e.ts)),
            h('span', { class: 'tl' }, subject(e)),
            h('span', { class: 'rs' }, e.reason ?? cat(e).label),
            pill(e)))))
      : h('div', { class: 'route' }, h('div', { class: 'route-empty' }, h('b', {}, 'Henüz tespit yok'), 'Firewall bir MCP sunucusunun önünde çalıştıkça olaylar burada görünür.')));
}

function signPanel(e, labels) {
  if (!e) {
    return h('section', { class: 'sign', 'aria-label': 'Seçili olay' }, h('div', { class: 'empty' }, h('b', {}, 'Olay seçilmedi'), 'Soldaki listeden bir olay seç.'));
  }
  const review = labels[e.id];
  const detection = DETECTIONS.has(e.verdict);
  return h('section', { class: 'sign', 'aria-labelledby': 'secili-olay' },
    h('h2', { class: 'name', id: 'secili-olay' }, 'Seçili olay'),
    h('h3', {}, typeof e.score === 'number' ? `${cat(e).label}, ML skoru ${e.score.toFixed(3)}` : cat(e).label),
    e.excerpt ? h('div', {}, h('p', { class: 'q-l' }, 'Tetikleyen metin'), h('blockquote', { class: 'q' }, e.excerpt)) : null,
    maskedBlock(e),
    h('dl', { class: 'meta' },
      h('dt', {}, 'Araç'), h('dd', {}, subject(e)),
      h('dt', {}, 'Sunucu'), h('dd', {}, e.server ?? '—'),
      h('dt', {}, 'Gerekçe'), h('dd', {}, e.reason ?? '—'),
      h('dt', {}, 'Zaman'), h('dd', {}, fmtTime(e.ts)),
      h('dt', {}, 'Karar'), h('dd', {}, pill(e))),
    h('div', { class: 'act' },
      detection ? [
        h('button', { class: 'btn-sign ok', 'aria-pressed': review === 'true_positive', onclick: () => label(e, 'true_positive') }, review === 'true_positive' ? [icon('check', 16, 2.4), 'Doğrulandı'] : 'Doğru tespit'),
        h('button', { class: 'btn-sign no', 'aria-pressed': review === 'false_positive', onclick: () => label(e, 'false_positive') }, review === 'false_positive' ? [icon('check', 16, 2.4), 'Yanlış alarm'] : 'Yanlış alarm'),
      ] : null,
      h('button', { class: 'btn-sign no', onclick: () => openEvent(e) }, 'Ayrıntı', icon('arrowRight', 16, 2.2))));
}

function radarCard({ detections }) {
  const data = radarData(detections);
  const head = h('div', { class: 'card-head' },
    h('span', { class: 'card-title' }, 'Tehdit dağılımı'),
    h('div', { class: 'seg' },
      ...[['radar', 'Radar'], ['list', 'Liste']].map(([mode, text]) =>
        h('button', { class: state.radarMode === mode ? 'active' : '', onclick: () => { state.radarMode = mode; render(); } }, text))),
    h('span', { class: 'spacer' }),
    h('span', { class: 'legend' }, h('i', { style: { background: 'var(--peach)' } }), 'Son 24 saat'),
    h('span', { class: 'legend' }, h('i', { style: { background: '#c3c7cc' } }), 'Günlük ort.'));

  if (state.radarMode === 'list') {
    const max = Math.max(1, ...data.map((d) => Math.max(d.cur, d.avg)));
    return h('article', { class: 'card' }, head,
      h('div', { class: 'list' }, data.map((d) => {
        const c = CATEGORIES[d.c];
        return h('div', { class: 'event-row' },
          h('span', { class: 'tile', style: { background: c.bg, color: c.fg } }, icon(c.icon, 16)),
          h('div', {},
            h('div', { class: 'event-name' }, c.label),
            h('div', { class: 'stack', style: { marginTop: '6px', height: '6px' } },
              h('i', { style: { width: `${(d.cur / max) * 100}%`, background: 'var(--ink)' } }))),
          h('div', { class: 'event-verdict' }, String(d.cur), h('div', { class: 'event-meta' }, `ort. ${d.avg.toFixed(1)}`)));
      })));
  }

  const W = 320, H = 280, cx = W / 2, cy = H / 2 + 4, R = 96, min = 14;
  const max = Math.max(1, ...data.map((d) => Math.max(d.cur, d.avg)));
  const angle = (i) => (-90 + i * (360 / RADAR.length)) * (Math.PI / 180);
  const point = (i, v) => { const r = min + (R - min) * (v / max); return [cx + r * Math.cos(angle(i)), cy + r * Math.sin(angle(i))]; };
  const svg = h('svg:svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Kategoriye göre tespit sayıları' });
  for (const f of [0.25, 0.5, 0.75, 1]) {
    const ring = RADAR.map((_, i) => [cx + R * f * Math.cos(angle(i)), cy + R * f * Math.sin(angle(i))]);
    svg.append(h('svg:polygon', { points: ring.map((p) => p.join(',')).join(' '), fill: 'none', stroke: 'var(--line)' }));
  }
  RADAR.forEach((c, i) => {
    const [x, y] = [cx + R * Math.cos(angle(i)), cy + R * Math.sin(angle(i))];
    svg.append(h('svg:line', { x1: cx, y1: cy, x2: x, y2: y, stroke: 'var(--line)' }));
    const [lx, ly] = [cx + (R + 24) * Math.cos(angle(i)), cy + (R + 20) * Math.sin(angle(i))];
    const anchor = Math.abs(lx - cx) < 5 ? 'middle' : lx > cx ? 'start' : 'end';
    svg.append(h('svg:text', { x: lx, y: ly, 'text-anchor': anchor, class: 'radar-label' }, CATEGORIES[c].short));
    svg.append(h('svg:text', { x: lx, y: ly + 11, 'text-anchor': anchor, class: 'radar-count' }, `${data[i].cur} / ort. ${data[i].avg.toFixed(1)}`));
  });
  svg.append(h('svg:path', { d: smoothClosed(data.map((d, i) => point(i, d.avg))), fill: 'none', stroke: '#b9bec4', 'stroke-width': 1.4, 'stroke-dasharray': '4 4' }));
  const cur = data.map((d, i) => point(i, d.cur));
  svg.append(h('svg:path', { d: smoothClosed(cur), fill: 'var(--peach)', 'fill-opacity': 0.9, stroke: 'var(--ink)', 'stroke-width': 1.6 }));
  cur.forEach(([x, y], i) => svg.append(h('svg:circle', { cx: x, cy: y, r: 3.2, fill: 'var(--ink)' }, h('svg:title', {}, `${CATEGORIES[RADAR[i]].label}: ${data[i].cur}`))));
  return h('article', { class: 'card' }, head, h('div', { class: 'radar-wrap' }, svg));
}

function quickCard({ config, ml }) {
  const servers = state.data?.servers ?? [];
  const current = state.threshold ?? config.ml?.threshold ?? 0.9;
  const flagged = ml.filter((e) => e.score >= current).length;
  const people = [{ name: 'Tümü', value: '' }, ...servers.map((s) => ({ name: s, value: s }))];
  return h('article', { class: 'card' },
    h('div', { class: 'card-head' },
      h('span', { class: 'card-title' }, 'Hızlı eşik ayarı'),
      h('span', { class: 'spacer' }),
      h('span', { class: 'card-sub' }, `${servers.length} sunucu`)),
    h('div', { class: 'avatars' }, people.map((p) =>
      h('button', { class: `avatar ${state.server === p.value ? 'active' : ''}`, title: p.name, onclick: () => selectServer(p.value) },
        h('span', { class: 'face', style: { background: p.value ? avatarColor(p.name) : 'var(--ink)' } }, p.value ? p.name.slice(0, 2).toUpperCase() : icon('server', 16)),
        p.name.length > 9 ? `${p.name.slice(0, 8)}…` : p.name))),
    h('div', { class: 'chips' }, THRESHOLDS.map((t) =>
      h('button', { class: `chip ${t === current ? 'active' : ''}`, onclick: () => { state.threshold = t; render(); } }, t.toFixed(2)))),
    h('div', { class: 'field' }, icon('sliders', 16), 'ML eşiği', h('span', { class: 'spacer' }), h('b', {}, current.toFixed(2))),
    h('div', { class: 'sim' }, ml.length
      ? ['Bu eşikte son ', h('strong', {}, String(ml.length)), ' ML tespitinin ', h('strong', {}, String(flagged)), ' tanesi işaretlenirdi. (Eşik altı skorlar loglanmaz.)']
      : 'Henüz ML tespiti yok. Politikada ml.enabled: true ile etkinleştir.'),
    h('span', { class: 'spacer' }),
    h('button', { class: 'btn-dark btn-block', onclick: () => copy(`ml:\n  threshold: ${current}\n`, 'YAML panoya kopyalandı') }, icon('copy', 14), "YAML'ı kopyala"));
}

function mlCard({ config, ml, labels, events }) {
  const labeled = Object.keys(labels).length;
  const trainable = trainableCount({ events, labels });
  const on = config.ml?.enabled;
  return h('article', { class: 'card' },
    h('div', { class: 'card-head' },
      h('span', { class: 'card-title' }, 'ML katmanı'),
      h('span', { class: 'spacer' }),
      h('span', { class: 'card-sub', style: { color: on ? 'var(--ok)' : 'var(--muted)', fontWeight: '600' } }, on ? '● Aktif' : '○ Kapalı')),
    h('div', { class: 'ml-card' },
      h('span', { class: 'ml-name' }, config.ml?.model ?? '—'),
      h('span', { class: 'ml-big' }, String(ml.length), ' ', h('small', {}, 'tespit')),
      h('div', { class: 'ml-foot' },
        h('span', {}, `eşik ${config.ml?.threshold ?? '—'} · fail ${config.ml?.failMode ?? '—'}`),
        h('span', { class: 'ml-brand' }, 'ONNX'))),
    h('dl', { class: 'kv' },
      h('dt', {}, 'DLP'), h('dd', {}, config.dlp?.enabled ? config.dlp.action : 'kapalı'),
      h('dt', {}, 'Tool pinning'), h('dd', {}, config.pinning ? 'açık' : 'kapalı'),
      h('dt', {}, 'Etiketlenen olay'), h('dd', {}, String(labeled)),
      h('dt', {}, 'Eğitime hazır örnek'), h('dd', {}, String(trainable))),
    h('span', { class: 'spacer' }),
    labelsLink('btn-dark btn-block', { events, labels }));
}

function promoCard({ pending }) {
  const art = h('svg:svg', { width: 150, height: 96, viewBox: '0 0 150 96', fill: 'none', stroke: 'var(--peach-ink)', 'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' },
    h('svg:path', { d: 'M48 14 22 24v20c0 18 11 28 26 32 15-4 26-14 26-32V24z' }),
    h('svg:path', { d: 'm37 45 8 8 15-16' }),
    h('svg:rect', { x: 92, y: 40, width: 32, height: 32, rx: 6 }),
    h('svg:rect', { x: 101, y: 49, width: 14, height: 14, rx: 2 }),
    h('svg:path', { d: 'M100 40v-7M108 40v-7M116 40v-7M100 72v7M108 72v7M116 72v7M92 48h-7M92 56h-7M92 64h-7M124 48h7M124 56h7M124 64h7' }),
    h('svg:path', { d: 'M80 18l2 5 5 2-5 2-2 5-2-5-5-2 5-2zM136 22l1.5 3.5L141 27l-3.5 1.5L136 32l-1.5-3.5L131 27l3.5-1.5z' }));
  return h('article', { class: 'card promo' },
    h('div', {},
      h('h2', {}, 'Modeli güçlendir:', h('br'), h('span', { class: 'ring' }, `${pending.length} olay`), ' etiket', h('br'), 'bekliyor'),
      h('p', {}, 'Etiketlediğin olaylar prepare_data.py --extra-train ile eğitim setine eklenir.')),
    h('div', { class: 'art' }, art),
    h('button', { class: 'btn-white', onclick: () => setView('ml', { mlFilter: 'pending', selectedId: null }) }, 'İncele'));
}

function renderOverview() {
  const d = derive();
  const recent = d.detections.slice(-8).reverse();
  const selected = recent.find((e) => e.id === state.overviewId) ?? recent[0];
  document.getElementById('view-overview').replaceChildren(
    statsRow(d),
    lineMap(d),
    h('div', { class: 'wrap' },
      h('div', { class: 'ov-main' }, routeList(recent, selected), signPanel(selected, d.labels)),
      h('div', { class: 'ov-extra' }, radarCard(d), quickCard(d), mlCard(d), promoCard(d))));
}

// ---------- event center ----------

const inWindow = (e) => !state.since || ago(e.ts) < state.since;

function filtered({ events }) {
  const q = state.q.trim().toLowerCase();
  return events
    .filter((e) => e.verdict !== 'info' && inWindow(e))
    .filter((e) => {
      if (state.tab === 'detections') return DETECTIONS.has(e.verdict);
      if (state.tab === 'blocked') return BLOCKS.has(e.verdict);
      if (state.tab === 'masked') return MASKS.has(e.verdict);
      if (state.tab === 'allowed') return e.verdict === 'allow';
      if (state.tab === 'warn') return e.verdict === 'warn' || e.verdict === 'would_block' || e.verdict === 'would_redact';
      return true;
    })
    .filter((e) => !state.category || e.category === state.category)
    .filter((e) => !q || [e.tool, e.method, e.server, e.reason].some((v) => v && v.toLowerCase().includes(q)))
    .reverse();
}

function sparkline(values, W = 200, H = 46, color = 'var(--blue)') {
  const svg = h('svg:svg', { width: '100%', height: H, viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  if (values.length < 2) return svg;
  const lo = Math.min(...values), hi = Math.max(...values), span = hi - lo || 1;
  const pts = values.map((v, i) => [(W * i) / (values.length - 1), H - 4 - ((H - 8) * (v - lo)) / span]);
  svg.append(h('svg:path', { d: monotonePath(pts), fill: 'none', stroke: color, 'stroke-width': 2, 'vector-effect': 'non-scaling-stroke' }));
  return svg;
}

function kpis({ detections, ml, pending, labels }) {
  const now = Date.now();
  const inWindow = (e, from, to) => { const a = now - Date.parse(e.ts); return a >= from && a < to; };
  const blocked = detections.filter((e) => BLOCKS.has(e.verdict) && inWindow(e, 0, DAY));
  const prev = detections.filter((e) => BLOCKS.has(e.verdict) && inWindow(e, DAY, 2 * DAY)).length;
  const change = prev ? Math.round(((blocked.length - prev) / prev) * 100) : null;

  const byCat = Object.keys(CATEGORIES).map((c) => [c, blocked.filter((e) => e.category === c).length]).filter(([, n]) => n);
  const stack = h('div', { class: 'stack' }, byCat.map(([c, n]) =>
    h('i', { title: `${CATEGORIES[c].label}: ${n}`, style: { width: `${(n / blocked.length) * 100}%`, background: CATEGORIES[c].fg } })));

  const redacts = detections.filter((e) => e.verdict === 'redact' || e.verdict === 'would_redact');
  const perDay = Array.from({ length: 7 }, (_, i) => redacts.filter((e) => inWindow(e, (6 - i) * DAY, (7 - i) * DAY)).length);
  const top = Math.max(1, ...perDay);
  const bars = h('svg:svg', { width: '100%', height: 46, viewBox: '0 0 210 46', 'aria-hidden': 'true' },
    perDay.flatMap((n, i) => [
      h('svg:rect', { x: i * 30 + 6, y: 34 - (28 * n) / top, width: 16, height: Math.max(2, (28 * n) / top), rx: 4, fill: i === 6 ? 'var(--blue)' : 'var(--blue-soft)' }),
      h('svg:text', { x: i * 30 + 14, y: 45, 'text-anchor': 'middle', class: 'axis' }, DAYS[new Date(now - (6 - i) * DAY).getDay()]),
    ]));

  const scores = ml.slice(-30).map((e) => e.score);
  const avg = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : null;
  const reviewed = ml.filter((e) => labels[e.id]).length;

  const kpi = (labelText, iconName, iconColor, value, trend, viz) =>
    h('article', { class: 'card kpi' },
      h('div', { class: 'k-label' }, labelText, h('span', { style: { color: iconColor } }, icon(iconName, 16))),
      h('div', { class: 'k-value' }, value),
      h('div', { class: 'k-trend' }, trend),
      h('div', { class: 'k-viz' }, viz));

  return h('div', { class: 'kpis' },
    kpi('Engellenen (24 sa)', 'alert', 'var(--danger)', String(blocked.length),
      change === null ? 'önceki 24 saatte engel yok' : [h('b', { class: change > 0 ? 'up' : 'down' }, `${change > 0 ? '↑' : '↓'} ${Math.abs(change)}%`), ' önceki 24 saate göre'],
      stack),
    kpi('Maskelenen veri (7 gün)', 'lock', 'var(--blue)', String(perDay.reduce((a, b) => a + b, 0)), 'DLP ile maskelenen sonuç ve argümanlar', bars),
    kpi('Ortalama ML skoru', 'cpu', 'var(--ink)', avg === null ? '—' : avg.toFixed(3), `son ${scores.length} ML tespiti`, sparkline(scores)),
    kpi('Etiket bekleyen', 'check', 'var(--ok)', String(pending.length), `${reviewed} / ${ml.length} ML tespiti etiketlendi`,
      h('button', { class: 'btn-dark', style: { marginTop: '8px' }, onclick: () => setView('ml', { mlFilter: 'pending', selectedId: null }) }, 'Etiketle', icon('arrowRight', 12, 2.2))));
}

function detailPane(e, labels) {
  if (!e) {
    return h('div', { class: 'detail' }, h('div', { class: 'empty' }, h('b', {}, 'Olay seçilmedi'), 'Soldaki listeden bir olay seç.'));
  }
  const review = labels[e.id];
  const detection = DETECTIONS.has(e.verdict);
  const ruleYaml = e.tool ? `tools:\n  rules:\n    - match: "${e.tool.replace(/"/g, '\\"')}"\n      action: deny\n      reason: "${evId(e)} incelemesi"\n` : null;
  return h('div', { class: 'detail' },
    h('div', { class: 'd-top' },
      h('div', {},
        h('div', { class: 'd-label' }, 'Olay detayı'),
        h('div', { class: 'd-id' }, `# ${evId(e)}`, pill(e))),
      h('div', {}, h('div', { class: 'd-label' }, 'Sunucu'), h('div', { class: 'd-strong' }, e.server ?? '—')),
      h('div', {}, h('div', { class: 'd-label' }, 'Araç / metod'), h('div', { class: 'd-strong' }, subject(e)))),
    h('div', { class: 'd-cards' },
      h('div', { class: 'd-card' }, h('b', {}, cat(e).label), h('span', {}, 'Kategori')),
      h('div', { class: 'd-card' }, h('b', {}, e.direction === 'client->server' ? 'İstemci → Sunucu' : e.direction ? 'Sunucu → İstemci' : '—'), h('span', {}, 'Yön')),
      h('div', { class: 'd-card' }, h('b', {}, typeof e.score === 'number' ? e.score.toFixed(3) : '—'), h('span', {}, 'ML skoru')),
      ruleYaml
        ? h('button', { class: 'd-card dashed', onclick: () => textDialog('Kural önerisi', `${e.tool} aracını engelleyen kural. Politika dosyandaki tools.rules listesine ekle.`, ruleYaml, 'Kural YAML olarak kopyalandı') }, h('span', { style: { color: '#fff' } }, icon('plus', 18)), h('span', {}, 'Kural öner'))
        : h('div', { class: 'd-card dashed' }, h('span', {}, 'Kural önerisi yok'))),
    h('div', { class: 'd-reason' },
      h('b', {}, 'Gerekçe'), h('div', {}, e.reason ?? '—'),
      e.excerpt ? [h('div', { class: 'd-label', style: { marginTop: '10px' } }, 'Tetikleyen metin (yalnızca audit logunda, modele gönderilmez)'), h('pre', {}, e.excerpt)] : null),
    maskedBlock(e),
    h('div', { class: 'd-foot' },
      h('div', {}, h('span', { class: 'd-label' }, 'Zaman'), h('b', {}, fmtTime(e.ts))),
      h('div', {}, h('span', { class: 'd-label' }, 'Doğrulama'), h('b', {}, review === 'true_positive' ? 'Doğru tespit' : review === 'false_positive' ? 'Yanlış pozitif' : detection ? 'Bekliyor' : '—')),
      h('div', {}, h('span', { class: 'd-label' }, 'Eğitime uygun'), h('b', {}, e.excerpt ? 'Evet' : 'Hayır')),
      detection
        ? h('div', { class: 'd-actions' },
          h('button', { class: 'btn-ghost', 'aria-pressed': review === 'false_positive', onclick: () => label(e, 'false_positive') }, icon(review === 'false_positive' ? 'check' : 'x', 14, 2.2), 'Yanlış pozitif'),
          h('button', { class: 'btn-white-pill', 'aria-pressed': review === 'true_positive', onclick: () => label(e, 'true_positive') }, icon('check', 14, 2.4), review === 'true_positive' ? 'Doğrulandı' : 'Doğru tespit'))
        : null));
}

function renderEvents() {
  const d = derive();
  if (!EVENT_TABS.some(([k]) => k === state.tab)) state.tab = 'detections';
  const list = filtered(d);
  if (!list.some((e) => e.id === state.selectedId)) state.selectedId = list[0]?.id ?? null;
  const selected = list.find((e) => e.id === state.selectedId);
  const base = d.events.filter((e) => e.verdict !== 'info' && inWindow(e));
  const counts = {
    detections: base.filter((e) => DETECTIONS.has(e.verdict)).length,
    all: base.length,
    blocked: base.filter((e) => BLOCKS.has(e.verdict)).length,
    masked: base.filter((e) => MASKS.has(e.verdict)).length,
    allowed: base.filter((e) => e.verdict === 'allow').length,
    warn: base.filter((e) => ['warn', 'would_block', 'would_redact'].includes(e.verdict)).length,
  };
  const tabs = EVENT_TABS;
  const activeFilters = [state.category, state.q.trim(), state.server, state.since].filter(Boolean).length;

  const search = h('input', { type: 'search', placeholder: 'Araç, sunucu veya gerekçe ara…', value: state.q, 'aria-label': 'Olay ara' });
  search.addEventListener('input', () => { state.q = search.value; renderEventsKeepFocus(); });

  document.getElementById('view-events').replaceChildren(
    h('div', { class: 'ev-head' },
      h('button', { class: 'back', 'aria-label': 'Genel bakışa dön', onclick: () => setView('overview') }, icon('arrowLeft', 16)),
      h('div', {}, h('h2', { class: 'ev-title' }, 'Olaylar'), h('div', { class: 'ev-sub' }, 'Firewall kararlarını izle, incele ve model eğitimi için etiketle.')),
      h('span', { class: 'spacer' }),
      labelsLink('btn-blue', d)),
    kpis(d),
    h('div', { class: 'filters' },
      h('span', { class: 'lbl' }, 'Aktif filtreler', h('span', { class: 'count' }, String(activeFilters))),
      h('label', { class: 'pill-select' },
        h('select', { 'aria-label': 'Kategori', onchange: (ev) => { state.category = ev.target.value; render(); } },
          h('option', { value: '' }, 'Tüm kategoriler'),
          Object.entries(CATEGORIES).map(([k, c]) => h('option', { value: k, selected: state.category === k }, c.label)))),
      state.since
        ? h('button', { class: 'filter-chip', 'aria-label': 'Son 24 saat filtresini kaldır', onclick: () => { state.since = null; state.selectedId = null; render(); } }, 'Son 24 saat', icon('x', 14, 2.4))
        : null,
      h('div', { class: 'seg' }, tabs.map(([k, text]) =>
        h('button', { class: state.tab === k ? 'active' : '', onclick: () => { state.tab = k; state.selectedId = null; render(); } }, `${text} ${counts[k]}`))),
      h('label', { class: 'search' }, icon('search', 14), search)),
    h('div', { class: 'panel' },
      h('div', { class: 'panel-list' },
        h('h3', {}, tabs.find(([k]) => k === state.tab)[1], h('span', {}, `${list.length} olay`)),
        list.length
          ? h('div', { class: 'panel-scroll' }, list.slice(0, 300).map((e) =>
            h('button', { class: `p-item ${e.id === state.selectedId ? 'active' : ''}`, onclick: () => { state.selectedId = e.id; renderEvents(); } },
              tile(e, 32),
              h('div', { style: { minWidth: '0' } }, h('div', { class: 'p-id' }, `# ${evId(e)}`), h('div', { class: 'p-sub' }, `${subject(e)} · ${rel(e.ts)}`)),
              h('div', { class: 'p-side' }, pill(e), h('span', { class: 'p-cat' }, cat(e).short)))))
          : h('div', { class: 'empty' }, h('b', {}, 'Olay yok'), 'Filtreleri değiştirmeyi dene.')),
      detailPane(selected, d.labels)));
}

function renderEventsKeepFocus() {
  const pos = document.activeElement?.selectionStart;
  renderEvents();
  const input = document.querySelector('.search input');
  input.focus();
  if (pos !== undefined) input.setSelectionRange(pos, pos);
}

// ---------- ML events ----------

const NEAR = 0.05;

function scoreHistogram(ml, threshold) {
  const lowest = Math.min(threshold, 0.9, ...ml.map((e) => e.score));
  // Only scores above the threshold are logged, so the range is usually narrow: use 0.01 bins there.
  const STEP = 1 - lowest <= 0.2 ? 0.01 : 0.05;
  const from = Math.floor(lowest / STEP + 1e-9) * STEP;
  const bins = Math.max(1, Math.round((1 - from) / STEP));
  const counts = Array(bins).fill(0);
  for (const e of ml) counts[Math.max(0, Math.min(bins - 1, Math.floor((e.score - from) / STEP + 1e-9)))]++;
  const W = 420, H = 160, pad = { l: 8, r: 8, t: 14, b: 20 };
  const top = Math.max(1, ...counts);
  const bw = (W - pad.l - pad.r) / bins;
  const x = (v) => pad.l + ((v - from) / (1 - from)) * (W - pad.l - pad.r);
  const svg = h('svg:svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'ML skor dağılımı' });
  counts.forEach((n, i) => {
    const bh = ((H - pad.t - pad.b) * n) / top;
    const lo = from + i * STEP;
    svg.append(h('svg:rect', { x: pad.l + i * bw + 3, y: H - pad.b - Math.max(2, bh), width: bw - 6, height: Math.max(2, bh), rx: 5, fill: lo >= threshold ? 'var(--blue)' : 'var(--peach-deep)' },
      h('svg:title', {}, `${lo.toFixed(2)}–${(lo + STEP).toFixed(2)}: ${n} olay`)));
    if (n) svg.append(h('svg:text', { x: pad.l + i * bw + bw / 2, y: H - pad.b - Math.max(2, bh) - 4, 'text-anchor': 'middle', class: 'axis' }, String(n)));
    svg.append(h('svg:text', { x: pad.l + i * bw + bw / 2, y: H - 6, 'text-anchor': 'middle', class: 'axis' }, lo.toFixed(2)));
  });
  svg.append(h('svg:line', { x1: x(threshold), x2: x(threshold), y1: pad.t - 6, y2: H - pad.b, stroke: 'var(--ink)', 'stroke-width': 1.5, 'stroke-dasharray': '4 3' }));
  svg.append(h('svg:text', { x: x(threshold) + 4, y: pad.t, class: 'axis' }, `eşik ${threshold}`));
  return svg;
}

function serverBars(ml) {
  const byServer = Object.entries(ml.reduce((acc, e) => ({ ...acc, [e.server ?? '—']: (acc[e.server ?? '—'] ?? 0) + 1 }), {}))
    .sort((a, b) => b[1] - a[1]);
  const top = Math.max(1, ...byServer.map(([, n]) => n));
  return byServer.length
    ? h('div', { class: 'srv-bars' }, byServer.map(([s, n]) =>
      h('div', { class: 'srv-row' },
        h('span', { class: 'srv-name' }, s),
        h('span', { class: 'srv-track' }, h('i', { style: { width: `${(n / top) * 100}%`, background: s === '—' ? 'var(--muted)' : avatarColor(s) } })),
        h('b', {}, String(n)))))
    : h('div', { class: 'empty' }, h('b', {}, 'ML tespiti yok'));
}

function renderMl() {
  const d = derive();
  const { config, ml, labels } = d;
  const threshold = config.ml?.threshold ?? 0.9;
  const tp = ml.filter((e) => labels[e.id] === 'true_positive');
  const fp = ml.filter((e) => labels[e.id] === 'false_positive');
  const groups = [['all', 'Tümü', ml], ['pending', 'Etiket bekleyen', d.pending], ['true_positive', 'Doğru tespit', tp], ['false_positive', 'Yanlış pozitif', fp]];
  const [, groupLabel, members] = groups.find(([k]) => k === state.mlFilter) ?? groups[0];
  const list = [...members].sort((a, b) => b.score - a.score);
  if (!list.some((e) => e.id === state.selectedId)) state.selectedId = list[0]?.id ?? null;
  const selected = list.find((e) => e.id === state.selectedId);

  const avg = ml.length ? ml.reduce((a, e) => a + e.score, 0) / ml.length : null;
  const near = ml.filter((e) => e.score < threshold + NEAR).length;
  const stat = (labelText, iconName, iconColor, value, note) =>
    h('article', { class: 'card kpi' },
      h('div', { class: 'k-label' }, labelText, h('span', { style: { color: iconColor } }, icon(iconName, 16))),
      h('div', { class: 'k-value' }, value),
      h('div', { class: 'k-trend' }, note));

  document.getElementById('view-ml').replaceChildren(
    h('div', { class: 'ev-head' },
      h('button', { class: 'back', 'aria-label': 'Genel bakışa dön', onclick: () => setView('overview') }, icon('arrowLeft', 16)),
      h('div', {},
        h('h2', { class: 'ev-title' }, 'ML olayları'),
        h('div', { class: 'ev-sub' }, config.ml?.model
          ? `Model ${config.ml.model} · eşik ${threshold} · fail ${config.ml.failMode ?? '—'}${config.ml.enabled ? '' : ' · politikada kapalı'}`
          : 'ML katmanı yapılandırılmamış. Politikada ml.enabled: true ile etkinleştir.')),
      h('span', { class: 'spacer' }),
      labelsLink('btn-blue', d)),
    h('div', { class: 'kpis' },
      stat('ML tespiti', 'cpu', 'var(--blue)', String(ml.length), 'eşiği geçen ve loglanan skorlar'),
      stat('Ortalama skor', 'activity', 'var(--ink)', avg === null ? '—' : avg.toFixed(3), `eşik ${threshold}`),
      stat('Eşiğe yakın', 'sliders', 'var(--warn)', String(near), `skor < ${(threshold + NEAR).toFixed(2)}, önce bunları incele`),
      stat('Yanlış pozitif oranı', 'check', 'var(--ok)', tp.length + fp.length ? `${Math.round((fp.length / (tp.length + fp.length)) * 100)}%` : '—',
        `${tp.length + fp.length} etiketli, ${d.pending.length} bekliyor`)),
    h('div', { class: 'ml-grid' },
      h('article', { class: 'card' },
        h('div', { class: 'card-head' }, h('span', { class: 'card-title' }, 'Skor dağılımı'), h('span', { class: 'spacer' }),
          h('span', { class: 'card-sub' }, 'Eşik altı skorlar loglanmaz')),
        h('div', { class: 'hist' }, scoreHistogram(ml, threshold))),
      h('article', { class: 'card' },
        h('div', { class: 'card-head' }, h('span', { class: 'card-title' }, 'Sunuculara göre'), h('span', { class: 'spacer' }),
          h('span', { class: 'card-sub' }, `${ml.length} tespit`)),
        serverBars(ml))),
    h('div', { class: 'filters' },
      h('div', { class: 'seg' }, groups.map(([k, text, rows]) =>
        h('button', { class: state.mlFilter === k ? 'active' : '', onclick: () => { state.mlFilter = k; state.selectedId = null; render(); } }, `${text} ${rows.length}`)))),
    h('div', { class: 'panel' },
      h('div', { class: 'panel-list' },
        h('h3', {}, groupLabel, h('span', {}, `${list.length} olay · skora göre`)),
        list.length
          ? h('div', { class: 'panel-scroll' }, list.slice(0, 300).map((e) =>
            h('button', { class: `p-item ${e.id === state.selectedId ? 'active' : ''}`, onclick: () => { state.selectedId = e.id; renderMl(); } },
              tile(e, 32),
              h('div', { style: { minWidth: '0' } }, h('div', { class: 'p-id' }, `# ${evId(e)}`), h('div', { class: 'p-sub' }, `${subject(e)} · ${e.server ?? '—'} · ${rel(e.ts)}`)),
              h('div', { class: 'p-side' }, h('span', { class: 'badge' }, e.score.toFixed(3)),
                h('span', { class: 'p-cat' }, labels[e.id] === 'true_positive' ? 'Doğru' : labels[e.id] === 'false_positive' ? 'Yanlış poz.' : e.excerpt ? 'Bekliyor' : '—')))))
          : h('div', { class: 'empty' }, h('b', {}, 'Olay yok'), 'Başka bir filtre seç.')),
      detailPane(selected, labels)));
}

// ---------- shell ----------

function render() {
  renderChrome();
  if (state.view === 'overview') renderOverview();
  else if (state.view === 'ml') renderMl();
  else renderEvents();
  renderFoot();
}

function selectServer(value) {
  state.server = value;
  state.signature = '';
  load();
}

function initShell() {
  for (const btn of document.querySelectorAll('[data-view]')) btn.addEventListener('click', () => setView(btn.dataset.view));
  document.getElementById('bell').addEventListener('click', () => setView('events', { tab: 'blocked', selectedId: null }));
  document.getElementById('server-filter').addEventListener('change', (ev) => selectServer(ev.target.value));
}

initShell();
render();
load();
setInterval(load, 5000);
