/**
 * Finds encoded runs inside text (base64/base64url, hex, percent-encoding, \u / \x escapes, HTML numeric
 * entities, ROT13) and decodes them, so instructions hidden as "aWdub3JlIHByZXZpb3Vz..." are scanned as text.
 * Payloads split into quoted pieces the model is asked to join ("'ign' + 'ore'") are joined back.
 * The model can decode these itself, so a scanner that only reads the surface is easy to walk past.
 * Only decodings that come out as readable text are kept: hashes, keys and binary blobs drop out.
 */

const MAX_DEPTH = 2;
const MAX_RESULTS = 32;
const MAX_OUTPUT_CHARS = 32_000;
/** Longer runs are bulk payloads (embedded files, images), not hidden instructions; decoding them only costs time. */
const MAX_RUN_CHARS = 1_000_000;

const utf8 = new TextDecoder('utf-8', { fatal: true });

/** Readable text: valid UTF-8, mostly letters/digits/punctuation/spaces, with some words in it. */
function readable(text: string): boolean {
  if (text.length < 8 || !/\p{L}{2}/u.test(text)) return false;
  const ok = text.match(/[\p{L}\p{M}\p{N}\p{P}\p{S}\p{Zs}\n\r\t]/gu)?.length ?? 0;
  return ok / text.length >= 0.9;
}

function bytesToText(bytes: Uint8Array): string | undefined {
  try {
    const text = utf8.decode(bytes);
    return readable(text) ? text : undefined;
  } catch {
    return undefined;
  }
}

function fromBase64(run: string): string | undefined {
  const std = run.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (std.length % 4 === 1) return undefined;
  return bytesToText(Buffer.from(std, 'base64'));
}

const fromHex = (run: string): string | undefined => bytesToText(Buffer.from(run, 'hex'));

function fromPercent(run: string): string | undefined {
  try {
    const text = decodeURIComponent(run.replace(/\+/g, ' '));
    return readable(text) ? text : undefined;
  } catch {
    return undefined;
  }
}

function fromEscapes(run: string): string | undefined {
  const text = run.replace(/\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})/g, (_, u, x) => String.fromCharCode(parseInt(u ?? x, 16)));
  return readable(text) ? text : undefined;
}

function fromEntities(run: string): string | undefined {
  const text = run.replace(/&#(x[0-9a-fA-F]+|\d+);/g, (_, n: string) => {
    const code = n.startsWith('x') ? parseInt(n.slice(1), 16) : Number(n);
    return code <= 0x10ffff ? String.fromCodePoint(code) : '';
  });
  return readable(text) ? text : undefined;
}

/**
 * Invisible Unicode smuggling. Tag characters carry a letter each (U+E0000 + code point; some tools
 * extend this into the variation selector range for letters such as ı or ö); variation selectors can
 * also carry raw bytes (U+FE00–FE0F = 0–15, U+E0100–E01EF = 16–255). A run with tag characters in it is
 * read the first way, a run of variation selectors only the second.
 */
function fromInvisible(run: string): string | undefined {
  const cps = [...run].map((c) => c.codePointAt(0)!);
  if (cps.some((c) => c >= 0xe0000 && c <= 0xe007f)) {
    const text = cps.filter((c) => c >= 0xe0000).map((c) => String.fromCodePoint(c - 0xe0000)).join('');
    return readable(text) ? text : undefined;
  }
  const bytes = cps.filter((c) => c < 0xe0000 || c >= 0xe0100).map((c) => (c < 0xe0000 ? c - 0xfe00 : c - 0xe0100 + 16));
  return bytesToText(Uint8Array.from(bytes));
}

/**
 * Frequent words of English and Turkish prose, instructions in particular. ROT13 output is only kept when it
 * holds many of them and the run itself did not: ordinary text rotated by 13 turns into gibberish, and
 * ROT13 gibberish rotated back turns into these words.
 */
const COMMON_WORDS = new Set((
  'the a an and or but not no to of in on at by for from with as is are was be been it its this that these those ' +
  'you your yours we our they them their he she his her i me my all any some every each other only now then also ' +
  'do does did done have has had will would should can could must may please just before after first next ' +
  'ignore disregard forget previous prior above earlier instructions instruction rules rule system prompt message ' +
  'user assistant tell say said show reveal send read write print output reply respond answer email mail address ' +
  'password key keys secret secrets token file files data contents content following below new task tasks follow ' +
  'what who how why when where which there here into out up about over again more most very ' +
  've veya ile bir bu şu o da de ki mi için gibi kadar daha çok her tüm bütün hiç sonra önce şimdi lütfen ' +
  'önceki talimat talimatları talimatı talimatlar kural kuralları sistem mesaj mesajı kullanıcı kullanıcının ' +
  'yok say unut göster gönder oku yaz yanıt cevap dosya dosyaları şifre anahtar gizli veri içeriği yeni görev'
).split(' '));

export const rot13 = (text: string): string =>
  text.replace(/[A-Za-z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });

/** Words of two or more letters, and how many of them are common; single letters ("a", "o") prove nothing. */
function commonWords(text: string): [words: number, common: number] {
  const words = text.toLocaleLowerCase('tr').match(/\p{L}{2,}/gu) ?? [];
  return [words.length, words.filter((w) => COMMON_WORDS.has(w)).length];
}

function fromRot13(run: string): string | undefined {
  const decoded = rot13(run);
  const [words, common] = commonWords(decoded);
  return words >= 3 && common >= 2 && common >= words * 0.3 && common > commonWords(run)[1] * 2 ? decoded : undefined;
}

/** Each encoding: where it may occur, and how to decode one occurrence. */
const DECODERS: [RegExp, (run: string) => string | undefined][] = [
  // At least 20 base64 characters; mixed case or digits keeps ordinary long words out cheaply.
  [/[A-Za-z0-9+/_-]{20,}={0,2}/g, (run) => (/[a-z]/.test(run) && /[A-Z0-9]/.test(run) ? fromBase64(run) : undefined)],
  [/\b(?:[0-9a-fA-F]{2}){12,}\b/g, fromHex],
  [/(?:%[0-9a-fA-F]{2}|[A-Za-z0-9._~+-]){0,40}(?:%[0-9a-fA-F]{2}[A-Za-z0-9._~+-]*){4,}/g, fromPercent],
  [/(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){6,}/g, fromEscapes],
  [/(?:&#(?:x[0-9a-fA-F]+|\d+);){6,}/g, fromEntities],
  [/[\u{E0000}-\u{E01EF}︀-️]{8,}/gu, fromInvisible],
  // Three or more words in one sentence: ROT13 keeps spaces and punctuation, so a hidden sentence stays one run.
  [/\p{L}[\p{L}']*(?:[ \t,;:"'()-]+\p{L}[\p{L}']*){2,}/gu, fromRot13],
];

// One quoted piece on one line, in straight, curly or back quotes. A single quote right after a letter is an
// apostrophe ("don't", Turkish "İstanbul'da"), never an opening quote.
const PIECE = '"([^"\\n]{1,120})"|(?<![\\p{L}\\p{N}])\'([^\'\\n]{1,120})\'|`([^`\\n]{1,120})`|“([^”\\n]{1,120})”|(?<![\\p{L}\\p{N}])‘([^’\\n]{1,120})’';
const pieceValue = (m: RegExpMatchArray, from = 1): string => m.slice(from, from + 5).find((v) => v !== undefined) ?? '';
const JOIN_CUE = /\b(?:combine|concatenat\w*|concat|join|merge|append|glue|put (?:them |these |it )?together)\b|birleştir|yan yana|art arda|ardı ardına|uç uca/iu;
const MAX_PIECES = 16;

/**
 * Payload splitting: an instruction cut into quoted pieces the model is asked to put back together.
 * Three shapes: `'ign' + 'ore'`, variables (`a = 'ignore all'; b = 'previous rules'; do a + b`), and a
 * sentence asking for the pieces to be joined ("join 'ign' and 'ore'", "'ign' ve 'ore' kelimelerini
 * birleştir"). Returns the text with the pieces joined in place and, for a joining sentence, its pieces
 * joined without and with spaces.
 */
export function joinPieces(text: string): string[] {
  if (!/["'`“‘]/.test(text)) return [];
  const out: string[] = [];
  const vars = new Map<string, string>();
  for (const m of text.matchAll(new RegExp(`\\b([A-Za-z_]\\w{0,15})\\s*(?:=|:=|:)\\s*(?:${PIECE})`, 'gu'))) vars.set(m[1], pieceValue(m, 2));
  let joined = text.replace(new RegExp(`(?:${PIECE})(?:\\s*\\+\\s*(?:${PIECE}))+`, 'gu'), (expr) =>
    [...expr.matchAll(new RegExp(PIECE, 'gu'))].map((m) => pieceValue(m)).join(''));
  if (vars.size >= 2) {
    joined = joined.replace(/\b[A-Za-z_]\w{0,15}(?:\s*\+\s*[A-Za-z_]\w{0,15})+\b/g, (expr) => {
      const names = expr.split('+').map((n) => n.trim());
      return names.every((n) => vars.has(n)) ? names.map((n) => vars.get(n)).join('') : expr;
    });
  }
  if (joined !== text) out.push(joined);
  for (const line of text.split('\n')) {
    if (!JOIN_CUE.test(line)) continue;
    const pieces = [...line.matchAll(new RegExp(PIECE, 'gu'))].map((m) => pieceValue(m)).slice(0, MAX_PIECES);
    if (pieces.length >= 2) out.push(pieces.join(''), pieces.join(' '));
  }
  return [...new Set(out)];
}

/** Decoded texts found in `text`, including encodings nested up to two levels deep. */
export function decodeEmbedded(text: string): string[] {
  const found: string[] = [];
  let budget = MAX_OUTPUT_CHARS;
  /** Records one decoding and looks inside it; false once the result or size budget is spent. */
  const keep = (decoded: string | undefined, depth: number): boolean => {
    if (found.length >= MAX_RESULTS || budget <= 0) return false;
    if (!decoded || found.includes(decoded)) return true;
    found.push(decoded.slice(0, budget));
    budget -= decoded.length;
    if (depth < MAX_DEPTH) visit(decoded, depth + 1);
    return true;
  };
  const visit = (source: string, depth: number): void => {
    for (const joined of joinPieces(source)) if (!keep(joined, depth)) return;
    for (const [pattern, decode] of DECODERS) {
      for (const match of source.matchAll(pattern)) {
        if (match[0].length > MAX_RUN_CHARS) continue;
        if (!keep(decode(match[0]), depth)) return;
      }
    }
  };
  visit(text, 1);
  return found;
}

/** Cyrillic and Greek letters that look like Latin ones. */
const HOMOGLYPHS: Record<string, string> = {
  а: 'a', с: 'c', е: 'e', і: 'i', ј: 'j', о: 'o', р: 'p', ѕ: 's', х: 'x', у: 'y', ԁ: 'd', һ: 'h', ӏ: 'l', ԛ: 'q', ԝ: 'w',
  А: 'A', В: 'B', С: 'C', Е: 'E', Н: 'H', І: 'I', Ј: 'J', К: 'K', М: 'M', О: 'O', Р: 'P', Ѕ: 'S', Т: 'T', Х: 'X', У: 'Y',
  α: 'a', ο: 'o', ν: 'v', ρ: 'p', τ: 't', υ: 'u', ι: 'i', κ: 'k', Α: 'A', Β: 'B', Ε: 'E', Η: 'H', Ι: 'I', Κ: 'K', Μ: 'M', Ν: 'N', Ο: 'O', Ρ: 'P', Τ: 'T', Χ: 'X', Υ: 'Y', Ζ: 'Z',
};
/**
 * lower, UPPER (plural "IDs" too), Title, camelCase, PascalCase, acronyms ("XMLHttpRequest", "ChatGPT", "iPhone").
 * Inner humps need two lowercase letters, otherwise "PrEvIoUs" would pass as PascalCase.
 */
const NAMING_STYLE = /^(?:[A-Z]+s?|[A-Z]*[a-z]*(?:[A-Z][a-z]{2,}|[A-Z]{2,})*(?:[A-Z][a-z]?)?s?)$/;
const LEET_BACK: Record<string, string> ={ '4': 'a', '@': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '5': 's', $: 's', '7': 't', '9': 'g', '8': 'b' };

/**
 * Undoes character-level obfuscation: look-alike letters, fullwidth forms, "i g n o r e" / "i.g.n.o.r.e"
 * spelling, l33t inside words and rAnDoM casing. Returns the text unchanged when nothing was obfuscated.
 */
export function deobfuscate(text: string): string {
  let out = text.normalize('NFKC');
  // Look-alike letters only count inside words that also hold Latin letters (Russian or Greek prose stays as is).
  out = out.replace(/[\p{L}\p{M}]+/gu, (word) => (/[A-Za-z]/.test(word) ? [...word].map((c) => HOMOGLYPHS[c] ?? c).join('') : word));
  // Letters separated one by one with a space or punctuation: "i g n o r e", "i.g.n.o.r.e", "i-g-n-o-r-e".
  out = out.replace(/\b(?:[A-Za-z][ ._\-*]){3,}[A-Za-z]\b/g, (run) => run.replace(/[ ._\-*]/g, ''));
  // l33t: digits or symbols inside words that are mostly letters ("1gn0r3", "in5truc71on$").
  // Symbols count only between letters or digits ("Hello!" stays), e-mail addresses stay, and so do
  // version-like tokens (sha256, v2, x86, MLH1), hex ids (7f3a), numbers with a unit or suffix
  // (1st, 10AM, 3pm, 2fa, 200bini), ISO date-time fragments (28T07) and \u/\x escapes (u003e, x1b).
  // When l33t is everywhere ("7he", "@nd", "0f" in over a fifth of the
  // words), the text is obfuscated as a whole and every word with a letter is mapped back.
  const leety = (w: string) => /[A-Za-z]/.test(w) && /[0-9@$!]/.test(w);
  // Counted without e-mail addresses and without a closing "!" ("Hello!").
  const tokens = (out.replace(/\S+@\S+\.\w+/g, ' ').match(/[\p{L}0-9@$!]+/gu) ?? [])
    .map((w) => w.replace(/!+$/, ''))
    .filter((w) => /\p{L}/u.test(w));
  const versionLike = /^[A-Za-z]?\d+$|\d{2,}$|^[A-Z]+\d+$|^\d{2,}\p{L}+$|^[0-9a-f]{4,}$/u; // v2, sha256, MLH1, 200bini, 7f3a
  const counted = tokens.filter((w) => leety(w) && !versionLike.test(w)).length;
  const everywhere = tokens.length >= 5 && counted >= 3 && counted / tokens.length > 0.2;
  const map = (w: string) => [...w].map((c) => LEET_BACK[c] ?? c).join('');
  // ISO date-time fragments (28T07) and \u / \x escapes (u003e, x1b) are not l33t — never map them, in either branch.
  const structuredToken = (w: string) => /^\d+T\d+$|^u[0-9a-fA-F]{4}$|^x[0-9a-fA-F]{2}$/.test(w);
  if (everywhere) {
    // Short all-l33t words ("@", "70", "15", "!5") are mapped too: here they are "a", "to", "is".
    const shortLeet = (w: string) => w.length <= 3 && [...w].every((c) => c in LEET_BACK);
    out = out.replace(/[A-Za-z0-9@$!]+/g, (word, at: number, all: string) =>
      (leety(word) || shortLeet(word)) && !structuredToken(word) && !(word.includes('@') && /^\.[A-Za-z]/.test(all.slice(at + word.length))) ? map(word) : word);
  }
  out = out.replace(/[A-Za-z0-9](?:[A-Za-z0-9@$!]*[A-Za-z0-9])?/g, (word, at: number, all: string) => {
    const swaps = [...word].filter((c) => c in LEET_BACK).length;
    if (swaps === 0 || swaps > (word.length * 2) / 3 || !/[A-Za-z]/.test(word)) return word;
    if (structuredToken(word) || /^[A-Za-z]?\d+$|^[A-Za-z]+\d{2,}$|^[A-Z]+\d+$|^\d+[A-Za-z]{1,3}$|^\d{2,}[A-Za-z]+$|^[0-9a-f]+$/.test(word)) return word;
    if (word.includes('@') && /^\.[A-Za-z]/.test(all.slice(at + word.length))) return word;
    return map(word);
  });
  // rAnDoM casing: when most words are neither lower, UPPER nor Title case, the whole text is lowercased
  // (prose with a few camelCase names stays); otherwise only odd words with several flips are.
  const words = out.match(/\p{L}{3,}/gu) ?? [];
  const mixed = words.filter((w) => w !== w.toLowerCase() && w !== w.toUpperCase() && w.slice(1) !== w.slice(1).toLowerCase()).length;
  // Turkish text lowercases I to ı, not i.
  if (words.length >= 4 && mixed / words.length > 0.5) return out.toLocaleLowerCase(/[ğşıİĞŞ]/.test(out) ? 'tr' : 'en');
  out = out.replace(/[A-Za-z]{4,}/g, (word) => (!NAMING_STYLE.test(word) && (word.slice(1).match(/[a-z][A-Z]|[A-Z][a-z]/g)?.length ?? 0) >= 2 ? word.toLowerCase() : word));
  return out;
}

const IMAGE_DATA_URI = /data:image\/(?:png|jpe?g|gif|webp|x-icon|vnd\.microsoft\.icon);base64,([A-Za-z0-9+/]+={0,2})/gi;
/** File signatures; a data URI only counts as an image when its bytes start with one. */
const IMAGE_MAGIC = ['89504e470d0a1a0a', 'ffd8ff', '47494638', '52494646', '00000100'];

/**
 * Replaces embedded raster images (`data:image/png;base64,…`, as in MCP tool icons) with the word "image".
 * The classifier reads a long base64 blob as obfuscation and flags it: every false alarm on the GitHub
 * server's tool list came from its icons. Only payloads that decode to a real image signature are removed,
 * so text dressed up as an image is still scanned. SVG is text and is never removed.
 */
export function stripImageData(text: string): string {
  return text.replace(IMAGE_DATA_URI, (uri, b64: string) => {
    const head = Buffer.from(b64.slice(0, 16), 'base64').toString('hex');
    return IMAGE_MAGIC.some((m) => head.startsWith(m)) ? 'image' : uri;
  });
}

/**
 * What the scanners read: the text with character-level obfuscation undone, plus everything decoded
 * from it. Scanning the de-obfuscated form (not the raw one) keeps odd-looking but harmless text from
 * scoring as an attack merely for looking odd.
 */
export function withDecoded(text: string): string {
  const plain = deobfuscate(text);
  const decoded = decodeEmbedded(text);
  return decoded.length === 0 ? plain : `${plain}\n${decoded.join('\n')}`;
}
