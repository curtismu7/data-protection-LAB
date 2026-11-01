// Masking. Anything the built-in detectors recognise (every personal-data kind and every secret detector) becomes a marker, so a value a
// visitor types is never echoed back in a response, an audit entry, a hop pane or an error. Iterative: a deep structure cannot overflow the stack.
//
// Two layers, both HEURISTIC (a heuristic recognises common shapes, it does not know what is secret):
//   1. the built-in detectors (pii.js, secrets.js), which see through zero-width characters, controls and fullwidth forms and mark exact spans;
//   2. the credential-shape pass below, which catches what a person WRITES around a secret: "password hunter2xyz", "my password is x", "pw: x",
//      {"password":"x"}, user:pw@host with or without a scheme, "Bearer x", sk-/ghp_/xox/AKIA/eyJ shapes, a private-key block.
// Layer 2 first deletes every C0/C1 control character except tab, newline and carriage return (a keyword cannot hide behind interleaved controls),
// NFKC-normalises, deletes zero-width/format characters, decodes percent-encoding and backslash escapes (\u0070) up to three rounds, and runs twice more with the tab/LF/CR separators
// deleted and with "+" read as a space. Its markers are [masked:credential-shape].
// FALSE-POSITIVE TRADEOFF (on purpose): after a plain space only a keyword (password, pw, token, secret, api key, ...) followed by a token of six or more
// characters that contains a digit is masked, so "password reset", "token bucket" and "the secret is out" stay readable. "password is x" masks x unless x
// is an ordinary word ("required", "wrong"); "token is x", "key is x" and the like need a digit or mixed case. After ":" or "=" ANY value is masked.
// WHAT IT STILL MISSES: a bare word with no keyword and no recognisable shape; look-alike letters from another alphabet (a Cyrillic "а" in "password":
// NFKC does not unify them); a keyword split by an ordinary space or letter ("pass word=x"); a value split over two stream frames when no built-in
// detector sees it; the weak keywords pass, auth, cookie, signature and key unless a value of six or more characters with a digit follows them.
// Every regular expression here is linear or bounded: none nests an unbounded quantifier inside another.
import { detectPii } from './pii.js';
import { detectSecrets } from './secrets.js';
import { normalise } from './normalize.js';

// Replace each span ({ start, end, id }) with a marker; overlapping spans collapse into the first.
export function maskSpans(text, spans) {
  const sorted = spans.filter((s) => s.end > s.start).sort((a, b) => a.start - b.start || b.end - a.end);
  if (!sorted.length) return text;
  let out = ''; let at = 0;
  for (const s of sorted) { if (s.start < at) { at = Math.max(at, s.end); continue; } out += `${text.slice(at, s.start)}[masked:${s.id}]`; at = s.end; }
  return out + text.slice(at);
}

// ---- layer 2: credential shapes ------------------------------------------------------------------------------------------------------------------
export const MARK = '[masked:credential-shape]';
// Markers this app writes itself; they are left alone (and never re-read as a keyword's value).
const MARKER = /(\[(?:masked(?: for display)?|REDACTED):[A-Za-z0-9_.-]{1,60}\])/;
const STRIP = /[\p{Default_Ignorable_Code_Point}\p{Cf}\uFFFD]/gu;
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g; // C0 and C1 except tab, newline, carriage return
export const deleteControls = (s) => s.replace(CONTROL, '');
const IS_CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/;
const flat = (s) => deleteControls(s.replace(STRIP, '').normalize('NFKC').replace(STRIP, ''));

const decodeRun = (run) => { try { return decodeURIComponent(run); } catch { return run.replace(/%([0-9a-fA-F]{2})/g, (m, h) => (parseInt(h, 16) < 128 ? String.fromCharCode(parseInt(h, 16)) : m)); } };
// Text a person writes as an escape is read as the character: percent-encoding (%70), and the backslash forms of JSON, TOML and JavaScript
// (\u0070, \U00000070, \u{70}, \x70, \n, \r, \t, \", \', \\, \/). A keyword cannot hide behind them.
const ESCAPES = /\\u\{([0-9a-fA-F]{1,6})\}|\\[uU]([0-9a-fA-F]{8}|[0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\([nrt"'\\/])/g;
const NAMED = { n: '\n', r: '\r', t: '\t', '"': '"', "'": "'", '\\': '\\', '/': '/' };
const unescapeOnce = (s) => s.replace(ESCAPES, (m, brace, uni, hex, named) => {
  if (named) return NAMED[named];
  const cp = parseInt(brace || uni || hex, 16);
  return cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) ? String.fromCodePoint(cp) : m;
});
const decodeOnce = (s) => unescapeOnce(s.replace(/(?:%[0-9a-fA-F]{2})+/g, decodeRun));

const hasDigit = (s) => /\d/.test(s);
const mixedCase = (s) => /[a-z]/.test(s) && /[A-Z]/.test(s);
const PW = 'passphrase|password|passwd|passcode'; // glued names ("my_password", "password_hash") are fine
const PW_SHORT = 'pwd|pw';
const SEC = 'secret|token|api[-_ ]?key|apikey|credentials?|private[-_ ]?key|access[-_ ]?key|client[-_ ]?secret|session[-_ ]?id|sessionid';
const WEAK = 'pass|auth|authorization|cookie|signature|keys?';
// Words that follow "password is" in ordinary prose and are never a value.
const PLAIN = new Set('a an the and or of to for in on at by as if is was are were be not no with from this that it its can will must should may has have had does do did but so than then when where which who how what used using required invalid incorrect wrong correct expired valid missing empty short long weak strong hashed stored encrypted set reset changed ok okay fine secure safe private public needed mandatory optional blank unknown unset lost forgotten hidden here there now too very case sensitive manager policy rules rule field form'.split(' '));
const VALUE = '"[^"]{0,300}"|\'[^\']{0,300}\'|\\{[^}]{0,300}\\}|\\[[^\\]]{0,300}\\]|[^\\s,;&}\\])]{1,300}';
const plainWord = (v) => PLAIN.has(v.toLowerCase().replace(/[^a-z]/g, '')) && !hasDigit(v);

const DETECTORS = [
  // URL userinfo: scheme://user:pw@host (the whole userinfo goes)
  [/(?<=:\/\/)[^\s/?#@]{1,200}(?=@)/g, () => MARK],
  // header lines run to the end of the line
  [/\b(authorization|proxy-authorization|set-cookie|cookie)(\s{0,20}[:=]\s{0,20})([^\s][^\r\n]{0,299})/gi, (m, k, sep) => `${k}${sep}${MARK}`, 3],
  // keyword assignment: password=x, "password":"x", my_password: x, apiKey => x (any value; the name may carry a short suffix)
  [new RegExp(`(${PW}|(?<![A-Za-z])(?:${PW_SHORT})|${SEC})(s?[\\w-]{0,30}["']?\\s{0,20}(?:=>|->|[:=])\\s{0,20})(${VALUE})`, 'gi'), (m, k, sep) => `${k}${sep}${MARK}`, 3],
  // the weak keywords only when the separator follows at once AND the value is six or more characters with a digit (no "author: Bob", no "keyboard: us",
  // no "key:key-refunds": the engine's own scope strings are written that way)
  [new RegExp(`((?<![A-Za-z])(?:${WEAK}))(["']?\\s{0,20}(?:=>|->|[:=])\\s{0,20})(${VALUE})`, 'gi'), (m, k, sep, v) => (v.length >= 6 && hasDigit(v) ? `${k}${sep}${MARK}` : m), 3],
  // plain language: "my password is x", "the key is x", "token was x"
  [new RegExp(`(${PW}|(?<![A-Za-z])(?:${PW_SHORT})|${SEC}|(?<![A-Za-z])keys?)(s?\\s{1,20}(?:is|was|are)\\s{1,20})(${VALUE})`, 'gi'), (m, k, sep, v) => {
    const isPw = new RegExp(`^(?:${PW}|${PW_SHORT})$`, 'i').test(k);
    const ok = isPw ? v.length >= 4 && !plainWord(v) : v.length >= 4 && (hasDigit(v) || (v.length >= 8 && mixedCase(v)));
    return ok ? `${k}${sep}${MARK}` : m;
  }, 3],
  // keyword, whitespace, then a token of six or more characters that has a digit: "password hunter2xyz", "pw hunter2xyz", "api key hunter2xyz"
  [new RegExp(`(${PW}|(?<![A-Za-z])(?:${PW_SHORT})|${SEC})(s?\\s{1,20})([^\\s,;&}\\])"']{6,300})`, 'gi'), (m, k, sep, v) => (hasDigit(v) ? `${k}${sep}${MARK}` : m), 3],
  // user:password@host with no scheme ("//bob:pw@host", "bob:pw@host"); a "mailto:" address is left alone
  [/(?<![\w.%+-])(?!mailto:)[\w.%+-]{1,200}:[^\s/?#@:]{1,200}(?=@[A-Za-z0-9[])/gi, () => MARK],
  [/\b(bearer|basic)(\s{1,5})([A-Za-z0-9._~+/=-]{6,})/gi, (m, k, sep, v) => (hasDigit(v) || mixedCase(v) || v.length >= 20 ? `${k}${sep}${MARK}` : m), 3],
  [/\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*/g, () => MARK],
  [/\b(?:sk|pk|rk)-(?=[A-Za-z0-9_-]{0,200}\d)[A-Za-z0-9_-]{8,}/g, () => MARK],
  [/\b[spr]k_(?:live|test)_[A-Za-z0-9]{8,}/g, () => MARK],
  [/\b(?:gh[pousr]_[A-Za-z0-9]{6,}|github_pat_[A-Za-z0-9_]{6,}|glpat-[A-Za-z0-9_-]{6,}|xox[abeprs]-[A-Za-z0-9-]{6,}|npm_[A-Za-z0-9]{6,}|AIza[0-9A-Za-z_-]{16,})/g, () => MARK],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{12,}/g, () => MARK],
];
const detect = (text) => DETECTORS.reduce((acc, [re, fn]) => acc.replace(re, fn), text);
// A second look at the text with one kind of character changed; kept only when it finds something the first look did not.
const SECOND_LOOKS = [[/[\t\n\r\u2028\u2029]/g, ''], [/\+/g, ' ']];

// The same detectors as SPANS of the original text (offsets), for the engine's display copy and the stream's split-value masking. They see through
// controls, zero-width characters, fullwidth forms, whitespace runs, percent-encoding and backslash escapes: the text is rewritten round by round
// (at most three) keeping, for every character, the stretch of the ORIGINAL it came from, so a span found in the decoded text masks the right characters.
const DECODE = /(?:%[0-9a-fA-F]{2})+|\\u\{[0-9a-fA-F]{1,6}\}|\\[uU](?:[0-9a-fA-F]{8}|[0-9a-fA-F]{4})|\\x[0-9a-fA-F]{2}|\\[nrt"'\\/]/g;
function decodeRound(t) {
  let s = ''; const a = []; const b = []; let at = 0;
  const keep = (from, to) => { for (let k = from; k < to; k++) { const c = t.s[k]; if (IS_CONTROL.test(c)) continue; s += c; a.push(t.a[k]); b.push(t.b[k]); } };
  for (const m of t.s.matchAll(DECODE)) {
    keep(at, m.index);
    const d = deleteControls(m[0][0] === '%' ? decodeRun(m[0]) : unescapeOnce(m[0])); const st = t.a[m.index]; const en = t.b[m.index + m[0].length - 1];
    s += d; for (let k = 0; k < d.length; k++) { a.push(st); b.push(en); }
    at = m.index + m[0].length;
  }
  keep(at, t.s.length);
  return { s, a, b };
}
function dropSeparators(t) {
  let s = ''; const a = []; const b = [];
  for (let k = 0; k < t.s.length; k++) { if (/[\t\n\r\u2028\u2029]/.test(t.s[k])) continue; s += t.s[k]; a.push(t.a[k]); b.push(t.b[k]); }
  return { s, a, b };
}
export function shapeSpans(text) {
  const n = normalise(String(text), { keepSpace: true }); let t = { s: n.norm, a: n.starts, b: n.ends };
  for (let i = 0; i < 3; i++) { const d = decodeRound(t); if (d.s === t.s) break; t = d; }
  const spans = [];
  // as typed; with "+" read as a space ("password+is+x"); and with tab, newline and carriage return deleted ("pass<TAB>word=x")
  for (const v of [t, { ...t, s: t.s.replace(/\+/g, ' ') }, dropSeparators(t)]) {
    for (const [re, fn, group = 0] of DETECTORS) {
      for (const m of v.s.matchAll(new RegExp(re.source, `${re.flags}d`))) {
        if (fn(...m, m.index, v.s) === m[0]) continue;
        const [s0, e0] = m.indices[group] || m.indices[0]; // the VALUE, so the keyword before it stays readable
        if (e0 > s0) spans.push({ start: v.a[s0], end: v.b[e0 - 1], id: 'credential-shape' });
      }
    }
  }
  return spans;
}

// One marker-free piece of text. Nothing found: the text as typed, controls deleted. Something found: the cleaned, decoded text with it masked.
function shapesIn(piece) {
  let s = flat(piece);
  for (let i = 0; i < 3; i++) { const d = flat(decodeOnce(s)); if (d === s) break; s = d; }
  let out = detect(s);
  for (const [re, to] of SECOND_LOOKS) { const changed = out.replace(re, to); const again = detect(changed); if (again !== changed) out = again; }
  return out === s ? deleteControls(piece) : out;
}
export function maskShapes(text) {
  if (!text) return text;
  return text.split(MARKER).map((p, i) => (i % 2 ? p : shapesIn(p))).join('');
}

// A private-key block, header to end line (or to the end of the text, or 4000 characters): the body is the secret, not just the header.
export const PEM_BLOCK = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,4000}?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|$)/g;
export function maskText(input) {
  const text = deleteControls(String(input)).replace(PEM_BLOCK, '[masked:lab-private-key-block]');
  if (!text) return text;
  const spans = [...detectPii(text).map((f) => ({ start: f.start, end: f.end, id: f.kind })), ...detectSecrets(text).map((f) => ({ start: f.start, end: f.end, id: f.rule }))];
  return maskShapes(maskSpans(text, spans));
}

// An identifier a visitor chose (workspace, rule, key, app) that is shaped like a credential: a long hex or random-looking run, or a secret prefix.
// Such an id is refused and never echoed.
const ID_PREFIX = /^(?:sk|pk|rk|pw|pwd|pass|passwd|password|passphrase|secret|token|tok|bearer|apikey|ghp|gho|ghu|ghs|ghr|glpat|xox[a-z]?|akia|asia|eyj)[-_.]/i;
export function looksLikeCredentialId(id) {
  const s = String(id);
  if (/[0-9a-f]{24,}/i.test(s)) return true; // 24 or more hex characters in a row
  if (/[a-z0-9]{24,}/i.test(s) && /\d/.test(s)) return true; // a long run of letters and digits
  if (ID_PREFIX.test(s)) return true;
  return maskText(s) !== s;
}

// Skipped keys hold opaque fields: a random ciphertext or a trace id must never be "masked" by an accidental match.
const OPAQUE = new Set(['epk', 'nonce', 'ct', 'traceparent', 'traceId', 'PublicKey']);
const put = (obj, key, value) => Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
export function maskDeep(value) {
  const clone = (x) => (Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x);
  const root = { v: clone(value) };
  const work = [[value, root, 'v', false]];
  while (work.length) {
    const [src, dst, key, opaque] = work.pop();
    if (typeof src === 'string') { put(dst, key, opaque ? src : maskText(src)); continue; }
    if (src === null || typeof src !== 'object') { put(dst, key, src); continue; }
    const copy = clone(src); put(dst, key, copy);
    const used = new Set();
    // Object KEYS are text the visitor may have typed: masked too (a collision after masking gets a numeric suffix, nothing is dropped).
    for (const k of Object.keys(src).reverse()) {
      let nk = Array.isArray(src) ? k : maskText(k);
      for (let n = 2; used.has(nk); n++) nk = `${maskText(k)}~${n}`;
      used.add(nk);
      work.push([src[k], copy, nk, OPAQUE.has(k)]);
    }
  }
  return root.v;
}
