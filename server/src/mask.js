// Masking: a thin adapter over the shared masker (./shared/mask.js, shared-masker 1.4.0, commit 9bc664a). The app keeps the names its call sites import.
//
// What the SHARED masker does: plain-language and assignment credentials, URL userinfo, header lines, prefixed tokens, JWTs, private-key blocks, look-alike and
// hidden characters, encodings, and the key-name rules of maskDeep. Marks look like [masked:assignment], [masked:shape], [masked:pem].
// What THIS app adds on purpose: its own detectors (every personal-data kind in pii.js, every secret detector in secrets.js) mark exact spans too, with
// [masked:<kind>] / [masked:<detector>]. Those detectors are the point of the lab, so they stay; only the credential-shape work moved to the shared module.
// Both are HEURISTICS: a short random value with no keyword and no recognisable shape is not found (see README.md, "What it still misses").
//
// Exports kept for the rest of the app: maskSpans, maskText, maskDeep, looksLikeCredentialId, shapeSpans.
import { createMasker } from './shared/mask.js';
import { detectPii } from './pii.js';
import { detectSecrets } from './secrets.js';

// Replace each span ({ start, end, id }) with a marker; overlapping spans collapse into the first.
export function maskSpans(text, spans) {
  const sorted = spans.filter((s) => s.end > s.start).sort((a, b) => a.start - b.start || b.end - a.end);
  if (!sorted.length) return text;
  let out = ''; let at = 0;
  for (const s of sorted) { if (s.start < at) { at = Math.max(at, s.end); continue; } out += `${text.slice(at, s.start)}[masked:${s.id}]`; at = s.end; }
  return out + text.slice(at);
}

// Opaque values: the app writes these itself and they look random, so a detector must never "mask" them by accident. Each is a narrow path, not a name a visitor
// can type: the sealed envelope (seal.js writes epk, nonce, ct), the W3C trace id and traceparent header (trace.js, 32 and 55 hex-shaped characters, validated), and
// the prompt-log PublicKey (promptlog.js re-serialises a validated X25519 public JWK, never the visitor's text).
const OPAQUE_PATH = /^(?:traceId|(?:\w+\.)*headers\.traceparent|(?:\w+\.)*envelope\.(?:epk|nonce|ct)|config\.PublicKey)$/;
const opaque = (_key, path) => OPAQUE_PATH.test(path);
const shared = createMasker({ opaque });

// App detectors over a text: the marked text. Offsets are those of the text it is given.
const appSpans = (text) => [...detectPii(text).map((f) => ({ start: f.start, end: f.end, id: f.kind })), ...detectSecrets(text).map((f) => ({ start: f.start, end: f.end, id: f.rule }))];

// The shared mask first (it sees the whole private-key block and every credential shape), then the app's own detectors over what is left.
export function maskText(input) {
  if (typeof input !== 'string') return shared.maskText(input);
  const s = shared.maskText(input);
  return s ? maskSpans(s, appSpans(s)) : s;
}

// An identifier a visitor chose (workspace, rule, key, app) that is shaped like a credential: refused and never echoed. The shared isCredentialId reads the prefix
// "key-" as a credential; this app's plain ids start with it on purpose ("key-refunds", "key-1", KeyID "key-v2"), so such an id is judged with a neutral prefix.
export function looksLikeCredentialId(id) {
  const s = String(id);
  return shared.isCredentialId(/^key-/i.test(s) ? `id-${s.slice(4)}` : s) || maskText(s) !== s;
}

const MARK = /\[masked:([a-z-]+)\]/g;
// Spans (offsets of the ORIGINAL text) of what the shared masker marks, for the engine's display copy and the stream's split-value masking. The shared masker
// returns the text with each masked stretch replaced by a mark and everything else as typed, so the pieces between the marks are found in the original and what
// lies between them is the span. Pieces are placed from both ends and the two readings are both kept (a repeated piece can never leave part of a value unmasked);
// when the pieces cannot be placed, the whole text is one span.
export function shapeSpans(text) {
  const t = String(text);
  const m = shared.maskText(t);
  if (m === t) return [];
  const ids = [...m.matchAll(MARK)].map((x) => x[1]);
  const pieces = m.split(MARK).filter((_, i) => i % 2 === 0);
  const whole = [{ start: 0, end: t.length, id: ids[0] ?? 'shape' }];
  const first = pieces[0]; const last = pieces[pieces.length - 1];
  if (!ids.length || pieces.length !== ids.length + 1 || !t.startsWith(first) || !t.endsWith(last) || first.length + last.length >= t.length) return whole;
  const stop = t.length - last.length;
  const forward = []; let pos = first.length;
  for (let k = 1; k < pieces.length - 1; k++) { const at = t.indexOf(pieces[k], pos + 1); if (at < 0 || at + pieces[k].length > stop) return whole; forward.push([pos, at]); pos = at + pieces[k].length; }
  forward.push([pos, stop]);
  const backward = []; let end = stop;
  for (let k = pieces.length - 2; k >= 1; k--) { const at = t.lastIndexOf(pieces[k], end - pieces[k].length - 1); if (at < first.length) return whole; backward.unshift([at + pieces[k].length, end]); end = at; }
  backward.unshift([first.length, end]);
  return [...forward, ...backward].map(([start, stop2], i) => ({ start, end: stop2, id: ids[i % ids.length], shape: true })).filter((s) => s.end > s.start);
}

// The response mask over a structure: every string value and every object KEY goes through maskText (opaque members excepted), then the shared maskDeep applies its
// key-name rules (a value under "password" is masked whatever it looks like). Iterative: a deep structure cannot overflow the stack. Keys that collide after masking
// get a numeric suffix; nothing is dropped. The input is never changed.
const put = (obj, key, value) => Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
export function maskDeep(value) {
  const clone = (x) => (Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x);
  const root = { v: clone(value) };
  const work = [[value, root, 'v', '']];
  while (work.length) {
    const [src, dst, key, path] = work.pop();
    if (typeof src === 'string') { put(dst, key, path && opaque(key, path) ? src : maskText(src)); continue; }
    if (src === null || typeof src !== 'object') { put(dst, key, src); continue; }
    const copy = clone(src); put(dst, key, copy);
    const used = new Set();
    for (const k of Object.keys(src).reverse()) {
      let nk = Array.isArray(src) ? k : maskText(k);
      for (let n = 2; used.has(nk); n++) nk = `${maskText(k)}~${n}`;
      used.add(nk);
      work.push([src[k], copy, nk, path ? `${path}.${k}` : k]);
    }
  }
  return shared.maskDeep(root.v);
}
