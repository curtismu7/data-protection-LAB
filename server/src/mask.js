// Masking. Anything the built-in detectors recognise (every personal-data kind and every secret detector) becomes a marker, so a value a
// visitor types is never echoed back in a response, an audit entry, a hop pane or an error. Iterative: a deep structure cannot overflow the stack.
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
export function maskText(input) {
  const text = String(input);
  if (!text) return text;
  return maskSpans(text, [...detectPii(text).map((f) => ({ start: f.start, end: f.end, id: f.kind })), ...detectSecrets(text).map((f) => ({ start: f.start, end: f.end, id: f.rule }))]);
}

// Skipped keys hold opaque base64url envelope fields: a random ciphertext must never be "masked" by an accidental match.
const OPAQUE = new Set(['epk', 'nonce', 'ct']);
export function maskDeep(value) {
  const clone = (x) => (Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x);
  const root = { v: clone(value) };
  const work = [[value, root, 'v', false]];
  while (work.length) {
    const [src, dst, key, opaque] = work.pop();
    if (typeof src === 'string') { dst[key] = opaque ? src : maskText(src); continue; }
    if (src === null || typeof src !== 'object') { dst[key] = src; continue; }
    const copy = clone(src); dst[key] = copy;
    for (const k of Object.keys(src)) work.push([src[k], copy, k, OPAQUE.has(k)]);
  }
  return root.v;
}
