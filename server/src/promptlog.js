// Prompt-logging settings (modelPromptLogConfig: Enabled, PublicKey, KeyID, Surfaces, IncludeResponses, MaxBytes; console swagger names,
// 2026-10-31, schema only). Off until a tenant asks, and nothing is recorded without a public key. Behaviour here is the lab's reading.
import { SURFACES } from './categories.js';
import { SealError, parsePublicJwk } from './seal.js';
import { looksLikeCredentialId } from './mask.js';

export const PL_LIMITS = { defaultMaxBytes: 16384, minBytes: 256, maxBytes: 65536 };
export const defaultPromptLog = () => ({ Enabled: false, PublicKey: '', KeyID: '', Surfaces: [], IncludeResponses: false, MaxBytes: 0 });
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Returns { ok, errors, config, publicKey }. A missing field is its default; a wrong-typed one is an error. Errors never echo the input.
export function validatePromptLog(c) {
  const errors = []; const config = defaultPromptLog(); let publicKey = null;
  if (c === undefined) return { ok: true, errors, config, publicKey };
  if (!isObj(c)) return { ok: false, errors: [{ field: 'promptLog', message: 'must be an object' }], config, publicKey };
  const has = (k) => Object.hasOwn(c, k);
  if (has('Enabled')) { if (typeof c.Enabled === 'boolean') config.Enabled = c.Enabled; else errors.push({ field: 'Enabled', message: 'must be true or false' }); }
  if (has('IncludeResponses')) { if (typeof c.IncludeResponses === 'boolean') config.IncludeResponses = c.IncludeResponses; else errors.push({ field: 'IncludeResponses', message: 'must be true or false' }); }
  if (has('Surfaces')) {
    if (Array.isArray(c.Surfaces) && c.Surfaces.length <= SURFACES.length && c.Surfaces.every((s) => typeof s === 'string' && SURFACES.includes(s))) config.Surfaces = [...new Set(c.Surfaces)];
    else errors.push({ field: 'Surfaces', message: `must list surfaces from ${SURFACES.join(', ')}` });
  }
  if (has('MaxBytes')) {
    if (Number.isInteger(c.MaxBytes) && (c.MaxBytes === 0 || (c.MaxBytes >= PL_LIMITS.minBytes && c.MaxBytes <= PL_LIMITS.maxBytes))) config.MaxBytes = c.MaxBytes;
    else errors.push({ field: 'MaxBytes', message: `must be 0 (the default) or ${PL_LIMITS.minBytes} to ${PL_LIMITS.maxBytes}` });
  }
  if (has('KeyID')) { if (typeof c.KeyID === 'string' && (c.KeyID === '' || (KEY_ID.test(c.KeyID) && !looksLikeCredentialId(c.KeyID)))) config.KeyID = c.KeyID; else errors.push({ field: 'KeyID', message: 'must be a plain name: letters, digits, dot, dash or underscore, up to 64, and not something that looks like personal data or a secret' }); }
  if (has('PublicKey') && c.PublicKey !== '' && c.PublicKey !== null) {
    try { const k = parsePublicJwk(c.PublicKey); publicKey = k; config.PublicKey = JSON.stringify(k.jwk); } catch (e) { errors.push({ field: 'PublicKey', message: e instanceof SealError ? e.message : 'not a usable key' }); }
  }
  if (publicKey && !config.KeyID) errors.push({ field: 'KeyID', message: 'is required with a PublicKey (it names the key a record was sealed to)' });
  return { ok: errors.length === 0, errors, config, publicKey: errors.length ? null : publicKey };
}

// Why a record is NOT written, or null when it is.
export function skipReason(config, publicKey, surface) {
  if (!config.Enabled) return 'prompt logging is off';
  if (!publicKey || !config.PublicKey) return 'no public key: nothing is recorded without one';
  if (config.Surfaces.length && !config.Surfaces.includes(surface)) return 'this surface is not selected';
  return null;
}

// Cut a string to at most `max` UTF-8 bytes without splitting a character.
export function capBytes(s, max) {
  const buf = Buffer.from(String(s), 'utf8');
  if (buf.length <= max) return { text: String(s), cut: false };
  let end = max; while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return { text: buf.subarray(0, end).toString('utf8'), cut: true };
}

// What is sealed: the prompt (and the response when IncludeResponses), capped to MaxBytes in total (the prompt first).
export function plaintextFor(config, prompt, response) {
  const max = config.MaxBytes || PL_LIMITS.defaultMaxBytes;
  const p = capBytes(prompt, max);
  let truncated = p.cut; let r = null;
  if (config.IncludeResponses && typeof response === 'string' && response) {
    const left = max - Buffer.byteLength(p.text, 'utf8');
    if (left <= 0) truncated = true; // no room left: the response is dropped, and the record says it was cut
    else { const c = capBytes(response, left); r = c.text; truncated = truncated || c.cut; }
  }
  const body = { prompt: p.text, ...(r === null ? {} : { response: r }), truncated };
  return { json: JSON.stringify(body), truncated, hasResponse: r !== null };
}
