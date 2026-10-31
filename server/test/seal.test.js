import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SEAL_VERSION, SealError, parsePublicJwk, sealRecord } from '../src/seal.js';
import { makeTestKey, openSealed } from './helpers.js';

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src');
const seal = (key, o = {}) => sealRecord({ publicKey: parsePublicJwk(key.publicJwk), keyId: 'k1', recordId: 'r-1', plaintext: 'hello sealed world', ...o });

test('a Node-side decrypt with a TEST-ONLY key proves the envelope: fields, round trip, UTF-8, empty and large plaintexts', () => {
  const key = makeTestKey();
  const env = seal(key);
  assert.deepEqual(Object.keys(env).sort(), ['ct', 'epk', 'kid', 'nonce', 'rid', 'v']);
  assert.equal(env.v, SEAL_VERSION); assert.equal(env.kid, 'k1'); assert.equal(env.rid, 'r-1');
  assert.equal(openSealed(key.privateJwk, env), 'hello sealed world');
  for (const text of ['héllo ✓ 😀', '', 'x'.repeat(70000)]) assert.equal(openSealed(key.privateJwk, seal(key, { plaintext: text })), text);
  assert.equal(Buffer.from(env.epk, 'base64url').length, 32); assert.equal(Buffer.from(env.nonce, 'base64url').length, 12);
  assert.equal(Buffer.from(env.ct, 'base64url').length, Buffer.byteLength('hello sealed world') + 16, 'ciphertext plus the 16-byte tag');
});

test('the ciphertext does not contain the plaintext, and sealing the same text twice gives different envelopes', () => {
  const key = makeTestKey(); const text = 'PLAINTEXT-MARKER-1234567890';
  const a = seal(key, { plaintext: text }); const b = seal(key, { plaintext: text });
  assert.ok(!Buffer.from(a.ct, 'base64url').toString('latin1').includes('MARKER') && !JSON.stringify(a).includes('MARKER'));
  assert.notEqual(a.ct, b.ct); assert.notEqual(a.epk, b.epk); assert.notEqual(a.nonce, b.nonce);
});

test('a WRONG key cannot open a record', () => {
  const a = makeTestKey(); const b = makeTestKey();
  assert.throws(() => openSealed(b.privateJwk, seal(a)));
  assert.equal(openSealed(a.privateJwk, seal(a)), 'hello sealed world');
});

test('tamper detection: flipping ANY byte of the ciphertext or tag, or changing the epk, nonce, kid or rid, makes opening fail', () => {
  const key = makeTestKey(); const env = seal(key, { plaintext: 'tamper me please' });
  const ct = Buffer.from(env.ct, 'base64url');
  for (let i = 0; i < ct.length; i++) { const c = Buffer.from(ct); c[i] ^= 1; assert.throws(() => openSealed(key.privateJwk, { ...env, ct: c.toString('base64url') }), `byte ${i}`); }
  const flip = (field) => { const b = Buffer.from(env[field], 'base64url'); b[0] ^= 1; return b.toString('base64url'); };
  assert.throws(() => openSealed(key.privateJwk, { ...env, nonce: flip('nonce') }));
  assert.throws(() => openSealed(key.privateJwk, { ...env, epk: flip('epk') }));
  assert.throws(() => openSealed(key.privateJwk, { ...env, kid: 'k2' }));
  assert.throws(() => openSealed(key.privateJwk, { ...env, rid: 'r-2' }), 'a ciphertext cannot be moved to another record id');
  assert.throws(() => openSealed(key.privateJwk, { ...env, ct: ct.subarray(0, ct.length - 1).toString('base64url') }));
});

test('a nonce (and the ephemeral key) is never reused across 500 records', () => {
  const key = makeTestKey(); const nonces = new Set(); const epks = new Set();
  for (let i = 0; i < 500; i++) { const e = seal(key, { recordId: `r-${i}`, plaintext: `p${i}` }); nonces.add(e.nonce); epks.add(e.epk); }
  assert.equal(nonces.size, 500); assert.equal(epks.size, 500);
});

test('the random source is used for BOTH the ephemeral key and the nonce (a fixed source would repeat them, which the test above would catch)', () => {
  const key = makeTestKey(); let calls = 0;
  const fixed = (n) => { calls++; return Buffer.alloc(n, 7); };
  const a = sealRecord({ publicKey: parsePublicJwk(key.publicJwk), keyId: 'k', recordId: 'r', plaintext: 'x', random: fixed });
  const b = sealRecord({ publicKey: parsePublicJwk(key.publicJwk), keyId: 'k', recordId: 'r', plaintext: 'x', random: fixed });
  assert.equal(calls, 4); assert.deepEqual(a, b, 'with a repeating source the envelopes repeat: the real source must not');
});

test('a rotated KeyID still opens old records with the retired private key; each key opens only its own', () => {
  const k1 = makeTestKey(); const k2 = makeTestKey();
  const r1 = seal(k1, { keyId: 'key-2026-10', recordId: 'a' }); const r2 = seal(k2, { keyId: 'key-2026-11', recordId: 'b' });
  assert.equal(openSealed(k1.privateJwk, r1), 'hello sealed world'); assert.equal(openSealed(k2.privateJwk, r2), 'hello sealed world');
  assert.throws(() => openSealed(k2.privateJwk, r1)); assert.throws(() => openSealed(k1.privateJwk, r2));
});

test('public key parsing: JSON string or object; a PRIVATE key (any d) is refused; wrong type, curve, length and encoding are refused without echoing the input', () => {
  const key = makeTestKey();
  assert.ok(parsePublicJwk(key.publicJwk).x.length === 32); assert.ok(parsePublicJwk(JSON.stringify(key.publicJwk)).x.length === 32);
  const refusal = (input, code, re) => assert.throws(() => parsePublicJwk(input), (e) => e instanceof SealError && e.code === code && re.test(e.message));
  refusal(key.privateJwk, 'private_key_refused', /PRIVATE key/); refusal(JSON.stringify(key.privateJwk), 'private_key_refused', /PRIVATE/); refusal({ ...key.publicJwk, d: 'x' }, 'private_key_refused', /PRIVATE/);
  refusal({ ...key.publicJwk, kty: 'RSA' }, 'bad_key', /X25519/); refusal({ ...key.publicJwk, crv: 'P-256' }, 'bad_key', /X25519/); refusal({ ...key.publicJwk, crv: 'Ed25519' }, 'bad_key', /X25519/);
  refusal({ ...key.publicJwk, x: Buffer.alloc(31).toString('base64url') }, 'bad_key', /32 bytes/); refusal({ ...key.publicJwk, x: Buffer.alloc(33).toString('base64url') }, 'bad_key', /32 bytes/);
  refusal({ ...key.publicJwk, x: 'not base64!!' }, 'bad_key', /32 bytes/); refusal({ ...key.publicJwk, x: 5 }, 'bad_key', /32 bytes/);
  refusal('{not json', 'bad_key', /not JSON/); refusal('x'.repeat(2001), 'bad_key', /too long/); refusal([], 'bad_key', /object/); refusal(null, 'bad_key', /object/); refusal(5, 'bad_key', /object/);
  try { parsePublicJwk({ kty: 'OKP', crv: 'X25519', x: 'MARKERMARKERMARKERMARKERMARKERMARKERMARKER' }); } catch (e) { assert.ok(!e.message.includes('MARKER')); }
});

test('the server code can only SEAL: no decipher, no decrypt, no key-pair generator, no use of a private member anywhere in server/src', () => {
  const files = fs.readdirSync(SRC).filter((f) => f.endsWith('.js'));
  for (const f of files) {
    const code = fs.readFileSync(path.join(SRC, f), 'utf8').split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
    assert.ok(!/createDecipheriv|\.decrypt\(|privateDecrypt|generateKeyPair|subtle\.generateKey|Decipher/.test(code), `${f} must not decrypt or generate key pairs`);
  }
  const sealSrc = fs.readFileSync(path.join(SRC, 'seal.js'), 'utf8');
  assert.match(sealSrc, /302e020100300506032b656e04220420/, 'the X25519 key is built from a PKCS8 prefix plus 32 random bytes');
  assert.ok(!/generateKeyPair/.test(sealSrc.split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n')));
  assert.match(sealSrc, /createCipheriv\('aes-256-gcm'/); assert.match(sealSrc, /hkdfSync\('sha256'/); assert.match(sealSrc, /diffieHellman\(/);
});
