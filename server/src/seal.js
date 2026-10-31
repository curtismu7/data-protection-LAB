// Sealing a record to a public key. The server ONLY seals: it never holds a private key that could open a record, has no decrypt function,
// and never accepts a private key (a JWK carrying `d` is refused). Per record it makes a fresh ephemeral X25519 key, does ECDH against the
// tenant's public key, runs HKDF-SHA256 and encrypts with AES-256-GCM. The ephemeral private half is wiped as soon as the secret is derived.
// THE ENVELOPE IS LAB-INVENTED (the product's format is not public). Field names, the HKDF salt/info and the AAD below are the lab's own:
//   { v: "lab-seal/1", kid, rid, epk, nonce, ct }   (all base64url; ct = AES-GCM ciphertext followed by its 16-byte tag)
//   HKDF: salt = epk(32) || recipientPublic(32), info = "lab-seal/1|aes-256-gcm|<kid>", 32 bytes out.   AAD = "lab-seal/1|<kid>|<rid>".
// X25519 keys are built with createPrivateKey from a PKCS8 prefix plus 32 random bytes (never generateKeyPair: SIGABRT lesson in the rulebook).
import { createCipheriv, createPrivateKey, createPublicKey, diffieHellman, hkdfSync, randomBytes } from 'node:crypto';

export const SEAL_VERSION = 'lab-seal/1';
const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');
export class SealError extends Error { constructor(code, message) { super(message); this.code = code; } }
export const b64u = (buf) => Buffer.from(buf).toString('base64url');
const fromB64u = (s) => (typeof s === 'string' && /^[A-Za-z0-9_-]+$/.test(s) ? Buffer.from(s, 'base64url') : null);

// A public JWK from a JSON string or an object. Returns { x: Buffer(32), jwk } or throws a SealError that never echoes the input.
export function parsePublicJwk(input) {
  let o = input;
  if (typeof input === 'string') { if (input.length > 2000) throw new SealError('bad_key', 'the key is too long'); try { o = JSON.parse(input); } catch { throw new SealError('bad_key', 'the key is not JSON'); } }
  if (o === null || typeof o !== 'object' || Array.isArray(o)) throw new SealError('bad_key', 'the key must be a JSON Web Key object');
  if (Object.hasOwn(o, 'd')) throw new SealError('private_key_refused', 'that is a PRIVATE key: paste only the public half, and keep the private half in your browser');
  if (o.kty !== 'OKP' || o.crv !== 'X25519') throw new SealError('bad_key', 'the key must be an X25519 public JWK (kty OKP, crv X25519)');
  const x = fromB64u(o.x);
  if (!x || x.length !== 32) throw new SealError('bad_key', 'the key x value must be 32 bytes, base64url');
  // A key the server can seal to AND the browser can open: bit 255 clear (the browser derives its HKDF salt from its own x, so a set bit seals
  // but cannot be opened), and a real key agreement with a throwaway key must work and give a non-zero secret (a low-order point is refused).
  if (x[31] & 0x80) throw new SealError('bad_key', 'the key x value is not a canonical X25519 public key (the top bit must be clear)');
  try {
    const probe = createPrivateKey({ key: Buffer.concat([PKCS8_X25519, randomBytes(32)]), format: 'der', type: 'pkcs8' });
    const secret = diffieHellman({ privateKey: probe, publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64u(x) }, format: 'jwk' }) });
    if (!secret.some((b) => b !== 0)) throw new Error('zero');
  } catch { throw new SealError('bad_key', 'the key is not a usable X25519 public key (a low-order point is refused)'); }
  return { x, jwk: { kty: 'OKP', crv: 'X25519', x: b64u(x) } };
}

const aadOf = (kid, rid) => Buffer.from(`${SEAL_VERSION}|${kid}|${rid}`, 'utf8');
export const infoOf = (kid) => Buffer.from(`${SEAL_VERSION}|aes-256-gcm|${kid}`, 'utf8');

// '|' separates the HKDF info and the AAD fields. It is unambiguous because kid is restricted to [A-Za-z0-9._-] (promptlog.js) and rid is hex we
// generate; this guard makes the encoding refuse anything else instead of relying on the callers.
export function sealRecord({ publicKey, keyId, recordId, plaintext, random = randomBytes }) {
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(keyId) || !/^[A-Za-z0-9._-]{1,64}$/.test(recordId)) throw new SealError('bad_id', 'key and record ids are plain names');
  const recipient = publicKey.x;
  const seed = random(32);
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_X25519, seed]), format: 'der', type: 'pkcs8' });
  const epk = Buffer.from(createPublicKey(priv).export({ format: 'jwk' }).x, 'base64url');
  const secret = diffieHellman({ privateKey: priv, publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64u(recipient) }, format: 'jwk' }) });
  seed.fill(0);
  const key = Buffer.from(hkdfSync('sha256', secret, Buffer.concat([epk, recipient]), infoOf(keyId), 32));
  secret.fill(0);
  const nonce = random(12);
  const c = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  c.setAAD(aadOf(keyId, recordId));
  const ct = Buffer.concat([c.update(plaintext, 'utf8'), c.final(), c.getAuthTag()]);
  key.fill(0);
  return { v: SEAL_VERSION, kid: keyId, rid: recordId, epk: b64u(epk), nonce: b64u(nonce), ct: b64u(ct) };
}
