// The browser half: key generation and opening a sealed record with WebCrypto. The private key is held by the caller in memory only; nothing
// here sends it anywhere, stores it, or logs it. Envelope format "lab-seal/1" is LAB-INVENTED (see server/src/seal.js).
const enc = new TextEncoder(); const dec = new TextDecoder();
export const SEAL_VERSION = "lab-seal/1";

export const toB64u = (bytes) => { let s = ""; for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
export const fromB64u = (s) => { const p = String(s).replace(/-/g, "+").replace(/_/g, "/"); const bin = atob(p + "=".repeat((4 - (p.length % 4)) % 4)); return Uint8Array.from(bin, (c) => c.charCodeAt(0)); };

// Does this browser do X25519 in WebCrypto? Answers with a reason a person can act on, never a silent failure.
export async function x25519Support() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return { ok: false, reason: "This page needs WebCrypto (a secure context: http://localhost or https). It is not available here, so keys cannot be made or records opened." };
  try { const k = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]); if (!k?.privateKey) throw new Error("no key"); return { ok: true, reason: "" }; } catch {
    return { ok: false, reason: "This browser does not support X25519 in WebCrypto (use a current Chrome, Edge, Safari or Firefox). Sealing still works on the server side, but this page cannot make a key or open a record." };
  }
}

export async function generateKeyPair() {
  const k = await globalThis.crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const priv = await globalThis.crypto.subtle.exportKey("jwk", k.privateKey);
  const pub = await globalThis.crypto.subtle.exportKey("jwk", k.publicKey);
  return { publicJwk: { kty: "OKP", crv: "X25519", x: pub.x }, privateJwk: { kty: "OKP", crv: "X25519", x: priv.x, d: priv.d } };
}

export function parsePrivateJwk(text) {
  let o; try { o = typeof text === "string" ? JSON.parse(text) : text; } catch { return { error: "That is not JSON." }; }
  if (!o || o.kty !== "OKP" || o.crv !== "X25519" || typeof o.d !== "string" || typeof o.x !== "string") return { error: "A private X25519 JWK needs kty OKP, crv X25519, x and d." };
  try { if (fromB64u(o.d).length !== 32 || fromB64u(o.x).length !== 32) return { error: "x and d must each be 32 bytes." }; } catch { return { error: "x and d must be base64url." }; }
  return { jwk: { kty: "OKP", crv: "X25519", x: o.x, d: o.d } };
}

// Opens one record. Returns { ok: true, plaintext } or { ok: false, reason } (a wrong key and a tampered record look the same: AES-GCM refuses both).
export async function openEnvelope(privateJwk, env) {
  try {
    if (!env || env.v !== SEAL_VERSION) return { ok: false, reason: "Unknown envelope version." };
    const subtle = globalThis.crypto.subtle;
    const epk = fromB64u(env.epk); const nonce = fromB64u(env.nonce); const ct = fromB64u(env.ct);
    if (epk.length !== 32 || nonce.length !== 12 || ct.length < 16) return { ok: false, reason: "The envelope is malformed." };
    const priv = await subtle.importKey("jwk", { kty: "OKP", crv: "X25519", x: privateJwk.x, d: privateJwk.d }, { name: "X25519" }, false, ["deriveBits"]);
    const pub = await subtle.importKey("raw", epk, { name: "X25519" }, false, []);
    const bits = await subtle.deriveBits({ name: "X25519", public: pub }, priv, 256);
    const salt = new Uint8Array(64); salt.set(epk, 0); salt.set(fromB64u(privateJwk.x), 32);
    const hk = await subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    const aes = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode(`${SEAL_VERSION}|aes-256-gcm|${env.kid}`) }, hk, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const plain = await subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: enc.encode(`${SEAL_VERSION}|${env.kid}|${env.rid}`), tagLength: 128 }, aes, ct);
    return { ok: true, plaintext: dec.decode(plain) };
  } catch { return { ok: false, reason: "This key cannot open this record (wrong key, or the record was altered)." }; }
}
