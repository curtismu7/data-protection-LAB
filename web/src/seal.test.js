// The browser half of the sealing, against the REAL server sealer: a record sealed by server/src/seal.js opens with WebCrypto, a wrong key and
// any alteration do not, and unsupported browsers get a message. (The server side has its own Node-side decrypt tests.)
import { describe, expect, it } from "vitest";
import { sealRecord, parsePublicJwk } from "../../server/src/seal.js";
import { fromB64u, generateKeyPair, openEnvelope, parsePrivateJwk, toB64u, x25519Support } from "./seal";

const seal = (kp, o = {}) => sealRecord({ publicKey: parsePublicJwk(kp.publicJwk), keyId: "k1", recordId: "r-1", plaintext: "hello from the server", ...o });

describe("browser seal", () => {
  it("opens a record sealed by the server, including UTF-8 and a large one", async () => {
    const kp = await generateKeyPair();
    expect(await openEnvelope(kp.privateJwk, seal(kp))).toEqual({ ok: true, plaintext: "hello from the server" });
    for (const t of ["héllo ✓ 😀", "", "x".repeat(70000)]) expect((await openEnvelope(kp.privateJwk, seal(kp, { plaintext: t }))).plaintext).toBe(t);
  });

  it("a wrong key cannot open it, and any alteration of the envelope is detected", async () => {
    const a = await generateKeyPair(); const b = await generateKeyPair(); const env = seal(a);
    const bad = await openEnvelope(b.privateJwk, env);
    expect(bad.ok).toBe(false); expect(bad.reason).toMatch(/cannot open/);
    const flip = (f) => { const x = fromB64u(env[f]); x[0] ^= 1; return toB64u(x); };
    for (const alt of [{ ct: flip("ct") }, { nonce: flip("nonce") }, { epk: flip("epk") }, { kid: "k2" }, { rid: "r-2" }]) expect((await openEnvelope(a.privateJwk, { ...env, ...alt })).ok).toBe(false);
    expect((await openEnvelope(a.privateJwk, { ...env, v: "lab-seal/2" })).reason).toMatch(/version/);
    expect((await openEnvelope(a.privateJwk, { ...env, nonce: "AA" })).reason).toMatch(/malformed/);
    expect((await openEnvelope(a.privateJwk, null)).ok).toBe(false);
  });

  it("a rotated key: each record opens with the key it was sealed to and not the other", async () => {
    const k1 = await generateKeyPair(); const k2 = await generateKeyPair();
    const r1 = seal(k1, { keyId: "v1" }); const r2 = seal(k2, { keyId: "v2" });
    expect((await openEnvelope(k1.privateJwk, r1)).ok).toBe(true); expect((await openEnvelope(k2.privateJwk, r2)).ok).toBe(true);
    expect((await openEnvelope(k2.privateJwk, r1)).ok).toBe(false); expect((await openEnvelope(k1.privateJwk, r2)).ok).toBe(false);
  });

  it("generated keys are X25519 JWKs with a 32-byte x and d, and the public half carries no d", async () => {
    const kp = await generateKeyPair();
    expect(kp.publicJwk).toEqual({ kty: "OKP", crv: "X25519", x: kp.privateJwk.x }); expect("d" in kp.publicJwk).toBe(false);
    expect(fromB64u(kp.privateJwk.d)).toHaveLength(32); expect(fromB64u(kp.privateJwk.x)).toHaveLength(32);
  });

  it("private key parsing refuses anything that is not a complete X25519 private JWK", () => {
    const ok = { kty: "OKP", crv: "X25519", x: toB64u(new Uint8Array(32)), d: toB64u(new Uint8Array(32)) };
    expect(parsePrivateJwk(JSON.stringify(ok)).jwk).toEqual(ok);
    for (const bad of ["{nope", "null", JSON.stringify({ ...ok, d: undefined }), JSON.stringify({ ...ok, crv: "P-256" }), JSON.stringify({ ...ok, d: "AA" }), JSON.stringify({ ...ok, x: 5 })]) expect(parsePrivateJwk(bad).error).toBeTruthy();
  });

  it("an unsupported browser gets a clear message, not a silent failure", async () => {
    const real = globalThis.crypto.subtle.generateKey;
    globalThis.crypto.subtle.generateKey = async () => { throw new Error("NotSupportedError"); };
    try { const s = await x25519Support(); expect(s.ok).toBe(false); expect(s.reason).toMatch(/does not support X25519/); } finally { globalThis.crypto.subtle.generateKey = real; }
    expect((await x25519Support()).ok).toBe(true);
  });
});
