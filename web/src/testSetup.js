import "@testing-library/jest-dom/vitest";

// React Flow measures the DOM; jsdom has no layout, so give it the few browser APIs it reads.
class RO { observe() {} unobserve() {} disconnect() {} }
globalThis.ResizeObserver = globalThis.ResizeObserver || RO;
globalThis.DOMMatrixReadOnly = globalThis.DOMMatrixReadOnly || class { constructor() { this.m22 = 1; } };
Object.defineProperties(HTMLElement.prototype, {
  offsetWidth: { configurable: true, get() { return 200; } },
  offsetHeight: { configurable: true, get() { return 80; } },
});

// Some Node versions expose a half-working global localStorage that shadows jsdom's; use a plain in-memory one.
if (typeof globalThis.localStorage?.clear !== "function") {
  const store = new Map();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k), clear: () => store.clear() },
  });
}

// jsdom has no scrolling; the reel and the step scroll call these.
Element.prototype.scrollTo = Element.prototype.scrollTo || function scrollTo() {};
Element.prototype.scrollIntoView = Element.prototype.scrollIntoView || function scrollIntoView() {};
window.scrollTo = () => {};

// WebCrypto: jsdom has none worth using, so use Node's. X25519 keys are made the way the server does it (a PKCS8 prefix plus 32 random bytes,
// never a key-pair generator), and subtle.generateKey is routed to that so the page's own "generate a key" button works under test.
import { createPrivateKey, randomBytes, webcrypto } from "node:crypto";
Object.defineProperty(globalThis, "crypto", { configurable: true, value: webcrypto });
const PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
export const testGenerate = async () => {
  const j = createPrivateKey({ key: Buffer.concat([PKCS8, randomBytes(32)]), format: "der", type: "pkcs8" }).export({ format: "jwk" });
  const privateKey = await webcrypto.subtle.importKey("jwk", { kty: "OKP", crv: "X25519", x: j.x, d: j.d }, { name: "X25519" }, true, ["deriveBits"]);
  const publicKey = await webcrypto.subtle.importKey("jwk", { kty: "OKP", crv: "X25519", x: j.x }, { name: "X25519" }, true, []);
  return { privateKey, publicKey };
};
const realGenerate = webcrypto.subtle.generateKey.bind(webcrypto.subtle);
webcrypto.subtle.generateKey = (alg, ...rest) => (alg?.name === "X25519" ? testGenerate() : realGenerate(alg, ...rest));
