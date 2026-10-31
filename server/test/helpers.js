import http from 'node:http';
import { createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, hkdfSync, randomBytes } from 'node:crypto';
import { createApp, startHttpServer } from '../src/app.js';
import { createHealth } from '../src/health.js';
import { createWorkspaces } from '../src/workspaces.js';
import { createRegexRunner } from '../src/regexRunner.js';

export async function withServer(fn, { configFile = '/nonexistent/customer.config.json', workspaces = createWorkspaces(), runner } = {}) {
  const health = createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });
  await health.ready;
  const r = runner || createRegexRunner();
  const { server, url } = await startHttpServer({ port: 0, host: '127.0.0.1', app: createApp({ health, configFile, workspaces, runner: r }) });
  try { await fn(url.replace(/\/$/, ''), { workspaces, runner: r }); } finally { health.stop(); await new Promise((res) => server.close(res)); if (!runner) await r.close(); }
}

export const post = (url, path, body, headers = {}) => fetch(`${url}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url, ...headers }, body: JSON.stringify(body) });
export const get = (url, path, headers = {}) => fetch(`${url}${path}`, { headers });
export const json = async (res) => res.json();

// fetch cannot set Host; node:http can.
export function rawHttp(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method, headers, agent: false }, (res) => {
      let data = ''; res.on('data', (c) => { data += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: data }));
    });
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}

// ---- TEST-ONLY crypto: a keypair and a Node-side opener. Nothing like this exists in server/src (a test pins that). -------------------------------
const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
export function makeTestKey() {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8, randomBytes(32)]), format: 'der', type: 'pkcs8' });
  const j = priv.export({ format: 'jwk' });
  return { publicJwk: { kty: 'OKP', crv: 'X25519', x: j.x }, privateJwk: { kty: 'OKP', crv: 'X25519', x: j.x, d: j.d } };
}
export function openSealed(privateJwk, env) {
  const priv = createPrivateKey({ key: privateJwk, format: 'jwk' });
  const epk = Buffer.from(env.epk, 'base64url');
  const secret = diffieHellman({ privateKey: priv, publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: env.epk }, format: 'jwk' }) });
  const recipient = Buffer.from(privateJwk.x, 'base64url');
  const key = Buffer.from(hkdfSync('sha256', secret, Buffer.concat([epk, recipient]), Buffer.from(`lab-seal/1|aes-256-gcm|${env.kid}`), 32));
  const ct = Buffer.from(env.ct, 'base64url');
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(env.nonce, 'base64url'), { authTagLength: 16 });
  d.setAAD(Buffer.from(`lab-seal/1|${env.kid}|${env.rid}`));
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8');
}
