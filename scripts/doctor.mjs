// Preflight: the same checks GET /api/health reports from, plus whether the port is free, plus a REAL seal-then-open round trip (the server
// seals, the browser's own WebCrypto code opens, with a throwaway key made here). The round trip lives in this script and not in server/src
// because the server must never contain code that can open a record. Prints only pass/fail lines, never a setting's value. Exit 1 on failure.
import net from 'node:net';
import { createPrivateKey, randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const load = (p) => import(pathToFileURL(path.join(root, p)));
const { installNetguard } = await load('server/src/netguard.js');
installNetguard();
const { applySharedSettings } = await load('server/src/settings.js');
applySharedSettings();

const { runChecks } = await load('server/src/doctor.js');
const { sharedRunner } = await load('server/src/regexRunner.js');
let failed = 0;
const report = (level, name, detail) => { if (level === 'fail') failed++; console.log(`${level.toUpperCase().padEnd(4)}  ${name}: ${detail}`); };
for (const c of await runChecks()) report(c.level, c.id, c.detail);

try {
  const { sealRecord, parsePublicJwk } = await load('server/src/seal.js');
  const web = await load('web/src/seal.js');
  const j = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), randomBytes(32)]), format: 'der', type: 'pkcs8' }).export({ format: 'jwk' });
  const priv = { kty: 'OKP', crv: 'X25519', x: j.x, d: j.d };
  const plaintext = `round trip ${randomBytes(6).toString('hex')}`;
  const env = sealRecord({ publicKey: parsePublicJwk({ kty: 'OKP', crv: 'X25519', x: j.x }), keyId: 'doctor', recordId: 'r-doctor', plaintext });
  const ok = await web.openEnvelope(priv, env);
  const other = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), randomBytes(32)]), format: 'der', type: 'pkcs8' }).export({ format: 'jwk' });
  const bad = await web.openEnvelope({ kty: 'OKP', crv: 'X25519', x: other.x, d: other.d }, env);
  if (ok.ok && ok.plaintext === plaintext && !bad.ok) report('pass', 'seal-roundtrip', 'the server sealed a fresh record and the browser WebCrypto code opened it with the right key; a wrong key could not');
  else report('fail', 'seal-roundtrip', ok.ok ? 'the wrong key opened a record' : (ok.reason || 'the record did not open'));
} catch { report('fail', 'seal-roundtrip', 'WebCrypto X25519 is not available in this Node'); }

const port = Number(process.env.PORT) || 7200;
await new Promise((resolve) => {
  const s = net.createServer();
  s.once('error', (e) => { report('fail', 'port-free', `${port} is not free (${e.code}). Set PORT to a free port in 7200-7249`); resolve(); });
  s.listen(port, '127.0.0.1', () => s.close(() => { report('pass', 'port-free', `${port} is free`); resolve(); }));
});
await sharedRunner.close();
process.exit(failed ? 1 : 0);
