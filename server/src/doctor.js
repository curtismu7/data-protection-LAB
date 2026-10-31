// Preflight checks shared by `npm run doctor` and GET /api/health. Never prints a secret, needs no network.
// Each check: { id, level: 'pass' | 'info' | 'fail', detail }.
import fs from 'node:fs';
import { randomBytes, createPrivateKey, createPublicKey } from 'node:crypto';
import { assertBindAllowed, bindHost, portProblem, scanHosts, scanKeys, DEFAULT_PORT, PORT_MIN, PORT_MAX } from './safety.js';
import { netguardSelfTest } from './netguard.js';
import { DEFAULT_CAST, VERTICALS, unfilled } from './cast.js';
import { buildStory, rawStory } from './story.js';
import { SCENARIOS, STREAM } from './data.js';
import { buildMockTable, scenarioCall, streamFrames } from './evaluation.js';
import { defaultPolicy, inspect, inspectStream, validatePolicy } from './guard.js';
import { runSelfCheck, selfCheckOk } from './selfcheck.js';
import { checkRegex } from './safeRegex.js';
import { importToml } from './rules.js';
import { RULE_SAMPLES } from './data.js';
import { modeFrom } from './config.js';
import { DIAGRAM_NAMES, buildDiagram } from './diagramData.js';
import { MOCK_TABLE } from './mockTable.js';
import { settingsPath } from './settings.js';
import { sealRecord, parsePublicJwk } from './seal.js';
import { sharedRunner } from './regexRunner.js';

export const settingsFile = (env = process.env) => (env.STANDALONE_ENV ? env.STANDALONE_ENV : settingsPath(env));
const STREAM_EXPECTED = ['allow', 'allow', 'block', 'sanitize', 'allow'];

export async function runChecks({ env = process.env, cast = DEFAULT_CAST, table = MOCK_TABLE, runner = sharedRunner } = {}) {
  const checks = [];
  const add = (id, level, detail) => checks.push({ id, level, detail });

  const major = Number(process.versions.node.split('.')[0]);
  add('node', major >= 26 ? 'pass' : 'fail', `v${process.versions.node} (need >= 26)`);

  try { add('mode', 'pass', `${modeFrom(env)} is the opening mode (mock is the default); the header toggle switches between mock and live, both loopback-only`); }
  catch (e) { add('mode', 'fail', e.message); }

  try { add('bind', 'pass', `${assertBindAllowed(bindHost(env), env)}${env.DPLAB_BIND ? ' (DPLAB_BIND opt-in)' : ' (loopback)'}`); }
  catch (e) { add('bind', 'fail', e.message); }

  const port = env.PORT === undefined || env.PORT === '' ? DEFAULT_PORT : Number(env.PORT);
  const problem = portProblem(port);
  add('port-range', problem ? 'fail' : 'pass', problem || `${port} is inside ${PORT_MIN}-${PORT_MAX} and not reserved`);

  const file = settingsFile(env);
  try { const m = fs.statSync(file).mode & 0o777; add('settings-file', m & 0o077 ? 'info' : 'pass', m & 0o077 ? 'the shared settings file is readable by others: chmod 600 it' : 'the shared settings file exists and is mode 600 (values are never printed)'); }
  catch { add('settings-file', 'info', 'no shared settings file: mock mode needs none'); }

  // Each scripted action gives the decision the story says it does, in every vertical, and the Mock table agrees with the engine.
  const wrong = [];
  for (const [vertical, c] of Object.entries(VERTICALS)) {
    for (const s of SCENARIOS) { const x = scenarioCall(c, s.id); const r = await inspect(x.text, { role: x.role, surface: x.surface, policy: defaultPolicy(), rules: [], runner }); if (r.decision !== s.expected) wrong.push(`${vertical}/${s.id}`); }
    const st = await inspectStream(streamFrames(c), { role: STREAM.role, surface: STREAM.surface, policy: defaultPolicy(), rules: [], runner });
    if (st.frames.map((f) => f.decision).join() !== STREAM_EXPECTED.join()) wrong.push(`${vertical}/stream`);
  }
  add('scenarios', wrong.length ? 'fail' : 'pass', wrong.length ? `actions that do not give their expected decision: ${wrong.slice(0, 6).join(', ')}` : `${SCENARIOS.length} scripted actions and the stream give their expected decisions in ${Object.keys(VERTICALS).length} verticals`);

  const fresh = JSON.parse(JSON.stringify(await buildMockTable()));
  const drift = Object.keys(fresh).filter((k) => JSON.stringify(fresh[k]) !== JSON.stringify(table[k]));
  add('mock-table', drift.length ? 'fail' : 'pass', drift.length ? `mock table drifts from the engine in: ${drift.join(', ')} (run npm run mock-table)` : 'the mock table matches the live engine');

  const sc = runSelfCheck();
  add('kinds-and-detectors', selfCheckOk(sc) ? 'pass' : 'fail', selfCheckOk(sc) ? `${Object.keys(sc.kinds).length} personal-data kinds and ${Object.keys(sc.secrets).length} secret detectors: every valid sample fires and every near miss stays quiet` : 'a kind or detector misses its valid sample or fires on its near miss');

  const hostile = ['(a+)+$', '(a|aa)+$', '^(\\w+\\s?)*$', '(a)\\1', '(?=a)b', 'a{1,100000}'];
  const let_through = hostile.filter((h) => checkRegex(h) === null);
  const paste = await importToml(RULE_SAMPLES.find((s) => s.id === 'one-bad').toml, { runner });
  add('regex-guard', !let_through.length && paste.Added.length === 0 && paste.Errors.length === 2 ? 'pass' : 'fail', !let_through.length && paste.Added.length === 0 ? `${hostile.length} hostile patterns refused up front; a paste with one bad rule adds nothing and lists each refused rule` : 'the regex guard let a hostile pattern through or half-applied a paste');

  try { const g = await runner.selftest(8000); add('worker-netguard', g.ok && g.attempts === 0 ? 'pass' : 'fail', g.ok ? 'the regex worker has its own netguard: it blocked all 6 routes out' : g.detail); }
  catch { add('worker-netguard', 'fail', 'the regex worker did not answer'); }

  const pol = validatePolicy(defaultPolicy());
  add('policy', pol.ok ? 'pass' : 'fail', pol.ok ? 'the default policy validates' : JSON.stringify(pol.errors).slice(0, 120));

  // Sealing: the server can only seal. A throwaway key (random bytes, PKCS8 prefix; no generateKeyPair) proves the envelope has its fields.
  try {
    const seed = randomBytes(32);
    const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
    const pk = parsePublicJwk(createPublicKey(priv).export({ format: 'jwk' }));
    const env2 = sealRecord({ publicKey: pk, keyId: 'doctor', recordId: 'r-doctor', plaintext: 'doctor' });
    const ok = ['v', 'kid', 'rid', 'epk', 'nonce', 'ct'].every((f) => typeof env2[f] === 'string' && env2[f]);
    add('sealing', ok ? 'pass' : 'fail', ok ? 'the server sealed a throwaway record with the lab-invented envelope (it has no way to open one: the round trip is checked by npm run doctor in the repo scripts)' : 'sealing produced a malformed envelope');
  } catch { add('sealing', 'fail', 'sealing failed'); }

  const raw = rawStory();
  const text = JSON.stringify(raw);
  const holes = unfilled(text, DEFAULT_CAST);
  add('story-tokens', holes.length ? 'fail' : 'pass', holes.length ? `unfilled {{tokens}}: ${[...new Set(holes)].join(', ')}` : 'every {{cast}} token is filled');
  const badVert = Object.entries(VERTICALS).filter(([, v]) => unfilled(text, v).length).map(([k]) => k);
  add('verticals', badVert.length ? 'fail' : 'pass', badVert.length ? `verticals missing a token: ${badVert.join(', ')}` : `${Object.keys(VERTICALS).length} vertical packs fill every token`);
  const filled = JSON.stringify(Object.keys(VERTICALS).map((v) => buildStory(VERTICALS[v], v)));
  const hosts = scanHosts(filled);
  add('story-hosts', hosts.length ? 'fail' : 'pass', hosts.length ? `non-reserved hosts: ${hosts.join(', ')}` : 'every host in the story data is .invalid or .example');
  const keys = scanKeys(filled);
  add('story-keys', keys.length ? 'fail' : 'pass', keys.length ? 'key-looking values that are not sk-MOCK-' : 'the only credential-shaped value is the labelled mock one, built at run time; detector samples never leave the server');
  add('diagrams', DIAGRAM_NAMES.every((n) => buildDiagram(cast, n).steps.length > 0) ? 'pass' : 'fail', `${DIAGRAM_NAMES.length} diagram-studio/1 diagrams load and validate`);

  const ng = await netguardSelfTest();
  add('netguard', ng.ok ? 'pass' : 'fail', ng.ok ? `blocked fetch, socket, socket-by-IP, dns lookup, dns resolve and udp to a non-loopback host (${ng.blocked}/6)` : ng.detail);

  add('tenant', 'pass', 'simulated only: no tenant, no credentials, no outbound network; every product claim is UNVERIFIED on our tenant');
  return checks;
}

export const allPassed = (checks) => checks.every((c) => c.level !== 'fail');
