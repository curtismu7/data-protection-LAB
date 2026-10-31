import test from 'node:test';
import assert from 'node:assert/strict';
import { PII_KINDS, SAMPLES } from '../src/pii.js';
import { SECRET_DETECTORS, detectSecrets } from '../src/secrets.js';
import { maskDeep, maskText } from '../src/mask.js';
import { get, makeTestKey, post, withServer } from './helpers.js';

// Reviewer lesson 1: a credential or personal data a visitor types must be absent from EVERY field of EVERY endpoint, every audit entry,
// every hop pane, every error and every log line. Only the labelled sk-MOCK- credential is shown (rule 4).
const W = { 'x-workspace': 'echo' };
const sentinels = () => [
  ...PII_KINDS.map((k) => SAMPLES[k.id].valid()),
  ...SECRET_DETECTORS.map((d) => d.sample()),
  'ZQX-9876',
];
const variants = (v) => { const n = v.replace(/^DOB: /, ''); return [...new Set([n, n.replace(/[ -]/g, '')])].filter((x) => x.length >= 8); };

test('typed values are in no response, whatever the endpoint, the field or the error', async () => {
  const logs = []; const orig = { log: console.log, error: console.error, warn: console.warn, info: console.info };
  for (const k of Object.keys(orig)) console[k] = (...a) => { logs.push(a.map(String).join(' ')); };
  const bodies = [];
  try {
    await withServer(async (url) => {
      const key = makeTestKey();
      const rec = async (r) => { const t = await r.text(); bodies.push(t); return t; };
      await rec(await post(url, '/api/promptlog/config', { config: { Enabled: true, PublicKey: JSON.stringify(key.publicJwk), KeyID: 'echo-1', IncludeResponses: true } }, W));
      const secret = SECRET_DETECTORS[1].sample();
      // a pasted rule whose id, description, regex, keywords and allowlist all carry credentials, so the rule itself must be masked everywhere
      const toml = `[[rules]]\nid = "echo-rule"\ndescription = "uses ${secret}"\nregex = '''ZQX-[0-9]{4}|${secret}'''\nkeywords = ["zqx-"]\nowasp = "${secret.slice(0, 30)}"\n[rules.allowlist]\nregexes = ['''^${secret}$''']\n`;
      await rec(await post(url, '/api/rules/import', { mode: 'live', toml }, W));
      await rec(await post(url, '/api/rules/enforcement', { id: 'cst-echo-rule', enforcement: 'enforce' }, W));
      await rec(await get(url, '/api/rules', W));
      for (const s of sentinels()) {
        const text = `before ${s} middle ${s} after ZQX-9876`;
        for (const role of ['user_prompt', 'tool_result', 'model_output']) {
          await rec(await post(url, '/api/evaluate', { mode: 'live', custom: { text, role, surface: 'llm', response: `the answer repeats ${s}` }, labels: { person: `p ${s}`, agent: `a ${s}`, app: `x ${s}` } }, W));
        }
        await rec(await post(url, '/api/stream', { mode: 'live', frames: [`one ${s}`, `${s} two`, 'three'] }, W));
        // errors must not echo the input either
        await rec(await post(url, '/api/evaluate', { mode: 'live', custom: { text: s, role: s, surface: 'llm' } }, W));
        await rec(await post(url, '/api/evaluate', { mode: 'live', custom: { text: s, role: 'user_prompt', surface: s } }, W));
        await rec(await post(url, '/api/evaluate', { mode: 'live', custom: { text: s, role: 'user_prompt', surface: 'llm' }, scope: { key: s }, policy: { PIIKinds: [s] } }, W));
        await rec(await post(url, '/api/rules/import', { mode: 'live', toml: `[[rules]]\nid = "${s.toLowerCase().slice(0, 20)}"\nregex = '(a+)+'\nweird = "${s}"\n` }, W));
        await rec(await post(url, '/api/rules/enforcement', { id: s, enforcement: 'enforce' }, W));
        await rec(await post(url, '/api/promptlog/config', { config: { KeyID: s, Surfaces: [s], PublicKey: s } }, W));
        await rec(await post(url, '/api/stream', { mode: 'live', frames: [s, 5] }, W));
      }
      for (const p of ['/api/insights?mode=live&window=30d', '/api/insights?mode=live&agent=x', '/api/promptlog', '/api/rules', '/api/selfcheck?mode=live', '/api/insights?mode=live&window=zzz', `/api/insights?mode=live&agent=${encodeURIComponent(sentinels()[0])}`]) await rec(await get(url, p, W));
    });
  } finally { Object.assign(console, orig); }
  const all = bodies.join('\n') + logs.join('\n');
  assert.ok(bodies.length > 100, `${bodies.length} responses were checked`);
  for (const s of sentinels()) for (const v of variants(s)) { const at = all.indexOf(v); assert.ok(at < 0, `a typed value leaked in: ${all.slice(Math.max(0, at - 150), at + 60)} : ${v.slice(0, 6)}... (${PII_KINDS.find((k) => SAMPLES[k.id].valid().includes(s))?.id || SECRET_DETECTORS.find((d) => d.sample() === s)?.id || 'custom'})`); }
});

test('the mock-labelled sk-MOCK- credential is the one thing that may be shown (rule 4), and only in the scripted story', async () => {
  await withServer(async (url) => {
    const story = await (await get(url, '/api/story')).text();
    assert.ok(story.includes('sk-MOCK-'));
    const ev = await (await post(url, '/api/evaluate', { mode: 'live', scenario: 'secret' }, W)).text();
    assert.ok(!ev.includes('sk-MOCK-a1b2'), 'even the mock value is masked in an evaluation: only the scripted story shows it');
  });
});

test('maskText and maskDeep: markers for every detected value, opaque envelope fields untouched, deep structures do not overflow', () => {
  for (const k of PII_KINDS) { const v = SAMPLES[k.id].valid().replace(/^DOB: /, ''); assert.ok(!maskText(`x ${SAMPLES[k.id].valid()} y`).includes(v), k.id); }
  for (const d of SECRET_DETECTORS) { const t = `x ${d.sample()} y`; const f = detectSecrets(t).find((x) => x.rule === d.id); assert.ok(!maskText(t).includes(t.slice(f.start, f.end)), d.id); }
  assert.equal(maskText('plain words'), 'plain words'); assert.equal(maskText(''), '');
  const env = { epk: 'sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', nonce: 'x', ct: 'ghp_' + 'a'.repeat(36), other: SECRET_DETECTORS[1].sample() };
  const m = maskDeep({ envelope: env });
  assert.equal(m.envelope.epk, env.epk); assert.equal(m.envelope.ct, env.ct); assert.match(m.envelope.other, /masked/);
  let deep = 'leaf'; for (let i = 0; i < 40000; i++) deep = { x: deep };
  assert.ok(maskDeep(deep));
});
