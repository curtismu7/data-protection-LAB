// Regression tests for the independent review: every repro the reviewer found, proved here, and mutation-checked.
import test from 'node:test';
import assert from 'node:assert/strict';
import { defaultPolicy, inspect, inspectStream, validatePolicy } from '../src/guard.js';
import { PII_KINDS, SAMPLES, abaValid, detectPii, dniLetter, healthIdValid, ibanCheckDigits, ibanValid, luhnComplete, luhnValid } from '../src/pii.js';
import { SECRET_DETECTORS, detectSecrets } from '../src/secrets.js';
import { SealError, parsePublicJwk, sealRecord } from '../src/seal.js';
import { parseToml } from '../src/toml.js';
import { importToml } from '../src/rules.js';
import { validatePromptLog } from '../src/promptlog.js';
import { createRegexRunner } from '../src/regexRunner.js';
import { createWorkspaces } from '../src/workspaces.js';
import { CATEGORY_MAP } from '../src/compliance.js';
import { get, makeTestKey, openSealed, post, withServer } from './helpers.js';

const runner = createRegexRunner();
test.after(() => runner.close());
const run = (text, o = {}) => inspect(text, { role: 'user_prompt', surface: 'llm', policy: defaultPolicy(), rules: [], runner, ...o });
const W = (id) => ({ 'x-workspace': id });
const ev = (url, ws, text, extra = {}) => post(url, '/api/evaluate', { mode: 'live', custom: { text, role: 'user_prompt', surface: 'llm' }, ...extra }, W(ws));
const compact = (v) => v.replace(/^DOB: /, '').replace(/[ -]/g, '');
const customPii = (enforcement = 'enforce') => ({ rule: { ID: 'cst-t', Description: '', Category: 'pii', Severity: 'high', Score: 0.7, OWASP: '', AppliesTo: [], Keywords: [], Pattern: 'ZQX-[0-9]{4}', Entropy: 0, Allowlist: [], ValueGroup: 0 }, enforcement });

// ---- B2: a narrowed PIIKinds list must never un-mask a value ---------------------------------------------------------------------------------
test('B2: narrowing PIIKinds to ANY single kind, to none, or with a pasted pii rule filtered out never lets a typed value through the display copy, the findings or the hops', async () => {
  const all = PII_KINDS.map((k) => SAMPLES[k.id].valid());
  const text = all.join(' | ');
  const raws = all.map((v) => v.replace(/^DOB: /, ''));
  for (const only of [...PII_KINDS.map((k) => [k.id]), [], ['cst-t'], ['pii-email', 'cst-t']]) {
    const p = defaultPolicy(); p.PIIKinds = only;
    for (const enforcement of ['enforce', 'observe']) {
      const r = await run(`${text} ZQX-1234`, { policy: p, rules: [customPii(enforcement)] });
      const json = JSON.stringify(r);
      for (const v of [...raws, 'ZQX-1234']) assert.ok(!json.includes(v), `PIIKinds=${only} ${enforcement}: ${v} leaked`);
    }
  }
});

test('B2 over the API: the reviewer repro (card + ssn, PIIKinds narrowed to the ssn) returns neither raw, in any field or hop; an unknown kind id is a 400 that echoes nothing', async () => {
  await withServer(async (url) => {
    const card = '4111 1111 1111 1111'; const ssn = '123-45-6789';
    for (const kinds of [['pii-ssn'], ['pii-email'], [], ['pii-credit-card']]) {
      const r = await ev(url, 'a', `card ${card} ssn ${ssn}`, { policy: { PIIKinds: kinds } });
      const t = await r.text(); assert.equal(r.status, 200);
      assert.ok(!t.includes(card) && !t.includes('4111') && !t.includes(ssn) && !t.includes('45-6789'), JSON.stringify(kinds));
    }
    const bad = await ev(url, 'a', 'x', { policy: { PIIKinds: ['pii-4111111111111111'] } });
    assert.equal(bad.status, 400); assert.ok(!(await bad.text()).includes('4111'));
    await post(url, '/api/rules/import', { mode: 'live', toml: "[[rules]]\nid = \"zq\"\nregex = '''ZQX-[0-9]{4}'''\ncategory = \"pii\"\n" }, W('a'));
    const r = await ev(url, 'a', 'code ZQX-4321 and ZQX-8765', { policy: { PIIKinds: ['pii-email'] } });
    assert.ok(!(await r.text()).match(/ZQX-(4321|8765)/), 'a pasted pii rule narrowed out by PIIKinds is still masked');
  });
});

// ---- S6: evasions: the finders see a normalised copy and the span maps back onto the original --------------------------------------------------
const toFullwidth = (s) => s.replace(/[!-~]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0xfee0)).replace(/ /g, '　');
const zw = (s) => `${s.slice(0, 3)}​${s.slice(3, 6)}⁠${s.slice(6)}`;

for (const k of PII_KINDS) {
  test(`S6 ${k.id}: found through zero-width characters, fullwidth forms, hyphen prefix and suffix, and the original characters are redacted`, async () => {
    const v = SAMPLES[k.id].valid(); const raw = v.replace(/^DOB: /, '');
    for (const [name, text] of [['zero-width', `x ${zw(v)} y`], ['fullwidth', `x ${toFullwidth(v)} y`], ['hyphen prefix', `ref-${v}`], ...(k.id === 'pii-email' ? [] : [['hyphen suffix', `${v}-x`]]), ['plain', `x ${v} y`]]) {
      const found = detectPii(text, [k.id]);
      assert.equal(found.length, 1, `${name}: ${JSON.stringify(text)}`);
      const r = await run(text);
      const shown = r.text; assert.ok(!shown.includes(text.slice(found[0].start, found[0].end)), `${name}: the original span is not shown`);
      assert.ok(!shown.includes(raw.slice(0, 6)) || name === 'plain' ? !shown.includes(raw) : true);
      assert.ok(!JSON.stringify(r).includes(raw), `${name} leaked`);
    }
  });
}

test('S6 numbers split by NBSP, newline, a dot, an underscore or a double space are still cards, SSNs and SINs', async () => {
  const card = luhnComplete('411111111111111'); const ssn = '123-45-6789'; const sin = SAMPLES['pii-ca-sin'].valid();
  const g = (d, sep) => d.replace(/\D/g, '').replace(/(\d{4})(?=\d)/g, `$1${sep}`);
  for (const sep of [' ', '\n', '.', '_', '  ', '\t', '​ ']) {
    assert.equal(detectPii(`pay ${g(card, sep)} now`, ['pii-credit-card']).length, 1, JSON.stringify(sep));
    const r = await run(`pay ${g(card, sep)} now`); assert.ok(!r.text.includes('4111') && r.decision === 'sanitize', JSON.stringify(sep));
  }
  for (const sep of ['.', '_', ' ', ' ']) assert.equal(detectPii(`ssn ${ssn.replace(/-/g, sep)}`, ['pii-ssn']).length, 1, JSON.stringify(sep));
  assert.equal(detectPii(sin.replace(/-/g, '.'), ['pii-ca-sin']).length, 1);
});

for (const d of SECRET_DETECTORS) {
  test(`S6 ${d.id}: found through zero-width characters and fullwidth forms, and fully masked`, async () => {
    const v = d.sample();
    const zwText = `k ${v.slice(0, 5)}\u200b${v.slice(5)} z`;
    const fwText = `k ${toFullwidth(v)} z`;
    for (const text of [zwText, fwText]) {
      assert.ok(detectSecrets(text).some((f) => f.rule === d.id), `${d.id}: ${JSON.stringify(text.slice(0, 30))}`);
      const r = await run(text);
      assert.ok(!JSON.stringify(r).includes(v.slice(5, 20)) && !r.text.includes(toFullwidth(v.slice(5, 20))), 'masked');
    }
  });
}

// ---- S4: a value split over 2, 3 or many frames ----------------------------------------------------------------------------------------------
const stream = (frames, o = {}) => inspectStream(frames, { role: 'tool_result', surface: 'mcp', policy: defaultPolicy(), rules: [], runner, ...o });
const awsKey = () => SECRET_DETECTORS.find((d) => d.id === 'lab-aws-access-key-id').sample();
const noFragment = (res, value, n = 8) => { const t = JSON.stringify(res); for (let i = 0; i + n <= value.length; i++) assert.ok(!t.includes(value.slice(i, i + n)), `fragment ${value.slice(i, i + n)} is shown`); };

test('S4: a key split in 2, in 3 (6|6|rest) and character by character is caught; the frame that completes it is withheld; no fragment of it is in the response', async () => {
  const key = awsKey();
  for (const frames of [[`hello ${key.slice(0, 8)}`, `${key.slice(8)} bye`], [`hello ${key.slice(0, 6)}`, key.slice(6, 12), `${key.slice(12)} bye`], key.split('').map((c) => c)]) {
    const r = await stream(frames);
    assert.equal(r.frames.at(-1).decision === 'block' || r.frames.some((f) => f.withheld), true, JSON.stringify(r.frames.map((f) => f.decision)));
    assert.ok(r.frames.some((f) => /split across/.test(f.note)));
    noFragment(r, key);
  }
});

test('S4: a card number split over three frames is caught and masked in the earlier frames\' displayed copies too', async () => {
  const card = luhnComplete('555555555555444').replace(/(\d{4})(?=\d)/g, '$1 ');
  const r = await stream([`pay ${card.slice(0, 10)}`, card.slice(10, 15), `${card.slice(15)} now`]);
  assert.deepEqual(r.frames.map((f) => f.decision), ['allow', 'allow', 'block']);
  assert.match(r.frames[0].text, /masked for display/); assert.match(r.frames[1].text, /masked for display/);
  noFragment(r, card.replace(/ /g, ''), 6);
  assert.ok(!JSON.stringify(r).includes('5555 5555'));
});

test('S4: the stated limit holds: a value split by more than the 128 character tail is not seen', async () => {
  const key = awsKey();
  const r = await stream([`see ${key.slice(0, 8)}`, 'x'.repeat(200), key.slice(8)]);
  assert.ok(r.frames.every((f) => f.decision === 'allow'));
});

test('S4: a stream with nothing split keeps every frame\'s own text untouched', async () => {
  const r = await stream(['one', 'two', 'three']);
  assert.deepEqual(r.frames.map((f) => f.text), ['one', 'two', 'three']);
});

// ---- S1: keys the server cannot seal to, or the browser cannot open ---------------------------------------------------------------------------
const hex = (h) => Buffer.from(h, 'hex').toString('base64url');
const BAD_POINTS = {
  'all zero': '00'.repeat(32), 'one': `01${'00'.repeat(31)}`,
  'order 8 point 1': 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', 'order 8 point 2': '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'p (non canonical zero)': `edff${'ff'.repeat(29)}7f`, 'p+1 (non canonical one)': `eeff${'ff'.repeat(29)}7f`,
  'high bit set': `${'11'.repeat(31)}80`, 'all ones': 'ff'.repeat(32),
};
test('S1: low-order, non-canonical and high-bit X25519 public keys are refused with a clear error; a good key still works', () => {
  for (const [name, h] of Object.entries(BAD_POINTS)) assert.throws(() => parsePublicJwk({ kty: 'OKP', crv: 'X25519', x: hex(h) }), (e) => e instanceof SealError && e.code === 'bad_key', name);
  const key = makeTestKey();
  const hi = Buffer.from(key.publicJwk.x, 'base64url'); hi[31] |= 0x80;
  assert.throws(() => parsePublicJwk({ ...key.publicJwk, x: hi.toString('base64url') }), /top bit/);
  assert.ok(parsePublicJwk(key.publicJwk));
  assert.throws(() => sealRecord({ publicKey: { x: Buffer.alloc(32) }, keyId: 'k', recordId: 'r', plaintext: 'x' }));
});

test('S1 over the API: such a key is a 400 bad_key at config time, evaluation keeps working (no 500), and the config stays off', async () => {
  await withServer(async (url, { workspaces }) => {
    for (const [name, h] of Object.entries(BAD_POINTS)) {
      const r = await post(url, '/api/promptlog/config', { config: { Enabled: true, KeyID: 'k', PublicKey: { kty: 'OKP', crv: 'X25519', x: hex(h) } } }, W('a'));
      assert.equal(r.status, 400, name); assert.equal(workspaces.promptLog('a').Enabled, false, name);
    }
    const e = await ev(url, 'a', 'hello there'); assert.equal(e.status, 200);
    const key = makeTestKey(); await post(url, '/api/promptlog/config', { config: { Enabled: true, KeyID: 'k', PublicKey: key.publicJwk } }, W('a'));
    const j = await (await ev(url, 'a', 'sealed ok')).json(); assert.ok(j.record);
    const rec = workspaces.records('a')[0]; assert.equal(JSON.parse(openSealed(key.privateJwk, rec.envelope)).prompt, 'sealed ok');
  });
});

test('S1: a sealing failure after config never makes evaluation a 500: the record is skipped and says why', async () => {
  const workspaces = createWorkspaces();
  workspaces.setPromptLog('a', { Enabled: true, PublicKey: '{}', KeyID: 'k', Surfaces: [], IncludeResponses: false, MaxBytes: 0 }, { x: Buffer.alloc(32) });
  await withServer(async (url) => { const r = await ev(url, 'a', 'hello'); assert.equal(r.status, 200); assert.match((await r.json()).recordSkipped, /sealing failed/); }, { workspaces });
});

// ---- S2: one workspace's slow rule cannot starve another's, and is quarantined ----------------------------------------------------------------
test('S2: a slow accepted rule times out once, is quarantined and reported, and another workspace is answered while it runs', async () => {
  const r = createRegexRunner({ timeoutMs: 4000, pool: 2 });
  try {
    await Promise.all([r.ping(60000, 'warm-1'), r.ping(60000, 'warm-2')]); // both pool children running: start-up time under load is not what is measured
    await withServer(async (url, { workspaces }) => {
      await post(url, '/api/rules/import', { mode: 'live', toml: "[[rules]]\nid = \"slow\"\nregex = '''.*.*.*.*.*.*x'''\n" }, W('a'));
      await post(url, '/api/rules/import', { mode: 'live', toml: "[[rules]]\nid = \"ok\"\nregex = '''zz[0-9]{3}'''\n" }, W('b'));
      const big = 'a'.repeat(20000);
      let aDone = false;
      const pa = ev(url, 'a', big).then((x) => x.json()).finally(() => { aDone = true; });
      await new Promise((res) => setTimeout(res, 150));
      const jb = await (await ev(url, 'b', 'zz123 hello')).json();
      assert.equal(jb.evaluation.findings.length, 1);
      assert.equal(aDone, false, 'workspace B was answered while workspace A\'s slow rule was still running');
      const ja = await pa;
      assert.match(ja.evaluation.ruleErrors.join(), /ran out of time, was stopped and is now disabled/);
      assert.equal(workspaces.quarantine('a').get('cst-slow'), 'timed out');
      const again = await (await ev(url, 'a', big)).json();
      assert.match(again.evaluation.ruleErrors.join(), /is disabled: it ran out of time earlier and is skipped/, 'the quarantined rule is not run again');
      const list = await (await get(url, '/api/rules', W('a'))).json(); assert.equal(list.rules[0].disabled, 'timed out');
      await post(url, '/api/reset', {}, W('a')); assert.equal(workspaces.quarantine('a').size, 0);
    }, { runner: r });
  } finally { await r.close(); }
});

test('S2: the whole inspection has a time budget: rules after it is used up are skipped and reported', async () => {
  const rules = Array.from({ length: 3 }, (_, i) => ({ ...customPii(), rule: { ...customPii().rule, ID: `cst-r${i}`, Pattern: `Q${i}[0-9]+` } }));
  const out = await run('hello Q1 12', { rules, budgetMs: 0 });
  assert.equal(out.ruleErrors.length, 3); assert.match(out.ruleErrors[0], /time budget/);
});

// ---- S3: concurrent imports -----------------------------------------------------------------------------------------------------------------------
test('S3: four concurrent imports of the same id add it once; two concurrent 40-rule imports cannot exceed 50 and say so; one bad rule among concurrent pastes still adds nothing', async () => {
  await withServer(async (url, { workspaces }) => {
    const toml = "[[rules]]\nid = \"dup-me\"\nregex = '''qq[0-9]{3}'''\n";
    const rs = await Promise.all([1, 2, 3, 4].map(() => post(url, '/api/rules/import', { mode: 'live', toml }, W('c')).then((r) => r.json())));
    assert.equal(rs.filter((x) => x.Added.length === 1).length, 1); assert.equal(rs.filter((x) => x.Errors.length === 1).length, 3);
    assert.deepEqual(workspaces.rules('c').map((r) => r.rule.ID), ['cst-dup-me']);
    const mk = (p, n) => Array.from({ length: n }, (_, i) => `[[rules]]\nid = "${p}-${i}"\nregex = '''k${p}${i}x'''\n`).join('\n');
    const two = await Promise.all([post(url, '/api/rules/import', { mode: 'live', toml: mk('p', 40) }, W('d')).then((r) => r.json()), post(url, '/api/rules/import', { mode: 'live', toml: mk('q', 40) }, W('d')).then((r) => r.json())]);
    assert.deepEqual(two.map((x) => x.Added.length).sort(), [0, 40]); assert.equal(workspaces.rules('d').length, 40);
    assert.ok(two.some((x) => /at most 50 rules/.test(x.Errors.join())));
    const mixed = "[[rules]]\nid = \"g1\"\nregex = '''abc[0-9]'''\n[[rules]]\nid = \"g2\"\nregex = '''(a+)+$'''\n";
    const mc = await Promise.all([1, 2].map(() => post(url, '/api/rules/import', { mode: 'live', toml: mixed }, W('e')).then((r) => r.json())));
    assert.deepEqual(mc.map((x) => x.Added.length), [0, 0]); assert.equal(workspaces.rules('e').length, 0);
  });
});

test('S3: addRules refuses (it does not slice or add a duplicate)', () => {
  const w = createWorkspaces();
  w.addRules('a', [{ ID: 'cst-1' }]);
  assert.throws(() => w.addRules('a', [{ ID: 'cst-1' }]), /duplicate_rule/);
  assert.throws(() => w.addRules('a', [{ ID: 'cst-2' }, { ID: 'cst-2' }]), /duplicate_rule/);
  assert.throws(() => w.addRules('a', Array.from({ length: 50 }, (_, i) => ({ ID: `cst-x${i}` }))), /rule_cap/);
  assert.equal(w.rules('a').length, 1, 'a refused add changes nothing');
});

// ---- S5: id-like fields ------------------------------------------------------------------------------------------------------------------------------
test('S5: a card or a token used as a rule id, KeyID, scope key, policy key or TOML key is refused or hidden: nowhere in any response', async () => {
  const card = '4111111111111111'; const tok = SECRET_DETECTORS.find((d) => d.id === 'lab-github-token').sample();
  const pub = makeTestKey().publicJwk;
  await withServer(async (url) => {
    const bodies = [];
    const rec = async (r) => { const t = await r.text(); bodies.push(t); return [r.status, t]; };
    for (const id of [card, `ref-${card}`, `${card}-x`, tok.toLowerCase()]) {
      const [s, t] = await rec(await post(url, '/api/rules/import', { mode: 'live', toml: `[[rules]]\nid = "${id}"\nregex = "abc+"\n` }, W('s5')));
      assert.equal(JSON.parse(t).Added.length, 0, `rule id ${id.slice(0, 8)} is refused`); assert.equal(s, 200);
    }
    assert.equal((await (await get(url, '/api/rules', W('s5'))).json()).rules.length, 0);
    for (const kid of [card, `${card}-x`, `ref-${card}`]) { const [s] = await rec(await post(url, '/api/promptlog/config', { config: { Enabled: true, PublicKey: pub, KeyID: kid } }, W('s5'))); assert.equal(s, 400, kid); }
    for (const scope of [{ key: card }, { app: card }, { key: `x-${card}` }]) { const [s] = await rec(await post(url, '/api/evaluate', { mode: 'live', scenario: 'ordinary', scope }, W('s5'))); assert.equal(s, 400); }
    for (const policy of [{ Categories: { [card]: {} } }, { Categories: { [tok.slice(0, 30)]: {} } }, { Keys: { [card]: {} } }, { Apps: { x: { Categories: { [card]: {} } } } }, { Keys: { [`a-${card}`]: {} } }]) {
      const [s, t] = await rec(await post(url, '/api/evaluate', { mode: 'live', scenario: 'ordinary', policy }, W('s5'))); assert.equal(s, 400); assert.equal(JSON.parse(t).error, 'bad_policy');
    }
    for (const toml of [`[[rules]]\nid="a"\nregex="abc"\n${card} = 1\n`, `[${card}]\nx=1\n`, `[[rules]]\nid="a"\nregex="abc"\n[rules.allowlist]\n${tok} = 1\n`, `${card} = 1\n`, `[[rules]]\nid="a"\nregex="abc"\n${tok.replace(/_/g, '-')} = 1\n`]) await rec(await post(url, '/api/rules/import', { mode: 'live', toml }, W('s5')));
    const all = bodies.join('\n');
    for (const v of [card, tok, tok.slice(0, 30), tok.toLowerCase()]) assert.ok(!all.includes(v), `leaked ${v.slice(0, 6)}`);
    assert.ok(!all.includes('4111'));
  });
});

test('S5: a plain id is fine, and the policy errors never carry the key they refuse', () => {
  assert.equal(validatePolicy({ Keys: { 'key-ok': {} } }).ok, true);
  const r = validatePolicy({ Categories: { 'pii-secret-name': { AlertThreshold: 1 } } });
  assert.ok(!JSON.stringify(r.errors).includes('secret-name')); assert.equal(r.errors[0].message, 'unknown category');
  assert.equal(validatePromptLog({ KeyID: 'plain-key-1' }).ok, true);
});

// ---- S8: prototype keys in TOML --------------------------------------------------------------------------------------------------------------------
test('S8: __proto__, constructor and prototype as TOML keys at every level are ordinary (refused) keys: no prototype is set, nothing is polluted', async () => {
  for (const key of ['__proto__', 'constructor', 'prototype']) {
    const t = parseToml(`[[rules]]\nid = "ok-1"\nregex = "a+b"\n${key} = [1,2]\n[rules.allowlist]\n${key} = "x"\n`);
    const f = t.rules[0].fields;
    assert.equal(Object.getPrototypeOf(f), null, `${key}: fields have no prototype`); assert.equal(Object.getPrototypeOf(t.rules[0].allowlist), null);
    assert.ok(Object.hasOwn(f, key), `${key} is an own, visible key`);
    assert.equal(Array.isArray(Object.getPrototypeOf(f)), false);
    assert.equal(({}).length, undefined); assert.equal(({}).regexes, undefined);
    const dup = parseToml(`[[rules]]\nid = "ok-1"\nregex = "a+b"\n${key} = 1\n${key} = 2\n`);
    assert.match(dup.rules[0].errors.join(), /set twice/, `${key} twice`);
    const imp = await importToml(`[[rules]]\nid = "ok-1"\nregex = "a+b"\n${key} = 1\n`, { runner });
    assert.deepEqual(imp.Added, [], key); assert.match(imp.Errors.join(), /unknown key/);
    const al = await importToml(`[[rules]]\nid = "ok-1"\nregex = "a+b"\n[rules.allowlist]\n${key} = ["x"]\n`, { runner });
    assert.deepEqual(al.Added, [], `allowlist ${key}`); assert.match(al.Errors.join(), /allowlist key/);
  }
  assert.equal(parseToml('title = "t"\n__proto__ = 1\n').errors.length, 1);
});

// ---- S7: literal known-valid and known-invalid vectors (from public documentation), not computed by the code under test ---------------------------
test('S7: card numbers: published test numbers (the ones that need the Luhn fold) are found, one-digit changes are not', () => {
  for (const c of ['4111111111111111', '4012888888881881', '5555555555554444', '5105105105105100', '378282246310005', '6011111111111117', '4222222222222', '4000056655665556']) assert.equal(detectPii(`pay ${c}`, ['pii-credit-card']).length, 1, c);
  for (const c of ['4111111111111112', '4012888888881882', '5555555555554445', '378282246310006', '6011111111111118', '4222222222223', '1234567890123456']) assert.equal(detectPii(`pay ${c}`, ['pii-credit-card']).length, 0, c);
  assert.ok(luhnValid('5555555555554444') && !luhnValid('5555555555554443'));
  assert.equal(luhnComplete('555555555555444'), '5555555555554444', 'the check digit that needs the n > 9 fold');
});
test('S7: IBANs: published examples are valid, wrong check digits and a wrong LENGTH for the country are not', () => {
  for (const i of ['GB82WEST12345698765432', 'DE89370400440532013000', 'FR1420041010050500013M02606', 'ES9121000418450200051332', 'NL91ABNA0417164300', 'IE29AIBK93115212345678', 'IT60X0542811101000000123456', 'CH9300762011623852957', 'BE68539007547034']) assert.ok(ibanValid(i), i);
  for (const i of ['GB82WEST12345698765433', 'DE89370400440532013001']) assert.ok(!ibanValid(i), i);
  const shortGb = `GB${ibanCheckDigits('GB', 'WEST1234569876543')}WEST1234569876543`; // mod 97 holds, length 21: wrong for GB
  assert.ok(!ibanValid(shortGb), 'IBAN_LEN is enforced'); assert.equal(detectPii(`x ${shortGb}`, ['pii-iban']).length, 0);
  assert.equal(detectPii('acct GB82 WEST 1234 5698 7654 32 ok', ['pii-iban']).length, 1);
});
test('S7: US routing numbers: published valid numbers, and the 3-7-1 weights (a swap changes the result)', () => {
  for (const a of ['021000021', '011401533', '091000019', '121042882', '026009593']) assert.ok(abaValid(a), a);
  for (const a of ['021000022', '123456789', '000000000', '999999999', '012000021', '210000021']) assert.ok(!abaValid(a), a);
  assert.ok(!abaValid('021000012'), 'digits 7 and 8 swapped: 3-7-1 weights are not symmetric');
});
test('S7: health ids (mod 11) and Canadian SINs (Luhn plus first digit)', () => {
  for (const n of ['9434765919', '4010232137', '5990128088']) assert.ok(healthIdValid(n), n);
  for (const n of ['9434765918', '9434765910', '1234567890']) assert.ok(!healthIdValid(n), n);
  for (const sin of ['130-692-544', '193-456-787', '046-454-286']) assert.equal(detectPii(`sin ${sin}`, ['pii-ca-sin']).length, sin.startsWith('0') ? 0 : 1, sin);
  for (const d of [luhnComplete('80000000'), luhnComplete('04645428'), luhnComplete('86000000')]) { assert.ok(luhnValid(d)); assert.equal(detectPii(`sin ${d.slice(0, 3)}-${d.slice(3, 6)}-${d.slice(6)}`, ['pii-ca-sin']).length, 0, `first digit ${d[0]} is never a SIN`); }
  assert.equal(detectPii('sin 193-456-787', ['pii-ca-sin']).length, 1);
  assert.equal(detectPii('sin 130-692-545', ['pii-ca-sin']).length, 0);
});
test('S7: Spanish DNI letters', () => {
  assert.equal(dniLetter('12345678'), 'Z'); assert.equal(dniLetter('00000000'), 'T'); assert.equal(dniLetter('99999999'), 'R');
  for (const d of ['12345678Z', '00000000T', '99999999R']) assert.equal(detectPii(`dni ${d}`, ['pii-es-dni']).length, 1, d);
  for (const d of ['12345678A', '00000000R']) assert.equal(detectPii(`dni ${d}`, ['pii-es-dni']).length, 0, d);
});
test('S7: detector coverage limits that the README states are real (so the README is true)', () => {
  for (const [n, c] of [['diners', '30569309025904'], ['jcb', '3530111333300000'], ['maestro', '6759649826438453'], ['unionpay', '6200000000000005']]) assert.equal(detectPii(`pay ${c}`, ['pii-credit-card']).length, 0, `${n} is not detected (stated)`);
  assert.equal(detectPii('acct gb82west12345698765432', ['pii-iban']).length, 0, 'lowercase IBAN');
  assert.equal(detectPii('ssn 123456789', ['pii-ssn']).length, 0, 'SSN without separators');
  assert.equal(detectPii('nhs 943-476-5919', ['pii-health-id']).length, 0, 'NHS with hyphens');
});
test('S7/nits: look-alikes that used to fire do not: a hash prefix as a health id, an area code starting 1, sk- prose', () => {
  assert.equal(detectPii('sha 9434765919abc', ['pii-health-id']).length, 0);
  assert.equal(detectPii('phone-like 100-200-3000', ['pii-phone']).length, 0);
  assert.equal(detectPii('call 415-555-2671', ['pii-phone']).length, 1);
  assert.equal(detectSecrets('sk-learn-version-is-fine-and-long-enough-xx').length, 0);
  assert.equal(detectSecrets(`slack ${['xo', 'xe-1-'].join('')}abcdef0123456789`).length, 1);
});
test('S7: the data_exfiltration category maps to ASI09 (the deck lists exfiltration among the shared rules of ASI09)', () => {
  assert.equal(CATEGORY_MAP.data_exfiltration.asi, 'ASI09'); assert.equal(CATEGORY_MAP.pii.asi, 'ASI09'); assert.equal(CATEGORY_MAP.jailbreak.asi, 'ASI01');
});
test('S7: the PIIKinds and Surfaces count caps', () => {
  const many = Array.from({ length: 61 }, (_, i) => `cst-r${i}`);
  assert.equal(validatePolicy({ PIIKinds: many }).ok, false); assert.equal(validatePolicy({ PIIKinds: many.slice(0, 60) }).ok, true);
  assert.equal(validatePromptLog({ Surfaces: ['llm', 'llm', 'llm', 'llm', 'llm'] }).ok, false, 'more entries than there are surfaces');
  assert.equal(validatePromptLog({ Surfaces: ['llm', 'llm'] }).ok, true);
});
test('S7: TOML refusals carry their own message (control characters, size)', () => {
  assert.match(parseToml('[[rules]]\nid = "a\u0000b"\n').errors.join(), /control characters/);
  assert.match(parseToml(`# ${'a'.repeat(65536)}`).errors.join(), /over 65536 characters/);
  assert.match(parseToml('a\n'.repeat(2100)).errors.join(), /over 2000 lines/);
  assert.equal(parseToml('# ' + 'a'.repeat(60000)).errors.length, 0, 'under the cap is fine');
});

// ---- B1 follow-up: Reset cancels in-flight work -----------------------------------------------------------------------------------------------------
test('B1: Reset on a workspace cancels its in-flight evaluation: the slow rule\'s child is killed and the request returns promptly', async () => {
  const r = createRegexRunner({ timeoutMs: 120000 });
  try {
    await withServer(async (url) => {
      await post(url, '/api/rules/import', { mode: 'live', toml: "[[rules]]\nid = \"slow\"\nregex = '''.*.*.*.*.*.*x'''\n" }, W('rs'));
      await r.ping(60000); const pids = r.stats().pids;
      const t0 = Date.now();
      const inflight = ev(url, 'rs', 'a'.repeat(20000)).then((x) => x.json());
      await new Promise((res) => setTimeout(res, 400));
      await post(url, '/api/reset', {}, W('rs'));
      const j = await inflight;
      assert.ok(Date.now() - t0 < 60000, 'the request did not wait for the 120 s limit');
      assert.match(j.evaluation.ruleErrors.join(), /could not run/);
      for (let i = 0; i < 100 && pids.some((p) => { try { process.kill(p, 0); return true; } catch { return false; } }); i++) await new Promise((res) => setTimeout(res, 50));
      assert.ok(pids.every((p) => { try { process.kill(p, 0); return false; } catch { return true; } }), 'the child that was running it is gone');
    }, { runner: r });
  } finally { await r.close(); }
});
