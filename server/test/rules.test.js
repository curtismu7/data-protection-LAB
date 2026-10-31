import test from 'node:test';
import assert from 'node:assert/strict';
import { RULE_LIMITS, SEVERITY_SCORE, importToml, tenantRuleId } from '../src/rules.js';
import { RULE_SAMPLES } from '../src/data.js';
import { createRegexRunner } from '../src/regexRunner.js';
import { CATEGORY_IDS } from '../src/categories.js';

const runner = createRegexRunner();
test.after(() => runner.close());
const imp = (toml, opts = {}) => importToml(toml, { runner, ...opts });
const rule = (body, id = 'r1') => `[[rules]]\nid = "${id}"\n${body}\n`;

test('a good paste: Added carries every modelAIGuardCustomRule field, Errors is empty, ids get the cst- prefix', async () => {
  const r = await imp(RULE_SAMPLES[0].toml);
  assert.deepEqual(r.Errors, []);
  assert.deepEqual(r.Added.map((x) => x.ID), ['cst-acme-token', 'cst-staff-ref']);
  for (const a of r.Added) assert.deepEqual(Object.keys(a).sort(), ['AppliesTo', 'Allowlist', 'Category', 'Description', 'Entropy', 'ID', 'Keywords', 'OWASP', 'Pattern', 'Score', 'Severity', 'ValueGroup'].sort());
  const a = r.Added[0];
  assert.deepEqual([a.Description, a.Category, a.Severity, a.Score, a.Pattern, a.Keywords, a.Entropy, a.Allowlist, a.ValueGroup], ['An Acme service token', 'secrets', 'high', SEVERITY_SCORE.high, 'acme_[a-z0-9]{20}', ['acme_'], 3, ['^acme_example'], 0]);
  assert.equal(r.Added[1].Category, 'pii'); assert.equal(r.Added[1].Score, SEVERITY_SCORE.medium);
  assert.equal(r.Toml, RULE_SAMPLES[0].toml);
  assert.equal(tenantRuleId('cst-x'), 'cst-x'); assert.equal(tenantRuleId('x'), 'cst-x');
});

test('ONE bad rule refuses the WHOLE paste: nothing is added and Errors lists each refused rule, one per line', async () => {
  const r = await imp(RULE_SAMPLES[1].toml);
  assert.deepEqual(r.Added, []);
  assert.equal(r.Errors.length, 2);
  assert.match(r.Errors[0], /^rule 2 \(nested-quantifier\): regex refused: nested quantifiers/);
  assert.match(r.Errors[1], /^rule 3 \(lookahead\): regex refused: lookahead or lookbehind/);
  assert.ok(r.Errors.every((e) => !e.includes('\n')), 'one line each');
  // the good rule alone IS accepted: it is the bad neighbours that sank the paste
  assert.equal((await imp(rule("regex = 'ref-[0-9]{6}'", 'good-one'))).Added.length, 1);
});

test('the hostile sample, a syntax error and a pile of other bad rules are each refused with a reason', async () => {
  assert.match((await imp(RULE_SAMPLES[2].toml)).Errors[0], /nested quantifiers/);
  const bad = {
    'no id': "[[rules]]\nregex = 'a'\n", 'no regex': rule('description = "x"'), 'bad id': rule("regex = 'a'", 'Bad_ID'),
    'regex that does not compile': rule("regex = '[b-a]x'"), 'empty-matching regex': rule("regex = 'a*'"), 'bad category': rule("regex = 'a'\ncategory = \"nope\""),
    'bad severity': rule("regex = 'a'\nseverity = \"huge\""), 'score 0': rule("regex = 'a'\nscore = 0"), 'score 2': rule("regex = 'a'\nscore = 2"), 'entropy 9': rule("regex = 'a'\nentropy = 9"),
    'secretGroup 3 of 0': rule("regex = 'a+'\nsecretGroup = 3"), 'secretGroup 10': rule("regex = 'a+'\nsecretGroup = 10"), 'keywords not strings': rule("regex = 'a'\nkeywords = [1]"),
    'unknown key': rule("regex = 'a'\npath = 'x'"), 'unknown surface': rule("regex = 'a'\nappliesTo = [\"fax\"]"), 'allowlist stopwords': `${rule("regex = 'a'")}[rules.allowlist]\nstopwords = ["x"]\n`,
    'allowlist hostile regex': `${rule("regex = 'a'")}[rules.allowlist]\nregexes = ["(x+)+"]\n`, 'allowlist that does not compile': `${rule("regex = 'a'")}[rules.allowlist]\nregexes = ["("]\n`,
    'long regex': rule(`regex = '${'a'.repeat(401)}'`), 'syntax error': '[[rules]]\nid = "x\n', 'nothing': '# empty\n', 'description too long': rule(`regex = 'a'\ndescription = "${'x'.repeat(201)}"`),
  };
  for (const [name, toml] of Object.entries(bad)) { const r = await imp(toml); assert.deepEqual(r.Added, [], name); assert.ok(r.Errors.length >= 1, name); }
});

test('every refusal is tested for its own message', async () => {
  const msg = async (toml) => (await imp(toml)).Errors.join('|');
  assert.match(await msg("[[rules]]\nregex = 'a'\n"), /id is required/);
  assert.match(await msg(rule('description = "x"')), /regex is required/);
  assert.match(await msg(rule("regex = '[b-a]x'")), /does not compile/);
  assert.match(await msg(rule("regex = '[a-'")), /unterminated character class/);
  assert.match(await msg(rule("regex = 'a*'")), /matches the empty string/);
  assert.match(await msg(rule("regex = 'a'\ncategory = \"nope\"")), /category must be one of/);
  assert.match(await msg(rule("regex = 'a+'\nsecretGroup = 3")), /secretGroup is higher than the number of groups/);
  assert.match(await msg(rule("regex = 'a'\nentropy = 9")), /entropy must be a number from 0 to 8/);
  assert.match(await msg(rule("regex = 'a'\nscore = 2")), /score must be/);
  assert.match(await msg(rule("regex = 'a'\nunknownthing = 2")), /unknown key unknownthing/);
  assert.match(await msg(`${rule("regex = 'a'")}[rules.allowlist]\nregexes = ["(x+)+"]\n`), /allowlist regex 1 refused: nested/);
});

test('every editable field of a pasted rule is carried through', async () => {
  const body = `regex = '''(?i)tok-([a-z0-9]{8})'''
description = "d"
keywords = ["TOK-", "Other"]
entropy = 2.5
secretGroup = 1
category = "data_exfiltration"
severity = "critical"
score = 0.42
owasp = "LLM02"
appliesTo = ["mcp", "a2a"]
[rules.allowlist]
regexes = ["^zzz"]`;
  const [a] = (await imp(rule(body, 'all-fields'))).Added;
  assert.deepEqual(a, { ID: 'cst-all-fields', Description: 'd', Category: 'data_exfiltration', Severity: 'critical', Score: 0.42, OWASP: 'LLM02', AppliesTo: ['mcp', 'a2a'], Keywords: ['tok-', 'other'], Pattern: '(?i)tok-([a-z0-9]{8})', Entropy: 2.5, Allowlist: ['^zzz'], ValueGroup: 1 });
  assert.ok(CATEGORY_IDS.includes(a.Category));
  assert.equal((await imp(rule("regex = 'a'\nseverity = \"low\""))).Added[0].Score, SEVERITY_SCORE.low);
});

test('duplicates within the paste and against the workspace are refused; the workspace cap is enforced', async () => {
  const dup = await imp(`${rule("regex = 'a'", 'same')}${rule("regex = 'b'", 'same')}`);
  assert.match(dup.Errors.join(), /already exists/);
  assert.match((await imp(rule("regex = 'a'", 'cst-same'), { existingIds: ['cst-same'] })).Errors.join(), /already exists/);
  assert.match((await imp(rule("regex = 'a'"), { existingCount: RULE_LIMITS.rulesPerWorkspace })).Errors.join(), /holds at most 50 rules/);
});

test('refusals never echo the pasted pattern back', async () => {
  const r = await imp(rule("regex = 'zzSECRETMARKERzz(a+)+'", 'id-with-marker'));
  assert.ok(!r.Errors.join().includes('SECRETMARKER'));
});

test('a rule paste with a catastrophic pattern returns promptly', async () => {
  const t0 = Date.now();
  await imp(rule("regex = '^(\\\\w+\\\\s?)*$'"));
  assert.ok(Date.now() - t0 < 30000);
});
