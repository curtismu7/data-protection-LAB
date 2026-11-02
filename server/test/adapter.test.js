// The adapter's own wiring, one behaviour per test: the final response mask on every answer (even a table that holds a raw secret), the lab's detectors on object keys, the
// display copy's keyword rule, and the TOML echo's reading of escapes inside a multi-line string.
import test from 'node:test';
import assert from 'node:assert/strict';
import { SAMPLES } from '../src/pii.js';
import { SECRET_DETECTORS } from '../src/secrets.js';
import { MOCK_TABLE } from '../src/mockTable.js';
import { maskDeep, maskText } from '../src/mask.js';
import { defaultPolicy, inspect } from '../src/guard.js';
import { echoToml } from '../src/rules.js';
import { post, withApp } from './helpers.js';

const S1 = ['hunter', '2xyz'].join('');
const W = { 'x-workspace': 'adapter' };

test('the response mask is the last step of EVERY answer: a table that holds a raw credential never gets it out through evaluate, stream, rules/import or insights', async () => {
  const table = structuredClone(MOCK_TABLE);
  table.scenarios.finance.ordinary.text = `password ${S1}`;
  table.stream.finance.frames[0].text = `password ${S1}`;
  table.rules['one-bad'] ??= { Added: [], Errors: [] };
  table.rules['one-bad'].Errors = [`bad rule: password ${S1}`];
  table.insights.finance[0].agent = `password ${S1}`;
  await withApp(async (url) => {
    const answers = [
      await (await post(url, '/api/evaluate?vertical=finance', { mode: 'mock', scenario: 'ordinary', vertical: 'finance' }, W)).text(),
      await (await post(url, '/api/stream', { mode: 'mock', vertical: 'finance' }, W)).text(),
      await (await post(url, '/api/rules/import', { mode: 'mock', sample: 'one-bad' }, W)).text(),
      await (await fetch(`${url}/api/insights?mode=mock&vertical=finance`, { headers: W })).text(),
    ];
    assert.equal(answers.length, 4);
    answers.forEach((a, i) => { assert.ok(a.length > 100, `answer ${i} is a real answer`); assert.ok(!a.includes(S1), `answer ${i} holds the credential`); assert.match(a, /\[masked:/, `answer ${i} was masked`); });
  }, { table });
});

test('maskDeep: the lab\'s own detectors mark personal data in object KEYS as well as in values', () => {
  const email = SAMPLES['pii-email'].valid();
  const out = JSON.stringify(maskDeep({ [email]: 1, nested: { [`x ${email}`]: [email] } }));
  assert.ok(!out.includes(email), out);
  assert.equal((out.match(/\[masked:pii-email\]/g) || []).length, 3);
});

test('display copy: a keyword before a detector\'s value stays readable, and a short value before it (digits) is masked with it', async () => {
  const sk = SECRET_DETECTORS.find((d) => d.id === 'lab-openai-style-key').sample();
  const ctx = { role: 'user_prompt', surface: 'llm', policy: defaultPolicy(), rules: [] };
  assert.equal((await inspect(`The payments gateway key is ${sk} for staging`, ctx)).text, 'The payments gateway key is [masked for display:lab-openai-style-key] for staging');
  const lead = await inspect(`Authorization: abc123xy ${sk}`, ctx);
  assert.equal(lead.text, '[masked for display:lab-openai-style-key]');
  assert.ok(!lead.text.includes(sk));
});

test('the lab\'s own display marks survive the shared masker, even right after a keyword, in text and in structures', async () => {
  const sk = SECRET_DETECTORS.find((d) => d.id === 'lab-openai-style-key').sample();
  const ctx = { role: 'user_prompt', surface: 'llm', policy: defaultPolicy(), rules: [] };
  assert.equal((await inspect(`a1b2c3 password=${sk}`, ctx)).text, 'a1b2c3 password=[masked for display:lab-openai-style-key]');
  for (const t of ['password=[masked for display:lab-openai-style-key]', 'token: [REDACTED:secrets] tail', 'x [masked for display:pii-email] y']) { assert.equal(maskText(t), t, t); assert.equal(maskText(maskText(t)), t); }
  const deep = { text: 'password=[REDACTED:pii] tail', list: ['api key [masked for display:pii-ssn]'] };
  assert.deepEqual(maskDeep(deep), deep);
});

test('the pasted-rule echo reads TOML escapes inside a multi-line string: a tab spelled \\t in the keyword does not hide it', () => {
  const toml = `[[rules]]\nid = "r-esc"\nregex = 'abc'\ndescription = """\npass\\tword=${S1}\nfine line\n"""\n`;
  const echo = echoToml(toml);
  assert.ok(!echo.includes(S1), echo);
  assert.ok(echo.includes('fine line'), 'a line that holds nothing is still shown');
  assert.match(echo, /\[masked:line\]/);
});
