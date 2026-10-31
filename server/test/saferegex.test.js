import test from 'node:test';
import assert from 'node:assert/strict';
import { REGEX_LIMITS, checkRegex, splitInlineFlags } from '../src/safeRegex.js';

test('hostile patterns are refused before they can run', () => {
  const hostile = {
    '(a+)+$': /nested/, '(a*)*b': /nested/, '(a+){10}': /nested/, '(.*a){20}': /nested/, '^(\\w+\\s?)*$': /nested/, '(x+x+)+y': /nested/,
    '(a|aa)+$': /alternatives/, '(a|a)*': /alternatives/,
    '(a)\\1': /backreference/, '(?<n>a)\\k<n>': /named group/,
    '(?=a)b': /lookahead/, '(?!a)b': /lookahead/, '(?<=a)b': /lookahead/, '(?<!a)b': /lookahead/,
    'a{1,1000}': /repeat count/, 'x{1000000}': /repeat count/, 'x{0,9999999999}': /repeat count/, 'a{5,2}': /backwards/,
    'a*b*c*d*e*f*g*': /variable quantifiers/, [`${'a?'.repeat(40)}${'a'.repeat(40)}`]: /variable quantifiers/, ['a{0,2}'.repeat(7)]: /variable quantifiers/, [`${'a?'.repeat(7)}`]: /variable quantifiers/,
    '*a': /nothing to repeat/, '(a': /unbalanced/, 'a)': /unbalanced/, '[a': /unterminated/, 'a\\': /backslash/,
    '(?i:a)': /inline flag/, '\\p{L}': /Unicode/,
  };
  for (const [p, why] of Object.entries(hostile)) assert.match(String(checkRegex(p)), why, p);
  assert.match(checkRegex('a'.repeat(REGEX_LIMITS.length + 1)), /longer than 400/);
  assert.match(checkRegex(''), /empty/); assert.match(checkRegex(undefined), /empty/); assert.match(checkRegex('(?i)'), /empty/);
  assert.match(checkRegex(`${'(a)'.repeat(13)}`), /more than 12 groups/);
});

test('ordinary secret-shaped patterns pass', () => {
  for (const p of ['\\bghp_[A-Za-z0-9]{36}\\b', '(?i)acme_[a-z0-9]{20}', '(?:foo|bar)_[0-9]{4}', '(\\d{3})+', 'a+?b', 'secret=([A-Za-z0-9]{8,64})', '[\\]a]+', 'x{2,5}', '\\{literal\\}', 'a{b']) assert.equal(checkRegex(p), null, p);
});

test('a leading (?i) becomes the i flag; other text is left alone', () => {
  assert.deepEqual(splitInlineFlags('(?i)abc'), { source: 'abc', flags: 'i' });
  assert.deepEqual(splitInlineFlags('abc(?i)'), { source: 'abc(?i)', flags: '' });
});

test('the reason never echoes the pattern', () => {
  const secretLooking = 'zzSECRETMARKERzz(a+)+';
  assert.ok(!String(checkRegex(secretLooking)).includes('SECRETMARKER'));
});
