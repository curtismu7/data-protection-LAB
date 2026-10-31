import test from 'node:test';
import assert from 'node:assert/strict';
import { SECRET_COUNT_IN_DECK, SECRET_DETECTORS, detectSecrets, filler, shannon } from '../src/secrets.js';

test('a small lab-written set, labelled as such: the deck figure is separate and the set is far smaller', () => {
  assert.equal(SECRET_COUNT_IN_DECK, 364);
  assert.ok(SECRET_DETECTORS.length >= 12 && SECRET_DETECTORS.length < 40);
  assert.equal(new Set(SECRET_DETECTORS.map((d) => d.id)).size, SECRET_DETECTORS.length);
});

for (const d of SECRET_DETECTORS) {
  test(`${d.id}: its sample (built at run time) fires once; its near miss does not`, () => {
    const hits = detectSecrets(`config: ${d.sample()} end`).filter((f) => f.rule === d.id);
    assert.equal(hits.length, 1, 'sample');
    assert.equal(detectSecrets(`config: ${d.nearMiss()} end`).filter((f) => f.rule === d.id).length, 0, 'near miss');
  });
}

test('the span is the value group, not the whole match (url password, bearer, assignment)', () => {
  for (const id of ['lab-url-password', 'lab-bearer-token', 'lab-generic-assignment']) {
    const d = SECRET_DETECTORS.find((x) => x.id === id); const text = `x ${d.sample()} y`;
    const f = detectSecrets(text).find((x) => x.rule === id);
    assert.ok(f.end - f.start < d.sample().length, id);
    assert.ok(!text.slice(f.start, f.end).includes('://') && !/bearer|api_/i.test(text.slice(f.start, f.end)), id);
  }
});

test('the entropy floor is real: a long run of one character after a secret-looking name is not a secret', () => {
  assert.equal(detectSecrets('api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"').length, 0);
  assert.equal(detectSecrets(`api_key = "${filler(28, 'e')}"`).length, 1);
  assert.ok(shannon('aaaa') === 0 && shannon('abcd') === 2);
});

test('the allowlist is real: placeholders after a secret-looking name are ignored', () => {
  for (const v of ['your_api_key_goes_here', 'changeme_changeme', 'example_example_key']) assert.equal(detectSecrets(`token = "${v}"`).length, 0, v);
});

test('the keyword prefilter does not hide a match, and hostile input is bounded', () => {
  const s = SECRET_DETECTORS.find((d) => d.id === 'lab-github-token').sample();
  assert.equal(detectSecrets(s.toUpperCase()).length, 0, 'prefix case matters for this detector');
  assert.equal(detectSecrets(s).length, 1);
  const t0 = Date.now();
  for (const x of ['a'.repeat(20000), 'sk-'.repeat(6000), 'bearer '.repeat(2500), 'ey'.repeat(10000), 'AKIA'.repeat(5000), '://'.repeat(6000), 'api_key='.repeat(2500)]) detectSecrets(x.slice(0, 20000));
  assert.ok(Date.now() - t0 < 20000, `took ${Date.now() - t0} ms`);
});
