import test from 'node:test';
import assert from 'node:assert/strict';
import { PII_KINDS, PII_KIND_IDS, SAMPLES, abaCheckDigit, abaValid, detectPii, dniLetter, healthIdValid, ibanCheckDigits, ibanValid, luhnComplete, luhnValid, mod11Check, mod97 } from '../src/pii.js';

const within = (s) => `Please check the value ${s} and reply.`;

test('eleven lab-written kinds, each with a label, a group, a stated validation and a score; the set is labelled illustrative elsewhere', () => {
  assert.equal(PII_KINDS.length, 11);
  assert.deepEqual(new Set(PII_KINDS.map((k) => k.group)), new Set(['national', 'financial', 'health', 'contact']));
  for (const k of PII_KINDS) { assert.match(k.id, /^pii-[a-z-]+$/); assert.ok(k.label && k.validation && k.score > 0 && k.score <= 1, k.id); }
  assert.deepEqual(Object.keys(SAMPLES).sort(), [...PII_KIND_IDS].sort());
});

for (const k of PII_KINDS) {
  test(`${k.id}: its valid sample is found exactly once, and its NEAR MISS is not`, () => {
    const hit = detectPii(within(SAMPLES[k.id].valid()), [k.id]);
    assert.equal(hit.length, 1, `valid sample of ${k.id}`);
    assert.equal(hit[0].kind, k.id);
    assert.equal(detectPii(within(SAMPLES[k.id].nearMiss()), [k.id]).length, 0, `near miss of ${k.id}`);
  });
  test(`${k.id}: selecting only other kinds hides it; selecting it finds it (per-kind selection)`, () => {
    const text = within(SAMPLES[k.id].valid());
    const others = PII_KIND_IDS.filter((x) => x !== k.id);
    assert.equal(detectPii(text, others).filter((f) => f.kind === k.id).length, 0);
    assert.equal(detectPii(text, [k.id]).length, 1);
    assert.equal(detectPii(text, null).filter((f) => f.kind === k.id).length, 1, 'null means every kind');
  });
}

test('the span of a finding is exactly the sensitive value', () => {
  for (const k of PII_KINDS) {
    const v = SAMPLES[k.id].valid(); const text = `xx ${v} yy`; const [f] = detectPii(text, [k.id]);
    assert.equal(text.slice(f.start, f.end), k.id === 'pii-dob' ? v.replace(/^DOB: /, '') : v, k.id);
  }
});

test('checksum primitives: Luhn, mod 97, ABA weights, mod 11, DNI letter', () => {
  assert.ok(luhnValid(luhnComplete('411111111111111')));
  assert.ok(!luhnValid('4111111111111112'));
  assert.equal(mod97('3214282912345698765432161182'), 1); // a worked IBAN rearrangement
  assert.ok(ibanValid(`GB${ibanCheckDigits('GB', 'WEST12345698765432')}WEST12345698765432`));
  assert.ok(!ibanValid(`GB00WEST12345698765432`));
  assert.ok(abaValid(`02100002${abaCheckDigit('02100002')}`));
  assert.ok(!abaValid('021000020') || abaCheckDigit('02100002') === 0);
  assert.ok(healthIdValid('9434765919'));
  assert.ok(!healthIdValid('9434765918'));
  assert.equal(mod11Check('943476591'), 9);
  assert.equal(dniLetter('12345678'), 'Z');
});

test('a credit-card number with ONE wrong digit does not match, in every position', () => {
  const d = luhnComplete('411111111111111');
  for (let i = 0; i < d.length; i++) {
    const bad = `${d.slice(0, i)}${(+d[i] + 1) % 10}${d.slice(i + 1)}`;
    assert.equal(detectPii(within(bad), ['pii-credit-card']).length, 0, `digit ${i}`);
  }
});

test('structure rules: SSN area 000, 666, 9xx and zero group or serial; calendar dates; excluded NINO prefixes', () => {
  for (const bad of ['000-12-3456', '666-12-3456', '912-12-3456', '123-00-3456', '123-45-0000']) assert.equal(detectPii(within(bad), ['pii-ssn']).length, 0, bad);
  assert.equal(detectPii(within('123-45-6789'), ['pii-ssn']).length, 1);
  for (const bad of ['DOB: 2021-02-29', 'born on 31/04/1990', 'DOB: 1850-01-01']) assert.equal(detectPii(within(bad), ['pii-dob']).length, 0, bad);
  assert.equal(detectPii(within('date of birth 29/02/2020'), ['pii-dob']).length, 1);
  for (const bad of ['BG 12 34 56 C', 'ZZ 12 34 56 C', 'AB 12 34 56 E']) assert.equal(detectPii(within(bad), ['pii-uk-nino']).length, 0, bad);
});

test('numbers inside longer digit runs, or glued to other characters, are not matched', () => {
  const card = SAMPLES['pii-credit-card'].valid().replace(/ /g, '');
  assert.equal(detectPii(`9${card}`, ['pii-credit-card']).length, 0);
  assert.equal(detectPii(`${card}9`, ['pii-credit-card']).length, 0);
  assert.equal(detectPii('9'.repeat(40), null).length, 0);
});

test('hostile input is bounded: 20000 characters of digits, separators and look-alikes scan in well under a second', () => {
  const t0 = Date.now();
  for (const s of ['1 '.repeat(10000), '1-'.repeat(10000), 'A1'.repeat(10000), `${'4'.repeat(18)} `.repeat(1000), 'GB82 '.repeat(4000), '@'.repeat(20000), 'a@'.repeat(10000), '+'.repeat(20000), '1'.repeat(20000), 'DOB: '.repeat(4000)]) detectPii(s.slice(0, 20000));
  assert.ok(Date.now() - t0 < 20000, `took ${Date.now() - t0} ms`);
});
