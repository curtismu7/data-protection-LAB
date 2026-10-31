import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { buildPack } from './build-content-pack.mjs';
import { validatePack } from './validate-content-pack.mjs';

const root = new URL('..', import.meta.url);
const committed = JSON.parse(fs.readFileSync(new URL('content-pack.json', root), 'utf8'));

test('the pack validates against the schema and its cross-references hold, with the assigned catalog D103', () => {
  assert.deepEqual(validatePack(buildPack()), []);
  assert.equal(buildPack().demo.catalog, 'D103');
  assert.equal(buildPack().schema, 'demo-content-pack/1');
});

test('the committed content-pack.json is exactly what the builder makes (no drift)', () => {
  assert.deepEqual(committed, buildPack());
});

test('every scenario has a story and a try-it card', () => {
  const pack = buildPack();
  assert.equal(pack.stories.length, 7);
  for (const s of pack.stories) assert.ok(pack.cards.find((c) => c.story === s.id), s.id);
});

test('a broken pack is caught: unknown term and unknown story', () => {
  const pack = buildPack();
  pack.cards[0].terms = ['nope'];
  pack.cards[1].story = 'ghost';
  const errors = validatePack(pack).join('\n');
  assert.match(errors, /unknown term nope/);
  assert.match(errors, /unknown story ghost/);
});

test('the pack has a Why it matters entry per feature (challenge, technical, business), names no real company, tenant or documentation URL, holds no credential or personal number', () => {
  const pack = buildPack(); const t = JSON.stringify(pack).toLowerCase();
  for (const w of ['united', 'mileageplus', 'datapower', 'optum', 'uhg', 'benefit']) assert.ok(!t.includes(w), w);
  assert.ok(!/https?:\/\/(?!(localhost|example\.invalid))/.test(t), 'only localhost and .invalid links');
  assert.ok(!/\bdoor\b/.test(t), 'say P1 Privilege Agent App, not door');
  assert.ok(!t.includes('sk-mock'), 'no credential-shaped value');
  assert.ok(!/\d{4} \d{4} \d{4} \d{4}/.test(t), 'no card number');
  for (const id of ['concept-why-aiguard', 'concept-why-insights', 'concept-why-prompt-logging', 'concept-why-owasp']) {
    const d = pack.cards.find((c) => c.id === id).description;
    assert.match(d, /Challenge:/); assert.match(d, /Technical:/); assert.match(d, /Business:/); assert.match(d, /Ping claims, unverified on our tenant/);
  }
});

test('every glossary definition of a product claim says it is UNVERIFIED on our tenant, and the lab-invented parts say so', () => {
  const pack = buildPack();
  for (const g of pack.glossary.filter((x) => ['aiguard', 'graduated-response', 'sanitize', 'indirect-injection', 'personal-data-kinds', 'secret-detectors', 'rule-import', 'observe-mode', 'prompt-logging', 'browser-decrypt', 'agent-insights', 'owasp-asi'].includes(x.id))) assert.match(g.definition, /UNVERIFIED on our tenant/, g.id);
  assert.match(pack.glossary.find((g) => g.id === 'sealed-envelope').definition, /LAB-INVENTED/);
  assert.match(pack.glossary.find((g) => g.id === 'personal-data-kinds').definition, /not Ping's list/);
});
