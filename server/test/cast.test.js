import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DEFAULT_CAST, VERTICALS, fill, fillDeep, loadCast, unfilled, verticalFrom } from '../src/cast.js';
import { rawStory } from '../src/story.js';
import { rawDiagram, DIAGRAM_NAMES } from '../src/diagramData.js';
import { CATEGORY_SAMPLES, SCENARIOS, STREAM } from '../src/data.js';
import { detectPii } from '../src/pii.js';

test('three vertical packs: finance, health, retail', () => {
  assert.deepEqual(Object.keys(VERTICALS).sort(), ['finance', 'health', 'retail']);
  assert.equal(verticalFrom('nope'), 'finance'); assert.equal(verticalFrom(5), 'finance'); assert.equal(verticalFrom('__proto__'), 'finance'); assert.equal(verticalFrom(['health']), 'finance');
});

test('every {{token}} in the story, samples, stream and diagram data is defined by every vertical pack', () => {
  const text = JSON.stringify([rawStory(), SCENARIOS, STREAM, CATEGORY_SAMPLES, ...DIAGRAM_NAMES.map(rawDiagram)]);
  assert.ok(/\{\{cast/.test(text), 'the story really uses tokens');
  for (const [v, cast] of Object.entries(VERTICALS)) assert.deepEqual(unfilled(text, cast), [], v);
});

test('a test would catch an undefined token', () => {
  assert.deepEqual(unfilled('hello {{castBrand}} {{castNope}}', DEFAULT_CAST), ['castNope']);
  assert.equal(fill('{{castNope}}', DEFAULT_CAST), '{{castNope}}');
});

test('the synthetic personal data in each pack really is detected as the kind it stands for (checksum-valid, built at run time)', () => {
  const kind = { finance: 'pii-ssn', health: 'pii-health-id', retail: 'pii-iban' };
  for (const [v, c] of Object.entries(VERTICALS)) {
    assert.equal(detectPii(` ${c.castCard} `, ['pii-credit-card']).length, 1, `${v} card`);
    assert.equal(detectPii(` ${c.castIdentifier} `, [kind[v]]).length, 1, `${v} identifier`);
    assert.equal(detectPii(` ${c.castEmail} `, ['pii-email']).length, 1); assert.equal(detectPii(` ${c.castPhone} `, ['pii-phone']).length, 1);
    assert.deepEqual(detectPii(` call ${c.castPhone} `).map((f) => f.kind), ['pii-phone'], `${v}: the phone number is not also another kind`);
  }
});

test('fillDeep fills nested data and is not recursive (a very deep value does not overflow the stack)', () => {
  assert.deepEqual(fillDeep({ a: ['{{castBrand}}', { b: '{{castHost}}' }], n: 1, z: null }, DEFAULT_CAST), { a: ['Fabrikam Bank', { b: 'fabrikam' }], n: 1, z: null });
  let deep = '{{castBrand}}'; for (let i = 0; i < 50_000; i++) deep = { x: deep };
  assert.ok(fillDeep(deep, DEFAULT_CAST));
});

test('customer.config.json overrides only brand, agentId and host, and refuses hosts and urls', () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'dpl-')), 'customer.config.json');
  fs.writeFileSync(f, JSON.stringify({ cast: { brand: 'Acme Corp', agentId: 'bot.one', host: 'acme', card: 'steal' } }));
  const c = loadCast(f, 'retail');
  assert.equal(c.castBrand, 'Acme Corp'); assert.equal(c.castAgentId, 'bot.one'); assert.equal(c.castHost, 'acme');
  assert.equal(c.castCard, VERTICALS.retail.castCard, 'the personal data is not configurable');
  fs.writeFileSync(f, JSON.stringify({ cast: { brand: 'See https://evil.com', host: 'a.b.c' } }));
  assert.equal(loadCast(f).castBrand, DEFAULT_CAST.castBrand); assert.equal(loadCast(f).castHost, DEFAULT_CAST.castHost);
});
