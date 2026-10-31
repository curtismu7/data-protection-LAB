import test from 'node:test';
import assert from 'node:assert/strict';
import { OWASP_ROWS, OWASP_STATUS_LABEL } from '../src/owasp.js';
import { CATEGORY_IDS } from '../src/categories.js';

const row = (id) => OWASP_ROWS.find((r) => r.id === id);

test('ASI01 to ASI10, each with a name, the deck\'s control text and a statement of what this lab shows', () => {
  assert.deepEqual(OWASP_ROWS.map((r) => r.id), Array.from({ length: 10 }, (_, i) => `ASI${String(i + 1).padStart(2, '0')}`));
  for (const r of OWASP_ROWS) { assert.ok(r.name && r.deck && r.lab, r.id); assert.ok(Object.hasOwn(OWASP_STATUS_LABEL, r.status), r.id); for (const c of r.labCategories) assert.ok(CATEGORY_IDS.includes(c), `${r.id}: ${c}`); }
});

test('the deck\'s own stated gaps are rendered exactly as qualified, never as full coverage', () => {
  assert.equal(row('ASI04').status, 'pending'); assert.match(row('ASI04').deck, /fingerprint pinning pending/); assert.match(row('ASI04').qualifier, /PENDING/); assert.match(row('ASI04').qualifier, /Do not present this row as full coverage/);
  assert.match(row('ASI04').lab, /fingerprint pinning are not built/);
  assert.equal(row('ASI06').status, 'in-progress'); assert.match(row('ASI06').deck, /memory-write inspection shipped; gateway integration in progress/); assert.match(row('ASI06').qualifier, /IN PROGRESS/);
  for (const id of ['ASI08', 'ASI09', 'ASI10']) { assert.equal(row(id).status, 'noted', id); assert.ok(row(id).qualifier.length > 40, id); }
  assert.match(row('ASI08').qualifier, /in-gateway behaviour scoring now supplements it/i); assert.match(row('ASI10').qualifier, /rogue-agent access scoring supplements/i); assert.match(row('ASI09').qualifier, /no dedicated ASI09 detector/);
  const full = OWASP_ROWS.filter((r) => r.status === 'stated').map((r) => r.id);
  assert.deepEqual(full, ['ASI01', 'ASI02', 'ASI03', 'ASI05', 'ASI07'], 'only these rows carry no qualification in the deck');
  for (const r of OWASP_ROWS.filter((x) => x.status !== 'stated')) assert.ok(!/fully covered|full coverage\./i.test(r.deck), r.id);
});

test('rows that are gateway controls say the lab does not demonstrate them', () => {
  for (const id of ['ASI03', 'ASI08', 'ASI10']) assert.match(row(id).lab, /Not demonstrated here/, id);
});
