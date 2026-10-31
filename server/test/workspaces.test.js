import test from 'node:test';
import assert from 'node:assert/strict';
import { MAX_EVENTS, MAX_RECORDS, MAX_RULES, WORKSPACE_RE, createWorkspaces, workspaceFrom } from '../src/workspaces.js';

test('workspaceFrom defaults, accepts a good id and refuses a bad one', () => {
  assert.equal(workspaceFrom({ headers: {} }), 'default');
  assert.equal(workspaceFrom({ headers: { 'x-workspace': 'abc-1' } }), 'abc-1');
  for (const bad of ['', 'A', 'a b', 'a/b', 'x'.repeat(41), ['a']]) assert.equal(workspaceFrom({ headers: { 'x-workspace': bad } }), null);
  assert.ok(WORKSPACE_RE.test('a'));
});

test('workspaces are isolated, events, records and rules are bounded, reset is per workspace', () => {
  const w = createWorkspaces();
  for (let i = 0; i < MAX_EVENTS + 5; i++) w.addEvent('a', { id: `e${i}` });
  for (let i = 0; i < MAX_RECORDS + 5; i++) w.addRecord('a', { id: `r${i}` });
  w.addRules('a', Array.from({ length: MAX_RULES + 5 }, (_, i) => ({ ID: `cst-${i}` })));
  w.addEvent('b', { id: 'x' });
  assert.deepEqual([w.events('a').length, w.records('a').length, w.rules('a').length], [MAX_EVENTS, MAX_RECORDS, MAX_RULES]);
  assert.equal(w.events('a').at(-1).id, `e${MAX_EVENTS + 4}`);
  assert.ok(w.events('a')[0].at, 'events are stamped');
  w.setPromptLog('a', { Enabled: true }, { x: 1 });
  w.reset('a');
  assert.deepEqual([w.events('a').length, w.records('a').length, w.rules('a').length, w.promptLog('a').Enabled, w.publicKey('a'), w.events('b').length], [0, 0, 0, false, null, 1]);
});

test('new rules start in observe; enforcement is per rule and per workspace; an unknown rule is refused', () => {
  const w = createWorkspaces();
  w.addRules('a', [{ ID: 'cst-1' }, { ID: 'cst-2' }]);
  assert.deepEqual(w.rules('a').map((r) => r.enforcement), ['observe', 'observe']);
  assert.equal(w.setEnforcement('a', 'cst-2', 'enforce'), true);
  assert.deepEqual(w.rules('a').map((r) => r.enforcement), ['observe', 'enforce']);
  assert.equal(w.setEnforcement('a', 'cst-9', 'enforce'), false); assert.equal(w.setEnforcement('b', 'cst-1', 'enforce'), false);
});

test('the store expires old workspaces and caps their count; a read never creates one', () => {
  let t = 0;
  const w = createWorkspaces({ max: 3, ttlMs: 100, now: () => t });
  for (const id of ['a', 'b', 'c', 'd']) w.addEvent(id, { id: 'x' });
  assert.equal(w.size(), 3);
  w.events('zzz'); assert.equal(w.size(), 3);
  t = 500;
  assert.equal(w.events('d').length, 0);
  assert.equal(w.size(), 0);
});
