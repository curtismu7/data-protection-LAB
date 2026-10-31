import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { DEFAULT_CAST, VERTICALS } from '../src/cast.js';
import { buildStory, renderTalkTrackMarkdown } from '../src/story.js';
import { scanHosts, scanKeys } from '../src/safety.js';
import { CLAIMS, CLAIM_LABEL, FIELD_SOURCES, NOT_DEMONSTRATED, TALK_TRACK } from '../src/data.js';
import { MOCK_TABLE } from '../src/mockTable.js';
import { buildMockTable } from '../src/evaluation.js';
import { sharedRunner } from '../src/regexRunner.js';

test.after(() => sharedRunner.close());

test('docs/talk-track.md is exactly what the talk-track data renders (no drift), and carries a Why it matters entry per feature', () => {
  const doc = fs.readFileSync(new URL('../../docs/talk-track.md', import.meta.url), 'utf8');
  assert.equal(doc, renderTalkTrackMarkdown(DEFAULT_CAST));
  assert.ok(TALK_TRACK.length >= 12);
  assert.match(TALK_TRACK.find((t) => t.id === 'why-aiguard').say, /fraction of the cost of one incident/);
  assert.match(TALK_TRACK.find((t) => t.id === 'why-insights').say, /shorter audits/);
  assert.match(TALK_TRACK.find((t) => t.id === 'why-prompt-logging').say, /data-trust concession/);
  assert.match(TALK_TRACK.find((t) => t.id === 'why-owasp').say, /accelerate security approval/);
  assert.match(doc, /## Not demonstrated/);
});

test('the Mock table is exactly what the engine produces now (no drift), in every part', async () => {
  const fresh = JSON.parse(JSON.stringify(await buildMockTable()));
  for (const k of Object.keys(fresh)) assert.deepEqual(MOCK_TABLE[k], fresh[k], `mockTable.${k} drifted: run npm run mock-table`);
  assert.deepEqual(Object.keys(MOCK_TABLE).sort(), Object.keys(fresh).sort());
});

test('every banner and the intro say the claims are UNVERIFIED on our tenant; each claim names its slide; what is not demonstrated is listed', () => {
  const s = buildStory(DEFAULT_CAST, 'finance');
  assert.equal(s.claimLabel, CLAIM_LABEL);
  for (const b of Object.values(s.banner)) assert.match(b, /UNVERIFIED on our tenant/);
  assert.match(s.banner.mock, /MOCK/); assert.match(s.banner.live, /LIVE/);
  assert.ok(CLAIMS.length >= 10 && CLAIMS.every((c) => [50, 53, 54, 55].includes(c.slide)));
  assert.ok(NOT_DEMONSTRATED.some((n) => /23 personal-data kinds/.test(n) && /does not reproduce or guess/.test(n)));
  assert.ok(NOT_DEMONSTRATED.some((n) => /External guardrail/.test(n)));
});

test('the 23 kinds, the 364 detectors and the 411 rules are never claimed as the lab\'s own', () => {
  const s = buildStory(DEFAULT_CAST, 'finance'); const text = JSON.stringify(s);
  assert.equal(s.piiKinds.length, 11); assert.ok(s.secretDetectors.length < 40);
  assert.ok(!/\b23 (kinds|personal)\b[^.]{0,40}(this lab|the lab ships)/i.test(text));
  assert.match(text, /lab-written|illustrative/i);
  for (const f of FIELD_SOURCES) assert.ok(['swagger', 'reading', 'invented'].includes(f.source), f.field);
  assert.ok(FIELD_SOURCES.some((f) => f.source === 'invented' && /Envelope/.test(f.field)), 'the envelope is labelled lab-invented');
  assert.ok(FIELD_SOURCES.some((f) => f.source === 'swagger' && /PIIKinds/.test(f.field)));
});

test('the filled story names no non-reserved host and no real-looking key, in any vertical; the only credential is the labelled mock one; never the word "door"', () => {
  for (const [v, cast] of Object.entries(VERTICALS)) {
    const text = JSON.stringify(buildStory(cast, v));
    assert.deepEqual(scanHosts(text), [], v); assert.deepEqual(scanKeys(text), [], v);
    assert.ok(text.includes('sk-MOCK-'), 'the mock credential is present in the secret scenario');
    assert.ok(!/\bdoor\b/i.test(text), `${v}: say "P1 Privilege Agent App", not "door"`);
  }
});

test('no credential-shaped string is committed: the repository holds no sk-MOCK literal, only the parts', () => {
  assert.ok(!fs.readFileSync(new URL('../src/data.js', import.meta.url), 'utf8').includes('sk-MOCK-'));
});
