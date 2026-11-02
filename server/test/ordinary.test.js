// Ordinary lab traffic is not changed by the masking: every scripted answer of every vertical, in Mock and in Live, carries exactly the display marks the engine puts there on
// purpose (a detected value is shown as [masked for display:<detector>]) and no other; the lists the page filters by (Insights facets) keep every name.
import test from 'node:test';
import assert from 'node:assert/strict';
import { post, withApp } from './helpers.js';

const W = { 'x-workspace': 'ordinary' };
const marks = (t) => [...t.matchAll(/\[masked[^\]]*\]/g)].map((m) => m[0]).sort();
const two = (id) => [`[masked for display:${id}]`, `[masked for display:${id}]`];
const EXPECT = {
  ordinary: [], contact: ['[masked for display:pii-email]', '[masked for display:pii-email]', '[masked for display:pii-phone]', '[masked for display:pii-phone]'],
  'card-and-id': [], 'direct-injection': [], 'indirect-injection': two('inj-ignore-previous'), secret: two('lab-openai-style-key'), 'exfil-image': two('exf-markdown-image'),
};
const CATEGORIES = ['data_exfiltration', 'hidden_instructions', 'indirect_injection', 'jailbreak', 'malicious_content', 'memory_poisoning', 'pii', 'prompt_injection', 'schema_violation', 'secrets', 'tool_abuse', 'tool_poisoning'];

test('scripted answers: exactly the documented display marks, in 3 verticals x 2 modes x 7 scenarios, and none in the stream, Insights or the info answers', async () => {
  assert.equal(Object.keys(EXPECT).length, 7);
  await withApp(async (url) => {
    let checked = 0;
    for (const vertical of ['finance', 'health', 'retail']) for (const mode of ['mock', 'live']) {
      for (const [scenario, want] of Object.entries(EXPECT)) {
        const t = await (await post(url, `/api/evaluate?vertical=${vertical}`, { mode, scenario, vertical }, W)).text();
        assert.deepEqual(marks(t), want, `${vertical}/${mode}/${scenario}`); checked++;
      }
      assert.deepEqual(marks(await (await post(url, '/api/stream', { mode, vertical }, W)).text()), [], `${vertical}/${mode}/stream`);
      assert.deepEqual(marks(await (await fetch(`${url}/api/insights?mode=${mode}&vertical=${vertical}`, { headers: W })).text()), [], `${vertical}/${mode}/insights`);
    }
    assert.equal(checked, 42);
    for (const p of ['/api/story', '/api/diagram', '/api/info', '/api/selfcheck?mode=live', '/api/selfcheck?mode=mock', '/api/rules', '/api/promptlog']) assert.deepEqual(marks(await (await fetch(`${url}${p}`, { headers: W })).text()), [], p);
  });
});

test('Insights facets keep every name: the 12 category ids (tool_abuse sits after "secrets" and is not read as its value) in Mock and, after a run, in Live', async () => {
  await withApp(async (url) => {
    const mock = await (await fetch(`${url}/api/insights?mode=mock`, { headers: W })).json();
    assert.deepEqual(mock.facets.category, CATEGORIES);
    assert.deepEqual(mock.facets.flow, ['a2a', 'coding_agent', 'llm', 'mcp']);
    assert.deepEqual(mock.facets.decision, ['alert', 'allow', 'block', 'sanitize']);
    // a typed agent name that holds a credential is still masked in the facet list
    await post(url, '/api/evaluate', { mode: 'live', scenario: 'secret', labels: { agent: `password ${['hunter', '2xyz'].join('')}` } }, W);
    const live = await (await fetch(`${url}/api/insights?mode=live`, { headers: W })).json();
    assert.ok(!JSON.stringify(live).includes(['hunter', '2xyz'].join('')));
    assert.ok(live.facets.category.includes('secrets'));
  });
});
