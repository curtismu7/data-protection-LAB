import test from 'node:test';
import assert from 'node:assert/strict';
import { FILTERS, LIVE_VIEW, MAX_ROWS, WINDOWS, ageHours, queryInsights } from '../src/insights.js';
import { CATEGORY_MAP, COMPLIANCE_NOTE, FRAMEWORKS, complianceSummary, mappingFor } from '../src/compliance.js';
import { CATEGORY_IDS } from '../src/categories.js';
import { MOCK_TABLE } from '../src/mockTable.js';
import { SEED_COUNT } from '../src/evaluation.js';
import { get, post, withServer } from './helpers.js';

const NOW = Date.parse('2026-11-02T12:00:00Z');
const seed = MOCK_TABLE.insights.finance;
const ids = (r) => r.events.map((e) => e.id);

test('the seeded events: forty per vertical, deterministic, covering every category, decision, flow and window, with observed-only alerts', () => {
  for (const v of ['finance', 'health', 'retail']) assert.equal(MOCK_TABLE.insights[v].length, SEED_COUNT);
  assert.deepEqual(new Set(seed.map((e) => e.category)).has('') && CATEGORY_IDS.every((c) => seed.some((e) => e.category === c)), true);
  assert.deepEqual(new Set(seed.map((e) => e.decision)), new Set(['allow', 'sanitize', 'block', 'alert']));
  assert.deepEqual(new Set(seed.map((e) => e.flow)), new Set(['llm', 'mcp', 'a2a', 'coding_agent']));
  assert.ok(seed.filter((e) => e.ageH < 24).length >= 5 && seed.some((e) => e.ageH > 168 && e.ageH <= 720) && seed.every((e) => e.ageH <= 720));
  const watch = seed.filter((e) => e.observed);
  assert.ok(watch.length >= 3 && watch.every((e) => e.decision === 'allow' && e.category === '' && e.observedRule === 'cst-ticket-ref'), 'an observation changes nothing');
  assert.equal(new Set(seed.map((e) => e.id)).size, SEED_COUNT);
});

test('windows: 24 hours, 7 days and 30 days cut by age; the live view is the newest 25', () => {
  assert.deepEqual(WINDOWS, { live: null, '24h': 24, '7d': 168, '30d': 720 });
  for (const [w, h] of [['24h', 24], ['7d', 168], ['30d', 720]]) { const r = queryInsights(seed, { window: w }, NOW); assert.equal(r.total, seed.filter((e) => e.ageH <= h).length, w); assert.ok(r.events.every((e) => e.ageH <= h)); }
  assert.ok(queryInsights(seed, { window: '24h' }, NOW).total < queryInsights(seed, { window: '7d' }, NOW).total);
  const live = queryInsights(seed, {}, NOW); assert.equal(live.window, 'live'); assert.equal(live.total, LIVE_VIEW);
  assert.deepEqual(live.events.map((e) => e.ageH), [...live.events.map((e) => e.ageH)].sort((a, b) => a - b), 'newest first');
  assert.equal(ageHours({ at: '2026-11-02T10:00:00Z' }, NOW), 2); assert.equal(ageHours({ ageH: 5 }, NOW), 5); assert.equal(ageHours({ at: '2027-01-01T00:00:00Z' }, NOW), 0);
});

for (const f of FILTERS) {
  test(`filter ${f}: each value narrows to exactly the matching events, and facets list the values`, () => {
    const all = queryInsights(seed, { window: '30d' }, NOW);
    const field = { agent: 'agent', app: 'app', category: 'category', decision: 'decision', flow: 'flow', event: 'event' }[f];
    assert.ok(all.facets[f].length >= 2, f);
    for (const v of all.facets[f]) { const r = queryInsights(seed, { window: '30d', [f]: v }, NOW); assert.deepEqual(ids(r), seed.filter((e) => e[field] === v).sort((a, b) => a.ageH - b.ageH).map((e) => e.id).slice(0, MAX_ROWS), `${f}=${v}`); }
    assert.equal(queryInsights(seed, { window: '30d', [f]: 'no-such-value' }, NOW).total, 0);
  });
}

test('filters combine, facets follow the window, and a bad window or a non-string filter is refused', () => {
  const r = queryInsights(seed, { window: '30d', decision: 'block', flow: 'llm' }, NOW);
  assert.ok(r.events.every((e) => e.decision === 'block' && e.flow === 'llm'));
  assert.ok(queryInsights(seed, { window: '24h' }, NOW).facets.agent.length <= queryInsights(seed, { window: '30d' }, NOW).facets.agent.length);
  for (const bad of ['1y', 5, ['24h'], '__proto__']) assert.throws(() => queryInsights(seed, { window: bad }), (e) => e.code === 'bad_window');
  for (const f of FILTERS) { assert.throws(() => queryInsights(seed, { [f]: ['a', 'b'] }), (e) => e.code === 'bad_filter'); assert.throws(() => queryInsights(seed, { [f]: 'x'.repeat(61) }), (e) => e.code === 'bad_filter'); }
});

test('Alerts: observation-only events, listed with the rule and what it would have done, and counted', () => {
  const r = queryInsights(seed, { window: '30d' }, NOW);
  assert.equal(r.alertTotal, seed.filter((e) => e.observed).length);
  assert.ok(r.alerts.every((a) => a.observed && a.observedRule && a.frameworks));
});

test('the cross-reference: every category maps to all four frameworks (lab-illustrative, labelled), and the summary counts findings per label', () => {
  assert.deepEqual(FRAMEWORKS.map((f) => f.id), ['owaspLlm', 'asi', 'atlas', 'nist']);
  for (const c of CATEGORY_IDS) { const m = mappingFor(c); assert.ok(m, c); for (const f of FRAMEWORKS) assert.ok(m[f.id], `${c}.${f.id}`); }
  assert.equal(mappingFor('nope'), null); assert.equal(mappingFor('__proto__'), null); assert.equal(mappingFor(5), null);
  assert.match(COMPLIANCE_NOTE, /not Ping's/); assert.match(COMPLIANCE_NOTE, /verify/);
  const s = complianceSummary([{ category: 'pii' }, { category: 'pii' }, { category: 'jailbreak' }, { category: '' }]);
  assert.equal(s.asi.ASI09, 2); assert.equal(s.asi.ASI01, 1); assert.equal(Object.values(s.owaspLlm).reduce((a, b) => a + b, 0), 3);
  assert.equal(CATEGORY_MAP.memory_poisoning.asi, 'ASI06'); assert.equal(CATEGORY_MAP.tool_poisoning.asi, 'ASI04');
});

test('the API: Mock insights per vertical; Live insights are this workspace\'s own evaluations, newest first, with no text in them', async () => {
  await withServer(async (url) => {
    const m = await (await get(url, '/api/insights?mode=mock&vertical=health&window=30d', { 'x-workspace': 'a' })).json();
    assert.equal(m.total, SEED_COUNT); assert.ok(m.events.every((e) => e.frameworks !== undefined));
    assert.equal((await (await get(url, '/api/insights?mode=live&window=30d', { 'x-workspace': 'a' })).json()).total, 0);
    for (const s of ['secret', 'ordinary', 'contact']) await post(url, '/api/evaluate', { mode: 'live', scenario: s }, { 'x-workspace': 'a' });
    const l = await (await get(url, '/api/insights?mode=live&window=24h', { 'x-workspace': 'a' })).json();
    assert.equal(l.total, 3); assert.deepEqual(l.events.map((e) => e.decision).sort(), ['alert', 'allow', 'block']);
    const e = l.events.find((x) => x.decision === 'block');
    assert.deepEqual([e.category, e.rule, e.flow, e.event, e.direction, e.person, e.agent, e.app], ['secrets', 'lab-openai-style-key', 'coding_agent', 'user_prompt', 'in', 'maya.chen', 'refund-assistant', 'support-portal']);
    assert.ok(!JSON.stringify(l).includes('MOCK') && !JSON.stringify(l).includes('deploy fails'));
    assert.equal((await (await get(url, '/api/insights?mode=live&window=24h&category=secrets', { 'x-workspace': 'a' })).json()).total, 1);
    assert.equal((await (await get(url, '/api/insights?mode=live&window=24h&agent=a&agent=b', { 'x-workspace': 'a' })).json()).error, 'bad_filter');
    assert.equal((await (await get(url, '/api/insights?mode=live&window=2d', { 'x-workspace': 'a' })).json()).error, 'bad_window');
  });
});

test('Live: an observe rule shows up in Alerts with what it would have caught, and promoting it moves it to Guard', async () => {
  await withServer(async (url) => {
    const W = { 'x-workspace': 'a' };
    await post(url, '/api/rules/import', { mode: 'live', toml: "[[rules]]\nid = \"tkt\"\nregex = '''TKT-[0-9]{6}'''\ncategory = \"pii\"\nscore = 0.7\n" }, W);
    const run = () => post(url, '/api/evaluate', { mode: 'live', custom: { text: 'see TKT-123456 please', role: 'user_prompt', surface: 'llm' } }, W);
    await run();
    let r = await (await get(url, '/api/insights?mode=live&window=24h', W)).json();
    assert.deepEqual([r.alertTotal, r.alerts[0].observed, r.alerts[0].observedRule, r.events[0].decision, r.events[0].category], [1, 'sanitize', 'cst-tkt', 'allow', '']);
    await post(url, '/api/rules/enforcement', { id: 'cst-tkt', enforcement: 'enforce' }, W); await run();
    r = await (await get(url, '/api/insights?mode=live&window=24h', W)).json();
    assert.deepEqual([r.alertTotal, r.events[0].decision, r.events[0].rule], [1, 'sanitize', 'cst-tkt']);
  });
});
