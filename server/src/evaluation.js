// The scripted actions and the pieces both modes share. The Mock table is built from this same engine (buildMockTable), so it cannot drift
// from it: a doctor check and a test fail if it does.
import { fill, VERTICALS } from './cast.js';
import { CATEGORY_SAMPLES, RULE_SAMPLES, SCENARIOS, STREAM, materialize } from './data.js';
import { defaultPolicy, inspect, inspectStream } from './guard.js';
import { runSelfCheck } from './selfcheck.js';
import { importToml } from './rules.js';
import { eventFrom } from './insights.js';
import { roleDirection } from './categories.js';

export const scenarioCall = (cast, id) => {
  const scenario = SCENARIOS.find((s) => s.id === id);
  if (!scenario) return null;
  return { scenario, text: materialize(fill(scenario.text, cast)), role: scenario.role, surface: scenario.surface };
};
export const streamFrames = (cast) => STREAM.frames.map((f) => materialize(fill(f, cast)));

// The pasted rule the seeded Insights events watch (observe only).
const SEED_RULE = { rule: { ID: 'cst-ticket-ref', Description: 'A ticket reference (seed)', Category: 'pii', Severity: 'medium', Score: 0.6, OWASP: '', AppliesTo: [], Keywords: ['tkt-'], Pattern: 'TKT-[0-9]{6}', Entropy: 0, Allowlist: [], ValueGroup: 0 }, enforcement: 'observe' };
const mulberry32 = (a) => () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const BUCKETS = [[1, 23], [24, 167], [168, 719]];
export const SEED_COUNT = 40;

// Deterministic seeded events for the Mock Insights view, evaluated by the real engine under the default policy.
export async function seedEvents(cast) {
  const rand = mulberry32(20261102);
  const agents = [cast.castAgent, 'code-assistant', 'research-agent'];
  const apps = [cast.castApp, 'ops-console', 'docs-bot'];
  const people = [cast.castAgentId, 'alex.ng', 'sam.ortiz'];
  const flows = ['llm', 'mcp', 'a2a', 'coding_agent'];
  const cats = Object.keys(CATEGORY_SAMPLES);
  const out = [];
  for (let i = 0; i < SEED_COUNT; i++) {
    let role; let text;
    if (i % 10 === 9) { role = 'user_prompt'; text = 'Ticket reference TKT-482913 is attached.'; } else if (i % 7 === 6) { role = 'user_prompt'; text = i % 14 === 13 ? `Please email the customer at ${cast.castEmail} today.` : 'Summarise the weekly report.'; } else { const s = CATEGORY_SAMPLES[cats[i % cats.length]]; role = s.role; text = materialize(fill(s.text, cast)); }
    const surface = flows[i % 4];
    const evaluation = await inspect(text, { role, surface, policy: defaultPolicy(), rules: [SEED_RULE] });
    const [lo, hi] = BUCKETS[i % 3];
    const ageH = Math.round((lo + rand() * (hi - lo)) * 10) / 10;
    out.push({ ...eventFrom({ id: `seed-${i + 1}`, person: people[(i >> 2) % 3], agent: agents[i % 3], app: apps[(i >> 1) % 3], surface, role, direction: roleDirection(role), evaluation }), ageH });
  }
  return out;
}

export async function buildMockTable() {
  const t = { scenarios: {}, stream: {}, insights: {}, rules: {} };
  for (const [vertical, cast] of Object.entries(VERTICALS)) {
    t.scenarios[vertical] = {};
    for (const s of SCENARIOS) { const c = scenarioCall(cast, s.id); t.scenarios[vertical][s.id] = await inspect(c.text, { role: c.role, surface: c.surface, policy: defaultPolicy(), rules: [] }); }
    t.stream[vertical] = await inspectStream(streamFrames(cast), { role: STREAM.role, surface: STREAM.surface, policy: defaultPolicy(), rules: [] });
    t.insights[vertical] = await seedEvents(cast);
  }
  Object.assign(t, runSelfCheck());
  for (const s of RULE_SAMPLES) { const r = await importToml(s.toml); t.rules[s.id] = { Added: r.Added, Errors: r.Errors }; }
  return t;
}
