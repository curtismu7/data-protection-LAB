// The service layer between the HTTP routes and the engine. Mock returns rows of the generated table; Live runs the real engine.
// Nothing here returns a value a visitor typed that a detector recognises: every echoed string is a masked display copy or a fixed message.
import { randomBytes } from 'node:crypto';
import { InputError } from './errors.js';
import { cleanText } from './safety.js';
import { maskSpans, maskText } from './mask.js';
import { formatTraceparent, newTrace } from './trace.js';
import { GUARD_LIMITS, defaultPolicy, inspect, inspectStream } from './guard.js';
import { isRole, isSurface, roleDirection } from './categories.js';
import { scenarioCall, streamFrames } from './evaluation.js';
import { STREAM } from './data.js';
import { eventFrom, queryInsights } from './insights.js';
import { PL_LIMITS, plaintextFor, skipReason, validatePromptLog } from './promptlog.js';
import { sealRecord } from './seal.js';
import { importToml, RULE_LIMITS } from './rules.js';
import { RULE_SAMPLES } from './data.js';
import { MAX_RULES } from './workspaces.js';

const ID = /^[a-z0-9-]{1,40}$/;
// A free-text label (person, agent, application) is cleaned and then passed through the same inspection as content, pasted rules included,
// so a value a built-in detector or one of the visitor's own rules recognises is masked in it.
// maskFull masks text of any length (in chunks of at most 20000 characters) with the built-in detectors AND the visitor's own rules.
async function maskFull(text, { rules, runner, owner, quarantine }) {
  const t = String(text); let out = '';
  for (let i = 0; i < t.length; i += GUARD_LIMITS.text) {
    const chunk = t.slice(i, i + GUARD_LIMITS.text);
    const r = await inspect(chunk, { role: 'user_prompt', surface: 'llm', policy: defaultPolicy(), rules, runner, owner, quarantine });
    out += maskSpans(chunk, r.findings.filter((f) => f.source !== 'builtin').map((f) => ({ start: f.start, end: f.end, id: f.rule })));
  }
  return maskText(out);
}
// The same, over every string in a structure (iterative).
async function maskDeepFull(value, ctx) {
  const clone = (x) => (Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x);
  const root = { v: clone(value) }; const work = [[value, root, 'v']]; const leaves = [];
  while (work.length) {
    const [src, dst, key] = work.pop();
    if (typeof src === 'string') { leaves.push([dst, key, src]); continue; }
    if (src === null || typeof src !== 'object') { dst[key] = src; continue; }
    const copy = clone(src); dst[key] = copy; for (const k of Object.keys(src).reverse()) work.push([src[k], copy, k]);
  }
  for (const [dst, key, text] of leaves) dst[key] = await maskFull(text, ctx);
  return root.v;
}
const labelOf = async (v, fallback, ctx) => (typeof v !== 'string' || !v.trim() ? fallback : (await maskFull(cleanText(v, 40), ctx)) || fallback);
const scopeOf = (s) => {
  if (s === undefined) return {};
  if (s === null || typeof s !== 'object' || Array.isArray(s)) throw new InputError('bad_scope', 'scope must be an object');
  const out = {};
  for (const k of ['key', 'app']) if (s[k] !== undefined && s[k] !== '') { if (typeof s[k] !== 'string' || !ID.test(s[k]) || maskText(s[k]) !== s[k]) throw new InputError('bad_scope', `${k} must be a plain id: lowercase letters, digits and dashes, and not something that looks like personal data or a secret`); out[k] = s[k]; }
  return out;
};
const hopper = (trace) => { const hops = []; return { hops, add: (label, request, response) => hops.push({ n: hops.length + 1, label, request: { ...request, headers: { traceparent: formatTraceparent(trace.traceId, trace.span()), ...(request.headers || {}) } }, response }) }; };

function customCall(c) {
  if (c === null || typeof c !== 'object' || Array.isArray(c)) throw new InputError('bad_custom', 'custom must be an object');
  if (typeof c.text !== 'string' || !c.text.trim()) throw new InputError('bad_custom', 'text is required');
  if (c.text.length > GUARD_LIMITS.text) throw new InputError('text_too_long', `text is over ${GUARD_LIMITS.text} characters`);
  if (!isRole(c.role)) throw new InputError('bad_role', 'role must be one of the listed roles');
  if (!isSurface(c.surface)) throw new InputError('bad_surface', 'surface must be llm, mcp, a2a or coding_agent');
  if (c.response !== undefined && (typeof c.response !== 'string' || c.response.length > GUARD_LIMITS.text)) throw new InputError('bad_custom', `response must be text up to ${GUARD_LIMITS.text} characters`);
  return { text: c.text, role: c.role, surface: c.surface, response: c.response };
}

export async function evaluateAction({ mode, cast, vertical, scenario, custom, policy, scope, labels = {}, ws, workspaces, table, traceparent, runner }) {
  const trace = newTrace(traceparent);
  const h = hopper(trace);
  let call;
  if (scenario !== undefined) {
    call = typeof scenario === 'string' ? scenarioCall(cast, scenario) : null;
    if (!call) throw new InputError('unknown_scenario', 'unknown scripted action');
  } else if (custom !== undefined) {
    if (mode !== 'live') throw new InputError('needs_live', 'Mock mode only has tables for the scripted actions: switch to Live to try your own text');
    call = customCall(custom);
  } else throw new InputError('no_action', 'give a scenario or a custom action');
  const sc = scopeOf(scope);
  const direction = roleDirection(call.role);
  let evaluation;
  const notes = [];
  if (mode === 'mock') {
    evaluation = structuredClone(table.scenarios[vertical][scenario]);
    notes.push('Mock: a row of the generated table under the default policy. Thresholds, kinds, overrides and pasted rules apply in Live only.');
  } else evaluation = await inspect(call.text, { role: call.role, surface: call.surface, policy, scope: sc, rules: workspaces.rules(ws), runner, owner: ws, quarantine: workspaces.quarantine(ws) });

  const lr = mode === 'live' ? { rules: workspaces.rules(ws), runner, owner: ws, quarantine: workspaces.quarantine(ws) } : { rules: [], runner, owner: ws };
  const person = await labelOf(labels.person, cast.castAgentId, lr); const agent = await labelOf(labels.agent, cast.castAgent, lr); const app = await labelOf(labels.app, cast.castApp, lr);
  h.add('Client to the gateway', { method: 'POST', url: '/api/evaluate', headers: { 'x-workspace': ws }, body: { mode, role: call.role, surface: call.surface, direction, scope: sc, text: evaluation.text } }, { status: 200, note: 'the text is a masked display copy: detected values never leave the engine' });
  h.add('Gateway to the inspection engine', { inspect: { role: call.role, surface: call.surface, length: evaluation.length, scope: evaluation.scope } }, { decision: evaluation.decision, forwarded: evaluation.forwarded, categories: evaluation.categories.map((c) => ({ category: c.category, rule: c.rule, score: c.score, tier: c.tier })), observed: evaluation.observed });

  let record = null; let recordSkipped = null;
  if (mode === 'live') {
    const cfg = workspaces.promptLog(ws); const pk = workspaces.publicKey(ws);
    recordSkipped = skipReason(cfg, pk, call.surface);
    let recordId;
    if (!recordSkipped) {
      const rid = `r-${randomBytes(6).toString('hex')}`;
      const pt = plaintextFor(cfg, call.text, call.response);
      let envelope = null;
      try { envelope = sealRecord({ publicKey: pk, keyId: cfg.KeyID, recordId: rid, plaintext: pt.json }); } catch { recordSkipped = 'sealing failed: check the PublicKey'; }
      if (envelope) {
        recordId = rid;
        const bytes = Buffer.byteLength(pt.json, 'utf8');
        const meta = eventFrom({ id: rid, person, agent, app, surface: call.surface, role: call.role, direction, evaluation, recordId: rid });
        workspaces.addRecord(ws, { ...meta, at: new Date().toISOString(), kid: cfg.KeyID, bytes, truncated: pt.truncated, hasResponse: pt.hasResponse, envelope });
        record = { id: rid, kid: cfg.KeyID, bytes, truncated: pt.truncated, hasResponse: pt.hasResponse };
        h.add('Gateway to the record store (sealed)', { seal: { rid, kid: cfg.KeyID, to: 'the PublicKey you supplied', bytes } }, { stored: 'ciphertext + clear metadata', envelopeFields: Object.keys(envelope) });
      }
    }
    workspaces.addEvent(ws, eventFrom({ id: `ev-${workspaces.nextSeq(ws)}`, person, agent, app, surface: call.surface, role: call.role, direction, evaluation, recordId }));
  }
  return { mode, vertical, scenario: scenario ?? null, role: call.role, surface: call.surface, direction, evaluation, hops: h.hops, traceId: trace.traceId, record, recordSkipped, notes, labels: { person, agent, app } };
}

export async function streamAction({ mode, cast, vertical, scenario, frames, policy, scope, ws, workspaces, table, traceparent, runner }) {
  const trace = newTrace(traceparent); const h = hopper(trace);
  const sc = scopeOf(scope);
  let result; let list;
  if (frames === undefined) {
    if (scenario !== undefined && scenario !== STREAM.id) throw new InputError('unknown_scenario', 'unknown stream');
    list = streamFrames(cast);
    result = mode === 'mock' ? structuredClone(table.stream[vertical]) : await inspectStream(list, { role: STREAM.role, surface: STREAM.surface, policy, scope: sc, rules: workspaces.rules(ws), runner, owner: ws, quarantine: workspaces.quarantine(ws) });
  } else {
    if (mode !== 'live') throw new InputError('needs_live', 'Mock mode only has the scripted stream: switch to Live to try your own frames');
    result = await inspectStream(frames, { role: STREAM.role, surface: STREAM.surface, policy, scope: sc, rules: workspaces.rules(ws), runner, owner: ws, quarantine: workspaces.quarantine(ws) });
    list = frames;
  }
  h.add('Upstream MCP server to the gateway (frames)', { stream: { frames: result.frames.length, chunk: 'one frame at a time' } }, { note: 'each frame is inspected as it arrives' });
  h.add('Gateway to the client (what is forwarded)', { forward: result.frames.map((f) => ({ frame: f.index, decision: f.decision })) }, { summary: result.summary });
  if (mode === 'live') {
    for (const f of result.frames) {
      const top = f.categories[0];
      workspaces.addEvent(ws, eventFrom({ id: `ev-${workspaces.nextSeq(ws)}`, person: cast.castAgentId, agent: cast.castAgent, app: cast.castApp, surface: 'mcp', role: STREAM.role, direction: 'in', evaluation: { categories: top ? [{ category: top.category, rule: top.rule }] : [], decision: f.decision, observed: [] } }));
    }
  }
  return { mode, vertical, ...result, hops: h.hops, traceId: trace.traceId, notes: mode === 'mock' ? ['Mock: the generated table.'] : [] };
}

// ---- pasted rules --------------------------------------------------------------------------------------------------------------------------------
export const rulesView = (ws, workspaces, runner) => {
  const q = workspaces.quarantine(ws);
  return maskDeepFull(workspaces.rules(ws).map(({ rule, enforcement }) => ({ ...rule, enforcement, disabled: q.get(rule.ID) || null })), { rules: workspaces.rules(ws), runner, owner: ws, quarantine: q });
};

export async function importRules({ mode, toml, sample, ws, workspaces, table, runner }) {
  if (mode === 'mock') {
    const s = RULE_SAMPLES.find((x) => x.id === sample);
    if (!s) throw new InputError('needs_live', 'Mock mode only has tables for the three sample pastes: switch to Live to paste your own rules');
    const t = table.rules[s.id];
    return { mode, Toml: s.toml, Added: structuredClone(t.Added), Errors: [...t.Errors], rules: [] };
  }
  if (typeof toml !== 'string') throw new InputError('bad_toml', 'toml must be text');
  // One import at a time per workspace: the duplicate-id and rule-count checks and the add happen together.
  const r = await workspaces.lock(ws, async () => {
    const out = await importToml(toml, { existingIds: workspaces.rules(ws).map((x) => x.rule.ID), existingCount: workspaces.rules(ws).length, runner, owner: ws });
    if (!out.Errors.length) {
      try { workspaces.addRules(ws, out.Added); } catch (e) { out.Errors.push(e.message === 'rule_cap' ? `a workspace holds at most ${RULE_LIMITS.rulesPerWorkspace} rules` : 'a rule with this id already exists'); out.Added = []; }
    }
    return out;
  });
  const q = workspaces.quarantine(ws);
  const ctx = { rules: workspaces.rules(ws), runner, owner: ws, quarantine: q };
  return maskDeepFull({ mode, ...r, rules: workspaces.rules(ws).map(({ rule, enforcement }) => ({ ...rule, enforcement, disabled: q.get(rule.ID) || null })) }, ctx);
}

export function setEnforcement({ ws, workspaces, id, enforcement, runner }) {
  if (typeof id !== 'string' || !/^cst-[a-z0-9-]{1,64}$/.test(id)) throw new InputError('bad_rule', 'id must be a pasted rule id');
  if (enforcement !== 'observe' && enforcement !== 'enforce') throw new InputError('bad_enforcement', 'enforcement must be observe or enforce');
  if (!workspaces.setEnforcement(ws, id, enforcement)) throw new InputError('unknown_rule', 'no such rule in this workspace');
  return rulesView(ws, workspaces, runner).then((rules) => ({ rules }));
}

// ---- prompt logging ---------------------------------------------------------------------------------------------------------------------------------
export function promptLogStatus(config, publicKey) {
  if (!config.Enabled) return { recording: false, why: 'Prompt logging is off (the default): content is not recorded.' };
  if (!publicKey) return { recording: false, why: 'Enabled, but no public key: nothing is recorded without one.' };
  return { recording: true, why: `Recording ${config.Surfaces.length ? config.Surfaces.join(', ') : 'every surface'}${config.IncludeResponses ? ', with responses' : ', prompts only'}, sealed to key ${config.KeyID}. MaxBytes ${config.MaxBytes || PL_LIMITS.defaultMaxBytes} caps the UTF-8 text of the prompt and response; the sealed JSON wrapper ({prompt, response, truncated}) adds a few dozen bytes more, and the record's reported size is that whole JSON.` };
}
export function setPromptLog({ ws, workspaces, config }) {
  const v = validatePromptLog(config);
  if (!v.ok) throw Object.assign(new InputError('bad_config', 'the prompt-log settings were refused'), { errors: v.errors });
  workspaces.setPromptLog(ws, v.config, v.publicKey);
  return { config: v.config, status: promptLogStatus(v.config, v.publicKey), limits: PL_LIMITS };
}
export const getPromptLog = (ws, workspaces) => { const c = workspaces.promptLog(ws); return { config: c, status: promptLogStatus(c, workspaces.publicKey(ws)), limits: PL_LIMITS, recordCount: workspaces.records(ws).length }; };

// ---- insights ---------------------------------------------------------------------------------------------------------------------------------------
const MOCK_ENVELOPE = (i) => ({ v: 'lab-seal/1', kid: 'mock-key', rid: `mock-${i}`, epk: '(mock placeholder)', nonce: '(mock placeholder)', ct: '(mock placeholder: not a real ciphertext and not decryptable)' });
export function insightsView({ mode, vertical, ws, workspaces, table, query, now = Date.now() }) {
  const events = mode === 'mock' ? table.insights[vertical] : workspaces.events(ws);
  const records = mode === 'mock'
    ? table.insights[vertical].filter((e) => e.category !== '' || e.observed !== '').slice(0, 14).map((e, i) => ({ ...e, id: `mock-rec-${i + 1}`, recordId: `mock-rec-${i + 1}`, kid: 'mock-key', bytes: 0, truncated: false, hasResponse: false, mock: true, envelope: MOCK_ENVELOPE(i + 1) }))
    : workspaces.records(ws);
  const qe = queryInsights(events, query, now);
  const qr = queryInsights(records, query, now);
  return { mode, ...qe, records: qr.events, recordTotal: qr.total, recordsShown: qr.shown };
}

export const LIMITS = { ...GUARD_LIMITS, rules: RULE_LIMITS, maxRules: MAX_RULES };
