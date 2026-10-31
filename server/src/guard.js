// The lab's inspection engine. Everything here is LAB-WRITTEN stand-in detection (phrase rules, the checksum-validated personal-data kinds,
// the secret detectors, and pasted rules run in a worker). It is not Ping's rule set. A policy turns finding scores into graduated outcomes:
// allow, alert, sanitize (redact the offending span, forward the rest) or block, with thresholds per category and per-key / per-app overrides.
// Responses never carry a detected value: only the rule, the category, the score, the offsets and a masked display copy of the text.
import { CATEGORIES, DEFAULT_THRESHOLDS, ROLES, THRESHOLD_FIELDS, TIERS, TIER_RANK, isCategory, isRole, isSurface, roleDirection, SURFACES, CATEGORY_IDS } from './categories.js';
import { PII_KIND_IDS, PII_KINDS, detectPii, piiKind } from './pii.js';
import { detectSecrets } from './secrets.js';
import { splitInlineFlags } from './safeRegex.js';
import { shannon } from './secrets.js';
import { RUNNER_LIMITS, RegexTimeout, sharedRunner } from './regexRunner.js';
import { InputError } from './errors.js';

export const GUARD_LIMITS = { text: RUNNER_LIMITS.textChars, frames: 20, frameChars: 2000, carry: 128, keys: 10, apps: 10 };

// ---- built-in phrase rules (lab-written). Patterns are fixed, lowercase, matched on a normalised copy of the text. ----------------------------------
const R = (id, category, score, re, extra = {}) => ({ id, category, score, re: new RegExp(re, 'g'), ...extra });
export const BUILTIN_RULES = [
  R('inj-ignore-previous', 'prompt_injection', 0.75, '\\b(?:ignore|disregard|forget)\\s+(?:all\\s+|any\\s+)?(?:the\\s+)?(?:previous|prior|above|earlier)\\s+(?:instructions?|prompts?|rules?|context)'),
  R('inj-reveal-system-prompt', 'prompt_injection', 0.7, '\\b(?:reveal|show|print|repeat|output)\\s+(?:me\\s+)?(?:your|the)\\s+(?:system\\s+prompt|hidden\\s+instructions?|initial\\s+instructions?)'),
  R('inj-new-instructions', 'prompt_injection', 0.5, '\\b(?:new|updated)\\s+instructions?\\s*:'),
  R('jb-do-anything-now', 'jailbreak', 0.8, '\\bdo\\s+anything\\s+now\\b|\\bdan\\s+mode\\b'),
  R('jb-no-restrictions', 'jailbreak', 0.8, 'pretend\\s+(?:that\\s+)?you\\s+(?:have|are)\\s+no\\s+(?:restrictions|rules|limits|filters)'),
  R('jb-developer-mode', 'jailbreak', 0.7, 'developer\\s+mode\\s+(?:enabled|on)\\b'),
  R('exf-send-to-url', 'data_exfiltration', 0.7, '\\b(?:send|post|upload|forward|email)\\b[^.\\n]{0,80}\\b(?:to|at)\\s+https?://[^\\s]{1,200}'),
  R('exf-markdown-image', 'data_exfiltration', 0.85, '!\\[[^\\]]{0,100}\\]\\(https?://[^)\\s]{0,200}\\?[^)\\s]{0,200}\\)', { roles: ['model_output'] }),
  R('exf-base64-curl', 'data_exfiltration', 0.8, 'base64[^\\n]{0,60}\\|\\s*curl'),
  R('ta-recursive-delete', 'tool_abuse', 0.85, '\\brm\\s+-[a-z]*r[a-z]*f?\\s+(?:/|~)'),
  R('ta-path-traversal', 'tool_abuse', 0.7, '(?:\\.\\.[/\\\\]){2,}'),
  R('ta-cloud-metadata', 'tool_abuse', 0.8, '169\\.254\\.169\\.254|metadata\\.google\\.internal'),
  R('ta-drop-table', 'tool_abuse', 0.7, '\\bdrop\\s+table\\b'),
  R('ia-grant-self', 'inter_agent_abuse', 0.8, '\\b(?:grant|give)\\s+(?:yourself|me)\\s+(?:admin|root|full)\\b', { roles: ['agent_message'] }),
  R('ia-orchestrator-claim', 'inter_agent_abuse', 0.75, '\\bas\\s+(?:the\\s+)?(?:orchestrator|supervisor|main\\s+agent)\\b[^.]{0,60}\\b(?:you\\s+must|override|bypass)', { roles: ['agent_message'] }),
  R('ia-skip-approval', 'inter_agent_abuse', 0.7, 'skip\\s+(?:the\\s+)?(?:human\\s+)?(?:approval|review|confirmation)', { roles: ['agent_message'] }),
  R('tp-important-block', 'tool_poisoning', 0.85, '<important>[\\s\\S]{0,600}</important>', { roles: ['tool_definition'] }),
  R('tp-read-secret-file', 'tool_poisoning', 0.85, '(?:read|cat|open)\\s+[^.\\n]{0,30}(?:~/\\.ssh|id_rsa|\\.aws/credentials|\\.env\\b)', { roles: ['tool_definition'] }),
  R('tp-do-not-tell', 'tool_poisoning', 0.8, 'do\\s+not\\s+(?:tell|mention|reveal)\\s+(?:this\\s+)?(?:to\\s+)?the\\s+user', { roles: ['tool_definition'] }),
  R('mp-standing-order', 'memory_poisoning', 0.75, '\\b(?:from\\s+now\\s+on|always|whenever)\\b[^.\\n]{0,80}\\b(?:send|forward|share|email|exfiltrate)\\b', { roles: ['memory_write'] }),
  R('mp-store-override', 'memory_poisoning', 0.8, '\\b(?:remember|store|save)\\s+(?:that|this)\\b[^.\\n]{0,80}\\b(?:ignore|override|disable|trust)\\b', { roles: ['memory_write'] }),
  R('mc-encoded-powershell', 'malicious_content', 0.85, 'powershell[^\\n]{0,40}-e(?:nc|ncodedcommand)?\\s+[a-za-z0-9+/=]{20,}'),
  R('mc-pipe-to-shell', 'malicious_content', 0.85, '(?:curl|wget)[^\\n|]{0,150}\\|\\s*(?:sudo\\s+)?(?:ba|z)?sh\\b'),
  R('mc-eval-decoded', 'malicious_content', 0.8, 'eval\\s*\\(\\s*(?:atob|base64)'),
];
export const BUILTIN_RULE_IDS = BUILTIN_RULES.map((r) => r.id);
const INDIRECT_BONUS = 0.15; // lab-invented: content the user never typed is scored higher than the same words typed by the user
const HIDDEN_RUN = /[​-‏⁠‪-‮⁦-⁩﻿]+|[\u{e0000}-\u{e007f}]+/gu;
const COMMENT_INSTR = /<!--[^>]{0,400}?(?:ignore|instruction|assistant|do not tell)[^>]{0,400}?-->/gi;
const ZERO_WIDTH = /[​-‏⁠‪-‮⁦-⁩﻿]/;

function normalise(text) {
  const chars = []; const map = []; let space = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ZERO_WIDTH.test(ch)) continue;
    if (/\s/.test(ch)) { if (!space) { chars.push(' '); map.push(i); space = true; } continue; }
    space = false; const lc = ch.toLowerCase(); chars.push(lc.length === 1 ? lc : ch); map.push(i);
  }
  return { norm: chars.join(''), map };
}

function schemaFindings(text, role) {
  if (role !== 'tool_call') return [];
  const t = text.trim(); if (!t.startsWith('{')) return [];
  const all = { start: 0, end: text.length };
  let o; try { o = JSON.parse(t); } catch { return [{ id: 'schema-malformed-json', category: 'schema_violation', score: 0.65, ...all }]; }
  let bad = typeof o.tool !== 'string' || o.arguments === null || typeof o.arguments !== 'object' || Array.isArray(o.arguments);
  if (!bad) {
    if (Object.keys(o.arguments).length > 20 || Object.hasOwn(o.arguments, '__proto__') || Object.hasOwn(o.arguments, 'constructor')) bad = true;
    const stack = [[o.arguments, 1]]; // iterative depth check
    while (!bad && stack.length) { const [v, d] = stack.pop(); if (d > 6) { bad = true; break; } if (v && typeof v === 'object') for (const x of Object.values(v)) if (x && typeof x === 'object') stack.push([x, d + 1]); }
  }
  return bad ? [{ id: 'schema-bad-tool-call', category: 'schema_violation', score: 0.65, ...all }] : [];
}

export function builtinFindings(text, { role, piiKinds }) {
  const out = [];
  const { norm, map } = normalise(text);
  const user = role === 'user_prompt';
  for (const r of BUILTIN_RULES) {
    if (r.roles && !r.roles.includes(role)) continue;
    for (const m of norm.matchAll(r.re)) {
      const start = map[m.index]; const end = map[m.index + m[0].length - 1] + 1;
      const indirect = r.category === 'prompt_injection' && !user;
      out.push({ id: r.id, category: indirect ? 'indirect_injection' : r.category, score: Math.min(1, r.score + (indirect ? INDIRECT_BONUS : 0)), start, end, source: 'builtin' });
    }
  }
  for (const m of text.matchAll(HIDDEN_RUN)) { if (m.index === 0 && m[0] === '﻿') continue; out.push({ id: 'hid-invisible-characters', category: 'hidden_instructions', score: 0.7, start: m.index, end: m.index + m[0].length, source: 'builtin' }); }
  for (const m of text.matchAll(COMMENT_INSTR)) out.push({ id: 'hid-comment-instruction', category: 'hidden_instructions', score: 0.8, start: m.index, end: m.index + m[0].length, source: 'builtin' });
  for (const f of schemaFindings(text, role)) out.push({ ...f, source: 'builtin' });
  for (const f of detectPii(text, piiKinds.length ? piiKinds : null)) out.push({ id: f.kind, category: 'pii', score: piiKind(f.kind).score, start: f.start, end: f.end, source: 'pii' });
  for (const f of detectSecrets(text)) out.push({ id: f.rule, category: 'secrets', score: f.score, start: f.start, end: f.end, source: 'secret' });
  return out;
}

// ---- policy ------------------------------------------------------------------------------------------------------------------------------------
export const defaultPolicy = () => ({ Categories: structuredClone(DEFAULT_THRESHOLDS), PIIKinds: [], Keys: {}, Apps: {} });
const ID = /^[a-z0-9-]{1,40}$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const KIND_OR_RULE = /^(?:pii-[a-z0-9-]{1,40}|cst-[a-z0-9-]{1,60})$/;

function checkCategories(cats, where, errors) {
  const out = {};
  if (!isObj(cats)) { errors.push({ field: `${where}Categories`, message: 'must be an object' }); return out; }
  for (const [id, th] of Object.entries(cats)) {
    if (!isCategory(id)) { errors.push({ field: `${where}Categories`, message: `unknown category ${id.slice(0, 30).replace(/[^\w-]/g, '?')}` }); continue; }
    if (!isObj(th)) { errors.push({ field: `${where}Categories.${id}`, message: 'must be an object' }); continue; }
    const t = {};
    for (const f of THRESHOLD_FIELDS) {
      const v = th[f];
      if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > 1) { errors.push({ field: `${where}Categories.${id}.${f}`, message: 'must be a number from 0 to 1 (0 turns the tier off)' }); continue; }
      t[f] = v;
    }
    if (Object.keys(t).length === 3) {
      const set = [t.AlertThreshold, t.SanitizeThreshold, t.BlockThreshold].filter((x) => x > 0);
      if (set.some((x, i) => i > 0 && x < set[i - 1])) errors.push({ field: `${where}Categories.${id}`, message: 'thresholds that are on must not decrease: alert, then sanitize, then block' });
      out[id] = t;
    }
  }
  return out;
}
function checkKinds(kinds, where, errors) {
  if (!Array.isArray(kinds) || kinds.length > 60 || kinds.some((k) => typeof k !== 'string' || !KIND_OR_RULE.test(k))) { errors.push({ field: `${where}PIIKinds`, message: 'must be a list of detector ids such as pii-ssn (or a cst- rule id)' }); return []; }
  const bad = kinds.filter((k) => k.startsWith('pii-') && !PII_KIND_IDS.includes(k));
  if (bad.length) { errors.push({ field: `${where}PIIKinds`, message: 'unknown personal-data kind' }); return []; }
  return [...new Set(kinds)];
}
function checkOverrides(map, name, errors) {
  const out = {};
  if (!isObj(map)) { errors.push({ field: name, message: 'must be an object' }); return out; }
  const ids = Object.keys(map);
  if (ids.length > GUARD_LIMITS.keys) { errors.push({ field: name, message: `at most ${GUARD_LIMITS.keys} entries` }); return out; }
  for (const id of ids) {
    if (!ID.test(id)) { errors.push({ field: name, message: 'ids are lowercase letters, digits and dashes' }); continue; }
    const o = map[id]; if (!isObj(o)) { errors.push({ field: `${name}.${id}`, message: 'must be an object' }); continue; }
    const e = {};
    if (Object.hasOwn(o, 'Categories')) e.Categories = checkCategories(o.Categories, `${name}.${id}.`, errors);
    if (Object.hasOwn(o, 'PIIKinds')) e.PIIKinds = checkKinds(o.PIIKinds, `${name}.${id}.`, errors);
    out[id] = e;
  }
  return out;
}
// Returns { ok, errors, policy }. A missing field is the default; a wrong-typed one is an error, never a silent default.
export function validatePolicy(p) {
  const errors = []; const out = defaultPolicy();
  if (p === undefined) return { ok: true, errors, policy: out };
  if (!isObj(p)) return { ok: false, errors: [{ field: 'policy', message: 'must be an object' }], policy: out };
  if (Object.hasOwn(p, 'Categories')) Object.assign(out.Categories, checkCategories(p.Categories, '', errors));
  if (Object.hasOwn(p, 'PIIKinds')) out.PIIKinds = checkKinds(p.PIIKinds, '', errors);
  if (Object.hasOwn(p, 'Keys')) out.Keys = checkOverrides(p.Keys, 'Keys', errors);
  if (Object.hasOwn(p, 'Apps')) out.Apps = checkOverrides(p.Apps, 'Apps', errors);
  return { ok: errors.length === 0, errors, policy: out };
}
// Precedence is a LAB READING of "overridden per key or per application": key beats application beats tenant, per category.
export function resolvePolicy(policy, { key, app } = {}) {
  const eff = { Categories: { ...policy.Categories }, PIIKinds: policy.PIIKinds, scope: 'tenant' };
  for (const [kind, id, map] of [['app', app, policy.Apps], ['key', key, policy.Keys]]) {
    if (typeof id !== 'string' || !Object.hasOwn(map, id)) continue;
    const o = map[id]; eff.scope = `${kind}:${id}`;
    if (o.Categories) Object.assign(eff.Categories, o.Categories);
    if (o.PIIKinds) eff.PIIKinds = o.PIIKinds;
  }
  return eff;
}
export function tierFor(score, th) {
  if (th.BlockThreshold > 0 && score >= th.BlockThreshold) return 'block';
  if (th.SanitizeThreshold > 0 && score >= th.SanitizeThreshold) return 'sanitize';
  if (th.AlertThreshold > 0 && score >= th.AlertThreshold) return 'alert';
  return 'allow';
}
const thresholdsOf = (eff, category) => (Object.hasOwn(eff.Categories, category) ? eff.Categories[category] : DEFAULT_THRESHOLDS[category]);

// ---- pasted rules (run in the worker) ------------------------------------------------------------------------------------------------------
async function customFindings(text, { rules, surface, runner }) {
  const out = []; const errors = [];
  const low = text.toLowerCase();
  const live = rules.filter(({ rule }) => (!rule.AppliesTo.length || rule.AppliesTo.includes(surface)) && (!rule.Keywords.length || rule.Keywords.some((k) => low.includes(k))));
  if (!live.length) return { out, errors };
  const jobs = live.map(({ rule }) => { const s = splitInlineFlags(rule.Pattern); return { id: rule.ID, source: s.source, flags: s.flags, group: rule.ValueGroup, allow: rule.Allowlist.map((a) => { const x = splitInlineFlags(a); return { source: x.source, flags: x.flags }; }) }; });
  let res;
  try { res = await runner.scan({ jobs, text }); } catch (e) { errors.push(e instanceof RegexTimeout ? 'a pasted rule was stopped after the time limit and skipped' : 'pasted rules could not run'); return { out, errors }; }
  const byId = new Map(live.map((l) => [l.rule.ID, l]));
  for (const m of res.matches) {
    const { rule, enforcement } = byId.get(m.id);
    if (rule.Entropy > 0 && shannon(text.slice(m.start, m.end)) < rule.Entropy) continue;
    out.push({ id: rule.ID, category: rule.Category, score: rule.Score, start: m.start, end: m.end, source: 'custom', observe: enforcement === 'observe', owasp: rule.OWASP });
  }
  return { out, errors };
}

// ---- inspection ----------------------------------------------------------------------------------------------------------------------------------
function displayFor(text, findings, redactPred, forwarded) {
  const sorted = findings.filter((f) => f.end > f.start).sort((a, b) => a.start - b.start || b.end - a.end);
  const merged = [];
  for (const f of sorted) { const last = merged[merged.length - 1]; if (last && f.start < last.end) { last.end = Math.max(last.end, f.end); last.members.push(f); } else merged.push({ start: f.start, end: f.end, members: [f] }); }
  let out = ''; let at = 0; let redacted = 0;
  for (const s of merged) {
    out += text.slice(at, s.start); at = s.end;
    const top = s.members.reduce((a, b) => (b.score > a.score ? b : a));
    if (forwarded && s.members.some(redactPred)) { out += `[REDACTED:${top.category}]`; redacted++; } else out += `[masked for display:${top.id}]`;
  }
  return { text: out + text.slice(at), redacted };
}

export async function inspect(text, ctx) {
  const { role, surface, policy, rules = [], runner = sharedRunner } = ctx;
  if (typeof text !== 'string') throw new InputError('bad_text', 'text must be a string');
  if (text.length > GUARD_LIMITS.text) throw new InputError('text_too_long', `text is over ${GUARD_LIMITS.text} characters`);
  if (!isRole(role)) throw new InputError('bad_role', 'unknown role');
  if (!isSurface(surface)) throw new InputError('bad_surface', 'unknown surface');
  const eff = ctx.effective || resolvePolicy(policy || defaultPolicy(), ctx.scope);
  let findings = builtinFindings(text, { role, piiKinds: eff.PIIKinds.filter((k) => k.startsWith('pii-')) });
  const custom = await customFindings(text, { rules, surface, runner });
  findings = findings.concat(custom.out);
  // PIIKinds also narrows a tenant's own pii rules (swagger: "pii-ssn, pii-credit-card, a tenant's own cst-... rule").
  if (eff.PIIKinds.length) findings = findings.filter((f) => !(f.source === 'custom' && f.category === 'pii') || eff.PIIKinds.includes(f.id));
  for (const f of findings) { f.tier = tierFor(f.score, thresholdsOf(eff, f.category)); f.length = f.end - f.start; }
  const enforced = findings.filter((f) => !f.observe);
  const cats = new Map();
  for (const f of enforced) {
    const c = cats.get(f.category) || { category: f.category, score: 0, rule: '', rules: [], count: 0 };
    c.count++; if (!c.rules.includes(f.id)) c.rules.push(f.id); if (f.score > c.score) { c.score = f.score; c.rule = f.id; }
    cats.set(f.category, c);
  }
  const categories = [...cats.values()].map((c) => ({ ...c, score: Math.round(c.score * 100) / 100, thresholds: { ...thresholdsOf(eff, c.category) }, tier: tierFor(c.score, thresholdsOf(eff, c.category)) }))
    .sort((a, b) => TIER_RANK[b.tier] - TIER_RANK[a.tier] || b.score - a.score);
  const decision = categories.reduce((d, c) => (TIER_RANK[c.tier] > TIER_RANK[d] ? c.tier : d), 'allow');
  const forwarded = decision !== 'block';
  const sanitizeSpan = (f) => decision === 'sanitize' && !f.observe && thresholdsOf(eff, f.category).SanitizeThreshold > 0 && f.score >= thresholdsOf(eff, f.category).SanitizeThreshold;
  const shown = displayFor(text, findings, sanitizeSpan, forwarded);
  const observed = findings.filter((f) => f.observe && f.tier !== 'allow').map((f) => ({ rule: f.id, category: f.category, score: f.score, wouldHave: f.tier }));
  return {
    decision, forwarded, scope: eff.scope, categories,
    findings: findings.map((f) => ({ rule: f.id, category: f.category, score: Math.round(f.score * 100) / 100, source: f.source, tier: f.tier, observe: !!f.observe, start: f.start, end: f.end, length: f.length })),
    observed, text: shown.text, redactedSpans: shown.redacted, ruleErrors: custom.errors, length: text.length,
  };
}

// Frames of a streamed MCP response, one by one. A flagged (blocked) frame is withheld and the session carries on. The tail of the previous
// frame is carried into the next inspection so a secret split across two frames is still seen; that carry is 128 characters (a lab limit).
export async function inspectStream(frames, ctx) {
  if (!Array.isArray(frames) || frames.length === 0 || frames.length > GUARD_LIMITS.frames || frames.some((f) => typeof f !== 'string' || f.length > GUARD_LIMITS.frameChars)) throw new InputError('bad_frames', `frames must be 1 to ${GUARD_LIMITS.frames} strings of at most ${GUARD_LIMITS.frameChars} characters`);
  const eff = ctx.effective || resolvePolicy(ctx.policy || defaultPolicy(), ctx.scope);
  const out = []; let carry = '';
  const role = ctx.role || 'tool_result';
  for (let i = 0; i < frames.length; i++) {
    const own = await inspect(frames[i], { ...ctx, effective: eff, role });
    let decision = own.decision; let note = '';
    if (carry) {
      // An enforced finding that starts in the carried tail and ends in this frame is a value split across frames.
      const joined = await inspect(carry + frames[i], { ...ctx, effective: eff, role });
      const straddle = joined.findings.filter((f) => !f.observe && f.start < carry.length && f.end > carry.length);
      const tier = straddle.reduce((d, f) => (TIER_RANK[f.tier] > TIER_RANK[d] ? f.tier : d), 'allow');
      if (TIER_RANK[tier] > TIER_RANK[decision]) { decision = tier === 'alert' ? 'alert' : 'block'; note = 'a value split across this frame and the one before'; }
    }
    out.push({ index: i + 1, decision, withheld: decision === 'block', text: decision === 'block' ? '' : own.text, categories: own.categories.map((c) => ({ category: c.category, rule: c.rule, tier: c.tier, score: c.score })), note, redactedSpans: own.redactedSpans });
    carry = frames[i].slice(-GUARD_LIMITS.carry);
  }
  return { frames: out, summary: { total: out.length, withheld: out.filter((f) => f.withheld).length, redacted: out.filter((f) => f.decision === 'sanitize').length, forwarded: out.filter((f) => !f.withheld).length, sessionContinues: true } };
}

export { CATEGORIES, ROLES, TIERS, SURFACES, CATEGORY_IDS, PII_KINDS, roleDirection };
