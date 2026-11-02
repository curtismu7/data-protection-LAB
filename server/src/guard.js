// The lab's inspection engine. Everything here is LAB-WRITTEN stand-in detection (phrase rules, the checksum-validated personal-data kinds,
// the secret detectors, and pasted rules run in a child process). It is not Ping's rule set. A policy turns finding scores into graduated outcomes:
// allow, alert, sanitize (redact the offending span, forward the rest) or block, with thresholds per category and per-key / per-app overrides.
// Responses never carry a detected value: only the rule, the category, the score, the offsets and a masked display copy of the text.
import { CATEGORIES, DEFAULT_THRESHOLDS, ROLES, THRESHOLD_FIELDS, TIERS, TIER_RANK, isCategory, isRole, isSurface, roleDirection, SURFACES, CATEGORY_IDS } from './categories.js';
import { PII_KIND_IDS, PII_KINDS, detectPii, piiKind } from './pii.js';
import { detectSecrets } from './secrets.js';
import { splitInlineFlags } from './safeRegex.js';
import { shannon } from './secrets.js';
import { looksLikeCredentialId, maskText, shapeSpans } from './mask.js';
import { RUNNER_LIMITS, RegexTimeout, sharedRunner } from './regexRunner.js';
import { InputError } from './errors.js';
import { mapSpan, normalise } from './normalize.js';

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
  const n = normalise(text, { lower: true }); // case, whitespace runs, zero-width characters and fullwidth forms do not hide a phrase
  const user = role === 'user_prompt';
  for (const r of BUILTIN_RULES) {
    if (r.roles && !r.roles.includes(role)) continue;
    for (const m of n.norm.matchAll(r.re)) {
      const o = mapSpan(n, m.index, m.index + m[0].length);
      const indirect = r.category === 'prompt_injection' && !user;
      out.push({ id: r.id, category: indirect ? 'indirect_injection' : r.category, score: Math.min(1, r.score + (indirect ? INDIRECT_BONUS : 0)), start: o.start, end: o.end, source: 'builtin' });
    }
  }
  for (const m of text.matchAll(HIDDEN_RUN)) { if (m.index === 0 && m[0] === '\ufeff') continue; out.push({ id: 'hid-invisible-characters', category: 'hidden_instructions', score: 0.7, start: m.index, end: m.index + m[0].length, source: 'builtin' }); }
  for (const m of text.matchAll(COMMENT_INSTR)) out.push({ id: 'hid-comment-instruction', category: 'hidden_instructions', score: 0.8, start: m.index, end: m.index + m[0].length, source: 'builtin' });
  for (const f of schemaFindings(text, role)) out.push({ ...f, source: 'builtin' });
  // Every kind is always FOUND (so its value is always masked in the display copy); PIIKinds only decides which ones are SCORED.
  for (const f of detectPii(text, null)) out.push({ id: f.kind, category: 'pii', score: piiKind(f.kind).score, start: f.start, end: f.end, source: 'pii', filtered: piiKinds.length > 0 && !piiKinds.includes(f.kind) });
  // What a person WRITES around a secret ("password hunter2xyz", user:pw@host, {"password":"x"}) is masked in the display copy and in a split stream,
  // but it is not a finding: it adds no category, no score and no decision. The detectors above stay the only thing that is scored.
  // The shared masker's span starts at the keyword ("key is sk-..."). Where a detector of this app marks the value that ends it, and what lies before the value is only
  // a short keyword (no digit, at most 40 characters), the span is left out, so the documented display copy ("The payments gateway key is [masked for display:...]")
  // keeps its keyword. In every other case the whole span is added (more is masked, never less).
  const secrets = detectSecrets(text);
  const marked = [...out.filter((f) => f.source === 'pii'), ...secrets.map((f) => ({ start: f.start, end: f.end }))];
  for (const s of shapeSpans(text)) {
    const keywordOnly = marked.some((k) => k.start > s.start && k.start < s.end && k.end >= s.end && k.start - s.start <= 40 && !/\d/.test(text.slice(s.start, k.start)));
    if (!keywordOnly) out.push({ id: s.id, category: 'secrets', score: 0, start: s.start, end: s.end, source: 'extra', extra: true, shape: true });
  }
  for (const f of secrets) {
    out.push({ id: f.rule, category: 'secrets', score: f.score, start: f.start, end: f.end, source: 'secret' });
    // The detector finds the PEM header; the body after it is the secret, so it is masked in the display copy too (not scored, not a finding).
    if (f.rule === 'lab-private-key-block') {
      const body = /^[\s\S]{0,4000}?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|$)/.exec(text.slice(f.end));
      if (body && body[0].length) out.push({ id: 'private-key-body', category: 'secrets', score: 0, start: f.end, end: f.end + body[0].length, source: 'extra', extra: true });
    }
  }
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
    if (!isCategory(id)) { errors.push({ field: `${where}Categories`, message: 'unknown category' }); continue; }
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
  for (const [i, id] of ids.entries()) {
    const at = `${name}[${i + 1}]`; // the position, never the id the visitor typed
    if (!ID.test(id) || looksLikeCredentialId(id)) { errors.push({ field: name, message: 'ids are plain names: lowercase letters, digits and dashes, not something that looks like personal data or a secret' }); continue; }
    const o = map[id]; if (!isObj(o)) { errors.push({ field: at, message: 'must be an object' }); continue; }
    const e = {};
    if (Object.hasOwn(o, 'Categories')) e.Categories = checkCategories(o.Categories, `${at}.`, errors);
    if (Object.hasOwn(o, 'PIIKinds')) e.PIIKinds = checkKinds(o.PIIKinds, `${at}.`, errors);
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

// ---- pasted rules (run in a child process) -----------------------------------------------------------------------------------------------------
// One job per rule, so a rule that runs out of time is known by name and is QUARANTINED: it is skipped from then on in this workspace and the
// skip is reported. A whole inspection has a time budget, and the runner queues per workspace, so one workspace's slow rule cannot starve another's.
export const CUSTOM_BUDGET_MS = 4000;
async function customFindings(text, { rules, surface, runner, owner, quarantine, budgetMs = CUSTOM_BUDGET_MS }) {
  const out = []; const errors = [];
  const low = text.toLowerCase();
  const live = rules.filter(({ rule }) => (!rule.AppliesTo.length || rule.AppliesTo.includes(surface)) && (!rule.Keywords.length || rule.Keywords.some((k) => low.includes(k))));
  const started = Date.now();
  for (const { rule, enforcement } of live) {
    if (quarantine?.has(rule.ID)) { errors.push(`${rule.ID} is disabled: it ran out of time earlier and is skipped`); continue; }
    const left = budgetMs - (Date.now() - started);
    if (left <= 0) { errors.push(`${rule.ID} was skipped: the time budget for this inspection was used up`); continue; }
    const s = splitInlineFlags(rule.Pattern);
    const job = { id: rule.ID, source: s.source, flags: s.flags, group: rule.ValueGroup, allow: rule.Allowlist.map((a) => { const x = splitInlineFlags(a); return { source: x.source, flags: x.flags }; }) };
    let res;
    try { res = await runner.scan({ jobs: [job], text }, Math.min(left, runner.timeoutMs ?? left), owner); } catch (e) {
      if (e instanceof RegexTimeout) { quarantine?.set(rule.ID, 'timed out'); errors.push(`${rule.ID} ran out of time, was stopped and is now disabled`); } else if (e?.code === 'busy') errors.push(`${rule.ID} was skipped: too many inspections are queued for this workspace`); else errors.push(`${rule.ID} could not run`);
      continue;
    }
    for (const m of res.matches) {
      if (rule.Entropy > 0 && shannon(text.slice(m.start, m.end)) < rule.Entropy) continue;
      out.push({ id: rule.ID, category: rule.Category, score: rule.Score, start: m.start, end: m.end, source: 'custom', observe: enforcement === 'observe', owasp: rule.OWASP });
    }
  }
  return { out, errors };
}

// ---- inspection ----------------------------------------------------------------------------------------------------------------------------------
// The DISPLAY copy masks EVERYTHING any detector found (whatever the policy scores, narrows or observes) plus any extra spans a stream adds.
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
  const all = builtinFindings(text, { role, piiKinds: eff.PIIKinds.filter((k) => k.startsWith('pii-')) });
  const custom = await customFindings(text, { rules, surface, runner, owner: ctx.owner, quarantine: ctx.quarantine, budgetMs: ctx.budgetMs });
  for (const f of custom.out) {
    // PIIKinds also narrows a tenant's own pii rules (swagger: "pii-ssn, pii-credit-card, a tenant's own cst-... rule"): narrowed out = not scored, still masked.
    all.push({ ...f, filtered: f.category === 'pii' && eff.PIIKinds.length > 0 && !eff.PIIKinds.includes(f.id) });
  }
  for (const x of ctx.extraMask || []) all.push({ id: 'split-value', category: 'secrets', score: 0, start: x.start, end: x.end, source: 'extra', extra: true });
  const findings = all.filter((f) => !f.filtered && !f.extra);
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
  const sanitizeSpan = (f) => !f.filtered && !f.extra && !f.observe && decision === 'sanitize' && thresholdsOf(eff, f.category).SanitizeThreshold > 0 && f.score >= thresholdsOf(eff, f.category).SanitizeThreshold;
  const shown = displayFor(text, all, sanitizeSpan, forwarded);
  const observed = findings.filter((f) => f.observe && f.tier !== 'allow').map((f) => ({ rule: f.id, category: f.category, score: f.score, wouldHave: f.tier }));
  const result = {
    decision, forwarded, scope: eff.scope, categories,
    findings: findings.map((f) => ({ rule: f.id, category: f.category, score: Math.round(f.score * 100) / 100, source: f.source, tier: f.tier, observe: !!f.observe, start: f.start, end: f.end, length: f.length })),
    observed, text: maskText(shown.text), redactedSpans: shown.redacted, ruleErrors: custom.errors, length: text.length,
  };
  // Every span any detector found (offsets only), for the stream's split-value masking. Not part of the JSON.
  Object.defineProperty(result, 'spans', { value: all.filter((f) => !f.extra || f.shape).map((f) => ({ start: f.start, end: f.end, id: f.id, shape: !!f.shape })), enumerable: false });
  return result;
}

// Frames of a streamed MCP response, one by one. A flagged (blocked) frame is withheld and the session carries on. A rolling tail of the
// last 128 characters of the WHOLE stream is joined to each frame before inspecting it, so a value split over two, three or many frames is
// seen. The lab forwards frames as they arrive, so the earlier parts of such a value were already forwarded when its last part arrives: the
// frame that completes it is withheld, and the displayed copies of the earlier frames are masked in the response. A value split by more than
// 128 characters is not seen. (A real gateway could hold the tail back; the lab does not.)
export async function inspectStream(frames, ctx) {
  if (!Array.isArray(frames) || frames.length === 0 || frames.length > GUARD_LIMITS.frames || frames.some((f) => typeof f !== 'string' || f.length > GUARD_LIMITS.frameChars)) throw new InputError('bad_frames', `frames must be 1 to ${GUARD_LIMITS.frames} strings of at most ${GUARD_LIMITS.frameChars} characters`);
  const eff = ctx.effective || resolvePolicy(ctx.policy || defaultPolicy(), ctx.scope);
  const role = ctx.role || 'tool_result';
  const base = { ...ctx, effective: eff, role };
  const results = []; const extras = frames.map(() => new Set());
  let tail = ''; let origin = [];
  for (let i = 0; i < frames.length; i++) {
    const own = await inspect(frames[i], base);
    let decision = own.decision; let note = '';
    if (tail) {
      const joined = await inspect(tail + frames[i], base);
      const straddle = joined.findings.filter((f) => !f.observe && f.start < tail.length && f.end > tail.length);
      const tier = straddle.reduce((d, f) => (TIER_RANK[f.tier] > TIER_RANK[d] ? f.tier : d), 'allow');
      if (TIER_RANK[tier] > TIER_RANK[decision]) { decision = tier === 'alert' ? 'alert' : 'block'; note = 'a value split across this frame and the ones before'; }
      // A value split across frames is masked wherever it falls. A credential-shape span ("password" then its value) is masked from the first frame that
      // holds any of it, even when only its value sits in this frame and the keyword sits in the tail.
      for (const sp of joined.spans.filter((x) => x.end > tail.length && (x.shape || x.start < tail.length))) {
        for (let k = sp.start; k < sp.end; k++) { if (k < tail.length) extras[origin[k][0]].add(origin[k][1]); else extras[i].add(k - tail.length); }
      }
    }
    results.push({ own, decision, note });
    origin = origin.concat(Array.from({ length: frames[i].length }, (_, k) => [i, k])).slice(-GUARD_LIMITS.carry);
    tail = (tail + frames[i]).slice(-GUARD_LIMITS.carry);
  }
  // The displayed copy of a frame that holds the early part of a split value is masked there too.
  for (let j = 0; j < frames.length; j++) {
    if (!extras[j].size) continue;
    const offs = [...extras[j]].sort((a, b) => a - b); const spans = [];
    for (const o of offs) { const last = spans[spans.length - 1]; if (last && o === last.end) last.end = o + 1; else spans.push({ start: o, end: o + 1 }); }
    results[j].own = await inspect(frames[j], { ...base, extraMask: spans });
  }
  const out = results.map(({ own, decision, note }, i) => ({ index: i + 1, decision, withheld: decision === 'block', text: decision === 'block' ? '' : own.text, categories: own.categories.map((c) => ({ category: c.category, rule: c.rule, tier: c.tier, score: c.score })), note, redactedSpans: own.redactedSpans }));
  return { frames: out, summary: { total: out.length, withheld: out.filter((f) => f.withheld).length, redacted: out.filter((f) => f.decision === 'sanitize').length, forwarded: out.filter((f) => !f.withheld).length, sessionContinues: true } };
}

export { CATEGORIES, ROLES, TIERS, SURFACES, CATEGORY_IDS, PII_KINDS, roleDirection };
