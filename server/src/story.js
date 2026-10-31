import { fillDeep, VERTICALS } from './cast.js';
import { BANNER, CLAIMS, CLAIM_LABEL, FIELD_SOURCES, FIELD_SOURCE_NAMES, INTRO, LIMITS_TEXT, NOT_DEMONSTRATED, RELEASE, RULE_SAMPLES, SCENARIOS, STREAM, TALK_TRACK, TITLE } from './data.js';
import { CATEGORIES, NOT_IMPLEMENTED_CATEGORY, ROLES, SURFACES, TIERS, DEFAULT_THRESHOLDS } from './categories.js';
import { PII_KINDS, SAMPLES as PII_SAMPLES } from './pii.js';
import { SECRET_COUNT_IN_DECK, SECRET_DETECTORS } from './secrets.js';
import { BUILTIN_RULES, GUARD_LIMITS, defaultPolicy } from './guard.js';
import { COMPLIANCE_NOTE, FRAMEWORKS, CATEGORY_MAP } from './compliance.js';
import { OWASP_ROWS, OWASP_STATUS_LABEL } from './owasp.js';
import { PL_LIMITS } from './promptlog.js';
import { RULE_LIMITS } from './rules.js';
import { TOML_LIMITS } from './toml.js';
import { REGEX_LIMITS } from './safeRegex.js';
import { scenarioCall, streamFrames } from './evaluation.js';

export const rawStory = () => ({ title: TITLE, intro: INTRO, banner: BANNER, claims: CLAIMS, scenarios: SCENARIOS, stream: STREAM, talkTrack: TALK_TRACK, ruleSamples: RULE_SAMPLES, owasp: OWASP_ROWS });

// The story with the cast filled in. The scripted texts hold SYNTHETIC personal data and one labelled mock credential, built at run time.
export function buildStory(cast, vertical) {
  const s = fillDeep(rawStory(), cast);
  return {
    title: s.title, intro: s.intro, release: RELEASE, claimLabel: CLAIM_LABEL, banner: s.banner, claims: s.claims, notDemonstrated: NOT_DEMONSTRATED,
    fieldSources: FIELD_SOURCES.map((f) => ({ ...f, sourceLabel: FIELD_SOURCE_NAMES[f.source] })), limitsText: LIMITS_TEXT,
    limits: { guard: GUARD_LIMITS, toml: TOML_LIMITS, regex: REGEX_LIMITS, rules: RULE_LIMITS, promptLog: PL_LIMITS },
    deck: { piiKindsBefore: 5, piiKindsAfter: 23, secretDetectors: SECRET_COUNT_IN_DECK, rules: 411, behavioural: 47 },
    categories: CATEGORIES.map((c) => ({ ...c, defaults: DEFAULT_THRESHOLDS[c.id], frameworks: Object.hasOwn(CATEGORY_MAP, c.id) ? CATEGORY_MAP[c.id] : null })), notImplementedCategory: NOT_IMPLEMENTED_CATEGORY,
    roles: ROLES, surfaces: SURFACES, tiers: TIERS,
    piiKinds: PII_KINDS.map((k) => ({ ...k, sample: PII_SAMPLES[k.id].valid(), nearMiss: PII_SAMPLES[k.id].nearMiss() })),
    secretDetectors: SECRET_DETECTORS.map((d) => ({ id: d.id, description: d.description, keywords: d.keywords, pattern: d.pattern, entropy: d.entropy, allowlist: d.allowlist, valueGroup: d.valueGroup, score: d.score})),
    builtinRules: BUILTIN_RULES.map((r) => ({ id: r.id, category: r.category, score: r.score, roles: r.roles || null })),
    defaultPolicy: defaultPolicy(),
    scenarios: SCENARIOS.map((sc) => { const x = scenarioCall(cast, sc.id); return { id: sc.id, title: sc.title, role: sc.role, surface: sc.surface, expected: sc.expected, lesson: fillDeep(sc.lesson, cast), text: x.text }; }),
    stream: { id: STREAM.id, title: STREAM.title, lesson: STREAM.lesson, surface: STREAM.surface, role: STREAM.role, frames: streamFrames(cast) },
    ruleSamples: s.ruleSamples, owasp: s.owasp, owaspStatusLabel: OWASP_STATUS_LABEL,
    compliance: { note: COMPLIANCE_NOTE, frameworks: FRAMEWORKS },
    scopes: { key: cast.castKey, app: cast.castApp }, labels: { person: cast.castAgentId, agent: cast.castAgent, app: cast.castApp },
    talkTrack: s.talkTrack, cast, vertical, verticals: Object.keys(VERTICALS),
  };
}

// docs/talk-track.md is generated from the same data the UI reads (`npm run talk-track`); a test fails if they drift.
export function renderTalkTrackMarkdown(cast) {
  const s = buildStory(cast, 'finance');
  const parts = ['# Talk track', '', '<!-- Generated from server/src/data.js by `npm run talk-track`. Do not edit by hand. -->', '', `> ${s.claimLabel}: every product claim here comes from the Ping ID4AI Workforce H2 2026 deck, slides 35, 50 and 53 to 55 (release ${s.release}).`, ''];
  for (const t of s.talkTrack) parts.push(`## ${t.title}`, '', t.say, '');
  parts.push('## The seven actions on the Detect tab', '');
  s.scenarios.forEach((sc, i) => parts.push(`${i + 1}. **${sc.title}** (${sc.expected} by the default policy). ${sc.lesson}`));
  parts.push('', '## Not demonstrated', '');
  for (const n of s.notDemonstrated) parts.push(`- ${n}`);
  return `${parts.join('\n')}\n`;
}
