// Pasted rules: gitleaks rule format (a TOML subset) -> imodelAIGuardRuleImport { Toml, Added[], Errors[] }.
// One bad rule refuses the WHOLE paste: nothing is added and Errors lists every refused rule, one per line (swagger description, 2026-10-31).
// The TOML key names are a LAB READING of the gitleaks format: id, description, regex, keywords, entropy, secretGroup, [rules.allowlist].regexes,
// plus the lab's own category, severity, score, owasp and appliesTo so a pasted rule can carry the other modelAIGuardCustomRule fields.
// Every regular expression is checked statically (safeRegex.js) and then compiled in a child process; none ever runs in the server process.
import { parseToml, TOML_LIMITS } from './toml.js';
import { checkRegex, splitInlineFlags } from './safeRegex.js';
import { CATEGORY_IDS, SURFACES, isCategory } from './categories.js';
import { cleanText } from './safety.js';
import { looksLikeCredentialId, maskText } from './mask.js';
import { RegexTimeout, sharedRunner } from './regexRunner.js';

export const RULE_LIMITS = { rulesPerWorkspace: 50, keywords: 20, keywordLength: 40, allowlist: 10, description: 200, id: 64 };
export const SEVERITY_SCORE = { low: 0.3, medium: 0.5, high: 0.75, critical: 0.9 };
const ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const KNOWN = ['id', 'description', 'regex', 'keywords', 'entropy', 'secretGroup', 'category', 'severity', 'score', 'owasp', 'appliesTo', 'tags'];

export const tenantRuleId = (id) => (id.startsWith('cst-') ? id : `cst-${id}`); // the swagger text calls a tenant's own rule "cst-..."; the prefix rule is a lab reading

const isStrArray = (v, max) => Array.isArray(v) && v.length <= max && v.every((x) => typeof x === 'string');

// Field checks that need no regular expression. Returns { problems, rule } where rule is the swagger-shaped rule when problems is empty.
function buildRule(raw, n) {
  const f = raw.fields; const problems = [...raw.errors];
  for (const k of Object.keys(f)) if (!KNOWN.includes(k)) problems.push('an unknown key');
  if (typeof f.id !== 'string' || !ID.test(f.id.toLowerCase())) problems.push('id is required: lowercase letters, digits and dashes, up to 64');
  else if (looksLikeCredentialId(f.id.toLowerCase()) || looksLikeCredentialId(`cst-${f.id.toLowerCase()}`)) problems.push('id looks like personal data or a secret: choose a plain name');
  if (typeof f.regex !== 'string') problems.push('regex is required (a string)');
  if (f.description !== undefined && (typeof f.description !== 'string' || f.description.length > RULE_LIMITS.description)) problems.push(`description must be text up to ${RULE_LIMITS.description} characters`);
  if (f.keywords !== undefined && (!isStrArray(f.keywords, RULE_LIMITS.keywords) || f.keywords.some((k) => !k || k.length > RULE_LIMITS.keywordLength))) problems.push(`keywords must be up to ${RULE_LIMITS.keywords} short strings`);
  if (f.entropy !== undefined && (typeof f.entropy !== 'number' || !(f.entropy >= 0 && f.entropy <= 8))) problems.push('entropy must be a number from 0 to 8');
  if (f.secretGroup !== undefined && (!Number.isInteger(f.secretGroup) || f.secretGroup < 0 || f.secretGroup > 9)) problems.push('secretGroup must be a whole number from 0 to 9');
  if (f.category !== undefined && !isCategory(f.category)) problems.push(`category must be one of ${CATEGORY_IDS.join(', ')}`);
  if (f.severity !== undefined && !Object.hasOwn(SEVERITY_SCORE, f.severity)) problems.push('severity must be low, medium, high or critical');
  if (f.score !== undefined && (typeof f.score !== 'number' || !(f.score > 0 && f.score <= 1))) problems.push('score must be a number above 0 and up to 1');
  if (f.owasp !== undefined && (typeof f.owasp !== 'string' || f.owasp.length > 40)) problems.push('owasp must be a short label (up to 40 characters)');
  if (f.appliesTo !== undefined && (!isStrArray(f.appliesTo, SURFACES.length) || f.appliesTo.some((s) => !SURFACES.includes(s)))) problems.push(`appliesTo must list surfaces from ${SURFACES.join(', ')}`);
  if (f.tags !== undefined && !isStrArray(f.tags, 20)) problems.push('tags must be a list of strings');
  const a = raw.allowlist;
  if (a) {
    for (const k of Object.keys(a)) if (k !== 'regexes' && k !== 'description') problems.push('an allowlist key other than regexes is not supported');
    if (a.regexes !== undefined && !isStrArray(a.regexes, RULE_LIMITS.allowlist)) problems.push(`allowlist regexes must be up to ${RULE_LIMITS.allowlist} strings`);
  }
  return { n, problems, f, allow: a?.regexes || [] };
}

// The paste echoed back (the swagger Toml field): only [[rules]] and [rules.allowlist] headers and the known key names are shown as typed; any other
// table or key name is hidden (a bare word cannot be recognised as a secret, so a name nobody asked for is not repeated), and then every value is
// masked as text. A rejected paste is echoed the same way.
const KNOWN_KEYS = new Set([...KNOWN, 'regexes', 'title']);
export function echoToml(toml) {
  if (typeof toml !== 'string') return '';
  const lines = maskText(toml).split('\n').map((line) => { // values first (a keyword may sit in a name, a block may start in a table header)
    if (/^\s*\[/.test(line)) return /^\s*(?:\[\[rules\]\]|\[rules\.allowlist\])\s*(?:#.*)?$/.test(line) ? line : '[masked:table]';
    const m = /^(\s*)([A-Za-z0-9_-]+)(\s*=)/.exec(line);
    if (m && !KNOWN_KEYS.has(m[2])) return `${m[1]}[masked:key] = [masked:value]`; // name and value both: the keyword may be in the name
    // a rule id is repeated only when it is exactly a quoted plain id that does not look like a credential
    const id = /^(\s*id\s*=\s*)(.*)$/.exec(line);
    if (!id) return line;
    const plain = /^(?:"([A-Za-z0-9-]{1,64})"|'([A-Za-z0-9-]{1,64})')\s*(?:#.*)?$/.exec(id[2]);
    return plain && !looksLikeCredentialId((plain[1] ?? plain[2]).toLowerCase()) ? line : `${id[1]}"[masked:id]"`;
  });
  return lines.join('\n');
}

export async function importToml(toml, { existingIds = [], existingCount = 0, runner = sharedRunner, owner } = {}) {
  const out = { Toml: echoToml(toml), Added: [], Errors: [] };
  const parsed = parseToml(toml);
  for (const e of parsed.errors) out.Errors.push(e);
  if (!parsed.rules.length && !out.Errors.length) out.Errors.push('no [[rules]] found in the paste');
  const built = parsed.rules.map((r, i) => buildRule(r, i + 1));
  if (existingCount + built.length > RULE_LIMITS.rulesPerWorkspace) out.Errors.push(`a workspace holds at most ${RULE_LIMITS.rulesPerWorkspace} rules`);
  const seen = new Set(existingIds);
  // The static check first; only patterns that pass it are sent to the child process to compile.
  const toCompile = [];
  for (const b of built) {
    const id = typeof b.f.id === 'string' ? tenantRuleId(b.f.id.toLowerCase()) : null;
    if (id) { if (seen.has(id)) b.problems.push('a rule with this id already exists'); seen.add(id); }
    b.id = id;
    if (typeof b.f.regex === 'string') {
      const why = checkRegex(b.f.regex);
      if (why) b.problems.push(`regex refused: ${why}`); else toCompile.push({ b, kind: 'regex', raw: b.f.regex });
    }
    b.allow.forEach((r, k) => { const why = checkRegex(r); if (why) b.problems.push(`allowlist regex ${k + 1} refused: ${why}`); else toCompile.push({ b, kind: 'allow', raw: r }); });
  }
  if (toCompile.length) {
    try {
      const patterns = toCompile.map((t) => { const s = splitInlineFlags(t.raw); return { source: s.source, flags: s.flags }; });
      const res = await runner.validate(patterns, undefined, owner);
      res.forEach((r, k) => {
        const t = toCompile[k];
        if (!r.ok) t.b.problems.push(`${t.kind === 'regex' ? 'regex' : 'allowlist regex'} ${r.error}`);
        else if (t.kind === 'regex') t.b.groups = r.groups;
      });
    } catch (e) { for (const t of toCompile) t.b.problems.push(e instanceof RegexTimeout ? 'regex check ran out of time (the pattern was stopped)' : e?.code === 'busy' ? 'too many checks are queued for this workspace: try again' : 'regex check failed'); }
  }
  for (const b of built) {
    if (b.f.secretGroup !== undefined && b.groups !== undefined && b.f.secretGroup > b.groups) b.problems.push('secretGroup is higher than the number of groups in the regex');
    if (b.problems.length) out.Errors.push(`rule ${b.n}: ${[...new Set(b.problems)].join('; ')}`);
  }
  if (out.Errors.length) return out; // the whole paste is refused: nothing is added
  out.Added = built.map((b) => {
    const f = b.f; const sp = splitInlineFlags(f.regex);
    const severity = f.severity ?? 'high';
    return {
      ID: b.id, Description: cleanText(maskText(f.description ?? ''), 2 * RULE_LIMITS.description), Category: f.category ?? 'secrets', Severity: severity,
      Score: f.score ?? SEVERITY_SCORE[severity], OWASP: cleanText(maskText(f.owasp ?? ''), 80), AppliesTo: f.appliesTo ?? [], Keywords: (f.keywords ?? []).map((k) => k.toLowerCase()),
      Pattern: f.regex, Entropy: f.entropy ?? 0, Allowlist: b.allow, ValueGroup: f.secretGroup ?? 0, _flags: sp.flags,
    };
  }).map(({ _flags, ...rule }) => rule);
  return out;
}

export { TOML_LIMITS };
