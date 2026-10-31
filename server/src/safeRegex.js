// Static safety check for a regular expression a visitor pastes (a gitleaks-format rule's `regex` or an allowlist entry). This is the FIRST
// of two guards: a restricted-syntax check here (cheap, conservative, so a hostile pattern is refused before it is ever run), and then the
// pattern only ever runs in a CHILD PROCESS with a hard time limit (SIGKILL), a capped heap and an input cap (regexRunner.js). Neither replaces the other.
// Refused: nested quantifiers, a quantified alternation, backreferences, lookaround, named groups, huge repeat counts, too many variable
// quantifiers, and patterns over the length cap. A leading (?i) (Go syntax, common in gitleaks files) becomes the `i` flag.
export const REGEX_LIMITS = { length: 400, repeat: 100, variable: 6, groups: 12 };

export function splitInlineFlags(source) {
  const m = /^\(\?i\)/.exec(source);
  return m ? { source: source.slice(4), flags: 'i' } : { source, flags: '' };
}

// Returns null when the pattern passes, else a short reason (never the pattern itself).
export function checkRegex(raw) {
  if (typeof raw !== 'string' || raw.length === 0) return 'the regular expression is empty';
  const { source } = splitInlineFlags(raw);
  if (!source) return 'the regular expression is empty';
  if (raw.length > REGEX_LIMITS.length) return `longer than ${REGEX_LIMITS.length} characters`;
  const stack = []; // per open group: { variable, alt }
  let top = { variable: false, alt: false };
  let variable = 0; let groups = 0;
  let lastAtom = null; // what a following quantifier applies to: { group?: {variable, alt}, variable?: bool }
  let i = 0;
  const quant = (min, max) => {
    const repeats = max === Infinity || max > 1;
    if (max !== Infinity && max > REGEX_LIMITS.repeat) return `repeat count over ${REGEX_LIMITS.repeat}`;
    if (min > REGEX_LIMITS.repeat) return `repeat count over ${REGEX_LIMITS.repeat}`;
    // Every quantifier whose count can vary (? * + {n,} {n,m}) counts: a?a?a?...aaa backtracks exponentially without any nested group.
    if ((max === Infinity || max !== min) && ++variable > REGEX_LIMITS.variable) return `more than ${REGEX_LIMITS.variable} variable quantifiers (?, *, +, {n,m})`;
    if (!lastAtom) return 'a quantifier with nothing to repeat';
    if (repeats && lastAtom.group) {
      if (lastAtom.group.variable) return 'nested quantifiers (a repeated group that already repeats)';
      if (lastAtom.group.alt) return 'a repeated group with alternatives';
    }
    if (max === Infinity || max !== min) top.variable = true;
    lastAtom = null; return null;
  };
  while (i < source.length) {
    const c = source[i];
    if (c === '\\') {
      const n = source[i + 1];
      if (n === undefined) return 'a trailing backslash';
      if (/[1-9]/.test(n) || n === 'k') return 'a backreference';
      if (n === 'p' || n === 'P' || n === 'u' && source[i + 2] === '{') return 'a Unicode property or code point escape';
      i += n === 'x' ? 4 : n === 'u' ? 6 : 2; lastAtom = { variable: false }; continue;
    }
    if (c === '[') {
      i++; if (source[i] === '^') i++;
      if (source[i] === ']') i++;
      while (i < source.length && source[i] !== ']') i += source[i] === '\\' ? 2 : 1;
      if (i >= source.length) return 'an unterminated character class';
      i++; lastAtom = { variable: false }; continue;
    }
    if (c === '(') {
      if (source[i + 1] === '?') {
        if (source.startsWith('(?:', i)) i += 3;
        else if (/^\(\?<?[=!]/.test(source.slice(i, i + 4))) return 'lookahead or lookbehind';
        else if (source.startsWith('(?<', i)) return 'a named group';
        else return 'an inline flag or special group';
      } else i++;
      if (++groups > REGEX_LIMITS.groups) return `more than ${REGEX_LIMITS.groups} groups`;
      stack.push(top); top = { variable: false, alt: false }; lastAtom = null; continue;
    }
    if (c === ')') {
      if (!stack.length) return 'an unbalanced parenthesis';
      const inner = top; top = stack.pop();
      if (inner.variable) top.variable = true;
      lastAtom = { group: inner }; i++; continue;
    }
    if (c === '|') { top.alt = true; lastAtom = null; i++; continue; }
    if (c === '*' || c === '+' || c === '?') {
      // `?` after a quantifier is the lazy marker, not a new quantifier
      if (c === '?' && lastAtom === null && /[*+?}]/.test(source[i - 1] || '')) { i++; continue; }
      const r = c === '?' ? quant(0, 1) : quant(c === '+' ? 1 : 0, Infinity); if (r) return r;
      i++; continue;
    }
    if (c === '{') {
      const m = /^\{(\d{1,30})(?:(,)(\d{0,30}))?\}/.exec(source.slice(i, i + 70));
      if (!m) { lastAtom = { variable: false }; i++; continue; } // a literal brace
      const min = Number(m[1]); const max = m[2] ? (m[3] === '' ? Infinity : Number(m[3])) : min;
      if (max !== Infinity && max < min) return 'a repeat count that runs backwards';
      const r = quant(min, max); if (r) return r;
      i += m[0].length; continue;
    }
    lastAtom = { variable: false }; i++;
  }
  if (stack.length) return 'an unbalanced parenthesis';
  return null;
}
