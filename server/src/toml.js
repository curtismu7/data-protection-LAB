// A small BOUNDED parser for the subset of TOML a gitleaks-format rule file uses. No dependency, no eval, iterative (a cursor, no recursion).
// Supported: comments, `[[rules]]`, `[rules.allowlist]`, `title = "..."`, bare keys, basic strings with escapes, literal strings, multi-line
// '''literal''' and """basic""" strings, integers, floats, booleans, arrays of scalars (also over several lines). Everything else is an error.
// One broken rule does not hide the others: the parser resynchronises at the next table header and reports each bad rule once, so the caller
// can refuse the WHOLE paste and list every refused rule, one per line.
export const TOML_LIMITS = { bytes: 65536, rules: 50, string: 2000, array: 50, keysPerRule: 20, lineLength: 4000, lines: 2000 };

class Stop extends Error {}
const KEY = /^[A-Za-z0-9_-]+$/;
const ESC = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' };

export function parseToml(input) {
  const out = { title: null, rules: [], errors: [] };
  if (typeof input !== 'string') { out.errors.push('the paste is not text'); return out; }
  if (input.length > TOML_LIMITS.bytes) { out.errors.push(`the paste is over ${TOML_LIMITS.bytes} characters`); return out; }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(input)) { out.errors.push('the paste contains control characters'); return out; }
  const text = input.replace(/\r\n?/g, '\n').replace(/^﻿/, '');
  const lineCount = text.split('\n').length;
  if (lineCount > TOML_LIMITS.lines) { out.errors.push(`the paste has over ${TOML_LIMITS.lines} lines`); return out; }

  let i = 0; let line = 1; let rule = null; let table = 'root'; let skipping = false;
  const fail = (msg) => { throw new Stop(`line ${line}: ${msg}`); };
  const peek = () => text[i];
  const adv = () => { const c = text[i++]; if (c === '\n') line++; return c; };
  const skipWs = () => { while (i < text.length && (text[i] === ' ' || text[i] === '\t')) i++; };
  const skipLine = () => { while (i < text.length && text[i] !== '\n') i++; };

  const unicode = (e) => {
    const n = e === 'u' ? 4 : 8; const hex = text.slice(i, i + n);
    if (!new RegExp(`^[0-9A-Fa-f]{${n}}$`).test(hex)) fail('bad unicode escape');
    const cp = parseInt(hex, 16); if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) fail('bad unicode escape');
    i += n; return String.fromCodePoint(cp);
  };
  const str = (q) => {
    // single-line string; q is ' or "
    adv(); let s = '';
    for (;;) {
      if (i >= text.length || peek() === '\n') fail('unterminated string');
      const c = adv();
      if (c === q) break;
      if (q === '"' && c === '\\') {
        const e = adv();
        if (e === 'u' || e === 'U') s += unicode(e); else if (Object.hasOwn(ESC, e)) s += ESC[e]; else fail('unknown escape');
      } else s += c;
      if (s.length > TOML_LIMITS.string) fail(`string is over ${TOML_LIMITS.string} characters`);
    }
    return s;
  };
  const multi = (q) => {
    i += 3; if (text[i] === '\n') adv(); let s = '';
    for (;;) {
      if (i >= text.length) fail('unterminated multi-line string');
      if (text.startsWith(q.repeat(3), i)) { i += 3; while (text[i] === q && s.length < TOML_LIMITS.string + 2) { s += q; i++; } break; }
      const c = adv();
      if (q === '"' && c === '\\') {
        const e = adv();
        if (e === '\n') { while (peek() === ' ' || peek() === '\t' || peek() === '\n') adv(); } else if (e === 'u' || e === 'U') s += unicode(e); else if (Object.hasOwn(ESC, e)) s += ESC[e]; else fail('unknown escape in multi-line string');
      } else s += c;
      if (s.length > TOML_LIMITS.string) fail(`string is over ${TOML_LIMITS.string} characters`);
    }
    return s;
  };
  const scalar = () => {
    const c = peek();
    if (c === '"') return text.startsWith('"""', i) ? multi('"') : str('"');
    if (c === "'") return text.startsWith("'''", i) ? multi("'") : str("'");
    const m = /^(true|false|[+-]?\d+(?:\.\d+)?)(?=[\s,\]#]|$)/.exec(text.slice(i, i + 40));
    if (!m) fail('value is not a string, number, boolean or array');
    i += m[0].length;
    return m[1] === 'true' ? true : m[1] === 'false' ? false : Number(m[1]);
  };
  const array = () => {
    adv(); const arr = [];
    for (;;) {
      for (;;) { skipWs(); if (peek() === '#') skipLine(); if (peek() === '\n') adv(); else break; }
      if (i >= text.length) fail('unterminated array');
      if (peek() === ']') { adv(); return arr; }
      if (peek() === '[') fail('nested arrays are not supported');
      if (arr.length >= TOML_LIMITS.array) fail(`array is over ${TOML_LIMITS.array} entries`);
      arr.push(scalar()); skipWs();
      for (;;) { skipWs(); if (peek() === '#') skipLine(); if (peek() === '\n') adv(); else break; }
      if (peek() === ',') adv(); else if (peek() !== ']') fail('expected , or ]');
    }
  };
  const value = () => (peek() === '[' ? array() : scalar());

  const syntaxError = (e) => {
    if (!(e instanceof Stop)) throw e;
    if (rule) { if (!rule.errors.length) rule.errors.push(e.message); rule.broken = true; } else out.errors.push(e.message);
    skipping = true; skipLine();
  };

  while (i < text.length) {
    skipWs();
    const c = peek();
    if (c === undefined) break;
    if (c === '\n') { adv(); continue; }
    if (c === '#') { skipLine(); continue; }
    try {
      if (c === '[') {
        const m = /^(\[\[?)\s*([A-Za-z0-9_.-]+)\s*(\]\]?)\s*(#.*)?$/.exec(text.slice(i, text.indexOf('\n', i) === -1 ? text.length : text.indexOf('\n', i)));
        skipping = false;
        if (!m || m[1].length !== m[3].length) { skipLine(); fail('bad table header'); }
        const name = m[2]; skipLine();
        if (m[1] === '[[' && name === 'rules') {
          if (out.rules.length >= TOML_LIMITS.rules) fail(`more than ${TOML_LIMITS.rules} rules`);
          rule = { line, fields: {}, allowlist: null, errors: [], broken: false }; out.rules.push(rule); table = 'rule';
        } else if (m[1] === '[' && name === 'rules.allowlist') {
          if (!rule) fail('[rules.allowlist] before any [[rules]]');
          if (rule.allowlist) { rule.errors.push(`line ${line}: a rule can have one [rules.allowlist]`); rule.broken = true; skipping = true; } else { rule.allowlist = {}; table = 'allow'; }
        } else {
          if (rule) { rule.errors.push(`line ${line}: table [${m[1] === '[[' ? '[' : ''}${name.slice(0, 40)}${m[1] === '[[' ? ']' : ''}] is not supported (only [[rules]] and [rules.allowlist])`); rule.broken = true; } else out.errors.push(`line ${line}: table [${name.slice(0, 40)}] is not supported (only [[rules]] and [rules.allowlist])`);
          skipping = true;
        }
        continue;
      }
      if (skipping) { skipLine(); continue; }
      // key = value
      const km = /^[A-Za-z0-9_-]+/.exec(text.slice(i, i + 80));
      if (!km || !KEY.test(km[0])) fail('expected a key');
      const key = km[0]; i += key.length; skipWs();
      if (peek() !== '=') fail(`expected = after ${key.slice(0, 30)}`);
      adv(); skipWs();
      if (peek() === '\n' || peek() === undefined) fail(`no value for ${key.slice(0, 30)}`);
      const lineStart = text.lastIndexOf('\n', i) + 1;
      if (i - lineStart > TOML_LIMITS.lineLength) fail('line is too long');
      const v = value(); skipWs();
      if (peek() === '#') skipLine();
      if (peek() !== undefined && peek() !== '\n') fail('unexpected text after the value');
      const target = table === 'root' ? null : table === 'rule' ? rule.fields : rule.allowlist;
      if (table === 'root') { if (key === 'title' && typeof v === 'string') out.title = v.slice(0, 200); else fail(`top-level key ${key.slice(0, 30)} is not supported`); continue; }
      if (Object.hasOwn(target, key)) fail(`${key.slice(0, 30)} is set twice`);
      if (Object.keys(target).length >= TOML_LIMITS.keysPerRule) fail('too many keys in one table');
      target[key] = v;
    } catch (e) { syntaxError(e); }
  }
  return out;
}
