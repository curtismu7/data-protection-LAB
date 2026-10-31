import test from 'node:test';
import assert from 'node:assert/strict';
import { TOML_LIMITS, parseToml } from '../src/toml.js';

test('the gitleaks-shaped subset parses: title, rules, strings of every kind, numbers, arrays over lines, comments, an allowlist table', () => {
  const t = parseToml(`# a comment
title = "My rules"
[[rules]]
id = "one"            # trailing comment
description = 'single'
regex = '''ab+c\\d'''
keywords = [
  "a",   # one
  'b',
]
entropy = 3.5
secretGroup = 1
flag = true
neg = -2
[rules.allowlist]
regexes = ['''^x''', "y\\\\z"]
[[rules]]
id = "two"
regex = """line \\"q\\" \\u0041"""
`);
  assert.deepEqual(t.errors, []);
  assert.equal(t.title, 'My rules');
  assert.equal(t.rules.length, 2);
  const f = t.rules[0].fields;
  assert.deepEqual([f.id, f.description, f.regex, f.keywords, f.entropy, f.secretGroup, f.flag, f.neg], ['one', 'single', 'ab+c\\d', ['a', 'b'], 3.5, 1, true, -2]);
  assert.deepEqual(t.rules[0].allowlist.regexes, ['^x', 'y\\z']);
  assert.equal(t.rules[1].fields.regex, 'line "q" A');
  assert.deepEqual(t.rules.map((r) => r.errors), [[], []]);
});

test('a multi-line literal string keeps backslashes and newlines; a leading newline is dropped', () => {
  const t = parseToml("[[rules]]\nid = \"a\"\nregex = '''\nfoo\\bar\nbaz'''\n");
  assert.equal(t.rules[0].fields.regex, 'foo\\bar\nbaz');
});

test('a bad rule is reported once with its line, the other rules still parse (so the caller can list each refused rule)', () => {
  const t = parseToml(`[[rules]]
id = "good"
regex = 'a'
[[rules]]
id = "broken
regex = 'b'
[[rules]]
id = "good2"
regex = 'c'
[[rules]]
id = 5 5
`);
  assert.equal(t.rules.length, 4);
  assert.deepEqual(t.rules.map((r) => r.errors.length), [0, 1, 0, 1]);
  assert.match(t.rules[1].errors[0], /^line 5: unterminated string/);
  assert.match(t.rules[3].errors[0], /^line 11: unexpected text after the value/);
});

test('hostile TOML is refused with a short message and never throws or hangs', () => {
  const t0 = Date.now();
  const cases = {
    'binary control characters': '[[rules]]\nid = "a\u0000b"\n',
    'too large': `[[rules]]\nid = "${'a'.repeat(TOML_LIMITS.bytes)}"`,
    'string over the limit': `[[rules]]\nid = "x"\nregex = "${'a'.repeat(TOML_LIMITS.string + 1)}"\n`,
    'unterminated multi-line': "[[rules]]\nid = \"x\"\nregex = '''abc\n",
    'nested arrays': '[[rules]]\nid = "x"\nkeywords = [[1],[2]]\n',
    'deeply nested arrays': `[[rules]]\nid = "x"\nkeywords = ${'['.repeat(50000)}`,
    'array too long': `[[rules]]\nid = "x"\nkeywords = [${'"a",'.repeat(TOML_LIMITS.array + 1)}]\n`,
    'unterminated array': '[[rules]]\nid = "x"\nkeywords = ["a",\n',
    'bad escape': '[[rules]]\nid = "\\q"\n',
    'surrogate escape': '[[rules]]\nid = "\\ud800"\n',
    'huge unicode escape': '[[rules]]\nid = "\\U00110000"\n',
    'no value': '[[rules]]\nid =\n',
    'bad header': '[[rules]\nid = "x"\n',
    'inline table value': '[[rules]]\nid = { a = 1 }\n',
    'date value': '[[rules]]\nid = 1979-05-27\n',
    'many empty lines': '\n'.repeat(TOML_LIMITS.lines + 5),
  };
  for (const [name, text] of Object.entries(cases)) {
    const t = parseToml(text);
    const all = [...t.errors, ...t.rules.flatMap((r) => r.errors)];
    assert.ok(all.length > 0, `${name} is refused`);
    assert.ok(all.every((e) => typeof e === 'string' && e.length < 200), name);
  }
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
});

test('limits: more than 50 rules, duplicate keys, too many keys, unsupported tables and top-level keys', () => {
  const many = Array.from({ length: TOML_LIMITS.rules + 1 }, (_, i) => `[[rules]]\nid = "r${i}"\nregex = 'a'\n`).join('');
  const t = parseToml(many);
  assert.ok([...t.errors, ...t.rules.flatMap((r) => r.errors)].some((e) => /more than 50 rules/.test(e)));
  assert.match(parseToml('[[rules]]\nid = "a"\nid = "b"\n').rules[0].errors[0], /set twice/);
  const keys = Array.from({ length: 25 }, (_, i) => `k${i} = 1`).join('\n');
  assert.match(parseToml(`[[rules]]\n${keys}\n`).rules[0].errors[0], /too many keys/);
  assert.match(parseToml('[extend]\nuseDefault = true\n').errors[0], /table \[extend\] is not supported/);
  assert.match(parseToml('x = 1\n').errors[0], /top-level key x is not supported/);
  assert.match(parseToml('[[rules]]\nid = "a"\n[[rules.allowlists]]\nregexes = []\n').rules[0].errors[0], /not supported/);
  assert.match(parseToml('[rules.allowlist]\nregexes = []\n').errors.concat(parseToml('[rules.allowlist]\n').rules.flatMap((r) => r.errors))[0] || '', /before any/);
});

test('input that is not text, and CRLF line endings, are handled', () => {
  assert.match(parseToml(undefined).errors[0], /not text/);
  assert.match(parseToml({}).errors[0], /not text/);
  const t = parseToml('[[rules]]\r\nid = "a"\r\nregex = \'x\'\r\n');
  assert.deepEqual([t.errors, t.rules[0].errors, t.rules[0].fields.id], [[], [], 'a']);
});
