import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

// index.js starts the server at import time, so it cannot be imported in a test. Pin its order instead: the network guard
// is installed before the env file is read, the doctor runs, or any server starts.
test('the entry installs the netguard first, before it can open any socket', () => {
  const src = fs.readFileSync(new URL('../src/index.js', import.meta.url), 'utf8');
  const m = /^installNetguard\(\);/m.exec(src);
  assert.ok(m, 'installNetguard() is called as a statement');
  const guard = m.index;
  for (const later of ['runChecks()', 'startHttpServer({', 'applySharedSettings(']) assert.ok(src.indexOf(later) > guard, `${later} comes after the guard`);
  assert.ok(src.indexOf('import { installNetguard }') < guard);
});

test('the regex worker installs its own netguard before it handles any job', () => {
  const src = fs.readFileSync(new URL('../src/regexWorker.js', import.meta.url), 'utf8');
  assert.match(src, /import \{ installNetguard, netguardSelfTest \} from '\.\/netguard\.js'/);
  assert.ok(src.indexOf('installNetguard()') > 0 && src.indexOf('installNetguard()') < src.indexOf('parentPort.on('));
});

test('no source file builds a regular expression from visitor input, evals, or writes a file', () => {
  const dir = new URL('../src/', import.meta.url);
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.js'))) {
    const code = fs.readFileSync(new URL(f, dir), 'utf8').split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
    assert.ok(!/\beval\(|new Function\(|\bvm\./.test(code), `${f}: no eval, Function or vm`);
    assert.ok(!/writeFile|appendFile|createWriteStream|mkdirSync|rmSync|unlinkSync/.test(code), `${f}: the server writes no file`);
    if (!['regexWorker.js', 'toml.js'].includes(f)) assert.ok(!/new RegExp\(/.test(code.replace(/new RegExp\(d\.pattern|new RegExp\(a, 'i'\)|new RegExp\(re, 'g'\)/g, '')), `${f}: no regular expression is built at run time here`);
  }
});
