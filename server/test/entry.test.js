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

test('the regex child process installs its own netguard before it handles any job', () => {
  const src = fs.readFileSync(new URL('../src/regexChild.js', import.meta.url), 'utf8');
  assert.match(src, /import \{ installNetguard, netguardSelfTest \} from '\.\/netguard\.js'/);
  assert.ok(src.indexOf('installNetguard()') > 0 && src.indexOf('installNetguard()') < src.indexOf("process.on('message'"));
  assert.ok(!/worker_threads|new Worker\(/.test(fs.readFileSync(new URL('../src/regexRunner.js', import.meta.url), 'utf8')), 'no thread: a thread stuck in the regex engine cannot be stopped');
});

test('no source file builds a regular expression from visitor input, evals, or writes a file', () => {
  const dir = new URL('../src/', import.meta.url);
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.js'))) {
    const code = fs.readFileSync(new URL(f, dir), 'utf8').split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
    assert.ok(!/\beval\(|new Function\(|\bvm\./.test(code), `${f}: no eval, Function or vm`);
    assert.ok(!/writeFile|appendFile|createWriteStream|mkdirSync|rmSync|unlinkSync/.test(code), `${f}: the server writes no file`);
    // mask.js builds its detectors once, at load, from constant keyword lists; the interpolations are pinned below.
    if (!['regexChild.js', 'toml.js', 'mask.js'].includes(f)) assert.ok(!/new RegExp\(/.test(code.replace(/new RegExp\(d\.pattern|new RegExp\(a, 'i'\)|new RegExp\(re, 'g'\)/g, '')), `${f}: no regular expression is built at run time here`);
  }
});

test('mask.js is a thin adapter over the shared masker: no regular expression of its own is built, and the shared files name the commit they were copied from', () => {
  const code = fs.readFileSync(new URL('../src/mask.js', import.meta.url), 'utf8').split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
  assert.ok(!/new RegExp\(/.test(code), 'the adapter builds no regular expression at run time');
  assert.match(code, /from '\.\/shared\/mask\.js'/);
  for (const f of ['mask.js', 'hygiene.js']) {
    const head = fs.readFileSync(new URL(`../src/shared/${f}`, import.meta.url), 'utf8').split('\n').slice(0, 2).join(' ');
    assert.match(head, /shared-masker 1\.4\.0, commit 9bc664a/, `${f}: the header names the version and the commit`);
  }
  assert.ok(!/import[^;]*from '(?:\.\.\/){2,}|createRequire|symlink/.test(fs.readFileSync(new URL('../src/app.js', import.meta.url), 'utf8')), 'nothing is imported across repositories');
});
