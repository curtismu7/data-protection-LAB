import test from 'node:test';
import assert from 'node:assert/strict';
import { RUNNER_LIMITS, RegexTimeout, createRegexRunner } from '../src/regexRunner.js';

const job = (id, source, flags = '', group = 0, allow = []) => ({ id, source, flags, group, allow });

test('a hostile pattern that gets past the static check is TERMINATED within the time limit, and the runner keeps working', async () => {
  const r = createRegexRunner({ timeoutMs: 300 });
  try {
    await r.ping(20000); // warm: worker start-up is not part of the limit
    const t0 = Date.now();
    await assert.rejects(r.scan({ jobs: [job('x', '(a+)+$')], text: `${'a'.repeat(45)}!` }), (e) => e instanceof RegexTimeout && e.code === 'timeout');
    const took = Date.now() - t0;
    assert.ok(took >= 250 && took < 3000, `took ${took} ms`);
    assert.equal(r.stats().killed, 1);
    for (let i = 0; i < 100 && r.stats().exited < 1; i++) await new Promise((res) => setTimeout(res, 50));
    assert.equal(r.stats().exited, 1, 'the runaway worker really exited (it was terminated, not just abandoned)');
    const ok = await r.scan({ jobs: [job('y', 'ab+')], text: 'xxabbbyy' }, 20000);
    assert.deepEqual(ok.matches, [{ id: 'y', start: 2, end: 6 }]);
    assert.equal(r.stats().spawned, 2, 'a fresh worker took over');
  } finally { await r.close(); }
});

test('several different catastrophic shapes are each killed in bounded time', async () => {
  const r = createRegexRunner({ timeoutMs: 250 });
  try {
    await r.ping(20000);
    for (const [src, text] of [['^(\\w+\\s?)*$', `${'word '.repeat(12)}!`], ['(a|aa)+$', `${'a'.repeat(50)}!`], ['(a*)*b', 'a'.repeat(40)], ['(x+x+)+y', 'x'.repeat(45)]]) {
      const t0 = Date.now();
      await assert.rejects(r.scan({ jobs: [job('h', src)], text }), RegexTimeout, src);
      assert.ok(Date.now() - t0 < 3000, src);
    }
  } finally { await r.close(); }
});

test('input is capped before it is sent, matches per rule are capped, group and allowlist are honoured', async () => {
  const r = createRegexRunner();
  try {
    const big = await r.scan({ jobs: [job('n', 'a')], text: 'a'.repeat(RUNNER_LIMITS.textChars + 5000), maxMatches: 1000 }, 20000);
    assert.equal(big.matches.length, 1000);
    assert.ok(big.matches.every((m) => m.end <= RUNNER_LIMITS.textChars), 'nothing past the cap is scanned');
    const capped = await r.scan({ jobs: [job('n', 'a')], text: 'a'.repeat(500) }, 20000);
    assert.equal(capped.matches.length, 25);
    const g = await r.scan({ jobs: [job('g', 'key=([a-z]+)', '', 1, [{ source: '^skip', flags: '' }])], text: 'key=value key=skipme' }, 20000);
    assert.deepEqual(g.matches, [{ id: 'g', start: 4, end: 9 }]);
    const v = await r.validate([{ source: 'a+', flags: '' }, { source: '(', flags: '' }, { source: 'a*', flags: '' }], 20000);
    assert.deepEqual(v.map((x) => x.ok), [true, false, false]);
    assert.match(v[2].error, /empty string/); assert.equal(v[0].groups, 0);
  } finally { await r.close(); }
});

test('the worker has its OWN network guard: it blocks all six routes out and records no real attempt', async () => {
  const r = createRegexRunner();
  try {
    const g = await r.selftest(20000);
    assert.equal(g.ok, true, g.detail);
    assert.equal(g.blocked, 6);
    assert.equal(g.attempts, 0);
  } finally { await r.close(); }
});

test('the worker gets an empty environment: nothing from the shared settings file can reach it', async () => {
  const { Worker } = await import('node:worker_threads');
  process.env.DPL_TEST_CANARY = 'visible-to-main';
  const w = new Worker('const { parentPort } = require("node:worker_threads"); parentPort.postMessage(Object.keys(process.env).length + ":" + (process.env.DPL_TEST_CANARY || "none"));', { eval: true, env: {} });
  const msg = await new Promise((res) => w.once('message', res)); await w.terminate();
  assert.equal(msg, '0:none');
  const src = (await import('node:fs')).readFileSync(new URL('../src/regexRunner.js', import.meta.url), 'utf8');
  assert.match(src, /env: \{\}/);
  delete process.env.DPL_TEST_CANARY;
});
