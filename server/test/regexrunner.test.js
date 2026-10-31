import test from 'node:test';
import assert from 'node:assert/strict';
import { RUNNER_LIMITS, RegexTimeout, RunnerBusy, createRegexRunner } from '../src/regexRunner.js';

const job = (id, source, flags = '', group = 0, allow = []) => ({ id, source, flags, group, allow });
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const until = async (fn, ms = 5000) => { for (let i = 0; i < ms / 25 && !fn(); i++) await new Promise((r) => setTimeout(r, 25)); return fn(); };
// Patterns the static check refuses but that, given to the runner directly, the regex engine cannot be interrupted in:
const UNINTERRUPTIBLE = 'a?'.repeat(60) + 'a'.repeat(60); // exponential backtracking inside compile/test, with no nested group

test('an UNINTERRUPTIBLE pattern is killed within the limit, its process is really gone, and no process remains after close (a thread would have kept burning a core)', async () => {
  const r = createRegexRunner({ timeoutMs: 400 });
  try {
    await r.ping(60000);
    const [pid] = r.stats().pids; assert.ok(alive(pid));
    const t0 = Date.now();
    await assert.rejects(r.validate([{ source: UNINTERRUPTIBLE, flags: '' }]), (e) => e instanceof RegexTimeout && e.code === 'timeout');
    assert.ok(Date.now() - t0 < 30000, `took ${Date.now() - t0} ms`);
    assert.ok(await until(() => !alive(pid), 1000), 'the stuck child process is gone within a second of the timeout (the PARENT killed it; the in-child watchdog only fires after a 1.5 s grace)');
    assert.equal(r.stats().killed, 1);
    assert.ok(await until(() => r.stats().exited >= 1));
    // and the same through a scan with a polynomial pattern the engine also cannot be interrupted in
    const [pid2] = (await r.ping(60000), r.stats().pids);
    await assert.rejects(r.scan({ jobs: [job('p', '.*.*.*.*.*.*x')], text: 'a'.repeat(20000) }), RegexTimeout);
    assert.ok(await until(() => !alive(pid2)));
    // the runner still works afterwards, with a fresh child
    assert.deepEqual((await r.scan({ jobs: [job('y', 'ab+')], text: 'xxabbbyy' }, 60000)).matches, [{ id: 'y', start: 2, end: 6 }]);
    assert.equal(r.stats().spawned, 3);
  } finally { await r.close(); }
  assert.deepEqual(r.stats().pids, [], 'no child process remains after close');
});

test('every pid the runner ever started is gone after close (no leaked thread or process)', async () => {
  const r = createRegexRunner({ timeoutMs: 300 }); const seen = new Set();
  try {
    for (let i = 0; i < 3; i++) { await r.ping(60000); r.stats().pids.forEach((p) => seen.add(p)); await assert.rejects(r.validate([{ source: UNINTERRUPTIBLE, flags: '' }]), RegexTimeout); }
    await r.ping(60000); r.stats().pids.forEach((p) => seen.add(p));
  } finally { await r.close(); }
  assert.ok(seen.size >= 4);
  for (const p of seen) assert.ok(await until(() => !alive(p)), `pid ${p} is gone`);
});

test('input is capped before it is sent, matches per rule are capped, group and allowlist are honoured, validate reports group counts and empty matches', async () => {
  const r = createRegexRunner();
  try {
    const big = await r.scan({ jobs: [job('n', 'a')], text: 'a'.repeat(RUNNER_LIMITS.textChars + 5000), maxMatches: 100000 }, 60000);
    assert.equal(big.matches.length, RUNNER_LIMITS.textChars, 'nothing past the 20000 character cap is scanned');
    assert.ok(big.matches.every((m) => m.end <= RUNNER_LIMITS.textChars));
    assert.equal((await r.scan({ jobs: [job('n', 'a')], text: 'a'.repeat(500) }, 60000)).matches.length, 25);
    const g = await r.scan({ jobs: [job('g', 'key=([a-z]+)', '', 1, [{ source: '^skip', flags: '' }])], text: 'key=value key=skipme' }, 60000);
    assert.deepEqual(g.matches, [{ id: 'g', start: 4, end: 9 }]);
    const v = await r.validate([{ source: 'a+', flags: '' }, { source: '(', flags: '' }, { source: 'a*', flags: '' }, { source: '(a)(b)', flags: '' }], 60000);
    assert.deepEqual(v.map((x) => x.ok), [true, false, false, true]);
    assert.match(v[2].error, /empty string/); assert.equal(v[0].groups, 0); assert.equal(v[3].groups, 2);
  } finally { await r.close(); }
});

test('the child has its OWN network guard (all six routes blocked, no real attempt), an empty environment and a capped heap', async () => {
  const r = createRegexRunner();
  try {
    process.env.DPL_TEST_CANARY = 'visible-to-main';
    const g = await r.selftest(60000);
    assert.equal(g.ok, true, g.detail); assert.equal(g.blocked, 6); assert.equal(g.attempts, 0);
    assert.ok(g.env.every((k) => ['NODE_CHANNEL_FD', '__CF_USER_TEXT_ENCODING'].includes(k)), `only the IPC descriptor (and a macOS locale marker) is in its environment: ${g.env}`);
    assert.ok(!g.env.some((k) => /DPL|HOME|PATH|TOKEN|SECRET|KEY/.test(k)));
    assert.ok(g.heapMb >= 80 && g.heapMb <= 200, `heap limit ${g.heapMb} MB`);
    assert.notEqual(g.pid, process.pid);
  } finally { delete process.env.DPL_TEST_CANARY; await r.close(); }
  const src = (await import('node:fs')).readFileSync(new URL('../src/regexRunner.js', import.meta.url), 'utf8');
  assert.match(src, /env: \{\}/); assert.match(src, /--max-old-space-size/);
});

test('one workspace\'s slow rule does not hold up another workspace (per-owner queues on a small pool), and a flood is refused', async () => {
  const r = createRegexRunner({ timeoutMs: 1200, pool: 2, queuePerOwner: 2 });
  try {
    await r.ping(60000);
    const slow = r.scan({ jobs: [job('p', '.*.*.*.*.*.*x')], text: 'a'.repeat(20000) }, 1200, 'ws-a').then(() => 'ok', (e) => e.code);
    await new Promise((res) => setTimeout(res, 80));
    const quick = await r.scan({ jobs: [job('q', 'zz[0-9]+')], text: 'zz123' }, 60000, 'ws-b');
    assert.equal(quick.matches.length, 1);
    assert.equal(await Promise.race([slow, new Promise((res) => setTimeout(() => res('still-running'), 1))]), 'still-running', 'the slow job had not finished when the other workspace was answered');
    assert.equal(await slow, 'timeout');
    // a flood from one owner: running + 2 queued are accepted, the next is refused
    const mk = () => r.scan({ jobs: [job('p', '.*.*.*.*.*.*x')], text: 'a'.repeat(20000) }, 300, 'flood').then(() => 'ok', (e) => e.code);
    const all = await Promise.all([mk(), mk(), mk(), mk(), mk()]);
    assert.ok(all.includes('busy'), JSON.stringify(all));
    assert.ok(new RunnerBusy() instanceof Error);
  } finally { await r.close(); }
});

test('jobs of different owners are served round-robin, not first-come first-served', async () => {
  const r = createRegexRunner({ pool: 1, queuePerOwner: 5 });
  try {
    await r.ping(60000);
    const order = [];
    const go = (owner, n) => r.scan({ jobs: [job('n', 'a')], text: 'a' }, 60000, owner).then(() => order.push(`${owner}${n}`));
    const all = [go('a', 1), go('a', 2), go('a', 3), go('b', 1), go('b', 2)];
    await Promise.all(all);
    assert.ok(order.indexOf('b1') < order.indexOf('a3'), order.join());
  } finally { await r.close(); }
});

test('a closed runner refuses new work', async () => {
  const r = createRegexRunner(); await r.ping(60000); await r.close();
  await assert.rejects(r.ping(), /closed/);
});
