import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, fork, spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRegexRunner } from '../src/regexRunner.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const until = async (fn, ms = 15000) => { for (let i = 0; i < ms / 50 && !fn(); i++) await new Promise((r) => setTimeout(r, 50)); return fn(); };
// regexChild.js processes started from THIS repo, with their parent pid (via ps; other sessions' processes are not ours and are not counted)
const REPO = path.resolve(HERE, '..');
const regexChildren = () => execFileSync('ps', ['-axo', 'pid=,ppid=,command=']).toString().split('\n').map((l) => /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(l)).filter((m) => m && m[3].includes(path.join(REPO, 'src', 'regexChild.js'))).map((m) => ({ pid: +m[1], ppid: +m[2] }));
const UNINTERRUPTIBLE = 'a?'.repeat(60) + 'a'.repeat(60);

test('a parent that DIES HARD (SIGKILL, no handlers) cannot leave its stuck child running: the child\'s own watchdog ends it', async () => {
  const p = spawn(process.execPath, [path.join(HERE, 'orphan-parent.mjs')], { stdio: ['ignore', 'pipe', 'ignore'] });
  let out = ''; p.stdout.on('data', (d) => { out += d; });
  const exit = await new Promise((r) => p.once('exit', (code, sig) => r(sig)));
  assert.equal(exit, 'SIGKILL');
  const pid = Number(/PID (\d+)/.exec(out)?.[1]); assert.ok(pid > 0, out);
  assert.ok(await until(() => !alive(pid), 20000), `orphaned child ${pid} is still running`);
});

test('the child\'s watchdog ends a job that outlives its deadline even if the parent never kills it', async () => {
  const c = fork(path.join(REPO, 'src', 'regexChild.js'), [], { env: {}, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  await new Promise((r) => c.once('message', r));
  const gone = new Promise((r) => c.once('exit', (code, sig) => r(sig)));
  c.send({ type: 'validate', id: 1, limit: 300, patterns: [{ source: UNINTERRUPTIBLE, flags: '' }] });
  assert.equal(await Promise.race([gone, new Promise((r) => setTimeout(() => r('still running'), 20000))]), 'SIGKILL');
});

test('Reset cancels a workspace\'s work: its queued jobs are dropped and the child running its job is killed', async () => {
  const r = createRegexRunner({ timeoutMs: 600000, pool: 1 });
  try {
    await r.ping(60000); const [pid] = r.stats().pids;
    const running = r.validate([{ source: UNINTERRUPTIBLE, flags: '' }], 600000, 'ws-x').then(() => 'finished', (e) => e.message);
    const queued = r.validate([{ source: 'a+', flags: '' }], 600000, 'ws-x').then(() => 'finished', (e) => e.message);
    await new Promise((res) => setTimeout(res, 300));
    r.cancel('ws-x');
    assert.equal(await queued, 'cancelled'); assert.match(await running, /child exited|cancelled/);
    assert.ok(await until(() => !alive(pid)), 'the child that was running the cancelled workspace\'s job is gone');
    assert.deepEqual((await r.scan({ jobs: [{ id: 'y', source: 'ab+', flags: '', group: 0, allow: [] }], text: 'xxabbbyy' }, 60000)).matches.length, 1, 'the runner still works');
  } finally { await r.close(); }
});

test('after uninterruptible patterns have run, no regexChild.js process of this repo remains with this test process as its parent', async () => {
  const r = createRegexRunner({ timeoutMs: 300 });
  try {
    await r.ping(60000);
    for (let i = 0; i < 3; i++) await assert.rejects(r.validate([{ source: UNINTERRUPTIBLE, flags: '' }]));
    await r.ping(60000);
  } finally { await r.close(); }
  assert.ok(await until(() => regexChildren().filter((c) => c.ppid === process.pid).length === 0), JSON.stringify(regexChildren()));
});

test('the server\'s children are gone when the server exits: on SIGTERM and on SIGKILL', async () => {
  for (const sig of ['SIGTERM', 'SIGKILL']) {
    const port = sig === 'SIGTERM' ? 7218 : 7219;
    const s = spawn(process.execPath, [path.join(REPO, 'src', 'index.js')], { env: { PORT: String(port), HOME: '/nonexistent', PATH: process.env.PATH }, stdio: ['ignore', 'ignore', 'ignore'] });
    try {
      assert.ok(await until(() => { try { execFileSync('curl', ['-sf', `http://127.0.0.1:${port}/api/health`]); return true; } catch { return false; } }, 60000), 'server started');
      const body = JSON.stringify({ mode: 'live', toml: "[[rules]]\nid = \"a\"\nregex = 'ab+'\n" });
      execFileSync('curl', ['-sf', '-X', 'POST', `http://127.0.0.1:${port}/api/rules/import`, '-H', 'content-type: application/json', '-H', `origin: http://127.0.0.1:${port}`, '-d', body]);
      const kids = regexChildren().filter((c) => c.ppid === s.pid); assert.ok(kids.length >= 1, 'the server started a regex child');
      const dead = new Promise((r) => s.once('exit', r)); s.kill(sig); await dead;
      for (const k of kids) assert.ok(await until(() => !alive(k.pid), 20000), `${sig}: child ${k.pid} of the exited server is still running`);
    } finally { if (s.exitCode === null && !s.killed) s.kill('SIGKILL'); }
  }
});
