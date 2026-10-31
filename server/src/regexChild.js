// Runs in a CHILD PROCESS (not a thread). The ONLY place a visitor-supplied regular expression is compiled or executed. A runaway pattern in
// a thread cannot be stopped (Worker.terminate cannot interrupt a regex that is stuck in the engine: the thread keeps burning a core), so the
// parent SIGKILLs this process when a job takes too long. It starts with an empty environment and a capped heap, and installs its own netguard
// (a separate process has its own realm, so the parent's guard does not cover it); nothing here needs a network.
import path from 'node:path';
import v8 from 'node:v8';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';
import { installNetguard, netguardSelfTest } from './netguard.js';

const guard = installNetguard();

// The watchdog thread (regexWatchdog.js) kills this process if the parent dies or a job outlives its deadline, even while the main thread is stuck.
const deadline = new BigInt64Array(new SharedArrayBuffer(8));
const dog = new Worker(path.join(path.dirname(fileURLToPath(import.meta.url)), 'regexWatchdog.js'), { workerData: { sab: deadline.buffer, ppid: process.ppid, pid: process.pid }, env: {} });
dog.unref();
const compile = (source, flags) => { try { return { re: new RegExp(source, flags) }; } catch { return { error: 'does not compile as a JavaScript regular expression' }; } };

function validate(patterns) {
  return patterns.map(({ source, flags }) => {
    const c = compile(source, flags);
    if (c.error) return { ok: false, error: c.error };
    if (c.re.test('')) return { ok: false, error: 'matches the empty string' };
    const groups = new RegExp(`${source}|`, flags).exec('').length - 1;
    return { ok: true, groups };
  });
}

function scan({ jobs, text, maxMatches }) {
  const matches = [];
  for (const job of jobs) {
    const c = compile(job.source, `${job.flags}dg`); if (c.error) continue;
    const allow = job.allow.map((a) => compile(a.source, a.flags).re).filter(Boolean);
    let n = 0;
    for (const m of text.matchAll(c.re)) {
      const [s, e] = m.indices[job.group] || m.indices[0] || [m.index, m.index + m[0].length];
      if (e <= s) continue;
      const value = text.slice(s, e);
      if (allow.some((a) => a.test(value))) continue;
      matches.push({ id: job.id, start: s, end: e });
      if (++n >= maxMatches) break;
    }
  }
  return { matches };
}

process.on('message', async (msg) => {
  const { id, type } = msg;
  Atomics.store(deadline, 0, BigInt(Date.now() + (Number.isFinite(msg.limit) ? msg.limit : 5000))); // the watchdog's deadline for this job
  const reply = (m) => { Atomics.store(deadline, 0, 0n); process.send({ id, ...m }); };
  try {
    if (type === 'ping') reply({ ok: true, result: { guard: true, pid: process.pid } });
    else if (type === 'validate') reply({ ok: true, result: validate(msg.patterns) });
    else if (type === 'scan') reply({ ok: true, result: scan(msg) });
    else if (type === 'selftest') { const r = await netguardSelfTest(); reply({ ok: true, result: { ...r, attempts: guard.attempts.length, env: Object.keys(process.env), heapMb: Math.round(v8.getHeapStatistics().heap_size_limit / 1048576), pid: process.pid } }); } else reply({ ok: false, error: 'unknown job' });
  } catch { reply({ ok: false, error: 'job failed' }); }
});
process.on('disconnect', () => process.exit(0)); // the parent went away: do not linger
process.send({ type: 'ready' });
