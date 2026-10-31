// Runs in a worker thread. The ONLY place a visitor-supplied regular expression is compiled or executed. The main thread terminates this
// worker if a job takes too long, so a pattern that gets past the static check (safeRegex.js) still cannot hold the server.
// The worker installs its own netguard (a worker has its own realm, so the main thread's guard does not cover it); nothing here needs a network.
import { parentPort } from 'node:worker_threads';
import { installNetguard, netguardSelfTest } from './netguard.js';

const guard = installNetguard();

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

parentPort.on('message', async (msg) => {
  const { id, type } = msg;
  try {
    if (type === 'ping') parentPort.postMessage({ id, ok: true, result: { guard: true } });
    else if (type === 'validate') parentPort.postMessage({ id, ok: true, result: validate(msg.patterns) });
    else if (type === 'scan') parentPort.postMessage({ id, ok: true, result: scan(msg) });
    else if (type === 'selftest') { const r = await netguardSelfTest(); parentPort.postMessage({ id, ok: true, result: { ...r, attempts: guard.attempts.length } }); } else parentPort.postMessage({ id, ok: false, error: 'unknown job' });
  } catch { parentPort.postMessage({ id, ok: false, error: 'job failed' }); }
});
