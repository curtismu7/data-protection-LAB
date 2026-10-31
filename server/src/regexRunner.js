// The main-thread side of the regex worker: one lazily started worker, jobs run one at a time, every job has a hard time limit, and a job
// that runs over is killed by terminating the worker (the next job starts a fresh one). Input is capped before it is sent.
import { Worker } from 'node:worker_threads';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const RUNNER_LIMITS = { textChars: 20000, timeoutMs: 4000, maxMatchesPerRule: 25 };
// Path-based (not new URL) so it also loads under the web tests' jsdom, whose URL class is not Node's.
const FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'regexWorker.js');

export class RegexTimeout extends Error { constructor() { super('stopped after the time limit'); this.code = 'timeout'; } }

export function createRegexRunner({ timeoutMs = RUNNER_LIMITS.timeoutMs } = {}) {
  let worker = null; let ready = null; let seq = 0; let queue = Promise.resolve(); let spawned = 0; let killed = 0; let exited = 0;
  const start = () => {
    spawned++;
    // `env: {}` gives the worker an empty environment: nothing from the shared settings file can reach it.
    const w = new Worker(FILE, { env: {}, resourceLimits: { maxOldGenerationSizeMb: 96 } });
    const online = new Promise((resolve, reject) => { w.once('online', resolve); w.once('error', reject); });
    worker = w; ready = online.then(() => w);
    w.once('exit', () => { exited++; if (worker === w) { worker = null; ready = null; } });
    return ready;
  };
  const exec = async (msg, limit) => {
    const w = await (worker ? ready : start());
    const id = ++seq;
    return new Promise((resolve, reject) => {
      const done = (fn, v) => { clearTimeout(timer); w.unref(); w.off('message', onMsg); w.off('error', onErr); fn(v); };
      const timer = setTimeout(() => { killed++; if (worker === w) { worker = null; ready = null; } w.terminate(); done(reject, new RegexTimeout()); }, limit);
      const onMsg = (r) => { if (r.id !== id) return; if (r.ok) done(resolve, r.result); else done(reject, new Error(r.error)); };
      const onErr = () => { if (worker === w) { worker = null; ready = null; } done(reject, new Error('worker failed')); };
      w.ref(); w.on('message', onMsg); w.on('error', onErr);
      w.postMessage({ ...msg, id });
    });
  };
  const run = (msg, limit = timeoutMs) => { const p = queue.then(() => exec(msg, limit)); queue = p.catch(() => {}); return p; };
  return {
    ping: (limit) => run({ type: 'ping' }, limit),
    validate: (patterns, limit) => run({ type: 'validate', patterns }, limit),
    scan: ({ jobs, text, maxMatches = RUNNER_LIMITS.maxMatchesPerRule }, limit) => run({ type: 'scan', jobs, text: String(text).slice(0, RUNNER_LIMITS.textChars), maxMatches }, limit),
    selftest: (limit) => run({ type: 'selftest' }, limit),
    stats: () => ({ spawned, killed, exited, alive: !!worker }),
    async close() { const w = worker; worker = null; ready = null; if (w) await w.terminate(); },
  };
}
export const sharedRunner = createRegexRunner();
