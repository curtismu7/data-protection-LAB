// The parent side of the regex child processes: a small pool, jobs queued PER OWNER (a workspace) and served round-robin, a hard time limit per
// job, and SIGKILL for a child that runs over (the next job starts a fresh one). An owner has at most one job running and a few queued, so one
// workspace's slow rule cannot hold up another's; beyond that its jobs are refused (code "busy"). Input is capped before it is sent.
// A child is a separate PROCESS because a thread stuck inside the regex engine cannot be stopped.
import { fork } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const RUNNER_LIMITS = { textChars: 20000, timeoutMs: 2000, maxMatchesPerRule: 25, pool: 2, queuePerOwner: 3, heapMb: 96 };
// Path-based (not new URL) so it also loads under the web tests' jsdom, whose URL class is not Node's.
const FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'regexChild.js');

export class RegexTimeout extends Error { constructor() { super('stopped after the time limit'); this.code = 'timeout'; } }
export class RunnerBusy extends Error { constructor() { super('too many jobs are queued for this owner'); this.code = 'busy'; } }

// Every live runner, so one 'exit' hook can SIGKILL every child if the server process ends for any reason (a child stuck in the regex engine
// cannot notice by itself; its watchdog thread is the second line of defence if even this hook does not run, e.g. after a SIGKILL of the parent).
const LIVE = new Set();
let hooked = false;
const killAll = () => { for (const r of LIVE) r.killNow(); };
function hook() {
  if (hooked) return; hooked = true;
  process.on('exit', killAll);
  for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(sig, () => { killAll(); process.exit(sig === 'SIGINT' ? 130 : 143); });
}

export function createRegexRunner({ timeoutMs = RUNNER_LIMITS.timeoutMs, pool = RUNNER_LIMITS.pool, queuePerOwner = RUNNER_LIMITS.queuePerOwner } = {}) {
  const slots = Array.from({ length: pool }, () => ({ child: null, ready: null, busy: false }));
  const queues = new Map(); // owner -> pending jobs
  const running = new Set(); // owners with a job running
  const order = []; // round-robin order of owners
  let seq = 0; let spawned = 0; let killed = 0; let exited = 0; let closed = false;
  const pids = new Set();
  const runningSlot = new Map(); // owner -> slot whose job is running

  const start = (slot) => {
    spawned++;
    // An empty environment, a capped heap, no stdio: nothing from the shared settings file reaches the child.
    const child = fork(FILE, [], { env: {}, execArgv: [`--max-old-space-size=${RUNNER_LIMITS.heapMb}`], stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
    pids.add(child.pid);
    const ready = new Promise((resolve, reject) => { child.once('message', (m) => (m?.type === 'ready' ? resolve(child) : reject(new Error('child did not start')))); child.once('error', reject); child.once('exit', () => reject(new Error('child exited'))); });
    ready.catch(() => {});
    child.once('exit', () => { exited++; pids.delete(child.pid); if (slot.child === child) { slot.child = null; slot.ready = null; } });
    slot.child = child; slot.ready = ready;
    return ready;
  };

  const exec = async (slot, job) => {
    let child;
    try { child = await (slot.child ? slot.ready : start(slot)); } catch { throw new Error('child failed to start'); }
    const id = ++seq;
    return new Promise((resolve, reject) => {
      let timer;
      const done = (fn, v) => { clearTimeout(timer); child.off('message', onMsg); child.off('exit', onExit); child.unref(); child.channel?.unref(); fn(v); };
      const onMsg = (r) => { if (r.id !== id) return; if (r.ok) done(resolve, r.result); else done(reject, new Error(r.error)); };
      const onExit = () => done(reject, new Error('child exited'));
      timer = setTimeout(() => { killed++; if (slot.child === child) { slot.child = null; slot.ready = null; } child.kill('SIGKILL'); done(reject, new RegexTimeout()); }, job.limit);
      child.ref(); child.channel?.ref(); child.on('message', onMsg); child.on('exit', onExit);
      try { child.send({ ...job.msg, id, limit: job.limit }); } catch { done(reject, new Error('child unreachable')); }
    });
  };

  const pump = () => {
    for (const slot of slots) {
      if (slot.busy || closed) continue;
      // the next owner (round-robin) that has work and nothing running
      let picked = null;
      for (let n = 0; n < order.length; n++) { const o = order[n]; if (!running.has(o) && queues.get(o)?.length) { picked = o; order.splice(n, 1); order.push(o); break; } }
      if (picked === null) return;
      const job = queues.get(picked).shift();
      if (!queues.get(picked).length) { queues.delete(picked); order.splice(order.indexOf(picked), 1); }
      slot.busy = true; running.add(picked); runningSlot.set(picked, slot);
      exec(slot, job).then(job.resolve, job.reject).finally(() => { slot.busy = false; running.delete(picked); runningSlot.delete(picked); pump(); });
    }
  };

  const run = (msg, limit = timeoutMs, owner = 'shared') => new Promise((resolve, reject) => {
    if (closed) return reject(new Error('runner closed'));
    const q = queues.get(owner) || [];
    if (q.length >= queuePerOwner) return reject(new RunnerBusy());
    q.push({ msg, limit, resolve, reject });
    if (!queues.has(owner)) { queues.set(owner, q); order.push(owner); }
    pump();
  });
  const killNow = () => { for (const slot of slots) { const c = slot.child; slot.child = null; slot.ready = null; if (c && !c.killed) c.kill('SIGKILL'); } };
  const api = {
    timeoutMs, killNow,
    // Drop an owner's queued jobs and kill the child that is running one of its jobs (a workspace Reset).
    cancel(owner) {
      const q = queues.get(owner);
      if (q) { queues.delete(owner); const i = order.indexOf(owner); if (i >= 0) order.splice(i, 1); for (const j of q) j.reject(new Error('cancelled')); }
      const slot = runningSlot.get(owner);
      if (slot?.child) { const c = slot.child; slot.child = null; slot.ready = null; c.kill('SIGKILL'); }
    },
    ping: (limit, owner) => run({ type: 'ping' }, limit ?? 20000, owner),
    validate: (patterns, limit, owner) => run({ type: 'validate', patterns }, limit, owner),
    scan: ({ jobs, text, maxMatches = RUNNER_LIMITS.maxMatchesPerRule }, limit, owner) => run({ type: 'scan', jobs, text: String(text).slice(0, RUNNER_LIMITS.textChars), maxMatches }, limit, owner),
    selftest: (limit, owner) => run({ type: 'selftest' }, limit ?? 20000, owner),
    stats: () => ({ spawned, killed, exited, alive: slots.filter((s) => s.child).length, pids: [...pids] }),
    async close() {
      closed = true; LIVE.delete(api);
      killNow();
      for (let i = 0; i < 200 && pids.size; i++) await new Promise((r) => setTimeout(r, 20));
    },
  };
  LIVE.add(api); hook();
  return api;
}
export const sharedRunner = createRegexRunner();
