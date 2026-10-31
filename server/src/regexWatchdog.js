// Runs in a worker thread INSIDE the regex child process: its own thread and isolate, so it keeps running while the child's main thread is stuck
// in the regex engine. It ends the child (SIGKILL) if (1) the parent is gone (the parent pid changed: a stuck child cannot see its own
// 'disconnect' event) or (2) a job has run past its deadline plus a grace period, even if the parent never killed it. This is what guarantees a
// runaway pattern cannot outlive the server that started it. It touches no file and no network.
import { workerData } from 'node:worker_threads';

const deadline = new BigInt64Array(workerData.sab);
const GRACE_MS = 1500;
setInterval(() => {
  if (process.ppid !== workerData.ppid) process.kill(workerData.pid, 'SIGKILL');
  const d = Number(Atomics.load(deadline, 0));
  if (d > 0 && Date.now() > d + GRACE_MS) process.kill(workerData.pid, 'SIGKILL');
}, 100);
