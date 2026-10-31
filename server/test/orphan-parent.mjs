// Helper for orphans.test.js: a parent that starts a child stuck in an uninterruptible regex, prints the child's pid, and then DIES HARD
// (SIGKILL, no handlers, no 'exit' hook). The child must not outlive it.
import { createRegexRunner } from '../src/regexRunner.js';
const r = createRegexRunner({ timeoutMs: 600000 });
await r.ping(60000);
console.log(`PID ${r.stats().pids[0]}`);
r.validate([{ source: 'a?'.repeat(60) + 'a'.repeat(60), flags: '' }], 600000).catch(() => {});
setTimeout(() => process.kill(process.pid, 'SIGKILL'), 400);
