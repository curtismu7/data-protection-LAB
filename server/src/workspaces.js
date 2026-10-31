// Rule 13: a workspace id keeps one visitor's state apart from another's. Server state per workspace: the Insights events of Live
// evaluations (metadata only, never the text), the sealed prompt records (ciphertext and clear metadata: the server holds no private key),
// the prompt-log settings and the pasted rules. All bounded in count and age. The browser sends its id in X-Workspace (default "default").
import { defaultPromptLog } from './promptlog.js';

export const WORKSPACE_RE = /^[a-z0-9-]{1,40}$/;
export const DEFAULT_WORKSPACE = 'default';
export const MAX_EVENTS = 200;
export const MAX_RECORDS = 100;
export const MAX_RULES = 50;

export function workspaceFrom(req) {
  const raw = req.headers['x-workspace'];
  if (raw === undefined) return DEFAULT_WORKSPACE;
  return typeof raw === 'string' && WORKSPACE_RE.test(raw) ? raw : null;
}

export function createWorkspaces({ max = 500, ttlMs = 60 * 60 * 1000, now = Date.now } = {}) {
  const map = new Map(); // id -> state; insertion order = oldest first
  const locks = new Map(); // per-workspace async mutex tails
  const fresh = () => ({ events: [], records: [], promptLog: defaultPromptLog(), publicKey: null, rules: [], quarantine: new Map(), seq: 0, at: now() });
  const sweep = () => {
    const t = now();
    for (const [id, v] of map) { if (t - v.at > ttlMs) map.delete(id); else break; }
    while (map.size > max) map.delete(map.keys().next().value);
  };
  const touch = (id) => { const v = map.get(id) || fresh(); v.at = now(); map.delete(id); map.set(id, v); sweep(); return v; };
  const peek = (id) => { sweep(); return map.get(id) || fresh(); };
  return {
    events: (id) => peek(id).events,
    records: (id) => peek(id).records,
    promptLog: (id) => peek(id).promptLog,
    publicKey: (id) => peek(id).publicKey,
    rules: (id) => peek(id).rules,
    nextSeq(id) { const v = touch(id); return ++v.seq; },
    addEvent(id, ev) { const v = touch(id); v.events = [...v.events, { ...ev, at: new Date(now()).toISOString() }].slice(-MAX_EVENTS); },
    addRecord(id, rec) { const v = touch(id); v.records = [...v.records, rec].slice(-MAX_RECORDS); },
    setPromptLog(id, config, publicKey) { const v = touch(id); v.promptLog = config; v.publicKey = publicKey; },
    // Throws (so the whole paste is refused) instead of dropping rules or adding a duplicate id.
    addRules(id, rules) {
      const v = touch(id);
      const ids = new Set(v.rules.map((r) => r.rule.ID));
      for (const r of rules) { if (ids.has(r.ID)) throw new Error('duplicate_rule'); ids.add(r.ID); }
      if (v.rules.length + rules.length > MAX_RULES) throw new Error('rule_cap');
      v.rules = [...v.rules, ...rules.map((rule) => ({ rule, enforcement: 'observe' }))];
    },
    quarantine: (id) => touch(id).quarantine,
    // Run fn after every earlier lock holder for this workspace has finished: concurrent imports cannot interleave their check and their add.
    async lock(id, fn) {
      const prev = locks.get(id) || Promise.resolve();
      let release; const mine = new Promise((r) => { release = r; });
      const tail = prev.then(() => mine); locks.set(id, tail);
      await prev;
      try { return await fn(); } finally { release(); if (locks.get(id) === tail) locks.delete(id); }
    },
    setEnforcement(id, ruleId, enforcement) { const v = touch(id); const r = v.rules.find((x) => x.rule.ID === ruleId); if (!r) return false; r.enforcement = enforcement; return true; },
    reset(id) { map.delete(id); },
    size() { return map.size; },
  };
}
