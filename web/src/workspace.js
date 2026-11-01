// Rule 13: each browser tab gets its own workspace id, kept in sessionStorage, and sends it as X-Workspace on every API call
// that touches server state. Storage can be blocked, so a failure falls back to a per-load id.
// The server refuses an id that looks like a credential (24 or more hex characters, a long random run, or a prefix such as sk- or pw-) with
// 400 bad_workspace and never echoes it. So a stored id is checked here first, and a 400 bad_workspace on any call makes the tab pick a NEW id and
// retry that call once: a refused id can never brick the tab. A generated id always starts "w-", so it always contains a letter.
const KEY = "dp.workspace";
let memo = null;

// Tests only: forget the id held in memory so the next call picks a new one.
export const forgetWorkspace = () => { memo = null; };

const SECRET_PREFIX = /^(?:sk|pk|rk|pw|pwd|pass|passwd|password|passphrase|secret|token|tok|bearer|apikey|ghp|gho|ghu|ghs|ghr|glpat|xox[a-z]?|akia|asia|eyj)[-_.]/i;
export const usableWorkspaceId = (id) => typeof id === "string" && /^[a-z0-9-]{1,40}$/.test(id) && /[a-z]/.test(id)
  && !/[0-9a-f]{24,}/i.test(id) && !(/[a-z0-9]{24,}/i.test(id) && /\d/.test(id)) && !SECRET_PREFIX.test(id);

function generate() {
  const bytes = new Uint8Array(8);
  (window.crypto || { getRandomValues: (a) => a.map(() => Math.floor(Math.random() * 256)) }).getRandomValues(bytes);
  return `w-${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

export function workspaceId() {
  if (memo) return memo;
  try { const saved = window.sessionStorage.getItem(KEY); if (usableWorkspaceId(saved)) return (memo = saved); } catch { /* blocked */ }
  memo = generate();
  try { window.sessionStorage.setItem(KEY, memo); } catch { /* blocked */ }
  return memo;
}

// A new id for this tab (the refused one is forgotten, in memory and in storage).
export function renewWorkspace() {
  memo = null;
  try { window.sessionStorage.removeItem(KEY); } catch { /* blocked */ }
  return workspaceId();
}

export async function workspaceFetch(url, opts = {}) {
  const send = () => fetch(url, { ...opts, headers: { "content-type": "application/json", ...(opts.headers || {}), "x-workspace": workspaceId() } });
  const r = await send();
  if (r.status !== 400) return r;
  let body = null;
  try { body = await r.clone().json(); } catch { /* not JSON */ }
  if (body?.error !== "bad_workspace") return r;
  renewWorkspace();
  return send(); // once: a second refusal is returned to the caller as it is
}
