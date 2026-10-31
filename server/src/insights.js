// Agent Insights: Guard (every inspection result), Alerts (observation-only findings) and Prompts, filtered by agent, application, category,
// decision, flow and event, over a live view or a fixed window of 24 hours to 30 days. Pure functions over event metadata; no text is ever in an event.
// flow = the surface (llm, mcp, a2a, coding_agent) and event = the role of the content: a lab reading of the deck's words.
import { InputError } from './errors.js';
import { mappingFor, complianceSummary } from './compliance.js';

export const WINDOWS = { live: null, '24h': 24, '7d': 168, '30d': 720 };
export const FILTERS = ['agent', 'app', 'category', 'decision', 'flow', 'event'];
const FIELD = { agent: 'agent', app: 'app', category: 'category', decision: 'decision', flow: 'flow', event: 'event' };
export const LIVE_VIEW = 25;
export const MAX_ROWS = 100;

export const ageHours = (ev, now) => (typeof ev.ageH === 'number' ? ev.ageH : Math.max(0, (now - Date.parse(ev.at)) / 3.6e6));

export function eventFrom({ id, person, agent, app, surface, role, direction, evaluation, recordId }) {
  const top = evaluation.categories[0];
  const obs = evaluation.observed[0];
  return { id, person, agent, app, flow: surface, event: role, direction, category: top ? top.category : '', rule: top ? top.rule : '', decision: evaluation.decision,
    observed: obs ? obs.wouldHave : '', observedRule: obs ? obs.rule : '', observedCategory: obs ? obs.category : '', ...(recordId ? { recordId } : {}) };
}

export function queryInsights(events, q = {}, now = Date.now()) {
  const win = q.window === undefined || q.window === '' ? 'live' : q.window;
  if (typeof win !== 'string' || !Object.hasOwn(WINDOWS, win)) throw new InputError('bad_window', 'window must be live, 24h, 7d or 30d');
  for (const f of FILTERS) if (q[f] !== undefined && (typeof q[f] !== 'string' || q[f].length > 60)) throw new InputError('bad_filter', `${f} must be a short string`);
  const sorted = [...events].sort((a, b) => ageHours(a, now) - ageHours(b, now));
  const inWindow = win === 'live' ? sorted.slice(0, LIVE_VIEW) : sorted.filter((e) => ageHours(e, now) <= WINDOWS[win]);
  const facets = Object.fromEntries(FILTERS.map((f) => [f, [...new Set(inWindow.map((e) => e[FIELD[f]]).filter((v) => v !== ''))].sort()]));
  const matched = inWindow.filter((e) => FILTERS.every((f) => !q[f] || e[FIELD[f]] === q[f]));
  const rows = matched.slice(0, MAX_ROWS);
  const alerts = matched.filter((e) => e.observed !== '');
  return {
    window: win, windowHours: WINDOWS[win], total: matched.length, shown: rows.length, limit: MAX_ROWS, facets,
    events: rows.map((e) => ({ ...e, frameworks: mappingFor(e.category) })),
    alerts: alerts.slice(0, MAX_ROWS).map((e) => ({ ...e, frameworks: mappingFor(e.observedCategory) })),
    alertTotal: alerts.length, compliance: complianceSummary(matched), recordTotal: matched.filter((e) => e.recordId).length,
  };
}
