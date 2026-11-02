// One Express app. /api = health, info, story, diagram, selfcheck, evaluate, stream, rules, promptlog, insights and reset. Server state per
// workspace id (X-Workspace) is the Insights events, the sealed records, the prompt-log settings and the pasted rules, so one visitor's Reset
// never touches another's. Both modes are loopback-only with zero outbound calls. Loopback Host check and same-origin writes on everything.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { hostCheck, sameOriginWrites } from './safety.js';
import { createHealth } from './health.js';
import { loadCast, verticalFrom } from './cast.js';
import { defaultMode, modeOf } from './config.js';
import { buildStory } from './story.js';
import { DIAGRAM_NAMES, buildDiagram } from './diagramData.js';
import { InputError } from './errors.js';
import { maskDeep } from './mask.js';
import { buildMethodTable, charsetProblem, isPageAddress, methodNotAllowed } from './shared/hygiene.js';
import { MOCK_TABLE } from './mockTable.js';
import { createWorkspaces, workspaceFrom } from './workspaces.js';
import { validatePolicy } from './guard.js';
import { evaluateAction, getPromptLog, importRules, insightsView, rulesView, setEnforcement, setPromptLog, streamAction } from './service.js';
import { runSelfCheck, selfCheckOk } from './selfcheck.js';
import { sharedRunner } from './regexRunner.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB_DIST = process.env.WEB_DIST || path.resolve(HERE, '../../web/dist');
const CONFIG = process.env.CUSTOMER_CONFIG || path.resolve(HERE, '../../customer.config.json');
const BIG = new Set(['/evaluate', '/stream', '/rules/import']);
// Every known API route and the methods it answers, in ONE table. A known path with another method is 405 with an Allow header (HEAD wherever GET is), before any
// body is read; any other path is the final JSON 404. The same table is what the 405 tests and mutants read.
export const ROUTES = { '/api/health': ['GET'], '/api/story': ['GET'], '/api/diagram': ['GET'], '/api/info': ['GET'], '/api/selfcheck': ['GET'], '/api/evaluate': ['POST'], '/api/stream': ['POST'], '/api/rules': ['GET'],
  '/api/rules/import': ['POST'], '/api/rules/enforcement': ['POST'], '/api/promptlog': ['GET'], '/api/promptlog/config': ['POST'], '/api/insights': ['GET'], '/api/reset': ['POST'] };
const METHODS = buildMethodTable(ROUTES);
// Static, scripted answers: the story shows the labelled sk-MOCK- credential on purpose (rule 4), so these are the only answers not passed through the response mask.
const UNMASKED = new Set(['/story', '/diagram', '/info', '/selfcheck']);

export function createApp({ health = createHealth(), configFile = CONFIG, workspaces = createWorkspaces(), table = MOCK_TABLE, runner = sharedRunner } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(hostCheck);
  app.use(sameOriginWrites);
  app.use((_req, res, next) => { res.set('X-Content-Type-Options', 'nosniff'); next(); });
  // A charset other than utf-8 is 415 with a fixed body: the value is never read into the answer, and nothing typed is logged.
  app.use((req, res, next) => (charsetProblem(req.headers['content-type']) ? res.status(415).json({ error: 'unsupported_charset' }) : next()));
  // A known API path with a method its table entry does not list is 405 with Allow, before the body is parsed.
  app.use('/api', (req, res, next) => {
    const miss = methodNotAllowed(METHODS, req.method, `/api${req.path}`);
    return miss ? res.set('Allow', miss.allow.join(', ')).status(405).json({ error: 'method_not_allowed' }) : next();
  });

  const api = express.Router();
  // 20000 characters can be 120 KB once JSON-escaped; a rule paste is up to 65536 characters.
  api.use((req, res, next) => express.json({ limit: BIG.has(req.path) ? '400kb' : '32kb' })(req, res, next));
  // Defence in depth: every other answer passes through the response mask, so a credential-shaped value cannot leave in any field or object KEY.
  api.use((req, res, next) => { if (!UNMASKED.has(req.path) && !req.path.startsWith('/health')) { const send = res.json.bind(res); res.json = (b) => send(maskDeep(b)); } next(); });
  api.use('/health', health.router);
  const verticalOf = (req) => verticalFrom(req.body?.vertical ?? req.query.vertical);
  const castFor = (req) => loadCast(configFile, verticalOf(req));
  const noStore = (res) => res.set('Cache-Control', 'no-store');
  api.get('/story', (req, res) => { noStore(res); res.json(buildStory(castFor(req), verticalOf(req))); });
  api.get('/diagram', (req, res) => { noStore(res); res.json(buildDiagram(castFor(req), DIAGRAM_NAMES.includes(req.query.name) ? req.query.name : 'inspection-flow')); });
  api.get('/info', (_req, res) => { noStore(res); res.json({ mode: defaultMode(), modes: ['mock', 'live'], simulated: true, release: '2026-11-02', unverified: true }); });

  // The workspace id is checked BEFORE any state is touched: a credential-looking or malformed id is 400 bad_workspace and is never echoed or stored.
  const workspace = (req, res, next) => { const id = workspaceFrom(req); if (!id) return res.status(400).json({ error: 'bad_workspace' }); req.workspaceId = id; return next(); };
  const failure = (res, next) => (e) => { if (e instanceof InputError) return res.status(400).json({ error: e.code, detail: e.message, ...(e.errors ? { errors: e.errors } : {}) }); return next(e); };
  const objectBody = (req) => req.body !== null && typeof req.body === 'object' && !Array.isArray(req.body);
  const modeFor = (v) => modeOf(v);
  const policyFor = (raw) => { const v = validatePolicy(raw); if (!v.ok) throw Object.assign(new InputError('bad_policy', 'the policy was refused'), { errors: v.errors }); return v.policy; };

  // What each kind and detector does with its valid sample and its near miss (Live: computed now; Mock: the generated table).
  api.get('/selfcheck', (req, res) => {
    noStore(res);
    const mode = modeFor(req.query.mode); if (!mode) return res.status(400).json({ error: 'bad_mode', detail: 'mode must be mock or live' });
    const r = mode === 'mock' ? { kinds: table.kinds, secrets: table.secrets } : runSelfCheck();
    return res.json({ mode, ...r, ok: selfCheckOk(r) });
  });

  api.post('/evaluate', workspace, async (req, res, next) => {
    const id = req.workspaceId;
    noStore(res);
    if (!objectBody(req)) return res.status(400).json({ error: 'bad_request' });
    try {
      const mode = modeFor(req.body.mode);
      if (!mode) return res.status(400).json({ error: 'bad_mode', detail: 'mode must be mock or live' });
      const policy = policyFor(req.body.policy);
      const vertical = verticalOf(req);
      const out = await evaluateAction({ mode, cast: castFor(req), vertical, scenario: req.body.scenario, custom: req.body.custom, policy, scope: req.body.scope, labels: req.body.labels && typeof req.body.labels === 'object' ? req.body.labels : {}, ws: id, workspaces, table, traceparent: req.headers.traceparent, runner });
      res.set('traceparent', out.hops?.[0]?.request.headers.traceparent || '');
      return res.json({ ...out, workspace: id });
    } catch (e) { return failure(res, next)(e); }
  });

  api.post('/stream', workspace, async (req, res, next) => {
    const id = req.workspaceId;
    noStore(res);
    if (!objectBody(req)) return res.status(400).json({ error: 'bad_request' });
    try {
      const mode = modeFor(req.body.mode);
      if (!mode) return res.status(400).json({ error: 'bad_mode', detail: 'mode must be mock or live' });
      const out = await streamAction({ mode, cast: castFor(req), vertical: verticalOf(req), scenario: req.body.scenario, frames: req.body.frames, policy: policyFor(req.body.policy), scope: req.body.scope, ws: id, workspaces, table, traceparent: req.headers.traceparent, runner });
      return res.json({ ...out, workspace: id });
    } catch (e) { return failure(res, next)(e); }
  });

  api.get('/rules', workspace, async (req, res, next) => { const id = req.workspaceId; noStore(res); try { res.json({ workspace: id, rules: await rulesView(id, workspaces, runner) }); } catch (e) { next(e); } });
  api.post('/rules/import', workspace, async (req, res, next) => {
    const id = req.workspaceId;
    noStore(res);
    if (!objectBody(req)) return res.status(400).json({ error: 'bad_request' });
    try {
      const mode = modeFor(req.body.mode);
      if (!mode) return res.status(400).json({ error: 'bad_mode', detail: 'mode must be mock or live' });
      return res.json({ ...(await importRules({ mode, toml: req.body.toml, sample: req.body.sample, ws: id, workspaces, table, runner })), workspace: id });
    } catch (e) { return failure(res, next)(e); }
  });
  api.post('/rules/enforcement', workspace, async (req, res, next) => {
    const id = req.workspaceId;
    noStore(res);
    if (!objectBody(req)) return res.status(400).json({ error: 'bad_request' });
    try { return res.json({ ...(await setEnforcement({ ws: id, workspaces, id: req.body.id, enforcement: req.body.enforcement, runner })), workspace: id }); } catch (e) { return failure(res, next)(e); }
  });

  api.get('/promptlog', workspace, (req, res) => { const id = req.workspaceId; noStore(res); res.json({ ...getPromptLog(id, workspaces), workspace: id }); });
  api.post('/promptlog/config', workspace, (req, res, next) => {
    const id = req.workspaceId;
    noStore(res);
    if (!objectBody(req)) return res.status(400).json({ error: 'bad_request' });
    try { return res.json({ ...setPromptLog({ ws: id, workspaces, config: req.body.config }), workspace: id }); } catch (e) { return failure(res, next)(e); }
  });

  api.get('/insights', workspace, (req, res, next) => {
    const id = req.workspaceId;
    noStore(res);
    try {
      const mode = modeFor(req.query.mode); if (!mode) return res.status(400).json({ error: 'bad_mode', detail: 'mode must be mock or live' });
      return res.json({ ...insightsView({ mode, vertical: verticalOf(req), ws: id, workspaces, table, query: req.query }), workspace: id });
    } catch (e) { return failure(res, next)(e); }
  });

  // Reset clears this workspace's events, sealed records, prompt-log settings and pasted rules only.
  api.post('/reset', workspace, (req, res) => { const id = req.workspaceId; noStore(res); workspaces.reset(id); runner.cancel?.(id); return res.json({ reset: 'ok', workspace: id }); });
  api.use((_req, res) => res.status(404).json({ error: 'not_found' }));
  app.use('/api', api);
  if (fs.existsSync(path.join(WEB_DIST, 'index.html'))) {
    // Real files only: no directory index, no redirect to a directory ("/assets" is not a page), dotfiles ignored.
    app.use(express.static(WEB_DIST, { index: false, dotfiles: 'ignore', fallthrough: true, redirect: false }));
    // The page shell is for PAGE ADDRESSES only (isPageAddress): GET or HEAD from a client that takes HTML. /assets, /assets/, /favicon.ico, /x.map, /.git/config are not.
    app.use((req, res, next) => {
      const accept = req.get('accept');
      const html = accept === undefined || accept.includes('text/html') || accept.includes('*/*');
      return (req.method === 'GET' || req.method === 'HEAD') && html && isPageAddress(req.path) ? res.sendFile(path.join(WEB_DIST, 'index.html')) : next();
    });
  }
  // Last: a JSON 404 (Express's default page would echo the path), a 405 for a write to the page itself, and one catch-all error handler. Errors become
  // short JSON with fixed text: Express's default handler would send an HTML stack trace with absolute file paths and the request path.
  app.use((req, res) => {
    if (req.path === '/' && req.method !== 'GET' && req.method !== 'HEAD') return res.set('Allow', 'GET, HEAD').status(405).json({ error: 'method_not_allowed' });
    return res.status(404).json({ error: 'not_found' });
  });
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, next) => {
    if (res.headersSent) return next(err);
    const status = Number(err?.status || err?.statusCode);
    if (status === 413) return res.status(413).json({ error: 'payload_too_large' });
    if (status === 404) return res.status(404).json({ error: 'not_found' });
    if (status >= 400 && status < 500) return res.status(400).json({ error: 'bad_request' });
    return res.status(500).json({ error: 'internal_error' });
  });
  return app;
}

export function startHttpServer({ port, host, app = createApp() } = {}) {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => resolve({ server, url: `http://${host}:${server.address().port}/` }));
    server.once('error', reject);
  });
}
