// The HTTP edge (shared-masker 1.4.0 Express recipe): the charset gate (415), the method table (405 + Allow), the final JSON 404, the catch-all error handler, the page-address
// rule of the single-page fallback, and the workspace-id rule. Numbers and route names are LITERALS on purpose: a test that imports the table cannot catch an entry removed from it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorkspaces } from '../src/workspaces.js';
import { SHELL, captured, rawHttp, withApp } from './helpers.js';

const S1 = ['hunter', '2xyz'].join('');
const OK_BODY = JSON.stringify({ mode: 'live', custom: { text: 'hello', role: 'user_prompt', surface: 'llm' } });

test('charset: any charset but utf-8 is 415 with one fixed body, on every route, and the value is not read, answered or logged', async () => {
  await withApp(async (url) => {
    const logs = await captured(async () => {
      for (const cs of ['latin1', 'utf-16', 'ISO-8859-1', `password-${S1}`, `"${S1}"`, '', 'utf-8;charset=latin1']) {
        for (const route of ['/api/evaluate', '/api/stream', '/api/rules/import', '/api/reset', '/api/story']) {
          const r = await rawHttp(`${url}${route}`, { method: 'POST', headers: { 'content-type': `application/json; charset=${cs}`, origin: url }, body: OK_BODY });
          assert.equal(r.status, 415, `${route} charset=${cs}`);
          assert.equal(r.text, '{"error":"unsupported_charset"}');
          assert.match(r.headers['content-type'], /^application\/json/);
        }
      }
    });
    assert.ok(!logs.includes(S1) && !/latin1|utf-16/i.test(logs), 'nothing typed was logged');
    // utf-8 in any spelling still works
    for (const ok of ['application/json', 'application/json; charset=utf-8', 'application/json; charset=UTF-8', 'application/json;charset="utf-8"']) {
      const r = await rawHttp(`${url}/api/evaluate`, { method: 'POST', headers: { 'content-type': ok, origin: url, 'x-workspace': 'cs' }, body: OK_BODY });
      assert.equal(r.status, 200, ok);
    }
  });
});

// path -> the exact Allow header; every other method on it is 405 (checked for the methods below).
const TABLE = [
  ['/api/health', 'GET, HEAD'], ['/api/story', 'GET, HEAD'], ['/api/diagram', 'GET, HEAD'], ['/api/info', 'GET, HEAD'], ['/api/selfcheck', 'GET, HEAD'],
  ['/api/rules', 'GET, HEAD'], ['/api/promptlog', 'GET, HEAD'], ['/api/insights', 'GET, HEAD'],
  ['/api/evaluate', 'POST'], ['/api/stream', 'POST'], ['/api/rules/import', 'POST'], ['/api/rules/enforcement', 'POST'], ['/api/promptlog/config', 'POST'], ['/api/reset', 'POST'],
];
test('methods: every route of the table answers 405 with its exact Allow header for every method it does not list, before the body is read (14 routes)', async () => {
  assert.equal(TABLE.length, 14);
  await withApp(async (url, workspaces) => {
    for (const [route, allow] of TABLE) {
      const wrong = allow === 'POST' ? ['GET', 'PUT', 'PATCH', 'DELETE'] : ['POST', 'PUT', 'PATCH', 'DELETE'];
      for (const method of wrong) {
        // a body that is not JSON: the 405 must come first, never a 400 from the body parser
        const r = await rawHttp(`${url}${route}`, { method, headers: { 'content-type': 'application/json', origin: url }, body: method === 'GET' ? undefined : '{"password":' });
        assert.equal(r.status, 405, `${method} ${route}`); assert.equal(r.headers.allow, allow, `${method} ${route}`); assert.equal(r.text, '{"error":"method_not_allowed"}');
      }
    }
    // the table is read case-insensitively and with one trailing slash, as Express routes it
    for (const p of ['/API/Story', '/api/story/', '/Api/StOrY/']) { const r = await rawHttp(`${url}${p}`, { method: 'PUT', headers: { origin: url } }); assert.equal(r.status, 405, p); assert.equal(r.headers.allow, 'GET, HEAD'); }
    // a path that is NOT in the table is the final JSON 404, whatever the method
    for (const p of ['/api/nothing', '/api/story/x', '/api/rules/import/x', '/api/evaluate.json']) for (const method of ['GET', 'POST', 'DELETE']) {
      const r = await rawHttp(`${url}${p}`, { method, headers: { origin: url, 'content-type': 'application/json' }, body: method === 'GET' ? undefined : '{}' });
      assert.equal(r.status, 404, `${method} ${p}`); assert.equal(r.text, '{"error":"not_found"}');
    }
    assert.equal(workspaces.size(), 0, 'no refusal and no 404 took a workspace slot');
  });
});

test('the final 404 and the catch-all error handler never echo the path, the body or an error message, and log nothing', async () => {
  const boom = createWorkspaces(); boom.rules = () => { throw new Error(`boom ${S1} /Users/x/secret.js`); };
  await withApp(async (url) => {
    const logs = await captured(async () => {
      const miss = await rawHttp(`${url}/api/zzz-${S1}`, { headers: { origin: url } });
      assert.equal(miss.status, 404); assert.equal(miss.text, '{"error":"not_found"}');
      const bad = await rawHttp(`${url}/api/evaluate`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url }, body: `{"password":"${S1}"` });
      assert.equal(bad.status, 400); assert.equal(bad.text, '{"error":"bad_request"}');
      const big = await rawHttp(`${url}/api/reset`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url }, body: JSON.stringify({ pad: 'x'.repeat(40000) }) });
      assert.equal(big.status, 413); assert.equal(big.text, '{"error":"payload_too_large"}');
      const thrown = await rawHttp(`${url}/api/rules`, { headers: { origin: url } });
      assert.equal(thrown.status, 500); assert.equal(thrown.text, '{"error":"internal_error"}');
    });
    assert.ok(!logs.includes(S1) && !/boom|Users/.test(logs), 'the error message and the stack are not logged');
  }, { workspaces: boom });
});

test('the page shell is for page addresses only: /assets and /assets/ and every file-shaped, dot or reserved path are a JSON 404; real files are served', async () => {
  await withApp(async (url) => {
    const html = { accept: 'text/html,application/xhtml+xml' };
    for (const p of ['/assets', '/assets/', '/Assets', '/assets/missing.js', '/assets/nested/', '/static', '/static/x', '/favicon.ico', '/robots.txt', '/a.map', '/.git/config', '/.well-known/x', '/a//b', '/%', '/%zz', '/%2e%2e/x.js', '/a%2fb.js', '/api', '/api/']) {
      for (const method of ['GET', 'HEAD']) {
        const r = await fetch(`${url}${p}`, { method, headers: html });
        assert.equal(r.status, 404, `${method} ${p}`); assert.match(r.headers.get('content-type'), /^application\/json/, p);
        if (method === 'GET') assert.equal(await r.text(), '{"error":"not_found"}', p);
      }
    }
    for (const p of ['/', '/rules', '/detect', '/some/spa/route', '/Rules', '/assets-list']) {
      const r = await fetch(`${url}${p}`, { headers: html }); assert.equal(r.status, 200, p); assert.match(r.headers.get('content-type'), /^text\/html/); assert.equal(await r.text(), SHELL);
    }
    // a client that does not take HTML (a script asking for JSON) is not given the shell
    const json = await fetch(`${url}/rules`, { headers: { accept: 'application/json' } }); assert.equal(json.status, 404);
    // a write to a page address is not a page
    const post = await fetch(`${url}/rules`, { method: 'POST', headers: { origin: url, 'content-type': 'application/json' }, body: '{}' }); assert.equal(post.status, 404);
    const js = await fetch(`${url}/assets/app.js`); assert.equal(js.status, 200); assert.equal(await js.text(), 'console.log(1)');
    assert.equal((await fetch(`${url}/favicon.svg`)).status, 200);
  });
});

test('workspace ids: a credential-looking id is 400 bad_workspace before a slot exists, on every route that uses one; info routes and 404s never take a slot', async () => {
  await withApp(async (url, workspaces) => {
    const bad = ['0123456789abcdef01234567', 'sk-aaaabbbbccccdddd1111', 'token-1', 'password-x', 'pw-hunter2xyz', 'ghp_abc', 'secret-key', 'UPPER', 'has space', `x${'y'.repeat(40)}`];
    const uses = [['GET', '/api/rules'], ['GET', '/api/promptlog'], ['GET', '/api/insights?mode=live'], ['POST', '/api/reset'], ['POST', '/api/evaluate'], ['POST', '/api/stream'], ['POST', '/api/rules/import'], ['POST', '/api/rules/enforcement'], ['POST', '/api/promptlog/config']];
    assert.equal(uses.length, 9);
    for (const id of bad) for (const [method, route] of uses) {
      const r = await rawHttp(`${url}${route}`, { method, headers: { 'x-workspace': id, origin: url, 'content-type': 'application/json' }, body: method === 'POST' ? OK_BODY : undefined });
      assert.equal(r.status, 400, `${method} ${route} ${id}`); assert.equal(r.text, '{"error":"bad_workspace"}');
    }
    assert.equal(workspaces.size(), 0, 'no refused id took a slot');
    for (const p of ['/api/health', '/api/info', '/api/story', '/api/diagram', '/api/selfcheck?mode=mock', '/api/nothing', '/rules']) await fetch(`${url}${p}`, { headers: { 'x-workspace': 'w-info', accept: 'text/html' } });
    assert.equal(workspaces.size(), 0, 'info routes, 404s and the page shell take no slot');
    const ok = await rawHttp(`${url}/api/rules`, { headers: { 'x-workspace': 'plain-tab-1' } }); assert.equal(ok.status, 200);
  });
});
