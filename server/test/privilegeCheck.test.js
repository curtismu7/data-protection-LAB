import test from 'node:test';
import assert from 'node:assert/strict';
import { installNetguard } from '../src/netguard.js';
import { post, json, withServer } from './helpers.js';

const guard = installNetguard();
test.after(() => { guard.restore(); });
const W = (id) => ({ 'x-workspace': id });
const ENV = {
  CENTRAL_AGENT_A2A_URL: 'https://aigw.example.invalid/a2a',
  CENTRAL_AGENT_A2A_BEARER: 'sk-test',
};
// Mock ONLY the gateway host: the lab's own test client uses the same global fetch.
function mockGateway(handler) {
  const real = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (u, init) => {
    if (!String(u).includes('aigw.example.invalid')) return real(u, init);
    seen.push({ u: String(u), auth: init?.headers?.authorization });
    return handler();
  };
  return { seen, restore: () => { globalThis.fetch = real; } };
}

test('POST /api/privilege-check 503s clearly when Real mode is not configured', async () => {
  await withServer(async (url) => {
    const res = await post(url, '/api/privilege-check', { text: 'hello' }, W('w-pc1'));
    assert.equal(res.status, 503);
    const body = await json(res);
    assert.equal(body.error, 'privilege_not_configured');
  });
});

test('POST /api/privilege-check relays the gateway decision (allow) and never leaks the bearer', async () => {
  const mock = mockGateway(() => new Response(JSON.stringify({ jsonrpc: '2.0', id: 'x', result: { status: { state: 'completed' } } }), { status: 200 }));
  try {
    await withServer(async (url) => {
      const res = await post(url, '/api/privilege-check', { text: 'an ordinary prompt' }, W('w-pc2'));
      assert.equal(res.status, 200);
      const body = await json(res);
      assert.equal(body.mapped.decision, 'allow');
      assert.equal(body.mapped.reasonCode, 'ALLOW-AIGUARD-CLEAN');
      assert.equal(body.mapped.measured, true);
      assert.equal(mock.seen.length, 1);
      assert.match(mock.seen[0].u, /aigw\.example\.invalid\/a2a\/jsonrpc/);
      assert.equal(mock.seen[0].auth, 'Bearer sk-test');
      assert.match(body.raw, /completed/);
    }, { env: ENV });
  } finally { mock.restore(); }
});

test('POST /api/privilege-check maps a policy block to deny', async () => {
  const mock = mockGateway(() => new Response(JSON.stringify({ jsonrpc: '2.0', id: 'x', error: { code: -32600, message: 'request blocked by security policy' } }), { status: 200 }));
  try {
    await withServer(async (url) => {
      const res = await post(url, '/api/privilege-check', { text: 'a credential-laden prompt' }, W('w-pc3'));
      const body = await json(res);
      assert.equal(body.mapped.decision, 'deny');
      assert.equal(body.mapped.reasonCode, 'DENY-AIGUARD-BLOCKED');
    }, { env: ENV });
  } finally { mock.restore(); }
});

test('POST /api/privilege-check refuses missing and oversized text without calling the gateway', async () => {
  const mock = mockGateway(() => new Response('{}', { status: 200 }));
  try {
    await withServer(async (url) => {
      const missing = await post(url, '/api/privilege-check', {}, W('w-pc4'));
      assert.equal(missing.status, 400);
      const big = await post(url, '/api/privilege-check', { text: 'x'.repeat(4001) }, W('w-pc4'));
      assert.equal(big.status, 400);
      assert.equal(mock.seen.length, 0);
    }, { env: ENV });
  } finally { mock.restore(); }
});
