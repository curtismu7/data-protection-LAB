import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp, startHttpServer } from '../server/src/app.js';
import { createHealth } from '../server/src/health.js';
import { createWorkspaces } from '../server/src/workspaces.js';
import { createRegexRunner } from '../server/src/regexRunner.js';
import { reset } from './reset.mjs';

test('the reset script clears the default workspace (events, sealed records, settings, rules) and refuses a non-loopback host', async () => {
  const workspaces = createWorkspaces(); const runner = createRegexRunner();
  const health = createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });
  const { server, url } = await startHttpServer({ port: 0, host: '127.0.0.1', app: createApp({ health, workspaces, runner }) });
  try {
    const base = url.replace(/\/$/, '');
    workspaces.addEvent('default', { id: 'e1' }); workspaces.addRecord('default', { id: 'r1' }); workspaces.addRules('default', [{ ID: 'cst-a' }]); workspaces.setPromptLog('default', { Enabled: true }, { x: 1 });
    workspaces.addEvent('other', { id: 'e2' });
    assert.deepEqual(await reset(base), { reset: 'ok', workspace: 'default' });
    assert.deepEqual([workspaces.events('default').length, workspaces.records('default').length, workspaces.rules('default').length, workspaces.promptLog('default').Enabled, workspaces.events('other').length], [0, 0, 0, false, 1]);
    await assert.rejects(reset('http://example.invalid:7200'), /loopback only/);
  } finally { health.stop(); await new Promise((r) => server.close(r)); await runner.close(); }
});
