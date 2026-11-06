import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SETTINGS_KEYS, applySharedSettings, readSharedSettings } from '../src/settings.js';

const withFile = (text, fn) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dpl-set-'));
  const f = path.join(dir, '.env'); fs.writeFileSync(f, text, { mode: 0o600 });
  try { return fn(f); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
};

test('only this lab\'s own keys are taken from the shared settings file; every other key stays out', () => {
  assert.deepEqual(SETTINGS_KEYS, ['DPL_LAB_MODE', 'CENTRAL_AGENT_A2A_URL', 'CENTRAL_AGENT_A2A_BEARER']);
  withFile('PINGONE_CLIENT_SECRET=hunter2hunter2\nMODE=live\nPORT=9999\nDPL_LAB_MODE=live\nCENTRAL_AGENT_A2A_URL=https://aigw.example.invalid/a2a\n# a comment\nOTHER_APP_TOKEN="x y"\n', (f) => {
    assert.deepEqual(readSharedSettings(f), { DPL_LAB_MODE: 'live', CENTRAL_AGENT_A2A_URL: 'https://aigw.example.invalid/a2a' });
    const env = { HOME: '/x' };
    applySharedSettings(env, f);
    assert.deepEqual(Object.keys(env).sort(), ['CENTRAL_AGENT_A2A_URL', 'DPL_LAB_MODE', 'HOME']);
    assert.equal(env.DPL_LAB_MODE, 'live');
    assert.equal(env.CENTRAL_AGENT_A2A_URL, 'https://aigw.example.invalid/a2a');
  });
});

test('the environment wins over the file; a missing, empty or unreadable file is the defaults', () => {
  withFile('DPL_LAB_MODE=live\n', (f) => assert.equal(applySharedSettings({ DPL_LAB_MODE: 'mock' }, f).DPL_LAB_MODE, 'mock'));
  assert.deepEqual(readSharedSettings('/nonexistent/.env'), {});
  withFile('', (f) => assert.deepEqual(readSharedSettings(f), {}));
  withFile('DPL_LAB_MODE=\n', (f) => assert.deepEqual(readSharedSettings(f), {}));
  assert.deepEqual(readSharedSettings(os.tmpdir()), {}, 'a directory is not a settings file');
});
