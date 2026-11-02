// The sweep leaks that were reported by name, each with its own test: U+1680, "login: bob / secret", "password - secret", four-times percent-encoding, the text of
// /api/stream frames, /assets and /assets/ answering 200 HTML, and the false positive "The secret is out". Each is checked in maskText AND over HTTP in the places the text comes back.
// Credential-shaped test values are built at run time (the repository holds no literal).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { maskText } from '../src/mask.js';
import { post, withApp } from './helpers.js';

const S1 = ['hunter', '2xyz'].join('');
const W = { 'x-workspace': 'named' };
const live = (text) => ({ mode: 'live', custom: { text, role: 'user_prompt', surface: 'llm', response: text } });
// every place a typed text comes back: the display copy and both hop panes (evaluate), a label, a stream frame, a pasted rule's description and the echo of the paste
async function answers(url, text) {
  const bodies = [];
  bodies.push(await (await post(url, '/api/evaluate', live(text), W)).text());
  bodies.push(await (await post(url, '/api/evaluate', { mode: 'live', custom: { text: 'hello', role: 'user_prompt', surface: 'llm' }, labels: { person: text, agent: text, app: text } }, W)).text());
  bodies.push(await (await post(url, '/api/stream', { mode: 'live', frames: [text] }, W)).text());
  bodies.push(await (await post(url, '/api/stream', { mode: 'live', frames: ['first frame', text, 'last frame'] }, W)).text());
  bodies.push(await (await post(url, '/api/rules/import', { mode: 'live', toml: `[[rules]]\nid = "r-named"\nregex = 'abc'\ndescription = ${JSON.stringify(text)}\n` }, W)).text());
  return bodies;
}
const absent = (bodies, secret, what) => bodies.forEach((b, i) => assert.ok(!b.includes(secret), `${what}: answer ${i} holds the secret: ${b.slice(Math.max(0, b.indexOf(secret) - 80), b.indexOf(secret) + 20)}`));

test('U+1680 (the Ogham space) between a keyword and its value, and inside the keyword, is read as a space', async () => {
  const forms = [`password ${S1}`, `pass word=${S1}`, `password= ${S1}`, `my password is ${S1}`, `pw: ${S1}`, `token  ${S1}`];
  for (const f of forms) { const m = maskText(f); assert.ok(!m.includes(S1), JSON.stringify(f)); assert.match(m, /\[masked:/, JSON.stringify(f)); }
  await withApp(async (url) => { for (const f of forms) absent(await answers(url, f), S1, JSON.stringify(f)); });
});

test('"login: bob / secret" and "password - secret" are masked (a one-character value is not: the shared minimum is three, said in the README)', async () => {
  const forms = [`login: bob / ${S1}`, `password - ${S1}`, `username: bob, password - ${S1}`, `user bob / pw ${S1}`];
  assert.equal(maskText(`login: bob / ${S1}`), '[masked:pair]'); assert.equal(maskText(`password - ${S1}`), '[masked:shape]');
  for (const f of forms) assert.ok(!maskText(f).includes(S1), f);
  await withApp(async (url) => { for (const f of forms) absent(await answers(url, f), S1, f); });
  // the limit, stated: a value of one character is not recognised after these keywords
  assert.equal(maskText('login: bob / x'), 'login: bob / x'); assert.equal(maskText('password - x'), 'password - x');
});

test('percent-encoding 1 to 6 times (the keyword, the separator and the value) is decoded and masked', async () => {
  const again = (s, n) => { let x = s; for (let i = 0; i < n; i++) x = x.replace(/%/g, '%25'); return x; };
  const forms = [];
  for (let n = 1; n <= 6; n++) forms.push(again(`password%3D${S1}`, n), again(`p%61ssword=${S1}`, n), again(`token%3A%20${S1}`, n));
  assert.equal(forms.length, 18);
  assert.equal(maskText(again(`password%3D${S1}`, 4)), '[masked:assignment]');
  for (const f of forms) assert.ok(!maskText(f).includes(S1), f);
  await withApp(async (url) => { for (const f of [forms[3], forms[4], forms[9], forms[17]]) absent(await answers(url, f), S1, f); });
});

test('/api/stream: frames[].text never holds a typed secret, whether the secret sits in one frame, is split over frames, or is the keyword in one and the value in the next', async () => {
  // frames are joined as they arrive, with nothing between them: "password" then "hunter2xyz" is the one word "passwordhunter2xyz", so a space belongs to one of the two frames
  const sets = [
    [`password ${S1}`], [`login: bob / ${S1}`], [`pass word=${S1}`], ['the password is ', S1], ['password ', S1], ['password', ` ${S1}`], ['password:', ` ${S1}`], [`bob:${S1.slice(0, 4)}`, `${S1.slice(4)}@host.example`],
    ['https://bob:', `${S1}@host.example/x`], [`token=${S1.slice(0, 5)}`, S1.slice(5)], ['ok', `${'password%25253D'}${S1}`, 'ok'], ['one', 'two', `pw = ${S1}`], [`Bearer ${S1}`, 'tail'],
  ];
  await withApp(async (url) => {
    for (const frames of sets) {
      const r = await post(url, '/api/stream', { mode: 'live', frames }, W); const j = await r.json();
      assert.equal(r.status, 200, JSON.stringify(frames));
      assert.ok(Array.isArray(j.frames) && j.frames.length === frames.length, JSON.stringify(frames));
      for (const f of j.frames) assert.ok(!f.text.includes(S1), `${JSON.stringify(frames)} -> frame ${f.index}: ${f.text}`);
      assert.ok(!JSON.stringify(j).includes(S1), `${JSON.stringify(frames)}: nowhere in the answer`);
    }
  });
});

test('/assets and /assets/ are a JSON 404 whether or not the build exists (they answered 200 HTML)', async () => {
  for (const dist of [true, false]) {
    await withApp(async (url) => {
      for (const p of ['/assets', '/assets/', '/ASSETS/']) for (const method of ['GET', 'HEAD']) {
        // redirect 'manual': a 301 to "/assets/" (static serving a directory) must not be followed into the same 404
        const r = await fetch(`${url}${p}`, { method, headers: { accept: 'text/html' }, redirect: 'manual' });
        assert.equal(r.status, 404, `${method} ${p} dist=${dist}`); assert.match(r.headers.get('content-type'), /^application\/json/);
        if (method === 'GET') assert.equal(await r.text(), '{"error":"not_found"}');
      }
    }, { dist });
  }
});

test('"The secret is out" stays readable, as the README says, in the text, in a label, in a frame and in a pasted description', async () => {
  const phrases = ['The secret is out', 'The secret is out.', 'the secret is out!', 'Rotate the secret quarterly', 'secret santa list'];
  for (const p of phrases) assert.equal(maskText(p), p, p);
  await withApp(async (url) => {
    const ev = await (await post(url, '/api/evaluate', { mode: 'live', custom: { text: 'The secret is out', role: 'user_prompt', surface: 'llm' }, labels: { person: 'The secret is out' } }, W)).json();
    assert.equal(ev.evaluation.text, 'The secret is out'); assert.equal(ev.labels.person, 'The secret is out');
    const st = await (await post(url, '/api/stream', { mode: 'live', frames: ['The secret is out'] }, W)).json();
    assert.equal(st.frames[0].text, 'The secret is out');
    const ru = await (await post(url, '/api/rules/import', { mode: 'live', toml: "[[rules]]\nid = \"r-out\"\nregex = 'abc'\ndescription = \"The secret is out\"\n" }, W)).json();
    assert.match(ru.Toml, /description = "The secret is out"/);
  });
  const readme = fs.readFileSync(new URL('../../README.md', import.meta.url), 'utf8');
  assert.ok(readme.includes('The secret is out'), 'the README names the sentence it keeps readable');
});
