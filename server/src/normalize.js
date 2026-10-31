// One normalised copy of a text, with an offset map, so every finder sees through the usual evasions: zero-width, bidirectional and tag
// characters and soft hyphens are dropped, every whitespace run (NBSP, newline, tab, double space) becomes one space, and compatibility forms
// (fullwidth digits and letters) become their plain form. `starts[i]` and `ends[i]` give the ORIGINAL offsets of normalised character i,
// so a span found in the copy redacts the right characters of the original.
const STRIP = /^[­​-‏⁠-⁩‪-‮﻿\u{e0000}-\u{e007f}]$/u;

export function normalise(text, { lower = false } = {}) {
  let norm = ''; const starts = []; const ends = []; let space = false; let i = 0;
  for (const cp of text) {
    const start = i; i += cp.length;
    if (STRIP.test(cp)) continue;
    if (/\s/u.test(cp)) { if (!space) { norm += ' '; starts.push(start); ends.push(i); space = true; } continue; }
    space = false;
    let c = cp.normalize('NFKC');
    if (!c || /\s/u.test(c)) c = cp;
    if (lower) { const l = c.toLowerCase(); if (l.length === c.length) c = l; }
    for (let k = 0; k < c.length; k++) { norm += c[k]; starts.push(start); ends.push(i); }
  }
  return { norm, starts, ends };
}
// A span of the normalised copy back to the original text.
export const mapSpan = (n, s, e) => ({ start: n.starts[s], end: n.ends[e - 1] });
