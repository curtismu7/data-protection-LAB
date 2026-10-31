// The lab-written ILLUSTRATIVE set of personal-data kinds. This is NOT Ping's list: the deck says the release goes from 5 kinds to 23 and
// the lab does not reproduce or guess that list. Eleven kinds here, each with a real checksum where the kind is numeric (or a
// structural check where no checksum exists: SSN-shaped, UK NINO-shaped, calendar date, e-mail, phone), each selectable per kind, and each
// with a valid sample and a NEAR-MISS sample that must not match (generated at run time from the checksum, so no literal sits in the repo).
// Candidate patterns are fixed, linear and bounded; nothing here builds a regular expression from user input.

const digits = (s) => s.replace(/\D/g, '');

// ---- checksums -------------------------------------------------------------------------------------------------------------------
export function luhnValid(d) {
  if (!/^\d+$/.test(d)) return false;
  let sum = 0; let dbl = false;
  for (let i = d.length - 1; i >= 0; i--) { let n = d.charCodeAt(i) - 48; if (dbl) { n *= 2; if (n > 9) n -= 9; } sum += n; dbl = !dbl; }
  return sum % 10 === 0;
}
export const luhnCheckDigit = (partial) => { for (let c = 0; c < 10; c++) if (luhnValid(`${partial}${c}`)) return c; return 0; };
export const luhnComplete = (partial) => `${partial}${luhnCheckDigit(partial)}`;

export const mod97 = (s) => { let r = 0; for (const ch of s) { const v = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55); for (const c of v) r = (r * 10 + (c.charCodeAt(0) - 48)) % 97; } return r; };
export const ibanCheckDigits = (country, bban) => String(98 - mod97(`${bban}${country}00`)).padStart(2, '0');
const IBAN_LEN = { GB: 22, DE: 22, FR: 27, ES: 24, NL: 18, IE: 22, IT: 27, CH: 21, BE: 16 };
export const ibanValid = (compact) => /^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(compact) && IBAN_LEN[compact.slice(0, 2)] === compact.length && mod97(`${compact.slice(4)}${compact.slice(0, 4)}`) === 1;

export const abaValid = (d) => /^\d{9}$/.test(d) && (3 * (+d[0] + +d[3] + +d[6]) + 7 * (+d[1] + +d[4] + +d[7]) + (+d[2] + +d[5] + +d[8])) % 10 === 0
  && (() => { const p = +d.slice(0, 2); return (p >= 1 && p <= 12) || (p >= 21 && p <= 32) || (p >= 61 && p <= 72) || p === 80; })();
export const abaCheckDigit = (eight) => { for (let c = 0; c < 10; c++) if (abaValid(`${eight}${c}`)) return c; return -1; };

// NHS-number-shaped (mod 11, weights 10..2). The lab calls it a "health id"; the format is a lab reading, not a claim about any product.
export function mod11Check(nine) { let s = 0; for (let i = 0; i < 9; i++) s += (10 - i) * +nine[i]; const c = 11 - (s % 11); return c === 11 ? 0 : c; }
export const healthIdValid = (d) => /^\d{10}$/.test(d) && mod11Check(d.slice(0, 9)) !== 10 && mod11Check(d.slice(0, 9)) === +d[9];

const DNI_LETTERS = 'TRWAGMYFPDXBNJZSQVHLCKE';
export const dniLetter = (n8) => DNI_LETTERS[Number(n8) % 23];

const calendarValid = (y, m, d) => { const dt = new Date(Date.UTC(y, m - 1, d)); return y >= 1900 && y <= 2100 && dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d; };

// ---- finders: each yields { start, end } for the sensitive span ------------------------------------------------------------------------
const spans = (re, text, ok) => { const out = []; for (const m of text.matchAll(re)) { const r = ok(m); if (r) out.push(r); } return out; };
const whole = (m) => ({ start: m.index, end: m.index + m[0].length });

const FINDERS = {
  'pii-ssn': (t) => spans(/(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])/g, t, (m) => (m[1] !== '000' && m[1] !== '666' && +m[1] < 900 && m[2] !== '00' && m[3] !== '0000' ? whole(m) : null)),
  'pii-credit-card': (t) => spans(/(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])/g, t, (m) => {
    const d = digits(m[0]);
    const brand = /^4(\d{12}|\d{15}|\d{18})$/.test(d) || /^(5[1-5]\d{14}|2(2[2-9]\d|[3-6]\d\d|7[01]\d|720)\d{12})$/.test(d) || /^3[47]\d{13}$/.test(d) || /^(6011|65\d\d)\d{12}$/.test(d);
    return brand && luhnValid(d) ? whole(m) : null;
  }),
  'pii-iban': (t) => spans(/(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}/g, t, (m) => {
    // Walk the match counting non-space characters until the country's length, so trailing capitalised words are not swallowed.
    const country = m[0].slice(0, 2); const want = IBAN_LEN[country]; if (!want) return null;
    let n = 0; let end = 0; let compact = '';
    for (let i = 0; i < m[0].length && n < want; i++) { const ch = m[0][i]; if (ch !== ' ') { compact += ch; n++; } end = i + 1; }
    return n === want && ibanValid(compact) && !/[A-Za-z0-9]/.test(t[m.index + end] ?? ' ') ? { start: m.index, end: m.index + end } : null;
  }),
  'pii-aba-routing': (t) => spans(/(?<![\d-])\d{9}(?![\d-])/g, t, (m) => (abaValid(m[0]) ? whole(m) : null)),
  'pii-health-id': (t) => spans(/(?<![\d-])\d{3}( ?)\d{3}\1\d{4}(?![\d-])/g, t, (m) => (healthIdValid(digits(m[0])) ? whole(m) : null)),
  'pii-ca-sin': (t) => spans(/(?<![\d-])\d{3}([ -])\d{3}\1\d{3}(?![\d-])/g, t, (m) => { const d = digits(m[0]); return luhnValid(d) && d[0] !== '0' && d[0] !== '8' ? whole(m) : null; }),
  'pii-es-dni': (t) => spans(/(?<![A-Za-z0-9])(\d{8})([A-HJ-NP-TV-Z])(?![A-Za-z0-9])/g, t, (m) => (dniLetter(m[1]) === m[2] ? whole(m) : null)),
  'pii-uk-nino': (t) => spans(/(?<![A-Za-z0-9])([A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]) ?\d{2} ?\d{2} ?\d{2} ?[A-D](?![A-Za-z0-9])/g, t, (m) => (['BG', 'GB', 'NK', 'KN', 'TN', 'NT', 'ZZ'].includes(m[1]) ? null : whole(m))),
  'pii-dob': (t) => spans(/\b(?:dob|d\.o\.b\.?|date of birth|born(?: on)?)\s*[:\-]?\s*(\d{4}-\d{2}-\d{2}|\d{1,2}[/.]\d{1,2}[/.]\d{4})/gi, t, (m) => {
    const v = m[1]; let y; let mo; let d;
    if (v.includes('-')) [y, mo, d] = v.split('-').map(Number); else [d, mo, y] = v.split(/[/.]/).map(Number);
    if (!calendarValid(y, mo, d)) return null;
    const start = m.index + m[0].length - v.length; return { start, end: start + v.length };
  }),
  'pii-email': (t) => spans(/(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,4}(?![A-Za-z0-9-])/g, t, (m) => (/\.[A-Za-z]{2,}$/.test(m[0]) ? whole(m) : null)),
  'pii-phone': (t) => spans(/(?<![\d+-])(?:\+\d{1,3}[ -]?\(?\d{1,4}\)?(?:[ -]?\d{2,4}){2,3}|\(\d{3}\) ?\d{3}-\d{4}|\d{3}-\d{3}-\d{4})(?![\d-])/g, t, (m) => { const n = digits(m[0]).length; return n >= 8 && n <= 15 ? whole(m) : null; }),
};

// ---- samples: a valid value and a near miss, computed from the checksum at run time -----------------------------------------------------------
const pad = (n, w) => String(n).padStart(w, '0');
export const SAMPLES = {
  'pii-ssn': { valid: () => `${pad(123, 3)}-${pad(45, 2)}-${pad(6789, 4)}`, nearMiss: () => `${pad(666, 3)}-${pad(45, 2)}-${pad(6789, 4)}` },
  'pii-credit-card': { valid: () => { const d = luhnComplete('411111111111111'); return d.replace(/(\d{4})(?=\d)/g, '$1 '); }, nearMiss: () => { const d = luhnComplete('411111111111111'); const bad = `${d.slice(0, 15)}${(+d[15] + 1) % 10}`; return bad.replace(/(\d{4})(?=\d)/g, '$1 '); } },
  'pii-iban': { valid: () => { const b = 'WEST12345698765432'; const c = `GB${ibanCheckDigits('GB', b)}${b}`; return c.replace(/(.{4})(?=.)/g, '$1 '); }, nearMiss: () => { const b = 'WEST12345698765432'; const cd = ibanCheckDigits('GB', b); const c = `GB${cd}${b.slice(0, 17)}${(+b[17] + 1) % 10}`; return c.replace(/(.{4})(?=.)/g, '$1 '); } },
  'pii-aba-routing': { valid: () => `02100002${abaCheckDigit('02100002')}`, nearMiss: () => `02100002${(abaCheckDigit('02100002') + 1) % 10}` },
  'pii-health-id': { valid: () => { const n = '943476591'; return `${n.slice(0, 3)} ${n.slice(3, 6)} ${n.slice(6)}${mod11Check(n)}`; }, nearMiss: () => { const n = '943476591'; return `${n.slice(0, 3)} ${n.slice(3, 6)} ${n.slice(6)}${(mod11Check(n) + 1) % 10}`; } },
  'pii-ca-sin': { valid: () => { const d = luhnComplete('46454286'); return `${d.slice(0, 3)}-${d.slice(3, 6)}-${d.slice(6)}`; }, nearMiss: () => { const d = luhnComplete('46454286'); return `${d.slice(0, 3)}-${d.slice(3, 6)}-${d.slice(6, 8)}${(+d[8] + 1) % 10}`; } },
  'pii-es-dni': { valid: () => `12345678${dniLetter('12345678')}`, nearMiss: () => `12345678${dniLetter('12345679')}` },
  'pii-uk-nino': { valid: () => 'AB 12 34 56 C', nearMiss: () => 'BG 12 34 56 C' },
  'pii-dob': { valid: () => 'DOB: 1984-03-27', nearMiss: () => 'DOB: 1984-02-30' },
  'pii-email': { valid: () => 'sam.jones@mail.example', nearMiss: () => 'sam.jones@localhost' },
  'pii-phone': { valid: () => '+44 20 7946 0958', nearMiss: () => '+44 20 79' },
};

export const PII_KINDS = [
  { id: 'pii-ssn', label: 'SSN-shaped national id', group: 'national', validation: 'structure (area, group and serial rules; no checksum exists)', score: 0.75 },
  { id: 'pii-ca-sin', label: 'Canadian SIN-shaped national id', group: 'national', validation: 'Luhn checksum, first digit rule', score: 0.75 },
  { id: 'pii-es-dni', label: 'Spanish DNI-shaped national id', group: 'national', validation: 'mod 23 check letter', score: 0.7 },
  { id: 'pii-uk-nino', label: 'UK NINO-shaped national id', group: 'national', validation: 'structure (letter classes and excluded prefixes; no checksum)', score: 0.7 },
  { id: 'pii-credit-card', label: 'Payment card number', group: 'financial', validation: 'brand prefix, length, Luhn checksum', score: 0.8 },
  { id: 'pii-iban', label: 'IBAN', group: 'financial', validation: 'country length and ISO 7064 mod 97', score: 0.75 },
  { id: 'pii-aba-routing', label: 'US routing number', group: 'financial', validation: '3-7-1 weighted checksum and Federal Reserve prefix range', score: 0.6 },
  { id: 'pii-health-id', label: 'Health id (NHS-number-shaped)', group: 'health', validation: 'mod 11 checksum (a lab reading of a published format)', score: 0.75 },
  { id: 'pii-dob', label: 'Date of birth after a label', group: 'health', validation: 'real calendar date', score: 0.6 },
  { id: 'pii-email', label: 'E-mail address', group: 'contact', validation: 'structure (local part, domain, letter TLD)', score: 0.4 },
  { id: 'pii-phone', label: 'Telephone number', group: 'contact', validation: 'structure (+CC form, or NANP shapes; 8 to 15 digits)', score: 0.5 },
];
export const PII_KIND_IDS = PII_KINDS.map((k) => k.id);
export const piiKind = (id) => PII_KINDS.find((k) => k.id === id) || null;

// kinds: null = every kind; otherwise an array of kind ids (a custom rule id is ignored here: it is filtered in guard.js).
export function detectPii(text, kinds = null) {
  const out = [];
  for (const k of PII_KINDS) {
    if (kinds && !kinds.includes(k.id)) continue;
    for (const s of FINDERS[k.id](text)) out.push({ kind: k.id, start: s.start, end: s.end });
  }
  return out;
}
