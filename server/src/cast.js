// {{token}} templating for the story data. customer.config.json (optional, git-ignored) overrides the default cast.
// Tokens are filled from one of three vertical packs. A test fails on any token a pack does not define.
// The personal-data values in a pack are SYNTHETIC: generated from each kind's checksum at run time (pii.js), so no literal number sits in the repo.
import fs from 'node:fs';
import { scanHosts } from './safety.js';
import { luhnComplete, ibanCheckDigits, mod11Check } from './pii.js';

const TOKEN = /\{\{(\w+)\}\}/g;
const MAX_CAST = 40;
const ID = /^[a-z0-9.-]{1,40}$/;

const card = (prefix15) => luhnComplete(prefix15).replace(/(\d{4})(?=\d)/g, '$1 ');
const iban = (bban) => `GB${ibanCheckDigits('GB', bban)}${bban}`.replace(/(.{4})(?=.)/g, '$1 ');
const health = (n) => `${n.slice(0, 3)} ${n.slice(3, 6)} ${n.slice(6)}${mod11Check(n)}`;
const ssn = (a, g, s) => `${a}-${g}-${s}`;

// Everything a story needs per vertical: who the person is, which agent and application, which gateway key, and the synthetic personal data.
export const VERTICALS = {
  finance: {
    castBrand: 'Fabrikam Bank', castAgentId: 'maya.chen', castHost: 'fabrikam', castAgent: 'refund-assistant', castApp: 'support-portal', castKey: 'key-refunds',
    castMcp: 'ledger-mcp', castSecretLabel: 'payments gateway key', castCard: card('411111111111111'), castIdLabel: 'national id', castIdentifier: ssn(123, 45, 6789),
    castEmail: 'sam.jones@fabrikam.example', castPhone: '+44 20 7946 0958', castOrder: 'order 9120',
  },
  health: {
    castBrand: 'Contoso Health', castAgentId: 'omar.reyes', castHost: 'contoso', castAgent: 'intake-assistant', castApp: 'patient-portal', castKey: 'key-intake',
    castMcp: 'claims-mcp', castSecretLabel: 'claims database password', castCard: card('510510510510510'), castIdLabel: 'health id', castIdentifier: health('943476591'),
    castEmail: 'lee.park@contoso.example', castPhone: '+44 161 496 0323', castOrder: 'claim 3307',
  },
  retail: {
    castBrand: 'Northwind Retail', castAgentId: 'priya.nair', castHost: 'northwind', castAgent: 'checkout-helper', castApp: 'storefront-web', castKey: 'key-checkout',
    castMcp: 'orders-mcp', castSecretLabel: 'checkout API key', castCard: card('37828224631000'), castIdLabel: 'IBAN', castIdentifier: iban('WEST12345698765432'),
    castEmail: 'ana.silva@northwind.example', castPhone: '+49 30 901820', castOrder: 'order 5521',
  },
};
export const DEFAULT_VERTICAL = 'finance';
export const DEFAULT_CAST = VERTICALS[DEFAULT_VERTICAL];

export const unfilled = (text, cast) => [...String(text).matchAll(TOKEN)].map((m) => m[1]).filter((k) => !Object.hasOwn(cast, k));
export const fill = (text, cast) => String(text).replace(TOKEN, (m, k) => (Object.hasOwn(cast, k) ? cast[k] : m));
// Iterative, so a deep structure cannot overflow the stack.
export function fillDeep(value, cast) {
  const clone = (x) => (Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x);
  const outRoot = { v: clone(value) };
  const work = [[value, outRoot, 'v']];
  while (work.length) {
    const [src, dst, key] = work.pop();
    if (typeof src === 'string') { dst[key] = fill(src, cast); continue; }
    if (src === null || typeof src !== 'object') { dst[key] = src; continue; }
    const copy = clone(src);
    dst[key] = copy;
    for (const k of Object.keys(src).reverse()) work.push([src[k], copy, k]);
  }
  return outRoot.v;
}

export const verticalFrom = (id) => (typeof id === 'string' && Object.hasOwn(VERTICALS, id) ? id : DEFAULT_VERTICAL);

// Only brand, agentId and host, as short plain strings; anything else in the file is ignored.
export function loadCast(file, vertical = DEFAULT_VERTICAL) {
  const cast = { ...VERTICALS[verticalFrom(vertical)] };
  if (!file) return cast;
  try {
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    for (const [short, key] of [['brand', 'castBrand'], ['agentId', 'castAgentId'], ['host', 'castHost']]) {
      const v = cfg?.cast?.[short];
      if (typeof v !== 'string' || !v.trim()) continue;
      const clean = v.replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, ' ').trim().slice(0, MAX_CAST);
      if (/:\/\/|@/.test(clean) || scanHosts(clean).length) continue;
      if (short !== 'brand' && !ID.test(clean.toLowerCase())) continue;
      if (short === 'host' && clean.includes('.')) continue;
      cast[key] = short === 'brand' ? clean : clean.toLowerCase();
    }
  } catch { /* no file or not JSON: the defaults */ }
  return cast;
}
