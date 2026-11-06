// Safety rules. Pure functions plus two tiny middlewares. No I/O.
//  1. Loopback bind only unless DPLAB_BIND is set on purpose.
//  2. Host header must be a loopback name (DNS-rebinding defence).
//  3. A write must be same-origin: a cross-origin Origin, or a cross-site Sec-Fetch-Site, is refused.
//  4. Every host in any shipped text is reserved (.invalid / .example / apex of example.com|net|org).
//  5. Ports are 7200-7249 and never one of the forbidden ones.
//  6. Every key-looking string is an obviously fake sk-MOCK- value.

export function isLoopbackHost(host) {
  const h = String(host).toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '::1' || /^127(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(h);
}

export function bindHost(env = process.env) { return env.DPLAB_BIND || '127.0.0.1'; }

export function assertBindAllowed(host, env = process.env) {
  if (isLoopbackHost(host) || env.DPLAB_BIND) return host;
  throw new Error(`refusing to bind ${host}: loopback only. Set DPLAB_BIND to opt in.`);
}

export const PORT_MIN = 7200;
export const PORT_MAX = 7249;
export const DEFAULT_PORT = 7200;
const FORBIDDEN_PORTS = new Set([8080, 5173, 3000, 3900, 4000, 4400, 4510, 4600, 4601, 4840, 18080, 19080, 19090]);
export function portProblem(port) {
  if (!Number.isInteger(port)) return 'PORT is not an integer';
  if (FORBIDDEN_PORTS.has(port)) return `port ${port} is reserved for something else`;
  if (port < PORT_MIN || port > PORT_MAX) return `port ${port} is outside ${PORT_MIN}-${PORT_MAX}`;
  return null;
}
export function resolvePort(env = process.env) {
  const port = env.PORT === undefined || env.PORT === '' ? DEFAULT_PORT : Number(env.PORT);
  const problem = portProblem(port);
  if (problem) throw new Error(problem);
  return port;
}

export function isReservedHost(host) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  return /(^|\.)(invalid|example)$/.test(h);
}

const NETWORK_URL = /\b(?:https?|wss?|ftp|sftp|ssh|smtp|tcp|udp):\/\/([^\s/?#"'<>\\]+)/gi;
const EMAIL = /[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g;
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const stripAuthority = (a) => a.replace(/^[^@]*@/, '').replace(/:\d+$/, '');

// Every hostname or IP in text that is not reserved. Loopback names in URLs are allowed. Empty = clean.
export function scanHosts(text) {
  const found = new Set();
  const s = String(text);
  for (const m of s.matchAll(NETWORK_URL)) found.add(stripAuthority(m[1]).toLowerCase());
  for (const m of s.matchAll(EMAIL)) found.add(m[1].toLowerCase());
  for (const m of s.matchAll(IPV4)) found.add(m[0]);
  return [...found].filter((h) => !isReservedHost(h) && !isLoopbackHost(h)).sort();
}

// Any "sk-" secret that is not an obviously fake sk-MOCK- value. Empty = clean.
export function scanKeys(text) {
  return [...String(text).matchAll(/\bsk-(?!MOCK-)[A-Za-z0-9_-]{8,}/g)].map((m) => `${m[0].slice(0, 8)}...`);
}

// Free text from a caller (custodian, description): C0/C1 control characters DELETED (a word cannot hide behind interleaved controls), tab, newline and
// carriage return and bidirectional marks become spaces / are dropped, length capped. Rendered as text, never as markup. Callers that must not cut
// check the length FIRST and refuse the whole value; the cap here is only a last backstop.
export function cleanText(value, max = 80) {
  return String(value ?? '').replace(/[\t\n\r]/g, ' ').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '').replace(/[\u202a-\u202e\u2066-\u2069]/g, '').trim().slice(0, max);
}

// Extra host names the Host check accepts, set per lab via LAB_ALLOWED_HOSTS: proxy-served names that
// point at this Mac, such as <lab>.local.ping-devops.com. Loopback always works.
const HOSTNAME = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;
export function allowedExtraHosts(env = process.env) {
  const extra = String(env.LAB_ALLOWED_HOSTS || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
  for (const h of extra) if (!HOSTNAME.test(h)) throw new Error(`LAB_ALLOWED_HOSTS: not a host name: ${h}`);
  return new Set(extra);
}

export function hostCheck(req, res, next) {
  const raw = String(req.headers.host || '');
  const host = raw.startsWith('[') ? raw.slice(0, raw.indexOf(']') + 1) : raw.replace(/:\d+$/, '');
  if (!isLoopbackHost(host) && !allowedExtraHosts().has(host.toLowerCase())) {
    return res.status(403).json({ error: 'bad_host', message: 'Host must be loopback or on LAB_ALLOWED_HOSTS' });
  }
  next();
}

const WRITE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
export function sameOriginWrites(req, res, next) {
  if (!WRITE.has(req.method)) return next();
  const site = req.headers['sec-fetch-site'];
  if (site && site !== 'same-origin' && site !== 'none') return res.status(403).json({ error: 'cross_origin', message: 'writes must be same-origin' });
  const origin = req.headers.origin;
  if (origin) {
    let ok = false;
    // Behind the shared lab-proxy the browser origin is https://local.ping-devops.com:8443 while the app
    // serves plain http on loopback: the proxy sets X-Forwarded-Host + X-Forwarded-Proto, so compare the
    // origin against the forwarded pair when present, and against the raw Host + http scheme otherwise.
    const fwdHost = String(req.headers['x-forwarded-host'] || '').toLowerCase();
    const fwdProto = String(req.headers['x-forwarded-proto'] || '').toLowerCase();
    try {
      const u = new URL(origin);
      if (fwdHost) {
        ok = u.host.toLowerCase() === fwdHost && u.protocol === (fwdProto ? fwdProto + ':' : 'https:');
      } else {
        ok = u.protocol === 'http:' && u.host.toLowerCase() === String(req.headers.host || '').toLowerCase();
      }
    } catch { /* malformed */ }
    if (!ok) return res.status(403).json({ error: 'cross_origin', message: 'writes must be same-origin' });
  }
  next();
}
