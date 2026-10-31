// Per kind and per detector: does the valid sample fire and does the near miss stay quiet? Computed by the engine on request (Live) or read
// from the generated table (Mock). The credential-shaped samples never leave the server: only the two booleans do.
import { PII_KINDS, SAMPLES, detectPii } from './pii.js';
import { SECRET_DETECTORS, detectSecrets } from './secrets.js';

export function runSelfCheck() {
  const kinds = {}; const secrets = {};
  for (const k of PII_KINDS) kinds[k.id] = { valid: detectPii(`value ${SAMPLES[k.id].valid()} end`, [k.id]).length === 1, nearMiss: detectPii(`value ${SAMPLES[k.id].nearMiss()} end`, [k.id]).length > 0 };
  for (const d of SECRET_DETECTORS) secrets[d.id] = { valid: detectSecrets(`x ${d.sample()} y`).some((f) => f.rule === d.id), nearMiss: detectSecrets(`x ${d.nearMiss()} y`).some((f) => f.rule === d.id) };
  return { kinds, secrets };
}
export const selfCheckOk = (r) => [...Object.values(r.kinds), ...Object.values(r.secrets)].every((x) => x.valid && !x.nearMiss);
