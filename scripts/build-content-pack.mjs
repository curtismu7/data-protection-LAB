// Builds content-pack.json for the Learning Hub from the story data, so the pack cannot drift from the lab.
//   node scripts/build-content-pack.mjs        (writes content-pack.json)
// The pack uses .invalid placeholders and no documentation URLs.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CAST } from '../server/src/cast.js';
import { buildStory } from '../server/src/story.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { version } = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const UNV = 'Ping release claim, UNVERIFIED on our tenant.';

export function buildPack() {
  const story = buildStory(DEFAULT_CAST, 'finance');
  const sid = (n) => `S${String(n).padStart(2, '0')}`;
  const terms = {
    ordinary: ['aiguard', 'agent-insights'], contact: ['graduated-response', 'personal-data-kinds'], 'card-and-id': ['sanitize', 'personal-data-kinds', 'checksum'],
    'direct-injection': ['sanitize', 'indirect-injection'], 'indirect-injection': ['indirect-injection', 'graduated-response'], secret: ['secret-detectors', 'graduated-response'], 'exfil-image': ['aiguard', 'graduated-response'],
  };
  const why = (id) => story.talkTrack.find((t) => t.id === id).say;
  return {
    schema: 'demo-content-pack/1',
    id: 'data-protection-lab',
    title: 'Data Protection LAB',
    version,
    demo: { id: 'data-protection-lab', name: 'Data Protection LAB', catalog: 'D103', baseUrl: 'http://localhost:7200', doctor: '/api/health', tags: ['aiguard', 'data-protection', 'prompt-logging', 'agent-insights', 'owasp-agentic', 'gitleaks', 'simulated'] },
    glossary: [
      { id: 'aiguard', term: 'AIGuard', definition: `Content inspection in and out across MCP, A2A, LLM and coding-agent traffic, for the attacks identity controls cannot see. In this lab: the lab's own deterministic stand-in. ${UNV}`, aliases: ['content inspection'] },
      { id: 'graduated-response', term: 'Graduated response', definition: `Four outcomes per policy: allow, alert, sanitize or block, with thresholds per category and overrides per key or per application. A threshold of 0 turns that outcome off. ${UNV}`, aliases: ['thresholds'] },
      { id: 'sanitize', term: 'Sanitize', definition: `Redact the offending span and forward the rest of the content, instead of blocking all of it. ${UNV}`, aliases: ['redact'] },
      { id: 'indirect-injection', term: 'Indirect injection', definition: `Instructions that arrive in content the user never typed: a tool result, a retrieved document, a peer agent's message. The same words score higher than when typed by the user, because it is a channel the user never sees. ${UNV}`, aliases: ['hidden instructions in a document'] },
      { id: 'personal-data-kinds', term: 'Personal-data kinds', definition: `The release goes from 5 kinds of personal data to 23, each numeric kind checksum-validated and selectable per kind (PIIKinds, console swagger name). The lab ships its OWN illustrative set of eleven, not Ping's list. ${UNV}`, aliases: ['PIIKinds'] },
      { id: 'checksum', term: 'Checksum validation and the near miss', definition: 'A numeric kind is only a finding if its checksum holds (Luhn, mod 97, mod 11, a weighted sum, a check letter). A card number with one digit wrong is a near miss and must not match. Each lab kind has a test for it.', aliases: ['near miss'] },
      { id: 'secret-detectors', term: 'Secret detectors', definition: `Detectors for credentials by prefix, length, entropy floor and allowlist. The deck says 364 and 411 maintained rules (47 behavioural); the lab ships fifteen of its own, labelled lab examples. ${UNV}`, aliases: ['gitleaks rules'] },
      { id: 'rule-import', term: 'Your own rules (rule import)', definition: `Rules paste in gitleaks rule format. One bad rule refuses the whole paste and the Errors list names each refused rule, one per line (imodelAIGuardRuleImport {Toml, Added, Errors}, console swagger names, 2026-10-31, schema only). ${UNV}`, aliases: ['AIGuardRuleImport'] },
      { id: 'redos-guard', term: 'ReDoS guard', definition: 'A pasted regular expression is user-fed, so it is checked up front for nested quantifiers, backreferences, lookaround and huge repeat counts, and only ever runs in a separate child process that is killed (SIGKILL) if it runs over its time limit, with a capped heap and an input cap.', aliases: ['catastrophic backtracking'] },
      { id: 'observe-mode', term: 'Observation only (Alerts)', definition: `A policy records what it would have caught without changing the outcome, so a rule can be authored, watched, and promoted to enforcement once the false-positive rate is known. In this lab a new rule starts in observe (lab-invented). ${UNV}`, aliases: ['watch-only'] },
      { id: 'prompt-logging', term: 'Prompt logging, sealed to your key', definition: `Prompts and responses retained under a public key you supply; only your private key opens them, entered in the console when you read a record; Privilege never holds it. Off until a tenant asks; nothing is recorded without a public key (modelPromptLogConfig, console swagger names). ${UNV}`, aliases: ['PromptLog'] },
      { id: 'sealed-envelope', term: 'The lab\'s sealing envelope', definition: 'Ephemeral X25519 key agreement, HKDF-SHA256 and AES-256-GCM, in an envelope {v, kid, rid, epk, nonce, ct}. The envelope format is LAB-INVENTED: the product\'s format is not public.', aliases: ['seal'] },
      { id: 'browser-decrypt', term: 'Decryption in the browser', definition: `A sealed record is decrypted in the console itself, at the moment you open it, with a private key you supply then. The lab generates the key pair in the browser with WebCrypto; the private half is never sent, never stored by default and never logged. ${UNV}`, aliases: ['WebCrypto'] },
      { id: 'agent-insights', term: 'Agent Insights', definition: `Guard (every inspection result with the category, the corroborating rule, the direction, the decision and the agent and person behind it), Alerts (observation only) and Prompts (the sealed record list), filterable by agent, application, category, decision, flow and event. ${UNV}`, aliases: ['Guard', 'Alerts', 'Prompts'] },
      { id: 'compliance-mapping', term: 'Compliance mapping', definition: 'Each finding cross-referenced to OWASP LLM Top 10, the OWASP Agentic Top 10, MITRE ATLAS and NIST AI RMF labels. In this lab the labels are lab-illustrative, not Ping\'s versioned catalogue.', aliases: [] },
      { id: 'owasp-asi', term: 'OWASP Agentic AI Top 10 (ASI01 to ASI10)', definition: `Each category maps to a named control, with the deck's own gaps stated: ASI04 fingerprint pinning pending, ASI06 memory-write inspection shipped with gateway integration in progress, and notes on ASI08, ASI09 and ASI10. ${UNV}`, aliases: ['ASI'] },
    ],
    sources: [
      { id: 'deck-slides', title: 'Ping ID4AI Workforce H2 2026 deck, slides 35, 50, 53, 54 and 55', url: 'https://example.invalid/ping-id4ai-workforce-h2-2026-deck', kind: 'deck', use: 'The data-protection release claims.', status: 'read', checked: '2026-10-31' },
      { id: 'console-swagger', title: 'Privilege console swagger, 2026-10-31 (schema only)', url: 'https://example.invalid/privilege-console-swagger', kind: 'schema', use: 'Field names for PIIKinds, the category thresholds, the custom rule, the rule import and the prompt-log settings. It proves names exist, not behaviour.', status: 'read', checked: '2026-10-31' },
    ],
    cards: [
      ...story.scenarios.map((sc, i) => ({ id: `try-${sc.id}`, label: `Action ${i + 1}: ${sc.title}`, description: sc.lesson, group: 'try-it', action: { type: 'route', href: '/#detect' }, terms: terms[sc.id], story: sid(i + 1) })),
      { id: 'try-rules', label: 'Paste your own rules', description: 'One bad rule refuses the whole paste; a hostile pattern is refused before it can run.', group: 'try-it', action: { type: 'route', href: '/#rules' }, terms: ['rule-import', 'redos-guard', 'observe-mode'] },
      { id: 'try-promptlog', label: 'Seal a prompt to your own key', description: 'Make a key in the browser, record a prompt sealed to it, open it with the private key; try the wrong key.', group: 'try-it', action: { type: 'route', href: '/#promptlog' }, terms: ['prompt-logging', 'sealed-envelope', 'browser-decrypt'] },
      { id: 'try-insights', label: 'Ask what happened', description: 'Guard, Alerts and Prompts with filters over a live view or a window of 24 hours to 30 days.', group: 'try-it', action: { type: 'route', href: '/#insights' }, terms: ['agent-insights', 'compliance-mapping', 'observe-mode'] },
      { id: 'try-owasp', label: 'The OWASP Agentic Top 10, as qualified', description: 'The deck\'s own gaps repeated exactly, never rounded up to full coverage.', group: 'try-it', action: { type: 'route', href: '/#owasp' }, terms: ['owasp-asi'] },
      { id: 'concept-why-aiguard', label: 'Why it matters: AIGuard (slide 53)', description: why('why-aiguard'), group: 'concept', action: { type: 'route', href: '/#talk' }, terms: ['aiguard', 'graduated-response'] },
      { id: 'concept-why-insights', label: 'Why it matters: Agent Insights (slide 54)', description: why('why-insights'), group: 'concept', action: { type: 'route', href: '/#talk' }, terms: ['agent-insights'] },
      { id: 'concept-why-prompt-logging', label: 'Why it matters: Prompt Logging (slide 50)', description: why('why-prompt-logging'), group: 'concept', action: { type: 'route', href: '/#talk' }, terms: ['prompt-logging', 'browser-decrypt'] },
      { id: 'concept-why-owasp', label: 'Why it matters: OWASP Agentic AI Top 10 (slide 55)', description: why('why-owasp'), group: 'concept', action: { type: 'route', href: '/#talk' }, terms: ['owasp-asi'] },
      { id: 'concept-diagram', label: 'Diagrams', description: 'Two diagrams: content inspected in and out with a graduated answer; and prompts sealed to your key.', group: 'concept', action: { type: 'route', href: '/#diagram' }, terms: ['aiguard', 'sealed-envelope'] },
      { id: 'ref-doctor', label: 'Doctor and health', description: 'Preflight checks and the demo-health/1 endpoint.', group: 'setup', action: { type: 'route', href: '/api/health' } },
    ],
    stories: story.scenarios.map((sc, i) => ({ id: sid(i + 1), title: sc.title, say: sc.lesson })),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  fs.writeFileSync(path.join(ROOT, 'content-pack.json'), `${JSON.stringify(buildPack(), null, 2)}\n`);
  console.log('wrote content-pack.json');
}
