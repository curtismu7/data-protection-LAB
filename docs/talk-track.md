# Talk track

<!-- Generated from server/src/data.js by `npm run talk-track`. Do not edit by hand. -->

> Ping release claim, UNVERIFIED on our tenant: every product claim here comes from the Ping ID4AI Workforce H2 2026 deck, slides 35, 50 and 53 to 55 (release 2026-11-02).

## Say this first

Everything on this page is simulated, and every product claim is a Ping release claim, unverified on our tenant: the 2026-11-02 release is not there yet. The detection is the lab's own small stand-in. The thing worth seeing is the shape of the control: graduated outcomes, your own rules, and prompts sealed to a key only you hold.

## Graduated, not all-or-nothing

A policy turns a finding's score into one of four outcomes: allow, alert, sanitize or block, with thresholds per category and overrides per key or per application. Sanitize redacts only the offending span and forwards the rest. Try the Detect tab in Live and move a threshold to see the outcome change. The same words typed by the user and returned by a tool are scored differently, because the second is a channel the user never saw.

## Personal data, your way

The release goes from 5 kinds of personal data to 23, each numeric kind checksum-validated and selectable on its own. The lab does not know that list, so it ships its own eleven as an illustration. Each numeric one has a real checksum and a near miss that must not fire: a card number with one digit wrong is not a card number. Switch kinds off one at a time and watch the findings change.

## Paste your own rules

Rules paste in unchanged in gitleaks rule format. One bad rule refuses the whole paste and the errors list each refused rule, one per line, so nothing is half-applied. The regular expression is user-supplied, so the lab refuses nested quantifiers, backreferences and lookaround up front, and runs every pattern in a separate process that is killed if it runs over its time limit. Paste the hostile sample and watch it refused. A new rule starts in observe: it records what it would have caught and changes nothing until you promote it.

## Sealed to a key only you hold

Generate a key pair in the browser; the private half never leaves this page. Paste the public half as the tenant's PublicKey and the server seals each record to it with an ephemeral key, HKDF and AES-GCM. Who, which agent, which application, what was detected and what was decided stay in the clear and searchable. The content stays sealed until you load the private key and open that one record, and the decryption happens in your browser. A record you never open is never decrypted anywhere. Nothing is recorded without a public key. The envelope format is the lab's own invention.

## One place to ask what happened

Agent Insights puts Guard results, Alerts and the prompt record in one place, filterable by agent, application, category, decision, flow and event, over a live view or a window from 24 hours to 30 days. The compliance view cross-references each finding to OWASP, MITRE ATLAS and NIST AI RMF labels. The labels here are the lab's illustrations, not Ping's catalogue.

## The OWASP Agentic Top 10, as qualified

Each category maps to a control. The deck states its own gaps and the table repeats them rather than rounding up: fingerprint pinning for the supply chain is pending, memory-write inspection is shipped but the gateway integration is in progress, and the cascading-failure, human-trust and rogue-agent rows carry notes. Do not present those rows as full coverage.

## Why it matters: AIGuard (Ping claim, slide 53)

Challenge: authorization cannot see content, so an agent following hidden instructions in a retrieved document can exfiltrate data entirely within policy; this blind spot is what security review flags on every agent rollout. Technical: content is inspected in and out on MCP, A2A, LLM and coding-agent traffic, and deterministic rules add no availability dependency. Business: a fraction of the cost of one incident, and framework-mapped evidence for AI governance sign-off. Ping claims, unverified on our tenant.

## Why it matters: Agent Insights (Ping claim, slide 54)

Challenge: enforcement is only half of an investigation; decisions and detections scatter across surfaces, so what happened takes days to answer and incidents stay open. Technical: one record set across every gateway surface, with sealed prompt content and clear-text searchable metadata. Business: incidents close faster, and assessor requests leave in the shape they were asked for, which means less investigation effort and shorter audits. Ping claims, unverified on our tenant.

## Why it matters: Prompt Logging (Ping claim, slide 50)

Challenge: prompts and responses are exactly the content an investigation needs and exactly the content a vendor should not be able to read, so teams refuse retention that hands the vendor the content and investigations stall. Technical: content sealed to your public key and decrypted only in your console session, with Privilege never holding the private half. Business: full forensic retention becomes acceptable to security and legal, and investigations get the record without a data-trust concession. Ping claims, unverified on our tenant.

## Why it matters: OWASP Agentic AI Top 10 (Ping claim, slide 55)

Challenge: security review now demands precise answers against the OWASP ASI taxonomy, and vague coverage claims stall approval and procurement. Technical: each ASI category maps to a named control and mechanism, with the ASI08, ASI09 and ASI10 coverage notes stated plainly. Business: framework-mapped answers accelerate security approval and de-risk the purchase. Ping claims, unverified on our tenant.

## Mock and Live

Mock is a set of tables generated from the same engine, with a test that fails if they drift. Live is the real local engine on your own text: real checksums, real rule matching in a child process, real sealing. Typed credentials and personal data are masked in every response, so nothing you try is echoed back. Still nothing leaves the machine.

## What is not proven

None of the product behaviour here has been run on our tenant. Field names such as PIIKinds, the three thresholds, the custom-rule fields and the prompt-log settings come from the console schema of 2026-10-31, schema only. The detection rules, scores, default thresholds, the envelope format, the framework labels and the sets of kinds and secret detectors are the lab's own. The external-guardrail layer is not built.

## The seven actions on the Detect tab

1. **An ordinary request** (allow by the default policy). Nothing sensitive. No rule fires, the content goes through, and the inspection still appears in Agent Insights with the person and the agent behind it.
2. **Contact details in a prompt** (alert by the default policy). An e-mail address and a telephone number are personal data, but low risk by default: the score reaches the alert threshold and not the sanitize one. The prompt goes through and the alert is recorded.
3. **A card number and an identifier** (sanitize by the default policy). Both numbers pass their checksum, so both are real findings. The policy says sanitize: each offending span is redacted and the rest of the prompt is forwarded. A number that fails its checksum would not have fired.
4. **An instruction override typed by the user** (sanitize by the default policy). A direct injection scores 0.75: above the sanitize threshold, below block. The offending phrase is redacted and the rest forwarded. Compare the next action, where the very same words arrive from somewhere else.
5. **Hidden instructions in a tool result** (block by the default policy). The words are the same family as the last action, but this content came back from a tool: a channel the user never typed and never saw. It scores higher (indirect injection), and the hidden comment fires a second rule. The result is withheld.
6. **A credential in a prompt** (block by the default policy). The credential matches a secret detector (a prefix, a length and an entropy floor). Secrets are blocked outright by default, so it never reaches the model. This one is the labelled mock credential; anything real you type in Live is masked everywhere.
7. **A model output that smuggles data in an image link** (block by the default policy). Inspection runs on the way out as well as in. A markdown image whose address carries a query string is a classic way to leak data when the page renders it. Blocked on output.

## Not demonstrated

- External guardrail and "bring your own model" (a second, model-based layer behind an HTTP contract): named by the deck, needs a model, not built here.
- The 23 personal-data kinds, the 364 secret detectors and the 411 rules: the deck's numbers and sets are Ping's; this lab ships its own small illustrative sets and does not reproduce or guess Ping's lists.
- Archive beyond 30 days, the versioned compliance catalogue held in code, and framework tags on every policy denial: the lab's framework mappings are illustrative labels only.
- Anything about how the real gateway, console or tenant behaves: nothing here ran against one.
