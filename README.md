# Data Protection LAB

A simulation of Ping's data-protection release claims: content inspected in and out with graduated outcomes, your own gitleaks-format rules, personal-data kinds with checksums, Agent Insights, the OWASP Agentic Top 10 as the deck qualifies it, and prompt logging sealed to a key that only your browser holds.

Tier: Demo
Repo: https://github.com/ping-sandbox/data-protection-LAB
Catalog: none assigned yet (the content pack carries the placeholder D0)

**Tier: Demo.** Source: the Ping ID4AI Workforce H2 2026 deck, slides 35, 50 and 53 to 55 (release 2026-11-02). **Every product claim is a Ping release claim, UNVERIFIED on our tenant.** Nothing here calls a real gateway, identity provider or tenant, and nothing leaves your machine.

## What is simulated

**Mock mode (default).** Everything runs offline in one process. Each outcome comes from a table generated from the lab's own engine (`server/src/mockTable.json`; a doctor check and a test fail if it drifts). The detection, the policy, the compliance labels and the sample data are the lab's own, and lab-invented. Nothing is sealed or opened in Mock: the Prompts list is a fixed set of placeholder records.

**Live mode (owner-run, still local).** The real local engine on your own text: real checksum validation, real rule matching (your pasted rules run in a separate child process that is killed if it runs over its time limit), and real sealing: you make an X25519 key pair in the browser, the server seals each record to the public half (ephemeral key, HKDF-SHA256, AES-256-GCM) and you open it in the browser with the private half. The banner says which mode you are in. Live never leaves loopback and never touches a tenant.

What it shows:

1. **Detect.** Seven scripted actions in three vertical packs, or your own text (Live): the category that fired, the corroborating rule, a score, and the graduated outcome (allow, alert, sanitize, block). Twelve categories from the deck plus the lab's own `secrets`. Thresholds per category are editable (Live), with per-key and per-application overrides; `PIIKinds` selects which personal-data kinds are looked for. Content from a tool result, a retrieved resource or a peer agent is scored higher than the same words typed by the user. A streamed MCP response is inspected frame by frame: a flagged frame is withheld and the session carries on. The kinds and secret-detector tables show each one's valid sample found and its near miss ignored.
2. **Your rules.** Paste rules in gitleaks rule format. One bad rule refuses the whole paste: nothing is added and `Errors` lists each refused rule, one per line (`imodelAIGuardRuleImport {Toml, Added, Errors}`). Every regular expression is checked up front (nested quantifiers, backreferences, lookaround, huge repeat counts, long patterns and more than 6 variable quantifiers (`?`, `*`, `+`, `{n,m}`) are refused) and only ever runs in a separate child process (empty environment, capped heap, its own netguard) that is killed with SIGKILL if a rule runs over 2 seconds, or an inspection over 4 seconds; a rule that runs out of time is disabled and reported, and each workspace has its own queue so one workspace's slow rule does not hold up another's. A new rule starts in observe and is promoted to enforcement.
3. **Prompt logging.** The tenant's `modelPromptLogConfig` (`Enabled`, `PublicKey`, `KeyID`, `Surfaces`, `IncludeResponses`, `MaxBytes`): nothing is recorded without a public key. Who, which agent, which application, what was detected and what was decided stay in the clear; the content opens only in your browser.
4. **Agent Insights.** Guard (every inspection result, with a compliance cross-reference to OWASP LLM Top 10, the OWASP Agentic Top 10, MITRE ATLAS and NIST AI RMF labels), Alerts (observation only, then promote) and Prompts (the sealed list), filtered by agent, application, category, decision, flow and event over a live view or a 24 hour, 7 day or 30 day window.
5. **OWASP Agentic Top 10.** ASI01 to ASI10 with the control that addresses each, including the deck's own stated gaps rendered as qualified: ASI04 fingerprint pinning is pending, ASI06 memory-write inspection is shipped and the gateway integration is in progress, and ASI08, ASI09 and ASI10 carry notes. None is shown as full coverage.
6. **Diagram.** ReactFlow, drawn from diagram-studio/1 data loaded by name: movable boxes, Simulate, speed, Reset (restores box positions). Two diagrams: inspection in and out; and prompts sealed to your key.
7. **Talk track,** with a "Why it matters" entry per feature (challenge, technical and business lines, marked as Ping claims). Also in `docs/talk-track.md`.

### What is lab-invented

The deck gives claims; the console swagger of 2026-10-31 (schema only) gives field names. Everything else here is the lab's own, and each field is tagged in the app as "console swagger name", "lab reading" or "lab-invented" (a swagger name proves a field exists, not how it behaves):

- **The personal-data kinds.** The deck says the release goes from 5 kinds to 23. The lab does not know that list and does not reproduce it, so it ships its own eleven (not Ping's list), labelled illustrative: SSN-shaped, Canadian SIN-shaped, Spanish DNI-shaped and UK NINO-shaped national ids; payment card (Luhn), IBAN (mod 97) and US routing number (weighted checksum); a health id (an NHS-number-shaped mod 11) and a date of birth after a label; e-mail and telephone. Each numeric kind has a real checksum and a near miss that must not match; the kinds without a checksum say so.
- **The secret detectors.** Fifteen lab-written examples (prefix, length, an entropy floor, an allowlist, a value group). The deck says 364 detectors and 411 maintained rules (47 behavioural); the lab holds neither set and copies no third-party rule list.
- **The detection rules, scores, default thresholds and the `secrets` category** (the schema has no category for secrets). `indirect_injection` is the deck's name for a case the schema has no key for.
- **The envelope.** `{ v: "lab-seal/1", kid, rid, epk, nonce, ct }` with HKDF salt `epk || recipient public key`, info `lab-seal/1|aes-256-gcm|<kid>` and AAD `lab-seal/1|<kid>|<rid>`. The product's sealing format is not public.
- **The observe/enforce flag on a pasted rule, the `cst-` prefix on its id, the per-key and per-application override structure and its precedence (key beats application beats tenant), the TOML key names (a reading of the gitleaks format), flow = surface and event = role.**
- **The framework labels** (OWASP LLM Top 10, ASI, MITRE ATLAS, NIST AI RMF per category) are illustrative, not Ping's versioned catalogue; verify before use.

### Known limits of the detection rules

The rules are the lab's own deterministic stand-ins, not Ping's detection. These are known gaps, not surprises:

- One text is at most 20000 characters (a longer one is refused, not cut). A stream is at most 20 frames of 2000 characters; the last 128 characters of each frame are carried into the next inspection, so a value split across two frames is seen, and a value split by more than 128 characters is not. A pasted rule file is at most 65536 characters and 50 rules (a workspace holds 50); a regular expression is at most 400 characters. A record is capped by `MaxBytes` (the default is 16384, at most 65536); a workspace keeps its latest 200 events and 100 sealed records.
- Phrase rules are a fixed English list matched on a normalised copy (case, whitespace and zero-width characters). Paraphrases and other languages are not seen. Hidden instructions are invisible or direction-changing characters and an HTML comment aimed at the model.
- Personal-data kinds need their shape: a number with spaces or dashes in unusual places, or an unlabelled date of birth, is not found. Kinds without a checksum (SSN-shaped, NINO-shaped, e-mail, telephone) can false-positive on look-alikes.
- Secrets are found by prefix and shape. An unlabelled password in prose, a short one, or a key split up is not found.
- The static regex check is conservative on purpose: a quantified group with alternatives (`(a|b)+`) is refused even though it can be safe, and so is a pattern with more than 6 variable quantifiers. Some patterns that pass it are still slow on 20000 characters (`.*.*.*x` is polynomial): the child process is killed at the time limit (2 seconds a rule, 4 seconds an inspection) and the rule is disabled for the rest of the workspace. The kill is SIGKILL of a separate process because a thread stuck inside the regex engine cannot be stopped.
- A value split across frames of a stream is found when the split is within the rolling 128 character tail of the whole stream (two, three or many frames). The lab forwards frames as they arrive, so the earlier parts of such a value were already forwarded when its last part arrives: the frame that completes it is withheld, and the displayed copies of the earlier frames are masked in the response. A real gateway could hold the tail back; the lab does not. A value split by more than 128 characters is not seen.
- The finders read a normalised copy (zero-width, bidirectional and tag characters dropped, whitespace runs collapsed, fullwidth forms folded), so those evasions do not hide a value, and the redaction lands on the right characters of the original. Pasted rules run on the raw text and get no such help.
- Detector coverage, stated so they are not surprises: Diners, JCB, Maestro, Discover 644 and UnionPay numbers are not recognised as cards; IBANs are checked for 9 countries only and a lowercase IBAN is missed; an NHS-shaped number with hyphens, UK domestic phone numbers (`020 ...`) and unformatted ten-digit phone numbers are missed; an SSN without separators is missed (nine bare digits are only a routing number if the checksum holds); `OA 12 34 56 C` style NINO prefixes are accepted where the real rules may refuse them; the e-mail check is structural; Slack `xoxe-` is covered but other token families are not. The numeric kinds can still match look-alikes that happen to satisfy the checksum.
- The response text sent with a prompt is sealed when `IncludeResponses` is on, and is not inspected.
- External guardrail and "bring your own model" (a model-based layer behind an HTTP contract) are named by the deck and are not built.

## Run from a clone

Prerequisites: Node 26 or newer. Docker only if you use the Docker form. Mock mode works with no setup at all: no tenant, no credentials, no settings file. The Prompt logging tab needs a browser with X25519 in WebCrypto (current Chrome, Edge, Safari or Firefox) and says so if yours has not.

```
git clone https://github.com/ping-sandbox/data-protection-LAB.git
cd data-protection-LAB
npm ci
npm run build
npm start
```

Open http://localhost:7200/. Or in one step: `./scripts/run.sh` (installs and builds if needed, runs the doctor, starts).

## Settings file

All standalone apps read one settings file, `~/Development/.env`, which must be mode 600. `STANDALONE_ENV` overrides its path. This lab needs none of it. It parses the file (`util.parseEnv`) and takes exactly one optional key; no other key from the file ever enters the server's environment (and the regex child process is started with an empty environment):

- `DPL_LAB_MODE` (optional): `mock` (default) or `live`, the mode the page opens in. The header toggle switches per visit. A bare `MODE` in the shared file is ignored, because it may belong to another app.

The shared file holds no `PORT`: the lab keeps its port default in code. Admin or worker credentials never belong in that file (they live in `~/.config/demo-kit/provisioning.json`), and this lab uses none. The doctor reports whether the file exists and its mode, and never prints a value.

## Ports, and what to do if the port is taken

```
Ports: data-protection-LAB listens on 7200 (set with PORT, default 7200).
Port range for this app: 7200-7249.

If the port is taken:
1. Find what is using it:
   lsof -iTCP:7200 -sTCP:LISTEN -n -P
2. If it is an old copy of this app, stop that process: kill <PID>.
3. If it is something else, stop it, or start this app on another port:
   PORT=<other port> npm start
4. Do not use 8080, 5173, 3000, 4000, 4400, 4510, 4600-4601, 18080, 19080 or 19090.
```

Other variables: `VITE_PORT` (Vite dev server, default 7201, `npm run dev -w web`), `HOST_PORT` (Docker host port, default 7200). Keep all of them inside 7200-7249.

## Mock and live modes

The header has a **Mock / Live** toggle on every page, and the banner and the mode chip show the same mode. Mock reads tables generated from the engine (the scripted actions, the stream, the three sample rule pastes, the kind and detector self-checks, and forty seeded Insights events per vertical) and is read-only for policy. Live runs the engine on whatever you give it, keeps this workspace's events, sealed records, prompt-log settings and pasted rules, and lets you edit the policy.

## Health, doctor and reset

```
npm run doctor   # 21 checks, including a real seal-then-open round trip; PORT=7209 npm run doctor to use a spare port
npm run reset    # clears the default workspace's events, sealed records, prompt-log settings and pasted rules (the UI Reset also restores the policy and the diagram)
```

`GET /api/health` returns `demo-health/1`. The workspace id comes in `X-Workspace`; every hop carries a W3C `traceparent`. Presenter mode: press `P` (Esc leaves); the simulation banner stays. `npm run mock-table`, `npm run talk-track` and `npm run content-pack` regenerate the generated files. Keys you generated in the page live in its memory only: Reset does not touch them, a reload forgets them. See `docs/safety.md`.

## Docker (optional)

```
HOST_PORT=7200 docker compose up --build -d
```

The container publishes to 127.0.0.1 only (a test pins it), runs as a non-root user with a read-only file system and no capabilities. Use OrbStack, not Docker Desktop. `DPL_LAB_MODE=live` opens the page in Live mode.

## Tests

```
npm test    # server (node --test), web (vitest, drives the UI against the real server), scripts
```

The shared checks are run by hand, because the scripts are not shipped into this repo's CI: `bash <AI-DEMO-Standalone>/scripts/check-drift.sh .`, `bash <AI-DEMO-Standalone>/scripts/check-css.sh .` and `node <demo-kit-base>/scripts/conformance.mjs . --new`. Conformance reports two rule-18 FAILs on purpose: the deferred SE k8s manifests, and a heuristic that greps for `process.env.MODE` (this lab reads `DPL_LAB_MODE` instead, because the shared settings file is read by every app).

On Node 26: 365 tests pass (310 server, 34 web, 21 scripts).

## Troubleshooting

- **The page says "Could not load the lab".** The server is not running, or it is on another port. Start it (`npm start`) and check `PORT`.
- **Port is taken.** See "Ports, and what to do if the port is taken" above.
- **`npm start` refuses to start.** Run `npm run doctor`; the first failing line says why (Node older than 26, a port outside 7200-7249, a drifting mock table).
- **"This browser does not support X25519 in WebCrypto".** Use a current Chrome, Edge, Safari or Firefox over `http://localhost` or https. The server can still seal; the page cannot make a key or open a record.
- **A record will not open.** The key you picked is not the one it was sealed to (the table shows each record's key name). Load the right private key, or choose it in the list beside Open.
- **The mock table is out of date after an engine change.** Run `npm run mock-table`; the doctor and a test tell you when it drifts.

## Ownership

- Owner: the Ping demo family owner (Demo tier).
- License: MIT (see `LICENSE`).
- Found a problem? Open an issue on the repo.

## Not done

No SE k8s build (deferred by the owner, 2026-10-31). No catalog id yet. Every product claim stays UNVERIFIED until it is measured on a tenant that has the release. The external-guardrail layer, Ping's list of 23 kinds, its 364 detectors and 411 rules, and the real product's sealing format are not reproduced.
