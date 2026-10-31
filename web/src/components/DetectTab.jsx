import { useCallback, useEffect, useState } from "react";
import { getJson, postJson } from "../api";
import { visible } from "../safeText";
import { CategoriesTable, ClaimTag, FieldSources, FindingsTable, Hops, Json, SourceTag, TierTag, Verdict, useSeq } from "./Bits";
import PolicyPanel, { scopeParts } from "./PolicyPanel";

const TEXT_LIMIT = 20000;
const FRAME_LIMIT = 20;
const FRAME_CHARS = 2000;

export function ResultView({ r }) {
  const ev = r.evaluation;
  return (
    <div className="stack" data-testid="result">
      <div className="cols">
        <section className="panel" aria-label="The outcome">
          <h3 className="panel__sub">Outcome <span className="tag">{r.role} / {r.surface} / {r.direction === "in" ? "going in" : "coming out"}</span></h3>
          <Verdict evaluation={ev} />
          <CategoriesTable categories={ev.categories} />
        </section>
        <section className="panel" aria-label="What is forwarded">
          <h3 className="panel__sub">What is forwarded</h3>
          <p className="muted">A display copy: a redacted span reads [REDACTED:category]; any other detected value is masked for display. The value itself is never in a response.</p>
          <Json value={ev.forwarded ? ev.text : `(withheld) ${ev.text}`} label="forwarded text" testId="forwarded-text" />
          {r.record && <p data-testid="record-note">Sealed record <code>{r.record.id}</code> stored under key <code>{visible(r.record.kid)}</code> ({r.record.bytes} bytes{r.record.truncated ? ", cut to MaxBytes" : ""}). Open it on the Prompt logging tab with your private key.</p>}
          {!r.record && r.recordSkipped && r.mode === "live" && <p className="muted" data-testid="record-skipped">Not recorded: {r.recordSkipped}.</p>}
          {r.notes.map((n) => <p key={n} className="muted">{visible(n)}</p>)}
        </section>
      </div>
      <FindingsTable findings={ev.findings} />
      <Hops hops={r.hops} traceId={r.traceId} />
    </div>
  );
}

function StreamPanel({ story, mode, policy, scope, resetSignal }) {
  const live = mode === "live";
  const [res, setRes] = useState(null);
  const [error, setError] = useState(null);
  const [own, setOwn] = useState("");
  const guard = useSeq();
  const sc = scopeParts(scope);
  const run = useCallback((frames) => {
    const ok = guard();
    postJson("/api/stream", { mode, vertical: story.vertical, policy, scope: { ...(sc[0] === "key" ? { key: sc[1] } : {}), ...(sc[0] === "app" ? { app: sc[1] } : {}) }, ...(frames ? { frames } : {}) }).then(({ ok: good, body }) => {
      if (!ok()) return;
      if (good) { setRes(body); setError(null); } else { setRes(null); setError(`${body.error}: ${body.detail || ""}`); }
    }, () => { if (ok()) setError("request failed"); });
  }, [mode, story.vertical, policy, scope]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { setRes(null); setError(null); }, [mode, story.vertical, resetSignal]);
  const frames = own.split(/\n---\n/).map((f) => f.replace(/^\n+|\n+$/g, "")).filter((f) => f.length);
  const tooMany = frames.length > FRAME_LIMIT || frames.some((f) => f.length > FRAME_CHARS);
  return (
    <section className="panel" aria-label="Streamed response" data-testid="stream">
      <h3 className="panel__sub">A streamed MCP response, frame by frame <ClaimTag label={story.claimLabel} /></h3>
      <p className="lesson">{story.stream.lesson}</p>
      <div className="scroll"><table className="tbl tbl--wide">
        <thead><tr><th>Frame</th><th>Text sent by the server</th><th>Outcome</th><th>What the client receives</th></tr></thead>
        <tbody>{story.stream.frames.map((f, i) => {
          const fr = res && !res.frames ? null : res?.frames?.[i];
          return (
            <tr key={i}><td>{i + 1}</td><td>{visible(f)}</td>
              <td>{fr ? <TierTag tier={fr.decision} /> : <span className="muted">not run</span>}</td>
              <td data-testid={`frame-${i + 1}`}>{fr ? (fr.withheld ? <b>withheld: the session continues</b> : visible(fr.text)) : ""}</td></tr>
          );
        })}</tbody>
      </table></div>
      <div className="toggles"><button type="button" className="primary" onClick={() => run(null)} data-testid="stream-run">Run the stream</button></div>
      {res?.summary && <p data-testid="stream-summary">Frames: {res.summary.total}; forwarded {res.summary.forwarded}; redacted {res.summary.redacted}; withheld {res.summary.withheld}; the session continues.</p>}
      <details>
        <summary>Your own frames {live ? "" : "(Live mode only)"}</summary>
        {!live ? <p className="muted" data-testid="stream-needs-live">Mock mode only has the scripted stream. Switch to Live to type frames.</p> : (
          <div className="form">
            <label>Frames, separated by a line containing only ---: at most {FRAME_LIMIT} frames of {FRAME_CHARS} characters
              <textarea rows={5} value={own} onChange={(e) => setOwn(e.target.value)} data-testid="stream-own" />
            </label>
            {tooMany && <p className="field-error" role="alert">At most {FRAME_LIMIT} frames of {FRAME_CHARS} characters.</p>}
            <button type="button" className="primary" disabled={!frames.length || tooMany} onClick={() => run(frames)} data-testid="stream-own-run">Run my frames</button>
          </div>
        )}
      </details>
      {error && <p className="field-error" role="alert" data-testid="stream-error">{visible(error)}</p>}
      {res && <Hops hops={res.hops} traceId={res.traceId} />}
    </section>
  );
}

function KindsPanel({ story, mode, resetSignal }) {
  const [check, setCheck] = useState(null);
  const guard = useSeq();
  useEffect(() => { const ok = guard(); setCheck(null); getJson(`/api/selfcheck?mode=${mode}`).then((j) => { if (ok()) setCheck(j); }, () => {}); }, [mode, resetSignal]); // eslint-disable-line react-hooks/exhaustive-deps
  const cell = (c) => (c ? <><TierTag tier={c.valid ? "allow" : "block"} /> {c.valid ? "valid sample found" : "MISSED"}; {c.nearMiss ? <b>near miss fired (bug)</b> : "near miss ignored"}</> : <span className="muted">checking...</span>);
  return (
    <section className="panel" aria-label="Kinds and detectors" data-testid="kinds">
      <h3 className="panel__sub">Personal-data kinds <SourceTag source="invented" /></h3>
      <p className="muted" data-testid="kinds-note">A lab-written ILLUSTRATIVE set of {story.piiKinds.length} kinds. The deck says the release goes from {story.deck.piiKindsBefore} kinds to {story.deck.piiKindsAfter}; the lab does not know that list and does not reproduce it. Each numeric kind has a real checksum, and a near miss that must not match. {mode === "live" ? "Live: checked now by the engine." : "Mock: read from the generated table."} The sample values are synthetic and belong to no one.</p>
      <div className="scroll"><table className="tbl tbl--wide" data-testid="kinds-table">
        <thead><tr><th>Kind (PIIKinds id)</th><th>Group</th><th>Validation</th><th>Synthetic sample</th><th>Self-check</th></tr></thead>
        <tbody>{story.piiKinds.map((k) => (
          <tr key={k.id}><td><code>{k.id}</code><div className="muted">{k.label}</div></td><td>{k.group}</td><td>{k.validation}</td><td><code>{k.sample}</code></td><td data-testid={`kc-${k.id}`}>{cell(check?.kinds?.[k.id])}</td></tr>
        ))}</tbody>
      </table></div>
      <h3 className="panel__sub">Secret and credential detectors <SourceTag source="invented" /></h3>
      <p className="muted" data-testid="secrets-note">Lab examples: {story.secretDetectors.length} detectors written here (prefix, length, an entropy floor, an allowlist, a value group). The deck says {story.deck.secretDetectors}, and {story.deck.rules} maintained rules ({story.deck.behavioural} behavioural); the lab holds neither set and copies no third-party rule list. The test credentials are built on the server at run time and never sent to this page: only the two results below are.</p>
      <div className="scroll"><table className="tbl tbl--wide" data-testid="secrets-table">
        <thead><tr><th>Detector</th><th>What it matches</th><th>Entropy floor / allowlist</th><th>Self-check</th></tr></thead>
        <tbody>{story.secretDetectors.map((d) => (
          <tr key={d.id}><td><code>{d.id}</code></td><td>{visible(d.description)}<div className="muted"><code>{visible(d.pattern)}</code></div></td><td>{d.entropy || "none"} / {d.allowlist.length ? "yes" : "none"}</td><td data-testid={`sc-${d.id}`}>{cell(check?.secrets?.[d.id])}</td></tr>
        ))}</tbody>
      </table></div>
    </section>
  );
}

export default function DetectTab({ story, mode, policy, setPolicy, resetSignal }) {
  const live = mode === "live";
  const [scenario, setScenario] = useState(story.scenarios[0].id);
  const [custom, setCustom] = useState({ text: "", role: "user_prompt", surface: "llm" });
  const [useCustom, setUseCustom] = useState(false);
  const [submitted, setSubmitted] = useState(null);
  const [scope, setScope] = useState("tenant");
  const [res, setRes] = useState(null);
  const [error, setError] = useState(null);
  const [policyError, setPolicyError] = useState(null);
  const guard = useSeq();
  const customOn = useCustom && live;
  const sc = story.scenarios.find((s) => s.id === scenario);
  const [kind, id] = scopeParts(scope);

  const run = useCallback((c) => {
    const ok = guard();
    const body = { mode, vertical: story.vertical, policy, scope: { ...(kind === "key" ? { key: id } : {}), ...(kind === "app" ? { app: id } : {}) }, labels: story.labels, ...(c ? { custom: c } : { scenario }) };
    postJson("/api/evaluate", body).then(({ ok: good, body: b }) => {
      if (!ok()) return;
      if (good) { setRes(b); setError(null); setPolicyError(null); } else if (b.error === "bad_policy") { setPolicyError(b.errors.map((e) => `${e.field}: ${e.message}`).join("; ")); } else { setRes(null); setError(`${b.error}: ${b.detail || ""}`); }
    }, () => { if (ok()) setError("request failed"); });
  }, [mode, scenario, story.vertical, policy, scope]); // eslint-disable-line react-hooks/exhaustive-deps

  // A policy, scope or mode change re-runs whatever was last judged (the scripted action, or the text you last submitted).
  useEffect(() => { setRes(null); if (customOn && submitted) run(submitted); else if (!customOn) run(null); }, [run, customOn, submitted, resetSignal]);
  useEffect(() => { if (!live) { setScope("tenant"); setUseCustom(false); } }, [live]);

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel__title">Detect: content inspected in and out <ClaimTag label={story.claimLabel} /></h2>
        <p className="muted" data-testid="detect-mode-note">{live ? "Live: the real local engine inspects the action or your own text: real checksums, real rule matching (pasted rules run in a child process), and real sealing if prompt logging is set up. Nothing leaves this machine." : "Mock: the outcome comes from a table generated from the same engine, under the default policy. Switch to Live to edit the policy, type your own text and use your own rules."}</p>
        <p className="muted" data-testid="limits">{story.limitsText}</p>
        <h3 className="panel__sub">Action</h3>
        <div className="seg" role="group" aria-label="Action">
          {story.scenarios.map((s) => <button key={s.id} type="button" aria-pressed={!customOn && scenario === s.id} onClick={() => { setUseCustom(false); setScenario(s.id); }} data-testid={`sc-${s.id}`}>{s.title}</button>)}
        </div>
        {!customOn && (
          <>
            <p className="lesson" data-testid="lesson">{sc.lesson} <span className="tag">{sc.role}</span> <span className="tag">{sc.surface}</span></p>
            <p className="muted">The text below is synthetic: the numbers are generated from each kind&apos;s checksum and belong to no one; the credential is the labelled mock one.</p>
            <Json value={sc.text} label="the action text" testId="action" />
          </>
        )}
        <details open={customOn}>
          <summary>Your own text {live ? "" : "(Live mode only)"}</summary>
          {!live ? <p className="muted" data-testid="custom-needs-live">Mock mode only has tables for the scripted actions. Switch to Live to type your own text: it is judged by the real engine and never echoed back.</p> : (
            <form className="form" onSubmit={(e) => { e.preventDefault(); setUseCustom(true); setSubmitted({ ...custom }); }}>
              <label>Where the content came from (role)
                <select value={custom.role} onChange={(e) => setCustom({ ...custom, role: e.target.value })} data-testid="custom-role">{story.roles.map((r) => <option key={r.id} value={r.id}>{r.label} ({r.direction === "in" ? "going in" : "coming out"})</option>)}</select>
              </label>
              <label>Surface (flow)
                <select value={custom.surface} onChange={(e) => setCustom({ ...custom, surface: e.target.value })} data-testid="custom-surface">{story.surfaces.map((s) => <option key={s} value={s}>{s}</option>)}</select>
              </label>
              <label>Text (at most {TEXT_LIMIT} characters; shown nowhere in the answer: a detected value is masked)
                <textarea rows={4} value={custom.text} maxLength={TEXT_LIMIT} onChange={(e) => setCustom({ ...custom, text: e.target.value })} data-testid="custom-text" />
              </label>
              <p className="muted">{custom.text.length} of {TEXT_LIMIT} characters.</p>
              <button type="submit" className="primary" data-testid="custom-run" disabled={!custom.text.trim()}>Inspect my text</button>
            </form>
          )}
        </details>
      </section>
      {error && <p className="field-error" role="alert" data-testid="eval-error">Could not run ({visible(error)}).</p>}
      {res ? <ResultView r={res} /> : !error && <p className="muted">{customOn ? "Type some text and press Inspect." : "Loading..."}</p>}
      <PolicyPanel story={story} policy={policy} setPolicy={setPolicy} scope={scope} setScope={setScope} live={live} error={policyError} />
      <StreamPanel story={story} mode={mode} policy={policy} scope={scope} resetSignal={resetSignal} />
      <KindsPanel story={story} mode={mode} resetSignal={resetSignal} />
      <FieldSources fields={story.fieldSources} />
    </div>
  );
}
