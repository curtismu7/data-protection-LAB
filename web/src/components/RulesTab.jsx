import { useCallback, useEffect, useState } from "react";
import { getJson, postJson } from "../api";
import { visible } from "../safeText";
import { ClaimTag, Json, SourceTag, useSeq } from "./Bits";

const TOML_LIMIT = 65536;

export function ImportResult({ r }) {
  const refused = r.Errors.length > 0;
  return (
    <section className="panel" aria-label="Import result" data-state={refused ? "bad" : "ok"} data-testid="import-result">
      <h3 className="panel__sub">imodelAIGuardRuleImport <SourceTag source="swagger" /></h3>
      {refused ? (
        <>
          <p data-testid="import-verdict"><b>The whole paste is refused. Nothing was added.</b> One line per refused rule:</p>
          <ul className="plain" data-testid="import-errors">{r.Errors.map((e, i) => <li key={i}>{visible(e)}</li>)}</ul>
        </>
      ) : (
        <>
          <p data-testid="import-verdict"><b>{r.Added.length} rule(s) added</b> to the profile, in observe mode (lab-invented): they record what they would have caught and change no outcome until you promote them.</p>
          <div className="scroll"><table className="tbl tbl--wide" data-testid="import-added">
            <thead><tr><th>ID</th><th>Category</th><th>Severity / score</th><th>Pattern</th><th>Keywords / entropy / group</th><th>Allowlist</th></tr></thead>
            <tbody>{r.Added.map((a) => (
              <tr key={a.ID}><td><code>{visible(a.ID)}</code><div className="muted">{visible(a.Description)}</div></td><td>{a.Category}</td><td>{a.Severity} / {a.Score}</td><td><code>{visible(a.Pattern)}</code></td>
                <td>{a.Keywords.map(visible).join(", ") || "none"} / {a.Entropy} / {a.ValueGroup}</td><td>{a.Allowlist.map(visible).join(", ") || "none"}</td></tr>
            ))}</tbody>
          </table></div>
        </>
      )}
      <details><summary>The Toml field (what you pasted, with detected values masked)</summary><Json value={r.Toml} label="pasted toml" testId="import-toml" /></details>
    </section>
  );
}

export default function RulesTab({ story, mode, resetSignal }) {
  const live = mode === "live";
  const [toml, setToml] = useState(story.ruleSamples[0].toml);
  const [res, setRes] = useState(null);
  const [error, setError] = useState(null);
  const [rules, setRules] = useState([]);
  const [busy, setBusy] = useState(false);
  const guard = useSeq();
  const listGuard = useSeq();

  const loadRules = useCallback(() => { const ok = listGuard(); getJson("/api/rules").then((j) => { if (ok()) setRules(j.rules); }, () => {}); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { setRes(null); setError(null); if (live) loadRules(); else setRules([]); }, [mode, resetSignal, loadRules, live]);

  const send = (body) => {
    const ok = guard(); setBusy(true);
    postJson("/api/rules/import", { mode, ...body }).then(({ ok: good, body: b }) => {
      if (!ok()) return;
      setBusy(false);
      if (good) { setRes(b); setError(null); if (live) loadRules(); } else { setRes(null); setError(`${b.error}: ${b.detail || ""}`); }
    }, () => { if (ok()) { setBusy(false); setError("request failed"); } });
  };
  const setEnforcement = (id, enforcement) => postJson("/api/rules/enforcement", { id, enforcement }).then(({ ok, body }) => { if (ok) setRules(body.rules); });
  const pick = (s) => { setToml(s.toml); if (!live) send({ sample: s.id }); };

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel__title">Your own rules, in gitleaks rule format <ClaimTag label={story.claimLabel} /></h2>
        <p className="muted" data-testid="rules-note">Paste rules and they are parsed (a small bounded TOML subset), checked and added. <b>One bad rule refuses the whole paste</b>: nothing is half-applied, and Errors lists each refused rule on its own line. The regular expression is user-supplied, so it is checked up front (nested quantifiers, backreferences, lookaround, huge repeat counts and long patterns are refused) and then only ever runs in a worker thread with a hard time limit and an input cap. TOML key names are a lab reading of the gitleaks format <SourceTag source="reading" />. At most {story.limits.toml.rules} rules and {story.limits.toml.bytes} characters per paste; {story.limits.rules.rulesPerWorkspace} rules per workspace.</p>
        <div className="seg" role="group" aria-label="Sample pastes">
          {story.ruleSamples.map((s) => <button key={s.id} type="button" onClick={() => pick(s)} data-testid={`sample-${s.id}`}>{s.title}</button>)}
        </div>
        {!live ? <p className="muted" data-testid="rules-needs-live">Mock: the three sample pastes are tables generated from the real parser. Switch to Live to paste your own.</p> : null}
        <label>Rules (TOML)
          <textarea rows={14} value={toml} readOnly={!live} maxLength={TOML_LIMIT} onChange={(e) => setToml(e.target.value)} data-testid="toml" />
        </label>
        <p className="muted">{toml.length} of {TOML_LIMIT} characters.</p>
        {live && <button type="button" className="primary" onClick={() => send({ toml })} disabled={busy || !toml.trim()} data-testid="import">Import the rules</button>}
      </section>
      {error && <p className="field-error" role="alert" data-testid="import-error">Could not import ({visible(error)}).</p>}
      {res && <ImportResult r={res} />}
      <section className="panel" aria-label="Rules in this workspace">
        <h3 className="panel__sub">Rules in this workspace ({rules.length})</h3>
        <p className="muted">A new rule starts in <b>observe</b> (lab-invented): it records what it would have caught in Agent Insights, Alerts, and changes no outcome. Promote it to enforcement once you know its false-positive rate. Try it on the Detect tab with your own text.</p>
        {rules.length === 0 ? <p className="muted" data-testid="no-rules">{live ? "No rules yet." : "Rules exist in Live mode only."}</p> : (
          <div className="scroll"><table className="tbl tbl--wide" data-testid="rules-list">
            <thead><tr><th>ID</th><th>Category</th><th>Score</th><th>Mode</th><th /></tr></thead>
            <tbody>{rules.map((r) => (
              <tr key={r.ID}><td><code>{visible(r.ID)}</code></td><td>{r.Category}</td><td>{r.Score}</td><td><span className="tag" data-state={r.enforcement === "enforce" ? "bad" : "warn"}>{r.enforcement}</span></td>
                <td>{r.enforcement === "observe"
                  ? <button type="button" onClick={() => setEnforcement(r.ID, "enforce")} data-testid={`promote-${r.ID}`}>Promote to enforcement</button>
                  : <button type="button" onClick={() => setEnforcement(r.ID, "observe")} data-testid={`demote-${r.ID}`}>Back to observe</button>}</td></tr>
            ))}</tbody>
          </table></div>
        )}
      </section>
    </div>
  );
}
