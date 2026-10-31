import { useCallback, useEffect, useState } from "react";
import { getJson, postJson } from "../api";
import { visible } from "../safeText";
import { ClaimTag, FieldSources, SourceTag, TierTag, useSeq } from "./Bits";
import RecordsList from "./RecordsList";

const SUBS = [["guard", "Guard"], ["alerts", "Alerts"], ["prompts", "Prompts"]];
const WINDOWS = [["live", "Live view (newest 25)"], ["24h", "Last 24 hours"], ["7d", "Last 7 days"], ["30d", "Last 30 days"]];
const FILTER_LABEL = { agent: "Agent", app: "Application", category: "Category", decision: "Decision", flow: "Flow", event: "Event" };

const when = (e) => (e.at ? new Date(e.at).toLocaleString() : `${e.ageH} h ago`);

function FrameworkCells({ f }) { return f ? <>{f.asi}; {f.owaspLlm.split(" ")[0]}</> : "-"; }

export default function InsightsTab({ story, mode, keyring, support, resetSignal }) {
  const live = mode === "live";
  const [sub, setSub] = useState("guard");
  const [win, setWin] = useState("30d");
  const [filters, setFilters] = useState({});
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [rules, setRules] = useState([]);
  const guard = useSeq(); const rg = useSeq();

  const load = useCallback(() => {
    const ok = guard();
    const q = new URLSearchParams({ mode, vertical: story.vertical, window: win, ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) });
    getJson(`/api/insights?${q}`).then((j) => { if (ok()) { setData(j); setError(null); } }, (e) => { if (ok()) setError(e.message); });
  }, [mode, story.vertical, win, filters]); // eslint-disable-line react-hooks/exhaustive-deps
  const loadRules = useCallback(() => { const ok = rg(); if (!live) { setRules([]); return; } getJson("/api/rules").then((j) => { if (ok()) setRules(j.rules); }, () => {}); }, [live]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { setData(null); load(); }, [load, resetSignal]);
  useEffect(() => { loadRules(); }, [loadRules, resetSignal]);

  const promote = (id, enforcement) => postJson("/api/rules/enforcement", { id, enforcement }).then(({ ok, body }) => { if (ok) { setRules(body.rules); load(); } });
  const setF = (k, v) => setFilters((f) => ({ ...f, [k]: v }));
  const caught = (id) => (data ? data.alerts.filter((a) => a.observedRule === id).length : 0);

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel__title">Agent Insights <ClaimTag label={story.claimLabel} /></h2>
        <p className="muted" data-testid="insights-note">One record set: Guard results, Alerts (observation only) and Prompts (the sealed record list). {live ? "Live: this workspace's own evaluations from the Detect and Prompt logging tabs (metadata only: no text is ever stored here)." : "Mock: forty seeded events per vertical, evaluated by the lab's engine under the default policy."} Flow is the surface and event is the role of the content (a lab reading).</p>
        <div className="seg" role="group" aria-label="Insights view">
          {SUBS.map(([id, l]) => <button key={id} type="button" aria-pressed={sub === id} onClick={() => setSub(id)} data-testid={`ins-${id}`}>{l}</button>)}
        </div>
        <div className="filters" data-testid="filters">
          <label>Window
            <select value={win} onChange={(e) => setWin(e.target.value)} data-testid="f-window">{WINDOWS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
          </label>
          {Object.keys(FILTER_LABEL).map((k) => (
            <label key={k}>{FILTER_LABEL[k]}
              <select value={filters[k] || ""} onChange={(e) => setF(k, e.target.value)} data-testid={`f-${k}`}>
                <option value="">any</option>
                {(data?.facets?.[k] || []).map((v) => <option key={v} value={v}>{v}</option>)}
              </select>
            </label>
          ))}
          <button type="button" onClick={() => { setFilters({}); }} data-testid="f-clear">Clear filters</button>
          <button type="button" onClick={load} data-testid="f-refresh">Refresh</button>
        </div>
        {error && <p className="field-error" role="alert">Could not load ({visible(error)}).</p>}
        {data && <p className="muted" data-testid="count" aria-live="polite">{data.total} event(s) match; showing {data.shown}{data.total > data.shown ? ` (the newest ${data.limit})` : ""}. Window: {data.window === "live" ? "live view" : data.window}.</p>}
      </section>

      {sub === "guard" && data && (
        <>
          <section className="panel" aria-label="Guard">
            <h3 className="panel__sub">Guard: every inspection result</h3>
            {data.events.length === 0 ? <p className="muted" data-testid="no-events">{live ? "No events yet: evaluate something on the Detect tab in Live mode." : "No events match."}</p> : (
              <div className="scroll"><table className="tbl tbl--wide" data-testid="guard-table">
                <thead><tr><th>When</th><th>Who</th><th>Agent / application</th><th>Flow / event</th><th>Direction</th><th>Category that fired</th><th>Rule that corroborated</th><th>Decision</th><th>ASI; OWASP LLM</th></tr></thead>
                <tbody>{data.events.map((e) => (
                  <tr key={e.id} data-testid="guard-row"><td>{when(e)}</td><td>{visible(e.person)}</td><td>{visible(e.agent)} / {visible(e.app)}</td><td>{e.flow} / {e.event}</td><td>{e.direction}</td>
                    <td>{e.category || "nothing"}</td><td>{e.rule ? <code>{visible(e.rule)}</code> : "-"}</td><td><TierTag tier={e.decision} />{e.observed ? <span className="muted"> (would have: {e.observed})</span> : null}</td><td><FrameworkCells f={e.frameworks} /></td></tr>
                ))}</tbody>
              </table></div>
            )}
          </section>
          <section className="panel" aria-label="Compliance view" data-testid="compliance">
            <h3 className="panel__sub">Compliance view: findings cross-referenced to frameworks <SourceTag source="invented" /></h3>
            <p className="muted" data-testid="compliance-note">{story.compliance.note}</p>
            <div className="cols">
              {story.compliance.frameworks.map((f) => (
                <div key={f.id}>
                  <h4 className="hops__title">{f.label}</h4>
                  {Object.keys(data.compliance[f.id] || {}).length === 0 ? <p className="muted">No findings.</p> : (
                    <table className="tbl"><tbody>{Object.entries(data.compliance[f.id]).sort((a, b) => b[1] - a[1]).map(([label, n]) => <tr key={label}><td>{visible(label)}</td><td>{n}</td></tr>)}</tbody></table>
                  )}
                </div>
              ))}
            </div>
            <details><summary>The mapping per category (lab-illustrative)</summary>
              <div className="scroll"><table className="tbl tbl--wide"><thead><tr><th>Category</th>{story.compliance.frameworks.map((f) => <th key={f.id}>{f.label}</th>)}</tr></thead>
                <tbody>{story.categories.filter((c) => c.frameworks).map((c) => <tr key={c.id}><td><code>{c.id}</code></td>{story.compliance.frameworks.map((f) => <td key={f.id}>{c.frameworks[f.id]}</td>)}</tr>)}</tbody></table></div>
            </details>
          </section>
        </>
      )}

      {sub === "alerts" && data && (
        <>
          <section className="panel" aria-label="Alerts">
            <h3 className="panel__sub">Alerts: observation only <span className="tag">{data.alertTotal}</span></h3>
            <p className="muted">A policy chose to record without changing the outcome. Author a rule on the Your rules tab (it starts in observe), watch what it would have caught here, and promote it to enforcement once the false-positive rate is known.</p>
            {data.alerts.length === 0 ? <p className="muted" data-testid="no-alerts">No observations in this window.</p> : (
              <div className="scroll"><table className="tbl tbl--wide" data-testid="alerts-table">
                <thead><tr><th>When</th><th>Who</th><th>Agent / application</th><th>Flow / event</th><th>Rule</th><th>Would have</th><th>Outcome</th></tr></thead>
                <tbody>{data.alerts.map((e) => <tr key={e.id}><td>{when(e)}</td><td>{visible(e.person)}</td><td>{visible(e.agent)} / {visible(e.app)}</td><td>{e.flow} / {e.event}</td><td><code>{visible(e.observedRule)}</code></td><td><TierTag tier={e.observed} /></td><td><TierTag tier={e.decision} /> unchanged</td></tr>)}</tbody>
              </table></div>
            )}
          </section>
          <section className="panel" aria-label="Rules to promote">
            <h3 className="panel__sub">Your rules: promote to enforcement</h3>
            {!live ? <p className="muted" data-testid="alerts-needs-live">Live mode only: Mock has no rules of its own.</p> : rules.length === 0 ? <p className="muted">No rules yet.</p> : (
              <table className="tbl" data-testid="promote-table"><tbody>{rules.map((r) => (
                <tr key={r.ID}><td><code>{visible(r.ID)}</code></td><td>would have caught {caught(r.ID)} in this window</td><td><span className="tag" data-state={r.enforcement === "enforce" ? "bad" : "warn"}>{r.enforcement}</span></td>
                  <td>{r.enforcement === "observe" ? <button type="button" onClick={() => promote(r.ID, "enforce")} data-testid={`ins-promote-${r.ID}`}>Promote to enforcement</button> : <button type="button" onClick={() => promote(r.ID, "observe")}>Back to observe</button>}</td></tr>
              ))}</tbody></table>
            )}
          </section>
        </>
      )}

      {sub === "prompts" && data && (
        <section className="panel" aria-label="Prompts">
          <h3 className="panel__sub">Prompts: the sealed record list <span className="tag">{data.recordTotal}</span></h3>
          <p className="muted">Searchable detail stays in the clear; the content is shown as sealed until you load the private half and open a record. Your key never leaves this browser.</p>
          <RecordsList records={data.records} keyring={keyring} mode={mode} support={support} />
        </section>
      )}
      <FieldSources fields={story.fieldSources.filter((f) => /Record metadata|OWASP LLM|Enabled/.test(f.field))} />
    </div>
  );
}
