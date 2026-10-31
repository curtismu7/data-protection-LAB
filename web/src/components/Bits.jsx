import { visible } from "../safeText";

// Raw JSON or text, rendered as text only (never markup). Control and bidi characters are shown as visible escapes.
export function Json({ value, label, testId }) {
  return <pre className="json" tabIndex={0} aria-label={label} data-testid={testId}>{visible(typeof value === "string" ? value : JSON.stringify(value, null, 2))}</pre>;
}

// Every product claim carries this tag. It is on every tab, and in presenter mode too.
export function ClaimTag({ label }) {
  return <span className="tag" data-state="warn" data-testid="claim-tag">{label || "Ping release claim, UNVERIFIED on our tenant"}</span>;
}

// Where a field comes from: the console swagger (a name only), the lab's reading of it, or the lab's own invention.
const SRC = { swagger: ["console swagger name", "ok"], reading: ["lab reading", "warn"], invented: ["lab-invented", "none"] };
export function SourceTag({ source }) {
  const [text, state] = SRC[source] || [source, "none"];
  return <span className="tag" data-state={state} data-testid="source-tag">{text}</span>;
}

const WORD = { allow: "ALLOW", alert: "ALERT (goes through, recorded)", sanitize: "SANITIZE (span redacted, rest forwarded)", block: "BLOCK (withheld)" };
export function Verdict({ evaluation }) {
  const d = evaluation.decision;
  return (
    <div className="verdict" data-decision={d} data-testid="verdict" role="status">
      <div className="verdict__word" data-testid="verdict-word">{WORD[d] || d}</div>
      <div>{evaluation.forwarded ? "The content is forwarded." : "The content is withheld."} Policy scope: <span className="verdict__code">{visible(evaluation.scope)}</span>.</div>
      {evaluation.observed.length > 0 && <div data-testid="observed-note">Observation only: {evaluation.observed.map((o) => `${visible(o.rule)} would have been ${o.wouldHave}`).join("; ")}. The outcome is unchanged.</div>}
      {evaluation.ruleErrors.length > 0 && <div className="field-error" role="alert">{evaluation.ruleErrors.map(visible).join(" ")}</div>}
    </div>
  );
}

export const TierTag = ({ tier }) => <span className="tag" data-state={tier === "block" ? "bad" : tier === "allow" ? "ok" : "warn"} data-testid="tier">{tier}</span>;

export function CategoriesTable({ categories }) {
  if (!categories.length) return <p className="muted" data-testid="no-categories">No category fired.</p>;
  return (
    <div className="scroll"><table className="tbl tbl--wide" data-testid="categories">
      <thead><tr><th>Category</th><th>Score</th><th>Corroborating rule(s)</th><th>Alert / sanitize / block</th><th>Outcome</th></tr></thead>
      <tbody>{categories.map((c) => (
        <tr key={c.category}><td><code>{c.category}</code></td><td>{c.score}</td><td>{c.rules.map(visible).join(", ")}</td>
          <td>{c.thresholds.AlertThreshold} / {c.thresholds.SanitizeThreshold} / {c.thresholds.BlockThreshold}</td><td><TierTag tier={c.tier} /></td></tr>
      ))}</tbody>
    </table></div>
  );
}

export function FindingsTable({ findings }) {
  if (!findings.length) return <p className="muted" data-testid="no-findings">No rule fired.</p>;
  return (
    <div className="scroll"><table className="tbl tbl--wide" data-testid="findings">
      <caption>Findings: a value is never shown, only its rule, offsets and length</caption>
      <thead><tr><th>Rule</th><th>Category</th><th>Score</th><th>Source</th><th>Where</th><th>Outcome</th></tr></thead>
      <tbody>{findings.map((f, i) => (
        <tr key={`${f.rule}-${f.start}-${i}`}><td><code>{visible(f.rule)}</code></td><td>{f.category}</td><td>{f.score}</td><td>{f.source}{f.observe ? " (observe)" : ""}</td><td>{f.start}-{f.end} ({f.length} chars)</td><td><TierTag tier={f.tier} /></td></tr>
      ))}</tbody>
    </table></div>
  );
}

export function Hops({ hops, traceId }) {
  return (
    <details className="hops" data-testid="hops">
      <summary>Raw hops with traceparent{traceId ? ` (trace ${traceId.slice(0, 8)}...)` : ""}</summary>
      {hops.map((h) => (
        <div key={h.n}>
          <h4 className="hops__title">{h.n}. {h.label}</h4>
          <Json value={h.request} label={`hop ${h.n} request`} />
          <Json value={h.response} label={`hop ${h.n} response`} />
        </div>
      ))}
    </details>
  );
}

// The per-field source table, so every claim is tagged swagger name, lab reading or lab-invented.
export function FieldSources({ fields }) {
  return (
    <details data-testid="field-sources">
      <summary>Where each field comes from ({fields.length})</summary>
      <div className="scroll"><table className="tbl tbl--wide">
        <thead><tr><th>Field</th><th>Source</th><th>Note</th></tr></thead>
        <tbody>{fields.map((f) => <tr key={f.field}><td><code>{f.field}</code></td><td><SourceTag source={f.source} /></td><td>{visible(f.note)}</td></tr>)}</tbody>
      </table></div>
    </details>
  );
}

// Stale-response guard: run(fn) returns a function that says whether a newer request has started since.
import { useRef } from "react";
export function useSeq() {
  const seq = useRef(0);
  return () => { const mine = ++seq.current; return () => mine === seq.current; };
}
