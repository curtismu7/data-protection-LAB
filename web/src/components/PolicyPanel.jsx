import { SourceTag } from "./Bits";

// The policy the engine uses (Live): per-category thresholds, which personal-data kinds are looked for, and per-key / per-application overrides.
// Editing writes the same shape the server validates (modelAIGuardConfig.Categories / PIIKinds, console swagger names; Keys and Apps are lab-invented).
const FIELDS = [["AlertThreshold", "Alert"], ["SanitizeThreshold", "Sanitize"], ["BlockThreshold", "Block"]];

export const scopeParts = (scope) => (scope === "tenant" ? [null, null] : scope.split(":"));

export function effective(policy, scope) {
  const [kind, id] = scopeParts(scope);
  const map = kind === "key" ? policy.Keys : kind === "app" ? policy.Apps : null;
  const o = map && Object.hasOwn(map, id) ? map[id] : {};
  return { Categories: { ...policy.Categories, ...(o.Categories || {}) }, PIIKinds: o.PIIKinds ?? policy.PIIKinds, overridden: Object.keys(o.Categories || {}) };
}

export default function PolicyPanel({ story, policy, setPolicy, scope, setScope, live, error }) {
  const eff = effective(policy, scope);
  const [kind, id] = scopeParts(scope);
  const kindIds = story.piiKinds.map((k) => k.id);
  const selected = eff.PIIKinds.length ? eff.PIIKinds : kindIds;

  const write = (fn) => setPolicy((p) => { const next = structuredClone(p); fn(next); return next; });
  const ensure = (next) => { const map = kind === "key" ? next.Keys : next.Apps; if (!Object.hasOwn(map, id)) map[id] = {}; return map[id]; };
  const setThreshold = (cat, field, raw) => {
    const v = raw === "" ? 0 : Number(raw);
    write((next) => {
      if (scope === "tenant") next.Categories[cat][field] = v;
      else { const o = ensure(next); o.Categories = o.Categories || {}; o.Categories[cat] = { ...eff.Categories[cat], [field]: v }; }
    });
  };
  const toggleKind = (kid) => {
    const set = new Set(selected); if (set.has(kid)) set.delete(kid); else set.add(kid);
    const list = kindIds.filter((k) => set.has(k));
    const value = list.length === kindIds.length ? [] : list;
    write((next) => { if (scope === "tenant") next.PIIKinds = value; else { const o = ensure(next); if (value.length) o.PIIKinds = value; else delete o.PIIKinds; } });
  };
  const clearScope = () => write((next) => { const map = kind === "key" ? next.Keys : next.Apps; if (map) delete map[id]; });

  return (
    <section className="panel" aria-label="Policy" data-testid="policy">
      <h3 className="panel__sub">Policy: thresholds, kinds and overrides</h3>
      <p className="muted">{live ? "Live: every change is sent with the next evaluation and validated by the server." : "Mock: the table uses the default policy. Switch to Live to edit thresholds, kinds and overrides."} A score at or above a threshold reaches that outcome; a threshold of 0 turns the outcome off.</p>
      <label>Policy scope
        <select value={scope} onChange={(e) => setScope(e.target.value)} disabled={!live} data-testid="scope">
          <option value="tenant">Tenant default</option>
          <option value={`key:${story.scopes.key}`}>Key {story.scopes.key} (overrides the tenant)</option>
          <option value={`app:${story.scopes.app}`}>Application {story.scopes.app} (overrides the tenant)</option>
        </select>
      </label>
      <p className="muted">Precedence, a lab reading: key beats application beats tenant, per category. <SourceTag source="invented" /> <span>The per-key and per-application maps are the lab&apos;s structure.</span></p>
      {error && <p className="field-error" role="alert" data-testid="policy-error">{error}</p>}
      <div className="scroll"><table className="tbl tbl--wide" data-testid="thresholds">
        <caption>Thresholds per category ({scope === "tenant" ? "tenant default" : `${kind} ${id}`}) <SourceTag source="swagger" /></caption>
        <thead><tr><th>Category</th>{FIELDS.map(([, l]) => <th key={l}>{l}</th>)}<th>Source of the key</th></tr></thead>
        <tbody>{story.categories.map((c) => (
          <tr key={c.id}>
            <td><code>{c.id}</code>{eff.overridden.includes(c.id) && <span className="tag" data-state="warn"> overridden</span>}</td>
            {FIELDS.map(([f, l]) => (
              <td key={f}><input type="number" min="0" max="1" step="0.05" value={eff.Categories[c.id][f]} disabled={!live} aria-label={`${c.id} ${l} threshold`} data-testid={`th-${c.id}-${f}`}
                onChange={(e) => setThreshold(c.id, f, e.target.value)} /></td>
            ))}
            <td className="muted">{c.source}</td>
          </tr>
        ))}</tbody>
      </table></div>
      <div className="toggles">
        <button type="button" onClick={() => setPolicy(structuredClone(story.defaultPolicy))} disabled={!live} data-testid="policy-default">Back to the default policy</button>
        {scope !== "tenant" && <button type="button" onClick={clearScope} disabled={!live} data-testid="scope-clear">Clear this scope&apos;s overrides</button>}
      </div>
      <fieldset className="fieldset" data-testid="kind-select">
        <legend>Personal-data kinds to look for ({selected.length} of {kindIds.length}) <SourceTag source="swagger" /></legend>
        <div className="toggles">
          {story.piiKinds.map((k) => (
            <label key={k.id} className="check"><input type="checkbox" checked={selected.includes(k.id)} disabled={!live} onChange={() => toggleKind(k.id)} data-testid={`kind-${k.id}`} /> {k.id}</label>
          ))}
        </div>
        <p className="muted">PIIKinds narrows which kinds are reported. Unticking one removes it from the list; all ticked means the field is empty (every kind). It also narrows a pasted pii rule, listed by its cst- id.</p>
      </fieldset>
    </section>
  );
}
