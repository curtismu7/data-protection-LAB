import { visible } from "../safeText";
import { ClaimTag } from "./Bits";

const STATE = { stated: "ok", pending: "bad", "in-progress": "warn", noted: "warn" };

// The deck's own table (slide 55), as qualified. A pending, in-progress or noted row is never shown as full coverage.
export default function OwaspTab({ story }) {
  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel__title">OWASP Agentic AI Top 10 <ClaimTag label={story.claimLabel} /></h2>
        <p className="muted" data-testid="owasp-note">Each category with the control the deck says addresses it, and what this lab demonstrates for the row. The deck states its own gaps; this table repeats them exactly and never rounds a row up to full coverage. {story.owasp.filter((r) => r.status !== "stated").length} of {story.owasp.length} rows carry a qualification.</p>
        <div className="scroll"><table className="tbl tbl--wide" data-testid="owasp-table">
          <thead><tr><th>Category</th><th>The deck says (Ping claim)</th><th>Status in the deck</th><th>In this lab</th></tr></thead>
          <tbody>{story.owasp.map((r) => (
            <tr key={r.id} data-testid={`owasp-${r.id}`}>
              <td><b>{r.id}</b> {r.name}</td>
              <td>{visible(r.deck)}{r.qualifier && <p className="qualifier" data-testid={`qualifier-${r.id}`}><b>{visible(r.qualifier)}</b></p>}</td>
              <td data-state={STATE[r.status]}><span className="tag" data-state={STATE[r.status]} data-testid={`status-${r.id}`}>{story.owaspStatusLabel[r.status]}</span></td>
              <td>{visible(r.lab)}{r.labCategories.length > 0 && <div className="muted">{r.labCategories.join(", ")}</div>}</td>
            </tr>
          ))}</tbody>
        </table></div>
      </section>
    </div>
  );
}
