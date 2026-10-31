import { useEffect, useState } from "react";
import { openEnvelope } from "../seal";
import { visible } from "../safeText";
import { SourceTag } from "./Bits";

// The sealed record list. The metadata is in the clear; the content stays sealed until a private key is chosen and ONE record is opened,
// and the opening happens here, in the browser. The plaintext lives in this component's state only, until Close (or unmount).
export default function RecordsList({ records, keyring, mode, support }) {
  const [open, setOpen] = useState(null); // { id, ok, text?, reason? }
  const [pick, setPick] = useState({});
  useEffect(() => () => setOpen(null), []);
  useEffect(() => { setOpen(null); }, [mode]);
  const keyFor = (rec) => keyring.find((k) => k.kid === (pick[rec.id] ?? rec.kid)) || keyring.find((k) => k.kid === rec.kid) || keyring[0] || null;

  const doOpen = async (rec) => {
    const k = keyFor(rec);
    if (!k) { setOpen({ id: rec.id, ok: false, reason: `No private key is loaded. Load the private key for key ${rec.kid} first.` }); return; }
    const r = await openEnvelope(k.privateJwk, rec.envelope);
    if (!r.ok) { setOpen({ id: rec.id, ok: false, reason: r.reason }); return; }
    let body; try { body = JSON.parse(r.plaintext); } catch { body = { prompt: r.plaintext }; }
    setOpen({ id: rec.id, ok: true, body });
  };
  const rec = open && records.find((r) => r.id === open.id);

  return (
    <div data-testid="records">
      {!support.ok && <p className="field-error" role="alert" data-testid="no-webcrypto">{support.reason}</p>}
      {records.length === 0 ? <p className="muted" data-testid="no-records">No sealed records.</p> : (
        <div className="scroll"><table className="tbl tbl--wide" data-testid="records-table">
          <caption>Clear metadata (searchable) with sealed content: the content is sealed until you open a record with your private key</caption>
          <thead><tr><th>When</th><th>Who</th><th>Agent / application</th><th>Flow / event</th><th>Detected</th><th>Decided</th><th>Key</th><th>Content</th></tr></thead>
          <tbody>{records.map((r) => (
            <tr key={r.id} data-testid={`rec-${r.id}`}>
              <td>{r.at ? new Date(r.at).toLocaleString() : `${r.ageH} h ago`}</td><td>{visible(r.person)}</td><td>{visible(r.agent)} / {visible(r.app)}</td><td>{r.flow} / {r.event}</td>
              <td>{r.category || "nothing"}{r.rule ? ` (${visible(r.rule)})` : ""}</td><td><span className="tag" data-state={r.decision === "block" ? "bad" : r.decision === "allow" ? "ok" : "warn"}>{r.decision}</span></td><td><code>{visible(r.kid)}</code></td>
              <td>
                <span className="tag" data-state="warn">sealed</span>{" "}
                {r.mock ? <span className="muted">mock placeholder</span> : (
                  <>
                    {keyring.length > 1 && (
                      <select aria-label={`Key to try for ${r.id}`} value={pick[r.id] ?? keyFor(r)?.kid ?? ""} onChange={(e) => setPick({ ...pick, [r.id]: e.target.value })} data-testid={`pick-${r.id}`}>
                        {keyring.map((k) => <option key={k.kid} value={k.kid}>{k.kid}</option>)}
                      </select>
                    )}
                    <button type="button" onClick={() => doOpen(r)} disabled={!support.ok} data-testid={`open-${r.id}`}>Open</button>
                  </>
                )}
              </td>
            </tr>
          ))}</tbody>
        </table></div>
      )}
      {mode === "mock" && records.length > 0 && <p className="muted" data-testid="mock-records-note">Mock: a fixed list of placeholder records. Nothing is sealed or opened in Mock. Switch to Live to seal and open real records.</p>}
      {open && (
        <section className="panel" data-state={open.ok ? "ok" : "bad"} aria-label="Opened record" data-testid="opened">
          <h3 className="panel__sub">Record {rec ? <code>{rec.id}</code> : null}: decrypted here, in this browser <SourceTag source="invented" /></h3>
          {open.ok ? (
            <>
              <p className="muted">The server never saw the key or this text. It is held only in this panel until you close it.</p>
              <pre className="json" tabIndex={0} aria-label="decrypted prompt" data-testid="opened-prompt">{visible(open.body.prompt ?? "")}</pre>
              {open.body.response !== undefined && <pre className="json" tabIndex={0} aria-label="decrypted response" data-testid="opened-response">{visible(open.body.response)}</pre>}
              {open.body.truncated && <p className="muted">This record was cut to MaxBytes when it was sealed.</p>}
            </>
          ) : <p className="field-error" role="alert" data-testid="open-error">{visible(open.reason)}</p>}
          <button type="button" onClick={() => setOpen(null)} data-testid="close-opened">Close</button>
        </section>
      )}
    </div>
  );
}
