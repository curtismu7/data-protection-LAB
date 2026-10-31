import { useCallback, useEffect, useState } from "react";
import { getJson, postJson } from "../api";
import { visible } from "../safeText";
import { ClaimTag, SourceTag, useSeq } from "./Bits";
import RecordsList from "./RecordsList";
import { generateKeyPair, parsePrivateJwk } from "../seal";

// Prompt logging, sealed to a key you hold. The key pair is made HERE, with WebCrypto: the private half is kept in memory (the `keyring` held by
// the App), is never sent to the server, is not put in localStorage and is never logged. The server only ever gets the public half.
export default function PromptLogTab({ story, mode, keyring, setKeyring, support, resetSignal }) {
  const live = mode === "live";
  const [cfg, setCfg] = useState({ Enabled: false, PublicKey: "", KeyID: "", Surfaces: [], IncludeResponses: false, MaxBytes: 0 });
  const [status, setStatus] = useState(null);
  const [cfgError, setCfgError] = useState(null);
  const [kid, setKid] = useState("key-1");
  const [pasted, setPasted] = useState("");
  const [keyMsg, setKeyMsg] = useState("");
  const [send, setSend] = useState({ text: "", response: "", role: "user_prompt", surface: "llm" });
  const [sent, setSent] = useState(null);
  const [records, setRecords] = useState([]);
  const guard = useSeq(); const recGuard = useSeq();

  const loadRecords = useCallback(() => { const ok = recGuard(); getJson(`/api/insights?mode=${mode}&window=30d`).then((j) => { if (ok()) setRecords(j.records); }, () => {}); }, [mode]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const ok = guard();
    getJson("/api/promptlog").then((j) => { if (ok()) { setCfg(j.config); setStatus(j.status); } }, () => {});
    setSent(null); loadRecords();
  }, [mode, resetSignal, loadRecords]); // eslint-disable-line react-hooks/exhaustive-deps

  const nextKid = (list) => { let n = list.length + 1; while (list.some((k) => k.kid === `key-${n}`)) n++; return `key-${n}`; };
  const make = async () => {
    setKeyMsg("");
    try {
      const pair = await generateKeyPair();
      const id = kid.trim() || nextKid(keyring);
      if (keyring.some((k) => k.kid === id)) { setKeyMsg(`A key named ${id} is already loaded: choose another name.`); return; }
      setKeyring([...keyring, { kid: id, publicJwk: pair.publicJwk, privateJwk: pair.privateJwk }]);
      setCfg((c) => ({ ...c, PublicKey: JSON.stringify(pair.publicJwk), KeyID: id }));
      setKid(nextKid([...keyring, { kid: id }]));
      setKeyMsg(`Key ${id} made in this browser. Its private half is held in memory only. Use the public half below as PublicKey, then Save.`);
    } catch { setKeyMsg("This browser could not make an X25519 key."); }
  };
  const download = (k) => {
    const blob = new Blob([JSON.stringify(k.privateJwk, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `${k.kid}.private.jwk.json`; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const loadPasted = () => {
    const r = parsePrivateJwk(pasted); const id = kid.trim();
    if (r.error) { setKeyMsg(r.error); return; }
    if (!id || keyring.some((k) => k.kid === id)) { setKeyMsg(id ? `A key named ${id} is already loaded.` : "Give the key a name (it should match the record's key id)."); return; }
    setKeyring([...keyring, { kid: id, publicJwk: { kty: "OKP", crv: "X25519", x: r.jwk.x }, privateJwk: r.jwk }]); setPasted(""); setKid(nextKid([...keyring, { kid: id }])); setKeyMsg(`Key ${id} loaded into memory.`);
  };
  const save = () => {
    const ok = guard();
    postJson("/api/promptlog/config", { config: cfg }).then(({ ok: good, body }) => {
      if (!ok()) return;
      if (good) { setCfg(body.config); setStatus(body.status); setCfgError(null); } else setCfgError(body.errors ? body.errors.map((e) => `${e.field}: ${e.message}`).join("; ") : `${body.error}`);
    }, () => { if (ok()) setCfgError("request failed"); });
  };
  const toggleSurface = (s) => setCfg((c) => ({ ...c, Surfaces: c.Surfaces.includes(s) ? c.Surfaces.filter((x) => x !== s) : [...c.Surfaces, s] }));
  const sendIt = () => {
    postJson("/api/evaluate", { mode, vertical: story.vertical, labels: story.labels, custom: { text: send.text, response: send.response || undefined, role: send.role, surface: send.surface } }).then(({ ok, body }) => {
      if (ok) { setSent(body); loadRecords(); } else setSent({ error: `${body.error}: ${body.detail || ""}` });
    }, () => setSent({ error: "request failed" }));
  };

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel__title">Prompt logging: sealed to a key only you hold <ClaimTag label={story.claimLabel} /></h2>
        <p className="muted" data-testid="pl-note">Off until you turn it on, and nothing is recorded without a public key. Records are sealed on the server to the public key you supply (ephemeral X25519, HKDF-SHA256, AES-256-GCM); who, which agent, which application, what was detected and what was decided stay in the clear and searchable. The content opens only in this browser, at the moment you open a record, with a private key you supply then. A record you never open is never decrypted anywhere. <b>The envelope format is the lab&apos;s own invention</b> <SourceTag source="invented" />; the settings below are console swagger names <SourceTag source="swagger" />.</p>
        {!support.ok && <p className="field-error" role="alert" data-testid="no-x25519">{support.reason}</p>}
        <h3 className="panel__sub">1. Your key pair (made in this browser)</h3>
        <div className="form">
          <label>Key name (KeyID)
            <input value={kid} onChange={(e) => setKid(e.target.value)} maxLength={64} data-testid="kid" />
          </label>
          <div className="toggles">
            <button type="button" className="primary" onClick={make} disabled={!support.ok} data-testid="gen-key">Generate a key pair in this browser</button>
          </div>
          <p className="muted" data-testid="key-msg" role="status">{keyMsg}</p>
          <details>
            <summary>Load an existing private key (to open older records, or after a reload)</summary>
            <label>Private key (a JWK; held in memory only, never sent anywhere)
              <textarea rows={3} value={pasted} onChange={(e) => setPasted(e.target.value)} data-testid="paste-private" autoComplete="off" spellCheck={false} />
            </label>
            <button type="button" onClick={loadPasted} disabled={!pasted.trim()} data-testid="load-private">Load this private key as the name above</button>
          </details>
        </div>
        <div className="scroll"><table className="tbl" data-testid="keyring">
          <caption>Keys held in this page&apos;s memory ({keyring.length}). A reload forgets them: download the private key if you need it later.</caption>
          <thead><tr><th>Key name</th><th>Public half</th><th /></tr></thead>
          <tbody>
            {keyring.length === 0 && <tr><td colSpan={3} className="muted">None yet.</td></tr>}
            {keyring.map((k) => (
              <tr key={k.kid}><td><code>{visible(k.kid)}</code></td><td><code>{k.publicJwk.x.slice(0, 12)}...</code></td>
                <td><button type="button" onClick={() => download(k)} data-testid={`dl-${k.kid}`}>Download the private key</button> <button type="button" onClick={() => setKeyring(keyring.filter((x) => x.kid !== k.kid))} data-testid={`forget-${k.kid}`}>Forget</button></td></tr>
            ))}
          </tbody>
        </table></div>
      </section>

      <section className="panel" aria-label="Prompt-log settings">
        <h3 className="panel__sub">2. The tenant&apos;s prompt-log settings (modelPromptLogConfig)</h3>
        {!live && <p className="muted" data-testid="pl-needs-live">Mock: the settings, sealing and the send box work in Live only. The list below is a fixed table of placeholder records.</p>}
        <div className="form">
          <label className="check"><input type="checkbox" checked={cfg.Enabled} disabled={!live} onChange={(e) => setCfg({ ...cfg, Enabled: e.target.checked })} data-testid="pl-enabled" /> Enabled</label>
          <label>PublicKey (an X25519 public JWK; a private key is refused)
            <textarea rows={3} value={cfg.PublicKey} disabled={!live} onChange={(e) => setCfg({ ...cfg, PublicKey: e.target.value })} data-testid="pl-public" spellCheck={false} />
          </label>
          <label>KeyID
            <input value={cfg.KeyID} disabled={!live} onChange={(e) => setCfg({ ...cfg, KeyID: e.target.value })} maxLength={64} data-testid="pl-kid" />
          </label>
          <fieldset className="fieldset"><legend>Surfaces (none ticked records every surface)</legend>
            <div className="toggles">{story.surfaces.map((s) => <label key={s} className="check"><input type="checkbox" checked={cfg.Surfaces.includes(s)} disabled={!live} onChange={() => toggleSurface(s)} data-testid={`pl-surface-${s}`} /> {s}</label>)}</div>
          </fieldset>
          <label className="check"><input type="checkbox" checked={cfg.IncludeResponses} disabled={!live} onChange={(e) => setCfg({ ...cfg, IncludeResponses: e.target.checked })} data-testid="pl-responses" /> IncludeResponses</label>
          <label>MaxBytes (0 takes the default {story.limits.promptLog.defaultMaxBytes}; otherwise {story.limits.promptLog.minBytes} to {story.limits.promptLog.maxBytes}; the text of one record, prompt first)
            <input type="number" min="0" max={story.limits.promptLog.maxBytes} value={cfg.MaxBytes} disabled={!live} onChange={(e) => setCfg({ ...cfg, MaxBytes: Number(e.target.value) })} data-testid="pl-max" />
          </label>
          <div className="toggles"><button type="button" className="primary" onClick={save} disabled={!live} data-testid="pl-save">Save the settings</button></div>
        </div>
        {cfgError && <p className="field-error" role="alert" data-testid="pl-error">{visible(cfgError)}</p>}
        {status && <p data-testid="pl-status" data-state={status.recording ? "ok" : "warn"}>{status.recording ? "Recording. " : "Not recording. "}{visible(status.why)}</p>}
      </section>

      <section className="panel" aria-label="Send a prompt">
        <h3 className="panel__sub">3. Send a prompt through the gateway</h3>
        {!live ? <p className="muted">Live mode only.</p> : (
          <div className="form">
            <label>Role
              <select value={send.role} onChange={(e) => setSend({ ...send, role: e.target.value })} data-testid="send-role">{story.roles.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}</select>
            </label>
            <label>Surface
              <select value={send.surface} onChange={(e) => setSend({ ...send, surface: e.target.value })} data-testid="send-surface">{story.surfaces.map((s) => <option key={s} value={s}>{s}</option>)}</select>
            </label>
            <label>Prompt (at most 20000 characters)
              <textarea rows={3} value={send.text} maxLength={20000} onChange={(e) => setSend({ ...send, text: e.target.value })} data-testid="send-text" />
            </label>
            <label>Response (retained when IncludeResponses is on; not inspected in this lab)
              <textarea rows={2} value={send.response} maxLength={20000} onChange={(e) => setSend({ ...send, response: e.target.value })} data-testid="send-response" />
            </label>
            <div className="toggles"><button type="button" className="primary" disabled={!send.text.trim()} onClick={sendIt} data-testid="send-go">Send and record</button></div>
          </div>
        )}
        {sent && (sent.error ? <p className="field-error" role="alert">{visible(sent.error)}</p> : (
          <p data-testid="sent-note">Decision <b>{sent.evaluation.decision}</b>. {sent.record ? <>Sealed as <code data-testid="sent-record">{sent.record.id}</code> under key <code>{visible(sent.record.kid)}</code>.</> : <span data-testid="sent-skipped">Not recorded: {sent.recordSkipped}.</span>}</p>
        ))}
      </section>

      <section className="panel" aria-label="Sealed records">
        <h3 className="panel__sub">4. Sealed records <span className="tag">{records.length}</span></h3>
        <RecordsList records={records} keyring={keyring} mode={mode} support={support} />
      </section>
    </div>
  );
}
