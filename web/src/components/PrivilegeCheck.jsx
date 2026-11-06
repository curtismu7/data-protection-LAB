import { useState } from "react";
import { postJson } from "../api";
import { Json } from "./Bits";

// Live Privilege check: sends one text through the BFF-less local server to the
// tenant's AI Guard (Real-mode outbound) and shows the gateway's own verdict.
// The gateway's policy decides; this panel never invents an outcome.
export default function PrivilegeCheck({ text, label = "Run the same text through live Privilege" }) {
  const [state, setState] = useState({ phase: "idle" });
  const run = () => {
    setState({ phase: "running" });
    postJson("/api/privilege-check", { text }).then(({ ok, body }) => {
      if (ok) setState({ phase: "done", result: body });
      else setState({ phase: "error", message: body?.message || body?.error || "request failed" });
    }, () => setState({ phase: "error", message: "request failed" }));
  };
  const D = state.result?.mapped?.decision;
  const cls = D === "deny" ? "pc--deny" : D === "allow" ? "pc--allow" : "";
  return (
    <div className="pc" data-testid="privilege-check">
      <div className="pc__row">
        <button type="button" className="pc__run" onClick={run} disabled={state.phase === "running"}>
          {state.phase === "running" ? "Calling the gateway…" : label}
        </button>
        <span className="pc__hint">Live call: this lab → the tenant's AI Guard (Privilege AI Guard in the decision path)</span>
      </div>
      {state.phase === "done" && (
        <div className={`pc__result ${cls}`} role="status" data-testid="pc-verdict">
          <strong>{D === "deny" ? "Gateway denied the content (policy)" : D === "allow" ? "Gateway allowed the content" : "Gateway answered; the lab could not map the answer shape"}</strong>
          <span className="pc__meta">{state.result.mapped?.reasonCode ?? ""} · HTTP {state.result.status} · {state.result.mapped?.decidedBy ?? "the gateway"}</span>
          <Json value={state.result.raw} label="gateway answer" testId="pc-raw" />
        </div>
      )}
      {state.phase === "error" && <div className="pc__result pc--warn" role="alert"><strong>Could not reach the gateway</strong><p>{state.message}</p></div>}
    </div>
  );
}
