import { useCallback, useEffect, useRef, useState } from "react";
import ShelfLink from "./components/ShelfLink";
import DetectTab from "./components/DetectTab";
import RulesTab from "./components/RulesTab";
import PromptLogTab from "./components/PromptLogTab";
import InsightsTab from "./components/InsightsTab";
import OwaspTab from "./components/OwaspTab";
import DiagramTab from "./components/DiagramTab";
import TalkTrack from "./components/TalkTrack";
import { getJson, postJson, resetWorkspace } from "./api";
import { x25519Support } from "./seal";

const THEME_KEY = "dataprot.theme";
const THEMES = [["auto", "Auto"], ["light", "Light"], ["dark", "Dark"]];
function initialTheme() {
  try { const t = localStorage.getItem(THEME_KEY); if (t === "light" || t === "dark") return t; } catch { /* storage blocked */ }
  return "auto";
}

export const TABS = [
  { id: "detect", label: "Detect" },
  { id: "rules", label: "Your rules" },
  { id: "promptlog", label: "Prompt logging" },
  { id: "insights", label: "Agent Insights" },
  { id: "owasp", label: "OWASP Agentic Top 10" },
  { id: "diagram", label: "Diagram" },
  { id: "talk", label: "Talk track" },
];
// The banner is never blank and never claims one mode before it knows: until the story answers it says both, honestly.
const TAIL = "Every product claim is a Ping release claim, UNVERIFIED on our tenant (release 2026-11-02). Nothing here calls a real gateway, identity provider or tenant.";
export const BANNER_UNKNOWN = `SIMULATED, MOCK or LIVE mode (loopback only, no outbound network). ${TAIL}`;
const PRESENTER_TALK = { detect: ["say-first", "detect", "kinds"], rules: ["rules"], promptlog: ["sealed"], insights: ["insights"], owasp: ["owasp"], diagram: ["why-aiguard"] };

const tabFromHash = () => { const h = window.location.hash.replace("#", ""); return TABS.some((t) => t.id === h) ? h : "detect"; };

export default function App() {
  const [vertical, setVertical] = useState("finance");
  const [story, setStory] = useState(null);
  const [mode, setModeState] = useState(null);
  const [policy, setPolicy] = useState(null);
  const [keyring, setKeyring] = useState([]); // private keys live in memory only: never sent, never stored
  const [support, setSupport] = useState({ ok: true, reason: "" });
  const [error, setError] = useState(null);
  const [tab, setTab] = useState(tabFromHash());
  const [presenter, setPresenter] = useState(false);
  const [resetSignal, setResetSignal] = useState(0);
  const [resetMsg, setResetMsg] = useState("");
  const [theme, setTheme] = useState(initialTheme);
  const pickTheme = (next) => {
    try { if (next === "auto") localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, next); } catch { /* not remembered */ }
    setTheme(next);
  };
  // The picker only sets data-theme; the shared stylesheet does the rest ("auto" follows the system setting).
  useEffect(() => { if (theme === "auto") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = theme; }, [theme]);
  const tabsRef = useRef(null);

  useEffect(() => { getJson("/api/info").then((i) => setModeState((m) => m || i.mode || i.source), () => setModeState((m) => m || "mock")); }, []);
  useEffect(() => { x25519Support().then(setSupport); }, []);
  useEffect(() => {
    getJson(`/api/story?vertical=${encodeURIComponent(vertical)}`).then((j) => { setStory(j); setPolicy((p) => p || structuredClone(j.defaultPolicy)); setError(null); }, (e) => setError(e.message));
  }, [vertical]);
  useEffect(() => {
    const on = () => setTab(tabFromHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  // Rule 19: switching is a server call (POST /api/mode with exactly {source}), then the data reloads so the banner,
  // mode chip and every tab reflect the mode the server answered with.
  const [modeError, setModeError] = useState(null);
  const setMode = async (m) => {
    setModeError(null);
    const r = await postJson("/api/mode", { source: m === "live" ? "real" : "mock" });
    if (!r.ok) { setModeError(r.body?.detail || r.body?.error || `HTTP ${r.status}`); return; }
    setModeState(r.body?.mode || m);
  };
  const select = (id) => { setTab(id); try { window.history.replaceState(null, "", `#${id}`); } catch { /* ignore */ } };

  // Keep the active tab fully in view in the scrolling tab strip (375px).
  useEffect(() => {
    const strip = tabsRef.current; const el = document.getElementById(`tab-${tab}`);
    if (!strip || !el) return;
    const left = el.offsetLeft - strip.offsetLeft;
    if (left < strip.scrollLeft || left + el.offsetWidth > strip.scrollLeft + strip.clientWidth) strip.scrollLeft = Math.max(0, left - 8);
  }, [tab]);

  useEffect(() => {
    const on = (e) => {
      if (e.target && /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) return;
      if (e.key === "p" || e.key === "P") setPresenter((v) => !v);
      else if (e.key === "Escape") setPresenter(false);
    };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, []);

  // Reset: the server clears this workspace's events, sealed records, settings and rules; the policy goes back to default and the diagram to its
  // place. The private keys in this page's memory are YOURS and stay until you forget them or reload.
  const reset = useCallback(async () => {
    const ok = await resetWorkspace().catch(() => false);
    setPolicy(story ? structuredClone(story.defaultPolicy) : null);
    setResetSignal((n) => n + 1);
    setResetMsg(ok ? "Reset: your workspace's events, sealed records, prompt-log settings and pasted rules are cleared, the policy is back to default and the diagram is back in place. Keys held in this page are untouched." : "Reset failed on the server; the view was reset.");
  }, [story]);

  const onKeyTab = (e, i) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const next = TABS[(i + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length];
    select(next.id);
    document.getElementById(`tab-${next.id}`)?.focus();
  };

  const banner = story && mode ? story.banner[mode] : BANNER_UNKNOWN;
  const ready = story && mode && policy;
  return (
    <div className={`app${presenter ? " app--presenter" : ""}`}>
      <header>
        <p className="banner" role="status" data-state={mode === "live" ? "live" : "mock"} data-testid="banner">{banner}</p>
        {modeError && <p className="app-error" role="alert" data-testid="mode-error">{modeError}</p>}
        <div className="head">
          <div>
            <h1 className="head__title">Data Protection LAB</h1>
            {!presenter && story && <p className="head__intro">{story.intro}</p>}
          </div>
          <div className="head__tools">
            <ShelfLink />
            <div className="seg" role="group" aria-label="Mode">
              <button type="button" aria-pressed={mode === "mock"} onClick={() => setMode("mock")} data-testid="mode-mock">Mock</button>
              <button type="button" aria-pressed={mode === "live"} onClick={() => setMode("live")} data-testid="mode-live">Live</button>
            </div>
            <label className="shell-theme">Theme
              <select value={theme} onChange={(e) => pickTheme(e.target.value)}>
                {THEMES.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
              </select>
            </label>
            <span className="chip" data-testid="mode">Mode: {mode || "..."}{mode === "live" ? " (local engine, loopback)" : mode === "mock" ? " (tables)" : ""}</span>
            {!presenter && (
              <label className="inline">Vertical{" "}
                <select value={vertical} onChange={(e) => setVertical(e.target.value)} data-testid="vertical">
                  {(story ? story.verticals : ["finance"]).map((v) => <option key={v} value={v}>{v}</option>)}
                </select>
              </label>
            )}
            <button type="button" onClick={reset} data-testid="reset">Reset</button>
            <button type="button" aria-pressed={presenter} onClick={() => setPresenter((v) => !v)} data-testid="presenter">{presenter ? "Exit presenter (Esc)" : "Presenter (P)"}</button>
          </div>
        </div>
      </header>
      <main>
        <p className="sr-only" role="status" aria-live="polite">{resetMsg}</p>
        <div role="tablist" aria-label="Lab sections" className="tabs" ref={tabsRef}>
          {TABS.map((t, i) => (
            <button key={t.id} id={`tab-${t.id}`} role="tab" type="button" aria-selected={tab === t.id} aria-controls={`panel-${t.id}`} tabIndex={tab === t.id ? 0 : -1}
              onClick={() => select(t.id)} onKeyDown={(e) => onKeyTab(e, i)}>{t.label}</button>
          ))}
        </div>
        <div id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`}>
          {error ? <p className="app-error" role="alert">Could not load the lab ({error}). Is the server running?</p> : !ready ? <p className="muted">Loading...</p> : (
            <>
              {presenter && tab !== "talk" && (
                <aside className="presenter-say" data-testid="presenter-say" aria-label="Talk track">
                  {story.talkTrack.filter((t) => (PRESENTER_TALK[tab] || []).includes(t.id)).map((t) => <p key={t.id}><strong>{t.title}.</strong> {t.say}</p>)}
                </aside>
              )}
              {tab === "detect" && <DetectTab key={vertical} story={story} mode={mode} policy={policy} setPolicy={setPolicy} resetSignal={resetSignal} />}
              {tab === "rules" && <RulesTab key={vertical} story={story} mode={mode} resetSignal={resetSignal} />}
              {tab === "promptlog" && <PromptLogTab key={vertical} story={story} mode={mode} keyring={keyring} setKeyring={setKeyring} support={support} resetSignal={resetSignal} />}
              {tab === "insights" && <InsightsTab key={vertical} story={story} mode={mode} keyring={keyring} support={support} resetSignal={resetSignal} />}
              {tab === "owasp" && <OwaspTab story={story} />}
              {tab === "diagram" && <DiagramTab vertical={vertical} resetSignal={resetSignal} />}
              {tab === "talk" && <TalkTrack talk={story.talkTrack} />}
            </>
          )}
        </div>
      </main>
    </div>
  );
}
