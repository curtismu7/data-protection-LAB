import { useCallback, useEffect, useState } from "react";
import TopMenu, { applyFontSize } from "./top-menu/TopMenu";
import ShelfLink from "./components/ShelfLink";
import VerifyMark from "./components/VerifyMark";
import DetectTab from "./components/DetectTab";
import RulesTab from "./components/RulesTab";
import PromptLogTab from "./components/PromptLogTab";
import InsightsTab from "./components/InsightsTab";
import OwaspTab from "./components/OwaspTab";
import DiagramTab from "./components/DiagramTab";
import TalkTrack from "./components/TalkTrack";
import HelpDialog from "./help-dialog/HelpDialog";
import { HELP_SECTIONS } from "./helpContent";
import { getJson, postJson, resetWorkspace } from "./api";
import { x25519Support } from "./seal";

const THEME_KEY = "dataprot.theme";
const FONT_KEY = "dataprot.font";
const THEMES = [["auto", "Auto"], ["light", "Light"], ["dark", "Dark"]];
function initialTheme() {
  try { const t = localStorage.getItem(THEME_KEY); if (t === "light" || t === "dark") return t; } catch { /* storage blocked */ }
  return "auto";
}
function initialFont() {
  try { const f = localStorage.getItem(FONT_KEY); if (f === "S" || f === "M" || f === "L") return f; } catch { /* storage blocked */ }
  return "M";
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
  const [helpOpen, setHelpOpen] = useState(false);
  const [resetSignal, setResetSignal] = useState(0);
  const [resetMsg, setResetMsg] = useState("");
  const [theme, setTheme] = useState(initialTheme);
  const [fontStep, setFontStep] = useState(initialFont);
  const pickTheme = (next) => {
    try { if (next === "auto") localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, next); } catch { /* not remembered */ }
    setTheme(next);
  };
  // The picker only sets data-theme; the shared stylesheet does the rest ("auto" follows the system setting).
  useEffect(() => { if (theme === "auto") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = theme; }, [theme]);
  useEffect(() => { applyFontSize(fontStep); try { localStorage.setItem(FONT_KEY, fontStep); } catch { /* not remembered */ } }, [fontStep]);

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
  // mode badge and every tab reflect the mode the server answered with.
  const [modeError, setModeError] = useState(null);
  const setMode = async (m) => {
    setModeError(null);
    const r = await postJson("/api/mode", { source: m === "live" ? "real" : "mock" });
    if (!r.ok) { setModeError(r.body?.detail || r.body?.error || `HTTP ${r.status}`); return; }
    setModeState(r.body?.mode || m);
  };
  const select = (id) => { setTab(id); try { window.history.replaceState(null, "", `#${id}`); } catch { /* ignore */ } };

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

  const banner = story && mode ? story.banner[mode] : BANNER_UNKNOWN;
  const ready = story && mode && policy;
  return (
    <div className={`app${presenter ? " app--presenter" : ""}`}>
      <header className="shell-bar">
        <span className="shell-brand">
          <span className="shell-logo" aria-hidden="true">DP</span>
          <h1>Data Protection LAB</h1>
          <span className={`shell-badge${mode === "live" ? " shell-badge--live" : ""}`} data-testid="mode">{mode === "live" ? "Live" : mode === "mock" ? "Mock" : "..."}</span>
        </span>
        <nav className="shell-nav" aria-label="Lab sections">
          {TABS.map((t) => (
            <a key={t.id} href={`#${t.id}`} aria-current={tab === t.id ? "page" : undefined}
              onClick={(e) => { e.preventDefault(); select(t.id); }}>{t.label}</a>
          ))}
        </nav>
        <TopMenu
          mode={{ value: mode === "live" ? "real" : "mock", onChange: (v) => setMode(v === "real" ? "live" : "mock"), realAvailable: true }}
          vertical={{ value: vertical, onChange: setVertical, options: story ? story.verticals : ["finance"] }}
          theme={{ value: theme, onChange: pickTheme }}
          fontSize={{ value: fontStep, onChange: setFontStep }}
          present={{ active: presenter, onToggle: () => setPresenter((v) => !v) }}
          talkTrack={{ active: tab === "talk", onToggle: () => select("talk") }}
          help={{ onClick: () => setHelpOpen(true), title: "What this lab is, and what is simulated" }}
          onReset={reset}
        >
          <ShelfLink />
          <VerifyMark id="data-protection-lab" />
        </TopMenu>
      </header>
      <main className="page">
        <p className="banner" role="status" data-state={mode === "live" ? "live" : "mock"} data-testid="banner">{banner}</p>
        {modeError && <p className="app-error" role="alert" data-testid="mode-error">{modeError}</p>}
        <p className="sr-only" role="status" aria-live="polite">{resetMsg}</p>
        {!presenter && story && <p className="page-intro">{story.intro}</p>}
        <div id={`panel-${tab}`} className="page-body">
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
      <HelpDialog isOpen={helpOpen} onClose={() => setHelpOpen(false)} sections={HELP_SECTIONS} docsUrl="https://github.com/curtismu7/data-protection-LAB#readme" />
    </div>
  );
}
