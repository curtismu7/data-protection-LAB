// What the Help dialog says. Plain, and as hedged as the rest of the lab (rule 2): what was measured, what is simulated, what is UNVERIFIED.
export const HELP_SECTIONS = [
  {
    heading: "What this lab is",
    body: [
      "A simulation of Ping's data-protection release claims: content inspected in and out with graduated outcomes (allow, alert, sanitize, block), your own gitleaks-format rules, personal-data kinds with real checksums, Agent Insights, the OWASP Agentic Top 10, and prompt logging sealed to a key only your browser holds.",
      "Source: the Ping ID4AI Workforce H2 2026 deck (slides 35, 50, 53-55; release 2026-11-02). Nothing here calls a real gateway, identity provider or tenant, and nothing leaves your machine."
    ]
  },
  {
    heading: "Measured vs simulated vs UNVERIFIED",
    body: [
      "SIMULATED (Mock, default): every outcome comes from a table generated from the lab's own engine; the detection, policy, compliance labels and sample data are the lab's own and lab-invented.",
      "REAL, still local (Live): real checksum validation, real rule matching (your pasted rules run in a killed-if-slow child process), and real sealing — an X25519 key pair made in your browser, the server seals each record to the public half (AES-256-GCM), and only your private half opens it.",
      "UNVERIFIED: every product claim is a Ping release claim, UNVERIFIED on our tenant. The 23 personal-data kinds the deck promises are NOT reproduced — the lab ships eleven of its own, labelled illustrative."
    ]
  },
  {
    heading: "How to use the page",
    body: [
      "Tabs: Detect, Your rules, Prompt logging, Agent Insights, OWASP Agentic Top 10, Diagram, Talk track.",
      "Detect: seven scripted actions in three vertical packs, or your own text in Live; you see the category that fired, the corroborating rule, a score and the outcome. Your rules: paste gitleaks rules — one bad rule refuses the whole paste, and rules start in observe before enforcement. Prompt logging: configure Enabled, PublicKey, KeyID, Surfaces, IncludeResponses, MaxBytes; nothing is recorded without a public key, and content opens only in your browser. Agent Insights: Guard, Alerts and the sealed Prompts list, filterable by agent, application, category, decision, flow and event.",
      "Diagram: ReactFlow with Simulate, Pause/Resume, Next and Reset positions and walkthrough. Top menu: mode toggle, vertical picker, theme, font size, Reset, Presenter (P)."
    ]
  },
  {
    heading: "Mode honesty",
    body: "Mock is offline and does not seal: the Prompts list is a fixed set of placeholder records, and the page says so. Live never leaves loopback and never touches a tenant; the banner and the header badge (Live / Mock) say which mode you are in. A refused mode switch stays put and shows the server's reason."
  },
  {
    heading: "Masking is a heuristic",
    body: "Everything you type comes back masked (lab detector marks plus the shared masker), but bare words, short tokens and some splits are missed. Do not type a real credential into a lab."
  }
];
